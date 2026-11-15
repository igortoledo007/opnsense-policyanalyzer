"""
    Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    Assistant: the single entry point consumers use.

        config = AIConfig.from_opnsense('OPNsense/policyanalyzer')
        assistant = Assistant(config, app='policyanalyzer')
        task = Task('explain_finding', instructions='...', question='Explain this finding.')
        result = assistant.ask(task, data, language='pt_BR', subject='finding:abc123')

    The task name is the scenario id of the catalog (scenarios.py); Task(scenario=...) overrides it for
    internal parts (map/reduce).  For every call the Assistant resolves the route of the scenario (provider,
    model, timeout, num_ctx, num_predict, keep_alive, budget, sync or queue, fallback) and then:

        anonymize data -> build prompts (guardrails + task; on Ollama the language reminder in the user
        message and /no_think for qwen3) -> cache (queue scenarios) -> queue (mode "queue": returns
        {"status": "queued", "job": {...}} at once, the worker runs the module again) -> provider (JSON Schema
        on Ollama for the structured scenarios, <think> removed, reasoning that leaked without tags cut) ->
        validation with one correction attempt -> "publish" scenarios (e-mail, PDF, dashboard): an answer still in
        the wrong language or still made of reasoning is rejected (AnswerRejected) -> fallback provider when the
        first one fails (bridge down, timeout, rejected) -> restore placeholders -> audit.
        ask(max_seconds=N) bounds the whole call (attempts and fallback), for the reports run from cron.

    The answer is text only; nothing here can change the firewall configuration.
"""

import hashlib
import json
import os
import re
import time

from . import scenarios as routing_mod
from . import validate
from .anonymizer import Anonymizer, StreamRestorer
from .audit import AuditLog, sha256
from .prompts import build_system, build_user, language_name
from .providers import ProviderError, ProviderRefusal, get_provider

# qwen3 hybrid builds take /no_think; the 2507 instruct builds have no thinking mode at all
THINKING_MODEL_RE = re.compile(r'(^|/)qwen3(?!.*instruct)', re.I)
MIN_ATTEMPT_SECONDS = 60            # with ask(max_seconds): no new attempt / fallback with less time than this
PRIMARY_SHARE = 0.6                 # with ask(max_seconds) and a fallback route: the time the first route may use


class AIDisabled(Exception):
    pass


class AnswerRejected(ProviderError):
    """ the answer of a "publish" scenario is unusable (wrong language, reasoning); never shown to anyone """


class Task:
    def __init__(self, name, instructions='', question='Explain the data below.', scenario=None, schema=None,
                 render=None, check_ctx=None, validate=True):
        """
        :param name: action name in the audit log; also the scenario id unless scenario is given
        :param scenario: catalog id whose route applies (map/reduce parts use the id of their scenario)
        :param schema: JSON Schema for Ollama structured output ("format")
        :param render: callable(dict) -> text in the format the module expects (None: keep the JSON text)
        :param check_ctx: context of the validation, e.g. {"valid_ids": [...]} or {"first_values": [...]}
        :param validate: False for internal parts (no format checks, no correction attempt)
        """
        self.name = name
        self.instructions = instructions
        self.question = question
        self.scenario = scenario or routing_mod.ALIASES.get(name, name)
        self.schema = schema
        self.render = render
        self.check_ctx = check_ctx or {}
        self.validate = validate


def is_queued(result):
    return isinstance(result, dict) and result.get('status') == 'queued'


class Assistant:
    def __init__(self, config, app='opnsense', audit=None, provider=None, sensitive_keys=None, routing=None,
                 inline=False, queue_path=None):
        """
        :param config: AIConfig
        :param app: consumer name written to the audit log
        :param audit: AuditLog instance (default: /var/log/policyanalyzer/ai.log)
        :param provider: provider instance override (tests); it answers every route and disables the fallback
        :param sensitive_keys: anonymizer key map override
        :param routing: routing dict override (tests), default /var/db/policyanalyzer/ai-routing.json
        :param inline: never queue (the caller already runs in the background: brief child, cron, report)
        :param queue_path: SQLite queue override (tests)
        """
        self.config = config
        self.app = app
        self.audit = audit if audit is not None else AuditLog()
        self._provider = provider           # injected (tests, console): answers every route, no fallback
        self._global_provider = None
        self.sensitive_keys = sensitive_keys
        self.routing = routing
        self.inline = inline
        self.queue_path = queue_path
        self.provider_factory = get_provider
        self.clock = time.monotonic
        self._deadline = None
        self._route_deadline = None

    @property
    def provider(self):
        """ the global provider of the settings (connection test, model list) """
        if self._provider is not None:
            return self._provider
        if self._global_provider is None:
            self._global_provider = get_provider(self.config.provider, self.config.options,
                                                 timeout=self.config.timeout)
        return self._global_provider

    def resolve_language(self, requested=None):
        """ explicit setting wins, "auto" follows the language passed in by the GUI """
        if self.config.language and self.config.language != 'auto':
            return self.config.language
        return requested or 'en_US'

    # ------------------------------------------------------------------ routing

    def route_for(self, task):
        route = routing_mod.resolve(task.scenario, self.config, routing=self.routing)
        if self._provider is not None:
            route.fallback = None
        return route

    def _provider_for(self, route):
        if self._provider is not None and route.role == 'primary':
            return self._provider
        return self.provider_factory(route.provider, route.provider_options(), timeout=route.timeout)

    # ------------------------------------------------------------------ prompts

    def prepare(self, task, data, language=None):
        """ :return: (anonymizer, messages) without contacting the provider """
        anonymizer = Anonymizer(enabled=self.config.anonymize, sensitive_keys=self.sensitive_keys)
        safe_data = anonymizer.anonymize(data)
        messages = [
            {'role': 'system', 'content': build_system(task.instructions, self.resolve_language(language))},
            {'role': 'user', 'content': build_user(task.question, safe_data)},
        ]
        return anonymizer, messages

    @staticmethod
    def finalize(messages, route, language):
        """ Ollama: language reminder in the last user message; qwen3: /no_think (think=false goes in the API),
            except on a route that asks for the reasoning (think on) """
        if not route.ollama:
            return messages
        out = [dict(m) for m in messages]
        for msg in reversed(out):
            if msg['role'] == 'user':
                msg['content'] = msg['content'].rstrip() + '\n\n' + validate.language_reminder(language)
                if THINKING_MODEL_RE.search(route.model or '') and not getattr(route, 'thinking', False):
                    msg['content'] += ' /no_think'
                break
        return out

    def preview(self, task, data, language=None):
        """ what would be sent, for the "show payload" button; nothing leaves the box """
        anonymizer, messages = self.prepare(task, data, language)
        route = self.route_for(task)
        messages = self.finalize(messages, route, self.resolve_language(language))
        return {
            'status': 'ok',
            'anonymized': anonymizer.enabled,
            'placeholders': len(anonymizer.mapping),
            'messages': messages,
            'bytes': sum(len(m['content'].encode()) for m in messages),
            'route': route.as_dict(),
        }

    # ------------------------------------------------------------------ ask

    def ask(self, task, data, language=None, subject=None, stream=False, on_chunk=None, inline=None,
            max_seconds=None):
        """ :param max_seconds: limit of the whole call (route timeouts, retries and fallback are cut to fit) """
        if not self.config.enabled:
            raise AIDisabled('AI assistance is disabled in the settings')
        self._deadline = (self.clock() + max_seconds) if max_seconds else None
        try:
            return self._ask(task, data, language, subject, stream, on_chunk, inline)
        finally:
            self._deadline = None
            self._route_deadline = None

    def remaining(self, route=False):
        """ seconds left of ask(max_seconds=...) (route=True: of the current route), None without a limit """
        if self._deadline is None:
            return None
        end = min(self._deadline, self._route_deadline or self._deadline) if route else self._deadline
        return end - self.clock()

    def _ask(self, task, data, language, subject, stream, on_chunk, inline):
        route = self.route_for(task)
        lang = self.resolve_language(language)
        anonymizer, base = self.prepare(task, data, language)
        job_id = os.environ.get('PA_AI_JOB') or None
        inline = bool(inline or self.inline or job_id or os.environ.get('PA_AI_INLINE'))
        chain = [route] + ([route.fallback] if route.fallback is not None else [])
        if os.environ.get('PA_AI_ROUTE') == 'fallback' and route.fallback is not None:
            chain = [route.fallback]
        started = self.clock()
        errors = []
        for idx, current in enumerate(chain):
            messages = self.finalize(base, current, lang)
            if current.mode == 'queue' and not inline:
                queued = self._enqueue(task, current, messages, lang, subject, errors)
                if queued is not None:
                    return queued
            if idx > 0 and not inline:
                left = self._sync_budget(route) - (self.clock() - started)
                if left < 45:
                    queued = self._enqueue(task, current, messages, lang, subject, errors, force=True)
                    if queued is not None:
                        return queued
                current.timeout = int(max(30, min(current.timeout or left, left)))
            left = self.remaining()
            if left is not None:
                if idx > 0 and left < MIN_ATTEMPT_SECONDS:
                    break
                share = left * PRIMARY_SHARE if idx < len(chain) - 1 else left    # keep time for the fallback
                current.timeout = int(max(MIN_ATTEMPT_SECONDS, min(current.timeout or share, share)))
                self._route_deadline = self.clock() + current.timeout
            try:
                return self._ask_route(task, current, anonymizer, messages, lang, subject, stream, on_chunk,
                                       job_id, errors)
            except ProviderRefusal:
                raise
            except ProviderError as exc:
                errors.append((current, exc))
                if idx == len(chain) - 1:
                    if len(errors) == 1:
                        raise
                    raise self._chain_error(errors)
        if errors:
            if len(errors) == 1:
                raise errors[0][1]
            raise self._chain_error(errors)
        raise ProviderError('no AI provider available for %s' % task.scenario)

    @staticmethod
    def _chain_error(errors):
        """ one error for every route that failed; AnswerRejected when the last one was a rejection """
        cls = AnswerRejected if isinstance(errors[-1][1], AnswerRejected) else ProviderError
        return cls('; '.join('%s: %s' % (r.label(), e) for r, e in errors))

    def _sync_budget(self, route):
        """ seconds the GUI request waits in total (PHP timeout minus a margin) """
        if route.php_timeout:
            return max(60, route.php_timeout - 45)
        return (route.timeout or routing_mod._default_timeout(route)) + 20

    def _cache_key(self, task, route, messages):
        material = json.dumps([task.scenario, task.name, route.provider, route.model, route.num_ctx, task.schema,
                               messages], sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(material.encode('utf-8')).hexdigest()

    def _jobqueue(self):
        from . import jobqueue
        return jobqueue

    def _enqueue(self, task, route, messages, language, subject, errors, force=False):
        """ :return: queued result, or None when this command can not be queued (CLI, tests) """
        jq = self._jobqueue()
        argv = jq.current_argv()
        if not jq.valid_argv(argv):
            return None
        key = self._cache_key(task, route, messages)
        if not force and jq.cache_get(key, self.queue_path) is not None:
            return None                 # answered from the cache synchronously
        info = route.as_dict()
        info.pop('fallback', None)
        meta = routing_mod.CATALOG.get(task.scenario) or {}
        timeout = (route.timeout or routing_mod._default_timeout(route)) * (2 + route.retries) + 300
        if meta.get('mapreduce'):
            timeout *= 6
        try:
            job = jq.enqueue(task.scenario, key, argv, subject=subject, route=info, language=language,
                             eta=meta.get('eta'), timeout=timeout, path=self.queue_path)
        except Exception as exc:        # noqa: BLE001 - no queue: answer synchronously
            self.audit.record(app=self.app, action=task.name, scenario=task.scenario, status='queue_error',
                              error=str(exc))
            return None
        if not job.get('merged'):
            try:
                jq.spawn_worker(self.queue_path)
            except OSError:
                pass
        event = {'app': self.app, 'action': task.name, 'scenario': task.scenario, 'subject': subject,
                 'provider': route.provider, 'model': route.model, 'status': 'queued', 'job': job['id'],
                 'route_role': route.role}
        if errors:
            event['fallback_from'] = ['%s: %s' % (r.label(), e) for r, e in errors]
        self.audit.record(**event)
        public = {k: job.get(k) for k in ('id', 'status', 'scenario', 'position', 'ahead', 'eta_seconds', 'created',
                                           'provider', 'model', 'label', 'merged')}
        return {'status': 'queued', 'job': public, 'scenario': task.scenario, 'provider': route.provider,
                'model': route.model, 'label': route.label(), 'fallback': bool(errors),
                'message': 'queued for the %s (position %s, about %d min)' % (
                    route.label(), job.get('position'), max(1, round((job.get('eta_seconds') or 60) / 60.0)))}

    def _ask_route(self, task, route, anonymizer, messages, language, subject, stream, on_chunk, job_id, errors):
        prompt = '\n'.join(m['content'] for m in messages)
        event = {
            'app': self.app,
            'action': task.name,
            'scenario': task.scenario,
            'subject': subject,
            'provider': route.provider,
            'model': route.model,
            'route_role': route.role,
            'anonymized': anonymizer.enabled,
            'language': language_name(language),
            'prompt_sha256': sha256(prompt),
            'prompt_bytes': len(prompt.encode()),
            'job': int(job_id) if job_id and str(job_id).isdigit() else None,
        }
        if errors:
            event['fallback_from'] = ['%s: %s' % (r.label(), e) for r, e in errors]
        if anonymizer.enabled:
            # this is exactly what left the firewall, safe to keep
            event['prompt'] = prompt
        if hasattr(self, 'last_messages'):
            self.last_messages = messages
        key = self._cache_key(task, route, messages)
        use_cache = route.mode == 'queue' or bool(job_id)
        if use_cache:
            hit = self._jobqueue().cache_get(key, self.queue_path)
            if hit is not None:
                answer = anonymizer.deanonymize(hit['text'])
                event.update({'status': 'ok', 'cached': True, 'model': hit.get('model'),
                              'response_sha256': sha256(hit['text'])})
                self.audit.record(**event)
                self._metrics(job_id, cached=True, provider=hit.get('provider'), model=hit.get('model'),
                              fallback=bool(errors))
                if stream and on_chunk is not None:
                    on_chunk(answer)
                meta = hit.get('meta') or {}
                return self._result(answer, hit.get('model'), 0, anonymizer, event, route, meta.get('attempts', 1),
                                    meta.get('problems') or [], errors, cached=True)
        restorer = StreamRestorer(anonymizer)
        think = validate.ThinkFilter()
        callback = None
        if stream and on_chunk is not None:
            def callback(piece):
                text = restorer.feed(think.feed(piece))
                if text:
                    on_chunk(text)
        provider = self._provider_for(route)
        schema = task.schema if route.ollama and task.schema and getattr(provider, 'supports_format', False) else None
        try:
            event['endpoint'] = provider.endpoint()
            text, result, attempts, problems, totals = self._attempts(task, route, provider, messages, language,
                                                                      stream, callback, schema)
        except ProviderRefusal as exc:
            event.update({'status': 'refusal', 'error': str(exc)})
            self.audit.record(**event)
            raise
        except ProviderError as exc:
            event.update({'status': 'error', 'error': str(exc)})
            self.audit.record(**event)
            if job_id:
                self._metrics(job_id, provider=route.provider, model=route.model, format_ok=False,
                              fallback=bool(errors))
            raise
        if callback is not None:
            tail = restorer.feed(think.flush()) + restorer.flush()
            if tail:
                on_chunk(tail)
        meta = routing_mod.CATALOG.get(task.scenario) or {}
        hard = validate.hard_problems(problems) if task.validate and (meta.get('checks') or {}).get('publish') else []
        if hard:
            event.update({'status': 'rejected', 'model': result.model, 'duration_ms': totals['duration_ms'],
                          'response_sha256': sha256(result.text), 'response_bytes': len(result.text.encode()),
                          'prompt_tokens': totals['prompt_tokens'], 'completion_tokens': totals['completion_tokens'],
                          'stop_reason': result.done_reason, 'attempts': attempts, 'problems': problems,
                          'error': 'answer rejected: %s' % '; '.join(hard)})
            self.audit.record(**event)
            if job_id:
                self._metrics(job_id, provider=route.provider, model=result.model, format_ok=False,
                              lang_ok=False, fallback=bool(errors))
            raise AnswerRejected('answer rejected after %d attempt(s): %s' % (attempts, '; '.join(hard)))
        answer = anonymizer.deanonymize(text)
        fmt_problems = [p for p in problems if not p.startswith('the answer is not in') and 'characters' not in p]
        event.update({
            'status': 'ok',
            'model': result.model,
            'duration_ms': totals['duration_ms'],
            'response_sha256': sha256(result.text),
            'response_bytes': len(result.text.encode()),
            'prompt_tokens': totals['prompt_tokens'],
            'completion_tokens': totals['completion_tokens'],
            'usage': result.usage or None,
            'stop_reason': result.done_reason,
            'truncated': result.truncated or None,
            'attempts': attempts if attempts > 1 else None,
            'problems': problems or None,
            'structured': True if schema else None,
            'reasoning_cut': totals.get('reasoning_cut') or None,
        })
        self.audit.record(**event)
        if use_cache and not problems:
            self._jobqueue().cache_put(key, task.scenario, text, route.provider, result.model,
                                       meta={'attempts': attempts, 'problems': problems}, path=self.queue_path)
        self._metrics(job_id, provider=route.provider, model=result.model, prompt_tokens=totals['prompt_tokens'],
                      completion_tokens=totals['completion_tokens'], duration_ms=totals['duration_ms'],
                      attempts=attempts, format_ok=not fmt_problems, lang_ok=len(fmt_problems) == len(problems),
                      fallback=bool(errors))
        out = self._result(answer, result.model, totals['duration_ms'], anonymizer, event, route, attempts, problems,
                           errors)
        out['truncated'] = bool(result.truncated)
        out['usage'] = result.usage
        return out

    def _attempts(self, task, route, provider, messages, language, stream, callback, schema):
        """ first answer plus at most route.retries corrections; :return: (text, last result, n, problems, totals) """
        kwargs = {'fmt': schema} if schema and getattr(provider, 'supports_format', False) else {}
        convo = list(messages)
        best = None
        totals = {'duration_ms': 0, 'prompt_tokens': None, 'completion_tokens': None, 'reasoning_cut': 0}
        attempt = 0
        while True:
            attempt += 1
            left = self.remaining(route=True)
            if left is not None and hasattr(provider, 'timeout'):
                provider.timeout = int(max(10, min(provider.timeout or left, left)))
            result = provider.chat(convo, stream=stream and attempt == 1, on_chunk=callback if attempt == 1 else None,
                                   **kwargs)
            totals['duration_ms'] += result.duration_ms or 0
            for key, value in (('prompt_tokens', result.prompt_tokens), ('completion_tokens', result.completion_tokens)):
                if value is not None:
                    totals[key] = (totals[key] or 0) + value
            raw = validate.strip_think(result.text)
            if not schema:
                raw, leaked = validate.strip_reasoning(raw, language)
                if leaked and not validate.leaked_reasoning(raw):
                    totals['reasoning_cut'] += 1
            text = self._render(task, raw, schema)
            problems = validate.check(task.scenario, text if not schema or task.render else raw, language,
                                      task.check_ctx) if task.validate else []
            rank = (len(validate.hard_problems(problems)), len(problems))
            if best is None or rank < best[4]:
                best = (text, result, attempt, problems, rank)
            if not problems or attempt > route.retries or stream:
                break
            left = self.remaining(route=True)
            if left is not None and left < MIN_ATTEMPT_SECONDS:
                break
            if validate.REASONING_PROBLEM in problems or not raw.strip():
                # a fresh attempt: sending the leaked notes back only makes the model continue them
                convo = [dict(m) for m in messages]
                for msg in reversed(convo):
                    if msg['role'] == 'user':
                        msg['content'] = msg['content'].rstrip() + '\n\n' + validate.no_reasoning_note(language)
                        break
                continue
            convo = convo + [{'role': 'assistant', 'content': raw},
                             {'role': 'user', 'content': validate.correction(problems, language)}]
        text, result, _n, problems, _rank = best
        return text, result, attempt, problems, totals

    @staticmethod
    def _render(task, raw, schema):
        """ structured output -> the format the module expects ("MAPPING: ..." / "TYPE: ..." / JSON text) """
        if not schema:
            return raw
        try:
            doc = json.loads(raw)
        except ValueError:
            start, end = raw.find('{'), raw.rfind('}')
            try:
                doc = json.loads(raw[start:end + 1]) if start >= 0 and end > start else None
            except ValueError:
                doc = None
        if not isinstance(doc, dict):
            return raw
        if task.render is None:
            return json.dumps(doc, ensure_ascii=False)
        try:
            return task.render(doc)
        except Exception:               # noqa: BLE001 - a bad render never loses the answer
            return raw

    def _metrics(self, job_id, **m):
        if not job_id or not str(job_id).isdigit():
            return
        try:
            self._jobqueue().add_metrics(int(job_id), path=self.queue_path, **m)
        except Exception:               # noqa: BLE001
            pass

    def _result(self, answer, model, duration_ms, anonymizer, event, route, attempts, problems, errors, cached=False):
        return {
            'status': 'ok',
            'text': answer,
            'model': model,
            'duration_ms': duration_ms,
            'anonymized': anonymizer.enabled,
            'placeholders': len(anonymizer.mapping),
            'language': event['language'],
            'provider': route.provider,
            'scenario': event['scenario'],
            'route': route.label(),
            'fallback': bool(errors),
            'fallback_reason': '; '.join('%s: %s' % (r.label(), e) for r, e in errors) or None,
            'attempts': attempts,
            'problems': problems,
            'cached': cached,
            'truncated': False,
            'usage': None,
        }

    def test(self):
        """ reachability + model presence, no user data is sent """
        start = self.provider.now_ms()
        event = {'app': self.app, 'action': 'test', 'provider': self.config.provider}
        try:
            event['endpoint'] = self.provider.endpoint()
            health = self.provider.health()
            models = [m['name'] for m in self.provider.list_models()]
        except ProviderError as exc:
            event.update({'status': 'error', 'error': str(exc)})
            self.audit.record(**event)
            raise
        wanted = self.config.options.get('model') or ''
        found = bool(wanted) and (wanted in models or (':' not in wanted and wanted + ':latest' in models))
        event.update({'status': 'ok', 'duration_ms': self.provider.now_ms() - start, 'model': wanted or None})
        self.audit.record(**event)
        return {
            'status': 'ok',
            'endpoint': self.provider.endpoint(),
            'version': health.get('version'),
            'models': len(models),
            'model': wanted,
            'model_available': found,
            'duration_ms': event['duration_ms'],
        }

    def list_models(self):
        return {'status': 'ok', 'endpoint': self.provider.endpoint(), 'models': self.provider.list_models()}
