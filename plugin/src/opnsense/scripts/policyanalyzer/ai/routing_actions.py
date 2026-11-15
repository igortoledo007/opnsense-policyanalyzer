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

    Change actions of the AI routing (registered in changes.py, so the GUI
    simulation dialog, the action history and revert work as for every other
    change):

        ai_routing <scenario id> <provider=..+model=..+mode=..+timeout=..+num_ctx=..+num_predict=..+
                                  keep_alive=..+budget=..+retries=..|reset>
        ai_routing preset <local_only|hybrid|global>
        ai_routing fallback <auto|none|provider=claudecode+model=fable>
        ai_queue_schedule <create|remove>     cron job (*/5) "policyanalyzer ai_queue_work", via the core model

    ai_routing only writes /var/db/policyanalyzer/ai-routing.json (0640); its revert puts the previous file back
    (or removes it).  Nothing else of the firewall changes.
"""

import hashlib
import json
import os
import subprocess
import xml.etree.ElementTree as ET

from . import scenarios
from .config import CONFIG_XML, AIConfig

MOUNT = 'OPNsense/policyanalyzer'
MODELS_DIR = os.environ.get('POLICYANALYZER_MODELS_DIR', '/var/db/ai/models')
MODEL_PHP = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model.php')
CRON_COMMAND = 'policyanalyzer ai_queue_work'
PHP = '/usr/local/bin/php'
CONFIGCTL = '/usr/local/sbin/configctl'


def _sha(text):
    return hashlib.sha256((text or '').encode()).hexdigest() if text is not None else None


def installed_models(models_dir=None):
    """ local Ollama models from the manifests on disk (no request to the runtime) """
    base = os.path.join(models_dir or MODELS_DIR, 'manifests', 'registry.ollama.ai', 'library')
    out = set()
    try:
        for name in os.listdir(base):
            for tag in os.listdir(os.path.join(base, name)):
                out.add('%s:%s' % (name, tag))
    except OSError:
        pass
    return out


def describe_entry(entry):
    if not entry:
        return 'global provider (settings)'
    parts = [entry.get('provider', 'global provider')]
    if entry.get('model'):
        parts.append(entry['model'])
    parts.append(entry.get('mode', 'sync'))
    if entry.get('timeout'):
        parts.append('%d s' % entry['timeout'])
    return ', '.join(str(p) for p in parts)


def new_routing(current, target, spec):
    """ :return: (routing, args) for the change; raises ValueError """
    routing = json.loads(json.dumps(current))
    if target == 'preset':
        if spec not in scenarios.PRESETS:
            raise ValueError('preset must be one of: %s' % ', '.join(scenarios.PRESETS))
        routing['scenarios'] = scenarios.preset_scenarios(spec)
        routing['preset'] = None if spec == 'global' else spec
        return routing, {'target': 'preset', 'preset': spec}
    if target == 'fallback':
        if spec in ('auto', 'none'):
            routing['fallback'] = {'provider': spec, 'model': ''}
        else:
            fields = {}
            for part in (spec or '').split('+'):
                if '=' not in part:
                    raise ValueError('fallback: expected auto, none or provider=..+model=..')
                key, value = part.split('=', 1)
                if key not in ('provider', 'model'):
                    raise ValueError('fallback: unknown field "%s"' % key)
                fields[key] = value
            routing['fallback'] = scenarios.validate_fallback(fields)
        return routing, {'target': 'fallback', 'fallback': routing['fallback']}
    if target not in scenarios.CATALOG:
        raise ValueError('unknown scenario "%s"' % target)
    if spec == 'reset':
        routing['scenarios'].pop(target, None)
    else:
        routing['scenarios'][target] = scenarios.parse_spec(spec)
    routing['preset'] = 'custom' if routing['scenarios'] else None
    return routing, {'target': target, 'spec': spec}


def plan_changes(current, routing, config, models=None):
    steps, warnings = [], []
    models = installed_models() if models is None else models
    for sid in scenarios.CATALOG:
        before = current['scenarios'].get(sid) or {}
        after = routing['scenarios'].get(sid) or {}
        if before == after:
            continue
        steps.append({'description': '%s: %s' % (sid, describe_entry(after)),
                      'command': 'ai-routing.json: scenarios.%s = %s' % (
                          sid, scenarios.format_spec(after) if after else '(removed: global provider)'),
                      'effect': 'before: %s' % describe_entry(before)})
        route = scenarios.resolve(sid, config, routing=routing)
        if route.local and route.model and models and route.model not in models and \
                (':' in route.model or route.model + ':latest' not in models):
            warnings.append('%s uses %s, which is not installed in the local runtime (AI setup, step 5)'
                            % (sid, route.model))
        if route.provider == 'claudecode' and not route.options.get('token'):
            warnings.append('%s uses Claude Code (LAN) but no bridge token is configured' % sid)
        if route.provider == 'claude' and not route.options.get('apikey'):
            warnings.append('%s uses Claude but no API key is configured' % sid)
    if current.get('fallback') != routing.get('fallback'):
        steps.append({'description': 'fallback provider: %s' % _fb(routing['fallback']),
                      'command': 'ai-routing.json: fallback = %s' % json.dumps(routing['fallback']),
                      'effect': 'before: %s' % _fb(current.get('fallback'))})
    if routing.get('fallback', {}).get('provider') == 'auto' and not scenarios.runtime_installed():
        warnings.append('fallback "auto" needs the local runtime (AI setup); without it there is no fallback')
    if any((routing['scenarios'].get(s) or {}).get('mode') == 'queue' for s in scenarios.CATALOG) and \
            not cron_jobs():
        warnings.append('queued scenarios start the worker on demand; the cron job of the queue '
                        '(ai_queue_schedule create) is a safety net that resumes jobs after a reboot')
    distinct = {}
    for sid in scenarios.CATALOG:
        route = scenarios.resolve(sid, config, routing=routing)
        if route.local and route.model:
            distinct.setdefault(route.model, set()).add(route.num_ctx or 'runtime default')
    for model, ctxs in distinct.items():
        if len(ctxs) > 1:
            warnings.append('%s is used with different num_ctx values (%s): Ollama reloads the model at every '
                            'change' % (model, ', '.join(str(c) for c in sorted(ctxs, key=str))))
    if len(distinct) > 1:
        warnings.append('two local models (%s): with one loaded model at a time (runtime limits) switching costs '
                        'a reload (about 10 s for qwen2.5:3b, 40 s for qwen3:30b-a3b)' % ', '.join(sorted(distinct)))
    return steps, warnings


def _fb(value):
    value = value or {}
    if value.get('provider') in (None, '', 'auto'):
        return 'auto (local Ollama when installed)'
    if value.get('provider') == 'none':
        return 'none'
    return '%s %s' % (value.get('provider'), value.get('model') or '')


def cron_jobs(config_xml=None):
    try:
        root = ET.parse(config_xml or CONFIG_XML).getroot()
    except (OSError, ET.ParseError):
        return []
    out = []
    for node in root.findall('./OPNsense/cron/jobs/job'):
        if (node.findtext('command') or '').strip() == CRON_COMMAND:
            out.append({'uuid': node.get('uuid'), 'minutes': node.findtext('minutes'),
                        'enabled': (node.findtext('enabled') or '1') != '0'})
    return out


def _run(argv, timeout=120):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                          stdin=subprocess.DEVNULL)
    out = proc.stdout.decode('utf-8', 'replace')
    if proc.returncode != 0:
        raise ValueError('%s failed: %s' % (' '.join(argv), (proc.stderr.decode('utf-8', 'replace') or out)[:300]))
    return out


def register(changes):
    @changes.register
    class AiRouting(changes.ChangeAction):
        name = 'ai_routing'
        description = 'AI per scenario: provider, model, limits and queue of one scenario, a preset or the fallback'
        PATH = None              # tests

        def parse_args(self, args):
            args = [a for a in args if a]
            if len(args) != 2:
                raise ValueError('usage: ai_routing <scenario|preset|fallback> <value>')
            return {'target': args[0], 'spec': args[1]}

        def _compute(self, target, spec):
            current = scenarios.load_routing(self.PATH)
            routing, args = new_routing(current, target, spec)
            config = AIConfig.from_opnsense(MOUNT)
            return current, routing, args, config

        def plan(self, target, spec):
            current, routing, args, config = self._compute(target, spec)
            steps, warnings = plan_changes(current, routing, config)
            return {'status': 'ok', 'args': args, 'steps': steps, 'warnings': warnings, 'irreversible': [],
                    'revert': ['Revert puts the previous per scenario settings back (%s)' % (
                        'the file did not exist: it is removed' if scenarios.raw_file(self.PATH) is None
                        else 'previous ai-routing.json')],
                    'risk': 'low' if steps else 'none',
                    'info': [{'title': 'Effect', 'items': [
                        'Only /var/db/policyanalyzer/ai-routing.json is written; the next AI request of each '
                        'scenario uses it. Queued scenarios answer in the background (the module shows the '
                        'position in the queue and the estimate).']}]}

        def apply(self, target, spec):
            current, routing, args, config = self._compute(target, spec)
            steps, warnings = plan_changes(current, routing, config)
            if not steps:
                return {'status': 'ok', 'args': args, 'steps': [], 'warnings': warnings, 'done': True,
                        'completed': []}
            previous = scenarios.raw_file(self.PATH)
            scenarios.write_routing(routing, self.PATH, config)
            written = scenarios.raw_file(self.PATH)
            return {'status': 'ok', 'args': args, 'steps': steps, 'warnings': warnings, 'done': True,
                    'completed': [s['description'] for s in steps],
                    'state': {'previous': previous, 'written_sha256': _sha(written)}}

        def revert_plan(self, entry):
            state = entry.get('state') or {}
            now = scenarios.raw_file(self.PATH)
            warnings = []
            if _sha(now) != state.get('written_sha256'):
                warnings.append('the per scenario settings were changed again after this change; the revert '
                                'still restores the version before it')
            if state.get('previous') is None:
                step = {'description': 'Remove ai-routing.json (every scenario follows the global provider)',
                        'command': 'rm /var/db/policyanalyzer/ai-routing.json', 'effect': 'routing as before'}
            else:
                step = {'description': 'Restore the previous ai-routing.json',
                        'command': 'write /var/db/policyanalyzer/ai-routing.json', 'effect': 'routing as before'}
            return {'status': 'ok', 'steps': [step], 'warnings': warnings, 'irreversible': [], 'risk': 'low'}

        def revert_apply(self, entry):
            plan = self.revert_plan(entry)
            state = entry.get('state') or {}
            path = self.PATH or scenarios.ROUTING_FILE
            if state.get('previous') is None:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            else:
                tmp = path + '.tmp'
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
                with os.fdopen(fd, 'w') as handle:
                    handle.write(state['previous'])
                os.replace(tmp, path)
            plan.update(done=True, completed=[s['description'] for s in plan['steps']])
            return plan

    @changes.register
    class AiQueueSchedule(changes.ChangeAction):
        name = 'ai_queue_schedule'
        description = 'AI queue: cron job every 5 minutes that resumes queued AI jobs (policyanalyzer ai_queue_work)'
        RUN = staticmethod(_run)            # tests
        JOBS = staticmethod(cron_jobs)

        def parse_args(self, args):
            args = [a for a in args if a]
            if len(args) != 1 or args[0] not in ('create', 'remove'):
                raise ValueError('usage: ai_queue_schedule <create|remove>')
            return {'op': args[0]}

        def plan(self, op):
            jobs = self.JOBS()
            steps = []
            if op == 'create' and not jobs:
                steps = [{'description': 'Add the cron job */5 * * * * "%s"' % CRON_COMMAND,
                          'command': 'model.php cron_set ai_queue */5 *', 'effect': 'System: Settings: Cron'},
                         {'description': 'Apply the cron configuration', 'command': 'configctl cron restart',
                          'effect': 'cron reloads its table'}]
            elif op == 'remove' and jobs:
                steps = [{'description': 'Remove the cron job of the AI queue', 'command': 'model.php cron_del ai_queue',
                          'effect': 'queued jobs then only start on demand'},
                         {'description': 'Apply the cron configuration', 'command': 'configctl cron restart',
                          'effect': 'cron reloads its table'}]
            return {'status': 'ok', 'args': {'op': op}, 'steps': steps, 'warnings': [], 'irreversible': [],
                    'revert': ['Revert %s the cron job' % ('removes' if op == 'create' else 'adds back')],
                    'risk': 'low' if steps else 'none'}

        def apply(self, op):
            plan = self.plan(op)
            if not plan['steps']:
                return dict(plan, done=True, completed=[])
            self.RUN([PHP, MODEL_PHP, 'cron_set' if op == 'create' else 'cron_del', 'ai_queue'])
            self.RUN([CONFIGCTL, 'cron', 'restart'])
            return dict(plan, done=True, completed=[s['description'] for s in plan['steps']], state={'op': op})

        def revert_plan(self, entry):
            op = (entry.get('state') or {}).get('op') or (entry.get('args') or {}).get('op')
            return self.plan('remove' if op == 'create' else 'create')

        def revert_apply(self, entry):
            op = (entry.get('state') or {}).get('op') or (entry.get('args') or {}).get('op')
            return self.apply('remove' if op == 'create' else 'create')
