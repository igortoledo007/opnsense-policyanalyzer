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

    Ollama provider (https://github.com/ollama/ollama/blob/main/docs/api.md),
    standard library only.  Used endpoints:
        GET  /api/version   health check
        GET  /api/tags      installed models
        POST /api/chat      chat completion (optionally streamed as NDJSON); "format" with a JSON Schema
                            (structured output) and "think": false (qwen3 and other thinking models) are sent
                            when asked; num_predict / num_ctx / keep_alive come from the scenario route
        POST /api/show      capabilities and chat template of the model (once per model and process)

    Thinking models (2026-11-09, Ollama 0.34.3): "think": false (and "/no_think") only works when the template
    honours it (hybrid Qwen3 of April 2025: empty <think></think> when Think is false). The qwen3:30b-a3b tag is
    now Qwen3-30B-A3B-Thinking-2507: its template ALWAYS ends the prompt with "<|im_start|>assistant\n<think>\n",
    so the model reasons anyway and, with think=false, Ollama returns the reasoning (no opening tag) + "</think>" +
    answer in "content"; cut by num_predict, only the English reasoning. For such a model (thinking_mode() ==
    "forced") the request goes with "think": true, so Ollama moves the reasoning to message.thinking (never used
    here) and content holds only the answer, and num_predict gets THINK_BUDGET more tokens for the reasoning.
"""

import json
import os
import re
import socket
from .base import BaseProvider, GenerateResult, ProviderError

LOCAL_TIMEOUT = 360
LOCAL_NUM_PREDICT = 450
LOCAL_URL = 'http://127.0.0.1:11434'
THINK_BUDGET = 2048             # extra num_predict for the reasoning of a model that always thinks
THINK_ON_BUDGET = 3072          # default extra num_predict when a route asks for the reasoning (route: think_budget)
THINK_LEVELS = ('low', 'medium', 'high')
_SHOW_CACHE = {}                # (base_url, model) -> /api/show subset
# written by the AI setup (set_limits); threads/ctx are sent with every request to the local runtime
LIMITS_FILE = os.environ.get('POLICYANALYZER_LIMITS', '/var/db/policyanalyzer/runtime-limits.json')


def location_of(options):
    """ "local" or "lan"; accepts the pre 1.0.1 "mode" (local|network) as well """
    location = options.get('location') or ('lan' if options.get('mode') == 'network' else 'local')
    return 'lan' if location in ('lan', 'network') else 'local'


def runtime_limits(path=None):
    try:
        with open(path or LIMITS_FILE) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}
MODEL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$')
# families that may think: only these pay the /api/show request (a LAN server that is down costs its timeout)
THINKING_NAME_RE = re.compile(r'(qwen3|qwq|deepseek-r1|(^|[-_/:])r1|magistral|gpt-oss|phi4-reasoning|cogito|'
                              r'think|reason|exaone-deep|granite3\.[23])', re.I)
TEMPLATE_ACTION_RE = re.compile(r'\{\{-?\s*(.*?)\s*-?\}\}', re.S)


def forced_thinking(template, finetune=''):
    """
    True when the chat template opens <think> for the answer whatever "think" says (Qwen3 Thinking-2507) or the
    model is a "Thinking" fine-tune; False for the hybrid templates that test .Think / .IsThinkSet there
    """
    if 'thinking' in str(finetune or '').lower():
        return True
    template = str(template or '')
    pos = template.rfind('<think>')
    if pos < 0:
        return False
    # the {{ if ... }} actions open before the last <think>: forced when none of them looks at Think
    opened = []
    for match in TEMPLATE_ACTION_RE.finditer(template[:pos]):
        action = match.group(1)
        if re.match(r'^(if|range|with)\b', action):
            opened.append(action)
        elif action.startswith('else') and opened:
            opened[-1] = opened[-1] + ' ' + action
        elif action == 'end' and opened:
            opened.pop()
    return not any('Think' in a for a in opened)


class OllamaProvider(BaseProvider):
    name = 'ollama'
    supports_format = True                  # Assistant: JSON Schema output for the structured scenarios
    max_timeout = 1800
    label = 'Ollama'
    group = 'local'
    choices = (
        {'id': 'ollama', 'label': 'Ollama', 'group': 'local', 'set': {}, 'wizard': False, 'icon': 'fa-microchip',
         'help': 'Open models on this firewall or on a server in your LAN; the data stays in your network.'},
    )
    fields = (
        # "choice" fields are sub-parameters: other fields declare show_if on them
        {'id': 'location', 'label': 'Where does Ollama run?', 'type': 'choice', 'required': True, 'default': 'local',
         'options': {'local': 'On this firewall (local)', 'lan': 'On a server in my LAN'},
         'option_help': {'local': 'Uses 127.0.0.1:11434, the isolated runtime prepared by the AI setup.',
                         'lan': 'Uses an Ollama server you run elsewhere in your network.'}},
        {'id': 'runtime', 'label': 'Local runtime', 'type': 'status', 'probe': 'runtime',
         'show_if': {'location': 'local'}, 'wizard_url': '/ui/policyanalyzer/setup',
         'help': 'State of the Ollama runtime on this firewall; install, update or remove it with the AI setup.'},
        {'id': 'url', 'label': 'Server URL', 'type': 'url', 'required': True, 'show_if': {'location': 'lan'},
         'warn_public': True, 'help': 'For example http://192.168.1.10:11434'},
        {'id': 'models_dir', 'label': 'Models directory', 'type': 'text', 'default': '/var/db/ai/models',
         'show_if': {'location': 'local'}, 'storage': True,
         'help': 'Where the local runtime keeps its models (OLLAMA_MODELS).'},
        {'id': 'model', 'label': 'Model', 'type': 'text', 'required': True, 'list_models': True},
        {'id': 'ram_budget', 'label': 'RAM budget for the model', 'type': 'integer', 'default': '40',
         'min': 10, 'max': 75, 'unit': '%', 'probe': 'hw_profile', 'show_if': {'location': 'local'},
         'help': 'Share of the total RAM the local model may use (10-75 %); the recommendation follows it.'},
        {'id': 'recommend', 'label': 'Recommended for this hardware', 'type': 'recommend', 'probe': 'recommend',
         'target': 'model', 'budget': 'ram_budget', 'show_if': {'location': 'local'}},
    )
    privacy = ('Data stays on this firewall (local mode) or goes to the Ollama server you configured in your '
               'network; it is anonymized first unless anonymization is disabled.')

    def __init__(self, options, timeout=None):
        super().__init__(options, timeout)
        self.location = location_of(self.options)
        url = LOCAL_URL if self.location == 'local' else self.options.get('url')
        self.base_url = self.validate_url(url or LOCAL_URL)
        self.model = (self.options.get('model') or '').strip()
        self.temperature = float(self.options.get('temperature', 0.2))
        self.num_ctx = self.options.get('num_ctx')
        self.num_thread = self.options.get('num_thread')
        self.keep_alive = self.options.get('keep_alive')
        self.num_predict = self.options.get('num_predict')
        # thinking models (qwen3, deepseek-r1): never think, the answer must fit num_predict (None: not sent)
        try:
            self.think_budget = max(512, min(16384, int(self.options.get('think_budget') or THINK_ON_BUDGET)))
        except (TypeError, ValueError):
            self.think_budget = THINK_ON_BUDGET
        think = self.options.get('think', False)
        if isinstance(think, str) and think.strip().lower() in THINK_LEVELS:
            self.think = think.strip().lower()      # gpt-oss level, or "on" for the other thinking models
        elif isinstance(think, str) and think.strip().lower() == 'on':
            self.think = True
        else:
            self.think = None if think in (None, '') else bool(think) and \
                str(think).lower() not in ('0', 'false', 'no', 'off')
        self.last_think = None
        if self.location == 'local':
            # CPU only, a few cores: prompt + answer of one finding take 1-3 minutes
            if not timeout:
                self.timeout = LOCAL_TIMEOUT
            limits = runtime_limits(self.options.get('limits_file'))
            if not self.num_thread and str(limits.get('threads', '')).isdigit():
                self.num_thread = int(limits['threads'])
            if not self.num_ctx and str(limits.get('ctx', '')).isdigit():
                self.num_ctx = int(limits['ctx'])

    def endpoint(self):
        return self.base_url

    def _get_json(self, path, timeout=None):
        with self._open(self.base_url + path, timeout=timeout) as response:
            try:
                return json.loads(self._read_limited(response))
            except ValueError:
                raise ProviderError('endpoint did not return JSON, is this an Ollama server?')

    def health(self):
        # a short timeout, this is only a reachability test
        data = self._get_json('/api/version', timeout=min(self.timeout, 10))
        if not isinstance(data, dict) or 'version' not in data:
            raise ProviderError('unexpected answer from /api/version, is this an Ollama server?')
        return {'version': data['version']}

    def list_models(self):
        data = self._get_json('/api/tags', timeout=min(self.timeout, 30))
        result = []
        for item in (data.get('models') or []) if isinstance(data, dict) else []:
            if not isinstance(item, dict) or not item.get('name'):
                continue
            details = item.get('details') or {}
            result.append({
                'name': str(item.get('name')),
                'size': item.get('size'),
                'modified': item.get('modified_at'),
                'family': details.get('family'),
                'parameters': details.get('parameter_size'),
                'quantization': details.get('quantization_level'),
            })
        result.sort(key=lambda x: x['name'])
        return result

    def model_info(self):
        """ capabilities, template and general.finetune of the model (cached; {} when unknown) """
        key = (self.base_url, self.model)
        if key not in _SHOW_CACHE:
            info = {}
            try:
                with self._open(self.base_url + '/api/show', {'model': self.model},
                                timeout=min(self.timeout or 10, 10)) as response:
                    doc = json.loads(self._read_limited(response))
                if isinstance(doc, dict):
                    info = {'capabilities': [str(c) for c in doc.get('capabilities') or [] if isinstance(c, str)],
                            'template': str(doc.get('template') or '')[:20000],
                            'finetune': str((doc.get('model_info') or {}).get('general.finetune') or '')}
            except (ProviderError, ValueError, OSError, socket.timeout):
                info = {}
            _SHOW_CACHE[key] = info
        return _SHOW_CACHE[key]

    def thinking_mode(self):
        """ "none" | "optional" (think=false works) | "forced" (the template always opens <think>) """
        if not THINKING_NAME_RE.search(self.model or ''):
            return 'none'
        info = self.model_info()
        if 'thinking' not in (info.get('capabilities') or []):
            return 'none'
        return 'forced' if forced_thinking(info.get('template'), info.get('finetune')) else 'optional'

    def supports_thinking(self):
        """ the model declares the thinking capability (/api/show), whatever its name """
        return 'thinking' in (self.model_info().get('capabilities') or [])

    def _payload(self, messages, stream, fmt=None):
        if not self.model or not MODEL_RE.match(self.model):
            raise ProviderError('no (valid) model configured')
        think = self.think
        extra = 0
        if think not in (None, False):
            # reasoning asked by the route: only for a model that can think (Ollama rejects think=true otherwise);
            # a level goes as is to gpt-oss (harmony), the other models take think=true
            if not self.supports_thinking():
                think = False
            else:
                if think in THINK_LEVELS and 'gpt-oss' not in (self.model or '').lower():
                    think = True
                extra = self.think_budget
        if think is False and self.thinking_mode() == 'forced':
            think, extra = True, THINK_BUDGET       # think=false is ignored: let Ollama separate the reasoning
        self.last_think = think
        options = {'temperature': self.temperature}
        if self.num_predict:
            options['num_predict'] = int(self.num_predict) + extra
        elif self.location == 'local':
            options['num_predict'] = LOCAL_NUM_PREDICT + extra  # bounded answer, predictable time per finding
        if self.num_ctx:
            options['num_ctx'] = int(self.num_ctx)
        if self.num_thread:
            options['num_thread'] = int(self.num_thread)
        payload = {'model': self.model, 'messages': messages, 'stream': bool(stream), 'options': options}
        if self.keep_alive not in (None, ''):
            payload['keep_alive'] = self.keep_alive
        if think is not None:
            payload['think'] = think
        if fmt:
            payload['format'] = fmt
        return payload

    def chat(self, messages, stream=False, on_chunk=None, fmt=None):
        """ :param fmt: JSON Schema (dict) or "json": structured output """
        start = self.now_ms()
        deadline = start + self.timeout * 1000
        payload = self._payload(messages, stream, fmt)
        parts = []
        total = 0
        last = {}
        try:
            with self._open(self.base_url + '/api/chat', payload) as response:
                if not stream:
                    try:
                        last = json.loads(self._read_limited(response))
                    except ValueError:
                        raise ProviderError('endpoint did not return JSON')
                    if last.get('error'):
                        raise ProviderError(str(last['error']))
                    parts.append((last.get('message') or {}).get('content', ''))
                else:
                    for line in response:
                        total += len(line)
                        if total > self.max_response_bytes:
                            raise ProviderError('answer exceeds %d bytes' % self.max_response_bytes)
                        if self.now_ms() > deadline:
                            raise ProviderError('timeout after %d seconds' % self.timeout)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except ValueError:
                            raise ProviderError('malformed streaming answer')
                        if item.get('error'):
                            raise ProviderError(str(item['error']))
                        piece = (item.get('message') or {}).get('content', '')
                        if piece:
                            parts.append(piece)
                            if on_chunk is not None:
                                on_chunk(piece)
                        if item.get('done'):
                            last = item
                            break
        except (socket.timeout, TimeoutError):
            raise ProviderError('timeout after %d seconds' % self.timeout)
        return GenerateResult(
            text=''.join(parts),
            model=last.get('model', self.model),
            duration_ms=self.now_ms() - start,
            prompt_tokens=last.get('prompt_eval_count'),
            completion_tokens=last.get('eval_count'),
            done_reason=last.get('done_reason'),
        )
