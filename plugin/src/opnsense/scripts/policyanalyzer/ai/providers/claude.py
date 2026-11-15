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

    Claude provider (Anthropic Messages API), standard library only.

        GET  /v1/models      key check and model list
        POST /v1/messages    explanation

    The official SDK exists in ports (misc/py-anthropic) but pulls in a large
    dependency tree (httpx, pydantic, ...); a plugin should stay on the base
    system, so this module speaks the HTTP API directly.  The API key is only
    ever placed in the x-api-key header: it is never logged or returned.
"""

import json
import re
import socket
import time

from .base import BaseProvider, GenerateResult, ProviderError, ProviderHTTPError, ProviderRefusal

API_URL = 'https://api.anthropic.com'
API_VERSION = '2026-10-21'
FALLBACK_BETA = 'server-side-fallback-2026-07-01'
# id -> label shown in the GUI (with list prices per million input/output tokens)
MODEL_LABELS = {
    'claude-fable-5-1': 'Fable 5.1 \u2014 most capable (US$10/50 per MTok in/out)',
    'claude-opus-5-5': 'Opus 5.5 \u2014 balanced (US$4/20)',
    'claude-sonnet-5-5': 'Sonnet 5.5 \u2014 fast (US$2/10)',
    'claude-haiku-5-5': 'Haiku 5.5 \u2014 cheapest (US$0.10/0.50)',
}
MODELS = ('claude-fable-5-1', 'claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5')
DEFAULT_MODEL = 'claude-fable-5-1'
FALLBACK_MODELS = ('claude-fable-5-1', 'claude-opus-5-5', 'claude-sonnet-5-5')
EFFORTS = ('low', 'medium', 'high', 'xhigh', 'max')
DEFAULT_EFFORT = 'high'
RETENTION_RE = re.compile(r'retention', re.I)
MAX_TOKENS = 16000
KEY_RE = re.compile(r'^[A-Za-z0-9_-]{20,256}$')


class ClaudeProvider(BaseProvider):
    name = 'claude'
    default_timeout = 180           # Fable can take longer per answer
    label = 'Claude (Anthropic)'
    group = 'api'
    choices = (
        {'id': 'claude', 'label': 'Claude (Anthropic API)', 'group': 'api', 'set': {}, 'wizard': False,
         'icon': 'fa-cloud',
         'help': 'Uses the Anthropic API with your own API key; the data leaves this firewall.'},
    )
    fields = (
        {'id': 'apikey', 'label': 'API key', 'type': 'password', 'required': True, 'secret': True,
         'help': 'Stored in the configuration, never shown again; leave empty to keep the current key.'},
        {'id': 'model', 'label': 'Model', 'type': 'dropdown', 'required': True, 'default': DEFAULT_MODEL,
         'options': {m: MODEL_LABELS[m] for m in MODELS}, 'list_models': True,
         'help': 'Fable needs 30 day data retention on your Anthropic organization; with zero data retention '
                 'choose Opus 5.5.'},
        {'id': 'effort', 'label': 'Effort', 'type': 'dropdown', 'required': True, 'default': DEFAULT_EFFORT,
         'options': {'low': 'Low', 'medium': 'Medium', 'high': 'High', 'xhigh': 'Extra high', 'max': 'Max'},
         'help': 'Higher effort gives more thorough answers but takes longer and uses more tokens.'},
    )
    privacy = ('With Claude, the data of the finding leaves this firewall and is sent to the Anthropic API '
               '(api.anthropic.com). It is anonymized first unless anonymization is disabled.')

    def __init__(self, options, timeout=None):
        super().__init__(options, timeout)
        base = self.options.get('base_url') or API_URL
        self.base_url = self.validate_url(base)
        if not self.base_url.startswith('https://') and not self.base_url.startswith('http://127.0.0.1'):
            raise ProviderError('the Anthropic API is only reachable over https')
        self.apikey = (self.options.get('apikey') or '').strip()
        self.model = (self.options.get('model') or DEFAULT_MODEL).strip()
        self.effort = self.options.get('effort') if self.options.get('effort') in EFFORTS else DEFAULT_EFFORT
        self.max_tokens = int(self.options.get('max_tokens') or MAX_TOKENS)
        self.retry_cap = float(self.options.get('retry_cap', 30))

    def endpoint(self):
        return self.base_url

    def _headers(self, beta=False):
        if not self.apikey:
            raise ProviderError('no API key configured')
        if not KEY_RE.match(self.apikey):
            raise ProviderError('the configured API key has an invalid format')
        headers = {'x-api-key': self.apikey, 'anthropic-version': API_VERSION, 'content-type': 'application/json'}
        if beta:
            headers['anthropic-beta'] = FALLBACK_BETA
        return headers

    @staticmethod
    def _explain_http(exc):
        if exc.code in (401, 403):
            return ProviderError('the API key was rejected (HTTP %d): %s' % (exc.code, exc.detail or 'check the key'))
        if exc.code == 429:
            return ProviderError('rate limited by the Anthropic API (HTTP 429), try again later')
        if exc.code == 529 or exc.code >= 500:
            return ProviderError('the Anthropic API is overloaded or unavailable (HTTP %d), try again later' % exc.code)
        if exc.code == 400 and RETENTION_RE.search(exc.detail or ''):
            return ProviderError('this model is not available under zero data retention; choose Opus 5.5')
        if exc.code == 404:
            return ProviderError('not found (HTTP 404): %s' % (exc.detail or 'unknown model?'))
        return ProviderError('Anthropic API error (HTTP %d): %s' % (exc.code, exc.detail))

    def _request(self, path, payload=None, beta=False, deadline=None):
        """ one retry on 429 (honouring retry-after) and on 5xx/529 (backoff) """
        attempt = 0
        while True:
            remaining = self.timeout if deadline is None else max(1, (deadline - self.now_ms()) / 1000.0)
            try:
                response = self._open(self.base_url + path, payload, timeout=remaining,
                                      extra_headers=self._headers(beta))
                with response:
                    return json.loads(self._read_limited(response))
            except ProviderHTTPError as exc:
                retryable = exc.code == 429 or exc.code == 529 or exc.code >= 500
                if not retryable or attempt >= 1:
                    raise self._explain_http(exc)
                wait = 2.0
                if exc.code == 429:
                    try:
                        wait = float(exc.headers.get('retry-after', 2))
                    except (TypeError, ValueError):
                        wait = 2.0
                wait = min(max(wait, 0.0), self.retry_cap)
                if deadline is not None and self.now_ms() + wait * 1000 >= deadline:
                    raise self._explain_http(exc)
                time.sleep(wait)
                attempt += 1
            except ValueError:
                raise ProviderError('the Anthropic API did not return JSON')
            except (socket.timeout, TimeoutError):
                raise ProviderError('timeout after %d seconds' % self.timeout)

    def health(self):
        self._request('/v1/models?limit=1')
        return {'version': 'anthropic-version %s' % API_VERSION}

    def list_models(self):
        data = self._request('/v1/models?limit=100')
        result = []
        for item in data.get('data') or []:
            if isinstance(item, dict) and item.get('id'):
                result.append({'name': item['id'], 'label': item.get('display_name'),
                               'modified': item.get('created_at'), 'size': None, 'family': 'claude',
                               'parameters': None, 'quantization': None})
        result.sort(key=lambda x: x['name'])
        return result

    def build_payload(self, messages):
        system = '\n\n'.join(m['content'] for m in messages if m['role'] == 'system')
        convo = [{'role': m['role'], 'content': m['content']} for m in messages if m['role'] != 'system']
        if not convo or convo[-1]['role'] != 'user':
            raise ProviderError('the last message must come from the user (no prefill)')
        payload = {
            'model': self.model,
            'max_tokens': self.max_tokens,
            # fixed text only, so consecutive explanations reuse the prompt cache.
            # Never sent: thinking (any form), temperature/top_p/top_k, tool_choice, assistant prefill.
            'system': [{'type': 'text', 'text': system, 'cache_control': {'type': 'ephemeral'}}],
            'messages': convo,
            'output_config': {'effort': self.effort},
        }
        beta = self.model in FALLBACK_MODELS
        if beta:
            payload['fallbacks'] = 'default'
        return payload, beta

    def chat(self, messages, stream=False, on_chunk=None):
        start = self.now_ms()
        payload, beta = self.build_payload(messages)
        data = self._request('/v1/messages', payload, beta=beta, deadline=start + self.timeout * 1000)
        stop = data.get('stop_reason')
        usage = data.get('usage') or {}
        usage = {k: usage.get(k) for k in ('input_tokens', 'output_tokens', 'cache_read_input_tokens',
                                            'cache_creation_input_tokens') if usage.get(k) is not None}
        if stop == 'refusal':
            details = data.get('stop_details') or {}
            raise ProviderRefusal('the model declined to answer (%s): %s' % (
                details.get('category') or 'refusal', details.get('explanation') or 'no explanation given'))
        text = ''.join(b.get('text', '') for b in data.get('content') or []
                       if isinstance(b, dict) and b.get('type') == 'text')
        if stream and on_chunk is not None and text:
            on_chunk(text)
        return GenerateResult(
            text=text,
            model=data.get('model', self.model),
            duration_ms=self.now_ms() - start,
            prompt_tokens=usage.get('input_tokens'),
            completion_tokens=usage.get('output_tokens'),
            done_reason=stop,
            usage=usage,
            truncated=(stop == 'max_tokens'),
        )
