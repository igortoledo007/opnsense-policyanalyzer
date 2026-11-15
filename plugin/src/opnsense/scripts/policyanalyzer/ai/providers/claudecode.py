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

    Claude Code (LAN) provider: Claude through the Claude Code subscription of
    a computer in the user's network, reached via a small HTTP bridge that runs
    there (claude-bridge).  Standard library only, no streaming.

        GET  {base}/health    reachability, token check, models
        POST {base}/v1/chat   {"model", "messages", "timeout"} -> {"status": "ok", "text", "model", "usage"}

    Authentication is "Authorization: Bearer <token>"; the token is never
    logged or returned.  Errors come as {"status": "error"|"busy", "message"}
    with HTTP 4xx/5xx (401 token, 403 source address, 413 body > 256 KiB,
    429 queue full).  No proxies and no redirects (see BaseProvider).
"""

import json
import re
import socket

from .base import BaseProvider, GenerateResult, ProviderError, ProviderHTTPError

DEFAULT_URL = 'http://bridge.example.lan:11436'
SERVICE = 'claude-bridge'
MODELS = ('fable', 'opus', 'sonnet', 'haiku')
MODEL_LABELS = {
    'fable': 'Fable — most capable, uses the quota fastest',
    'opus': 'Opus — balanced, uses the quota fast',
    'sonnet': 'Sonnet — fast (recommended)',
    'haiku': 'Haiku — fastest, lightest on the quota',
}
DEFAULT_MODEL = 'sonnet'
DEFAULT_TIMEOUT = 300
HEALTH_TIMEOUT = 10
# seconds we wait beyond the timeout handed to the bridge, so the bridge reports its own timeout first
TIMEOUT_MARGIN = 15
MAX_REQUEST_BYTES = 256 * 1024
TOKEN_RE = re.compile(r'^[A-Za-z0-9._~+/=-]{16,512}$')


def _bridge_message(detail):
    """ {"status": "error", "message": "..."} -> message; anything else is returned as is """
    try:
        data = json.loads(detail)
    except (TypeError, ValueError):
        return detail or ''
    if isinstance(data, dict):
        return str(data.get('message') or data.get('error') or detail)
    return detail or ''


class ClaudeCodeProvider(BaseProvider):
    name = 'claudecode'
    default_timeout = DEFAULT_TIMEOUT
    label = 'Claude Code (LAN)'
    group = 'local'
    # the data does leave the network (bridge -> Anthropic): the GUI shows the privacy note as a warning
    privacy_warn = True
    choices = (
        {'id': 'claudecode', 'label': 'Claude Code (LAN)', 'group': 'local', 'set': {}, 'wizard': False,
         'icon': 'fa-laptop', 'badge': 'LAN',
         'help': 'Claude through the Claude Code subscription of a computer in your LAN that runs the '
                 'claude-bridge; no API key needed on this firewall.'},
    )
    fields = (
        {'id': 'url', 'label': 'Bridge URL', 'type': 'url', 'required': True, 'default': DEFAULT_URL,
         'warn_public': True,
         'help': 'Address of the claude-bridge on the computer in your LAN, for example %s.' % DEFAULT_URL},
        {'id': 'token', 'label': 'Bridge token', 'type': 'password', 'required': True, 'secret': True,
         'help': 'Bearer token configured on the bridge. Stored in the configuration, never shown again; '
                 'leave empty to keep the current token.'},
        {'id': 'model', 'label': 'Model', 'type': 'dropdown', 'required': True, 'default': DEFAULT_MODEL,
         'options': {m: MODEL_LABELS[m] for m in MODELS}, 'list_models': True,
         'help': 'Uses the Claude plan quota of the owner of the LAN computer; Fable and Opus use the quota '
                 'up faster.'},
    )
    privacy = ('The data (anonymized, if the option is enabled) goes to the computer in your network that runs '
               'the bridge, and from there to Anthropic through the Claude Code subscription of its owner.')

    def __init__(self, options, timeout=None):
        super().__init__(options, timeout)
        self.base_url = self.validate_url(self.options.get('url') or DEFAULT_URL)
        self.token = (self.options.get('token') or '').strip()
        model = (self.options.get('model') or DEFAULT_MODEL).strip()
        self.model = model if model in MODELS else DEFAULT_MODEL
        try:
            self.margin = max(0.0, float(self.options.get('timeout_margin', TIMEOUT_MARGIN)))
        except (TypeError, ValueError):
            self.margin = TIMEOUT_MARGIN

    @classmethod
    def describe(cls):
        data = super().describe()
        data['privacy_warn'] = cls.privacy_warn
        return data

    def endpoint(self):
        return self.base_url

    def _headers(self):
        if not self.token:
            raise ProviderError('no bridge token configured')
        if not TOKEN_RE.match(self.token):
            raise ProviderError('the configured bridge token has an invalid format')
        return {'Authorization': 'Bearer %s' % self.token}

    @staticmethod
    def _explain_http(exc):
        message = _bridge_message(exc.detail)
        if exc.code == 401:
            return ProviderError('the bridge rejected the token (HTTP 401): check the token')
        if exc.code == 403:
            return ProviderError('the bridge does not accept requests from this firewall (HTTP 403): '
                                 'allow its address on the bridge')
        if exc.code == 404:
            return ProviderError('not found (HTTP 404): is this a Claude Code bridge?')
        if exc.code == 413:
            return ProviderError('the request is too large for the bridge (HTTP 413, limit 256 KiB)')
        if exc.code == 429:
            return ProviderError('the Claude Code bridge is busy (%s), try again in a moment' % (message or 'queue full'))
        if exc.code >= 500:
            return ProviderError('Claude Code bridge error (HTTP %d): %s' % (exc.code, message or 'no details'))
        return ProviderError('Claude Code bridge error (HTTP %d): %s' % (exc.code, message))

    def _request(self, path, payload=None, timeout=None):
        try:
            with self._open(self.base_url + path, payload, timeout=timeout,
                            extra_headers=self._headers()) as response:
                raw = self._read_limited(response)
        except ProviderHTTPError as exc:
            raise self._explain_http(exc)
        except (socket.timeout, TimeoutError):
            raise ProviderError('timeout after %d seconds' % (timeout or self.timeout))
        try:
            data = json.loads(raw)
        except ValueError:
            raise ProviderError('the endpoint did not return JSON, is this a Claude Code bridge?')
        if not isinstance(data, dict):
            raise ProviderError('unexpected answer from the bridge')
        if data.get('status') != 'ok':
            raise ProviderError('Claude Code bridge: %s' % (data.get('message') or data.get('status') or 'error'))
        return data

    def _health(self):
        data = self._request('/health', timeout=min(self.timeout, HEALTH_TIMEOUT))
        if data.get('service') != SERVICE:
            raise ProviderError('unexpected answer from /health, is this a Claude Code bridge?')
        return data

    def health(self):
        data = self._health()
        return {
            'version': str(data.get('claude_version') or 'claude-bridge %s' % data.get('version', '?')),
            'bridge_version': data.get('version'),
            'busy': bool(data.get('busy')),
            'default_model': data.get('default_model'),
        }

    def list_models(self):
        data = self._health()
        result = []
        for name in data.get('models') or []:
            if isinstance(name, str) and name:
                result.append({'name': name, 'label': MODEL_LABELS.get(name), 'size': None, 'modified': None,
                               'family': 'claude', 'parameters': None, 'quantization': None})
        return result

    def build_payload(self, messages):
        convo = [{'role': m['role'], 'content': m['content']} for m in messages
                 if m.get('role') in ('system', 'user', 'assistant')]
        if not convo or convo[-1]['role'] != 'user':
            raise ProviderError('the last message must come from the user')
        payload = {'model': self.model, 'messages': convo, 'timeout': int(self.timeout)}
        if len(json.dumps(payload).encode()) > MAX_REQUEST_BYTES:
            raise ProviderError('the request exceeds the 256 KiB limit of the bridge')
        return payload

    def chat(self, messages, stream=False, on_chunk=None):
        """ no streaming: with stream=True on_chunk receives the complete answer once """
        start = self.now_ms()
        payload = self.build_payload(messages)
        data = self._request('/v1/chat', payload, timeout=self.timeout + self.margin)
        text = data.get('text')
        if not isinstance(text, str):
            raise ProviderError('unexpected answer from the bridge (no text)')
        usage = data.get('usage') if isinstance(data.get('usage'), dict) else {}
        usage = {k: usage[k] for k in ('input_tokens', 'output_tokens', 'cache_read_input_tokens',
                                        'cache_creation_input_tokens') if usage.get(k) is not None}
        if stream and on_chunk is not None and text:
            on_chunk(text)
        return GenerateResult(
            text=text,
            model=data.get('model') or self.model,
            duration_ms=self.now_ms() - start,
            prompt_tokens=usage.get('input_tokens'),
            completion_tokens=usage.get('output_tokens'),
            done_reason=data.get('stop_reason'),
            usage=usage,
        )
