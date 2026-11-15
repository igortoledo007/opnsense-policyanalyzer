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

    Provider interface.  A provider only talks to a model endpoint; it never
    sees configuration outside its own options, never anonymizes and never
    writes audit records (the Assistant does that).
"""

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


class ProviderError(Exception):
    """ any failure talking to the model endpoint, message is safe to show in the GUI """


# OPNsense trust store, used when Python's own default store is empty (it is on OPNsense)
SYSTEM_CA_FILES = ('/usr/local/etc/ssl/cert.pem', '/etc/ssl/cert.pem')


def ssl_context():
    """ certificate and hostname verification are always on """
    ctx = ssl.create_default_context()
    if not ctx.cert_store_stats().get('x509_ca'):
        for cafile in SYSTEM_CA_FILES:
            try:
                ctx.load_verify_locations(cafile=cafile)
                break
            except (OSError, ssl.SSLError):
                continue
    return ctx


class ProviderHTTPError(ProviderError):
    def __init__(self, code, detail='', headers=None):
        self.code = code
        self.detail = detail
        self.headers = headers or {}
        super().__init__(('HTTP %d from endpoint %s' % (code, detail)).strip())


class ProviderRefusal(ProviderError):
    """ the model declined to answer; message holds the explanation """


class GenerateResult:
    def __init__(self, text, model, duration_ms, prompt_tokens=None, completion_tokens=None, done_reason=None,
                 usage=None, truncated=False, refusal=None):
        self.text = text
        self.model = model
        self.duration_ms = duration_ms
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.done_reason = done_reason
        self.usage = usage or {}
        self.truncated = truncated
        self.refusal = refusal

    def as_dict(self):
        return {
            'model': self.model,
            'duration_ms': self.duration_ms,
            'prompt_tokens': self.prompt_tokens,
            'completion_tokens': self.completion_tokens,
            'done_reason': self.done_reason,
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """ never follow redirects: data must only go to the configured endpoint """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError('endpoint answered with a redirect (%d), refusing to follow' % code)


class BaseProvider:
    """
    Every provider module declares, besides the methods below:
        name     id used in the settings ("provider" option) and as the model container name
        label    human readable name
        group    "local" (runs on this firewall or in the LAN) or "api" (third party service)
        choices  entries for the initial provider choice in the GUI, each
                 {"id", "label", "group", "set": {field: value}, "wizard": bool, "help", "icon" (fa-* class)}
        fields   configuration fields rendered by the GUI, each
                 {"id" (relative to the provider container), "label", "type": text|password|dropdown|integer|url,
                  "required": bool, "secret": bool, "default", "options": {value: label}, "help",
                  "show_if": {field: value}}
        privacy  text shown next to the provider, what leaves the firewall
    """
    name = 'base'
    default_timeout = 120
    label = ''
    group = 'local'
    choices = ()
    fields = ()
    privacy = ''
    # hard cap on the size of any answer we are willing to buffer
    max_response_bytes = 2 * 1024 * 1024

    def __init__(self, options, timeout=None):
        self.options = dict(options or {})
        self.timeout = int(timeout) if timeout else self.default_timeout
        # no proxies (environment of configd), no redirects
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl_context()), _NoRedirect()
        )

    @staticmethod
    def validate_url(url):
        """ only plain http(s) URLs with a host, no credentials, query or fragment """
        if not isinstance(url, str) or not url:
            raise ProviderError('no endpoint URL configured')
        parts = urllib.parse.urlsplit(url.strip())
        if parts.scheme not in ('http', 'https') or not parts.hostname:
            raise ProviderError('endpoint URL must be http(s)://host[:port]')
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ProviderError('endpoint URL must not contain credentials, query or fragment')
        try:
            parts.port
        except ValueError:
            raise ProviderError('invalid port in endpoint URL')
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip('/'), '', ''))

    @classmethod
    def describe(cls):
        return {'id': cls.name, 'label': cls.label, 'group': cls.group, 'choices': list(cls.choices),
                'fields': list(cls.fields), 'privacy': cls.privacy}

    def _open(self, url, payload=None, timeout=None, extra_headers=None):
        headers = {'Accept': 'application/json', 'User-Agent': 'OPNsense-policyanalyzer'}
        headers.update(extra_headers or {})
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=data, headers=headers, method='POST' if data else 'GET')
        try:
            return self._opener.open(req, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as exc:
            detail = ''
            try:
                detail = exc.read(4096).decode(errors='replace')
                error = json.loads(detail).get('error', detail)
                # {"error": "text"} (Ollama) or {"error": {"type", "message"}} (Anthropic, OpenAI)
                detail = error.get('message', '') if isinstance(error, dict) else error
            except Exception:
                pass
            finally:
                exc.close()
            raise ProviderHTTPError(exc.code, str(detail)[:500], exc.headers)
        except urllib.error.URLError as exc:
            if isinstance(getattr(exc, 'reason', None), (socket.timeout, TimeoutError)):
                raise ProviderError('timeout after %d seconds' % (timeout or self.timeout))
            raise ProviderError('cannot reach endpoint: %s' % getattr(exc, 'reason', exc))
        except (socket.timeout, TimeoutError):
            raise ProviderError('timeout after %d seconds' % (timeout or self.timeout))
        except OSError as exc:
            raise ProviderError('cannot reach endpoint: %s' % exc)

    def _read_limited(self, response):
        data = response.read(self.max_response_bytes + 1)
        if len(data) > self.max_response_bytes:
            raise ProviderError('answer exceeds %d bytes' % self.max_response_bytes)
        return data

    @staticmethod
    def now_ms():
        return int(time.monotonic() * 1000)

    # interface ---------------------------------------------------------------
    def endpoint(self):
        """ printable endpoint (scheme://host:port), used for audit records """
        raise NotImplementedError

    def health(self):
        """ :return: dict with at least 'version' """
        raise NotImplementedError

    def list_models(self):
        """ :return: list of dicts {'name', 'size', 'modified', 'family', 'parameters', 'quantization'} """
        raise NotImplementedError

    def chat(self, messages, stream=False, on_chunk=None):
        """
        :param messages: list of {'role': 'system'|'user'|'assistant', 'content': str}
        :param stream: request a streamed answer, on_chunk(text) is called for every piece
        :return: GenerateResult
        """
        raise NotImplementedError
