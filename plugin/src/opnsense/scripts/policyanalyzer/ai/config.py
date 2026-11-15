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

    AI provider settings, read (read only) from config.xml.

    The layout is shared by every consumer of this module, only the mount
    point differs (e.g. OPNsense/policyanalyzer for the Policy Analyzer):

        <mount>
          <ai>
            <enabled>0|1</enabled>
            <provider>ollama</provider>
            <timeout>120</timeout>        empty: the provider default (Ollama 120 s, local 360 s,
                                          Claude 180 s, Claude Code (LAN) 300 s)
            <anonymize>0|1</anonymize>
            <language>auto|en_US|pt_BR|...</language>
          </ai>
          <ollama>                 one container per provider, named after it
            <location>local|lan</location>
            <url>http://host:11434</url>
            <model>name:tag</model>
          </ollama>
          <claude>
            <apikey>...</apikey>   secret, never returned by the API
            <model>claude-opus-5-5</model>
            <effort>medium</effort>
          </claude>
          <claudecode>             Claude Code (LAN): bridge on a computer in the LAN
            <url>http://bridge.example.lan:11436</url>
            <token>...</token>     secret (Bearer token), never returned by the API
            <model>sonnet</model>  fable|opus|sonnet|haiku
          </claudecode>
        </mount>
    provider "none" (or enabled=0) disables the AI layer.
"""

import os
import xml.etree.ElementTree as ET

CONFIG_XML = os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')
LOCAL_URLS = {
    'ollama': 'http://127.0.0.1:11434',
}


class AIConfig:
    def __init__(self, enabled=False, provider='none', timeout=None, anonymize=True, language='auto',
                 options=None, raw=None):
        self.provider = provider or 'none'
        self.enabled = bool(enabled) and self.provider != 'none'
        try:
            # None: the provider's own default (see BaseProvider.default_timeout)
            self.timeout = None if timeout in (None, '') else max(5, min(int(timeout), 900))
        except (TypeError, ValueError):
            self.timeout = None
        self.anonymize = bool(anonymize)
        self.language = language or 'auto'
        self.options = dict(options or {})
        # the whole <mount> as read, so a scenario can use another provider than the global one (scenarios.py)
        self.raw = raw if isinstance(raw, dict) else {}

    @classmethod
    def from_dict(cls, data):
        data = data or {}
        ai = data.get('ai', {}) or {}
        provider = ai.get('provider') or 'none'
        location = None
        if provider in ('ollama_local', 'ollama_lan'):
            # values used by early development builds
            provider, location = 'ollama', provider.split('_')[1]
        options = dict(data.get(provider, {}) or {})
        if location:
            options['location'] = location
        if 'mode' in options and 'location' not in options:
            options['location'] = 'lan' if options['mode'] == 'network' else 'local'
        if options.get('location', 'local') == 'local' and provider in LOCAL_URLS:
            options['url'] = LOCAL_URLS[provider]
        return cls(
            enabled=_bool(ai.get('enabled'), False),
            provider=provider,
            timeout=ai.get('timeout') or None,
            anonymize=_bool(ai.get('anonymize'), True),
            language=ai.get('language') or 'auto',
            options=options,
            raw=data,
        )

    @classmethod
    def from_opnsense(cls, mount, path=CONFIG_XML):
        """
        :param mount: model mount point without leading slashes, e.g. "OPNsense/policyanalyzer"
        :param path: config.xml location
        """
        return cls.from_dict(read_mount(mount, path))


def read_mount(mount, path=CONFIG_XML):
    """ :return: nested dict of the model below mount, {} when absent """
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return {}
    node = root.find('./' + mount.strip('/'))
    return _to_dict(node) if node is not None else {}


def _bool(value, default):
    if value is None or value == '':
        return default
    return str(value).strip().lower() in ('1', 'yes', 'true', 'on')


def _to_dict(node):
    result = {}
    for child in node:
        if len(child):
            result[child.tag] = _to_dict(child)
        else:
            result[child.tag] = (child.text or '').strip()
    return result
