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

    Provider registry.

    Adding a provider (llama.cpp server, OpenAI compatible, ...):
      1. a module here with a BaseProvider subclass that declares name,
         label, group ("local" or "api"), choices, fields, privacy and
         implements endpoint/health/list_models/chat (a "local" provider whose
         data still leaves the network, like Claude Code (LAN), adds
         privacy_warn to describe(); a choice may carry a "badge", e.g. "LAN");
      2. an entry in PROVIDERS below;
      3. an option in ai.provider and a container named after the provider
         (one element per field) in models/OPNsense/PolicyAnalyzer/PolicyAnalyzer.xml,
         so the values are persisted and validated.
    The GUI builds the provider choice and the provider fields from
    describe() (configd "policyanalyzer ai_providers"); it needs no change.
"""

from .base import BaseProvider, GenerateResult, ProviderError, ProviderHTTPError, ProviderRefusal
from .claude import ClaudeProvider
from .claudecode import ClaudeCodeProvider
from .ollama import OllamaProvider

# GUI order inside each group follows this order (local group first)
PROVIDERS = {
    OllamaProvider.name: OllamaProvider,
    ClaudeCodeProvider.name: ClaudeCodeProvider,
    ClaudeProvider.name: ClaudeProvider,
}


def get_provider(name, options, timeout=None):
    if not name or name == 'none':
        raise ProviderError('no AI provider selected')
    if name not in PROVIDERS:
        raise ProviderError('unsupported AI provider "%s"' % name)
    return PROVIDERS[name](options, timeout=timeout)


def describe():
    """ registry metadata for the GUI, grouped local first, registry order inside a group """
    items = [cls.describe() for cls in PROVIDERS.values()]
    items.sort(key=lambda x: x['group'] != 'local')
    return {'status': 'ok', 'groups': {'local': 'Local', 'api': 'API'}, 'providers': items}


__all__ = [
    'BaseProvider', 'ClaudeCodeProvider', 'ClaudeProvider', 'GenerateResult', 'OllamaProvider', 'PROVIDERS', 'ProviderError',
    'ProviderHTTPError', 'ProviderRefusal', 'describe', 'get_provider',
]
