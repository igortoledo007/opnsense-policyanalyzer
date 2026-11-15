"""
Fakes shared by the tests of the per scenario routing, fallback, queue, validation and map/reduce (no network).
"""

import os
import shutil
import tempfile
import unittest

import ai_helpers  # noqa: F401  (import path)

from ai import AIConfig, Assistant, scenarios
from ai.audit import NullAuditLog
from ai.providers import ProviderError, ProviderRefusal
from ai.providers.base import GenerateResult


class FakeProvider:
    """ scripted answers; an answer that is an Exception instance is raised """

    def __init__(self, name='fake', answers=None, supports_format=False, model='fake-model'):
        self.name = name
        self.answers = [answers] if callable(answers) else list(answers or ['ok'])
        self.calls = []
        self.supports_format = supports_format
        self.model = model

    def endpoint(self):
        return 'fake://%s' % self.name

    def chat(self, messages, stream=False, on_chunk=None, fmt=None):
        self.calls.append({'messages': [dict(m) for m in messages], 'fmt': fmt, 'stream': stream})
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        text = answer(messages) if callable(answer) else answer
        if stream and on_chunk is not None:
            on_chunk(text)
        return GenerateResult(text=text, model=self.model, duration_ms=5, prompt_tokens=100, completion_tokens=20,
                              done_reason='stop')


class Factory:
    """ Assistant.provider_factory replacement: one FakeProvider per provider name """

    def __init__(self, **providers):
        self.providers = providers
        self.created = []

    def __call__(self, name, options, timeout=None):
        self.created.append({'name': name, 'options': dict(options), 'timeout': timeout})
        if name not in self.providers:
            raise ProviderError('cannot reach endpoint: %s not available' % name)
        return self.providers[name]


def config(provider='claudecode', model='fable', ollama_model='qwen2.5:3b', enabled=True):
    raw = {'ai': {'enabled': '1', 'provider': provider},
           'ollama': {'location': 'local', 'model': ollama_model},
           'claudecode': {'url': 'http://bridge.example:11436', 'token': 'x' * 20, 'model': 'sonnet'},
           'claude': {'apikey': 'k', 'model': 'claude-x'}}
    raw[provider] = dict(raw.get(provider) or {}, model=model)
    cfg = AIConfig.from_dict(raw)
    cfg.enabled = enabled
    return cfg


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-ai-test-')
        self.queue_path = os.path.join(self.tmp, 'ai-queue.db')
        self.limits = os.path.join(self.tmp, 'runtime-limits.json')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._env = {k: os.environ.get(k) for k in ('PA_AI_JOB', 'PA_AI_INLINE', 'PA_AI_ROUTE')}
        for key in self._env:
            os.environ.pop(key, None)
        self.addCleanup(self._restore_env)
        self._limits = scenarios.LIMITS_FILE
        scenarios.LIMITS_FILE = self.limits
        self.addCleanup(setattr, scenarios, 'LIMITS_FILE', self._limits)

    def _restore_env(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def runtime(self, installed=True):
        if installed:
            with open(self.limits, 'w') as handle:
                handle.write('{"ctx": 8192}')
        elif os.path.exists(self.limits):
            os.unlink(self.limits)

    def assistant(self, cfg, routing, factory, **kw):
        a = Assistant(cfg, app='test', audit=NullAuditLog(), routing=routing, queue_path=self.queue_path, **kw)
        a.provider_factory = factory
        return a


def routing(scenarios_map=None, fallback=None):
    r = scenarios.empty_routing()
    r['scenarios'] = {k: scenarios.validate_entry(v) for k, v in (scenarios_map or {}).items()}
    if fallback is not None:
        r['fallback'] = fallback
    return r


__all__ = ['FakeProvider', 'Factory', 'config', 'TempDirCase', 'routing', 'ProviderError', 'ProviderRefusal']
