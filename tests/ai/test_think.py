"""
Reasoning per scenario (think field of the routing, 2026-11-12): validation, route -> provider options, the Ollama
payload (only for models with the thinking capability, extra num_predict) and no "/no_think" when it is on.
"""

import unittest

import ai_helpers  # noqa: F401  (import path)
from ai_fakes import TempDirCase, config, routing
from ai import scenarios
from ai.assistant import Assistant


class TestThinkSpec(unittest.TestCase):
    def test_values_and_aliases(self):
        self.assertEqual(scenarios.parse_spec('model=qwen3.5:2b+think=on'), {'model': 'qwen3.5:2b', 'think': 'on'})
        self.assertEqual(scenarios.parse_spec('think=true'), {'think': 'on'})
        self.assertEqual(scenarios.parse_spec('think=0'), {'think': 'off'})
        self.assertEqual(scenarios.parse_spec('think=HIGH'), {'think': 'high'})
        with self.assertRaises(ValueError):
            scenarios.parse_spec('think=maybe')
        self.assertEqual(scenarios.parse_spec('think=on+think_budget=8000'), {'think': 'on', 'think_budget': 8000})
        for bad in ('think_budget=100', 'think_budget=20000', 'think_budget=x'):
            with self.assertRaises(ValueError, msg=bad):
                scenarios.parse_spec(bad)

    def test_format_spec_round_trip(self):
        entry = scenarios.parse_spec('provider=ollama+model=qwen3.5:2b+timeout=1200+think=on')
        self.assertEqual(scenarios.parse_spec(scenarios.format_spec(entry)), entry)
        self.assertTrue(scenarios.format_spec(entry).endswith('think=on'))


class TestThinkRoute(TempDirCase):
    def test_route_options(self):
        self.runtime(False)
        cfg = config('ollama', 'qwen2.5:3b')
        on = scenarios.resolve('console_explain_rule', cfg, routing=routing(
            {'console_explain_rule': {'provider': 'ollama', 'model': 'qwen3.5:2b', 'think': 'on'}}))
        self.assertTrue(on.thinking)
        self.assertIs(on.provider_options()['think'], True)
        self.assertEqual(on.as_dict()['think'], 'on')
        self.assertNotIn('think_budget', on.provider_options())
        big = scenarios.resolve('console_explain_rule', cfg, routing=routing(
            {'console_explain_rule': {'provider': 'ollama', 'model': 'qwen3:8b', 'think': 'on', 'think_budget': 8000}}))
        self.assertEqual(big.provider_options()['think_budget'], 8000)
        self.assertEqual(big.as_dict()['think_budget'], 8000)
        level = scenarios.resolve('console_explain_rule', cfg, routing=routing(
            {'console_explain_rule': {'provider': 'ollama', 'model': 'gpt-oss:20b', 'think': 'low'}}))
        self.assertEqual(level.provider_options()['think'], 'low')
        off = scenarios.resolve('console_explain_rule', cfg, routing=routing(
            {'console_explain_rule': {'provider': 'ollama', 'model': 'qwen3.5:2b'}}))
        self.assertFalse(off.thinking)
        self.assertNotIn('think', off.provider_options())
        self.assertEqual(off.as_dict()['think'], 'off')

    def test_no_think_suffix_only_when_off(self):
        self.runtime(False)
        cfg = config('ollama', 'qwen2.5:3b')
        msgs = [{'role': 'system', 'content': 's'}, {'role': 'user', 'content': 'q'}]
        for think, expect in (('on', False), (None, True)):
            entry = {'provider': 'ollama', 'model': 'qwen3:8b'}
            if think:
                entry['think'] = think
            route = scenarios.resolve('console_explain_rule', cfg, routing=routing({'console_explain_rule': entry}))
            out = Assistant.finalize(msgs, route, 'pt_BR')
            self.assertEqual(out[-1]['content'].endswith('/no_think'), expect, think)


class TestThinkPayload(unittest.TestCase):
    def body(self, show, think, model='qwen3.5:2b', **extra):
        from ai.providers import ollama
        from ai_helpers import FakeOllama
        ollama._SHOW_CACHE.clear()
        with FakeOllama(answer='Resposta em português.', show=show) as fake:
            p = ollama.OllamaProvider({'location': 'lan', 'url': fake.url, 'model': model, 'num_predict': 1200,
                                       'think': think, **extra}, timeout=20)
            p.chat([{'role': 'user', 'content': 'q'}])
            return [r for r in fake.requests if r[1] == '/api/chat'][-1][2]

    def test_on_for_a_thinking_model(self):
        from ai.providers import ollama
        show = {'capabilities': ['completion', 'thinking'], 'template': '{{ if not .Think }}<think></think>{{ end }}'}
        body = self.body(show, True)
        self.assertIs(body['think'], True)
        self.assertEqual(body['options']['num_predict'], 1200 + ollama.THINK_ON_BUDGET)

    def test_route_budget(self):
        show = {'capabilities': ['completion', 'thinking'], 'template': '{{ if not .Think }}<think></think>{{ end }}'}
        self.assertEqual(self.body(show, True, think_budget=8000)['options']['num_predict'], 1200 + 8000)
        self.assertEqual(self.body(show, True, think_budget=99999)['options']['num_predict'], 1200 + 16384)

    def test_on_ignored_without_the_capability(self):
        body = self.body({'capabilities': ['completion', 'tools'], 'template': '{{ .Prompt }}'}, True,
                         model='granite4.2:3b')
        self.assertIs(body['think'], False)
        self.assertEqual(body['options']['num_predict'], 1200)

    def test_level_only_for_gpt_oss(self):
        show = {'capabilities': ['completion', 'thinking'], 'template': '<|channel|>'}
        self.assertEqual(self.body(show, 'high', model='gpt-oss:20b')['think'], 'high')
        show = {'capabilities': ['completion', 'thinking'], 'template': '{{ .Prompt }}'}
        self.assertIs(self.body(show, 'high')['think'], True)

    def test_off_stays_false(self):
        show = {'capabilities': ['completion', 'thinking'], 'template': '{{ if not .Think }}<think></think>{{ end }}'}
        body = self.body(show, 'off')
        self.assertIs(body['think'], False)
        self.assertEqual(body['options']['num_predict'], 1200)


if __name__ == '__main__':
    unittest.main()
