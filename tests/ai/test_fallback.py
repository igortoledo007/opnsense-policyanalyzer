"""
Assistant: route per scenario, fallback provider, audit of who answered.
"""

import unittest
from unittest import mock

from ai_fakes import Factory, FakeProvider, ProviderError, ProviderRefusal, TempDirCase, config, routing
from ai import Task, jobqueue
from ai.assistant import is_queued


class TestRouteAndFallback(TempDirCase):
    def test_scenario_goes_to_its_provider(self):
        self.runtime(False)
        local = FakeProvider('ollama', ['local answer'])
        bridge = FakeProvider('claudecode', ['bridge answer'])
        factory = Factory(ollama=local, claudecode=bridge)
        a = self.assistant(config('claudecode', 'fable'), routing({'explain_cve': {'provider': 'ollama',
                                                                                    'retries': 0}}), factory)
        res = a.ask(Task('explain_cve', 'x', 'q'), {'a': 1}, language='en_US')
        self.assertEqual(res['text'], 'local answer')
        self.assertEqual(res['provider'], 'ollama')
        self.assertEqual(factory.created[0]['options']['model'], 'qwen2.5:3b')
        res = a.ask(Task('console_ask', 'x', 'q'), {'a': 1}, language='en_US')
        self.assertEqual(res['provider'], 'claudecode')
        self.assertEqual(res['text'], 'bridge answer')
        self.assertFalse(res['fallback'])
        records = a.audit.records
        self.assertEqual([r['scenario'] for r in records], ['explain_cve', 'console_ask'])

    def test_bridge_down_falls_back_to_local(self):
        self.runtime(True)
        local = FakeProvider('ollama', ['resposta local'])
        bridge = FakeProvider('claudecode', [ProviderError('cannot reach endpoint: connection refused')])
        a = self.assistant(config('claudecode', 'fable'), routing(), Factory(ollama=local, claudecode=bridge))
        res = a.ask(Task('explain_cve', 'x', 'q'), {'a': 1}, language='en_US')
        self.assertEqual(res['text'], 'resposta local')
        self.assertEqual(res['provider'], 'ollama')
        self.assertTrue(res['fallback'])
        self.assertIn('connection refused', res['fallback_reason'])
        ok = [r for r in a.audit.records if r.get('status') == 'ok'][0]
        self.assertEqual((ok['provider'], ok['route_role']), ('ollama', 'fallback'))
        self.assertIn('connection refused', ok['fallback_from'][0])
        err = [r for r in a.audit.records if r.get('status') == 'error'][0]
        self.assertEqual(err['provider'], 'claudecode')

    def test_both_fail_and_refusal_does_not_fall_back(self):
        self.runtime(True)
        local = FakeProvider('ollama', [ProviderError('timeout after 600 seconds')])
        bridge = FakeProvider('claudecode', [ProviderError('HTTP 502 from endpoint')])
        a = self.assistant(config('claudecode', 'fable'), routing(), Factory(ollama=local, claudecode=bridge))
        with self.assertRaises(ProviderError) as ctx:
            a.ask(Task('explain_cve', 'x', 'q'), {'a': 1}, language='en_US')
        self.assertIn('HTTP 502', str(ctx.exception))
        self.assertIn('timeout after 600', str(ctx.exception))
        bridge2 = FakeProvider('claudecode', [ProviderRefusal('declined')])
        local2 = FakeProvider('ollama', ['never'])
        a2 = self.assistant(config('claudecode', 'fable'), routing(), Factory(ollama=local2, claudecode=bridge2))
        with self.assertRaises(ProviderRefusal):
            a2.ask(Task('explain_cve', 'x', 'q'), {'a': 1}, language='en_US')
        self.assertEqual(local2.calls, [])

    def test_injected_provider_disables_fallback(self):
        self.runtime(True)
        injected = FakeProvider('x', [ProviderError('down')])
        from ai import Assistant
        from ai.audit import NullAuditLog
        a = Assistant(config('claudecode', 'fable'), audit=NullAuditLog(), provider=injected, routing=routing())
        with self.assertRaises(ProviderError) as ctx:
            a.ask(Task('explain_cve', 'x', 'q'), {'a': 1})
        self.assertEqual(str(ctx.exception), 'down')

    def test_long_fallback_goes_to_the_queue(self):
        """ the bridge is down for an interactive long scenario: the local fallback is queued, not waited for """
        self.runtime(True)
        local = FakeProvider('ollama', ['local'])
        bridge = FakeProvider('claudecode', [ProviderError('cannot reach endpoint')])
        a = self.assistant(config('claudecode', 'fable'), routing(), Factory(ollama=local, claudecode=bridge))
        with mock.patch.object(jobqueue, 'current_argv', return_value=['/x/explain.py', 'explain', 'all']), \
                mock.patch.object(jobqueue, 'valid_argv', return_value=True), \
                mock.patch.object(jobqueue, 'spawn_worker', return_value=True):
            res = a.ask(Task('console_ask', 'x', 'q'), {'a': 1}, language='en_US', subject='console:x')
        self.assertTrue(is_queued(res))
        self.assertTrue(res['fallback'])
        self.assertEqual(res['provider'], 'ollama')
        self.assertEqual(local.calls, [])
        job = jobqueue.get(res['job']['id'], self.queue_path)['job']
        self.assertEqual(job['route']['role'], 'fallback')
        self.assertEqual(job['status'], 'queued')
        queued = [r for r in a.audit.records if r.get('status') == 'queued'][0]
        self.assertIn('cannot reach endpoint', queued['fallback_from'][0])

    def test_sync_fallback_respects_the_request_budget(self):
        self.runtime(True)
        local = FakeProvider('ollama', ['local'])
        bridge = FakeProvider('claudecode', [ProviderError('timeout after 300 seconds')])
        factory = Factory(ollama=local, claudecode=bridge)
        a = self.assistant(config('claudecode', 'fable'), routing(), factory)
        ticks = iter([0, 280, 280, 280])
        a.clock = lambda: next(ticks)
        a.ask(Task('explain_cve', 'x', 'q'), {'a': 1}, language='en_US')
        # the global bridge timeout (300 s) + 20: only 40 s left -> not queueable here (tests), runs with >= 30 s
        self.assertLessEqual(factory.created[-1]['timeout'], 40)
        self.assertGreaterEqual(factory.created[-1]['timeout'], 30)


if __name__ == '__main__':
    unittest.main()
