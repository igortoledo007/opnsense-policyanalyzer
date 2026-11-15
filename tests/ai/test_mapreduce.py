"""
Map/reduce for data above the budget of a local route (ai/mapreduce.py): explain_set and the AI Console.
"""

import unittest
from unittest import mock

from ai_fakes import Factory, FakeProvider, TempDirCase, config, routing
from ai import Task, jobqueue, mapreduce
from ai.assistant import is_queued
from console import context

SET_ANSWER = 'Overview: ok.\nPriorities: the high ones.\nClean-up plan: review.'


def findings(n):
    return [{'id': '%06x' % i, 'type': 'unused', 'severity': 'low', 'title': 'Rule %d is never used' % i,
             'detail': 'The rule matched no packet since the counters were reset ' * 3,
             'rules': [{'interface': 'lan', 'sequence': i, 'action': 'pass', 'summary': 'pass in on lan port %d' % i}]}
            for i in range(n)]


class TestPack(unittest.TestCase):
    def test_pack_respects_budget_and_limit(self):
        items = findings(40)
        parts = mapreduce.pack(items, 600, {'summary': {}}, limit=100)
        self.assertEqual(sum(len(p) for p in parts), 40)
        self.assertGreater(len(parts), 3)
        self.assertTrue(all(mapreduce.size_tokens(p) <= 600 for p in parts), [mapreduce.size_tokens(p) for p in parts])
        self.assertLessEqual(len(mapreduce.pack(items, 600, {'summary': {}})), mapreduce.MAX_PARTS)
        few = mapreduce.pack(items, 200, None, limit=3)
        self.assertEqual(len(few), 3)
        self.assertEqual(sum(len(p) for p in few), 40)


class TestExplainSet(TempDirCase):
    def setUp(self):
        super().setUp()
        self.runtime(False)

    def test_batches_then_consolidation(self):
        local = FakeProvider('ollama', lambda msgs: SET_ANSWER if 'batch_notes' in msgs[-1]['content']
                             else '- note of this batch')
        r = routing({'explain_set': {'provider': 'ollama', 'model': 'qwen3:30b-a3b', 'mode': 'sync', 'budget': 900}})
        a = self.assistant(config('claudecode', 'fable'), r, Factory(ollama=local))
        data = {'summary': {'findings': 40}, 'findings_total': 40, 'findings': findings(40)}
        task = Task('explain_set', 'Summarise.', 'Summarise these findings.')
        route = a.route_for(task)
        self.assertTrue(mapreduce.needed(route, data))
        res = mapreduce.explain_set(a, task, data, 'en_US', 'finding:all', route.budget)
        parts = res['map_reduce']['parts']
        self.assertGreater(parts, 1)
        self.assertEqual(len(local.calls), parts + 1)
        self.assertEqual(res['text'], SET_ANSWER)
        # every part fits the budget (with the instructions around it)
        for call in local.calls[:-1]:
            self.assertLess(len(call['messages'][-1]['content']) / mapreduce.CHARS_PER_TOKEN, 900 + 300)
        actions = [rec['action'] for rec in a.audit.records]
        self.assertEqual(actions[:-1], ['explain_set_part'] * parts)
        self.assertEqual(actions[-1], 'explain_set')
        self.assertEqual({rec['scenario'] for rec in a.audit.records}, {'explain_set'})

    def test_not_needed_for_the_bridge_or_small_data(self):
        cfg = config('claudecode', 'fable')
        a = self.assistant(cfg, routing(), Factory())
        route = a.route_for(Task('explain_set'))
        self.assertFalse(mapreduce.needed(route, {'findings': findings(40)}))
        r = routing({'explain_set': {'provider': 'ollama', 'budget': 4000}})
        a2 = self.assistant(cfg, r, Factory())
        self.assertFalse(mapreduce.needed(a2.route_for(Task('explain_set')), {'findings': findings(2)}))

    def test_queue_mode_queues_the_whole_command(self):
        local = FakeProvider('ollama', ['never'])
        r = routing({'explain_set': {'provider': 'ollama', 'mode': 'queue', 'budget': 600}})
        a = self.assistant(config('claudecode', 'fable'), r, Factory(ollama=local))
        data = {'summary': {}, 'findings': findings(30)}
        with mock.patch.object(jobqueue, 'current_argv', return_value=['/x/explain.py', 'explain', 'all']), \
                mock.patch.object(jobqueue, 'valid_argv', return_value=True), \
                mock.patch.object(jobqueue, 'spawn_worker', return_value=True):
            res = mapreduce.explain_set(a, Task('explain_set', 'x', 'q'), data, 'en_US', 'finding:all', 600)
        self.assertTrue(is_queued(res))
        self.assertEqual(local.calls, [])


class TestConsole(TempDirCase):
    def test_sections_split_and_reduce_with_citations(self):
        self.runtime(False)

        def answer(msgs):
            content = msgs[-1]['content']
            if 'evidence_notes' in content:
                return 'Answer [filterlog: 14 blocks] and [rules: lan #3].'
            return '- fact [filterlog: 14 blocks]'
        local = FakeProvider('ollama', answer)
        r = routing({'console_ask': {'provider': 'ollama', 'model': 'qwen3:30b-a3b', 'mode': 'sync', 'budget': 700}})
        a = self.assistant(config('claudecode', 'fable'), r, Factory(ollama=local))
        analysis = {'intents': ['who_blocked'], 'window': 'today'}
        big = [{'src': '203.0.113.%d' % i, 'blocks': i, 'ports': list(range(8))} for i in range(60)]
        sections = [('filterlog_top', {'available': True, 'top': big}),
                    ('rules', {'available': True, 'rules': big[:30]}),
                    ('quarantine', {'available': True, 'entries': big[:25]})]
        task = Task('console_ask', 'Answer with citations.', 'Quem mais foi bloqueado hoje?')
        res, data = mapreduce.console(a, task, analysis, sections, 700, 'pt_BR', 'console:x', context.build)
        self.assertEqual(res['status'], 'ok')
        self.assertGreaterEqual(res['map_reduce']['parts'], 2)
        self.assertEqual(data['context_limits']['map_reduce'], res['map_reduce']['parts'])
        self.assertEqual(len(local.calls), res['map_reduce']['parts'] + 1)
        self.assertIn('[filterlog', res['text'])
        self.assertTrue(all(n['notes'].startswith('- fact') for n in data['evidence_notes']))
        # fits: no map/reduce
        small, d2 = mapreduce.console(a, task, analysis, [('rules', {'available': True, 'rules': []})], 700,
                                      'pt_BR', 'console:x', context.build)
        self.assertIsNone(small)
        self.assertIsNone(d2)


if __name__ == '__main__':
    unittest.main()
