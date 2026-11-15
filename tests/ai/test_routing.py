"""
Per scenario routing (ai/scenarios.py) and its change action (ai/routing_actions.py).
"""

import json
import os
import unittest

from ai_fakes import TempDirCase, config, routing
from ai import changes, routing_actions, scenarios
from ai.assistant import Task


class TestCatalog(unittest.TestCase):
    def test_ids_are_the_contract(self):
        expected = ['explain_finding', 'explain_set', 'war_room_brief', 'war_room_focus', 'console_ask',
                    'console_explain_log', 'console_explain_rule', 'console_explain_alert', 'incident_summary',
                    'incident_digest', 'anomaly_explain', 'anomaly_host', 'explain_cve', 'vuln_review_suggest',
                    'explain_device', 'posture_check', 'posture_summary', 'shadowai_overview', 'minrule_explain',
                    'report_summary', 'notification_summary', 'quicktest']
        self.assertEqual(sorted(scenarios.CATALOG), sorted(expected))
        for sid, meta in scenarios.CATALOG.items():
            self.assertIn(meta['kind'], ('short', 'long'), sid)
            self.assertTrue(meta['eta'] > 0)

    def test_task_scenario_defaults_to_name_and_alias(self):
        self.assertEqual(Task('explain_cve').scenario, 'explain_cve')
        self.assertEqual(Task('shadowai_host').scenario, 'shadowai_overview')
        self.assertEqual(Task('part', scenario='explain_set').scenario, 'explain_set')

    def test_presets(self):
        local = scenarios.preset_scenarios('local_only')
        self.assertEqual(set(local), set(scenarios.CATALOG))
        self.assertEqual(local['explain_cve']['model'], 'qwen2.5:3b')
        self.assertEqual(local['explain_cve']['mode'], 'sync')
        self.assertEqual(local['console_ask']['model'], 'qwen3:30b-a3b')
        self.assertEqual(local['console_ask']['mode'], 'queue')
        self.assertEqual(local['war_room_brief']['mode'], 'sync')          # already in the background
        self.assertLessEqual(local['war_room_brief']['timeout'], 840)
        self.assertTrue(all(e['provider'] == 'ollama' for e in local.values()))
        self.assertEqual({e['num_ctx'] for e in local.values() if 'num_ctx' in e}, {8192})   # no reloads
        hybrid = scenarios.preset_scenarios('hybrid')
        self.assertEqual(hybrid['console_ask']['provider'], 'claudecode')
        self.assertEqual(hybrid['explain_finding']['provider'], 'ollama')
        self.assertEqual(hybrid['posture_summary']['mode'], 'queue')
        self.assertEqual(hybrid['war_room_focus']['provider'], 'claudecode')
        self.assertEqual(scenarios.preset_scenarios('global'), {})
        with self.assertRaises(ValueError):
            scenarios.preset_scenarios('nope')

    def test_validation(self):
        self.assertEqual(scenarios.parse_spec('provider=ollama+model=qwen2.5:3b+mode=queue+timeout=1800'),
                         {'provider': 'ollama', 'model': 'qwen2.5:3b', 'mode': 'queue', 'timeout': 1800})
        self.assertEqual(scenarios.parse_spec('provider=default+mode=sync'), {'mode': 'sync'})
        for bad in ('timeout=1801', 'mode=later', 'provider=openai', 'keep_alive=forever', 'model=a b',
                    'num_ctx=12', 'colour=red', 'timeout'):
            with self.assertRaises(ValueError, msg=bad):
                scenarios.parse_spec(bad)


class TestResolve(TempDirCase):
    def test_no_routing_is_the_global_provider_synchronously(self):
        self.runtime(False)
        cfg = config('claudecode', 'fable')
        route = scenarios.resolve('console_ask', cfg, routing=routing())
        self.assertEqual((route.provider, route.model, route.mode, route.retries), ('claudecode', 'fable', 'sync', 0))
        self.assertIsNone(route.fallback)
        self.assertEqual(route.source, 'global')

    def test_scenario_entry_and_local_options(self):
        self.runtime(False)
        cfg = config('claudecode', 'fable')
        r = routing({'incident_summary': {'provider': 'ollama', 'model': 'qwen3:30b-a3b', 'mode': 'auto',
                                          'timeout': 1800, 'num_ctx': 8192, 'num_predict': 900, 'keep_alive': '1h'}})
        route = scenarios.resolve('incident_summary', cfg, routing=r)
        self.assertTrue(route.local)
        self.assertEqual(route.mode, 'queue')                       # auto: local + long
        self.assertEqual(route.retries, 1)
        opts = route.provider_options()
        self.assertEqual((opts['url'], opts['num_ctx'], opts['num_predict'], opts['keep_alive']),
                         ('http://127.0.0.1:11434', 8192, 900, '1h'))
        short = scenarios.resolve('explain_cve', cfg, routing=routing({'explain_cve': {'provider': 'ollama',
                                                                                        'mode': 'auto'}}))
        self.assertEqual(short.mode, 'sync')
        self.assertEqual(short.model, 'qwen2.5:3b')                 # the configured Ollama model

    def test_background_scenarios_never_queue(self):
        cfg = config('ollama', 'qwen2.5:3b')
        r = routing({'report_summary': {'mode': 'queue'}, 'war_room_brief': {'mode': 'queue'}})
        self.assertEqual(scenarios.resolve('report_summary', cfg, routing=r).mode, 'sync')
        self.assertEqual(scenarios.resolve('war_room_brief', cfg, routing=r).mode, 'sync')

    def test_fallback_auto_needs_the_runtime(self):
        cfg = config('claudecode', 'fable', ollama_model='')
        self.runtime(False)
        self.assertIsNone(scenarios.resolve('console_ask', cfg, routing=routing()).fallback)
        self.runtime(True)
        fb = scenarios.resolve('console_ask', cfg, routing=routing()).fallback
        self.assertEqual((fb.provider, fb.model, fb.mode, fb.role), ('ollama', 'qwen3:30b-a3b', 'queue', 'fallback'))
        fb_short = scenarios.resolve('explain_cve', cfg, routing=routing()).fallback
        self.assertEqual((fb_short.model, fb_short.mode), ('qwen2.5:3b', 'sync'))
        # local primary: the same local model is no fallback of itself
        cfg2 = config('ollama', 'qwen2.5:3b')
        self.assertIsNone(scenarios.resolve('explain_cve', cfg2, routing=routing()).fallback)
        none = routing(fallback={'provider': 'none', 'model': ''})
        self.assertIsNone(scenarios.resolve('console_ask', cfg, routing=none).fallback)
        bridge = routing({'explain_cve': {'provider': 'ollama'}}, fallback={'provider': 'claudecode', 'model': 'haiku'})
        fb = scenarios.resolve('explain_cve', cfg, routing=bridge).fallback
        self.assertEqual((fb.provider, fb.model, fb.mode), ('claudecode', 'haiku', 'sync'))

    def test_effective_php_timeout(self):
        self.runtime(True)
        cfg = config('claudecode', 'fable')
        r = routing({'explain_cve': {'provider': 'claudecode', 'timeout': 300, 'retries': 1}})
        eff = scenarios.effective(r, cfg)
        # 300 s + one correction + the synchronous local fallback (600 s) + margin
        self.assertEqual(eff['explain_cve']['php_timeout'], 300 * 2 + 600 + 45)
        self.assertEqual(eff['console_ask']['mode'], 'sync')

    def test_file_round_trip_and_broken_file(self):
        path = os.path.join(self.tmp, 'ai-routing.json')
        cfg = config()
        r = routing({'explain_cve': {'provider': 'ollama', 'model': 'qwen2.5:3b'}})
        scenarios.write_routing(r, path, cfg)
        back = scenarios.load_routing(path)
        self.assertEqual(back['scenarios'], r['scenarios'])
        self.assertIn('explain_cve', back['effective'])
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o640')
        with open(path, 'w') as handle:
            handle.write('{broken')
        self.assertEqual(scenarios.load_routing(path)['scenarios'], {})
        with open(path, 'w') as handle:
            json.dump({'scenarios': {'explain_cve': {'timeout': 'x'}, 'nope': {}, 'console_ask': {'mode': 'queue'}}},
                      handle)
        self.assertEqual(scenarios.load_routing(path)['scenarios'], {'console_ask': {'mode': 'queue'}})


class TestRoutingAction(TempDirCase):
    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.tmp, 'ai-routing.json')
        cls = changes.REGISTRY['ai_routing']
        cls.PATH = self.path
        self.addCleanup(setattr, cls, 'PATH', None)
        self.cfg = config('claudecode', 'fable')
        orig = routing_actions.AIConfig.from_opnsense
        routing_actions.AIConfig.from_opnsense = classmethod(lambda c, mount, path=None: self.cfg)
        self.addCleanup(setattr, routing_actions.AIConfig, 'from_opnsense', orig)
        orig_models = routing_actions.installed_models
        routing_actions.installed_models = lambda models_dir=None: {'qwen2.5:3b'}
        self.addCleanup(setattr, routing_actions, 'installed_models', orig_models)
        routing_actions.cron_jobs.__defaults__ = (os.path.join(self.tmp, 'none.xml'),)
        self.addCleanup(setattr, routing_actions.cron_jobs, '__defaults__', (None,))

    def act(self):
        return changes.REGISTRY['ai_routing']()

    def test_plan_apply_revert_preset(self):
        a = self.act()
        plan = a.plan(**a.parse_args(['preset', 'local_only']))
        self.assertEqual(plan['status'], 'ok')
        self.assertEqual(len(plan['steps']), len(scenarios.CATALOG))
        self.assertFalse(os.path.exists(self.path))                 # plan changes nothing
        self.assertTrue(any('qwen3:30b-a3b' in w and 'not installed' in w for w in plan['warnings']))
        self.assertTrue(any('two local models' in w for w in plan['warnings']))
        res = a.apply('preset', 'local_only')
        self.assertTrue(res['done'])
        self.assertIsNone(res['state']['previous'])
        self.assertEqual(scenarios.load_routing(self.path)['preset'], 'local_only')
        # a second apply is a no-op
        self.assertEqual(a.apply('preset', 'local_only')['completed'], [])
        entry = {'state': res['state']}
        rplan = a.revert_plan(entry)
        self.assertEqual(rplan['warnings'], [])
        a.revert_apply(entry)
        self.assertFalse(os.path.exists(self.path))

    def test_scenario_spec_reset_and_changed_warning(self):
        a = self.act()
        res1 = a.apply('explain_cve', 'provider=ollama+model=qwen2.5:3b+timeout=600')
        res2 = a.apply('console_ask', 'provider=claudecode+model=fable+mode=sync')
        self.assertEqual(scenarios.load_routing(self.path)['preset'], 'custom')
        rplan = a.revert_plan({'state': res1['state']})
        self.assertTrue(rplan['warnings'])                           # changed again later
        a.revert_apply({'state': res2['state']})
        cur = scenarios.load_routing(self.path)
        self.assertEqual(list(cur['scenarios']), ['explain_cve'])
        res3 = a.apply('explain_cve', 'reset')
        self.assertEqual(scenarios.load_routing(self.path)['scenarios'], {})
        self.assertTrue(res3['done'])
        with self.assertRaises(ValueError):
            a.parse_args(['explain_cve'])
        out = changes.run('plan', 'ai_routing', ['nope', 'mode=sync'])
        self.assertEqual(out['status'], 'error')
        out = changes.run('plan', 'ai_routing', ['explain_cve', 'timeout=99999'])
        self.assertEqual(out['status'], 'error')

    def test_fallback_spec(self):
        a = self.act()
        a.apply('fallback', 'provider=claudecode+model=haiku')
        self.assertEqual(scenarios.load_routing(self.path)['fallback'], {'provider': 'claudecode', 'model': 'haiku'})
        a.apply('fallback', 'none')
        self.assertEqual(scenarios.load_routing(self.path)['fallback']['provider'], 'none')
        with self.assertRaises(ValueError):
            a.plan('fallback', 'provider=openai')

    def test_queue_schedule(self):
        cls = changes.REGISTRY['ai_queue_schedule']
        calls, jobs = [], []
        a = cls()
        a.RUN = lambda argv, timeout=120: calls.append(argv) or ''
        a.JOBS = lambda: list(jobs)
        plan = a.plan(**a.parse_args(['create']))
        self.assertEqual(len(plan['steps']), 2)
        res = a.apply('create')
        self.assertEqual(calls[0][-2:], ['cron_set', 'ai_queue'])
        self.assertEqual(calls[1][-2:], ['cron', 'restart'])
        jobs.append({'uuid': 'u'})
        self.assertEqual(a.plan('create')['steps'], [])             # idempotent
        rplan = a.revert_plan({'state': res['state']})
        self.assertIn('Remove', rplan['steps'][0]['description'])
        a.revert_apply({'state': res['state']})
        self.assertEqual(calls[2][-2:], ['cron_del', 'ai_queue'])
        with self.assertRaises(ValueError):
            a.parse_args(['sometimes'])


if __name__ == '__main__':
    unittest.main()
