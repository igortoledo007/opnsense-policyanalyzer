"""
enable_racct (tunable through the core model, journal, revert) and warning -> action hints.
"""

import os
import unittest
from unittest import mock

from setup_helpers import SetupTestCase, common

from ai import changes, journal as ai_journal
from setup import actions, adapter, runtime


class TestEnableRacct(SetupTestCase):
    def test_plan_is_read_only_and_says_reboot(self):
        before = self.tree()
        plan = actions.plan('enable_racct', {}, self.ctx)
        self.assertEqual(self.tree(), before)
        self.assertEqual(self.system.writes(), [])
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertTrue(plan['reboot_required'])
        self.assertTrue(any('after the next reboot' in w for w in plan['warnings']))
        self.assertIn({'label': 'System: Power: Reboot', 'url': '/ui/core/reboot'}, plan['links'])
        self.assertEqual([s['type'] for s in plan['steps']], ['tunable', 'run', 'run'])
        self.assertEqual(plan['steps'][1]['argv'][-3:], ['service', 'restart', 'login'])
        self.assertTrue(any(h.get('link') for h in plan['warning_actions']))
        # never reboot, never edit loader.conf by hand
        commands = ' '.join(' '.join(s.get('argv') or []) for s in plan['steps'])
        self.assertNotIn('reboot', commands)
        self.assertNotIn('shutdown', commands)
        self.assertFalse(any(s.get('path', '').endswith('loader.conf') for s in plan['steps']))

    def test_apply_revert_and_status(self):
        res = actions.apply('enable_racct', {}, self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        self.assertEqual(self.system.tunables, {'kern.racct.enable': '1'})
        self.assertIn('kern.racct.enable="1"', self.read('/boot/loader.conf'))
        state = runtime.racct_state(self.ctx)
        self.assertEqual((state['enabled_now'], state['pending_reboot']), (False, True))
        status = actions.plan('status_runtime', {}, self.ctx)['result']
        self.assertEqual(status['racct']['pending_reboot'], True)
        # idempotent
        again = actions.apply('enable_racct', {}, self.ctx)
        self.assertEqual(again['status'], 'ok')
        self.assertEqual(again['executed'][0]['status'], 'skipped')
        # revert removes the tunable and regenerates loader.conf (post revert steps run, no jail needed)
        plan = actions.revert_plan(res['journal'], {}, self.ctx)
        self.assertEqual(plan['status'], 'ok', plan)
        n = len(self.system.calls)
        done = actions.revert_apply(res['journal'], {}, self.ctx)
        self.assertEqual(done['status'], 'ok', done)
        self.assertEqual(self.system.tunables, {})
        self.assertNotIn('racct', self.read('/boot/loader.conf'))
        restarts = [c for c in self.system.calls[n:] if c[0] == '/usr/local/sbin/configctl']
        self.assertEqual(len(restarts), 2)
        self.assertFalse(runtime.racct_state(self.ctx)['pending_reboot'])

    def test_revert_restores_previous_value(self):
        self.system.tunables = {'kern.racct.enable': '0'}
        self.system.write_config()
        res = actions.apply('enable_racct', {}, self.ctx)
        self.assertTrue(any("value '0'" in w for w in actions.plan('enable_racct', {}, self.ctx)['warnings'])
                        or res['status'] == 'ok')
        actions.revert_apply(res['journal'], {}, self.ctx)
        self.assertEqual(self.system.tunables, {'kern.racct.enable': '0'})

    def test_after_reboot_set_limits_applies_rctl(self):
        actions.apply('install_runtime', {}, self.ctx)
        self.assertNotIn('rctl', self.read('/etc/jail.conf.d/ollama.conf'))
        actions.apply('enable_racct', {}, self.ctx)
        self.system.sysctl['kern.racct.enable'] = '1'            # "rebooted"
        plan = actions.plan('start_runtime', {}, self.ctx)
        hint = [h for h in plan['warning_actions'] if h.get('action', {}).get('id') == 'set_limits']
        self.assertEqual(hint[0]['action']['args'], ['2-3/2/8192/20'])
        self.assertEqual(runtime.racct_state(self.ctx)['pending_reboot'], False)
        res = actions.apply('set_limits', actions.parse_cli_args('set_limits', hint[0]['action']['args']), self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        self.assertIn('rctl -a jail:ollama:memoryuse:deny=12g', self.read('/etc/jail.conf.d/ollama.conf'))
        self.assertIn(['/usr/bin/rctl', '-a', 'jail:ollama:memoryuse:deny=12g'], self.system.calls)

    def test_dispatcher(self):
        undo = os.path.join(self.tmp, 'undo')
        with mock.patch.object(ai_journal, 'UNDO_DIR', undo), \
                mock.patch.object(adapter, 'CONTEXT_FACTORY', lambda: self.make_ctx(official=ai_journal)):
            applied = changes.run('apply', 'enable_racct', [])
            self.assertEqual(applied['status'], 'ok', applied)
            self.assertTrue(applied['journal_id'])
            self.assertTrue(any('reboot' in w for w in applied['warnings']))
            self.assertEqual(changes.run('apply', 'revert', [applied['journal_id']])['status'], 'ok')
            self.assertEqual(self.system.tunables, {})


class TestWarningActions(SetupTestCase):
    def ids(self, plan):
        return [h.get('action', {}).get('id') or ('link' if h.get('link') else None)
                for h in plan.get('warning_actions', [])]

    def test_install_racct_hint(self):
        plan = actions.plan('install_runtime', {}, self.ctx)
        self.assertIn('enable_racct', self.ids(plan))

    def test_not_installed_hints(self):
        for action in ('start_runtime', 'set_limits'):
            self.assertIn('install_runtime', self.ids(actions.plan(action, {}, self.ctx)))
        self.assertIn('install_runtime', self.ids(actions.plan('pull_model', {'model': 'qwen2.5:3b'}, self.ctx)))

    def test_benchmark_hints(self):
        actions.apply('install_runtime', {'start': 'no'}, self.ctx)
        ids = self.ids(actions.plan('benchmark', {}, self.ctx))
        self.assertIn('start_runtime', ids)
        self.assertIn('pull_model', ids)

    def test_storage_large_busy_hints(self):
        os.rmdir(self.root + '/var/db/ai/models')
        plan = actions.plan('pull_model', {'model': 'qwen2.5:3b'}, self.ctx)
        hint = [h for h in plan['warning_actions'] if h.get('action', {}).get('id') == 'prepare_storage']
        self.assertEqual(hint[0]['action']['args'], ['/var/db/ai/models'])
        os.makedirs(self.root + '/var/db/ai/models')
        big = __import__('setup_helpers').model_manifest(sizes={__import__('setup_helpers').MODEL_LAYERS[0][0]:
                                                               7 * common.GIB})
        self.http.manifests[('qwen3', '8b')] = big
        plan = actions.plan('pull_model', {'model': 'qwen3:8b'}, self.ctx)
        hint = [h for h in plan['warning_actions'] if h.get('action', {}).get('id') == 'pull_model']
        self.assertEqual(hint[0]['action']['args'], ['qwen3:8b', '+large'])
        with common.Lock(self.ctx):
            self.assertIn('setup_cancel', self.ids(actions.plan('enable_racct', {}, self.ctx)))

    def test_revert_blocked_hint(self):
        actions.apply('install_runtime', {}, self.ctx)
        first = actions.apply('set_limits', {'cpus': '0-1'}, self.ctx)['journal']
        second = actions.apply('set_limits', {'cpus': '1-2'}, self.ctx)['journal']
        plan = actions.revert_plan(first, {}, self.ctx)
        hint = [h for h in plan['warning_actions'] if h.get('action', {}).get('id') == 'revert']
        self.assertEqual(hint[0]['action']['args'], [second])

    def test_status_listener_hint(self):
        actions.apply('install_runtime', {}, self.ctx)
        self.system.listeners = ['127.0.0.1:11434', '192.0.2.1:11434']
        status = actions.plan('status_runtime', {}, self.ctx)['result']
        self.assertIn('stop_runtime', [h['action']['id'] for h in status['warning_actions'] if 'action' in h])
        self.assertIn('enable_racct', [h['action']['id'] for h in status['warning_actions'] if 'action' in h])

    def test_recommend_pull_action(self):
        from setup import recommend
        import test_recommend
        res = recommend.recommend(test_recommend.N100, budget_pct=70)
        moe = [c for c in res['candidates'] if c['model'] == 'qwen3:30b-a3b'][0]
        self.assertEqual(moe['action']['args'], ['qwen3:30b-a3b', '+large'])
        self.assertEqual(actions.parse_cli_args('pull_model', moe['action']['args']),
                         {'model': 'qwen3:30b-a3b', 'large': 'yes'})


if __name__ == '__main__':
    unittest.main()
