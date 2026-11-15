"""
Mandatory reversion: undo journal of every apply, revert plan/apply, dependency order, and the
integration with the plugin's generic dispatcher (ai/changes.py + ai/journal.py, one journal only).
"""

import json
import os
import unittest
from unittest import mock

from setup_helpers import SetupTestCase, MODEL_LAYERS, common

from ai import changes, journal as ai_journal
from setup import actions, adapter, ops


class TestRevertStandalone(SetupTestCase):
    def apply(self, action, **args):
        res = actions.apply(action, args, self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        return res['journal']

    def test_revert_set_limits_restores_previous(self):
        self.apply('install_runtime')
        self.system.running = True
        before_conf = self.read('/etc/jail.conf.d/ollama.conf')
        before_rc = self.read('/var/db/ai/jail/etc/rc.conf.d/ollama')
        jid = self.apply('set_limits', cpus='0-1', threads='2', ctx='4096', nice='10')
        self.assertIn('cpuset -l 0-1', self.read('/etc/jail.conf.d/ollama.conf'))
        plan = actions.revert_plan(jid, {}, self.ctx)
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertEqual(plan['irreversible'], [])
        n = len(self.system.calls)
        res = actions.revert_apply(jid, {}, self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        self.assertEqual(self.read('/etc/jail.conf.d/ollama.conf'), before_conf)
        self.assertEqual(self.read('/var/db/ai/jail/etc/rc.conf.d/ollama'), before_rc)
        cmds = [' '.join(c) for c in self.system.calls[n:]]
        self.assertIn('/usr/bin/cpuset -l 2-3 -j ollama', cmds)                  # live cpuset restored
        self.assertTrue(cmds[-1].endswith('service ollama restart') or
                        any('service ollama restart' in c for c in cmds))      # restart after the files
        self.assertEqual(common.load_journal(self.ctx, jid)['status'], 'reverted')
        self.assertEqual(actions.revert_plan(jid, {}, self.ctx)['status'], 'blocked')   # only once

    def test_revert_order_on_same_resource(self):
        self.apply('install_runtime')
        first = self.apply('set_limits', cpus='0-1')
        second = self.apply('set_limits', cpus='1-2')
        plan = actions.revert_plan(first, {}, self.ctx)
        self.assertEqual(plan['status'], 'blocked')
        self.assertIn(second, plan['blocked_by'])
        self.assertEqual(actions.revert_apply(first, {}, self.ctx)['status'], 'blocked')
        self.assertEqual(actions.revert_apply(second, {}, self.ctx)['status'], 'ok')
        self.assertEqual(actions.revert_apply(first, {}, self.ctx)['status'], 'ok')
        self.assertIn('cpuset -l 2-3', self.read('/etc/jail.conf.d/ollama.conf'))

    def test_force_overrides_dependency_block(self):
        self.apply('install_runtime')
        first = self.apply('set_limits', cpus='0-1')
        self.apply('set_limits', cpus='1-2')
        plan = actions.revert_plan(first, {'force': True}, self.ctx)
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertTrue(any('force' in w for w in plan['warnings']))
        self.assertEqual(actions.revert_apply(first, {'force': 'yes'}, self.ctx)['status'], 'ok')
        self.assertIn('cpuset -l 2-3', self.read('/etc/jail.conf.d/ollama.conf'))

    def test_revert_start_stop(self):
        self.apply('install_runtime', start='no')
        self.assertFalse(self.system.running)
        jid = self.apply('start_runtime')
        self.assertTrue(self.system.running)
        self.assertEqual(actions.revert_apply(jid, {}, self.ctx)['status'], 'ok')
        self.assertFalse(self.system.running)

    def test_revert_pull_and_remove(self):
        pull = self.apply('pull_model', model='qwen2.5:3b')
        plan = actions.revert_plan(pull, {}, self.ctx)
        self.assertEqual(plan['status'], 'ok')
        self.assertEqual(actions.revert_apply(pull, {}, self.ctx)['status'], 'ok')
        self.assertFalse(os.path.exists(ops.model_manifest_path(self.ctx, 'qwen2.5', '3b')))
        # remove -> revert downloads the same digests again (shown as irreversible in the plan)
        self.apply('pull_model', model='qwen2.5:3b')
        removed = self.apply('remove_model', model='qwen2.5:3b')
        plan = actions.revert_plan(removed, {}, self.ctx)
        self.assertTrue(plan['irreversible'])
        self.assertGreater(plan['download_bytes'], 0)
        self.assertTrue(plan['background'])
        self.assertEqual(actions.revert_apply(removed, {}, self.ctx)['status'], 'ok')
        for digest, data in MODEL_LAYERS:
            self.assertTrue(os.path.isfile(ops.blob_path(self.ctx, digest)))

    def test_revert_install_keeps_models_and_supersedes(self):
        install = self.apply('install_runtime')
        limits = self.apply('set_limits', nice='15')
        pull = self.apply('pull_model', model='qwen2.5:3b')
        plan = actions.revert_plan(install, {}, self.ctx)
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertEqual(plan['superseded'], [limits])
        self.assertEqual(plan['dependents'], [pull])
        self.assertTrue(plan['requires_double_confirmation'])
        self.assertTrue(any('keep_models' in w or 'kept' in w for w in plan['warnings']))
        res = actions.revert_apply(install, {}, self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        self.assertFalse(self.system.running)
        self.assertNotIn('zroot/ai/jail', self.system.datasets)
        self.assertFalse(os.path.exists(self.root + '/etc/jail.conf.d/ollama.conf'))
        self.assertFalse(os.path.exists(self.root + '/etc/rc.conf.d/jail'))
        self.assertTrue(os.path.exists(ops.model_manifest_path(self.ctx, 'qwen2.5', '3b')))     # kept
        self.assertEqual(common.load_journal(self.ctx, limits)['status'], 'superseded')
        self.assertEqual(common.load_journal(self.ctx, pull)['status'], 'applied')          # still revertable

    def test_revert_install_deleting_models(self):
        install = self.apply('install_runtime')
        self.apply('pull_model', model='qwen2.5:3b')
        plan = actions.revert_plan(install, {'keep_models': 'no'}, self.ctx)
        self.assertTrue(any('models deleted' in i for i in plan['irreversible']))
        self.assertEqual(actions.revert_apply(install, {'keep_models': 'no'}, self.ctx)['status'], 'ok')
        self.assertFalse(os.path.exists(ops.model_manifest_path(self.ctx, 'qwen2.5', '3b')))

    def test_revert_uninstall_reinstalls(self):
        self.apply('install_runtime')
        self.apply('set_limits', cpus='1-2')
        un = self.apply('uninstall_runtime')
        self.assertNotIn('zroot/ai/jail', self.system.datasets)
        plan = actions.revert_plan(un, {}, self.ctx)
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertTrue(plan['irreversible'])                 # downloads again
        self.assertGreater(plan['download_bytes'], 0)
        self.assertEqual(actions.revert_apply(un, {}, self.ctx)['status'], 'ok')
        self.assertIn('zroot/ai/jail', self.system.datasets)
        self.assertTrue(self.system.running)
        self.assertIn('cpuset -l 1-2', self.read('/etc/jail.conf.d/ollama.conf'))   # limits kept

    def test_failed_apply_has_nothing_to_revert(self):
        self.system.fail_on = 'pkg install'
        res = actions.apply('install_runtime', {}, self.ctx)
        self.assertEqual(res['status'], 'failed')
        self.assertEqual(actions.revert_plan(res['journal'], {}, self.ctx)['status'], 'blocked')

    def test_revert_plan_is_read_only(self):
        jid = self.apply('install_runtime')
        before = self.tree()
        calls = len(self.system.calls)
        actions.revert_plan(jid, {}, self.ctx)
        self.assertEqual(self.tree(), before)
        writes = [c for c in self.system.calls[calls:] if c in self.system.writes()]
        self.assertEqual(writes, [])


class TestDispatcherIntegration(SetupTestCase):
    """ the GUI path: ai.changes.run('plan'|'apply', action, tokens) with the single official journal """

    def setUp(self):
        super().setUp()
        undo = os.path.join(self.tmp, 'undo')
        for patcher in (mock.patch.object(ai_journal, 'UNDO_DIR', undo),
                        mock.patch.object(adapter, 'CONTEXT_FACTORY', lambda: self.make_ctx(official=ai_journal))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.ctx = self.make_ctx(official=ai_journal)

    def test_registered(self):
        names = {a['name'] for a in changes.describe()['actions']}
        for name in list(actions.ACTIONS) + ['setup_cancel']:
            self.assertIn(name, names)

    def test_plan_contract(self):
        res = changes.run('plan', 'set_limits', ['2-3/2/8192/20'])
        self.assertEqual(res['status'], 'error')           # not installed yet
        self.assertIn('not installed', res['message'])
        res = changes.run('plan', 'install_runtime', [])
        for key in ('steps', 'warnings', 'irreversible', 'revert', 'risk', 'requires_confirmation',
                    'requires_double_confirmation', 'apply_via'):
            self.assertIn(key, res)
        self.assertEqual(set(res['steps'][0]), {'description', 'command', 'effect'})
        self.assertTrue(res['requires_double_confirmation'])       # downloads can not be undone

    def test_sync_apply_and_revert_through_dispatcher(self):
        # install runs in the background in production; here call the core and record like the worker does
        res = actions.apply('install_runtime', {}, self.ctx)
        official_install = adapter.record_apply('install_runtime', {}, res, self.ctx)
        self.assertTrue(official_install)
        self.assertFalse(os.listdir(self.ctx.journal_dir))      # one journal only: working copy folded
        before = self.read('/etc/jail.conf.d/ollama.conf')
        applied = changes.run('apply', 'set_limits', ['1-2/2/4096/10'])
        self.assertEqual(applied['status'], 'ok', applied)
        self.assertTrue(applied['journal_id'])
        entry = ai_journal.load(applied['journal_id'])
        self.assertEqual(entry['action'], 'set_limits')
        self.assertIn('inverse', entry['state']['journal'])
        self.assertEqual(os.listdir(self.ctx.journal_dir), [])
        hist = changes.history()['items']
        self.assertEqual(sorted(i['action'] for i in hist), ['install_runtime', 'set_limits'])
        plan = changes.run('plan', 'revert', [applied['journal_id']])
        self.assertEqual(plan['status'], 'ok', plan)
        done = changes.run('apply', 'revert', [applied['journal_id']])
        self.assertEqual(done['status'], 'ok', done)
        self.assertEqual(self.read('/etc/jail.conf.d/ollama.conf'), before)
        self.assertTrue(ai_journal.load(applied['journal_id'])['reverted'])
        again = changes.run('plan', 'revert', [applied['journal_id']])
        self.assertEqual(again['status'], 'error')

    def test_install_revert_supersedes_in_official_journal(self):
        res = actions.apply('install_runtime', {}, self.ctx)
        install = adapter.record_apply('install_runtime', {}, res, self.ctx)
        limits = changes.run('apply', 'set_limits', ['1-2/2/4096/10'])['journal_id']
        plan = changes.run('plan', 'revert', [install])
        self.assertTrue(plan['requires_double_confirmation'])
        self.assertEqual(changes.run('apply', 'revert', [install])['status'], 'ok')
        self.assertEqual(ai_journal.load(limits)['reverted']['status'], 'superseded')
        self.assertTrue(ai_journal.load(install)['reverted'])

    def test_revert_flags_through_dispatcher(self):
        res = actions.apply('install_runtime', {}, self.ctx)
        install = adapter.record_apply('install_runtime', {}, res, self.ctx)
        lock = common.Lock(self.ctx).acquire()
        adapter.worker('job-p', lock.fd, 'pull_model', {'model': 'qwen2.5:3b'}, ctx=self.ctx)
        manifest = ops.model_manifest_path(self.ctx, 'qwen2.5', '3b')
        # default keeps the models
        plan = changes.run('plan', 'revert', [install])
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertTrue(any('kept' in w for w in plan['warnings']))
        self.assertFalse(any('models deleted' in i for i in plan['irreversible']))
        # keep_models=no deletes them, and the flag reaches the apply too
        plan = changes.run('plan', 'revert', [install, 'keep_models=no'])
        self.assertTrue(any('models deleted' in i for i in plan['irreversible']))
        self.assertTrue(plan['requires_double_confirmation'])
        done = changes.run('apply', 'revert', [install, 'keep_models=no'])
        self.assertEqual(done['status'], 'ok', done)
        self.assertFalse(os.path.exists(manifest))
        self.assertFalse(self.system.running)
        # force on a dependency-blocked revert
        res = actions.apply('install_runtime', {}, self.ctx)
        adapter.record_apply('install_runtime', {}, res, self.ctx)
        first = changes.run('apply', 'set_limits', ['0-1/2/8192/20'])['journal_id']
        changes.run('apply', 'set_limits', ['1-2/2/8192/20'])
        self.assertEqual(changes.run('plan', 'revert', [first])['status'], 'error')
        forced = changes.run('plan', 'revert', [first, 'force'])
        self.assertEqual(forced['status'], 'ok', forced)
        self.assertTrue(any('force' in w for w in forced['warnings']))
        self.assertEqual(changes.run('apply', 'revert', [first, 'force'])['status'], 'ok')
        self.assertTrue(ai_journal.load(first)['reverted'])

    def test_background_apply_returns_started(self):
        with mock.patch.object(adapter, 'spawn', return_value={'status': 'started', 'job': 'x', 'completed': [],
                                                               'done': False, 'steps': []}) as spawn:
            res = changes.run('apply', 'pull_model', ['qwen2.5:3b'])
        spawn.assert_called_once()
        self.assertEqual(res['status'], 'started')
        self.assertNotIn('journal_id', res)                    # the worker records it when it ends
        self.assertEqual(ai_journal.entries(), [])

    def test_worker_records_official_entry(self):
        lock = common.Lock(self.ctx).acquire()
        result = adapter.worker('job-2', lock.fd, 'pull_model', {'model': 'qwen2.5:3b'}, ctx=self.ctx)
        self.assertEqual(result['status'], 'ok')
        entry = ai_journal.load(result['official_journal'])
        self.assertEqual(entry['action'], 'pull_model')
        self.assertTrue(entry['irreversible'])
        # background revert through the worker marks the official entry
        lock = common.Lock(self.ctx).acquire()
        sid = entry['state']['setup_journal']
        out = adapter.worker('job-3', lock.fd, 'revert', {'journal': sid}, official_target=entry['id'], ctx=self.ctx)
        self.assertEqual(out['status'], 'ok', out)
        self.assertTrue(ai_journal.load(entry['id'])['reverted'])

    def test_cancel_registered_and_not_journaled(self):
        res = changes.run('apply', 'setup_cancel', [])
        self.assertEqual(res['status'], 'error')               # nothing running
        self.assertEqual(ai_journal.entries(), [])


if __name__ == '__main__':
    unittest.main()
