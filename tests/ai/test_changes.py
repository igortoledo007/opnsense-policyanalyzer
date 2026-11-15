import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import ai_helpers  # noqa: F401  (sets sys.path)
from ai import changes, journal, settings_journal, storage


CONFIG = """<?xml version="1.0"?>
<opnsense><OPNsense><policyanalyzer>
  <ai><enabled>{enabled}</enabled><provider>claude</provider><anonymize>1</anonymize></ai>
  <claude><apikey>{key}</apikey><model>claude-opus-5-5</model><effort>medium</effort></claude>
</policyanalyzer></OPNsense></opnsense>
"""


class Sandbox(unittest.TestCase):
    """ undo dir, snapshot and storage roots redirected to a temp dir """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.patches = [
            mock.patch.object(journal, 'UNDO_DIR', os.path.join(self.tmp, 'undo')),
            mock.patch.object(settings_journal, 'SNAPSHOT', os.path.join(self.tmp, 'snap.json')),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp)


class PrepareStorageTest(Sandbox):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, 'var', 'db')
        os.makedirs(self.root)
        # the real code only accepts /var/db/...; map it into the sandbox
        real_validate = storage.validate_prepare_path
        real_audit = storage.AuditLog
        self.patches += [
            mock.patch.object(storage, 'validate_prepare_path', lambda p: p if p.startswith(self.root) else
                              os.path.join(self.root, real_validate(p)[len('/var/db/'):])),
            mock.patch.object(storage, '_zfs_root_pool', lambda: None),
            mock.patch.object(storage, 'AuditLog', lambda path: real_audit(os.path.join(self.tmp, 's.log'))),
            mock.patch.object(os, 'chown', lambda *a: None),
        ]
        for p in self.patches[2:]:
            p.start()

    def test_plan_apply_revert(self):
        planned = changes.run('plan', 'prepare_storage', ['/var/db/ai/models'])
        self.assertEqual(planned['status'], 'ok', planned)
        self.assertTrue(planned['requires_confirmation'])
        self.assertEqual(len(planned['steps']), 1)
        self.assertEqual(set(planned['steps'][0]), {'description', 'command', 'effect'})
        self.assertIn('irreversible', planned)
        self.assertFalse(os.path.exists(os.path.join(self.root, 'ai')))       # plan changed nothing

        applied = changes.run('apply', 'prepare_storage', ['/var/db/ai/models'])
        self.assertTrue(applied['done'])
        self.assertTrue(os.path.isdir(os.path.join(self.root, 'ai', 'models')))
        jid = applied['journal_id']
        entry = journal.load(jid)
        self.assertEqual(entry['state']['created_dirs'],
                         [os.path.join(self.root, 'ai', 'models'), os.path.join(self.root, 'ai')])

        again = changes.run('plan', 'prepare_storage', ['/var/db/ai/models'])     # idempotent
        self.assertFalse(again['requires_confirmation'])

        history = changes.history()['items']
        self.assertEqual(history[0]['id'], jid)
        self.assertTrue(history[0]['revertible'])

        rplan = changes.run('plan', 'revert', [jid])
        self.assertEqual([s['command'].split()[0] for s in rplan['steps']], ['/bin/rmdir', '/bin/rmdir'])
        reverted = changes.run('apply', 'revert', [jid])
        self.assertTrue(reverted['done'])
        self.assertFalse(os.path.exists(os.path.join(self.root, 'ai')))
        self.assertTrue(journal.load(jid)['reverted'])
        self.assertEqual(changes.run('plan', 'revert', [jid])['status'], 'error')   # only once

    def test_revert_keeps_non_empty_dirs(self):
        applied = changes.run('apply', 'prepare_storage', ['/var/db/ai/models'])
        with open(os.path.join(self.root, 'ai', 'models', 'blob'), 'w') as fh:
            fh.write('x')
        rplan = changes.run('plan', 'revert', [applied['journal_id']])
        self.assertEqual(rplan['steps'], [])
        self.assertTrue(any('not empty' in w for w in rplan['warnings']))

    def test_rejects_paths_outside_var_db(self):
        res = changes.run('plan', 'prepare_storage', ['/etc/models'])
        self.assertEqual(res['status'], 'error')

    def test_unknown_action_and_bad_id(self):
        self.assertEqual(changes.run('plan', 'rm_rf', [])['status'], 'error')
        self.assertEqual(changes.run('plan', 'revert', ['../../etc/passwd'])['status'], 'error')


class ZfsPlanTest(unittest.TestCase):
    def test_dataset_step_when_root_on_zfs(self):
        with mock.patch.object(storage, '_zfs_root_pool', lambda: 'zroot'), \
                mock.patch.object(storage, '_dataset_exists', lambda n: False), \
                mock.patch.object(storage.os.path, 'isdir', lambda p: False):
            plan = storage.plan('/var/db/ai/models')
        cmds = [s['command'] for s in plan['steps']]
        self.assertEqual(cmds[0], '/sbin/zfs create -o mountpoint=/var/db/ai -o recordsize=1M -o compression=off '
                                  '-o atime=off -o primarycache=metadata zroot/ai')
        self.assertTrue(cmds[1].startswith('/bin/mkdir -p -m 0750'))

    def test_existing_dataset_untouched(self):
        with mock.patch.object(storage, '_zfs_root_pool', lambda: 'zroot'), \
                mock.patch.object(storage, '_dataset_exists', lambda n: True), \
                mock.patch.object(storage.os.path, 'isdir', lambda p: True):
            plan = storage.plan('/var/db/ai/models')
        self.assertEqual(plan['steps'], [])
        self.assertTrue(any('already exists' in w for w in plan['warnings']))


class SettingsJournalTest(Sandbox):
    def write_config(self, enabled, key):
        path = os.path.join(self.tmp, 'config.xml')
        with open(path, 'w') as fh:
            fh.write(CONFIG.format(enabled=enabled, key=key))
        return path

    def test_record_and_revert_plan_masks_secret(self):
        cfg = self.write_config(0, 'sk-ant-old-key-000000000000AAAA')
        settings_journal.snapshot('OPNsense/policyanalyzer', cfg)
        cfg = self.write_config(1, 'sk-ant-new-key-000000000000BBBB')
        rec = settings_journal.record('OPNsense/policyanalyzer', cfg)
        entry = journal.load(rec['journal_id'])
        self.assertEqual(entry['action'], 'settings')
        self.assertEqual(oct(os.stat(os.path.join(journal.UNDO_DIR, rec['journal_id'] + '.json')).st_mode & 0o777),
                         '0o600')
        self.assertNotIn('sk-ant-old', json.dumps(entry['completed']))
        with mock.patch.object(settings_journal, 'CONFIG_XML', cfg):
            plan = changes.run('plan', 'revert', [rec['journal_id']])
        self.assertEqual(plan['apply_via'], 'gui')
        self.assertEqual(plan['values'], {'ai.enabled': '0', 'claude.apikey': 'sk-ant-old-key-000000000000AAAA'})
        shown = json.dumps(plan['steps'])
        self.assertIn('****AAAA', shown)
        self.assertNotIn('sk-ant-old', shown)
        # backend never applies gui entries itself
        with mock.patch.object(settings_journal, 'CONFIG_XML', cfg):
            res = changes.run('apply', 'revert', [rec['journal_id']])
        self.assertEqual(res['apply_via'], 'gui')
        self.assertIsNone(journal.load(rec['journal_id'])['reverted'])

    def test_no_change_no_entry(self):
        cfg = self.write_config(1, 'k' * 30)
        settings_journal.snapshot('OPNsense/policyanalyzer', cfg)
        self.assertIsNone(settings_journal.record('OPNsense/policyanalyzer', cfg)['journal_id'])


class DependencyTest(Sandbox):
    def test_dependents_block_revert(self):
        base = journal.create('prepare_storage', {}, {'done': True, 'completed': ['x']}, state={})
        journal.create('prepare_storage', {}, {'done': True, 'completed': ['y']}, state={},
                       depends_on=[base['id']])
        plan = changes.run('plan', 'revert', [base['id']])
        self.assertTrue(plan['requires_double_confirmation'])
        self.assertIn('revert these later changes first', plan['warnings'][0])
        res = changes.run('apply', 'revert', [base['id']])
        self.assertEqual(res['status'], 'error')


if __name__ == '__main__':
    unittest.main()
