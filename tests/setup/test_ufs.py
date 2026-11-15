"""
Installations without ZFS (UFS): models directory on the system disk, removal of the models with
uninstall_runtime, the space guard, the optional ZFS pool in a file (plan, simulated apply, revert,
remove_file_pool) and the ZFS behaviour that must stay as it was.
"""

import os
import stat
import unittest
from unittest import mock

import setup_helpers
from setup_helpers import SetupTestCase, common

from setup import actions, filepool, ops, runtime

GIB = common.GIB
MODELS = '/var/db/ai/models'
IMAGE = '/var/db/ai.zpool.img'


def sparse_allocate(fd, size, progress=None, ctx=None):
    """ the real _allocate reserves every byte; the tests only need the size """
    os.ftruncate(fd, size)
    if progress:
        progress(size, size)


class UfsTestCase(SetupTestCase):
    zfs = False
    free = 500 * GIB

    def setUp(self):
        super().setUp()
        for target, value in ((common, 'free_bytes'), (ops, '_allocate')):
            patcher = mock.patch.object(target, value, side_effect=self._free if value == 'free_bytes'
                                        else sparse_allocate)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _free(self, path):
        return self.free

    def tree(self):
        """ like SetupTestCase.tree(), but a (sparse) pool image is compared by size, never read """
        out = {}
        for dirpath, dirnames, filenames in os.walk(self.tmp):
            out[dirpath] = None
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.getsize(path) > common.MIB:
                    out[path] = ('size', os.path.getsize(path))
                    continue
                with open(path, 'rb') as handle:
                    out[path] = handle.read()
        return out

    def plan(self, action, **args):
        before = self.tree()
        writes = len(self.system.writes())
        result = actions.plan(action, args, self.ctx)
        self.assertEqual(self.tree(), before, 'plan %s wrote to the file system' % action)
        self.assertEqual(self.system.writes()[writes:], [], 'plan %s ran a mutating command' % action)
        return result

    def apply(self, action, **args):
        return actions.apply(action, args, self.ctx)

    def fake_installed(self):
        os.makedirs(self.root + '/var/db/ai/jail/usr/local/bin', exist_ok=True)
        open(self.root + '/var/db/ai/jail/.policyanalyzer-base', 'w').close()
        open(self.root + '/var/db/ai/jail/usr/local/bin/ollama', 'w').close()
        open(self.root + '/etc/jail.conf.d/ollama.conf', 'w').close()

    def add_model_file(self):
        os.makedirs(self.root + MODELS + '/blobs', exist_ok=True)
        with open(self.root + MODELS + '/blobs/sha256-' + 'a' * 64, 'wb') as handle:
            handle.write(b'weights')


class TestUfsDirectory(UfsTestCase):
    def test_install_plan_uses_a_directory_and_warns(self):
        res = self.plan('install_runtime')
        self.assertEqual(res['status'], 'ok', res.get('errors'))
        types = [s['type'] for s in res['steps']]
        self.assertEqual(types[0], 'mkdir')
        self.assertNotIn('zfs_create', types)
        self.assertTrue(any('is not a ZFS dataset' in w for w in res['warnings']))
        self.assertTrue(any('shares the file system of /var' in w for w in res['warnings']))

    def test_status_reports_shared_disk(self):
        res = self.plan('status_runtime')['result']
        self.assertIsNone(res['ai_dataset'])
        self.assertIsNone(res['file_pool'])
        self.assertTrue(res['models_fs']['shares_var'])
        self.assertTrue(any('shares the file system of /var' in w for w in res['warnings']))

    def test_storage_plan_on_ufs(self):
        from ai import storage
        with mock.patch.object(storage, '_zfs_root_pool', return_value=None), \
                mock.patch.object(storage, '_mount_of', return_value=('/dev/gpt/rootfs', '/', 'ufs')):
            res = storage.plan(MODELS)
        self.assertIsNone(res['dataset'])
        self.assertNotIn('zfs_create', [s['type'] for s in res['steps']])
        self.assertTrue(any('share the system disk' in w for w in res['warnings']))

    def test_storage_plan_uses_the_file_pool_dataset(self):
        from ai import storage
        with mock.patch.object(storage, '_zfs_root_pool', return_value=None), \
                mock.patch.object(storage, '_mount_of', return_value=('aipool/ai', '/var/db/ai', 'zfs')):
            res = storage.plan(MODELS)
        self.assertEqual(res['dataset'], 'aipool/ai')
        self.assertNotIn('zfs_create', [s['type'] for s in res['steps']])
        self.assertFalse(any('share the system disk' in w for w in res['warnings']))


class TestUfsRemoveModels(UfsTestCase):
    def test_cli_token(self):
        self.assertEqual(actions.parse_cli_args('uninstall_runtime', ['+remove_dataset', MODELS]),
                         {'remove_dataset': 'yes', 'confirm': MODELS})

    def test_plan_requires_the_path_as_confirmation(self):
        self.fake_installed()
        self.add_model_file()
        res = self.plan('uninstall_runtime', remove_dataset='yes')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('confirm=%s' % MODELS in e for e in res['errors']), res['errors'])
        self.assertFalse(any('nothing to destroy' in e for e in res['errors']))
        res = self.plan('uninstall_runtime', remove_dataset='yes', confirm='zroot/ai')
        self.assertEqual(res['status'], 'blocked')
        res = self.plan('uninstall_runtime', remove_dataset='yes', confirm=MODELS)
        self.assertEqual(res['status'], 'ok', res['errors'])
        self.assertEqual(res['risk'], 'high')
        last = res['steps'][-1]
        self.assertEqual((last['type'], last['path'], last['models']), ('remove_tree', self.root + MODELS, True))
        self.assertTrue(any('permanently deleted' in i and MODELS in i for i in res['irreversible']))
        self.assertNotIn('zfs_destroy', [s['type'] for s in res['steps']])

    def test_apply_deletes_jail_and_models(self):
        self.fake_installed()
        self.add_model_file()
        res = self.apply('uninstall_runtime', remove_dataset='yes', confirm=MODELS)
        self.assertEqual(res['status'], 'ok', res)
        self.assertFalse(os.path.exists(self.root + MODELS))
        self.assertFalse(os.path.exists(self.root + '/var/db/ai/jail'))
        self.assertFalse(os.path.exists(self.root + '/etc/jail.conf.d/ollama.conf'))
        journal = common.load_journal(self.ctx, res['journal'])
        self.assertTrue(any('permanently deleted' in i for i in journal['irreversible']))

    def test_keep_models_by_default(self):
        self.fake_installed()
        self.add_model_file()
        res = self.apply('uninstall_runtime')
        self.assertEqual(res['status'], 'ok', res)
        self.assertTrue(os.path.isfile(self.root + MODELS + '/blobs/sha256-' + 'a' * 64))

    def test_guard_of_the_models_directory(self):
        os.makedirs(self.root + MODELS + '/blobs', exist_ok=True)
        for step in ({'type': 'remove_tree', 'path': self.root + MODELS},
                     {'type': 'remove_tree', 'path': self.root + MODELS + '/blobs', 'models': True},
                     {'type': 'remove_tree', 'path': self.root + '/var/db/ai', 'models': True},
                     {'type': 'remove_tree', 'path': self.root + '/var/db/policyanalyzer', 'models': True}):
            with self.assertRaises(common.SetupError, msg=step):
                ops.execute_step(self.ctx, step)
        self.system.mounts.append((MODELS, self.root + '/var/db/ai/jail/var/lib/ollama/models', 'nullfs'))
        os.makedirs(self.root + '/var/db/ai/jail/var/lib/ollama/models')
        with self.assertRaises(common.SetupError):
            ops.execute_step(self.ctx, {'type': 'remove_tree', 'path': self.root + '/var/db/ai/jail'})
        self.system.mounts = [(self.root + MODELS, MODELS, 'nullfs')]
        with self.assertRaises(common.SetupError):
            ops.execute_step(self.ctx, {'type': 'remove_tree', 'path': self.root + MODELS, 'models': True})
        self.assertTrue(os.path.isdir(self.root + MODELS + '/blobs'))


class TestSpaceGuard(UfsTestCase):
    def test_install_blocked_below_the_system_floor(self):
        res = self.plan('install_runtime')
        needed = res['space_needed']
        self.free = needed + 3 * GIB
        self.assertEqual(self.plan('install_runtime')['status'], 'ok')
        self.free = needed + int(1.5 * GIB)          # would leave 1.5 GiB on the file system of /var
        res = self.plan('install_runtime')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('not enough space for the runtime' in e for e in res['errors']), res['errors'])
        self.assertTrue(any(h.get('action', {}).get('id') == 'remove_model' for h in res['warning_actions']))

    def test_pull_blocked_with_20_percent_margin(self):
        big = {d: 10 * GIB for d, _ in setup_helpers.MODEL_LAYERS[:1]}
        self.http.manifests[('qwen3', '8b')] = setup_helpers.model_manifest(sizes=big)
        self.free = 12 * GIB + 64 * common.MIB        # 10 GiB + 20 % = 12 GiB, plus a bit
        self.assertEqual(self.plan('pull_model', model='qwen3:8b', large='yes')['status'], 'ok')
        self.free = int(11.9 * GIB)
        res = self.plan('pull_model', model='qwen3:8b', large='yes')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('not enough space for model qwen3:8b' in e for e in res['errors']), res['errors'])

    def test_small_pull_keeps_two_gib_on_ufs(self):
        self.free = int(1.9 * GIB)
        res = self.plan('pull_model', model='qwen2.5:3b')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('margin of 2.0 GiB' in e for e in res['errors']), res['errors'])
        self.assertTrue(any('shares the file system of /var' in w for w in res['warnings']))

    def test_check_helper(self):
        self.free = 10 * GIB
        res = common.space_check(self.ctx, self.ctx.models_dir, 7 * GIB, 'x')
        self.assertEqual(res['margin'], 2 * GIB)
        self.assertEqual(res['errors'], [])
        res = common.space_check(self.ctx, self.ctx.models_dir, int(8.5 * GIB), 'x')
        self.assertTrue(res['errors'])
        res = common.space_check(self.ctx, self.ctx.models_dir, 8 * GIB, 'x', exact=True)
        self.assertEqual(res['errors'], [])


class TestFilePoolPlan(UfsTestCase):
    def test_plan(self):
        res = self.plan('create_file_pool', size='8', arc_mb='512')
        self.assertEqual(res['status'], 'ok', res.get('errors'))
        self.assertTrue(res['background'])
        self.assertEqual(res['irreversible'], [])
        types = [s['type'] for s in res['steps']]
        self.assertEqual(types, ['run', 'run', 'write_file', 'write_file', 'image_create', 'md_attach',
                                 'zpool_create', 'zfs_create', 'mkdir'])
        steps = {s['type']: s for s in res['steps']}
        self.assertEqual(steps['image_create']['size'], 8 * GIB)
        self.assertEqual(steps['md_attach']['argv'], ['/sbin/mdconfig', '-a', '-t', 'vnode', '-f', IMAGE,
                                                      '-u', '10'])
        zpool = steps['zpool_create']['argv']
        for item in ('cachefile=none', 'mountpoint=none', 'canmount=off', 'ashift=12'):
            self.assertIn(item, zpool)
        self.assertEqual(zpool[-2:], ['aipool', '/dev/md10'])
        dataset = steps['zfs_create']['argv']
        for item in ('mountpoint=/var/db/ai', 'recordsize=1M', 'primarycache=metadata'):
            self.assertIn(item, dataset)
        self.assertIn('vfs.zfs.arc.max=%d' % (512 * common.MIB), res['steps'][1]['argv'])
        script = next(s for s in res['steps'] if s.get('path', '').endswith(filepool.RC_SCRIPT))
        self.assertEqual(script['mode'], '0755')
        for item in ('# REQUIRE: FILESYSTEMS', '# BEFORE: jail', 'rcvar="policyanalyzer_aipool_enable"',
                     '/sbin/zpool import -d "/dev/md${unit}" -o cachefile=none "${pool}"',
                     '/sbin/mdconfig -a -t vnode -f "${img}" -u "${unit}"', '/sbin/zpool export',
                     'run_rc_command "$1"'):
            self.assertIn(item, script['content'])
        conf = next(s for s in res['steps'] if s.get('path', '').endswith(filepool.RC_CONF))['content']
        self.assertIn('policyanalyzer_aipool_enable="YES"', conf)
        self.assertIn('policyanalyzer_aipool_unit="10"', conf)
        self.assertIn('policyanalyzer_aipool_arc_max="%d"' % (512 * common.MIB), conf)
        self.assertTrue(any('two file systems are stacked' in w for w in res['warnings']))

    def test_cli_and_validation(self):
        self.assertEqual(actions.parse_cli_args('create_file_pool', ['40', '512']), {'size': '40', 'arc_mb': '512'})
        self.assertEqual(actions.parse_cli_args('remove_file_pool', ['aipool']), {'confirm': 'aipool'})
        for args in ({}, {'size': '2'}, {'size': 'x'}, {'size': '9999'}, {'size': '8', 'arc_mb': '1'},
                     {'size': '8', 'image': '/var/db/ai/x.img'}, {'size': '8', 'image': '/etc/x.img'},
                     {'size': '8', 'image': '/var/db/../x.img'}):
            self.assertEqual(actions.plan('create_file_pool', args, self.ctx)['status'], 'error', args)

    def test_md_unit_skips_used_units(self):
        self.system.md = {10: '/var/db/other.img', 11: ''}
        res = self.plan('create_file_pool', size='8')
        self.assertIn('/dev/md12', next(s for s in res['steps'] if s['type'] == 'zpool_create')['argv'])

    def test_blocked_when_not_enough_space(self):
        self.free = 9 * GIB                    # 8 GiB image would leave 1 GiB on the system disk
        res = self.plan('create_file_pool', size='8')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('not enough space for the pool image' in e for e in res['errors']), res['errors'])

    def test_blocked_when_models_or_runtime_exist(self):
        self.add_model_file()
        res = self.plan('create_file_pool', size='8')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('already holds files' in e for e in res['errors']))

    def test_blocked_while_running(self):
        self.system.running = True
        res = self.plan('create_file_pool', size='8')
        self.assertTrue(any('stop it first' in e for e in res['errors']))

    def test_blocked_on_a_zfs_system(self):
        self.system.mounts.append(('zroot/ROOT/default', '/', 'zfs'))
        res = self.plan('create_file_pool', size='8')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('already on ZFS' in e for e in res['errors']))


class TestFilePoolApply(UfsTestCase):
    def create(self, **args):
        args.setdefault('size', '8')
        res = self.apply('create_file_pool', **args)
        self.assertEqual(res['status'], 'ok', res)
        return res

    def assert_clean(self):
        self.assertFalse(os.path.exists(self.root + IMAGE))
        self.assertEqual(self.system.md, {})
        self.assertNotIn('aipool', self.system.pools)
        self.assertFalse(os.path.exists(self.root + filepool.RC_SCRIPT))
        self.assertFalse(os.path.exists(self.root + filepool.RC_CONF))
        self.assertFalse(any(m[0].startswith('aipool') for m in self.system.mounts))

    def test_apply_idempotency_and_revert(self):
        res = self.create(arc_mb='512')
        self.assertEqual(os.path.getsize(self.root + IMAGE), 8 * GIB)
        self.assertEqual(self.system.md, {10: IMAGE})
        self.assertIn('aipool', self.system.pools)
        self.assertEqual(self.system.datasets['aipool/ai'], '/var/db/ai')
        self.assertIn(('aipool/ai', '/var/db/ai', 'zfs'), self.system.mounts)
        self.assertTrue(os.path.isdir(self.root + MODELS))
        self.assertTrue(self.system.zfs_loaded)
        self.assertEqual(self.system.sysctl['vfs.zfs.arc.max'], str(512 * common.MIB))
        mode = stat.S_IMODE(os.stat(self.root + filepool.RC_SCRIPT).st_mode)
        self.assertEqual(mode, 0o755)
        # the rest of the setup now sees /var/db/ai as a ZFS dataset
        info = runtime.probe(self.ctx)
        self.assertEqual((info['ai_dataset'], info['jail_dataset']), ('aipool/ai', 'aipool/ai/jail'))
        install = self.plan('install_runtime')
        self.assertEqual(install['steps'][0]['dataset'], 'aipool/ai/jail')
        self.assertFalse(any('shares the file system of /var' in w for w in install['warnings']))
        state = self.plan('status_runtime')['result']['file_pool']
        self.assertTrue(state['pool_imported'] and state['dataset_mounted'] and state['boot_enabled'])
        # second apply: nothing to do
        again = self.apply('create_file_pool', size='8', arc_mb='512')
        self.assertEqual(again['status'], 'ok', again)
        self.assertTrue(again.get('nothing_changed'), again)
        # revert while empty: everything goes away, in the right order
        plan = actions.revert_plan(res['journal'], {}, self.ctx)
        self.assertEqual(plan['status'], 'ok', plan)
        order = [s['type'] for s in plan['steps']]
        self.assertLess(order.index('zfs_destroy'), order.index('zpool_destroy'))
        self.assertLess(order.index('zpool_destroy'), order.index('md_detach'))
        self.assertLess(order.index('md_detach'), order.index('image_remove'))
        self.assertGreater(order.index('restore_file'), order.index('image_remove'))
        out = actions.revert_apply(res['journal'], {}, self.ctx)
        self.assertEqual(out['status'], 'ok', out)
        self.assert_clean()
        self.assertEqual(self.system.sysctl['vfs.zfs.arc.max'], '0')

    def test_revert_refused_when_the_pool_holds_models(self):
        res = self.create()
        self.add_model_file()
        out = actions.revert_apply(res['journal'], {}, self.ctx)
        self.assertEqual(out['status'], 'failed', out)
        self.assertIn('holds files', out['message'])
        self.assertIn('aipool', self.system.pools)
        self.assertEqual(self.system.md, {10: IMAGE})
        self.assertTrue(os.path.isfile(self.root + IMAGE))
        self.assertTrue(os.path.isfile(self.root + filepool.RC_SCRIPT))       # boot import still configured
        self.assertTrue(os.path.isfile(self.root + filepool.RC_CONF))
        self.assertTrue(os.path.isfile(self.root + MODELS + '/blobs/sha256-' + 'a' * 64))

    def test_failure_rolls_back(self):
        self.system.fail_on = 'zpool create'
        res = self.apply('create_file_pool', size='8')
        self.assertEqual(res['status'], 'failed', res)
        self.assert_clean()

    def test_remove_file_pool(self):
        self.create()
        self.add_model_file()
        res = self.plan('remove_file_pool')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('confirm=aipool' in e for e in res['errors']))
        res = self.plan('remove_file_pool', confirm='aipool')
        self.assertEqual(res['status'], 'ok', res['errors'])
        self.assertEqual(res['risk'], 'high')
        self.assertTrue(any('permanently deleted' in i for i in res['irreversible']))
        self.assertEqual([s['type'] for s in res['steps']],
                         ['write_file', 'write_file', 'zpool_destroy', 'md_detach', 'image_remove'])
        out = self.apply('remove_file_pool', confirm='aipool')
        self.assertEqual(out['status'], 'ok', out)
        self.assert_clean()
        journal = common.load_journal(self.ctx, out['journal'])
        self.assertEqual(journal['revert_action'], {'action': 'create_file_pool',
                                                    'args': {'size': 8, 'image': IMAGE}})
        # revert = an empty pool again
        back = actions.revert_apply(out['journal'], {}, self.ctx)
        self.assertEqual(back['status'], 'ok', back)
        self.assertIn('aipool', self.system.pools)
        self.assertFalse(os.path.exists(self.root + MODELS + '/blobs'))

    def test_remove_refused_with_runtime_installed(self):
        self.create()
        self.fake_installed()
        res = self.plan('remove_file_pool', confirm='aipool')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('uninstall_runtime' in e for e in res['errors']))

    def test_uninstall_with_remove_dataset_uses_the_pool_dataset(self):
        self.create()
        self.fake_installed()
        res = self.plan('uninstall_runtime', remove_dataset='yes', confirm='aipool/ai')
        self.assertEqual(res['status'], 'ok', res['errors'])
        self.assertIn('aipool/ai', [s.get('dataset') for s in res['steps'] if s['type'] == 'zfs_destroy'])
        self.assertNotIn('remove_tree', [s['type'] for s in res['steps'] if s.get('models')])

    def test_step_guards(self):
        for step in ({'type': 'image_create', 'path': self.root + '/var/db/ai/x.img', 'size': GIB},
                     {'type': 'image_create', 'path': self.root + '/etc/x.img', 'size': GIB},
                     {'type': 'image_remove', 'path': self.root + '/var/db/policyanalyzer/x'},
                     {'type': 'zpool_destroy', 'pool': 'zroot'}):
            with self.assertRaises(common.SetupError, msg=step):
                ops.execute_step(self.ctx, step)
        self.create()
        with self.assertRaises(common.SetupError):
            ops.execute_step(self.ctx, {'type': 'image_remove', 'path': self.root + IMAGE})     # still attached
        with self.assertRaises(common.SetupError):
            ops.execute_step(self.ctx, {'type': 'md_detach', 'unit': 10, 'path': '/var/db/other.img'})
        with self.assertRaises(common.SetupError):
            ops.execute_step(self.ctx, {'type': 'md_attach', 'unit': 10, 'path': '/var/db/other.img'})


class TestZfsUnchanged(SetupTestCase):
    """ ZFS root: same plans as before, no UFS specific step or warning """

    def test_uninstall_and_install(self):
        open(self.root + '/etc/jail.conf.d/ollama.conf', 'w').close()
        self.system.datasets['zroot/ai/jail'] = '/var/db/ai/jail'
        res = actions.plan('uninstall_runtime', {'remove_dataset': 'yes', 'confirm': 'zroot/ai'}, self.ctx)
        self.assertEqual(res['status'], 'ok', res.get('errors'))
        self.assertEqual([s['dataset'] for s in res['steps'] if s['type'] == 'zfs_destroy'],
                         ['zroot/ai/jail', 'zroot/ai'])
        self.assertFalse(any(s.get('models') for s in res['steps']))
        res = actions.plan('uninstall_runtime', {'remove_dataset': 'yes', 'confirm': MODELS}, self.ctx)
        self.assertEqual(res['status'], 'blocked')              # the dataset name is still the confirmation
        res = actions.plan('install_runtime', {}, self.ctx)
        self.assertEqual(res['steps'][0]['type'], 'zfs_create')
        self.assertFalse(any('shares the file system of /var' in w for w in res['warnings']))
        self.assertIsNone(actions.plan('status_runtime', {}, self.ctx)['result']['file_pool'])



class TestSmallHostDefaults(SetupTestCase):
    """ a 2-cpu host (the UFS lab VM): the default cpu set 2-3 does not exist """

    def ctx_with(self, ncpu):
        return common.Context(root=self.root, runner=self.system, http=self.http, ncpu=ncpu, is_root=True,
                              clock=lambda: 1794000000)

    def test_two_cpus_use_upper_half_and_one_thread(self):
        out = runtime.runtime_args(self.ctx_with(2), {})
        self.assertEqual(out['cpus'], '1')
        self.assertEqual(out['threads'], 1)

    def test_four_cpus_keep_defaults(self):
        out = runtime.runtime_args(self.ctx_with(4), {})
        self.assertEqual(out['cpus'], '2-3')
        self.assertEqual(out['threads'], 2)

    def test_explicit_threads_still_validated(self):
        with self.assertRaises(ValueError):
            runtime.runtime_args(self.ctx_with(2), {'threads': '2'})


class TestLabFindings(SetupTestCase):
    """ round 2 of the UFS lab (OPNsense nano, /var/log on tmpfs, pool in a file) """

    def test_jail_console_log_outside_var_log(self):
        conf = runtime.render_jail_conf(self.ctx, dict(common.DEFAULT_LIMITS), False)
        self.assertIn('exec.consolelog = "/var/db/ai/jail-ollama.console.log";', conf)
        self.assertNotIn('/var/log/', conf)

    def test_zfs_destroy_waits_for_dying_jail(self):
        step = {'type': 'zfs_destroy', 'dataset': 'zroot/ai/jail', 'recursive': True}
        calls = []
        real_run = self.ctx.runner.run

        def run(argv, *a, **kw):
            if argv[:2] == ['/sbin/zfs', 'destroy']:
                calls.append(argv)
                if len(calls) < 3:
                    return 1, '', "cannot destroy 'zroot/ai/jail': dataset is busy"
                return 0, '', ''
            return real_run(argv, *a, **kw)
        with mock.patch.object(common, 'dataset_exists', return_value=True), \
                mock.patch.object(common, 'mounts_below', return_value=[]), \
                mock.patch.object(self.ctx.runner, 'run', side_effect=run), \
                mock.patch.object(ops.time, 'sleep'):
            status, _ = ops.execute_step(self.ctx, step)
        self.assertEqual(status, 'done')
        self.assertEqual(len(calls), 3)

    def test_zfs_destroy_other_error_fails_at_once(self):
        step = {'type': 'zfs_destroy', 'dataset': 'zroot/ai/jail'}
        with mock.patch.object(common, 'dataset_exists', return_value=True), \
                mock.patch.object(common, 'mounts_below', return_value=[]), \
                mock.patch.object(self.ctx.runner, 'run', return_value=(1, '', 'permission denied')), \
                mock.patch.object(ops.time, 'sleep') as sleep:
            with self.assertRaises(common.SetupError):
                ops.execute_step(self.ctx, step)
        sleep.assert_not_called()

    def test_uninstall_stop_keeps_its_inverse(self):
        res = runtime.uninstall_plan(self.ctx, {})
        stop = [s for s in res['steps'] if s.get('argv') and s['argv'][-2:-1] == ['-r'] or
                (s.get('description') or '').startswith('Stop jail')]
        self.assertTrue(stop)
        self.assertTrue(stop[0].get('undo_argv'))
        self.assertEqual(res['revert_action']['action'], 'install_runtime')

    def test_rc_stop_retries_export(self):
        script = filepool.render_rc_script()
        self.assertIn('until /sbin/zpool export', script)
        self.assertIn('sleep 3', script)


class TestLabRound3(SetupTestCase):
    """ round 3 of the lab: console log left in /var/db/ai, pid parsed from "status" by rc.freebsd """

    def test_console_log_does_not_block_the_pool(self):
        d = self.root + '/var/db/ai'
        os.makedirs(d + '/.staging/blobs', exist_ok=True)
        with open(d + '/jail-ollama.console.log', 'w') as fh:
            fh.write('boot\n')
        self.assertFalse(filepool._has_files(d, filepool.LEFTOVER_FILES))
        with open(d + '/other', 'w') as fh:
            fh.write('x')
        self.assertTrue(filepool._has_files(d, filepool.LEFTOVER_FILES))

    def test_status_has_no_digits_in_last_field(self):
        script = filepool.render_rc_script()
        body = script[script.index('_status()'):]
        body = body[:body.index('\n}')]
        for line in body.splitlines():
            if 'echo' in line:
                self.assertTrue(line.rstrip().endswith(('imported"',)), line)

    def test_uninstall_with_models_deletes_console_log(self):
        res = runtime.uninstall_plan(self.ctx, {'remove_dataset': True, 'confirm': 'zroot/ai'})
        paths = [s.get('path', '') for s in res['steps'] if s['type'] == 'unlink']
        self.assertTrue(any(p.endswith('/var/db/ai/jail-ollama.console.log') for p in paths))


class TestInstallWithoutStorageStep(SetupTestCase):
    """ after remove_file_pool (or skipping prepare_storage) /var/db/ai/models does not exist """

    def test_install_creates_models_dir(self):
        import shutil
        shutil.rmtree(self.ctx.models_dir, ignore_errors=True)
        res = runtime.install_plan(self.ctx, {})
        mk = [s for s in res['steps'] if s['type'] == 'mkdir' and s['path'] == self.ctx.models_dir]
        self.assertTrue(mk)
        order = [(s['type'], s.get('path')) for s in res['steps']]
        self.assertLess(order.index(('mkdir', self.ctx.models_dir)), order.index(('chown', self.ctx.models_dir)))


class TestRevertWithConsoleLog(SetupTestCase):
    """ macro review: the jail console log left in /var/db/ai must not block destroying an empty pool dataset """

    def test_only_empty_ignores_console_log(self):
        d = self.root + '/var/db/ai'
        os.makedirs(d + '/models', exist_ok=True)
        with open(d + '/jail-ollama.console.log', 'w') as fh:
            fh.write('boot\n')
        self.assertFalse(ops._has_files(d))
        with open(d + '/models/blob', 'w') as fh:
            fh.write('x')
        self.assertTrue(ops._has_files(d))

if __name__ == '__main__':
    unittest.main()
