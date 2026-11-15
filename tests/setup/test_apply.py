"""
apply: execution, idempotency, lock, rollback on failure, cancel, background worker.
"""

import json
import os
import unittest
from unittest import mock

from setup_helpers import SetupTestCase, MODEL_LAYERS, common

from setup import actions, adapter, ops, runtime


def ops_wait_step():
    return runtime.wait_step('wait')


class TestApply(SetupTestCase):
    def install(self, **args):
        return actions.apply('install_runtime', args, self.ctx)

    def test_install_apply_and_idempotency(self):
        res = self.install()
        self.assertEqual(res['status'], 'ok', res)
        self.assertTrue(self.system.running)
        self.assertIn('zroot/ai/jail', self.system.datasets)
        self.assertTrue(os.path.isfile(self.root + '/var/db/ai/jail/usr/local/bin/ollama'))
        self.assertIn('ip4.addr = "127.0.0.1";', self.read('/etc/jail.conf.d/ollama.conf'))
        self.assertIn('jail_list="ollama"', self.read('/etc/rc.conf.d/jail'))
        self.assertIn('nameserver 127.0.0.1', self.read('/var/db/ai/jail/etc/resolv.conf'))
        self.assertFalse(os.path.exists(self.root + '/var/db/ai/.staging/base-15.1-RELEASE.txz'))  # cleaned
        self.assertEqual(json.loads(self.read('/var/db/policyanalyzer/runtime-limits.json'))['cpus'], '2-3')
        # devfs was only mounted temporarily
        self.assertFalse(any(m[2] == 'devfs' for m in self.system.mounts))
        journal = common.load_journal(self.ctx, res['journal'])
        self.assertEqual(journal['status'], 'applied')
        self.assertTrue(any(s['type'] == 'zfs_destroy' for s in journal['inverse']))
        self.assertIn('restore_file', [s['type'] for s in journal['inverse']])
        # log
        with open(self.ctx.log_file) as handle:
            lines = [json.loads(line) for line in handle]
        self.assertEqual(lines[0]['phase'], 'start')
        self.assertEqual(lines[-1]['status'], 'ok')
        # second apply: every step skipped, nothing downloaded again
        calls = len(self.http.requests)
        res2 = self.install()
        self.assertEqual(res2['status'], 'ok')
        # (read only checks always run; chown is mocked in the tests so it can not observe its own effect)
        self.assertTrue(all(e['status'] == 'skipped' for e in res2['executed']
                            if not e['description'].startswith(('Wait', 'Check', 'Give', 'Make'))), res2['executed'])
        downloads = [r for r in self.http.requests[calls:] if r[1].endswith('base.txz') and r[0] == 'GET']
        self.assertEqual(downloads, [])
        # plan after install: nothing pending
        plan = actions.plan('install_runtime', {}, self.ctx)
        self.assertEqual(plan['download_bytes'], 0)
        pending = [s['type'] for s in plan['steps'] if not s['already']]
        self.assertEqual(pending, ['chown', 'chown'])            # os.chown is mocked in the tests

    def test_apply_requires_root_and_valid_plan(self):
        ctx = common.Context(root=self.root, runner=self.system, http=self.http, ncpu=4, is_root=False,
                             official=None)
        self.assertEqual(actions.apply('install_runtime', {}, ctx)['status'], 'error')
        res = actions.apply('start_runtime', {}, self.ctx)        # not installed: blocked, nothing executed
        self.assertEqual(res['status'], 'blocked')
        self.assertEqual(self.system.writes(), [])

    def test_lock(self):
        with common.Lock(self.ctx):
            res = actions.apply('install_runtime', {}, self.ctx)
            self.assertEqual(res['status'], 'error')
            self.assertIn('another setup action', res['message'])
            plan = actions.plan('install_runtime', {}, self.ctx)
            self.assertEqual(plan['status'], 'blocked')
        self.assertEqual(self.system.writes(), [])
        self.assertEqual(self.install()['status'], 'ok')

    def test_rollback_on_failure(self):
        self.system.fail_on = 'pkg install'
        res = self.install()
        self.assertEqual(res['status'], 'failed')
        self.assertIn('pkg install', res['failed_step'] + res['message'] or '')
        # what was created is gone: dataset destroyed, devfs unmounted, no config written
        self.assertNotIn('zroot/ai/jail', self.system.datasets)
        self.assertFalse(any(m[2] == 'devfs' for m in self.system.mounts))
        self.assertFalse(os.path.exists(self.root + '/etc/jail.conf.d/ollama.conf'))
        self.assertFalse(os.path.exists(self.root + '/var/db/ai/jail'))
        self.assertTrue(all(r['status'] != 'error' for r in res['rollback']), res['rollback'])
        # the umount happened before the destroy
        cmds = [' '.join(c) for c in self.system.calls]
        self.assertLess(max(i for i, c in enumerate(cmds) if c.startswith('/sbin/umount')),
                        max(i for i, c in enumerate(cmds) if c.startswith('/sbin/zfs destroy')))
        journal = common.load_journal(self.ctx, res['journal'])
        self.assertEqual(journal['status'], 'failed')
        # a retry after fixing the cause works
        self.system.fail_on = None
        self.assertEqual(self.install()['status'], 'ok')

    def test_ollama_rc_has_writable_home_and_log(self):
        res = self.install()
        self.assertEqual(res['status'], 'ok', res)
        rc = self.read('/var/db/ai/jail/etc/rc.conf.d/ollama')
        self.assertIn('HOME=/var/lib/ollama', rc)
        self.assertIn('ollama_log="/var/log/ollama.log"', rc)
        chowns = [c for c in self.ctx_steps('install_runtime') if c['type'] == 'chown']
        self.assertIn(self.root + '/var/db/ai/jail/var/lib/ollama', [c['path'] for c in chowns])

    def ctx_steps(self, action):
        return actions.plan(action, {}, self.ctx)['steps']

    def test_ollama_dies_fails_fast_with_diagnostics(self):
        self.system.api_down = True
        self.system.ollama_alive = False
        log_path = self.root + '/var/db/ai/jail/var/log/ollama.log'
        real_wait = ops._wait_ollama

        def fast(ctx, step):
            # the log is written by the (fake) daemon once the jail exists
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, 'w') as handle:
                handle.write('Error: could not create directory /root/.ollama: permission denied\n')
            return real_wait(ctx, dict(step, grace=0, interval=0))
        with mock.patch.object(ops, '_wait_ollama', fast):
            res = self.install()
        self.assertEqual(res['status'], 'failed')
        self.assertIn('ollama exited inside the jail', res['message'])
        self.assertIn('permission denied', res['message'])
        diag = res['diagnostics']
        for key in ('jls', 'service_status', 'ps', 'sockstat', 'dmesg', 'ls'):
            self.assertIn(key, diag['commands'])
        self.assertIn('ollama_log', diag['files'])
        self.assertIn('jail_rc_conf_d_ollama', diag['files'])
        # captured before the rollback stopped the jail
        cmds = [' '.join(c) for c in self.system.calls]
        first_diag = cmds.index('/usr/sbin/jls -v -j ollama')
        stop = max(i for i, c in enumerate(cmds) if c.endswith('-r ollama'))
        self.assertLess(first_diag, stop)
        self.assertFalse(self.system.running)                    # still rolled back
        with open(self.ctx.log_file) as handle:
            self.assertTrue(any('diagnostics' in json.loads(l) for l in handle))

    def test_wait_timeout_while_alive(self):
        self.system.running = True
        self.system.api_down = True
        step = dict(ops_wait_step(), timeout=0, grace=0, interval=0)
        with self.assertRaises(common.SetupError) as err:
            ops.execute_step(self.ctx, step)
        self.assertIn('although ollama is running', str(err.exception))
        self.system.api_down = False
        self.assertEqual(ops.execute_step(self.ctx, step)[0], 'done')

    def test_listener_outside_loopback_rolls_back(self):
        self.system.listeners = ['127.0.0.1:11434', '192.0.2.1:11434']
        res = self.install()
        self.assertEqual(res['status'], 'failed')
        self.assertIn('192.0.2.1', res['message'])
        self.assertFalse(self.system.running)

    def test_remove_tree_guard(self):
        for path in ('/etc', '/var/db/ai/models', '/var/db/ai/../../etc'):
            with self.assertRaises(common.SetupError):
                ops.execute_step(self.ctx, {'type': 'remove_tree', 'path': self.root + path})
        os.makedirs(self.root + '/var/db/ai/jail/dev')
        self.system.mounts.append(('devfs', self.root + '/var/db/ai/jail/dev', 'devfs'))
        with self.assertRaises(common.SetupError):
            ops.execute_step(self.ctx, {'type': 'remove_tree', 'path': self.root + '/var/db/ai/jail'})


class TestModels(SetupTestCase):
    def test_pull_and_idempotency(self):
        res = actions.apply('pull_model', {'model': 'qwen2.5:3b'}, self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        manifest = ops.model_manifest_path(self.ctx, 'qwen2.5', '3b')
        self.assertTrue(os.path.isfile(manifest))
        for digest, data in MODEL_LAYERS:
            with open(ops.blob_path(self.ctx, digest), 'rb') as handle:
                self.assertEqual(handle.read(), data)
        n = len(self.http.requests)
        res = actions.apply('pull_model', {'model': 'qwen2.5:3b'}, self.ctx)
        self.assertEqual(res['status'], 'ok')
        self.assertFalse([r for r in self.http.requests[n:] if '/blobs/' in r[1]])

    def test_pull_bad_hash_rolls_back(self):
        digest = MODEL_LAYERS[1][0]
        self.http.blobs[digest] = b'tampered!!!!!!!!!'[:len(MODEL_LAYERS[1][1])].ljust(len(MODEL_LAYERS[1][1]), b'x')
        res = actions.apply('pull_model', {'model': 'qwen2.5:3b'}, self.ctx)
        self.assertEqual(res['status'], 'failed')
        self.assertIn('SHA256', res['message'])
        blobs = os.listdir(self.root + '/var/db/ai/models/blobs')
        self.assertEqual(blobs, [])                      # the first, valid blob was removed too
        self.assertFalse(os.path.exists(ops.model_manifest_path(self.ctx, 'qwen2.5', '3b')))

    def test_cancel_during_pull(self):
        def cancel_on_second(ref):
            if ref == MODEL_LAYERS[1][0]:
                common.write_atomic(self.ctx.cancel_file, '*\n')
        self.http.fail_blob_after = cancel_on_second
        res = actions.apply('pull_model', {'model': 'qwen2.5:3b'}, self.ctx)
        self.assertEqual(res['status'], 'cancelled')
        self.assertEqual(os.listdir(self.root + '/var/db/ai/models/blobs'), [])

    def test_shared_blobs_kept_on_remove(self):
        actions.apply('pull_model', {'model': 'qwen2.5:3b'}, self.ctx)
        actions.apply('pull_model', {'model': 'llama3.2:3b'}, self.ctx)
        shared = MODEL_LAYERS[2][0]
        plan = actions.plan('remove_model', {'model': 'qwen2.5:3b'}, self.ctx)
        self.assertEqual(plan['status'], 'ok')
        self.assertTrue(plan['irreversible'])            # undo downloads again
        res = actions.apply('remove_model', {'model': 'qwen2.5:3b'}, self.ctx)
        self.assertEqual(res['status'], 'ok')
        self.assertTrue(os.path.isfile(ops.blob_path(self.ctx, shared)))
        self.assertFalse(os.path.isfile(ops.blob_path(self.ctx, MODEL_LAYERS[0][0])))

    def test_benchmark(self):
        actions.apply('install_runtime', {}, self.ctx)
        actions.apply('pull_model', {'model': 'qwen2.5:3b'}, self.ctx)
        res = actions.apply('benchmark', {}, self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        self.assertEqual(res['result']['prompt_tps'], 20.0)
        self.assertEqual(res['result']['gen_tps'], 8.0)
        self.assertTrue(os.path.isfile(self.ctx.bench_file))
        self.assertNotIn('benchmark', [j['action'] for j in common.list_journals(self.ctx)])


class TestCancelAndWorker(SetupTestCase):
    def test_cancel_without_job(self):
        self.assertEqual(actions.plan('cancel', {}, self.ctx)['status'], 'blocked')
        self.assertEqual(actions.apply('cancel', {}, self.ctx)['status'], 'error')

    def test_cancel_running_job(self):
        state = common.State(self.ctx)
        state.update_job(id='j1', action='pull_model', status='running')
        with common.Lock(self.ctx):
            res = actions.apply('cancel', {}, self.ctx)
            self.assertEqual(res['status'], 'ok')
        self.assertEqual(self.read('/var/db/policyanalyzer/setup.cancel').strip(), 'j1')

    def test_worker_runs_and_releases_lock(self):
        lock = common.Lock(self.ctx).acquire()
        fd = os.dup(lock.fd)
        lock.release()
        lock2 = common.Lock(self.ctx).acquire()       # simulate the fd handed over by spawn()
        with mock.patch.object(adapter, 'record_apply', return_value=None):
            result = adapter.worker('job-1', lock2.fd, 'pull_model', {'model': 'qwen2.5:3b'}, ctx=self.ctx)
        os.close(fd)
        self.assertEqual(result['status'], 'ok')
        job = common.State(self.ctx).load()['job']
        self.assertEqual(job['status'], 'done')
        self.assertEqual(job['bytes_done'], job['bytes_total'])
        self.assertIsNone(common.lock_holder(self.ctx))


if __name__ == '__main__':
    unittest.main()
