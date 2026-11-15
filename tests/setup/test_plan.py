"""
plan of every runtime action (read only) and parameter validation.
"""

import os
import unittest

from setup_helpers import SetupTestCase, BASE_SHA, BASE_TXZ, common

from setup import actions, runtime


class TestValidation(unittest.TestCase):
    def test_model_names(self):
        self.assertEqual(common.validate_model('qwen2.5:3b'), ('qwen2.5', '3b'))
        self.assertEqual(common.validate_model('phi4-mini'), ('phi4-mini', 'latest'))
        for bad in ('Qwen:3b', '../x', 'a b', 'x;rm', 'ns/model:1', '', 'a' * 70, ':3b', 'x:'):
            with self.assertRaises(ValueError, msg=bad):
                common.validate_model(bad)

    def test_cpuset(self):
        self.assertEqual(common.parse_cpuset('2-3', 4), [2, 3])
        self.assertEqual(common.parse_cpuset('0,2', 4), [0, 2])
        self.assertEqual(common.format_cpuset([0, 1, 3]), '0-1,3')
        for bad in ('4', '3-2', '1-', 'a', '0;1', '1,,2'):
            with self.assertRaises(ValueError, msg=bad):
                common.parse_cpuset(bad, 4)

    def test_cli_tokens(self):
        parse = actions.parse_cli_args
        self.assertEqual(parse('set_limits', ['2-3/2/8192/20']),
                         {'cpus': '2-3', 'threads': '2', 'ctx': '8192', 'nice': '20'})
        self.assertEqual(parse('set_limits', ['0_2', '2', '4096', '10', '', '']),
                         {'cpus': '0,2', 'threads': '2', 'ctx': '4096', 'nice': '10'})
        self.assertEqual(parse('pull_model', ['qwen3:8b', '+custom', '+large']),
                         {'model': 'qwen3:8b', 'custom': 'yes', 'large': 'yes'})
        self.assertEqual(parse('uninstall_runtime', ['+remove_dataset', 'zroot/ai']),
                         {'remove_dataset': 'yes', 'confirm': 'zroot/ai'})
        self.assertEqual(parse('install_runtime', ['latest', '1-2', '+no_start']),
                         {'branch': 'latest', 'cpus': '1-2', 'start': 'no'})
        for action, tokens in (('pull_model', ['a', 'b']), ('pull_model', ['x;y']), ('pull_model', ['$(id)']),
                               ('pull_model', ['+evil']), ('set_limits', ['shell=1']), ('revert', ['../x']),
                               ('pull_model', ['a b'])):
            with self.assertRaises(ValueError, msg=tokens):
                parse(action, tokens)

    def test_journal_id(self):
        common.validate_journal_id('20261107T183000-install_runtime-a1b2c3')
        for bad in ('x', '../../etc/passwd', '20261107T183000-a1b2c3;'):
            with self.assertRaises(ValueError):
                common.validate_journal_id(bad)


class TestPlans(SetupTestCase):
    def plan(self, action, **args):
        before = self.tree()
        result = actions.plan(action, args, self.ctx)
        self.assertEqual(self.tree(), before, 'plan %s wrote to the file system' % action)
        self.assertEqual(self.system.writes(), [], 'plan %s ran a mutating command' % action)
        return result

    def test_install_plan(self):
        res = self.plan('install_runtime')
        self.assertEqual(res['status'], 'ok', res.get('errors'))
        types = [s['type'] for s in res['steps']]
        self.assertEqual(types[0], 'zfs_create')
        self.assertIn('fetch', types)
        fetch = res['steps'][types.index('fetch')]
        self.assertEqual(fetch['sha256'], BASE_SHA)
        self.assertEqual(res['download_bytes'], len(BASE_TXZ) + common.PKG_DOWNLOAD_ESTIMATE['quarterly'])
        self.assertTrue(res['irreversible'])
        self.assertTrue(res['requires_confirmation'])
        self.assertTrue(res['background'])
        self.assertTrue(any('racct' in w for w in res['warnings']))
        conf = next(s for s in res['steps'] if s.get('path', '').endswith('/etc/jail.conf.d/ollama.conf'))['content']
        self.assertIn('ip4.addr = "127.0.0.1";', conf)
        self.assertNotIn('lo0', conf.replace('alias on lo0', ''))      # never an interface alias
        self.assertNotIn('vnet', conf)
        self.assertIn('ip6 = "disable";', conf)
        self.assertIn('/var/db/ai/models /var/db/ai/jail/var/lib/ollama/models nullfs rw', conf)
        self.assertIn('cpuset -l 2-3 -j ollama', conf)
        self.assertNotIn('rctl', conf)
        rc = next(s for s in res['steps'] if s.get('path', '').endswith('/etc/rc.conf.d/ollama'))['content']
        for item in ('OLLAMA_HOST=127.0.0.1:11434', 'OLLAMA_NUM_PARALLEL=1', 'OLLAMA_MAX_LOADED_MODELS=1',
                     'OLLAMA_KEEP_ALIVE=5m', 'ollama_context_length="8192"', 'ollama_nice="20"',
                     'ollama_use_vulkan="0"'):
            self.assertIn(item, rc)
        pkg = [s for s in res['steps'] if s['type'] == 'run' and '/usr/sbin/chroot' in (s.get('argv') or [])]
        self.assertTrue(pkg and all(s['argv'][1] == self.ctx.jail_dir for s in pkg))     # never the host pkg db
        repo = next(s for s in res['steps'] if s.get('path', '').endswith('pkg/repos/FreeBSD.conf'))['content']
        self.assertIn('quarterly', repo)
        self.assertIn('FreeBSD-ports-kmods: { enabled: no }', repo)

    def test_install_plan_racct_and_space(self):
        self.system.sysctl['kern.racct.enable'] = '1'
        res = self.plan('install_runtime', cpus='1-2', branch='latest', mem_gb='8')
        conf = next(s for s in res['steps'] if s.get('path', '').endswith('ollama.conf'))['content']
        self.assertIn('rctl -a jail:ollama:memoryuse:deny=8g', conf)
        self.assertIn('cpuset -l 1-2 -j ollama', conf)
        with unittest.mock.patch.object(common, 'free_bytes', return_value=100 * common.MIB):
            res = self.plan('install_runtime')
        self.assertEqual(res['status'], 'blocked')
        self.assertTrue(any('not enough space' in e for e in res['errors']))

    def test_install_plan_bad_args(self):
        for args in ({'branch': 'head'}, {'cpus': '7'}, {'threads': '9'}, {'ctx': '1234'}, {'nice': '30'},
                     {'start': 'maybe'}, {'cpus': '3', 'threads': '2'}):
            res = actions.plan('install_runtime', args, self.ctx)
            self.assertEqual(res['status'], 'error', args)

    def test_install_plan_without_zfs(self):
        self.system.datasets.clear()
        self.system.mounts.clear()
        res = self.plan('install_runtime')
        self.assertEqual(res['steps'][0]['type'], 'mkdir')

    def test_start_stop_enable_plans(self):
        res = self.plan('start_runtime')
        self.assertEqual(res['status'], 'blocked')            # not installed
        self._fake_installed()
        res = self.plan('start_runtime')
        self.assertEqual(res['status'], 'ok')
        self.assertEqual(res['steps'][0]['argv'][-2:], ['-c', 'ollama'])
        res = self.plan('stop_runtime')
        self.assertTrue(res['steps'][0]['already'])           # not running
        res = self.plan('enable_runtime')
        self.assertIn('jail_list="ollama"', res['steps'][0]['content'])

    def _fake_installed(self):
        os.makedirs(self.root + '/var/db/ai/jail/usr/local/bin', exist_ok=True)
        open(self.root + '/var/db/ai/jail/.policyanalyzer-base', 'w').close()
        open(self.root + '/var/db/ai/jail/usr/local/bin/ollama', 'w').close()
        open(self.root + '/etc/jail.conf.d/ollama.conf', 'w').close()

    def test_set_limits_plan(self):
        self._fake_installed()
        self.system.running = True
        res = self.plan('set_limits', cpus='0-1', threads='2', ctx='4096', nice='10')
        self.assertEqual(res['status'], 'ok', res.get('errors'))
        commands = [s['command'] for s in res['steps']]
        self.assertIn('/usr/bin/cpuset -l 0-1 -j ollama', commands)
        self.assertTrue(any('service ollama restart' in c for c in commands))
        self.assertIn('restores the previous limits', res['undo'])
        res = actions.plan('set_limits', {'cpus': '0-1', 'threads': '3'}, self.ctx)
        self.assertEqual(res['status'], 'error')

    def test_pull_plan(self):
        res = self.plan('pull_model', model='qwen2.5:3b')
        self.assertEqual(res['status'], 'ok', res.get('errors'))
        self.assertGreater(res['download_bytes'], 0)
        self.assertEqual(res['steps'][1]['type'], 'model_pull')
        self.assertTrue(res['irreversible'])
        self.assertTrue(res['background'])
        res = actions.plan('pull_model', {'model': 'tinyllama:1b'}, self.ctx)
        self.assertEqual(res['status'], 'error')               # not in the list
        res = self.plan('pull_model', model='nonexistent:1b', custom='yes')
        self.assertEqual(res['status'], 'blocked')

    def test_pull_plan_large_and_space(self):
        big = {d: 7 * common.GIB for d, _ in __import__('setup_helpers').MODEL_LAYERS[:1]}
        self.http.manifests[('qwen3', '8b')] = __import__('setup_helpers').model_manifest(sizes=big)
        res = self.plan('pull_model', model='qwen3:8b')
        self.assertTrue(any('large=yes' in e for e in res['errors']))
        with unittest.mock.patch.object(common, 'free_bytes', return_value=10 * common.MIB):
            res = self.plan('pull_model', model='qwen2.5:3b')
        self.assertTrue(any('not enough space' in e for e in res['errors']))

    def test_remove_and_benchmark_plans(self):
        res = self.plan('remove_model', model='qwen2.5:3b')
        self.assertEqual(res['status'], 'blocked')            # not installed
        res = self.plan('benchmark')
        self.assertEqual(res['status'], 'blocked')
        self.assertFalse(res['reversible'])

    def test_uninstall_plan(self):
        self._fake_installed()
        self.system.datasets['zroot/ai/jail'] = '/var/db/ai/jail'
        res = self.plan('uninstall_runtime')
        self.assertEqual(res['status'], 'ok')
        destroys = [s for s in res['steps'] if s['type'] == 'zfs_destroy']
        self.assertEqual([s['dataset'] for s in destroys], ['zroot/ai/jail'])
        self.assertTrue(any('kept' in w for w in res['warnings']))
        res = self.plan('uninstall_runtime', remove_dataset='yes')
        self.assertEqual(res['status'], 'blocked')               # needs confirm=<dataset>
        res = self.plan('uninstall_runtime', remove_dataset='yes', confirm='zroot/ai')
        self.assertEqual(res['risk'], 'high')
        self.assertIn('zroot/ai', [s.get('dataset') for s in res['steps']])

    def test_status(self):
        res = self.plan('status_runtime')
        self.assertEqual(res['result']['installed'], False)
        self.assertEqual(res['result']['ai_dataset'], 'zroot/ai')

    def test_rc_jail_merge(self):
        text = 'jail_enable="YES"\njail_list="web"\njail_parallel_start="YES"\n'
        merged = runtime.render_rc_jail(text, True)
        self.assertIn('jail_list="web ollama"', merged)
        self.assertIn('jail_parallel_start="YES"', merged)
        removed = runtime.render_rc_jail(merged, False)
        self.assertIn('jail_list="web"', removed)
        self.assertIsNone(runtime.render_rc_jail(runtime.render_rc_jail('', True), False))


if __name__ == '__main__':
    unittest.main()
