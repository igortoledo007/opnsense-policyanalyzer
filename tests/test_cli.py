"""
analyze.py command line and performance tests (synthetic data only, nothing is written to disk).
"""

import contextlib
import io
import json
import os
import time
import unittest

from helpers import ENGINE_DIR, FIXTURES, analyze, rule, alias

import analyze as cli  # plugin/src/opnsense/scripts/policyanalyzer/analyze.py (ENGINE_DIR is on sys.path)


def run_cli(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(list(args))
    return code, out.getvalue()


class TestCli(unittest.TestCase):
    def test_offline_run_with_stats(self):
        code, out = run_cli('--config', os.path.join(FIXTURES, 'sample-config.xml'),
                            '--stats', os.path.join(FIXTURES, 'sample-stats.json'), '--no-write')
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc['version'], 1)
        self.assertTrue(doc['stats_available'])
        types = {f['type'] for f in doc['findings']}
        for expected in ('shadowed', 'redundant', 'wan_exposed', 'empty_alias', 'unused_alias', 'disabled',
                         'no_description', 'unused'):
            self.assertIn(expected, types)
        # the rule already reported as wan_exposed is not repeated as "any source on WAN"
        wan_gui = [f for f in doc['findings'] if f['rules'] and f['rules'][0]['description'] == 'WAN GUI']
        self.assertEqual(sorted(f['type'] for f in wan_gui), ['wan_exposed'])

    def test_missing_stats_file(self):
        code, out = run_cli('--config', os.path.join(FIXTURES, 'sample-config.xml'),
                            '--stats', os.path.join(FIXTURES, 'does-not-exist.json'), '--no-write')
        doc = json.loads(out)
        self.assertFalse(doc['stats_available'])
        self.assertNotIn('unused', {f['type'] for f in doc['findings']})

    def test_bad_config(self):
        code, out = run_cli('--config', os.path.join(FIXTURES, 'does-not-exist.xml'), '--no-write', '--no-stats')
        self.assertEqual(code, 1)
        self.assertIn('error', json.loads(out))

    def test_engine_dir(self):
        self.assertTrue(os.path.isfile(os.path.join(ENGINE_DIR, 'analyze.py')))


class TestPerformance(unittest.TestCase):
    def test_500_rules_under_two_seconds(self):
        aliases = [alias('HOSTS%d' % i, 'host', ['192.0.2.%d' % (i % 250 + 1), 'host%d.example.com' % i])
                   for i in range(40)]
        aliases += [alias('PORTS%d' % i, 'port', ['%d' % (1000 + i), '%d:%d' % (2000 + i, 2100 + i)])
                    for i in range(20)]
        ifaces = ['lan', 'opt1', 'opt2', 'wan', 'INTERNAL', 'lan,opt1', '']
        rules = []
        for i in range(500):
            rules.append(rule(
                'perf %d' % i,
                action=('pass', 'block', 'reject')[i % 3],
                interface=ifaces[i % len(ifaces)],
                ipprotocol=('inet', 'inet46', 'inet6')[i % 3] if i % 5 == 0 else 'inet',
                protocol=('TCP', 'UDP', 'TCP/UDP', 'any')[i % 4],
                source_net=('lan', 'HOSTS%d' % (i % 40), '192.0.2.%d/32' % (i % 250), 'any')[i % 4],
                destination_net=('any', '198.51.100.%d' % (i % 250), 'opt1')[i % 3],
                destination_port='' if i % 4 == 3 else ('PORTS%d' % (i % 20) if i % 2 else str(1 + i))))
        started = time.monotonic()
        res = analyze(rules=rules, aliases=aliases)
        elapsed = time.monotonic() - started
        self.assertEqual(res['summary']['rules'], 500)
        self.assertLess(elapsed, 2.0, 'analysis took %.2fs' % elapsed)


if __name__ == '__main__':
    unittest.main()
