"""
Minimal rule from the observed traffic: filter log path (exact), NetFlow path (approximate, earlier quick rules
respected), grouping of destinations and ports, broad use, sources never narrowed to single addresses, coverage,
what would be blocked, candidates, CLI validation and AI explain with a fake provider.

    cd tests/minrule && /usr/bin/python3 -m unittest discover -s . -v
"""

import ipaddress
import os
import sys
import unittest

import min_helpers as H

os.environ['POLICYANALYZER_NOW'] = str(H.NOW)

from minrule import analyze as A, cli  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(H.HERE), 'posture'))
import post_helpers  # noqa: E402


def change(result, field):
    return next((c for c in result['proposal']['changes'] if c['field'] == field), None)


class FilterLogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = H.Root(H.lan_traffic())
        cls.r = A.analyze(cls.root.paths, H.LAN_ANY, 7)

    @classmethod
    def tearDownClass(cls):
        cls.root.cleanup()

    def test_source_and_counts(self):
        self.assertEqual(self.r['status'], 'ok')
        self.assertEqual(self.r['observed']['unit'], 'connections')
        self.assertEqual(self.r['sources']['source'], 'filterlog')
        self.assertEqual(self.r['observed']['total'], 6 * 7 + 1)   # the 20 day old line is out
        self.assertEqual(self.r['observed']['protocols'], {'tcp': 6 * 5 + 1, 'udp': 6, 'icmp': 6})

    def test_destinations_grouped(self):
        dst = change(self.r, 'Destination')
        self.assertEqual(dst['from'], 'any')
        alias = next(a for a in self.r['proposal']['aliases'] if a['name'] == dst['to'])
        self.assertIn('198.51.100.0/24', alias['content'])      # 4 hosts in one /24
        self.assertIn('203.0.113.53', alias['content'])
        self.assertEqual(alias['type'], 'network')

    def test_ports_and_protocol(self):
        self.assertEqual(change(self.r, 'Protocol')['to'], 'TCP/UDP')
        port = change(self.r, 'Destination port')
        alias = next(a for a in self.r['proposal']['aliases'] if a['name'] == port['to'])
        self.assertEqual(alias['content'], ['53', '443', '853', '8443'])
        extra = self.r['proposal']['extra_rules']
        self.assertEqual([e['protocol'] for e in extra], ['ICMP'])

    def test_source_kept_as_lan(self):
        self.assertIsNone(change(self.r, 'Source'))   # already "lan"

    def test_coverage_full(self):
        self.assertEqual(self.r['coverage']['percent'], 100.0)
        self.assertEqual(self.r['would_block'], [])
        self.assertEqual(self.r['confidence'], 'high')     # exact source, 5+ days of data, 43 connections
        self.assertIn('ui/firewall/filter#search=%s' % H.LAN_ANY, self.r['rule']['ref'])

    def test_diff_and_plan(self):
        self.assertIn('- Destination: any', self.r['diff'])
        self.assertIn('+ Protocol: TCP/UDP', self.r['diff'])
        self.assertIn('Firewall › Aliases', self.r['diff'])
        plan = self.r['plan']
        self.assertTrue(plan['steps'])
        self.assertIn('nothing is applied', plan['message'])
        self.assertFalse(any('configctl' in s['command'] or 'pfctl' in s['command'] for s in plan['steps']))

    def test_trimmed_tail_is_reported(self):
        saved = A.MAX_ENTRIES
        A.MAX_ENTRIES = 2
        try:
            r = A.analyze(self.root.paths, H.LAN_ANY, 7)
        finally:
            A.MAX_ENTRIES = saved
        self.assertLess(r['coverage']['percent'], 100)
        self.assertTrue(r['would_block'])
        self.assertTrue(any('left out' in w for w in r['plan']['warnings']))


class NetflowTest(unittest.TestCase):
    def flows(self):
        out = []
        for i in range(40):
            out.append({'time': H.NOW - H.DAY * (i % 5) - 100, 'src': '192.0.2.140', 'dst': '198.51.100.%d' % (20 + i % 3),
                        'sport': 40000, 'dport': 443, 'proto': 'tcp', 'ifin': 3, 'octets': 1000, 'packets': 5})
        # entered on the LAN (other rule), on the WAN (reply direction) and to a host blocked earlier on the LAN
        out.append({'time': H.NOW - 50, 'src': '192.0.2.10', 'dst': '198.51.100.99', 'sport': 1, 'dport': 80,
                    'proto': 'tcp', 'ifin': 2})
        out.append({'time': H.NOW - 50, 'src': '198.51.100.20', 'dst': '192.0.2.140', 'sport': 443, 'dport': 40000,
                    'proto': 'tcp', 'ifin': 1})
        return out

    def test_netflow_fallback(self):
        root = H.Root(flows=self.flows())
        try:
            r = A.analyze(root.paths, H.SRV_ANY, 7)
            self.assertEqual(r['observed']['unit'], 'flows')
            self.assertEqual(r['observed']['total'], 40)
            self.assertEqual(r['sources']['fallback_reason'], 'the rule does not log')
            self.assertEqual(change(r, 'Destination port')['to'], '443')
            self.assertEqual(change(r, 'Protocol')['to'], 'TCP')
            self.assertTrue(any('NetFlow' in w for w in r['plan']['warnings']))
            self.assertEqual(r['confidence'], 'medium')
        finally:
            root.cleanup()

    def test_earlier_quick_rule_decides(self):
        flows = [{'time': H.NOW - 10, 'src': '192.0.2.10', 'dst': '203.0.113.66', 'dport': 443, 'proto': 'tcp',
                  'ifin': 2}] * 3 + [{'time': H.NOW - 10, 'src': '192.0.2.10', 'dst': '203.0.113.7', 'dport': 443,
                                      'proto': 'tcp', 'ifin': 2}]
        root = H.Root(flows=flows)
        try:
            # the logged rule has no log line in the window: NetFlow is used and the blocked host is skipped
            r = A.analyze(root.paths, H.LAN_ANY, 7)
            self.assertEqual(r['observed']['total'], 1)
            self.assertEqual(r['sources']['decided_by_earlier_rules'], 3)
            self.assertEqual(r['sources']['fallback_reason'], 'no labelled log line in the window')
        finally:
            root.cleanup()

    def test_without_interface_map_flows_are_kept(self):
        root = H.Root(flows=self.flows(), ifindex={})
        try:
            r = A.analyze(root.paths, H.SRV_ANY, 7)
            self.assertGreaterEqual(r['observed']['total'], 40)
        finally:
            root.cleanup()


class PolicyTest(unittest.TestCase):
    def test_wan_sources_never_narrowed(self):
        lines = [(H.NOW - 100 - i, H.log_line(H.NOW - 100 - i, H.WG, '203.0.113.%d' % (10 + i % 2), '198.51.100.2',
                                              'udp', 51820, device='vtnet0')) for i in range(30)]
        root = H.Root(lines)
        try:
            r = A.analyze(root.paths, H.WG, 7)
            self.assertIsNone(change(r, 'Source'))
            self.assertTrue(any('not narrowed' in n for n in r['notes']))
            self.assertEqual(r['proposal']['changes'], [])
            self.assertEqual(r['coverage']['percent'], 100.0)
        finally:
            root.cleanup()

    def test_broad_use_keeps_fields(self):
        lines = []
        for i in range(300):
            ts = H.NOW - 1000 - i
            dst = str(ipaddress.ip_address('198.51.100.0') + (i % 250)) if i < 250 else '203.0.113.%d' % (i - 240)
            lines.append((ts, H.log_line(ts, H.LAN_ANY, '192.0.2.10', dst, 'tcp', 1024 + i)))
        root = H.Root(lines)
        try:
            r = A.analyze(root.paths, H.LAN_ANY, 7)
            self.assertIsNone(change(r, 'Destination'))
            self.assertIsNone(change(r, 'Destination port'))
            self.assertEqual(change(r, 'Protocol')['to'], 'TCP')
            self.assertEqual(len(r['notes']), 2)
        finally:
            root.cleanup()

    def test_no_traffic(self):
        root = H.Root()
        try:
            r = A.analyze(root.paths, H.SSH, 7)
            self.assertEqual(r['status'], 'ok')
            self.assertIsNone(r['proposal'])
            self.assertEqual(r['confidence'], 'none')
        finally:
            root.cleanup()

    def test_group_ports_folds(self):
        ranges, wide = A.group_ports({p: 1 for p in range(1000, 1100, 2)}, max_ports=5)
        self.assertTrue(wide)
        self.assertLessEqual(len(ranges), 5)
        ranges, wide = A.group_ports({80: 5, 81: 1, 443: 9})
        self.assertEqual([(r['lo'], r['hi']) for r in ranges], [(80, 81), (443, 443)])
        self.assertFalse(wide)

    def test_ifnet_token(self):
        cfg, _ = A.load_rules(H.Root().paths.config)
        entries, left, token = A.group_addresses({ipaddress.ip_address('192.0.2.10'): 3,
                                                  ipaddress.ip_address('192.0.2.20'): 1}, A.interface_networks(cfg))
        self.assertEqual(token, 'lan')
        self.assertEqual(entries[0]['value'], 'lan net')


class CliTest(unittest.TestCase):
    def setUp(self):
        self.root = H.Root(H.lan_traffic())

    def tearDown(self):
        self.root.cleanup()

    def test_candidates(self):
        out = cli.main(['candidates'], paths=self.root.paths)
        uuids = [c['uuid'] for c in out['candidates']]
        self.assertIn(H.LAN_ANY, uuids)
        self.assertIn(H.SRV_ANY, uuids)
        self.assertIn(H.WG, uuids)
        self.assertNotIn(H.BLOCK, uuids)
        self.assertNotIn(H.SSH, uuids)   # already narrow
        lan = next(c for c in out['candidates'] if c['uuid'] == H.LAN_ANY)
        self.assertTrue(lan['exact'])

    def test_validation(self):
        self.assertEqual(cli.main(['analyze', 'bad;rm'], paths=self.root.paths)['status'], 'error')
        self.assertEqual(cli.main(['analyze', H.BLOCK], paths=self.root.paths)['status'], 'error')
        self.assertEqual(cli.main(['analyze', '00000000-0000-4000-8000-00000000ffff'],
                                  paths=self.root.paths)['status'], 'error')
        self.assertEqual(cli.main(['analyze', H.LAN_ANY, '999'], paths=self.root.paths)['window_days'], 7)

    def test_explain_uses_cache_and_fake_provider(self):
        out = cli.main(['analyze', H.LAN_ANY, '7'], paths=self.root.paths)
        self.assertEqual(out['status'], 'ok')
        assistant, provider = post_helpers.fake_assistant()
        answer = cli.main(['explain', H.LAN_ANY, '7', 'en_US', 'send'], paths=self.root.paths, assistant=assistant)
        self.assertEqual(answer['status'], 'ok')
        sent = provider.messages[0][1]['content']
        self.assertIn('coverage', sent)
        self.assertNotIn('198.51.100.10', sent)   # addresses are anonymized
        preview = cli.main(['explain', H.LAN_ANY, '7', 'en_US', 'preview'], paths=self.root.paths,
                           assistant=assistant)
        self.assertIn('messages', preview)
        self.assertEqual(len(provider.messages), 1)


if __name__ == '__main__':
    unittest.main()
