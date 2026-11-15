"""
reachability: WAN rules open / closed / opaque alias, quick block, LAN and loopback binds.
"""

import unittest

from exposure_helpers import (CLOSED_RULES, ExposureCase, FakeRunner, SOCKSTAT_LOCAL_ONLY, adapter, reach,
                              rule, service)


class TestReach(ExposureCase):
    def exposure(self, **kw):
        runner = kw.pop('runner', None) or FakeRunner()
        return adapter.probe_exposure([], runner=runner, config_path=self.write_config(**kw))

    def test_open_rules(self):
        res = self.exposure()
        self.assertEqual(res['wan'], ['wan'])
        ssh = service(res, 'ssh', 22)
        self.assertEqual(ssh['internet_reachable'], 'yes')
        self.assertEqual([r['description'] for r in ssh['rules']], ['wan ssh open'])
        self.assertTrue(ssh['rules'][0]['ref'].startswith('ui/firewall/filter#search='))
        self.assertEqual({t['family'] for t in ssh['reach']['targets']}, {4, 6})
        self.assertFalse(ssh['source_restricted'])
        self.assertEqual(service(res, 'wireguard', 51820)['internet_reachable'], 'yes')
        gui = service(res, 'webgui', 8443)
        self.assertEqual(gui['internet_reachable'], 'maybe')           # GeoIP alias is opaque
        self.assertIn('opaque alias or dynamic address', gui['rules'][0]['notes'])
        self.assertEqual(service(res, 'webgui', 80)['internet_reachable'], 'no')
        self.assertEqual(service(res, 'unknown:mystery', 9999)['internet_reachable'], 'no')  # quick block first
        dns = service(res, 'unbound', 53)
        self.assertEqual(dns['internet_reachable'], 'no')
        self.assertIn('non WAN', dns['reach']['reason'])
        self.assertEqual(service(res, 'unbound-control', 953)['reach']['reason'], 'listens on loopback only')
        self.assertEqual(res['summary']['reachable'], 2)
        self.assertEqual(res['summary']['maybe_reachable'], 1)

    def test_closed(self):
        res = self.exposure(rules=CLOSED_RULES, aliases=[])
        self.assertTrue(all(s['internet_reachable'] == 'no' for s in res['services']))
        self.assertIn('default deny', service(res, 'ssh', 22)['reach']['reason'])

    def test_restricted_source_is_maybe(self):
        rules = [rule('wan ssh admin host', interface='wan', protocol='TCP', source_net='203.0.113.10',
                      destination_net='(self)', destination_port='22')]
        ssh = service(self.exposure(rules=rules, aliases=[]), 'ssh', 22)
        self.assertEqual(ssh['internet_reachable'], 'maybe')
        self.assertTrue(ssh['source_restricted'])

    def test_non_quick_block_after_pass(self):
        rules = [rule('wan pass ssh', interface='wan', protocol='TCP', destination_port='22', quick='0'),
                 rule('wan block all ssh', interface='wan', action='block', protocol='TCP', destination_port='22',
                      quick='0', ipprotocol='inet46')]
        self.assertEqual(service(self.exposure(rules=rules, aliases=[]), 'ssh', 22)['internet_reachable'], 'no')

    def test_floating_rule_and_other_destination(self):
        rules = [rule('floating any', interface='', protocol='TCP', destination_port='22'),
                 rule('wan to dmz only', interface='wan', protocol='TCP', destination_net='192.0.2.130',
                      destination_port='8443')]
        res = self.exposure(rules=rules, aliases=[])
        self.assertEqual(service(res, 'ssh', 22)['internet_reachable'], 'yes')
        self.assertEqual(service(res, 'webgui', 8443)['internet_reachable'], 'no')   # not the WAN address

    def test_lan_bound_services(self):
        res = self.exposure(runner=FakeRunner(sockstat=SOCKSTAT_LOCAL_ONLY))
        self.assertEqual(service(res, 'ssh', 22)['internet_reachable'], 'no')
        self.assertEqual(service(res, 'webgui', 8443)['internet_reachable'], 'no')

    def test_unknown_wan_address(self):
        rules = [rule('wan ssh self', interface='wan', protocol='TCP', destination_net='(self)', destination_port='22'),
                 rule('wan to dmz only', interface='wan', protocol='TCP', destination_net='192.0.2.130',
                      destination_port='8443')]
        rs = reach.RuleSet(self.write_config(rules=rules, aliases=[]))
        self.assertEqual(reach.evaluate(rs, 'wan', None, 4, 'tcp', 22)[0], 'yes')      # (self) is the firewall
        self.assertEqual(reach.evaluate(rs, 'wan', None, 4, 'tcp', 8443)[0], 'maybe')  # address unknown
        self.assertEqual(reach.evaluate(rs, 'wan', '198.51.100.2', 4, 'tcp', 8443)[0], 'no')
        targets = reach.wan_targets({'bind': [{'address': '*', 'family': 4, 'scope': 'any'}]},
                                    [{'name': 'wan', 'ipv4': [], 'ipv6': []}], ['wan'])
        self.assertEqual(targets, [('wan', None, 4)])

if __name__ == '__main__':
    unittest.main()
