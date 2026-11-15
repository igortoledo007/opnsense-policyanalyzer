"""
pure decisions: ladder, repeat offenses, reset after 90 days, scenarios (base / scan / bait / suricata),
connection attempts, targets and the interval set.
"""

import ipaddress
import unittest

from qhelpers import T0, common, engine

SETTINGS = common.effective_settings({})
DAY = 86400


def rec(ts, dport, proto='tcp', flags='S', iface='pppoe1'):
    return {'ts': ts, 'dport': str(dport), 'proto': proto, 'flags': flags, 'iface': iface}


class TestLadder(unittest.TestCase):
    def test_first_offense_is_30_minutes(self):
        self.assertEqual(engine.next_level(None, T0, SETTINGS, 1), 1)
        self.assertEqual(common.ttl(1), 1800)

    def test_repeat_offenses_climb_the_ladder(self):
        entry = {'level': 0, 'last_offense': None}
        expected = [1, 2, 3, 4, 5, 5, 5]
        ts = T0
        for level in expected:
            got = engine.next_level(entry, ts, SETTINGS, 1)
            self.assertEqual(got, level)
            entry = {'level': got, 'last_offense': ts}
            ts += common.ttl(got) + 60          # offends again after the quarantine ended
        self.assertEqual([common.ttl(n) for n in range(1, 6)], [1800, 7200, 2 * DAY, 10 * DAY, 30 * DAY])

    def test_reset_after_90_days_without_offenses(self):
        entry = {'level': 4, 'last_offense': T0}
        self.assertEqual(engine.next_level(entry, T0 + 90 * DAY, SETTINGS, 1), 5)
        self.assertEqual(engine.next_level(entry, T0 + 90 * DAY + 1, SETTINGS, 1), 1)
        custom = common.effective_settings({'reset_days': '30'})
        self.assertEqual(engine.next_level(entry, T0 + 31 * DAY, custom, 1), 1)

    def test_scenario_minimum_or_one_level_up(self):
        self.assertEqual(engine.next_level(None, T0, SETTINGS, 2), 2)          # scan/bait: straight to 2 h
        self.assertEqual(engine.next_level({'level': 2, 'last_offense': T0}, T0 + 9000, SETTINGS, 2), 3)
        self.assertEqual(engine.next_level(None, T0, SETTINGS, 3), 3)          # suricata: 2 days
        self.assertEqual(engine.next_level({'level': 4, 'last_offense': T0}, T0 + 11 * DAY, SETTINGS, 3), 5)
        self.assertEqual(engine.next_level({'level': 5, 'last_offense': T0}, T0 + 40 * DAY, SETTINGS, 3), 5)

    def test_permanent_stays(self):
        self.assertEqual(engine.next_level({'level': 6, 'last_offense': T0}, T0 + 400 * DAY, SETTINGS, 1), 6)


class TestScenarios(unittest.TestCase):
    def test_base(self):
        found = engine.detect([rec(T0, 6322)], [], SETTINGS)
        self.assertEqual(found['primary'], 'base')
        self.assertEqual(found['min_level'], 1)
        self.assertEqual(found['ports'], '6322/tcp')

    def test_scan_needs_10_ports_within_5_minutes(self):
        nine = [rec(T0 + i, 1000 + i) for i in range(9)]
        self.assertEqual(engine.detect(nine, [], SETTINGS)['primary'], 'base')
        ten = nine + [rec(T0 + 299, 2000)]
        found = engine.detect(ten, [], SETTINGS)
        self.assertEqual(found['primary'], 'scan')
        self.assertEqual(found['min_level'], 2)
        self.assertIn('10 ports', found['detail'])
        spread = [rec(T0 + i * 40, 3000 + i) for i in range(10)]       # 10 ports over 6 minutes
        self.assertEqual(engine.max_distinct_ports(spread, 300), 8)
        self.assertEqual(engine.detect(spread, [], SETTINGS)['primary'], 'base')

    def test_bait_ports(self):
        found = engine.detect([rec(T0, 3389)], [], SETTINGS)
        self.assertEqual(found['primary'], 'bait')
        self.assertEqual(found['min_level'], 2)
        self.assertEqual(engine.detect([rec(T0, 445, 'udp', '')], [], SETTINGS)['primary'], 'bait')
        custom = common.effective_settings({'bait_ports': '2222'})
        self.assertEqual(engine.detect([rec(T0, 3389)], [], custom)['primary'], 'base')
        self.assertEqual(engine.detect([rec(T0, 2222)], [], custom)['primary'], 'bait')

    def test_suricata(self):
        alert = {'ts': T0, 'sid': 1, 'severity': 1, 'signature': 'ET X', 'dport': '443', 'proto': 'tcp'}
        found = engine.detect([], [alert], SETTINGS)
        self.assertEqual(found['primary'], 'suricata')
        self.assertEqual(found['min_level'], 3)
        both = engine.detect([rec(T0, 3389)], [alert], SETTINGS)
        self.assertEqual(both['reasons'], ['suricata', 'bait', 'base'])
        self.assertEqual(both['primary'], 'suricata')

    def test_connection_attempts_only(self):
        self.assertTrue(engine.counts_as_connection(rec(T0, 22, flags='S'), True))
        self.assertFalse(engine.counts_as_connection(rec(T0, 22, flags='SA'), True))
        self.assertFalse(engine.counts_as_connection(rec(T0, 22, flags='FA'), True))
        self.assertTrue(engine.counts_as_connection(rec(T0, 22, flags='FA'), False))
        self.assertTrue(engine.counts_as_connection(rec(T0, 53, 'udp', ''), True))

    def test_nothing(self):
        self.assertIsNone(engine.detect([], [], SETTINGS))

    def test_covers(self):
        entry = {'state': 'active', 'last_offense': T0, 'since': T0 + 5, 'until': T0 + 1800}
        self.assertTrue(engine.covers(entry, T0))
        self.assertTrue(engine.covers(entry, T0 + 1799))
        self.assertFalse(engine.covers(entry, T0 + 1800))
        self.assertFalse(engine.covers(entry, T0 - 1))
        self.assertTrue(engine.covers({'state': 'permanent', 'until': None}, T0 + 10 ** 8))

    def test_next_run(self):
        self.assertEqual(engine.next_run(T0) % 300, 0)
        self.assertGreater(engine.next_run(T0), T0)


class TestTargets(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(common.parse_target('203.0.113.5')['kind'], 'ip')
        self.assertEqual(common.parse_target('203.0.113.0/24')['label'], '203.0.113.0/24')
        self.assertEqual(common.parse_target('203.0.113.7/24')['label'], '203.0.113.0/24')
        rng = common.parse_target('203.0.113.0-203.0.113.9')
        self.assertEqual([str(n) for n in rng['nets']], ['203.0.113.0/29', '203.0.113.8/31'])
        self.assertEqual(common.parse_target('AS64500'), {'kind': 'asn', 'nets': [], 'asn': 64500,
                                                          'label': 'AS64500'})
        self.assertEqual(common.parse_target('2001:db8::1')['kind'], 'ip')
        for bad in ('', 'x', '203.0.113.9-203.0.113.1', '1.2.3.4-2001:db8::1', 'AS0', '::ffff:203.0.113.1'):
            with self.assertRaises(ValueError):
                common.parse_target(bad)
        with self.assertRaises(ValueError):
            common.parse_target('203.0.113.1-203.0.113.254-1')
        with self.assertRaises(ValueError):                    # 1 + 2 + ... networks: more than 64
            common.parse_target('2001:db8::1-2001:db8::ffff:ffff:ffff:fffe')

    def test_sizes(self):
        self.assertFalse(common.check_network_size(ipaddress.ip_network('203.0.0.0/16')))
        self.assertTrue(common.check_network_size(ipaddress.ip_network('203.0.0.0/15')))
        with self.assertRaises(ValueError):
            common.check_network_size(ipaddress.ip_network('192.0.0.0/7'))
        self.assertTrue(common.check_network_size(ipaddress.ip_network('2001:db8::/31')))

    def test_external(self):
        for value in ('10.1.2.3', '192.168.1.1', '100.64.1.1', '127.0.0.1', '169.254.1.1', '224.0.0.1',
                      '239.1.1.1', '0.0.0.0', '255.255.255.255', 'fe80::1', 'fc00::1', 'ff02::1', '::1'):
            self.assertFalse(common.is_external(common.addr(value)), value)
        self.assertTrue(common.is_external(common.addr('203.0.113.9')))      # documentation, as public in tests
        self.assertEqual(str(common.addr('::ffff:203.0.113.9')), '203.0.113.9')
        self.assertFalse(common.network_is_external(ipaddress.ip_network('100.64.0.0/10')))

    def test_settings(self):
        self.assertEqual(common.validate_setting('bait_ports', '23, 3389+23'), '23+3389')
        with self.assertRaises(ValueError):
            common.validate_setting('max_active', '5')
        with self.assertRaises(ValueError):
            common.validate_setting('bait_ports', '70000')
        with self.assertRaises(ValueError):
            common.validate_setting('nope', '1')
        self.assertEqual(common.effective_settings({'max_active': 'junk'})['max_active'], 20000)


class TestIntervalSet(unittest.TestCase):
    def test_lookup_and_overlap(self):
        s = common.IntervalSet()
        s.add('203.0.113.0/28', 'dns')
        s.add('203.0.113.16/28', 'dns')
        s.add('203.0.113.20', 'never_block')
        s.add('2001:db8::/64', 'firewall')
        self.assertEqual(s.lookup(ipaddress.ip_address('203.0.113.31')), 'dns')
        self.assertEqual(s.lookup(ipaddress.ip_address('203.0.113.20')), 'dns')
        self.assertIsNone(s.lookup(ipaddress.ip_address('203.0.113.32')))
        self.assertEqual(s.lookup(ipaddress.ip_address('2001:db8::5')), 'firewall')
        found = s.overlapping(ipaddress.ip_network('203.0.113.0/24'))
        self.assertIn(('dns', ipaddress.ip_network('203.0.113.0/27')), found)
        self.assertIn(('never_block', ipaddress.ip_network('203.0.113.20/32')), found)


if __name__ == '__main__':
    unittest.main()
