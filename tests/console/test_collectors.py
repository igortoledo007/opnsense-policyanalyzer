"""
Read-only collectors of the AI Console against the synthetic firewall of console_helpers.
"""

import os
import time
import unittest

from console_helpers import (NOW, U_ALLOW_LAN, U_BLOCK_IOT, U_BLOCK_PRINTER, U_SSH_WAN, L_DEFAULT_DENY, Firewall,
                             filter_lines, v4)
from console.collectors import aliases, changes, filterlog, fwinfo, hosts, quarantine, reports, rules, suricata
from console.common import Budget


def window(seconds, now=NOW):
    return {'since': int(now - seconds), 'until': int(now), 'label': 'test', 'explicit': True}


class Base(unittest.TestCase):
    def setUp(self):
        self.fw = Firewall()
        self.paths = self.fw.paths

    def tearDown(self):
        self.fw.cleanup()


class TestFilterLog(Base):
    def test_parse_line(self):
        rec = filterlog.parse_line(v4(NOW, 'igc0', 'block', 'in', 'tcp', '192.168.1.50', '198.51.100.20', '5000',
                                      '443', rid=U_BLOCK_PRINTER))
        self.assertEqual((rec['iface'], rec['action'], rec['dir'], rec['proto']), ('igc0', 'block', 'in', 'tcp'))
        self.assertEqual((rec['src'], rec['dst'], rec['sport'], rec['dport'], rec['flags']),
                         ('192.168.1.50', '198.51.100.20', '5000', '443', 'S'))
        self.assertEqual(rec['rid'], U_BLOCK_PRINTER)
        self.assertEqual(rec['ts'], NOW)
        self.assertIsNone(filterlog.parse_line('<38>1 2026-11-08T10:00:00Z fw sshd 1 - - hello'))

    def test_focus_address_and_port(self):
        flt = filterlog.Filter(ips=['192.168.1.50'], ports=[443])
        data = filterlog.focus(self.paths, window(3600), Budget(5), flt, rules.index(self.paths), now=NOW)
        self.assertTrue(data['complete'])
        self.assertEqual(data['events'], 6)
        self.assertEqual(data['by_action'], {'block': 6})
        self.assertEqual(data['by_rule'][0]['rule'], 'lan #10 block "Block printer HTTPS"')
        self.assertEqual(data['top_peers'][0]['address'], '198.51.100.20')
        self.assertEqual(len(data['sample_events']), 6)
        self.assertEqual(data['sample_events'][0]['interface_name'], 'lan')

    def test_focus_window_reads_older_daily_file(self):
        flt = filterlog.Filter(ips=['192.168.1.50'], ports=[443])
        data = filterlog.focus(self.paths, window(2 * 86400), Budget(5), flt, rules.index(self.paths), now=NOW)
        self.assertEqual(data['events'], 7)      # 6 today + 1 in yesterday's file

    def test_automatic_rule_label(self):
        flt = filterlog.Filter(ips=['203.0.113.9'])
        data = filterlog.focus(self.paths, window(3600), Budget(5), flt, rules.index(self.paths), now=NOW)
        self.assertEqual(data['by_rule'][0]['rule'], 'automatic "Default deny / state violation rule"')

    def test_top(self):
        data = filterlog.top(self.paths, window(86400 // 2), Budget(5), rules.index(self.paths), now=NOW)
        self.assertEqual(data['top_blocked_external_sources'][0]['address'], '203.0.113.9')
        self.assertEqual(data['top_blocked_external_sources'][0]['distinct_ports'], 10)
        self.assertEqual(data['top_blocked_internal_sources'][0]['address'], '192.168.1.50')
        self.assertEqual(data['wan_interfaces'], ['pppoe1 (wan, wan)'])
        self.assertEqual(data['top_blocking_rules'][0]['events'], 11)

    def test_tail_filters(self):
        rows, meta = filterlog.tail(self.paths, filterlog.Filter(action='block', devices=['igc1']), 10, Budget(5),
                                    rules.index(self.paths), now=NOW)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r['rid'] == U_BLOCK_IOT for r in rows))
        self.assertGreater(rows[0]['ts'], rows[-1]['ts'])        # newest first

    def test_budget_cut_marks_incomplete(self):
        records, meta = filterlog.read(self.paths.filter_log, NOW - 86400 * 3, NOW, Budget(5), max_lines=5, now=NOW)
        self.assertFalse(meta['complete'])
        self.assertLessEqual(meta['lines_read'], 5)
        expired = Budget(0)
        many = os.path.join(self.fw.dir, 'filter', 'big.log')
        with open(many, 'w') as handle:
            handle.write('\n'.join(filter_lines() * 600) + '\n')
        records, meta = filterlog.read(many, NOW - 86400, NOW, expired, now=NOW)
        self.assertFalse(meta['complete'])

    def test_rid_filter(self):
        data = filterlog.focus(self.paths, window(86400), Budget(5), filterlog.Filter(rids=[U_SSH_WAN]),
                               rules.index(self.paths), now=NOW)
        self.assertEqual(data['events'], 0)


class TestRules(Base):
    def test_index(self):
        idx = rules.index(self.paths)
        self.assertEqual(idx[U_ALLOW_LAN]['display'], 'lan #100 pass "Allow LAN to any"')
        self.assertTrue(idx[L_DEFAULT_DENY]['automatic'])
        self.assertNotIn('fdc0d4140dde5aad7dc76e6017cd7934', idx)        # commented out line

    def test_table_counters_and_findings(self):
        data = rules.table(self.paths, Budget(5))
        self.assertTrue(data['stats_available'])
        by_uuid = {r['uuid']: r for r in data['rows']}
        self.assertEqual(by_uuid[U_SSH_WAN]['counters']['packets'], 0)
        self.assertEqual({f['type'] for f in by_uuid[U_SSH_WAN]['findings']}, {'unused', 'wan_exposed'})
        self.assertEqual(by_uuid[U_SSH_WAN]['ref'], 'ui/firewall/filter#search=' + U_SSH_WAN)
        unused = rules.table(self.paths, Budget(5), unused=True)['rows']
        self.assertEqual([r['uuid'] for r in unused], [U_SSH_WAN])
        self.assertEqual(len(rules.table(self.paths, Budget(5), interface='opt1')['rows']), 2)
        self.assertEqual(len(rules.table(self.paths, Budget(5), search='printer')['rows']), 1)

    def test_find(self):
        found = rules.find(self.paths, {'texts': ['block iot to lan']})
        self.assertEqual(found[0][1].uuid, U_BLOCK_IOT)
        found = rules.find(self.paths, {'texts': ['SSH to server']})
        self.assertEqual(found[0][1].uuid, U_SSH_WAN)
        self.assertEqual(rules.find(self.paths, {'uuids': [U_ALLOW_LAN]})[0][1].uuid, U_ALLOW_LAN)
        self.assertEqual(rules.find(self.paths, {'texts': ['nothing like this']}), [])

    def test_path_quick_block_decides(self):
        data = rules.path(self.paths, src='192.168.1.50', dst='198.51.100.20', dport=443, proto='tcp')
        path = data['paths'][0]
        self.assertTrue(path['interface'].startswith('lan'))
        self.assertEqual(path['likely_decision']['display'], 'lan #10 block "Block printer HTTPS"')
        self.assertTrue(path['candidates'][0]['certain'])

    def test_path_pass(self):
        data = rules.path(self.paths, src='192.168.1.60', dst='198.51.100.20', dport=443, proto='tcp')
        self.assertEqual(data['paths'][0]['likely_decision']['display'], 'lan #100 pass "Allow LAN to any"')

    def test_path_alias_iot(self):
        data = rules.path(self.paths, src='192.168.20.7', dst='192.168.1.10', dport=445, proto='tcp')
        self.assertEqual(data['paths'][0]['likely_decision']['display'], 'opt1 #10 block "Block IoT to LAN"')

    def test_path_from_internet_uses_wan(self):
        data = rules.path(self.paths, src='203.0.113.9', dst='192.168.1.10', dport=22, proto='tcp')
        self.assertTrue(data['paths'][0]['interface'].startswith('wan'))
        self.assertEqual(data['paths'][0]['likely_decision']['display'], 'wan #10 pass "SSH to server"')
        data = rules.path(self.paths, src='203.0.113.9', dst='192.168.1.10', dport=23, proto='tcp')
        self.assertTrue(data['paths'][0]['likely_decision'].startswith('default deny'))


class TestOtherCollectors(Base):
    def test_hosts(self):
        data = hosts.lookup(self.paths, ['192.168.1.50', '192.168.20.7', '192.168.1.10'])
        by = {h['address']: h for h in data['hosts']}
        self.assertEqual(by['192.168.1.50']['names'][0]['hostname'], 'printer')
        self.assertEqual(by['192.168.20.7']['names'][0]['source'], 'kea lease')
        self.assertEqual(by['192.168.1.10']['names'][0]['hostname'], 'nas.example.lan')
        self.assertEqual(by['192.168.20.7']['subnet_of'], 'opt1 (IoT)')
        names = hosts.known_names(self.paths)
        self.assertEqual(names['printer'], ['192.168.1.50'])
        self.assertEqual(names['nas'], ['192.168.1.10'])

    def test_aliases(self):
        data = aliases.member_of(self.paths, '192.168.1.50', Budget(5))
        self.assertEqual([m['alias'] for m in data['member_of']], ['Printers'])
        data = aliases.member_of(self.paths, '198.51.100.77', Budget(5))
        self.assertEqual([m['alias'] for m in data['member_of']], ['Blocklist'])
        self.assertEqual(data['member_of'][0]['how'], 'pf table')
        named = aliases.describe(self.paths, ['iot_net'])
        self.assertEqual(named[0]['content_sample'], ['192.168.20.0/24'])

    def test_quarantine(self):
        entry = quarantine.entry(self.paths, '203.0.113.9', now=NOW)
        self.assertTrue(entry['blocked_now'])
        self.assertEqual(entry['level'], '2 h')
        self.assertEqual(entry['recent_offenses'][0]['reason'], 'scan')
        self.assertFalse(quarantine.entry(self.paths, '198.51.100.5', now=NOW)['in_ledger'])
        summary = quarantine.summary(self.paths, now=NOW)
        self.assertEqual(summary['active'], 1)
        self.assertEqual(summary['offenses_24h_by_reason'], {'scan': 1})
        # the ledger was opened read only: no -wal/-shm, unchanged file
        self.assertFalse(os.path.exists(self.paths.quarantine_db + '-wal'))
        os.unlink(self.paths.quarantine_db)
        self.assertFalse(quarantine.summary(self.paths)['installed'])

    def test_reports(self):
        f = reports.findings(self.paths, rule_uuids={U_SSH_WAN})
        self.assertEqual(f['findings'][0]['severity'], 'high')
        self.assertEqual(f['findings_matching'], 2)
        e = reports.exposure(self.paths)
        self.assertEqual(e['services_list'][0]['service'], 'OpenSSH')

    def test_changes(self):
        win = {'since': int(NOW - 86400), 'until': int(NOW), 'label': 'last 24 h', 'explicit': True}
        data = changes.collect(self.paths, win, now=NOW)
        self.assertEqual(data['revisions_in_window'], 1)
        self.assertEqual(data['revisions'][0]['what'], 'saved a rule')
        rules_diff = data['diff']['collections'][0]
        self.assertEqual((rules_diff['collection'], rules_diff['added']), ('filter rules', 1))
        self.assertEqual(rules_diff['added_items'][0]['item'], 'SSH to server')
        self.assertEqual(rules_diff['added_items'][0]['destination_port'], '22')
        # nothing secret: the admin password hash never appears
        self.assertNotIn('secret', repr(data))
        old = {'since': int(NOW - 86400 * 10), 'until': int(NOW - 86400 * 9), 'label': 'old', 'explicit': True}
        self.assertIn('note', changes.collect(self.paths, old, now=NOW))

    def test_suricata(self):
        data = suricata.summary(self.paths, window(86400), Budget(5))
        self.assertEqual(data['alerts'], 2)
        self.assertEqual(data['top_signatures'][0]['sid'] in (2003933, 2210000), True)
        sev1 = suricata.summary(self.paths, window(86400), Budget(5), severity_max=1)
        self.assertEqual(sev1['alerts'], 1)
        rows, _meta = suricata.tail(self.paths, Budget(5), now=NOW)
        alert = [r for r in rows if r['sid'] == 2003933][0]
        self.assertEqual(alert['hostname'], 'evil.example.com')
        found = suricata.find(self.paths, Budget(5), alert['timestamp'], alert['flow_id'], 2003933)
        self.assertEqual(found['alert']['signature_id'], 2003933)
        os.unlink(self.paths.eve)
        self.assertFalse(suricata.summary(self.paths, window(3600), Budget(5))['available'])

    def test_fwinfo(self):
        self.assertEqual(fwinfo.interface_of(self.paths.config, '192.168.20.9')['name'], 'opt1')
        self.assertEqual(fwinfo.wan_devices(self.paths.config), {'pppoe1'})
        self.assertIn('IoT', fwinfo.interface_names(self.paths.config))

    def test_collectors_are_fast(self):
        start = time.monotonic()
        filterlog.top(self.paths, window(86400), Budget(5), rules.index(self.paths), now=NOW)
        rules.table(self.paths, Budget(5))
        self.assertLess(time.monotonic() - start, 2.0)


if __name__ == '__main__':
    unittest.main()
