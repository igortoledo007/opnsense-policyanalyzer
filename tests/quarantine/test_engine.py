"""
the 5 minute run: position markers (no event lost or counted twice, rotation, first run), scenarios end to
end, repeat offenses after expiry, hits while in quarantine, upgrades, guards, limit, expiry and the pf
table sync with the fake runner, history kept forever (yearly aggregate, CSV export).
"""

import os
import time
import unittest

from qhelpers import (RULE_UUID, T0, WAN_IP, QuarantineCase, cli, common, eve_alert, filter_line, sources,
                      store)

ATTACKER = '203.0.113.10'


class TestMarker(QuarantineCase):
    def test_no_loss_no_repeat(self):
        self.log(filter_line(T0 - 60, ATTACKER))
        first = self.run_engine()
        self.assertEqual(first['offenses'], 1)
        again = self.run_engine(advance=60)
        self.assertEqual(again['filter_log']['records'], 0)
        self.assertEqual(again['offenses'], 0)
        self.assertEqual(len(self.offenses(ATTACKER)), 1)

    def test_partial_line_is_kept_for_the_next_run(self):
        line = filter_line(T0 - 30, '203.0.113.11')
        self.log(line[:40])
        self.assertEqual(self.run_engine()['filter_log']['records'], 0)
        self.log(line[40:])
        self.assertEqual(self.run_engine(advance=10)['offenses'], 1)

    def test_rotation_reads_the_rest_of_the_previous_file(self):
        self.log(filter_line(T0 - 120, '203.0.113.12'))
        self.run_engine()
        self.log(filter_line(T0 - 10, '203.0.113.13'))              # written before midnight, after the run
        new_file = os.path.join(os.path.dirname(self.log_file), 'filter_20261027.log')
        with open(new_file, 'w') as handle:
            handle.write(filter_line(T0 + 30, '203.0.113.14'))
        os.unlink(self.ctx.filter_log)
        os.symlink(new_file, self.ctx.filter_log)
        result = self.run_engine(advance=60)
        self.assertEqual(result['offenses'], 2)
        self.assertIsNotNone(self.entry('203.0.113.13'))
        self.assertIsNotNone(self.entry('203.0.113.14'))
        self.assertEqual(self.run_engine(advance=60)['offenses'], 0)

    def test_first_run_starts_near_the_end(self):
        lines = ''.join(filter_line(T0 - 3600, '203.0.113.%d' % (i % 200 + 1)) for i in range(30000))
        self.log(lines, filter_line(T0 - 5, '203.0.113.250'))
        st = self.db()
        st.begin()
        st.del_meta('marker_filter')
        st.commit()
        st.close()
        result = self.run_engine()
        self.assertTrue(result['filter_log']['first_run'])
        self.assertLess(result['filter_log']['bytes'], common.FIRST_RUN_TAIL + 1)

    def test_read_new_truncated_file(self):
        self.log(filter_line(T0, ATTACKER))
        _lines, marker, _info = sources.read_new(self.ctx.filter_log, lambda: [], None, first_tail=10 ** 9)
        open(self.log_file, 'w').close()
        self.log(filter_line(T0 + 1, '203.0.113.20'))
        lines, _marker, _info = sources.read_new(self.ctx.filter_log, lambda: [], dict(marker, offset=10 ** 6))
        self.assertEqual(len(lines), 1)


class TestRun(QuarantineCase):
    def test_base_offense_and_pf_table(self):
        self.log(filter_line(T0 - 60, ATTACKER, dport=6322))
        result = self.run_engine()
        self.assertEqual(result['by_reason'], {'base': 1})
        entry = self.entry(ATTACKER)
        self.assertEqual((entry['level'], entry['state'], entry['origin']), (1, 'active', 'auto'))
        self.assertEqual(entry['until'], T0 + 1800)
        self.assertEqual(entry['iface'], 'wan')
        self.assertEqual(self.runner.table, {ATTACKER})
        off = self.offenses(ATTACKER)[0]
        self.assertEqual((off['reason'], off['level'], off['ports'], off['iface']), (1, 1, '6322/tcp', 'wan'))

    def test_only_inbound_blocks_on_wan(self):
        self.log(filter_line(T0 - 50, '203.0.113.30', iface='igc0'),          # LAN
                 filter_line(T0 - 50, '203.0.113.31', direction='out'),
                 filter_line(T0 - 50, '203.0.113.32', action='pass'),
                 filter_line(T0 - 50, '203.0.113.33', flags='SA'),           # not a connection attempt
                 filter_line(T0 - 50, '203.0.113.34', iface='igc2'))          # second WAN (opt6)
        self.run_engine()
        self.assertEqual(self.runner.table, {'203.0.113.34'})
        self.assertEqual(self.entry('203.0.113.34')['iface'], 'opt6')

    def test_ipv6(self):
        self.log(filter_line(T0 - 50, '2001:db8::bad', ipver=6, dst='2001:db8:1::1'))
        self.run_engine()
        self.assertEqual(self.runner.table, {'2001:db8::bad'})

    def test_scan_and_bait_and_suricata(self):
        self.log(*[filter_line(T0 - 200 + i, '203.0.113.40', dport=1000 + i) for i in range(12)])
        self.log(filter_line(T0 - 100, '203.0.113.41', dport=23))
        self.eve(eve_alert(T0 - 90, '203.0.113.42'), eve_alert(T0 - 80, '203.0.113.43', severity=2),
                 eve_alert(T0 - 70, '192.168.1.50'))
        result = self.run_engine()
        self.assertEqual(result['by_reason'], {'scan': 1, 'bait': 1, 'suricata': 1})
        self.assertEqual(self.entry('203.0.113.40')['level'], 2)
        self.assertEqual(self.entry('203.0.113.41')['level'], 2)
        sur = self.entry('203.0.113.42')
        self.assertEqual((sur['level'], sur['until']), (3, T0 + 2 * 86400))
        self.assertIn('sid 2003933', self.offenses('203.0.113.42')[0]['detail'])
        self.assertIsNone(self.entry('203.0.113.43'))                       # severity 2
        self.assertIsNone(self.entry('192.168.1.50'))
        self.assertIn('203.0.113.42', self.runner.killed)                   # states of a Suricata source

    def test_suricata_disabled(self):
        self.set_setting('suricata', 0)
        self.eve(eve_alert(T0 - 90, '203.0.113.42'))
        self.assertEqual(self.run_engine()['offenses'], 0)

    def test_hits_while_quarantined_and_repeat_after_expiry(self):
        self.log(filter_line(T0 - 60, ATTACKER))
        self.run_engine()
        self.log(filter_line(T0 + 100, ATTACKER, rid=RULE_UUID), filter_line(T0 + 200, ATTACKER))
        result = self.run_engine(advance=300)
        self.assertEqual(result['offenses'], 0)
        self.assertEqual(result['hits'], 2)
        self.assertEqual(self.entry(ATTACKER)['hits'], 2)
        # quarantine ends at T0 + 1800
        result = self.run_engine(advance=1600)
        self.assertEqual(result['expired'], 1)
        self.assertEqual(self.runner.table, set())
        self.log(filter_line(T0 + 2000, ATTACKER))
        self.run_engine(advance=200)
        entry = self.entry(ATTACKER)
        self.assertEqual((entry['level'], entry['offenses'], entry['state']), (2, 2, 'active'))
        self.assertEqual(entry['until'], self.clock.now + 7200)

    def test_upgrade_while_quarantined(self):
        self.log(filter_line(T0 - 60, ATTACKER))
        self.run_engine()
        self.eve(eve_alert(T0 + 30, ATTACKER))
        result = self.run_engine(advance=60)
        self.assertEqual(result['upgrades'], 1)
        entry = self.entry(ATTACKER)
        self.assertEqual(entry['level'], 3)
        self.assertEqual(entry['until'], self.clock.now + 2 * 86400)

    def test_reset_after_90_days(self):
        self.log(filter_line(T0 - 60, ATTACKER))
        self.run_engine()
        st = self.db()
        st.begin()
        entry = st.entry_by_addr(ATTACKER)
        st.update_entry(entry['id'], level=4, state='expired', last_offense=T0 - 91 * 86400, until=T0 - 80 * 86400)
        st.commit()
        st.close()
        self.log(filter_line(T0 + 100, ATTACKER))
        self.run_engine(advance=200)
        self.assertEqual(self.entry(ATTACKER)['level'], 1)

    def test_paused_keeps_recording(self):
        st = self.db()
        st.begin()
        st.set_meta('paused', '1')
        st.commit()
        st.close()
        self.log(filter_line(T0 - 60, ATTACKER))
        self.assertEqual(self.run_engine()['offenses'], 1)

    def test_not_installed(self):
        os.unlink(self.ctx.db)
        self.assertEqual(self.engine().run()['status'], 'not_installed')

    def test_busy(self):
        from quarantine import engine as engine_mod
        lock = engine_mod.Lock(self.ctx.lock_file).acquire()
        try:
            self.assertEqual(self.engine().run()['status'], 'busy')
        finally:
            lock.release()


class TestGuards(QuarantineCase):
    def test_protected_sources_are_never_quarantined(self):
        self.aliases[common.NEVER_ALIAS] = '203.0.113.128/25'
        self.write_config()
        protected = ['198.51.100.53',     # dns (config)
                     '198.51.100.54',     # resolv.conf
                     '198.51.100.123',    # ntp
                     '198.51.100.124',    # ntp hostname, resolved
                     '198.51.100.8',      # gateway monitor
                     '198.51.100.254',    # PPP peer / default route
                     WAN_IP,              # own address
                     '198.51.100.77',     # WireGuard peer (config)
                     '198.51.100.66',     # WireGuard endpoint (wg show)
                     '203.0.113.200',     # pa_never_block
                     '10.0.0.5', '100.64.0.9', '224.0.0.5']
        self.log(*[filter_line(T0 - 60, ip) for ip in protected])
        result = self.run_engine()
        self.assertEqual(result['offenses'], 0)
        self.assertEqual(self.runner.table, set())
        self.assertIn('never_block', result['guarded'])

    def test_wireguard_allowed_in_the_last_24_hours(self):
        client = '203.0.113.60'
        self.log(filter_line(T0 - 3600, client, dport=51830, proto='udp', action='pass'),
                 filter_line(T0 - 60, client, dport=22))
        self.assertEqual(self.run_engine()['offenses'], 0)
        self.log(filter_line(T0 + 25 * 3600, client, dport=22))
        self.assertEqual(self.run_engine(advance=25 * 3600 + 60)['offenses'], 1)

    def test_admin_session(self):
        self.runner.outputs['sockstat'] = ('USER COMMAND PID FD PROTO LOCAL FOREIGN\n'
                                           'root sshd 1 7 tcp4 198.51.100.1:22 203.0.113.70:56710\n')
        self.log(filter_line(T0 - 60, '203.0.113.70', dport=443))
        self.assertEqual(self.run_engine()['offenses'], 0)

    def test_entry_released_when_it_becomes_protected(self):
        self.log(filter_line(T0 - 60, ATTACKER))
        self.run_engine()
        self.aliases[common.NEVER_ALIAS] = ATTACKER
        self.write_config()
        result = self.run_engine(advance=60)
        self.assertEqual(result['released'], 1)
        self.assertEqual(self.entry(ATTACKER)['state'], 'released')
        self.assertEqual(self.runner.table, set())

    def test_report(self):
        report = self.engine().guards_report()
        self.assertEqual(report['status'], 'ok')
        addrs = {i['addr'] for i in report['labels']['dns']}
        self.assertIn('198.51.100.53', addrs)
        self.assertIn('private', report['implicit'])


class TestLimitAndTable(QuarantineCase):
    def test_limit(self):
        self.set_setting('max_active', 100)
        self.log(*[filter_line(T0 - 60, '203.0.113.%d' % i) for i in range(1, 120)])
        result = self.run_engine()
        self.assertEqual(result['offenses'], 100)
        self.assertEqual(result['limited'], 19)
        self.assertTrue(result['limit_hit'])
        self.assertEqual(len(self.runner.table), 100)
        status = self.engine().status()
        self.assertTrue(any(w.get('action', {}).get('id') == 'quarantine_settings' for w in status['warning_actions']))
        st = self.db()
        try:
            self.assertEqual(st.db.execute('SELECT count(*) FROM offenses WHERE limited = 1').fetchone()[0], 19)
        finally:
            st.close()
        self.assertEqual(self.offenses('203.0.113.119')[0]['limited'], 1)      # sorted: the last ones wait

    def test_sync_rebuilds_after_reboot_and_removes_strays(self):
        self.log(filter_line(T0 - 60, ATTACKER))
        self.run_engine()
        self.runner.table = {'203.0.113.99'}                    # empty after reboot + a stray entry
        result = self.engine().sync()
        self.assertEqual((result['added'], result['deleted']), (1, 1))
        self.assertEqual(self.runner.table, {ATTACKER})

    def test_table_missing(self):
        self.runner.table = None
        self.log(filter_line(T0 - 60, ATTACKER))
        result = self.run_engine()
        self.assertEqual(result['table']['status'], 'missing')
        self.assertEqual(self.entry(ATTACKER)['state'], 'active')     # recorded, synced once the table exists

    def test_network_entry_with_protected_hole(self):
        st = self.db()
        st.begin()
        st.create_entry('198.51.100.0/24', 'net', T0, state='active', level=2, since=T0, last_offense=T0,
                        until=T0 + 7200, origin='manual')
        st.commit()
        st.close()
        self.engine().sync()
        self.assertIn('198.51.100.0/24', self.runner.table)
        self.assertIn('!198.51.100.1', self.runner.table)          # own WAN address stays reachable
        self.assertIn('!198.51.100.53', self.runner.table)
        self.log(filter_line(T0 + 10, '198.51.100.200'))
        result = self.run_engine(advance=60)
        self.assertEqual((result['offenses'], result['hits']), (0, 1))


class TestHistory(QuarantineCase):
    def test_history_is_kept_and_aggregated_per_year(self):
        self.log(filter_line(T0 - 60, ATTACKER, dport=3389))
        self.run_engine()
        self.log(filter_line(T0 + 7300, ATTACKER))
        self.run_engine(advance=7400)
        st = self.db()
        try:
            year = time.localtime(T0).tm_year
            row = st.db.execute('SELECT * FROM v_yearly WHERE addr = ?', (ATTACKER,)).fetchone()
            self.assertEqual((row['year'], row['offenses'], row['max_level'], row['reasons']),
                             (year, 2, 3, 'base bait'))
            kinds = [r['kind'] for r in st.db.execute('SELECT kind FROM v_events ORDER BY id')]
            self.assertEqual(kinds, ['enter', 'expire', 'enter'])
            self.assertEqual(st.db.execute('SELECT count(*) FROM v_offenses WHERE year = ?', (year,)).fetchone()[0], 2)
        finally:
            st.close()
        csv_text = self.engine().export_csv(str(time.localtime(T0).tm_year))
        lines = csv_text.strip().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith('time,address'))
        self.assertIn(ATTACKER, lines[1])
        self.assertEqual(self.engine().export_csv('2001').strip().count('\n'), 0)

    def test_queries(self):
        self.log(filter_line(T0 - 60, ATTACKER), filter_line(T0 - 60, '203.0.113.11', dport=23))
        self.run_engine()
        eng = self.engine()
        page = eng.search({'reason': 'bait'}, None, 1, 20)
        self.assertEqual([r['addr'] for r in page['rows']], ['203.0.113.11'])
        self.assertEqual(eng.search({'state': 'active'}, ('addr', 'asc'), 1, 1)['total'], 2)
        row = eng.search({'search': '203.0.113.10'}, None, 1, 20)['rows'][0]
        self.assertEqual(row['remaining'], 1800)
        self.assertEqual(row['reason'], 'base')
        detail = eng.entry_detail(ATTACKER)
        self.assertEqual(len(detail['offenses']), 1)
        hist = eng.history('offenses', ATTACKER, str(time.localtime(T0).tm_year), 1, 50)
        self.assertEqual(hist['total'], 1)
        yearly = eng.history('yearly', None, str(time.localtime(T0).tm_year), 1, 50)
        self.assertEqual(yearly['total'], 2)
        summary = eng.summary()
        self.assertEqual((summary['active'], len(summary['latest'])), (2, 2))
        self.assertEqual(summary['latest'][0]['expires_in'] > 0, True)
        status = eng.status()
        self.assertTrue(status['installed'])
        self.assertEqual(status['counts']['active_by_level'], {'1': 1, '2': 1})
        self.assertEqual(status['rule']['description'], 'Max Cyber IA')


class TestCli(QuarantineCase):
    def run_cli(self, *args):
        import io
        import json
        buf = io.StringIO()
        cli.main(list(args), out=buf)
        text = buf.getvalue()
        return json.loads(text) if text.startswith('{') else text

    def test_commands(self):
        self.log(filter_line(T0 - 60, ATTACKER))
        self.assertEqual(self.run_cli('run')['offenses'], 1)
        self.assertEqual(self.run_cli('list', 'state=active+reason=base', 'until:desc', '1:20')['total'], 1)
        self.assertEqual(self.run_cli('list', 'state=bogus')['status'], 'error')
        self.assertEqual(self.run_cli('list', 'search=a b')['status'], 'error')
        self.assertEqual(self.run_cli('history', 'offenses', ATTACKER, '-', '1:10')['total'], 1)
        self.assertEqual(self.run_cli('history', 'events', '-', '20261001-20261231', '1:10')['status'], 'ok')
        self.assertEqual(self.run_cli('history', 'offenses', '-', '2026-1', '1:10')['status'], 'error')
        self.assertIn(ATTACKER, self.run_cli('export', str(time.localtime(T0).tm_year), '-'))
        self.assertEqual(self.run_cli('entry', ATTACKER)['entry']['addr'], ATTACKER)
        self.assertEqual(self.run_cli('summary')['active'], 1)
        self.assertEqual(self.run_cli('nope')['status'], 'error')
        self.assertEqual(self.run_cli('list', 'a;b')['status'], 'error')


if __name__ == '__main__':
    unittest.main()
