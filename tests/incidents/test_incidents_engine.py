"""
Correlation rules, case merging, score and the incremental run of the incident triage.

    cd tests/incidents && /usr/bin/python3 -m unittest discover -s .
"""

import os
import unittest

import ihelpers as H
from ihelpers import LAN_DEV, OUT_BLOCK_RULE, T0, WAN_IP, eve_alert, v4

SCANNER = '203.0.113.9'
WEB = '192.168.1.10'


def scan(ts, src=SCANNER, ports=12):
    return [v4(ts + i, src, WAN_IP, 1000 + i, action='block') for i in range(ports)]


class TestScanThenAllowed(H.IncidentCase):
    def test_scan_then_allowed_creates_case(self):
        self.log(*scan(T0 - 900))
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        result = self.run_engine()
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['cases_new'], 1)
        case = self.cases()[0]
        self.assertEqual(case['rule'], 'scan_then_allowed')
        self.assertEqual((case['primary_kind'], case['primary_value']), ('ext', SCANNER))
        self.assertIn(SCANNER, case['title'])
        ids = {f['id']: f['points'] for f in case['factors']}
        self.assertEqual(ids['rule:scan_then_allowed'], 50)
        self.assertEqual(ids['allowed_internal'], 15)
        self.assertEqual(case['score'], sum(ids.values()))       # every point is explained
        self.assertEqual(case['severity'], 'high')
        detail = self.detail(case['id'])
        kinds = {(e['kind'], e['value']) for e in detail['entities']}
        self.assertIn(('int', WEB), kinds)
        self.assertIn(('rule', H.NAT_RULE), kinds)
        texts = [e['text'] for e in detail['evidence']]
        self.assertTrue(any('12 port(s)' in t for t in texts))
        self.assertTrue(any('NAT web server' in t for t in texts))

    def test_scan_without_allowed_connection_is_no_case(self):
        self.log(*scan(T0 - 900))
        self.run_engine()
        self.assertEqual(self.cases(), [])

    def test_allowed_before_the_scan_is_no_case(self):
        self.log(v4(T0 - 3000, SCANNER, WEB, 443))
        self.log(*scan(T0 - 900))
        self.run_engine()
        self.assertEqual(self.cases(), [])

    def test_few_ports_is_no_scan(self):
        self.log(*scan(T0 - 900, ports=5))
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()
        self.assertEqual(self.cases(), [])

    def test_quarantine_scan_offense_counts_as_scan(self):
        q = self.quarantine()
        q.begin()
        e = q.create_entry(SCANNER, 'ip', T0 - 1200, state='active', level=2, until=T0 + 6000, since=T0 - 1200)
        q.add_offense(e['id'], T0 - 1200, 'scan', ['scan', 'base'], 2, T0 + 6000, 'auto', events=30,
                      ports='22/tcp,23/tcp', detail='14 ports in 300 s', iface='wan')
        q.commit()
        q.close()
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()
        cases = self.cases()
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]['rule'], 'scan_then_allowed')
        # in quarantine right now: contained, -10
        ids = {f['id']: f['points'] for f in cases[0]['factors']}
        self.assertEqual(ids.get('contained'), -10)

    def test_incremental_runs_do_not_count_twice(self):
        self.log(*scan(T0 - 900))
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()
        self.run_engine(advance=300)           # nothing new
        detail = self.detail(1)
        passes = [e for e in detail['evidence'] if 'allowed inbound' in e['text']]
        self.assertEqual(sum(e['count'] for e in passes), 1)
        self.assertEqual(detail['matches'], 1)
        # a new allowed connection in the next run updates the same case
        self.log(v4(T0 + 200, SCANNER, WEB, 443))
        result = self.run_engine(advance=300)
        self.assertEqual(result['cases_updated'], 1)
        self.assertEqual(len(self.cases()), 1)
        detail = self.detail(1)
        scans = [e for e in detail['evidence'] if 'blocked inbound' in e['text']]
        passes = [e for e in detail['evidence'] if 'allowed inbound' in e['text']]
        self.assertEqual(sum(e['count'] for e in passes), 2)
        self.assertEqual(sum(e['count'] for e in scans), 12)      # the scan context is added only once

    def test_resolved_case_reopens_as_new_case_with_recurrence(self):
        self.log(*scan(T0 - 900))
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()
        st = self.db()
        st.update_case(1, state='resolved')
        st.close()
        self.log(v4(T0 + 100, SCANNER, WEB, 443))
        self.run_engine(advance=300)
        cases = self.cases()
        self.assertEqual(len(cases), 2)
        self.assertEqual(cases[1]['previous_id'], 1)
        self.assertIn('recurrence', {f['id'] for f in cases[1]['factors']})

    def test_false_positive_absorbs_new_matches(self):
        self.log(*scan(T0 - 900))
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()
        st = self.db()
        st.update_case(1, state='false_positive')
        st.close()
        self.log(v4(T0 + 100, SCANNER, WEB, 443))
        result = self.run_engine(advance=300)
        self.assertEqual(result['suppressed'], 1)
        cases = self.cases()
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]['state'], 'false_positive')
        self.assertEqual(cases[0]['suppressed'], 1)

    def test_quiet_gap_opens_a_new_case(self):
        self.log(*scan(T0 - 900))
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()
        later = T0 + 8 * 3600
        self.clock.now = later
        self.log(*scan(later - 900))
        self.log(v4(later - 600, SCANNER, WEB, 443))
        self.run_engine()
        self.assertEqual(len(self.cases()), 2)


class TestIdsAndAllowed(H.IncidentCase):
    def test_alert_and_allowed_inbound(self):
        attacker = '198.51.100.66'
        self.eve(eve_alert(T0 - 500, attacker, severity=1, dport=443))
        self.log(v4(T0 - 480, attacker, WEB, 443))
        self.run_engine()
        cases = self.cases()
        self.assertEqual(len(cases), 1)
        case = cases[0]
        self.assertEqual(case['rule'], 'ids_and_allowed')
        ids = {f['id']: f['points'] for f in case['factors']}
        self.assertEqual(ids['ids_sev1'], 20)
        self.assertEqual(ids['same_port'], 10)
        self.assertEqual(ids['allowed_internal'], 15)
        self.assertEqual(case['severity'], 'critical')
        self.assertIn(WEB, case['title'])
        sources = {e['source'] for e in self.detail(case['id'])['evidence']}
        self.assertEqual(sources, {'suricata', 'filter'})

    def test_alert_and_outbound_from_internal_host(self):
        c2 = '192.0.2.99'
        self.eve(eve_alert(T0 - 500, '192.168.1.40', severity=2, dport=8080, dst=c2))
        self.log(v4(T0 - 520, '192.168.1.40', c2, 8080, iface=LAN_DEV))
        self.run_engine()
        case = self.cases()[0]
        self.assertEqual((case['primary_kind'], case['primary_value']), ('ext', c2))
        self.assertIn('ids_sev2', {f['id'] for f in case['factors']})

    def test_alert_alone_is_no_case(self):
        self.eve(eve_alert(T0 - 500, '198.51.100.66', severity=1))
        self.run_engine()
        self.assertEqual(self.cases(), [])

    def test_alert_far_from_the_traffic_is_no_case(self):
        attacker = '198.51.100.66'
        self.log(v4(T0 - 7000, attacker, WEB, 443))
        self.eve(eve_alert(T0 - 300, attacker, severity=1, dport=443))
        self.run_engine()
        self.assertEqual(self.cases(), [])


class TestInternalToBad(H.IncidentCase):
    def _quarantined(self, addr='203.0.113.50', active=True):
        q = self.quarantine()
        q.begin()
        until = T0 + 3600 if active else T0 - 86400
        e = q.create_entry(addr, 'ip', T0 - 2 * 86400, state='active' if active else 'expired', level=3,
                           until=until, since=T0 - 2 * 86400)
        q.add_offense(e['id'], T0 - 2 * 86400, 'suricata', ['suricata'], 3, until, 'auto', events=1)
        q.commit()
        q.close()

    def test_allowed_to_quarantined_address(self):
        self._quarantined()
        self.log(v4(T0 - 400, '192.168.1.30', '203.0.113.50', 443, iface=LAN_DEV))
        self.run_engine()
        case = self.cases()[0]
        self.assertEqual(case['rule'], 'internal_to_bad')
        self.assertEqual((case['primary_kind'], case['primary_value']), ('int', '192.168.1.30'))
        ids = {f['id'] for f in case['factors']}
        self.assertIn('allowed_to_bad', ids)
        self.assertIn('active_quarantine', ids)
        ents = {(e['kind'], e['value']): e for e in self.detail(case['id'])['entities']}
        self.assertTrue(ents[('ext', '203.0.113.50')]['info']['quarantine']['active'])

    def test_recently_quarantined_counts_too(self):
        self._quarantined(active=False)
        self.log(v4(T0 - 400, '192.168.1.30', '203.0.113.50', 443, iface=LAN_DEV))
        self.run_engine()
        self.assertEqual(self.cases()[0]['rule'], 'internal_to_bad')

    def test_clean_destination_is_no_case(self):
        self.log(v4(T0 - 400, '192.168.1.30', '203.0.113.51', 443, iface=LAN_DEV))
        self.run_engine()
        self.assertEqual(self.cases(), [])

    def test_blocked_outbound_by_rule(self):
        self.log(*[v4(T0 - 400 + i, '192.168.1.31', '198.51.100.200', 443, action='block', iface=LAN_DEV,
                      rid=OUT_BLOCK_RULE) for i in range(4)])
        self.run_engine()
        detail = self.detail(1)
        self.assertEqual(detail['rule'], 'internal_to_bad')
        self.assertTrue(any('Block Q-feeds outbound' in e['text'] for e in detail['evidence']))

    def test_dns_blocklist(self):
        self.dns(*[(int(T0 - 600 + i), '192.168.1.32', 'bad%d.example.com' % (i % 2), 1, 'hgz002') for i in range(6)],
                 (int(T0 - 500), '192.168.1.33', 'ok.example.com', 0, None))
        result = self.run_engine()
        self.assertTrue(result['dns']['available'])
        case = self.cases()[0]
        self.assertEqual(case['primary_value'], '192.168.1.32')
        detail = self.detail(case['id'])
        self.assertEqual(detail['evidence'][0]['source'], 'dns')
        self.assertIn('6 blocked DNS queries', detail['evidence'][0]['text'])
        # the DNS mark moved: the same queries are not read again
        self.run_engine(advance=300)
        self.assertEqual(self.detail(case['id'])['evidence'][0]['count'], 6)


class TestCampaignAndSpike(H.IncidentCase):
    def _baseline(self, hours, sources=2, events=10, port='22/tcp'):
        st = self.db()
        st.begin()
        hour = T0 - T0 % 3600
        for h in range(1, hours + 1):
            st.set_hourly(hour - h * 3600, '*', events, events, 0, sources)
            st.set_hourly(hour - h * 3600, port, events, events, 0, sources)
        st.commit()
        st.close()

    def _sources(self, n, port=22, start=T0 - 1800):
        lines = []
        for i in range(n):
            lines.append(v4(start + i, '198.51.100.%d' % (10 + i), WAN_IP, port, action='block'))
        return lines

    def test_campaign_with_baseline(self):
        self._baseline(30)
        self.log(*self._sources(25))
        self.run_engine()
        case = self.cases()[0]
        self.assertEqual(case['rule'], 'campaign')
        self.assertEqual((case['primary_kind'], case['primary_value']), ('port', '22/tcp'))
        self.assertIn('25 sources', case['title'])
        ev = self.detail(case['id'])['evidence']
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]['count'], 25)
        # next run in the same hour: the hourly line is replaced, not added
        self.log(*self._sources(3, start=T0 + 10)[:0])
        self.log(v4(T0 + 50, '198.51.100.200', WAN_IP, 22, action='block'))
        self.run_engine(advance=120)
        ev = self.detail(case['id'])['evidence']
        self.assertEqual(ev[-1]['count'], 26)

    def test_usual_number_of_sources_is_no_campaign(self):
        self._baseline(30, sources=20)
        self.log(*self._sources(25))
        self.run_engine()
        self.assertEqual(self.cases(), [])

    def test_without_baseline_needs_many_more_sources(self):
        self.log(*self._sources(25))
        self.run_engine()
        self.assertEqual(self.cases(), [])
        self.log(*self._sources(60, start=T0 - 1000)[25:])
        self.log(*[v4(T0 - 900 + i, '192.0.2.%d' % (10 + i), WAN_IP, 22, action='block') for i in range(30)])
        self.run_engine(advance=60)
        self.assertEqual(self.cases()[0]['rule'], 'campaign')

    def test_port_spike(self):
        self._baseline(30, sources=1, events=10, port='8443/tcp')
        lines = [v4(T0 - 1500 + i, '203.0.113.77', WAN_IP, 8443, action='block') for i in range(260)]
        self.log(*lines)
        self.run_engine()
        case = self.cases()[0]
        self.assertEqual(case['rule'], 'port_spike')
        self.assertEqual(case['primary_value'], '8443/tcp')
        self.assertIn('spike_ratio', {f['id'] for f in case['factors']})

    def test_spike_needs_baseline_hours(self):
        self._baseline(5, sources=1, events=10, port='8443/tcp')
        self.log(*[v4(T0 - 1500 + i, '203.0.113.77', WAN_IP, 8443, action='block') for i in range(260)])
        self.run_engine()
        self.assertEqual(self.cases(), [])

    def test_hourly_counters_are_written(self):
        self.log(*self._sources(6))
        self.run_engine()
        st = self.db()
        hour = (T0 - 1800) - (T0 - 1800) % 3600
        rows = st.hourly('22/tcp', hour, hour + 1)
        st.close()
        self.assertEqual(rows[0]['sources'], 6)


class TestRepeatOffender(H.IncidentCase):
    def test_back_after_expiry(self):
        addr = '203.0.113.88'
        q = self.quarantine()
        q.begin()
        e = q.create_entry(addr, 'ip', T0 - 5 * 86400, state='active', level=3, until=T0 + 86400, since=T0 - 100)
        q.add_offense(e['id'], T0 - 5 * 86400, 'scan', ['scan'], 2, T0 - 5 * 86400 + 7200, 'auto', events=20)
        q.commit()
        q.close()
        self.run_engine()                        # first look: remembers the last offense id
        q = self.quarantine()
        q.begin()
        q.add_offense(e['id'], T0 - 100, 'suricata', ['suricata', 'base'], 3, T0 + 86400, 'auto', events=2,
                      detail='sid 2003933 sev 1: ET TEST')
        q.commit()
        q.close()
        self.run_engine(advance=300)
        case = self.cases()[0]
        self.assertEqual(case['rule'], 'repeat_offender')
        self.assertEqual(case['primary_value'], addr)
        self.assertIn('level', {f['id'] for f in case['factors']})
        self.assertIn('Back in quarantine at level 3', self.detail(case['id'])['evidence'][0]['text'])

    def test_extension_during_quarantine_is_not_repeat(self):
        addr = '203.0.113.89'
        q = self.quarantine()
        q.begin()
        e = q.create_entry(addr, 'ip', T0 - 3600, state='active', level=2, until=T0 + 3600, since=T0 - 3600)
        q.add_offense(e['id'], T0 - 3600, 'scan', ['scan'], 2, T0 + 3600, 'auto', events=20)
        q.commit()
        q.close()
        self.run_engine()
        q = self.quarantine()
        q.begin()
        q.add_offense(e['id'], T0 - 50, 'suricata', ['suricata'], 3, T0 + 86400, 'auto', events=1)
        q.commit()
        q.close()
        self.run_engine(advance=300)
        self.assertEqual(self.cases(), [])


class TestMergeAndScore(H.IncidentCase):
    def test_two_rules_on_the_same_entity_are_one_case(self):
        self.eve(eve_alert(T0 - 500, SCANNER, severity=1, dport=443))
        self.log(*scan(T0 - 900))
        self.log(v4(T0 - 480, SCANNER, WEB, 443))
        self.run_engine()
        cases = self.cases()
        self.assertEqual(len(cases), 1)
        rules = {r['rule'] for r in self.detail(cases[0]['id'])['rules']}
        self.assertEqual(rules, {'scan_then_allowed', 'ids_and_allowed'})
        ids = {f['id']: f['points'] for f in cases[0]['factors']}
        self.assertEqual(ids['rule:scan_then_allowed'], 50)
        self.assertEqual(ids['also:ids_and_allowed'], 10)
        self.assertEqual(cases[0]['score'], 100)                  # capped
        self.assertEqual(cases[0]['severity'], 'critical')

    def test_compute_score(self):
        score, factors = H.engine.compute_score(['campaign'], {'x': {'id': 'x', 'label': 'x', 'points': 7}},
                                                recurrence=True, contained=True)
        self.assertEqual(score, 25 + 7 + 10 - 10)
        self.assertEqual([f['id'] for f in factors], ['rule:campaign', 'x', 'recurrence', 'contained'])

    def test_severity_levels(self):
        self.assertEqual(H.common.severity_of(70), 'critical')
        self.assertEqual(H.common.severity_of(50), 'high')
        self.assertEqual(H.common.severity_of(30), 'medium')
        self.assertEqual(H.common.severity_of(29), 'low')


class TestRunAndViews(H.IncidentCase):
    def test_not_installed(self):
        os.unlink(self.ctx.db)
        self.assertEqual(self.run_engine()['status'], 'not_installed')
        self.assertEqual(H.engine.Engine(self.ctx).summary(), {'status': 'ok', 'installed': False})

    def test_first_run_starts_near_the_end(self):
        st = self.db()
        st.db.execute("DELETE FROM meta WHERE key LIKE 'marker_%'")
        st.close()
        self.log(*scan(T0 - 900))
        result = self.run_engine()
        self.assertTrue(result['filter_log']['first_run'])
        self.assertEqual(result['filter_log']['records'], 12)    # small file: read from the start of the tail

    def test_busy(self):
        lock = H.engine.Lock(self.ctx.lock_file).acquire()
        try:
            self.assertEqual(self.run_engine()['status'], 'busy')
        finally:
            lock.release()

    def test_old_observations_are_pruned(self):
        self.log(*scan(T0 - 900))
        self.run_engine()
        self.clock.now = T0 + 3 * 86400
        self.run_engine()
        st = self.db()
        left = st.db.execute('SELECT count(*) FROM obs').fetchone()[0]
        st.close()
        self.assertEqual(left, 0)

    def test_summary_and_search(self):
        self.log(*scan(T0 - 900))
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()
        eng = H.engine.Engine(self.ctx)
        summary = eng.summary()
        self.assertEqual(summary['open'], 1)
        self.assertEqual(summary['open_by_severity'], {'high': 1})
        self.assertEqual(summary['latest'][0]['primary'], {'kind': 'ext', 'value': SCANNER})
        found = eng.search({'search': '192.168.1.10'}, None, 1, 10)
        self.assertEqual(found['total'], 1)
        self.assertEqual(found['rows'][0]['rules'], ['scan_then_allowed'])
        self.assertEqual(eng.search({'state': 'resolved'}, None, 1, 10)['total'], 0)
        self.assertEqual(eng.search({'severity': 'high', 'rule': 'scan_then_allowed'}, None, 1, 10)['total'], 1)
        status = eng.status()
        self.assertTrue(status['installed'])
        self.assertEqual(status['counts']['open'], 1)

    def test_cli_list_and_case(self):
        import io
        import json
        from contextlib import redirect_stdout
        self.log(*scan(T0 - 900))
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()
        buf = io.StringIO()
        with redirect_stdout(buf):
            H.cli.main(['cli.py', 'list', 'state=open+severity=high+days=7', 'score:desc', '1:10'])
        data = json.loads(buf.getvalue())
        self.assertEqual(data['total'], 1)
        buf = io.StringIO()
        with redirect_stdout(buf):
            H.cli.main(['cli.py', 'case', '1'])
        self.assertEqual(json.loads(buf.getvalue())['case']['id'], 1)
        buf = io.StringIO()
        with redirect_stdout(buf):
            H.cli.main(['cli.py', 'list', 'state=evil', '-', '-'])
        self.assertEqual(json.loads(buf.getvalue())['status'], 'error')
        buf = io.StringIO()
        with redirect_stdout(buf):
            H.cli.main(['cli.py', 'case', '1;rm'])
        self.assertEqual(json.loads(buf.getvalue())['status'], 'error')


if __name__ == '__main__':
    unittest.main()
