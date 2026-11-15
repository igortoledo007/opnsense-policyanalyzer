"""
End to end: runs of the engine over injected sources (markers, baselines, learning, exceptions, history),
the change actions (plan / apply / revert through ai.changes and the undo journal), the CLI views and the
AI explanations (preview and a fake provider; the real AI is never called).
"""

import base64
import json
import os
import random
import unittest

from ahelpers import LAN, T0, AnomalyCase, beacon_times, common, dga_dns, flow, store, tunnel_dns
import ahelpers

H = LAN % 50
H2 = LAN % 51


def host(mac, ip, vendor='ACME', source='hostwatch', iface='igc0'):
    return {'mac': mac, 'ip': ip, 'iface': iface, 'first_seen': None, 'last_seen': None, 'vendor': vendor,
            'hostname': None, 'source': source}


class TestRun(AnomalyCase):
    def test_first_run_learns_and_reports_nothing(self):
        self.data['hosts'] = [host('00:11:22:00:00:01', H), host('00:11:22:00:00:02', H2)]
        self.data['flows'] = [flow(T0 - 100, H, '203.0.113.200', 443, octets=900000)]
        result = self.run_at(T0)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(self.findings(), [])
        st = self.store()
        self.assertEqual(st.db.execute('SELECT count(*) FROM devices WHERE learned = 1').fetchone()[0], 2)
        st.close()

    def test_markers_never_count_twice(self):
        self.age_hosts([H])
        rnd = random.Random(1)
        for t in beacon_times(rnd, T0 - 6 * 3600, 300, 72):
            self.data['flows'].append(flow(t, H, '203.0.113.9', 443, octets=900))
        self.run_at(T0)
        self.run_at(T0 + 60)          # nothing new: same finding, no new occurrence
        f = self.findings('beaconing')
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['occurrences'], 1)
        st = self.store()
        times = json.loads(st.db.execute('SELECT times FROM pairs WHERE host = ?', (H,)).fetchone()[0])
        st.close()
        self.assertEqual(len(times), 72)

    def test_duplicate_interfaces_and_nat_copies_are_ignored(self):
        """ NetFlow sees a routed flow on every captured interface: only the LAN ingress copy counts """
        self.age_hosts([H])
        for i in range(30):
            t = T0 - 3600 + i * 60
            self.data['flows'].append(flow(t, H, '203.0.113.9', 443, octets=1000, sport=50000 + i))
            self.data['flows'].append(flow(t, H, '203.0.113.9', 443, octets=1000, sport=50000 + i,
                                           if_in='igc0', if_out='pppoe1'))            # same record twice
            self.data['flows'].append(flow(t, '10.99.0.2', '203.0.113.9', 443, octets=1000, if_in='wg0'))  # NAT
        self.run_at(T0)
        st = self.store()
        out = st.db.execute('SELECT sum(bytes_out), sum(flows) FROM host_hour WHERE host = ?', (H,)).fetchone()
        nat = st.db.execute("SELECT count(*) FROM host_hour WHERE host = '10.99.0.2'").fetchone()[0]
        st.close()
        self.assertEqual(out[0], 30000)
        self.assertEqual(nat, 0)

    def test_volume_baseline_then_spike(self):
        self.age_hosts([H], days=30)
        rnd = random.Random(2)
        start = int((T0 - 8 * 86400) // 3600 * 3600)
        # 8 days of ~30 MiB per hour, one run per hour
        for hour in range(8 * 24):
            ts = start + hour * 3600
            self.data['flows'].append(flow(ts + 100, H, '198.51.100.20', 443,
                                           octets=int(rnd.uniform(25, 35) * 1048576)))
            self.run_at(ts + 3700)
        self.assertEqual(self.findings('volume'), [])
        spike = start + 8 * 24 * 3600
        self.data['flows'].append(flow(spike + 100, H, '203.0.113.77', 443, octets=3 * 1024 * 1048576))
        self.run_at(spike + 3700)
        f = self.findings('volume')
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['severity'], 'high')
        self.assertEqual(f[0]['evidence']['top'][0][0], '203.0.113.77')
        detail = self.cli('finding', f[0]['id'])['finding']
        self.assertTrue(detail['series']['points'])
        self.assertTrue(any(a['id'] == 'quarantine' and a['target'] == '203.0.113.77' for a in detail['actions']))
        # the anomalous hour did not enter the baseline
        st = self.store()
        mean = st.db.execute('SELECT mean FROM vol_base WHERE host = ? AND slot = -1', (H,)).fetchone()[0]
        st.close()
        self.assertLess(mean, 50 * 1048576)

    def test_rare_destination_and_insight_seed(self):
        self.data['insight'] = [(H, '198.51.100.20', 1000, '2026-10-01 00:00:00', 1792000000),
                                (H2, '203.0.113.201', 500, '2026-10-01 00:00:00', 1792000000)]
        self.run_at(T0 - 3600)
        st = self.store()
        seeded = st.db.execute('SELECT count(*) FROM host_dest').fetchone()[0]
        st.close()
        self.assertEqual(seeded, 4)
        # H talks to KP: H2 already did (seed) -> not rare (1 other host = rare_max_hosts) ...
        self.data['flows'] = [flow(T0 - 100 + i, H, '203.0.113.210', 443, octets=200000) for i in range(5)]
        self.run_at(T0)
        self.assertEqual(self.findings('rare_destination'), [])

    def test_rare_destination_fires(self):
        self.data['insight'] = [(H, '198.51.100.20', 1000, '2026-09-01 00:00:00', 1792000000)]
        self.run_at(T0 - 3600)
        self.data['flows'] = [flow(T0 - 100 + i, H, '203.0.113.210', 443, octets=600000) for i in range(5)]
        self.run_at(T0)
        f = self.findings('rare_destination')
        self.assertEqual(len(f), 1)
        self.assertIn('KP', f[0]['detail'])

    def test_new_device_after_learning(self):
        self.data['hosts'] = [host('00:11:22:00:00:01', H)]
        self.run_at(T0 - 900)
        self.data['hosts'].append(host('00:11:22:00:00:09', LAN % 99, vendor=None, source='kea'))
        self.data['hosts'].append(host('00:11:22:00:00:0a', '198.51.100.7', iface='pppoe1'))     # WAN side
        self.run_at(T0)
        f = self.findings('new_device')
        self.assertEqual([x['key'] for x in f], ['00:11:22:00:00:09'])

    def test_dga_tunnel_bypass_scan(self):
        self.age_hosts([H])
        rnd = random.Random(3)
        self.data['dns'] = dga_dns(rnd, H, T0 - 1800) + tunnel_dns(rnd, H, T0 - 1200) + \
            [ahelpers.dns_row(T0 - 60, H, 'dns.google')]
        self.data['flows'] = [flow(T0 - 500 + i, H, '198.51.100.53', 853, octets=300) for i in range(3)]
        self.data['flows'] += [flow(T0 - 400 + i * 0.5, H, '192.168.2.%d' % (i + 2), 445, packets=1, flags=0x02,
                                    if_out='igc1') for i in range(60)]
        self.data['filter'] = [{'dir': 'in', 'src': H, 'dst': '192.168.2.9', 'action': 'block'}]
        self.run_at(T0)
        kinds = {f['type']: f for f in self.findings()}
        self.assertIn('dga', kinds)
        self.assertIn('dns_tunnel', kinds)
        self.assertEqual(kinds['dns_bypass']['severity'], 'medium')
        self.assertIn('dns.google', kinds['dns_bypass']['evidence']['doh_lookups'])
        self.assertEqual(kinds['internal_scan']['evidence']['blocked'], 1)

    def test_plain_dns_redirected_is_info(self):
        self.age_hosts([H])
        self.data['flows'] = [flow(T0 - 500 + i, H, '198.51.100.53', 53, proto=17) for i in range(5)]
        self.run_at(T0)
        f = self.findings('dns_bypass')[0]
        self.assertEqual(f['severity'], 'info')
        self.assertEqual(f['evidence']['redirect'], 'Redirect DNS')

    def test_new_domain_after_seed(self):
        self.data['dns_seed'] = [(H, 'www.google.com.', T0 - 6 * 86400, T0 - 3600, 50),
                                 (H2, 'shop.example-store.com.', T0 - 6 * 86400, T0 - 3600, 5)]
        self.run_at(T0 - 3600)
        self.age_hosts([H])
        self.data['dns'] = [ahelpers.dns_row(T0 - 300, H, 'www.google.com'),
                            ahelpers.dns_row(T0 - 290, H, 'shop.example-store.com'),        # H2 knows it
                            ahelpers.dns_row(T0 - 280, H, 'cdn.qwzkxvbt.top'),
                            ahelpers.dns_row(T0 - 270, H, 'a.brand-new-thing.com'),
                            ahelpers.dns_row(T0 - 260, H, 'login.another-new-site.net')]
        self.run_at(T0)
        f = self.findings('new_domain')
        self.assertEqual(len(f), 1)
        domains = [d['domain'] for d in f[0]['evidence']['domains']]
        self.assertEqual(sorted(domains), ['another-new-site.net', 'brand-new-thing.com', 'qwzkxvbt.top'])

    def test_tls(self):
        good = {'sni': 'www.example.com', 'subject': 'CN=www.example.com', 'issuerdn': 'CN=Good CA',
                'subjectaltname': ['www.example.com'], 'notafter_epoch': T0 + 9e6, 'notbefore_epoch': T0 - 9e6,
                'fingerprint': 'aa', 'ja4': 't13d1516h2_aaa_bbb', 'src': H, 'dst': '203.0.113.5', 'dport': 443}
        self.data['tls'] = [dict(good, ts=T0 - 7200)]
        self.run_at(T0 - 7000)                    # first run: learns the fingerprints and issuers
        self.age_hosts([H])
        bad = dict(good, ts=T0 - 60, subject='CN=evil', issuerdn='CN=evil', sni='update.example.com',
                   subjectaltname=[], notafter_epoch=T0 - 10, fingerprint='bb', ja4='t12i0000_ccc_ddd')
        self.data['tls'].append(bad)
        self.run_at(T0)
        f = {x['key'].split(':')[0]: x for x in self.findings('tls')}
        self.assertEqual(set(f), {'ja4', 'cert'})
        self.assertEqual(f['cert']['severity'], 'medium')

    def test_budget_and_busy(self):
        lock = __import__('anomalies.engine', fromlist=['Lock']).Lock(self.ctx.lock_file)
        lock.acquire()
        try:
            self.assertEqual(self.engine().run(now=T0)['status'], 'busy')
        finally:
            lock.release()

    def test_cost_of_a_busy_run(self):
        """ 40 hosts, ~60k flows and 20k DNS rows in one run must stay well inside the budget """
        rnd = random.Random(5)
        hosts = [LAN % (20 + i) for i in range(40)]
        self.age_hosts(hosts)
        for i in range(60000):
            self.data['flows'].append(flow(T0 - 900 + rnd.uniform(0, 899), rnd.choice(hosts),
                                           '198.51.100.%d' % rnd.randint(2, 250), rnd.choice([443, 80, 8443, 3478]),
                                           octets=rnd.randint(100, 90000), sport=rnd.randint(1024, 65000)))
        for hst in hosts[:20]:
            self.data['dns'] += ahelpers.benign_dns(rnd, hst, T0 - 3500, 58, rate_per_min=20)
        # Unbound history of the network (first run seed): the usual domains are known
        self.data['dns_seed'] = [(hosts[0], d, T0 - 6 * 86400, T0 - 7200, 10) for d in ahelpers.BENIGN_DOMAINS]
        result = self.run_at(T0)
        self.assertEqual(result['status'], 'ok')
        ahelpers_cost = {'flows': len(self.data['flows']), 'dns_rows': len(self.data['dns']),
                         'duration_ms': result['duration_ms'], 'cpu_ms': result['cpu_ms']}
        import sys
        sys.stderr.write('\ncost of a busy run on this machine: %s\n' % ahelpers_cost)
        self.assertLess(result['duration_ms'], 30000)
        self.assertEqual([f for f in self.findings() if f['type'] not in ('rare_destination',)], [])


class TestExceptionsAndActions(AnomalyCase):
    def beacon(self):
        self.age_hosts([H])
        rnd = random.Random(1)
        for t in beacon_times(rnd, T0 - 6 * 3600, 300, 72):
            self.data['flows'].append(flow(t, H, '203.0.113.9', 443, octets=900))
        self.run_at(T0)
        return self.findings('beaconing')[0]

    def test_expect_plan_apply_revert(self):
        f = self.beacon()
        comment = base64.b64encode('backup agent'.encode()).decode()
        plan = self.cli('plan', 'anomaly_expect', f['id'], 'finding', comment)
        self.assertEqual(plan['status'], 'ok')
        self.assertTrue(plan['requires_confirmation'])
        self.assertEqual(self.findings('beaconing')[0]['status'], 'open')     # plan changes nothing
        result = self.cli('apply', 'anomaly_expect', f['id'], 'finding', comment)
        self.assertTrue(result['done'])
        self.assertTrue(result['journal_id'])
        self.assertEqual(self.findings('beaconing')[0]['status'], 'expected')
        # a new occurrence later stays expected
        for t in beacon_times(random.Random(2), T0 + 7200, 300, 30):
            self.data['flows'].append(flow(t, H, '203.0.113.9', 443, octets=900))
        self.run_at(T0 + 7200 + 30 * 300)
        f2 = self.findings('beaconing')[0]
        self.assertEqual(f2['status'], 'expected')
        self.assertEqual(f2['occurrences'], 2)
        # revert through the journal
        revert = self.cli('apply', 'revert', result['journal_id'])
        self.assertEqual(revert['status'], 'ok')
        self.assertEqual(self.findings('beaconing')[0]['status'], 'open')
        st = self.store()
        self.assertEqual(st.exceptions(), [])
        st.close()

    def test_resolve_and_reopen(self):
        f = self.beacon()
        self.assertTrue(self.cli('apply', 'anomaly_resolve', f['id'])['done'])
        self.assertEqual(self.findings('beaconing')[0]['status'], 'resolved')
        for t in beacon_times(random.Random(2), T0 + 7200, 300, 30):
            self.data['flows'].append(flow(t, H, '203.0.113.9', 443, octets=900))
        self.run_at(T0 + 7200 + 30 * 300)
        self.assertEqual(self.findings('beaconing')[0]['status'], 'open')

    def test_settings_action(self):
        self.run_at(T0)
        plan = self.cli('plan', 'anomaly_settings', 'beacon_min_conn=20:vol_min_mb=500')
        self.assertEqual(len(plan['steps']), 2)
        result = self.cli('apply', 'anomaly_settings', 'beacon_min_conn=20')
        st = self.store()
        self.assertEqual(st.settings(), {'beacon_min_conn': '20'})
        st.close()
        self.cli('apply', 'revert', result['journal_id'])
        st = self.store()
        self.assertEqual(st.settings(), {})
        st.close()
        self.assertEqual(self.cli('plan', 'anomaly_settings', 'beacon_min_conn=2')['status'], 'error')
        self.assertEqual(self.cli('plan', 'anomaly_settings', 'rm -rf=1')['status'], 'error')

    def test_install_and_remove(self):
        plan = self.cli('plan', 'install_anomalies')
        self.assertEqual(len(plan['steps']), 3)
        result = self.cli('apply', 'install_anomalies')
        self.assertTrue(result['done'])
        self.assertTrue(os.path.exists(self.ctx.db))
        calls = [c for c in self.runner.calls if c[0].endswith('php')]
        self.assertEqual(calls[0][-1], 'cron_add')
        self.assertIn(['/usr/local/sbin/configctl', 'cron', 'restart'], self.runner.calls)
        self.write_config(True)                         # the core model wrote the job
        self.assertEqual(self.cli('plan', 'install_anomalies')['steps'], [])     # idempotent
        rplan = self.cli('plan', 'revert', result['journal_id'])
        self.assertEqual(len(rplan['steps']), 2)
        remove = self.cli('plan', 'remove_anomalies', 'purge_db=yes')
        self.assertTrue(remove['requires_double_confirmation'])
        self.assertTrue(remove['irreversible'])

    def test_only_anomaly_actions(self):
        self.assertEqual(self.cli('plan', 'quarantine_pause')['status'], 'error')
        self.assertEqual(self.cli('plan', 'prepare_storage', '/var/db/x')['status'], 'error')


class TestViewsAndAI(AnomalyCase):
    def setUp(self):
        super().setUp()
        self.age_hosts([H])
        rnd = random.Random(1)
        for t in beacon_times(rnd, T0 - 6 * 3600, 300, 72):
            self.data['flows'].append(flow(t, H, '203.0.113.9', 443, octets=900))
        self.data['dns'] = dga_dns(rnd, H, T0 - 1800)
        self.run_at(T0)

    def test_summary_list_host(self):
        s = self.cli('summary')
        self.assertEqual(set(s['by_type']), {'beaconing', 'dga', 'rare_destination'})   # NL is new for this host
        self.assertEqual(s['top_hosts'][0]['host'], H)
        lst = self.cli('list', 'status=open+severity=high', 'score:desc', '1:10')
        self.assertEqual([r['type'] for r in lst['rows']], ['beaconing'])
        self.assertEqual(self.cli('list', 'bad=1', '-', '1:10')['status'], 'error')
        prof = self.cli('host', H)
        self.assertEqual(prof['status'], 'ok')
        self.assertEqual(len(prof['findings']), 3)
        self.assertEqual(self.cli('host', 'not-an-ip')['status'], 'error')
        status = self.cli('status')
        self.assertTrue(status['settings'])
        self.assertIn('192.168.1.0/24', status['network']['internal'])

    def test_explain_preview_is_anonymized_and_sends_nothing(self):
        with open(self.ctx.config_xml) as handle:
            text = handle.read()
        text = text.replace('<OPNsense>', '<OPNsense><policyanalyzer><ai><enabled>1</enabled><provider>ollama'
                                          '</provider><anonymize>1</anonymize></ai></policyanalyzer>', 1)
        with open(self.ctx.config_xml, 'w') as handle:
            handle.write(text)
        fid = self.findings('beaconing')[0]['id']
        prev = self.cli('explain', 'finding', fid, 'pt_BR', 'preview')
        self.assertEqual(prev['status'], 'ok')
        body = '\n'.join(m['content'] for m in prev['messages'])
        self.assertNotIn(H, body)
        self.assertNotIn('203.0.113.9', body)
        self.assertIn('interval regularity', body)
        self.assertIn('Mark as expected', body)
        self.assertTrue(any(a['id'] == 'quarantine' for a in prev['actions']))
        hprev = self.cli('explain', 'host', H, 'en_US', 'preview')
        self.assertEqual(hprev['status'], 'ok')
        self.assertNotIn(H, '\n'.join(m['content'] for m in hprev['messages']))

    def test_explain_with_fake_provider(self):
        from anomalies import explain
        from ai import Assistant, AIConfig

        class Result:
            text = 'IP4_PRIV_1 beacons every 5 min.'
            model = 'fake'
            duration_ms = 5
            prompt_tokens = completion_tokens = 1
            usage = {}
            done_reason = 'stop'
            truncated = False

        class Provider:
            def endpoint(self):
                return 'fake://'

            def chat(self, messages, stream=False, on_chunk=None):
                self.messages = messages
                return Result()

        class Audit:
            def record(self, **kw):
                self.kw = kw

        config = AIConfig(enabled=True, provider='ollama', anonymize=True, options={'model': 'fake'})
        prov = Provider()
        assistant = Assistant(config, app='policyanalyzer', audit=Audit(), provider=prov)
        data = explain.compact_finding(self.cli('finding', self.findings('beaconing')[0]['id'])['finding'])
        result = explain.ask('finding', 'x', data, 'en_US', 'send', self.ctx.config_xml, assistant=assistant)
        self.assertEqual(result['status'], 'ok')
        self.assertIn(H, result['text'])               # placeholder restored locally


if __name__ == '__main__':
    unittest.main()
