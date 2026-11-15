"""
Detector unit tests: for every detector a case that must fire and cases that must not, plus the measured
false positive / detection rates on synthetic populations (printed with -v and kept in RATES).
"""

import random
import time
import unittest

from ahelpers import (LAN, T0, beacon_times, benign_dns, common, detectors, dga_dns, dnsfeat, netcfg,
                      poisson_times, random_label, tunnel_dns)
import ahelpers

S = dict(common.DEFAULTS)
CFG = None
RATES = {}


def cfg():
    global CFG
    if CFG is None:
        import tempfile
        import os
        tmp = tempfile.mkdtemp(prefix='pa-anom-cfg-')
        path = os.path.join(tmp, 'config.xml')
        with open(path, 'w') as handle:
            handle.write(ahelpers.CONFIG.replace('%CRON%', ''))
        CFG = netcfg.NetConfig(path)
    return CFG


def rate(name, hits, total):
    RATES[name] = (hits, total, round(100.0 * hits / total, 2) if total else 0.0)
    return hits / float(total) if total else 0.0


# ================================================================== (a) beaconing


class TestBeaconing(unittest.TestCase):
    def score(self, times, sizes=None, durs=None):
        sizes = sizes or [900] * len(times)
        durs = durs or [1.0] * len(times)
        return detectors.beaconing(LAN % 50, '203.0.113.9', 443, 6, times, sizes, durs, S, ts=times[-1])

    def test_regular_beacon_fires(self):
        rnd = random.Random(1)
        cand = self.score(beacon_times(rnd, T0, 300, 60, jitter=0.02))
        self.assertIsNotNone(cand)
        self.assertEqual(cand['severity'], 'high')
        names = {f['name']: f for f in cand['factors']}
        self.assertTrue(names['interval regularity']['met'])
        self.assertTrue(names['duration']['met'])

    def test_jittered_beacon_fires_medium_or_high(self):
        rnd = random.Random(2)
        times = beacon_times(rnd, T0, 600, 40, jitter=0.10)
        cand = self.score(times, [rnd.randint(850, 950) for _ in times])
        self.assertIsNotNone(cand)

    def test_browsing_does_not_fire(self):
        rnd = random.Random(3)
        times = poisson_times(rnd, T0, 300, 80)
        self.assertIsNone(self.score(times, [rnd.randint(500, 200000) for _ in times]))

    def test_short_burst_does_not_fire(self):
        rnd = random.Random(4)
        self.assertIsNone(self.score(beacon_times(rnd, T0, 30, 30)))     # 15 minutes only

    def test_streaming_is_not_a_beacon(self):
        rnd = random.Random(5)
        self.assertIsNone(self.score(beacon_times(rnd, T0, 2, 2000)))

    def test_too_few_connections(self):
        self.assertIsNone(self.score([T0 + i * 600 for i in range(8)]))

    def test_rates(self):
        rnd = random.Random(10)
        fp = sum(1 for _ in range(400) if self.score(poisson_times(rnd, T0, rnd.choice([30, 60, 300, 900]),
                                                                   rnd.randint(12, 300)),
                                                     None) is not None)
        # periodic but irregular sizes and big jitter (e.g. sync clients with backoff)
        fp2 = 0
        for _ in range(200):
            times = beacon_times(rnd, T0, rnd.choice([60, 300]), 60, jitter=0.6)
            if self.score(times, [rnd.randint(200, 900000) for _ in times]) is not None:
                fp2 += 1
        tp = 0
        for _ in range(400):
            interval = rnd.choice([60, 120, 300, 600, 1800])
            # at least the minimum span (2 h): shorter series are not beacons yet (test_short_burst)
            n = max(rnd.randint(30, 120), int(S['beacon_min_span_h'] * 3600 / interval) + 2)
            if self.score(beacon_times(rnd, T0, interval, n, jitter=rnd.uniform(0, 0.12))) is not None:
                tp += 1
        self.assertLessEqual(rate('beaconing FP (Poisson)', fp, 400), 0.01)
        self.assertLessEqual(rate('beaconing FP (60% jitter, variable size)', fp2, 200), 0.02)
        self.assertGreaterEqual(rate('beaconing detection (jitter <= 12%)', tp, 400), 0.95)


# ================================================================== (b) DGA / (c) tunnel / (i) new domain


class TestDNS(unittest.TestCase):
    def prep(self, rows):
        return detectors.dns_prepare(rows, cfg())

    def test_dga_fires(self):
        rnd = random.Random(1)
        h = self.prep(dga_dns(rnd, LAN % 9, T0) + benign_dns(rnd, LAN % 9, T0 - 3000, 50))[LAN % 9]
        cand = detectors.dga(LAN % 9, h, S)
        self.assertIsNotNone(cand)
        self.assertIn(cand['severity'], ('medium', 'high'))
        self.assertTrue(cand['evidence']['samples'])

    def test_search_suffix_and_blocklist_noise_is_not_dga(self):
        """ the real noise of the firewall: blocked ad names re-asked with the local domain appended """
        rows = []
        for i in range(400):
            dom = random.Random(i).choice(ahelpers.BENIGN_DOMAINS)
            rows.append(ahelpers.dns_row(T0 + i, LAN % 9, 'telemetry%d.%s' % (i, dom), rcode=3, action=1))
            rows.append(ahelpers.dns_row(T0 + i, LAN % 9, 'telemetry%d.%s.home.example' % (i, dom), rcode=3))
        h = self.prep(rows)[LAN % 9]
        self.assertEqual(len(h['nx_names']), 0)
        self.assertEqual(h['suffix_nx'], 400)
        self.assertIsNone(detectors.dga(LAN % 9, h, S))

    def test_typos_are_not_dga(self):
        rows = [ahelpers.dns_row(T0 + i, LAN % 9, 'www.%s' % d.replace('o', '0', 1), rcode=3)
                for i, d in enumerate(ahelpers.BENIGN_DOMAINS)]
        h = self.prep(rows)[LAN % 9]
        self.assertIsNone(detectors.dga(LAN % 9, h, S))

    def test_dga_rates(self):
        rnd = random.Random(7)
        fp = 0
        for i in range(300):
            client = LAN % (10 + i % 200)
            h = self.prep(benign_dns(rnd, client, T0, 60, rate_per_min=rnd.choice([2, 8, 30]), typo_nx=0.05))
            if client in h and detectors.dga(client, h[client], S):
                fp += 1
        tp = 0
        for i in range(200):
            client = LAN % 20
            rows = dga_dns(rnd, client, T0, n=rnd.randint(20, 80)) + benign_dns(rnd, client, T0, 60)
            if detectors.dga(client, self.prep(rows)[client], S):
                tp += 1
        self.assertLessEqual(rate('DGA FP (benign hours)', fp, 300), 0.01)
        self.assertGreaterEqual(rate('DGA detection (20-80 generated NX)', tp, 200), 0.9)

    def test_tunnel_fires(self):
        rnd = random.Random(2)
        h = self.prep(tunnel_dns(rnd, LAN % 9, T0))[LAN % 9]
        cands = detectors.dns_tunnel(LAN % 9, h, S)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]['key'], 'example-tunnel.net')
        self.assertEqual(cands[0]['severity'], 'high')

    def test_tunnel_a_records_fire(self):
        rnd = random.Random(3)
        h = self.prep(tunnel_dns(rnd, LAN % 9, T0, n=60, qtype='A'))[LAN % 9]
        self.assertEqual(len(detectors.dns_tunnel(LAN % 9, h, S)), 1)

    def test_cdn_and_reputation_lookups_are_not_tunnels(self):
        rnd = random.Random(4)
        rows = []
        for i in range(300):
            hexsub = ''.join(rnd.choice('0123456789abcdef') for _ in range(40))
            rows.append(ahelpers.dns_row(T0 + i, LAN % 9, '%s.sophosxl.net' % hexsub, 'TXT'))
            rows.append(ahelpers.dns_row(T0 + i, LAN % 9, 'e%d.dscx.akamaiedge.net' % i))
        h = self.prep(rows)[LAN % 9]
        self.assertEqual(detectors.dns_tunnel(LAN % 9, h, S), [])

    def test_many_short_subdomains_are_not_tunnels(self):
        rows = [ahelpers.dns_row(T0 + i, LAN % 9, 'shard%d.example-game.com' % i) for i in range(100)]
        self.assertEqual(detectors.dns_tunnel(LAN % 9, self.prep(rows)[LAN % 9], S), [])

    def test_tunnel_rates(self):
        rnd = random.Random(8)
        fp = sum(1 for i in range(300) if detectors.dns_tunnel(
            LAN % 9, self.prep(benign_dns(rnd, LAN % 9, T0, 60, rate_per_min=30)).get(LAN % 9), S))
        tp = sum(1 for i in range(100) if detectors.dns_tunnel(
            LAN % 9, self.prep(tunnel_dns(rnd, LAN % 9, T0, n=rnd.randint(40, 300),
                                          qtype=rnd.choice(['TXT', 'A', 'NULL'])))[LAN % 9], S))
        self.assertLessEqual(rate('DNS tunnel FP (benign hours, 30 q/min)', fp, 300), 0.0)
        self.assertGreaterEqual(rate('DNS tunnel detection', tp, 100), 0.95)

    def test_new_domain(self):
        regs = [{'domain': 'brand-new-shop.com', 'hosts': 0, 'label_score': 0.1},
                {'domain': 'qx7zkw9vt3.top', 'hosts': 0, 'label_score': 0.9},
                {'domain': 'x9a.cloudfront.net', 'hosts': 0, 'label_score': 0.9},
                {'domain': 'google.com', 'hosts': 12, 'label_score': 0.0}]
        cand = detectors.new_domain(LAN % 9, regs, S, 30 * 86400, ts=T0, min_new=2)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['severity'], 'low')
        self.assertEqual([d['domain'] for d in cand['evidence']['domains']], ['brand-new-shop.com', 'qx7zkw9vt3.top'])
        self.assertIsNone(detectors.new_domain(LAN % 9, regs, S, 2 * 86400, ts=T0))          # learning
        self.assertIsNone(detectors.new_domain(LAN % 9, regs[3:], S, 30 * 86400, ts=T0))      # others know it

    def test_name_score_separates(self):
        rnd = random.Random(9)
        real = ['google', 'mercadolivre', 'magazineluiza', 'steampowered', 'letsencrypt', 'crunchyroll',
                'samsungcloudsolution', 'windowsupdate', 'paramountplus', 'digitalocean', 'applovin', 'statsigapi']
        self.assertTrue(all(dnsfeat.name_score(w)[0] < S['dga_name_pct'] / 100.0 for w in real))
        hits = sum(1 for _ in range(500) if dnsfeat.name_score(random_label(rnd))[0] >= S['dga_name_pct'] / 100.0)
        rate('name score: random labels >= threshold (per name)', hits, 500)
        self.assertGreater(hits, 300)

    def test_registrable(self):
        self.assertEqual(dnsfeat.registrable('a.b.uol.com.br')[0], 'uol.com.br')
        self.assertEqual(dnsfeat.registrable('x.y.example.co.uk')[0], 'example.co.uk')
        self.assertEqual(dnsfeat.registrable('www.google.com')[:2], ('google.com', 'www'))


# ================================================================== (d) volume


class TestVolume(unittest.TestCase):
    MB = 1048576

    def base(self, values, alpha=0.15):
        b = None
        for v in values:
            b = detectors.ewma_update(b, v, alpha)
        return b

    def test_spike_fires(self):
        rnd = random.Random(1)
        slot = self.base([rnd.uniform(20, 40) * self.MB for _ in range(10)])
        cand = detectors.volume(LAN % 9, T0, 2048 * self.MB, 30 * self.MB, slot, slot, S)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['severity'], 'high')
        self.assertTrue(any(f['name'] == 'sent / received' and f['met'] for f in cand['factors']))

    def test_normal_heavy_host_does_not_fire(self):
        rnd = random.Random(2)
        slot = self.base([rnd.uniform(800, 1600) * self.MB for _ in range(10)])
        self.assertIsNone(detectors.volume(LAN % 9, T0, 1700 * self.MB, 500 * self.MB, slot, slot, S))

    def test_small_absolute_volume_never_fires(self):
        slot = self.base([1 * self.MB] * 10)
        self.assertIsNone(detectors.volume(LAN % 9, T0, 150 * self.MB, 1, slot, slot, S))

    def test_learning_does_not_fire(self):
        self.assertIsNone(detectors.volume(LAN % 9, T0, 5000 * self.MB, 1, self.base([1 * self.MB] * 2), None, S))

    def test_volume_rates(self):
        rnd = random.Random(3)
        fp = tp = 0
        for _ in range(300):
            mean = rnd.choice([5, 50, 300, 1500]) * self.MB
            hist = [max(0, rnd.gauss(mean, mean * 0.4)) for _ in range(14)]
            slot = self.base(hist)
            normal = max(0, rnd.gauss(mean, mean * 0.4))
            if detectors.volume(LAN % 9, T0, normal, normal, slot, slot, S):
                fp += 1
            exfil = max(mean * rnd.uniform(8, 30), 300 * self.MB)
            if detectors.volume(LAN % 9, T0, exfil, mean * 0.1, slot, slot, S):
                tp += 1
        self.assertLessEqual(rate('volume FP (normal hours, sd 40%)', fp, 300), 0.01)
        self.assertGreaterEqual(rate('volume detection (8-30x, >= 300 MiB)', tp, 300), 0.95)


# ================================================================== (e) rare / (f) device / (g) scan / (h) bypass


class TestOthers(unittest.TestCase):
    def test_rare_destination(self):
        items = [{'kind': 'country', 'value': 'KP', 'hosts': 0, 'bytes': 5 << 20, 'conns': 4, 'sample': '203.0.113.200'},
                 {'kind': 'asn', 'value': '64999', 'hosts': 0, 'bytes': 5 << 20, 'conns': 4, 'sample': '203.0.113.200'}]
        cand = detectors.rare_destination(LAN % 9, items, S, 30 * 86400, ts=T0)
        self.assertEqual(cand['severity'], 'medium')
        self.assertIsNone(detectors.rare_destination(LAN % 9, items, S, 3 * 86400))            # learning
        common_items = [dict(i, hosts=5) for i in items]
        self.assertIsNone(detectors.rare_destination(LAN % 9, common_items, S, 30 * 86400))     # others use it
        tiny = [dict(i, bytes=100, conns=1) for i in items]
        self.assertIsNone(detectors.rare_destination(LAN % 9, tiny, S, 30 * 86400))             # one packet

    def test_new_device(self):
        cand = detectors.new_device({'mac': '00:11:22:33:44:55', 'ip': LAN % 77, 'vendor': None, 'source': 'kea'}, S)
        self.assertEqual(cand['severity'], 'low')
        cand = detectors.new_device({'mac': 'da:11:22:33:44:55', 'ip': LAN % 78, 'vendor': None, 'source': 'kea'}, S)
        self.assertEqual(cand['severity'], 'info')
        self.assertTrue(detectors.is_random_mac('da:11:22:33:44:55'))

    def scan_events(self, hosts, ports, start=T0, step=1.0, failed=True):
        events, t = [], start
        for h in hosts:
            for p in ports:
                events.append((t, h, p, 6, failed))
                t += step
        return events

    def test_sweep_fires(self):
        cand = detectors.internal_scan(LAN % 9, self.scan_events([LAN % i for i in range(20, 80)], [445]), S)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['evidence']['max_hosts'], 60)

    def test_port_scan_fires(self):
        cand = detectors.internal_scan(LAN % 9, self.scan_events(['192.168.2.5'], range(1, 200), step=0.5), S)
        self.assertIsNotNone(cand)
        self.assertGreaterEqual(cand['evidence']['max_ports'], 50)

    def test_normal_internal_traffic_does_not_fire(self):
        rnd = random.Random(1)
        events = []
        for i in range(500):
            events.append((T0 + i * 3, rnd.choice(['192.168.2.5', '192.168.2.6', '192.168.1.1']),
                           rnd.choice([53, 443, 8123, 1883]), 6, False))
        self.assertIsNone(detectors.internal_scan(LAN % 9, events, S))

    def test_slow_sweep_below_window_does_not_fire(self):
        events = self.scan_events([LAN % i for i in range(20, 80)], [445], step=60)    # 1 per minute
        self.assertIsNone(detectors.internal_scan(LAN % 9, events, S))

    def test_scan_rates(self):
        rnd = random.Random(2)
        fp = 0
        for _ in range(200):
            peers = ['192.168.2.%d' % rnd.randint(2, 30) for _ in range(rnd.randint(1, 12))]
            events = sorted((T0 + rnd.uniform(0, 900), rnd.choice(peers), rnd.choice([80, 443, 53, 8009, 1900, 554]),
                             6, rnd.random() < 0.1) for _ in range(rnd.randint(10, 800)))
            if detectors.internal_scan(LAN % 9, events, S):
                fp += 1
        self.assertLessEqual(rate('internal scan FP (busy IoT host)', fp, 200), 0.0)

    def test_bypass(self):
        dot = {('198.51.100.53', 853, 'tcp'): {'flows': 3, 'bytes': 900, 'kind': 'dot'}}
        self.assertEqual(detectors.dns_bypass(LAN % 9, dot, S)['severity'], 'medium')
        plain = {('198.51.100.53', 53, 'udp'): {'flows': 30, 'bytes': 2000, 'kind': 'dns'}}
        self.assertEqual(detectors.dns_bypass(LAN % 9, plain, S)['severity'], 'medium')
        self.assertEqual(detectors.dns_bypass(LAN % 9, plain, S, redirect='Redirect DNS')['severity'], 'info')
        doh = {('1.1.1.1', 443, 'tcp'): {'flows': 3, 'bytes': 900, 'kind': 'doh'}}
        self.assertEqual(detectors.dns_bypass(LAN % 9, doh, S)['severity'], 'low')
        self.assertIsNone(detectors.dns_bypass(LAN % 9, doh, dict(S, bypass_doh=0)))
        self.assertIsNone(detectors.dns_bypass(LAN % 9, {}, S))
        self.assertEqual(detectors.dns_bypass(LAN % 9, {}, S, doh_lookups=['dns.google'])['severity'], 'info')


# ================================================================== (j) TLS


class TestTLS(unittest.TestCase):
    def tls(self, **kw):
        base = {'sni': 'www.example.com', 'subject': 'CN=www.example.com', 'issuerdn': 'C=US, O=Good CA, CN=R3',
                'subjectaltname': ['www.example.com', 'example.com'], 'notafter_epoch': T0 + 86400 * 60,
                'notbefore_epoch': T0 - 86400 * 30, 'fingerprint': 'aa:bb', 'ja4': 't13d1516h2_x_y'}
        base.update(kw)
        return base

    def test_good_certificate(self):
        issues = detectors.cert_issues(self.tls(), T0, 500)
        self.assertEqual(issues, [])
        self.assertIsNone(detectors.tls_certificate(LAN % 9, '203.0.113.5', self.tls(), issues))

    def test_wildcard_matches(self):
        self.assertEqual(detectors.cert_issues(self.tls(sni='a.example.com', subjectaltname=['*.example.com']),
                                               T0, 500), [])
        self.assertTrue(detectors.cert_issues(self.tls(sni='a.b.example.com', subjectaltname=['*.example.com'],
                                                       subject='CN=*.example.com'), T0, 500))

    def test_self_signed_expired(self):
        t = self.tls(subject='CN=router', issuerdn='CN=router', sni='10.0.0.1', subjectaltname=[],
                     notafter_epoch=T0 - 10)
        issues = detectors.cert_issues(t, T0, None)
        names = {i[0] for i in issues}
        self.assertTrue({'self signed', 'expired', 'SNI mismatch', 'rare issuer'} <= names)
        self.assertEqual(detectors.tls_certificate(LAN % 9, '203.0.113.5', t, issues)['severity'], 'medium')

    def test_rare_issuer_alone_is_context(self):
        issues = detectors.cert_issues(self.tls(), T0, None)
        self.assertEqual({i[0] for i in issues}, {'rare issuer'})
        self.assertIsNone(detectors.tls_certificate(LAN % 9, '203.0.113.5', self.tls(), issues))

    def test_tls13_has_no_certificate(self):
        self.assertEqual(detectors.cert_issues({'sni': 'x', 'ja4': 'a'}, T0, None), [])

    def test_new_ja4(self):
        self.assertEqual(detectors.new_ja4(LAN % 9, 't13d', 0, '', S, 30 * 86400)['severity'], 'low')
        self.assertEqual(detectors.new_ja4(LAN % 9, 't13d', 3, 'x', S, 30 * 86400)['severity'], 'info')
        self.assertIsNone(detectors.new_ja4(LAN % 9, 't13d', 0, '', S, 86400))


def tearDownModule():
    if RATES:
        lines = ['', 'measured rates on synthetic data (hits / cases):']
        for name, (hits, total, pct) in sorted(RATES.items()):
            lines.append('  %-55s %4d / %-4d = %6.2f%%' % (name, hits, total, pct))
        import sys
        sys.stderr.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    unittest.main()
