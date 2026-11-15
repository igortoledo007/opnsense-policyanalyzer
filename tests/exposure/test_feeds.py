"""
feed registry, enrichment (KEV / EPSS / NVD / OSV / OPNsense advisories), cache, offline mode, privacy.
"""

import json
import os
import re
import unittest

from exposure_helpers import ExposureCase, FakeHTTP, GHSA_DOC, feeds

from exposure import cvss

CVES = ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2025-15367']


class TestRegistry(ExposureCase):
    def test_defaults(self):
        ids = [f['id'] for f in self.feed_list()]
        self.assertEqual(ids, ['cisa_kev', 'first_epss', 'nvd', 'osv', 'opnsense_ghsa'])

    def test_file_and_config_override(self):
        path = os.path.join(self.tmp, 'feeds.json')
        with open(path, 'w') as handle:
            json.dump({'feeds': [{'id': 'nvd', 'enabled': False},
                                 {'id': 'mirror_kev', 'name': 'KEV mirror', 'type': 'kev',
                                  'url': 'https://mirror.example.org/kev.json', 'ttl': 10}]}, handle)
        config = self.write_config(feeds_xml='<feed><id>osv</id><enabled>0</enabled></feed>'
                                             '<feed><id>osv_mirror</id><type>osv</type>'
                                             '<url>https://osv.example.org/v1/vulns/{cve}</url></feed>')
        items, errors = feeds.registry(config, path)
        self.assertEqual(errors, [])
        by_id = {f['id']: f for f in items}
        self.assertFalse(by_id['nvd']['enabled'])
        self.assertEqual(by_id['nvd']['origin'], 'file')
        self.assertFalse(by_id['osv']['enabled'])
        self.assertEqual(by_id['osv_mirror']['mode'], 'per_cve')
        self.assertEqual(by_id['mirror_kev']['ttl'], feeds.TTL_MIN)       # clamped

    def test_invalid_feeds(self):
        for bad in ({'id': 'x1', 'type': 'kev', 'url': 'http://insecure.example.org/kev.json'},
                    {'id': 'x2', 'type': 'nvd', 'url': 'https://nvd.example.org/?id={cve}&host={hostname}'},
                    {'id': 'x3', 'type': 'osv', 'url': 'https://osv.example.org/fixed'},
                    {'id': 'x4', 'type': 'shell', 'url': 'https://example.org/'},
                    {'id': 'Bad Id', 'type': 'kev', 'url': 'https://example.org/'}):
            with self.assertRaises(ValueError):
                feeds.validate(bad)


class TestEnrich(ExposureCase):
    def test_online_merge_and_privacy(self):
        http = FakeHTTP()
        res = feeds.enrich(CVES, self.feed_list(), self.fetcher(http), opnsense_version='26.7.5')
        kev = res['by_feed']['cisa_kev']
        self.assertEqual(list(kev), ['CVE-2026-0001'])                 # only the CVEs asked for
        self.assertTrue(kev['CVE-2026-0001']['kev_ransomware'])
        self.assertEqual(len(res['by_feed']['first_epss']), 3)
        self.assertEqual(res['by_feed']['nvd']['CVE-2026-0002']['cvss'], 9.8)
        self.assertEqual(res['by_feed']['osv']['CVE-2026-0002']['cvss'], 6.1)   # computed from the vector
        # one EPSS batch request, one NVD and OSV request per CVE, two bulk downloads
        self.assertEqual(len(http.requests), 2 + 1 + 3 + 3)
        cve_re = re.compile(r'CVE-\d{4}-\d+')
        for url in http.requests:
            fixed = [f['url'] for f in self.feed_list() if f['mode'] == 'bulk']
            if url in fixed:
                continue
            # nothing but CVE ids is ever sent
            rest = cve_re.sub('', url)
            self.assertIn(rest, ('https://api.first.org/data/v1/epss?cve=,,',
                                 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=',
                                 'https://api.osv.dev/v1/vulns/'))
        self.assertEqual(self.sleeps, [6.5, 6.5])                          # NVD public rate limit
        adv = {a['id']: a['affected'] for a in res['advisories']}
        self.assertEqual(adv, {'GHSA-aaaa-bbbb-cccc': True, 'GHSA-dddd-eeee-ffff': False})
        states = {s['id']: s['state'] for s in res['status']}
        self.assertEqual(set(states.values()), {'ok'})

    def test_cache_ttl_and_offline(self):
        now = [1000000.0]
        http = FakeHTTP()
        feed_list = self.feed_list()
        feeds.enrich(CVES, feed_list, self.fetcher(http, clock=lambda: now[0]))
        first = len(http.requests)
        feeds.enrich(CVES, feed_list, self.fetcher(http, clock=lambda: now[0] + 3600))
        self.assertEqual(len(http.requests), first)                        # all fresh in the cache
        now[0] += 2 * 86400
        offline = feeds.enrich(CVES, feed_list, self.fetcher(http, online=False, clock=lambda: now[0]))
        self.assertEqual(len(http.requests), first)                        # offline: never the network
        self.assertIn('CVE-2026-0001', offline['by_feed']['cisa_kev'])     # stale cache is used
        self.assertTrue(all(s['state'] == 'offline_cache' for s in offline['status']))
        self.assertTrue(all(s['stale'] > 0 for s in offline['status']))
        feeds.enrich(CVES, feed_list, self.fetcher(http, clock=lambda: now[0]))
        self.assertEqual(len(http.requests), 2 * first)                    # expired: fetched again

    def test_offline_without_cache(self):
        http = FakeHTTP()
        res = feeds.enrich(CVES, self.feed_list(), self.fetcher(http, online=False))
        self.assertEqual(http.requests, [])
        self.assertEqual(res['by_feed']['nvd'], {})
        nvd = [s for s in res['status'] if s['id'] == 'nvd'][0]
        self.assertEqual((nvd['state'], nvd['deferred']), ('offline', 3))

    def test_no_cache_writes(self):
        feeds.enrich(CVES, self.feed_list(), self.fetcher(FakeHTTP(), write_cache=False))
        self.assertFalse(os.path.exists(self.cache))

    def test_errors_not_found_and_limits(self):
        feed_list = self.feed_list()
        for f in feed_list:
            if f['id'] == 'osv':
                f['max_requests'] = 1
        http = FakeHTTP(fail=['services.nvd.nist.gov'], not_found=['api.osv.dev'])
        res = feeds.enrich(CVES, feed_list, self.fetcher(http))
        status = {s['id']: s for s in res['status']}
        self.assertEqual(status['nvd']['state'], 'error')
        self.assertEqual(len(status['nvd']['errors']), 3)
        self.assertEqual(status['osv']['deferred'], 2)
        self.assertEqual(status['osv']['requests'], 1)
        # the 404 is cached as "nothing known": no new request on the next run
        before = len(http.requests)
        feeds.enrich(sorted(CVES)[:1], [f for f in feed_list if f['id'] == 'osv'], self.fetcher(http))
        self.assertEqual(len(http.requests), before)

    def test_disabled_feed(self):
        feed_list = [dict(f, enabled=False) for f in self.feed_list()]
        http = FakeHTTP()
        res = feeds.enrich(CVES, feed_list, self.fetcher(http))
        self.assertEqual(http.requests, [])
        self.assertTrue(all(s['state'] == 'disabled' for s in res['status']))


class TestParsers(unittest.TestCase):
    def test_cvss(self):
        self.assertEqual(cvss.v3_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8)
        self.assertEqual(cvss.v3_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1)
        self.assertEqual(cvss.v3_base_score('CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'), 0.0)
        self.assertIsNone(cvss.v3_base_score('CVSS:4.0/AV:N/AC:L/AT:N'))
        self.assertEqual(cvss.severity(9.0), 'critical')
        self.assertEqual(cvss.severity(6.9), 'medium')

    def test_osv_v4_only(self):
        doc = {'id': 'CVE-2025-15367', 'summary': 's',
               'severity': [{'type': 'CVSS_V4', 'score': 'CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:N/VC:L/VI:H/VA:N'}]}
        rec = feeds.parse_osv(doc)['CVE-2025-15367']
        self.assertNotIn('cvss', rec)
        self.assertEqual(rec['cvss_version'], '4.0')

    def test_opnsense_version_ranges(self):
        adv = feeds.parse_ghsa_opnsense(GHSA_DOC)[0]
        self.assertTrue(feeds.opnsense_affected(adv, '26.7.5'))
        self.assertTrue(feeds.opnsense_affected(adv, '26.7.7_1'))
        self.assertFalse(feeds.opnsense_affected(adv, '26.7.8'))
        self.assertFalse(feeds.opnsense_affected(adv, '26.7.8_2'))
        self.assertTrue(feeds.opnsense_affected(adv, '26.4.2p4'))
        self.assertFalse(feeds.opnsense_affected(adv, '26.10'))
        odd = {'ranges': [('OPNsense 26.7.1_1', '')]}
        self.assertTrue(feeds.opnsense_affected(odd, '26.7.1_1'))
        self.assertIsNone(feeds.opnsense_affected({'ranges': [('all versions', '')]}, '26.7.5'))
        self.assertFalse(feeds.opnsense_affected({'ranges': [('<= 26.1.2', '26.1.3')]}, '26.7.5'))  # older series
        self.assertIsNone(feeds.opnsense_affected({'ranges': [('<= 27.1.1', '27.1.2')]}, '26.7.5'))  # newer only
        self.assertIsNone(feeds.opnsense_affected(adv, None))


if __name__ == '__main__':
    unittest.main()
