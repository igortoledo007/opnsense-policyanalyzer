"""
exposure_report: findings (types, severities, recommendations), summary / posture, storage, devices slot.
"""

import json
import os
import unittest

from exposure_helpers import (AUDIT_CLEAN, CLOSED_RULES, ExposureCase, FakeHTTP, FakeRunner, SOCKSTAT_LOCAL_ONLY,
                              by_type, service)

CONTRACT_KEYS = {'id', 'type', 'severity', 'title', 'detail', 'recommendation', 'rules', 'aliases', 'evidence'}


class TestReport(ExposureCase):
    def test_exposed_online(self):
        doc = self.report(online=True, tokens=['online', 'no-write'])
        self.assertEqual(doc['status'], 'ok')
        self.assertNotIn('stored', doc)
        for f in doc['findings']:
            self.assertEqual(set(f), CONTRACT_KEYS)
            self.assertIn(f['severity'], ('high', 'medium', 'low', 'info'))
        # ssh: reachable, KEV -> high, with the opening rule and suggested isolation
        exposed = {(f['evidence'].get('service'), f['evidence']['package']): f
                   for f in by_type(doc, 'exposed_vulnerable_service')}
        ssh = exposed[('ssh', 'openssh-portable')]
        self.assertEqual(ssh['severity'], 'high')
        self.assertEqual(ssh['rules'][0]['description'], 'wan ssh open')
        self.assertNotIn('level', ssh['rules'][0])
        self.assertIn('Update openssh-portable to 10.1.p1,1', ssh['recommendation'])
        self.assertIn('quick block rule', ssh['recommendation'])
        # sqlite3 reaches the web GUI through php85-sqlite3 (dependency), GUI maybe reachable -> medium
        gui_sqlite = exposed[('webgui', 'sqlite3')]
        self.assertEqual((gui_sqlite['severity'], gui_sqlite['evidence']['link']), ('medium', 'dependency'))
        self.assertEqual(sorted(gui_sqlite['evidence']['ports']), [80, 8443])      # one finding for the GUI
        self.assertEqual(gui_sqlite['evidence']['internet_reachable'], 'maybe')
        self.assertIn('repository does not offer it yet', gui_sqlite['recommendation'])
        # python313: vulnerable, unbound depends on it but interpreters are not linked -> low, not exposed
        py = exposed[(None, 'python313')]
        self.assertEqual((py['severity'], py['evidence']['internet_reachable']), ('low', 'no'))
        self.assertIn('No fixed version', py['recommendation'])
        kev = by_type(doc, 'known_exploited_vuln')
        self.assertEqual([(k['severity'], k['evidence']['cve']) for k in kev], [('high', 'CVE-2026-0001')])
        self.assertEqual(len(kev[0]['evidence']['reachable_services']), 1)
        admin = {f['evidence']['service']: f for f in by_type(doc, 'admin_exposed_to_internet')}
        self.assertEqual(admin['ssh']['severity'], 'high')
        self.assertEqual(admin['ssh']['evidence']['suggested_rule'][0]['destination'], '(self)')
        self.assertEqual(admin['webgui']['severity'], 'medium')             # maybe, GeoIP source = restricted
        self.assertNotIn('unbound-control', admin)                           # loopback only
        alls = {f['evidence']['service'] for f in by_type(doc, 'service_listening_all_interfaces')}
        self.assertEqual(alls, {'ssh', 'webgui', 'wireguard'})
        review = by_type(doc, 'needs_review')
        self.assertIn('unknown process "mystery"', [f['evidence']['reason'] for f in review])
        outdated = {f['evidence']['package']: f['severity'] for f in by_type(doc, 'outdated_component')}
        self.assertEqual(outdated, {'openssh-portable': 'low', 'beep': 'info'})
        # OPNsense advisory affecting 26.7.5 links to the web GUI directly
        core = exposed[('webgui', 'opnsense')]
        self.assertEqual(core['evidence']['cves'], ['GHSA-aaaa-bbbb-cccc'])
        s = doc['summary']
        self.assertEqual(s['posture'], 'critical')
        self.assertEqual((s['reachable'], s['maybe_reachable'], s['admin_reachable']), (2, 1, 2))
        self.assertEqual((s['cves_total'], s['kev']), (5, 1))
        self.assertEqual(sum(s['by_severity'].values()), len(doc['findings']))
        self.assertEqual({a['service'] for a in s['attack_surface']}, {'ssh', 'wireguard', 'webgui'})
        self.assertEqual(doc['devices'], {'status': 'not_collected', 'items': [], 'source': None})
        self.assertEqual(service(doc, 'ssh', 22)['kev'], 1)
        self.assertNotIn('sockets', doc['inventory'])
        # the findings are sorted by severity
        order = [{'high': 0, 'medium': 1, 'low': 2, 'info': 3}[f['severity']] for f in doc['findings']]
        self.assertEqual(order, sorted(order))
        json.dumps(doc)

    def test_ids_are_stable(self):
        a = self.report()
        b = self.report()
        self.assertEqual([f['id'] for f in a['findings']], [f['id'] for f in b['findings']])

    def test_hardened(self):
        doc = self.report(runner=FakeRunner(sockstat=SOCKSTAT_LOCAL_ONLY, audit=AUDIT_CLEAN, pkg_version=''),
                          config=self.write_config(rules=CLOSED_RULES, aliases=[]))
        self.assertEqual(doc['summary']['posture'], 'hardened')
        self.assertEqual(doc['summary']['by_severity']['high'], 0)
        self.assertEqual(doc['summary']['by_severity']['medium'], 0)
        self.assertEqual(doc['summary']['cves_total'], 0)
        self.assertEqual(by_type(doc, 'admin_exposed_to_internet'), [])

    def test_offline_not_reachable_is_low(self):
        doc = self.report(config=self.write_config(rules=CLOSED_RULES, aliases=[]))
        sev = {f['evidence']['package']: f['severity'] for f in by_type(doc, 'exposed_vulnerable_service')}
        self.assertEqual(set(sev.values()), {'low'})
        self.assertEqual(by_type(doc, 'known_exploited_vuln'), [])            # offline: no KEV data
        self.assertEqual(doc['summary']['posture'], 'hardened')

    def test_partial_inventory(self):
        doc = self.report(runner=FakeRunner(privileged=False))
        reasons = [f['evidence']['reason'] for f in by_type(doc, 'needs_review')]
        self.assertIn('not root', reasons)
        self.assertFalse(doc['summary']['services_complete'])
        self.assertEqual(doc['summary']['posture_confidence'], 'partial')

    def test_stale_and_missing_database(self):
        with open(os.path.join(self.tmp, 'vuln.xml'), 'w') as handle:
            handle.write('<vuxml/>')
        old = 1700000000
        os.utime(os.path.join(self.tmp, 'vuln.xml'), (old, old))
        doc = self.report()
        self.assertIn('stale database', [f['evidence']['reason'] for f in by_type(doc, 'needs_review')])
        doc = self.report(runner=FakeRunner(audit=None))
        self.assertIn('pkg audit failed', [f['evidence']['reason'] for f in by_type(doc, 'needs_review')])

    def test_write(self):
        out = os.path.join(self.tmp, 'db', 'exposure.json')
        doc = self.report(tokens=[], output=out)
        self.assertEqual(doc['stored'], out)
        with open(out) as handle:
            self.assertEqual(json.load(handle)['summary'], doc['summary'])
        self.assertEqual(oct(os.stat(out).st_mode & 0o777), '0o640')

    def test_no_write_keeps_cache_untouched(self):
        http = FakeHTTP()
        self.report(online=True, http=http, tokens=['online', 'no-write'])
        self.assertTrue(http.requests)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'db', 'exposure.json')))


if __name__ == '__main__':
    unittest.main()
