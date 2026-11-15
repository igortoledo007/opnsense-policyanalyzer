"""
pkg audit parsing (JSON and text), merge with provenance and deduplication, pkg version, Suricata references.
"""

import json
import os
import unittest

from exposure_helpers import (AUDIT_CLEAN, AUDIT_TEXT, AUDIT_VULN, ExposureCase, FakeHTTP, FakeRunner, adapter,
                              vulns)


class TestAudit(ExposureCase):
    def test_json(self):
        pkgs, meta = vulns.audit(FakeRunner())
        self.assertEqual(meta['format'], 'json')
        by = {p['name']: p for p in pkgs}
        self.assertEqual(by['sqlite3']['fixed_in'], ['3.53.5,1'])
        self.assertTrue(by['sqlite3']['fix_available'])
        self.assertEqual(by['python313']['fixed_in'], [])             # ">= 0": no fixed version yet
        self.assertFalse(by['python313']['fix_available'])
        self.assertEqual(by['python313']['advisories'][0]['vid'], '6d3488ae-2e0f-11f1-88c7-00a098b42aeb')
        self.assertIn('php85-sqlite3', by['sqlite3']['reverse_deps'])

    def test_clean(self):
        pkgs, meta = vulns.audit(FakeRunner(audit=AUDIT_CLEAN))
        self.assertEqual(pkgs, [])
        self.assertIsNone(meta['error'])

    def test_text_fallback(self):
        pkgs, meta = vulns.audit(FakeRunner(audit=None, audit_text=AUDIT_TEXT))
        self.assertEqual(meta['format'], 'text')
        by = {p['name']: p for p in pkgs}
        self.assertEqual(by['sqlite3']['version'], '3.53.4,1')
        self.assertEqual(by['sqlite3']['advisories'][0]['cves'], ['CVE-2026-0002', 'CVE-2026-0003'])
        self.assertIsNone(by['sqlite3']['fix_available'])

    def test_missing_database(self):
        pkgs, meta = vulns.audit(FakeRunner(audit=None))
        self.assertIsNone(pkgs)
        self.assertIn('vuln.xml', meta['error'])

    def test_refresh_only_with_flag(self):
        runner = FakeRunner()
        vulns.audit(runner)
        self.assertFalse(any('-F' in c for c in runner.calls))
        vulns.audit(runner, refresh=True)
        self.assertTrue(any('-F' in c for c in runner.calls))

    def test_outdated(self):
        items, reason = vulns.outdated(FakeRunner())
        self.assertIsNone(reason)
        self.assertEqual(items[0], {'name': 'openssh-portable', 'version': '10.0.p1,1', 'available': '10.1.p1,1'})


class TestCollect(ExposureCase):
    def collect(self, online=True, runner=None, http=None):
        return adapter.probe_vulns(['online'] if online else [], runner=runner or FakeRunner(),
                                   config_path=self.write_config(), fetcher=self.fetcher(http, online=online))

    def test_offline_local_only(self):
        http = FakeHTTP()
        res = self.collect(online=False, http=http)
        self.assertEqual(http.requests, [])
        self.assertFalse(res['online'])
        self.assertEqual(res['cves_total'], 4)
        sqlite = [p for p in res['packages'] if p['name'] == 'sqlite3'][0]
        rec = sqlite['cves'][0]
        self.assertEqual(rec['sources'], ['vuxml'])
        self.assertEqual(rec['provenance'], {'summary': 'vuxml'})
        self.assertIsNone(rec['cvss'])
        self.assertFalse(any(p['name'] == 'opnsense' for p in res['packages']))

    def test_online_merge(self):
        res = self.collect()
        by = {p['name']: p for p in res['packages']}
        ssh = by['openssh-portable']['cves'][0]
        self.assertTrue(ssh['kev'])
        self.assertEqual(ssh['cvss'], 9.8)
        self.assertEqual(ssh['provenance']['cvss'], 'nvd')                 # NVD wins over OSV
        self.assertEqual(ssh['provenance']['kev'], 'cisa_kev')
        self.assertEqual(ssh['provenance']['epss'], 'first_epss')
        self.assertEqual(ssh['summary'], 'NVD description of CVE-2026-0001')
        self.assertEqual(ssh['refs'][0], 'https://vuxml.FreeBSD.org/freebsd/11111111-2222-3333-4444-555555555555.html')
        self.assertEqual(ssh['sources'], ['vuxml', 'cisa_kev', 'first_epss', 'nvd', 'osv'])
        self.assertEqual(ssh['cwe'], ['CWE-787'])
        self.assertEqual(res['kev_total'], 1)
        # OPNsense advisories that affect 26.7.5 become an "opnsense" entry (GHSA id when there is no CVE)
        core = by['opnsense']
        self.assertEqual(core['source'], 'opnsense_ghsa')
        self.assertEqual([c['id'] for c in core['cves']], ['GHSA-aaaa-bbbb-cccc'])
        self.assertEqual(core['cves'][0]['cvss'], 7.2)
        self.assertEqual(core['cves'][0]['provenance']['cvss'], 'opnsense_ghsa')
        self.assertEqual(res['cves_total'], 5)

    def test_osv_when_nvd_disabled(self):
        path = os.path.join(self.tmp, 'db')
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, 'feeds.json'), 'w') as handle:
            json.dump({'feeds': [{'id': 'nvd', 'enabled': False}]}, handle)
        res = self.collect()
        rec = [p for p in res['packages'] if p['name'] == 'sqlite3'][0]['cves'][0]
        self.assertEqual((rec['cvss'], rec['provenance']['cvss']), (6.1, 'osv'))
        self.assertEqual(rec['provenance']['summary'], 'osv')

    def test_duplicate_cve_across_packages(self):
        audit = json.loads(json.dumps(AUDIT_VULN))
        audit['packages']['python311'] = dict(audit['packages']['python313'], version='3.11.15')
        res = self.collect(online=False, runner=FakeRunner(audit=audit))
        self.assertEqual(res['cves_total'], 4)                              # counted once


class TestSuricata(ExposureCase):
    def test_rule_references(self):
        rules = os.path.join(self.tmp, 'rules')
        os.makedirs(rules)
        with open(os.path.join(rules, 'emerging-exploit.rules'), 'w') as handle:
            handle.write('alert tcp any any -> $HOME_NET 22 (msg:"ET EXPLOIT sshd"; '
                         'reference:cve,2026-0001; sid:2059001; rev:1;)\n'
                         '# alert tcp any any -> any any (msg:"old"; reference:cve,CVE-2026-0001; sid:2059002;)\n'
                         'alert tcp any any -> any any (msg:"other"; reference:cve,2019-0001; sid:1;)\n')
        found = vulns.suricata_rules(['CVE-2026-0001', 'CVE-2026-0002'], rules)
        self.assertEqual([(x['sid'], x['enabled']) for x in found['CVE-2026-0001']], [(2059001, True),
                                                                                       (2059002, False)])
        self.assertNotIn('CVE-2026-0002', found)
        self.assertEqual(vulns.suricata_rules([], rules), {})
        self.assertEqual(vulns.suricata_rules(['CVE-2026-0001'], os.path.join(self.tmp, 'none')), {})


if __name__ == '__main__':
    unittest.main()
