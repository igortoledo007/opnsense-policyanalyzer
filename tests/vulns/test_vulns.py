"""
Vulnerability prioritisation: P1..P4 with KEV/EPSS, the review queue and its decisions (plan/apply/revert),
the KEV/EPSS update action (fake HTTP), Explain CVE and the mapping suggestion (fake AI provider).
Run: cd tests/vulns && TMPDIR=<scratch> /usr/bin/python3 -m unittest discover -s . -v
"""

import base64
import io
import json
import os
import unittest
from contextlib import redirect_stdout

import vhelpers
from vhelpers import KEV, VulnsCase

from vulns import actions, cli, common, explain, intel, prioritize, review  # noqa: E402
from ai import changes  # noqa: E402


def by_cve(result):
    return {i['cve']: i for i in result['items']}


class PriorityTest(VulnsCase):
    def test_priorities_with_kev(self):
        self.write('vulns/kev.json', KEV)
        items = by_cve(prioritize.build())
        self.assertEqual(items['CVE-2099-1000']['priority'], 'P1')          # internet + KEV
        self.assertEqual(items['CVE-2099-1000']['rule'], 'exposed and in KEV')
        self.assertEqual(items['CVE-2099-2000']['priority'], 'P2')          # internet + CVSS 7.5 (openssl in openvpn)
        self.assertEqual(items['CVE-2099-3000']['priority'], 'P3')          # LAN only + CVSS 8.1
        self.assertEqual(items['CVE-2099-4000']['priority'], 'P4')          # python313: no network path known
        self.assertEqual(items['CVE-2099-5000']['priority'], 'P4')          # sqlite3 library
        self.assertEqual(items['CVE-2099-6000']['priority'], 'P1')          # "maybe" reachable + EPSS 0.62
        self.assertIn('not conclusive', items['CVE-2099-6000']['factors'][0]['text'])
        self.assertEqual(items['CVE-2099-1000']['suricata'][0]['sid'], 2099001)
        self.assertTrue(items['CVE-2099-1000']['explanation'].startswith('P1 (critical)'))

    def test_without_kev_cache(self):
        items = by_cve(prioritize.build())
        self.assertEqual(items['CVE-2099-1000']['priority'], 'P3')          # exposed, no high score
        self.assertIsNone(items['CVE-2099-1000']['kev'])

    def test_score_rules(self):
        t = common.DEFAULT_THRESHOLDS
        self.assertEqual(prioritize.score('none', True, None, None, t)[0], 'P2')      # KEV, not exposed
        self.assertEqual(prioritize.score('lan', False, 0.15, None, t)[0], 'P3')      # EPSS medium
        self.assertEqual(prioritize.score('internet', False, 0.5, 2.0, t)[0], 'P1')   # EPSS high, exposed
        self.assertEqual(prioritize.score('none', False, 0.01, 9.8, t)[0], 'P4')      # library, no signal

    def test_thresholds_file(self):
        self.write('vulns-settings.json', {'epss_high': 0.7})
        items = by_cve(prioritize.build())
        self.assertEqual(items['CVE-2099-6000']['priority'], 'P3')           # 0.62 < 0.7 but >= 0.1

    def test_summary_and_cli(self):
        self.write('vulns/kev.json', KEV)
        s = prioritize.summary()
        self.assertEqual(s['counts'], {'P1': 2, 'P2': 1, 'P3': 1, 'P4': 2})
        self.assertEqual(s['top'][0]['cve'], 'CVE-2099-1000')
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(['summary'])
        self.assertEqual(json.loads(out.getvalue())['total'], 6)
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(['cve', 'bad'])
        self.assertEqual(json.loads(out.getvalue())['status'], 'error')

    def test_no_exposure(self):
        os.unlink(os.path.join(self.tmp, 'exposure.json'))
        self.assertEqual(prioritize.build()['status'], 'none')


class ReviewTest(VulnsCase):
    def queue(self):
        return {q['kind']: q for q in prioritize.build()['review']}

    def test_queue_items(self):
        q = self.queue()
        self.assertIn('package_unmapped', q)
        self.assertEqual(q['package_unmapped']['package'], 'python313')
        self.assertEqual([c['service'] for c in q['package_unmapped']['candidates']], ['kea'])
        self.assertIn('service_unknown', q)
        self.assertEqual(q['package_unmapped']['status'], 'pending')

    def test_decide_plan_apply_revert(self):
        item = self.queue()['package_unmapped']
        comment = base64.urlsafe_b64encode('kea hooks não usam python'.encode()).decode().rstrip('=')
        plan = changes.run('plan', 'vulns_review_decide', [item['id'], 'map:aaaa000000000003', comment])
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertEqual(plan['changes'], [{'cve': 'CVE-2099-4000', 'before': 'P4', 'after': 'P3'}])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'vulns-review.json')))      # plan changes nothing
        result = changes.run('apply', 'vulns_review_decide', [item['id'], 'map:aaaa000000000003', comment])
        self.assertTrue(result['done'], result)
        items = by_cve(prioritize.build())
        self.assertEqual(items['CVE-2099-4000']['priority'], 'P3')
        self.assertTrue(items['CVE-2099-4000']['exposure']['mapped_by_owner'])
        self.assertEqual(self.queue()['package_unmapped']['decision']['comment'], 'kea hooks não usam python')
        rev = changes.run('apply', 'revert', [result['journal_id']])
        self.assertTrue(rev.get('done'), rev)
        self.assertEqual(by_cve(prioritize.build())['CVE-2099-4000']['priority'], 'P4')
        self.assertEqual(self.queue()['package_unmapped']['status'], 'pending')

    def test_invalid_decisions(self):
        item = self.queue()['package_unmapped']
        self.assertEqual(changes.run('plan', 'vulns_review_decide', [item['id'], 'map:aaaa000000000001', '-'])
                         ['status'], 'error')                                  # not a candidate
        self.assertEqual(changes.run('plan', 'vulns_review_decide', [item['id'], 'ignore=999', '-'])['status'],
                         'error')
        self.assertEqual(changes.run('plan', 'vulns_review_decide', ['zz', 'none', '-'])['status'], 'error')

    def test_ignore_expires(self):
        item = self.queue()['service_unknown']
        changes.run('apply', 'vulns_review_decide', [item['id'], 'ignore=1', '-'])
        self.assertEqual(self.queue()['service_unknown']['status'], 'decided')
        later = common.now() + 2 * 86400
        queue = {q['kind']: q for q in prioritize.build(now=later)['review']}
        self.assertEqual(queue['service_unknown']['status'], 'pending')
        self.assertIsNotNone(queue['service_unknown']['decision_expired'])


class IntelTest(VulnsCase):
    def fake_get(self, url, timeout=None):
        self.urls.append(url)
        if 'known_exploited' in url:
            return {'catalogVersion': '2099.1', 'dateReleased': '2099-01-01', 'vulnerabilities': [
                {'cveID': 'CVE-2099-3000', 'vendorProject': 'NLnet Labs', 'product': 'Unbound',
                 'vulnerabilityName': 'x', 'dateAdded': '2099-01-01', 'requiredAction': 'update',
                 'knownRansomwareCampaignUse': 'Unknown'}]}
        return {'data': [{'cve': 'CVE-2099-5000', 'epss': '0.31', 'percentile': '0.97', 'date': '2099-01-01'}]}

    def test_plan_lists_only_cve_ids(self):
        plan = changes.run('plan', 'vulns_intel_update', ['all'])
        self.assertEqual(plan['status'], 'ok')
        sent = ' '.join(plan['info'][0]['items'])
        self.assertIn('CVE-2099-1000', sent)
        self.assertNotIn('openvpn', sent.lower())
        self.assertEqual(len(plan['steps']), 2)

    def test_apply_and_revert(self):
        self.urls = []
        result = actions.VulnsIntelUpdate().apply('all', get=self.fake_get)
        self.assertTrue(result['done'], result)
        self.assertTrue(any('cve=CVE-2099-1000,' in u for u in self.urls))
        items = by_cve(prioritize.build())
        self.assertEqual(items['CVE-2099-3000']['priority'], 'P2')           # KEV, not exposed
        self.assertEqual(items['CVE-2099-5000']['priority'], 'P3')           # EPSS 0.31
        self.assertEqual(intel.status(['CVE-2099-5000'])['epss']['covered'], 1)
        entry = {'state': result['state']}
        intel.revert_update(entry)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'vulns', 'kev.json')))

    def test_exposure_feed_cache_fallback(self):
        import hashlib
        key = hashlib.sha1(b'all').hexdigest()[:24]
        self.write('vuln-cache/cisa_kev/%s.json' % key, {'fetched': common.now(), 'key': 'all', 'data': {
            'CVE-2099-2000': {'kev': True, 'kev_date_added': '2099-02-02'}}})
        items, meta = intel.load_kev()
        self.assertEqual(meta['source'], 'exposure_cache')
        self.assertEqual(by_cve(prioritize.build())['CVE-2099-2000']['priority'], 'P1')


class ExplainTest(VulnsCase):
    def test_preview_and_cache(self):
        self.write('vulns/kev.json', KEV)
        a = vhelpers.assistant('Impact here\nfictitious answer', tmp=self.tmp)
        prev = explain.explain_cve('CVE-2099-1000', 'pt_BR', 'preview', assistant=a)
        self.assertEqual(prev['status'], 'ok')
        payload = prev['messages'][1]['content']
        self.assertIn('CVE-2099-1000', payload)
        self.assertIn('2099001', payload)                     # suricata sid offered as virtual patching input
        self.assertNotIn('192.0.2', payload)
        self.assertEqual(a.provider.calls, [])                # preview never calls the provider
        self.assertEqual(explain.explain_cve('CVE-2099-1000', 'pt_BR', 'cached')['status'], 'none')
        ans = explain.explain_cve('CVE-2099-1000', 'pt_BR', 'refresh', assistant=a)
        self.assertEqual(ans['status'], 'ok')
        self.assertTrue(explain.explain_cve('CVE-2099-1000', 'pt_BR', 'cached')['cached'])

    def test_disabled(self):
        a = vhelpers.assistant('x', enabled=False, tmp=self.tmp)
        self.assertEqual(explain.explain_cve('CVE-2099-1000', 'en_US', 'refresh', assistant=a)['status'], 'disabled')

    def test_suggest_mapping(self):
        item = next(q for q in prioritize.build()['review'] if q['kind'] == 'package_unmapped')
        a = vhelpers.assistant('MAPPING: none\nkea does not embed python.', tmp=self.tmp)
        ans = explain.suggest(item['id'], 'pt_BR', 'refresh', assistant=a)
        self.assertEqual(ans['mapping'], 'none')
        self.assertEqual(review.load_state()['suggestions'][item['id']]['mapping'], 'none')
        self.assertEqual(review.load_state()['decisions'], {})                   # advice only
        bad = vhelpers.assistant('MAPPING: ffffffffffff\n', tmp=self.tmp)
        self.assertEqual(explain.suggest(item['id'], 'pt_BR', 'refresh', assistant=bad)['mapping'], 'unsure')


if __name__ == '__main__':
    unittest.main()
