"""
AI usage ("shadow AI"): catalogue matching and merge, DNS + TLS aggregation per host/service/day, names, expected
usage (Claude Code bridge, firewall runtime, local catalogue), first/new with the history, summary, blocking
proposal with replay and AI explain with a fake provider.

    cd tests/shadowai && /usr/bin/python3 -m unittest discover -s . -v
"""

import base64
import json
import os
import sys
import unittest

import sai_helpers as H

os.environ['POLICYANALYZER_NOW'] = str(H.NOW)

from shadowai import cli, report as R  # noqa: E402
from shadowai.catalog import Catalog  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(H.HERE), 'posture'))
import post_helpers  # noqa: E402


def payload(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')


class CatalogTest(unittest.TestCase):
    def test_suffix_match(self):
        c = Catalog()
        self.assertEqual(c.match('api.anthropic.com.')[0], 'anthropic')
        self.assertEqual(c.match('CHATGPT.COM')[0], 'openai')
        self.assertEqual(c.match('generativelanguage.googleapis.com')[0], 'gemini')
        for name in ('notclaude.ai', 'claudeers.com', 'scan.cypex.ai', 'www.googleapis.com', 'x.com', 'google.com',
                     '', None):
            self.assertIsNone(c.match(name), name)
        self.assertGreaterEqual(len(c.services), 25)
        for sid in ('openai', 'anthropic', 'gemini', 'copilot', 'perplexity', 'deepseek', 'mistral', 'meta_ai',
                    'xai', 'huggingface', 'character_ai', 'midjourney'):
            self.assertIn(sid, c.services)

    def test_shipped_file_is_valid(self):
        with open(os.path.join(H.SCRIPTS, 'shadowai', 'data', 'ai-services.json')) as handle:
            data = json.load(handle)
        self.assertTrue(data['version'])
        seen = {}
        for svc in data['services']:
            self.assertIn(svc['category'], data['categories'])
            for d in svc['domains']:
                self.assertNotIn(d, seen, 'domain %s in %s and %s' % (d, seen.get(d), svc['id']))
                seen[d] = svc['id']

    def test_local_merge(self):
        c = Catalog(local=os.path.join(H.HERE, 'fixtures', 'ai-services.local.json'))
        self.assertEqual(c.local_version, 'test-local-1')
        self.assertEqual(c.match('openai-proxy.example.test')[0], 'openai')
        self.assertEqual(c.match('llm.example.test')[0], 'corp_llm')
        self.assertNotIn('midjourney', c.services)
        self.assertIsNone(c.match('www.midjourney.com'))
        self.assertEqual(len(c.known), 1)

    def test_regex_prefilter_agrees(self):
        import re
        c = Catalog()
        rx = re.compile(c.regex())
        for name in ('api.anthropic.com.', 'chatgpt.com', 'a.b.hf.co'):
            self.assertTrue(rx.search(name), name)
        self.assertFalse(rx.search('notclaude.ai.'))


class ReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = H.Root()
        cls.report = R.build(cls.root.paths, days=7, write=True)
        cls.hosts = {h['ip']: h for h in cls.report['hosts']}

    @classmethod
    def tearDownClass(cls):
        cls.root.cleanup()

    def svc(self, ip, sid):
        return next((s for s in self.hosts[ip]['services'] if s['service'] == sid), None)

    def test_counts(self):
        s = self.svc('192.0.2.10', 'openai')
        self.assertEqual(s['dns'], 35)
        self.assertEqual(s['tls'], 3)            # the TLS event 20 days ago is outside the window
        self.assertEqual(self.svc('192.0.2.10', 'deepseek')['blocked'], 1)
        self.assertIsNone(self.svc('192.0.2.10', 'gemini'))   # 30 days ago
        self.assertEqual(self.report['totals']['unattributed_dns'], 1)  # public client address
        self.assertNotIn('100.200.0.9', self.hosts)

    def test_no_false_matches(self):
        self.assertNotIn('192.0.2.40', self.hosts)  # midjourney disabled, notclaude.ai, example.org

    def test_names_and_vendor(self):
        self.assertEqual(self.hosts['192.0.2.10']['name'], 'laptop-01.example.test')
        self.assertEqual(self.hosts['192.0.2.10']['vendor'], 'Example Devices Inc')
        self.assertEqual(self.hosts['192.0.2.20']['name'], 'bridge')
        self.assertEqual(self.hosts['192.0.2.30']['name'], 'dev-ws')

    def test_expected_usage(self):
        bridge = self.svc('192.0.2.20', 'anthropic')
        self.assertTrue(bridge['known'])
        self.assertTrue(bridge['bridge'])
        self.assertIn('Claude Code bridge', bridge['known_reason'])
        self.assertTrue(self.svc('192.0.2.30', 'github_copilot')['known'])
        self.assertFalse(self.svc('192.0.2.30', 'anthropic')['known'])
        self.assertTrue(self.hosts['127.0.0.1']['firewall'])
        self.assertTrue(self.svc('127.0.0.1', 'ollama')['known'])
        self.assertFalse(self.svc('192.0.2.10', 'openai')['known'])
        self.assertEqual(self.report['hosts'][0]['ip'], '192.0.2.10')   # most unexpected use first

    def test_ja4_and_daily(self):
        bridge = self.svc('192.0.2.20', 'anthropic')
        self.assertEqual(len(bridge['ja4']), 2)
        self.assertEqual(len(self.report['daily']), 7)
        self.assertGreater(sum(d['total'] for d in self.report['daily']), 0)
        self.assertEqual(self.report['sources']['tls']['events'], 5)

    def test_first_run_is_baseline(self):
        self.assertEqual(self.report['totals']['new'], 0)

    def test_new_after_baseline(self):
        root = H.Root()
        try:
            R.build(root.paths, days=7, write=True)
            os.environ['POLICYANALYZER_NOW'] = str(H.NOW + 2 * H.DAY)
            later = H.NOW + 2 * H.DAY - 600
            with open(root.paths.unbound_db, 'a') as handle:
                handle.write(json.dumps({'time': later, 'client': '192.0.2.10', 'domain': 'www.perplexity.ai.',
                                         'action': 0}) + '\n')
            rep = R.build(root.paths, days=7, write=True)
            new = [(n['host'], n['service']) for n in rep['new_items']]
            self.assertIn(('192.0.2.10', 'perplexity'), new)
            self.assertNotIn(('192.0.2.10', 'openai'), new)
            # first use is kept from the history even when the source lost it
            first = R.Store(root.paths.db('shadowai.db')).first_seen()
            self.assertLess(first[('192.0.2.10', 'openai')][0], later)
        finally:
            os.environ['POLICYANALYZER_NOW'] = str(H.NOW)
            root.cleanup()

    def test_without_eve(self):
        root = H.Root(with_eve=False)
        try:
            rep = R.build(root.paths, days=7, write=False)
            self.assertFalse(rep['sources']['tls']['available'])
            self.assertEqual(rep['totals']['tls'], 0)
            self.assertGreater(rep['totals']['dns'], 0)
        finally:
            root.cleanup()


class CliTest(unittest.TestCase):
    def setUp(self):
        self.root = H.Root()

    def tearDown(self):
        self.root.cleanup()

    def test_last_and_summary(self):
        out = cli.main(['last', '7'], paths=self.root.paths)
        self.assertEqual(out['status'], 'ok')
        again = cli.main(['last', '7'], paths=self.root.paths)
        self.assertEqual(again['generated'], out['generated'])
        summary = cli.main(['summary'], paths=self.root.paths)
        self.assertEqual(summary['kind'], 'shadowai_summary')
        self.assertLessEqual(len(summary['top_services']), 5)
        self.assertNotIn('hosts', summary)
        self.assertLess(len(json.dumps(summary)), 4000)

    def test_catalog(self):
        out = cli.main(['catalog'], paths=self.root.paths)
        self.assertEqual(out['status'], 'ok')
        self.assertTrue(any(s['id'] == 'corp_llm' for s in out['services']))

    def test_propose_dns_for_host(self):
        out = cli.main(['propose', payload({'services': ['openai', 'deepseek'], 'scope': 'host',
                                            'value': '192.0.2.10', 'method': 'unbound'})], paths=self.root.paths)
        self.assertEqual(out['status'], 'ok')
        self.assertTrue(out['readonly'])
        self.assertEqual(out['simulation']['events_blocked'], 35 + 3 + 2)
        self.assertEqual([a['ip'] for a in out['simulation']['hosts_affected']], ['192.0.2.10'])
        self.assertIn('Source net(s): 192.0.2.10/32', out['diff'])
        self.assertIn('chatgpt.com', out['domains'])
        self.assertEqual(out['plan']['risk'], 'low')
        self.assertIn('nothing is applied', out['plan']['message'])

    def test_propose_conflict_with_bridge(self):
        out = cli.main(['propose', payload({'services': ['anthropic'], 'scope': 'all', 'method': 'alias'})],
                       paths=self.root.paths)
        self.assertEqual(out['status'], 'ok')
        self.assertTrue(any(c['bridge'] for c in out['simulation']['expected_conflicts']))
        self.assertEqual(out['plan']['risk'], 'medium')
        self.assertTrue(out['plan']['warnings'][0].startswith('Expected usage would break'))
        self.assertIn('Type: Host(s)', out['diff'])

    def test_propose_invalid(self):
        bad = [{'services': ['nope']}, {'services': ['openai'], 'scope': 'host', 'value': '192.0.2.0/24'},
               {'services': ['openai'], 'scope': 'net', 'value': 'x'}, {'services': ['openai'], 'method': 'rm'},
               {'services': ['openai'], 'scope': 'evil'}]
        for item in bad:
            self.assertEqual(cli.main(['propose', payload(item)], paths=self.root.paths)['status'], 'error', item)
        self.assertEqual(cli.main(['propose', 'not base64!'], paths=self.root.paths)['status'], 'error')

    def test_explain_fake_provider(self):
        assistant, provider = post_helpers.fake_assistant()
        out = cli.main(['explain', payload({'target': 'overview'}), 'en_US', 'send'], paths=self.root.paths,
                       assistant=assistant)
        self.assertEqual(out['status'], 'ok')
        sent = provider.messages[0][1]['content']
        self.assertIn('OpenAI ChatGPT', sent)
        self.assertNotIn('laptop-01', sent)      # host names are anonymized
        self.assertNotIn('192.0.2.10', sent)
        out = cli.main(['explain', payload({'target': 'host', 'ip': '192.0.2.10'}), 'en_US', 'send'],
                       paths=self.root.paths, assistant=assistant)
        self.assertEqual(out['status'], 'ok')
        self.assertIn('ja4_fingerprints', provider.messages[1][1]['content'])
        out = cli.main(['explain', payload({'target': 'host', 'ip': '192.0.2.99'}), 'en_US'],
                       paths=self.root.paths, assistant=assistant)
        self.assertEqual(out['status'], 'error')

    def test_explain_preview(self):
        assistant, provider = post_helpers.fake_assistant()
        out = cli.main(['explain', payload({'target': 'overview'}), 'en_US', 'preview'], paths=self.root.paths,
                       assistant=assistant)
        self.assertIn('messages', out)
        self.assertEqual(provider.messages, [])


if __name__ == '__main__':
    unittest.main()
