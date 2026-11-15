"""
Posture health check: catalogue, results on a weak and a hardened fictional configuration, score, history,
summary, AI explain (fake provider only) and robustness.

    cd tests/posture && /usr/bin/python3 -m unittest discover -s . -v
"""

import os
import sqlite3
import unittest

import post_helpers as H

os.environ['POLICYANALYZER_NOW'] = str(H.NOW)

from posture import checks, cli, engine  # noqa: E402


def by_id(report):
    return {c['id']: c for c in report['checks']}


class CatalogueTest(unittest.TestCase):
    def test_at_least_30_checks_with_metadata(self):
        self.assertGreaterEqual(len(checks.CHECKS), 30)
        ids = [c.id for c in checks.CHECKS]
        self.assertEqual(len(ids), len(set(ids)), 'duplicate check id')
        for c in checks.CHECKS:
            self.assertRegex(c.id, r'^PA-[A-Z]{2,4}-\d{2}$')
            self.assertIn(c.severity, checks.SEVERITIES)
            self.assertIn(c.category, checks.CATEGORIES)
            self.assertTrue(c.references, c.id)
            self.assertTrue(c.recommendation, c.id)
            self.assertTrue(all(r['url'].startswith('https://') for r in c.references), c.id)

    def test_cli_checks(self):
        root = H.Root('config-strong.xml')
        try:
            out = cli.main(['checks'], paths=root.paths)
            self.assertEqual(out['status'], 'ok')
            self.assertEqual(len(out['checks']), len(checks.CHECKS))
        finally:
            root.cleanup()


class WeakConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = H.Root('config-weak.xml', firmware={'product_version': '26.7.1', 'needs_reboot': '1',
                                                       'upgrade_packages': [{'name': 'opnsense'}, {'name': 'php'}]},
                          report=H.REPORT_WEAK,
                          hostkeys=(('ssh_host_dsa_key.pub', 'ssh-dss AAAAB3NzaC1kc3MAAACBAP root@fw'),))
        cls.runner = H.FakeRunner(sysctl={'net.inet.tcp.blackhole': '0', 'net.inet.udp.blackhole': '0',
                                          'net.inet.ip.redirect': '1', 'vm.pmap.pti': '0', 'hw.ibrs_disable': '1',
                                          'security.bsd.see_other_uids': '1'},
                                  sockstat=H.SOCKSTAT_WEAK, states=(95000, 100000))
        cls.report = engine.build_report(cls.root.paths, cls.runner)
        cls.c = by_id(cls.report)

    @classmethod
    def tearDownClass(cls):
        cls.root.cleanup()

    def expect(self, cid, result):
        self.assertEqual(self.c[cid]['result'], result, '%s: %s' % (cid, self.c[cid]['summary']))

    def test_management_access(self):
        self.expect('PA-ACC-01', 'warn')   # GUI on all interfaces, no WAN rule to the GUI port
        self.expect('PA-ACC-02', 'fail')   # http
        self.expect('PA-ACC-03', 'na')
        self.expect('PA-ACC-04', 'fail')   # rebind check off
        self.expect('PA-ACC-05', 'fail')   # ssh on wan + wan rule to 22
        self.expect('PA-ACC-06', 'fail')
        self.expect('PA-ACC-07', 'fail')
        self.expect('PA-ACC-08', 'fail')   # cbc cipher
        self.expect('PA-ACC-09', 'warn')

    def test_accounts(self):
        self.expect('PA-USR-01', 'fail')
        self.expect('PA-USR-02', 'fail')
        self.assertEqual(self.c['PA-USR-02']['severity'], 'high')
        self.expect('PA-USR-03', 'fail')
        self.expect('PA-USR-04', 'fail')   # alice: admin with API key
        self.expect('PA-USR-05', 'warn')
        self.expect('PA-CRT-03', 'fail')   # bob's DSA key

    def test_system(self):
        self.expect('PA-SYS-01', 'fail')
        self.assertEqual(self.c['PA-SYS-01']['severity'], 'high')  # core package pending
        self.expect('PA-SYS-02', 'warn')
        self.expect('PA-SYS-03', 'fail')
        self.expect('PA-SYS-04', 'warn')
        self.expect('PA-SYS-05', 'warn')
        self.assertIn('chronyd 123/udp', self.c['PA-SYS-05']['evidence']['wildcard'])
        self.expect('PA-SYS-06', 'fail')   # UPnP on without ACL

    def test_firewall(self):
        self.expect('PA-FW-01', 'fail')
        self.assertEqual(self.c['PA-FW-01']['fix']['minrule'], '11111111-1111-4111-8111-111111111111')
        self.expect('PA-FW-02', 'fail')
        self.expect('PA-FW-03', 'fail')
        self.expect('PA-FW-04', 'warn')
        self.expect('PA-FW-05', 'fail')
        self.expect('PA-FW-06', 'warn')
        self.expect('PA-FW-07', 'fail')
        self.expect('PA-FW-08', 'fail')    # IPv6 on lan, no IPv6 rule
        self.expect('PA-FW-09', 'fail')    # 95 % of the state table
        self.expect('PA-FW-11', 'warn')
        self.assertEqual(self.c['PA-FW-11']['fix']['action']['name'], 'install_quarantine')

    def test_logging_dns_ids_backup(self):
        self.expect('PA-LOG-01', 'fail')
        self.expect('PA-LOG-02', 'warn')
        self.expect('PA-LOG-03', 'warn')
        self.expect('PA-DNS-01', 'fail')
        self.expect('PA-DNS-02', 'warn')
        self.expect('PA-DNS-03', 'fail')
        self.expect('PA-DNS-04', 'warn')
        self.expect('PA-NTP-01', 'warn')
        self.expect('PA-IDS-01', 'fail')
        self.expect('PA-IDS-02', 'na')
        self.expect('PA-BAK-01', 'fail')
        self.expect('PA-BAK-03', 'warn')

    def test_fixes_are_proposals_with_page(self):
        for c in self.report['checks']:
            if c['result'] in ('pass', 'na'):
                self.assertNotIn('fix', c)
            if 'fix' in c:
                self.assertTrue(c['fix']['page'], c['id'])
                self.assertIn('\n+ ', c['fix']['diff'], c['id'])

    def test_score_is_low(self):
        self.assertLess(self.report['score'], 40)
        self.assertEqual(self.report['grade'], 'F')

    def test_runner_never_writes(self):
        for argv in self.runner.calls:
            self.assertIn(os.path.basename(argv[0]), ('sysctl', 'sockstat', 'pfctl'))
            self.assertNotIn('-w', argv)
            self.assertFalse(any(a.startswith('-T') or a in ('-f', '-k', '-F') for a in argv[1:]), argv)


class StrongConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = H.Root('config-strong.xml', report=H.REPORT_CLEAN)
        cls.report = engine.build_report(cls.root.paths, H.FakeRunner())
        cls.c = by_id(cls.report)

    @classmethod
    def tearDownClass(cls):
        cls.root.cleanup()

    def test_no_failures(self):
        fails = [(c['id'], c['summary']) for c in self.report['checks'] if c['result'] == 'fail']
        self.assertEqual(fails, [])

    def test_score_high(self):
        self.assertGreaterEqual(self.report['score'], 90)
        self.assertEqual(self.report['grade'], 'A')

    def test_selected_passes(self):
        for cid in ('PA-ACC-01', 'PA-ACC-02', 'PA-ACC-03', 'PA-ACC-05', 'PA-ACC-06', 'PA-USR-01', 'PA-USR-02',
                    'PA-USR-04', 'PA-SYS-01', 'PA-FW-01', 'PA-FW-06', 'PA-FW-07', 'PA-FW-08', 'PA-FW-11',
                    'PA-LOG-01', 'PA-DNS-01', 'PA-DNS-02', 'PA-IDS-02', 'PA-IDS-03', 'PA-BAK-01', 'PA-BAK-02',
                    'PA-NTP-01', 'PA-CRT-01', 'PA-CRT-03'):
            self.assertEqual(self.c[cid]['result'], 'pass', '%s: %s' % (cid, self.c[cid]['summary']))

    def test_upnp_not_installed(self):
        self.assertEqual(self.c['PA-SYS-06']['result'], 'na')


class CertificateTest(unittest.TestCase):
    def run_with(self, **kw):
        root = H.Root('config-strong.xml', report=H.REPORT_CLEAN, **kw)
        try:
            return by_id(engine.build_report(root.paths, H.FakeRunner()))
        finally:
            root.cleanup()

    def test_expiring_soon(self):
        c = self.run_with(cert_days=10)
        self.assertEqual(c['PA-ACC-03']['result'], 'fail')
        self.assertEqual(c['PA-CRT-01']['result'], 'warn')

    def test_expired(self):
        c = self.run_with(cert_days=-3)
        self.assertEqual(c['PA-ACC-03']['result'], 'fail')
        self.assertEqual(c['PA-ACC-03']['severity'], 'high')
        self.assertEqual(c['PA-CRT-01']['result'], 'fail')

    def test_staging_ca(self):
        c = self.run_with(cert_issuer='(STAGING) Artificial Apricot R3')
        self.assertEqual(c['PA-ACC-03']['result'], 'fail')

    def test_self_signed(self):
        c = self.run_with(cert_issuer=None)
        self.assertEqual(c['PA-ACC-03']['result'], 'warn')


class ScoreAndHistoryTest(unittest.TestCase):
    def test_score_formula(self):
        items = [{'result': 'pass', 'severity': 'high'}, {'result': 'fail', 'severity': 'high'},
                 {'result': 'warn', 'severity': 'medium'}, {'result': 'na', 'severity': 'high'}]
        # (10 + 0 + 2.5) / (10 + 10 + 5)
        self.assertEqual(engine.score_of(items), 50.0)
        self.assertIsNone(engine.score_of([{'result': 'na', 'severity': 'high'}]))
        self.assertEqual(engine.grade(90), 'A')
        self.assertEqual(engine.grade(59.9), 'F')

    def test_history_changes_and_summary(self):
        root = H.Root('config-strong.xml', report=H.REPORT_CLEAN)
        try:
            first = engine.run(root.paths, H.FakeRunner())
            self.assertIsNone(first['changes']['delta'])
            os.environ['POLICYANALYZER_NOW'] = str(H.NOW + 86400)
            second = engine.run(root.paths, H.FakeRunner(sockstat=H.SOCKSTAT_WEAK, states=(99000, 100000)))
            self.assertLess(second['changes']['delta'], 0)
            worse = [c['id'] for c in second['changes']['new_failures']]
            self.assertIn('PA-FW-09', worse)
            self.assertIn('PA-SYS-05', worse)
            hist = cli.main(['history', '30'], paths=root.paths)
            self.assertEqual(len(hist['history']), 2)
            db = sqlite3.connect(root.paths.db('posture.db'))
            self.assertEqual(db.execute('SELECT count(*) FROM results').fetchone()[0], 2 * len(checks.CHECKS))
            db.close()
            summary = cli.main(['summary'], paths=root.paths)
            self.assertEqual(summary['kind'], 'posture_summary')
            self.assertEqual(summary['score'], second['score'])
            self.assertLessEqual(len(summary['top']), 3)
            self.assertEqual(summary['top'][0]['id'], 'PA-FW-09')
            self.assertEqual(len(summary['trend']), 2)
            self.assertNotIn('checks', summary)
            self.assertLess(len(str(summary)), 3000)
            last = cli.main(['last'], paths=root.paths)
            self.assertEqual(last['generated'], second['generated'])
        finally:
            os.environ['POLICYANALYZER_NOW'] = str(H.NOW)
            root.cleanup()

    def test_last_runs_once_when_missing(self):
        root = H.Root('config-strong.xml', report=H.REPORT_CLEAN)
        try:
            out = cli.main(['last'], paths=root.paths, runner=H.FakeRunner())
            self.assertEqual(out['status'], 'ok')
            self.assertTrue(os.path.exists(root.paths.db('posture.json')))
        finally:
            root.cleanup()


class RobustnessTest(unittest.TestCase):
    def test_probes_unavailable(self):
        root = H.Root('config-strong.xml', firmware=False, report=None)
        try:
            c = by_id(engine.build_report(root.paths, H.FakeRunner(broken=('sysctl', 'sockstat', 'pfctl'))))
            for cid in ('PA-SYS-03', 'PA-SYS-04', 'PA-SYS-05', 'PA-FW-09', 'PA-FW-01', 'PA-FW-02'):
                self.assertEqual(c[cid]['result'], 'na', cid)
            self.assertEqual(c['PA-SYS-01']['result'], 'warn')
        finally:
            root.cleanup()

    def test_crashing_check_is_na(self):
        root = H.Root('config-strong.xml', report=H.REPORT_CLEAN)
        original = checks.CHECKS[0].func
        try:
            def boom(ctx):
                raise RuntimeError('broken')
            checks.CHECKS[0].func = boom
            c = by_id(engine.build_report(root.paths, H.FakeRunner()))
            self.assertEqual(c[checks.CHECKS[0].id]['result'], 'na')
            self.assertIn('broken', c[checks.CHECKS[0].id]['evidence']['error'])
        finally:
            checks.CHECKS[0].func = original
            root.cleanup()

    def test_unreadable_config(self):
        root = H.Root('config-strong.xml')
        try:
            os.unlink(root.paths.config)
            out = engine.build_report(root.paths, H.FakeRunner())
            self.assertEqual(out['status'], 'error')
        finally:
            root.cleanup()

    def test_27_1_settings_layout(self):
        """ anti-lockout and keep counters in the 27.1 MVC firewall settings """
        root = H.Root('config-strong.xml', report=H.REPORT_CLEAN)
        try:
            with open(root.paths.config) as handle:
                text = handle.read()
            text = text.replace('<noantilockout>1</noantilockout>', '').replace('<keepcounters>1</keepcounters>', '')
            text = text.replace('<Firewall><Filter>', '<Firewall><Filter version="1.0.8"><settings><filter>'
                                '<keep_counters>1</keep_counters><disable_antilockout>1</disable_antilockout>'
                                '</filter></settings>')
            with open(root.paths.config, 'w') as handle:
                handle.write(text)
            c = by_id(engine.build_report(root.paths, H.FakeRunner()))
            self.assertEqual(c['PA-FW-06']['result'], 'pass')
            self.assertEqual(c['PA-FW-10']['result'], 'pass')
        finally:
            root.cleanup()


class ExplainTest(unittest.TestCase):
    def setUp(self):
        self.root = H.Root('config-weak.xml', report=H.REPORT_WEAK)
        engine.run(self.root.paths, H.FakeRunner())

    def tearDown(self):
        self.root.cleanup()

    def test_explain_check_fake_provider(self):
        assistant, provider = H.fake_assistant()
        out = cli.main(['explain', 'PA-USR-02', 'pt_BR', 'send'], paths=self.root.paths, assistant=assistant)
        self.assertEqual(out['status'], 'ok')
        self.assertEqual(out['text'], provider.answer)
        sent = provider.messages[0][1]['content']
        self.assertIn('PA-USR-02', sent)
        # account names never leave the box, only their number
        self.assertNotIn('alice', sent)
        self.assertNotIn('bob', sent)
        self.assertNotIn('root,', sent)
        self.assertIn('ACCOUNT_', sent)
        self.assertIn('without_otp_count', sent)
        self.assertIn('Brazilian Portuguese', provider.messages[0][0]['content'])
        again = cli.main(['explain', 'PA-USR-02', 'pt_BR', 'send'], paths=self.root.paths, assistant=assistant)
        self.assertTrue(again['cached'])
        self.assertEqual(len(provider.messages), 1)

    def test_executive_summary(self):
        assistant, provider = H.fake_assistant()
        out = cli.main(['explain', 'summary', 'en_US', 'send'], paths=self.root.paths, assistant=assistant)
        self.assertEqual(out['status'], 'ok')
        self.assertIn('"score"', provider.messages[0][1]['content'])
        self.assertIn('failing', provider.messages[0][1]['content'])

    def test_preview_sends_nothing(self):
        assistant, provider = H.fake_assistant()
        out = cli.main(['explain', 'PA-ACC-02', 'en_US', 'preview'], paths=self.root.paths, assistant=assistant)
        self.assertEqual(out['status'], 'ok')
        self.assertIn('messages', out)
        self.assertEqual(provider.messages, [])

    def test_disabled_and_invalid(self):
        assistant, provider = H.fake_assistant(enabled=False)
        out = cli.main(['explain', 'PA-ACC-02', 'en_US', 'send'], paths=self.root.paths, assistant=assistant)
        self.assertEqual(out['status'], 'disabled')
        self.assertEqual(cli.main(['explain', '../etc', 'en_US'], paths=self.root.paths)['status'], 'error')
        self.assertEqual(cli.main(['explain', 'PA-XXX-99', 'en_US'], paths=self.root.paths,
                                  assistant=assistant)['status'], 'error')


if __name__ == '__main__':
    unittest.main()
