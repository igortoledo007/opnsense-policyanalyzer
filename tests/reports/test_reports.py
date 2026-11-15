"""
Reports and notification center: Monit settings (by reference and imported), settings/cron change actions with
revert, the report (HTML + text, AI summary with fallback), delivery through a FAKE local SMTP server, the
notification queue (baseline, subscriptions, throttle/digest, retry, resend). No real e-mail, no real AI.
Run: cd tests/reports && TMPDIR=<scratch> /usr/bin/python3 -m unittest discover -s . -v
"""

import json
import os
import stat
import unittest

import rhelpers
import vhelpers
from rhelpers import MONIT_PASSWORD, ReportsCase

from reports import actions, aisum, deliver, monit, notify, settings, store  # noqa: E402
from ai import changes  # noqa: E402


def own_settings(port, **extra):
    cfg = settings.load()
    cfg['email'].update({'mode': 'own', 'host': '127.0.0.1', 'port': port, 'security': 'none', 'verify': True,
                         'username': 'relay@example.test', 'sender': 'fw@example.test',
                         'recipients': ['ops@example.test']})
    for key, value in extra.items():
        cfg[key].update(value)
    return cfg


class MonitTest(ReportsCase):
    def test_read_without_password(self):
        data = monit.public()
        self.assertTrue(data['available'])
        self.assertEqual((data['host'], data['port'], data['security'], data['min_tls']),
                         ('smtp.example.test', 587, 'starttls', 'tlsv12'))
        self.assertEqual(data['hosts'], ['smtp.example.test', 'smtp2.example.test'])
        self.assertEqual(data['sender'], 'alerts@example.test')
        self.assertEqual(data['recipients'], ['ops@example.test'])          # disabled alert ignored
        self.assertTrue(data['password_set'])
        self.assertNotIn(MONIT_PASSWORD, json.dumps(data))
        self.assertNotIn(MONIT_PASSWORD, json.dumps(settings.public()))

    def test_ssl_port_465(self):
        self.write_text('config.xml', rhelpers.config_xml(465))
        self.assertEqual(monit.read()['security'], 'ssl')
        self.write_text('config.xml', rhelpers.config_xml(25, ssl='0'))
        self.assertEqual(monit.read()['security'], 'none')

    def test_effective_by_reference(self):
        chan = settings.effective_smtp()
        self.assertEqual(chan['mode'], 'monit')
        self.assertIn('read at every send', chan['origin'])
        self.assertNotIn('password', chan)
        self.assertEqual(settings.effective_smtp(with_password=True)['password'], MONIT_PASSWORD)
        # Monit changes: the channel follows without any copy
        self.write_text('config.xml', rhelpers.config_xml(2525).replace('smtp.example.test,', 'mail.example.test,'))
        self.assertEqual((settings.effective_smtp()['host'], settings.effective_smtp()['port']),
                         ('mail.example.test', 2525))


class SettingsActionTest(ReportsCase):
    def test_plan_apply_revert_with_crons(self):
        cfg = settings.load()
        cfg['report'].update({'enabled': True, 'every_6h': True, 'daily': True, 'daily_hour': 6})
        cfg['notify']['enabled'] = True
        token = self.payload(cfg)
        with open(self.path('reports-settings.json')) as handle:
            before = handle.read()
        plan = changes.run('plan', 'reports_settings', [token])
        self.assertEqual(plan['status'], 'ok', plan)
        with open(self.path('reports-settings.json')) as handle:
            self.assertEqual(handle.read(), before)                          # the plan writes nothing
        commands = [s['command'] for s in plan['steps']]
        self.assertIn('model.php cron_set report_6h 0 0,12,18', commands)   # the daily hour is not doubled
        self.assertIn('model.php cron_set report_daily 0 6', commands)
        self.assertIn('model.php cron_set notify */5 *', commands)
        self.assertIn('model.php cron_set report_weekly 30 7 1', commands)        # Monday 07:30 (old --semanal)
        self.assertIn('configctl cron restart', commands)
        self.assertEqual(self.php_calls, [])
        res = changes.run('apply', 'reports_settings', [token])
        self.assertTrue(res['done'], res)
        self.assertTrue(settings.load()['notify']['enabled'])
        self.assertEqual([c[2:] for c in self.php_calls if c[0].endswith('php')],
                         [['cron_set', 'notify', '*/5', '*'], ['cron_set', 'report_6h', '0', '0,12,18'],
                          ['cron_set', 'report_daily', '0', '6'], ['cron_set', 'report_weekly', '30', '7', '1']])
        self.php_calls.clear()
        changes.run('apply', 'revert', [res['journal_id']])
        self.assertFalse(settings.load()['notify']['enabled'])

    def test_own_password_never_journaled(self):
        cfg = own_settings(self.smtp.port)
        data = dict(cfg, password='Own-Pa55word-x')
        res = changes.run('apply', 'reports_settings', [self.payload(data)])
        self.assertTrue(res['done'], res)
        self.assertEqual(settings.secret(), 'Own-Pa55word-x')
        self.assertEqual(stat.S_IMODE(os.stat(self.path('reports-secret.json')).st_mode), 0o600)
        for name in os.listdir(self.path('undo')):
            with open(os.path.join(self.path('undo'), name)) as handle:
                self.assertNotIn('Own-Pa55word-x', handle.read())
        self.assertEqual(settings.public()['password_hint'], '****rd-x')
        changes.run('apply', 'revert', [res['journal_id']])
        self.assertEqual(settings.secret(), '')
        self.assertEqual(settings.load()['email']['mode'], 'monit')

    def test_validation(self):
        bad = settings.load()
        bad['email']['recipients'] = ['not-an-address']
        self.assertEqual(changes.run('plan', 'reports_settings', [self.payload(bad)])['status'], 'error')
        self.assertEqual(changes.run('plan', 'reports_settings', ['!!'])['status'], 'error')
        cfg = settings.load()
        self.assertEqual(changes.run('plan', 'reports_settings', [self.payload(dict(cfg, password='x'))])['status'],
                         'error')                                           # password only for mode own


class ImportTest(ReportsCase):
    def test_import_and_reimport(self):
        plan = changes.run('plan', 'reports_import_monit', [])
        self.assertEqual(plan['status'], 'ok')
        self.assertFalse(plan['requires_double_confirmation'])
        self.assertNotIn(MONIT_PASSWORD, json.dumps(plan))
        res = changes.run('apply', 'reports_import_monit', [])
        self.assertTrue(res['done'], res)
        cfg = settings.load()
        self.assertEqual((cfg['email']['mode'], cfg['email']['host'], cfg['email']['sender']),
                         ('own', 'smtp.example.test', 'alerts@example.test'))
        self.assertEqual(settings.secret(), MONIT_PASSWORD)
        self.assertIn('imported from Monit', settings.effective_smtp()['origin'])
        again = changes.run('plan', 'reports_import_monit', [])
        self.assertTrue(again['requires_double_confirmation'])                 # overwrite needs confirmation
        changes.run('apply', 'revert', [res['journal_id']])
        self.assertEqual(settings.load()['email']['mode'], 'monit')
        self.assertEqual(settings.secret(), '')


class DeliveryTest(ReportsCase):
    def test_starttls_required(self):
        db = store.connect()
        res = deliver.send_and_record(db, 'test', 's', '<p>x</p>', 'x', settings.load(),
                                      smtp_factory=self.smtp.factory())
        self.assertEqual(res['status'], 'failed')
        self.assertIn('STARTTLS', res['error'])
        self.assertNotIn(MONIT_PASSWORD, res['error'])
        self.assertEqual(self.smtp.messages, [])
        db.close()

    def test_send_test_action_own_channel(self):
        settings.save(own_settings(self.smtp.port))
        settings.set_secret('Own-Pa55word-x')
        plan = changes.run('plan', 'reports_send_test', ['test'])
        self.assertEqual(plan['irreversible'], ['an e-mail can not be unsent'])
        deliver.SMTP_FACTORY = self.smtp.factory()
        try:
            res = changes.run('apply', 'reports_send_test', ['test'])
        finally:
            deliver.SMTP_FACTORY = None
        self.assertTrue(res['done'], res)
        self.assertEqual(len(self.smtp.messages), 1)
        self.assertEqual(self.smtp.auth[0], [b'relay@example.test', b'Own-Pa55word-x'])
        body = self.smtp.messages[0]['data']
        self.assertIn('multipart/alternative', body)
        self.assertIn('text/html', body)
        db = store.connect(readonly=True)
        total, rows = store.messages(db)
        db.close()
        self.assertEqual((total, rows[0]['kind'], rows[0]['status']), (1, 'test', 'sent'))


class ReportTest(ReportsCase):
    def test_preview_content(self):
        prev = deliver.preview_report('6h')
        self.assertEqual(prev['status'], 'ok')
        html = prev['html']
        for text in ('Relatório de segurança', 'Quarentena', '203.0.113.5', 'CVE-2099-1000', 'Resumo automático',
                     'Rule is shadowed', 'https://fw.example.test:8443/ui/policyanalyzer/reports',
                     '@media only screen and (max-width:600px)'):
            self.assertIn(text, html)
        self.assertIn('QUARENTENA', prev['text'])
        self.assertNotIn(MONIT_PASSWORD, html + prev['text'])
        self.assertFalse(os.path.exists(self.path('reports.db')))          # preview stores nothing

    def test_data(self):
        cfg = settings.load()
        rep = deliver.build_report('6h', cfg, self.now, ai=False)
        d = rep['data']
        self.assertEqual(d['quarantine']['active'], 3)
        self.assertEqual(d['quarantine']['by_level'], {'1': 1, '5': 1, '6': 1})
        self.assertEqual(d['quarantine']['top_repeat'][0]['addr'], '203.0.113.5')
        self.assertEqual(d['traffic']['blocked_in'], 39)
        self.assertEqual(d['traffic']['top_countries'][0]['country'], 'NL')   # quarantine offenses (no GeoIP index)
        self.assertEqual(d['cves']['counts']['P1'], 2)
        self.assertTrue(rep['has_events'])

    def test_ai_summary_aggregates_only(self):
        a = vhelpers.assistant('Período com pontos de atenção: 2 CVEs P1.', tmp=self.tmp)
        rep = deliver.build_report('daily', settings.load(), self.now, assistant=a)
        self.assertTrue(rep['summary']['ai'])
        self.assertIn('Resumo executivo pela IA', rep['html'])
        sent = json.dumps(a.provider.calls)
        self.assertNotIn('203.0.113.5', sent)
        self.assertIn('blocked_in', sent)

    def test_fallback_when_ai_fails(self):
        class Broken(vhelpers.FakeProvider):
            def chat(self, *a, **k):
                from ai.providers.base import ProviderError
                raise ProviderError('bridge down')
        a = vhelpers.assistant('x', tmp=self.tmp)
        a._provider = Broken('x')
        summary = aisum.executive({'kind': '6h', 'cves': {'counts': {'P1': 1}}}, 'pt_BR', assistant=a)
        self.assertFalse(summary['ai'])
        self.assertIn('crítico', summary['text'])

    def test_scheduled_send(self):
        self.assertEqual(deliver.send_report('6h', scheduled=True)['status'], 'skipped')     # disabled
        settings.save(own_settings(self.smtp.port, report={'enabled': True}))
        res = deliver.send_report('daily', scheduled=True, smtp_factory=self.smtp.factory())
        self.assertEqual(res['status'], 'sent', res)
        self.assertEqual(self.smtp.messages[0]['to'], ['ops@example.test'])
        db = store.connect(readonly=True)
        total, rows = store.messages(db, kind='report')
        msg = store.message(db, rows[0]['id'])
        db.close()
        self.assertIn('CVE-2099-1000', msg['html'])
        self.assertEqual(msg['summary']['quarantine']['active'], 3)


class NotifyTest(ReportsCase):
    def enable(self, **events):
        cfg = own_settings(self.smtp.port)
        cfg['notify']['enabled'] = True
        cfg['notify']['ai_summary'] = False
        for key, value in events.items():
            cfg['notify']['events'][key].update(value)
        settings.save(cfg)

    def run_notify(self, now):
        return notify.run(now=now, smtp_factory=self.smtp.factory())

    def rows(self):
        db = store.connect(readonly=True)
        _t, rows = store.notifications(db, rows=200)
        db.close()
        return rows

    def test_baseline_then_event(self):
        self.enable()
        first = self.run_notify(self.now)
        self.assertEqual(self.smtp.messages, [])                              # baseline: nothing sent
        self.assertTrue(all(r['status'] == 'suppressed' for r in self.rows()))
        self.assertTrue(first['sources']['quarantine']['available'])
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 10, 1, 'upgrade', 5)
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 11, 2, 'enter', 2)   # level < 4
        self.run_notify(self.now + 60)
        self.assertEqual(len(self.smtp.messages), 1)
        mail = self.smtp.messages[0]['data']
        self.assertIn('203.0.113.5 in quarantine: 30 days', mail)
        self.assertIn('https://fw.example.test:8443/ui/policyanalyzer/#quarantine', mail)
        sent = [r for r in self.rows() if r['status'] == 'sent']
        self.assertEqual([r['type'] for r in sent], ['quarantine_long'])

    def test_throttle_digest(self):
        self.enable(quarantine_long={'throttle_minutes': 60})
        self.run_notify(self.now)
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 1, 1, 'upgrade', 5)
        self.run_notify(self.now + 60)
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 120, 2, 'upgrade', 4)
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 130, 3, 'permanent', 6, 'manual')
        self.run_notify(self.now + 300)
        self.assertEqual(len(self.smtp.messages), 1)
        self.assertEqual(sum(1 for r in self.rows() if r['status'] == 'held'), 2)
        self.run_notify(self.now + 60 + 3601)
        self.assertEqual(len(self.smtp.messages), 2)
        self.assertIn('Resumo de 2 eventos', self.smtp.messages[1]['data'])

    def test_subscription_and_severity(self):
        self.enable(quarantine_long={'enabled': False})
        self.run_notify(self.now)
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 1, 1, 'upgrade', 5)
        self.run_notify(self.now + 60)
        self.assertEqual(self.smtp.messages, [])
        self.assertEqual([r['reason'] for r in self.rows() if r['key'].startswith('quarantine:')][0], 'not subscribed')

    def test_ai_down_and_inbox(self):
        self.enable()
        os.makedirs(self.path('events'))
        self.write_text('events/incidents.jsonl', '{"id": "old", "title": "old", "severity": "high"}\n')
        self.write_text('ai.log', '')
        self.run_notify(self.now)
        with open(self.path('ai.log'), 'a') as handle:
            for i in range(3):
                handle.write(json.dumps({'ts': self.now + i, 'action': 'war_room_brief', 'provider': 'claudecode',
                                         'status': 'error', 'error': 'connection refused'}) + '\n')
        with open(self.path('events/incidents.jsonl'), 'a') as handle:
            handle.write(json.dumps({'id': 'case-7', 'ts': self.now + 5, 'severity': 'critical',
                                     'title': 'Brute force followed by a login', 'link': '/ui/policyanalyzer/incidents#7'})
                         + '\n')
        self.run_notify(self.now + 60)
        subjects = ' '.join(m['data'] for m in self.smtp.messages)
        self.assertIn('claude-bridge', subjects)
        self.assertIn('Brute force followed by a login', subjects)
        self.assertNotIn('"old"', subjects)

    def test_retry_and_resend(self):
        self.enable()
        self.run_notify(self.now)
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 1, 1, 'upgrade', 5)
        failing = rhelpers.FakeSMTP(fail=True)
        try:
            notify.run(now=self.now + 60, smtp_factory=failing.factory())
        finally:
            failing.close()
        row = next(r for r in self.rows() if r['key'].startswith('quarantine:'))
        self.assertEqual((row['status'], row['attempts']), ('queued', 1))
        self.assertGreater(row['next_try'], self.now + 60)
        notify.resend(row['id'], now=self.now + 70, smtp_factory=self.smtp.factory())
        self.assertEqual(next(r for r in self.rows() if r['id'] == row['id'])['status'], 'sent')

    def test_sources_state(self):
        os.environ['POLICYANALYZER_SCRIPTS'] = self.path('scripts')       # no other module installed
        self.addCleanup(os.environ.pop, 'POLICYANALYZER_SCRIPTS', None)
        state = notify.sources_state()
        self.assertTrue(state['quarantine_long'])
        self.assertFalse(state['anomaly'])
        overview = notify.overview()
        self.assertFalse(next(e for e in overview['events'] if e['type'] == 'anomaly')['available'])


if __name__ == '__main__':
    unittest.main()
