"""
Change actions (install / remove / state / note, journaled by ai/changes.py) and the AI triage (candidate
actions, answer parsing, summary and daily digest with a fake provider: the real AI is never called).
"""

import base64
import io
import json
import os
import unittest
from contextlib import redirect_stdout

import ihelpers as H
from ihelpers import T0, WAN_IP, eve_alert, v4

SCANNER = '203.0.113.9'
WEB = '192.168.1.10'


def b64(text):
    return base64.b64encode(text.encode()).decode()


class TestInstall(H.IncidentCase):
    installed = False

    def test_plan_apply_revert(self):
        plan = H.changes.run('plan', 'install_incidents', [])
        self.assertEqual(plan['status'], 'ok')
        self.assertEqual(len(plan['steps']), 3)
        self.assertTrue(plan['requires_confirmation'])
        self.assertFalse(os.path.exists(self.ctx.db))             # plan changes nothing
        self.assertEqual(self.runner.calls, [])
        result = H.changes.run('apply', 'install_incidents', [])
        self.assertTrue(result['done'])
        self.assertTrue(os.path.exists(self.ctx.db))
        self.assertTrue(self.cron)
        self.assertIn(['/usr/local/sbin/configctl', 'cron', 'restart'], self.runner.calls)
        jid = result['journal_id']
        # idempotent
        again = H.changes.run('plan', 'install_incidents', [])
        self.assertEqual(again['steps'], [])
        self.assertFalse(again['requires_confirmation'])
        rplan = H.changes.run('plan', 'revert', [jid])
        self.assertEqual([s['description'] for s in rplan['steps']],
                         ['Remove the cron job', 'Apply the cron configuration'])
        reverted = H.changes.run('apply', 'revert', [jid])
        self.assertEqual(reverted['status'], 'ok')
        self.assertFalse(self.cron)
        self.assertTrue(os.path.exists(self.ctx.db))              # the history is kept

    def test_remove_and_revert(self):
        H.changes.run('apply', 'install_incidents', [])
        result = H.changes.run('apply', 'remove_incidents', [])
        self.assertFalse(self.cron)
        H.changes.run('apply', 'revert', [result['journal_id']])
        self.assertTrue(self.cron)

    def test_arguments_refused(self):
        self.assertEqual(H.changes.run('plan', 'install_incidents', ['x'])['status'], 'error')


class TestStateAndNotes(H.IncidentCase):
    def setUp(self):
        super().setUp()
        self.log(*[v4(T0 - 900 + i, SCANNER, WAN_IP, 1000 + i, action='block') for i in range(12)])
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.run_engine()

    def test_state_change_journal_and_revert(self):
        plan = H.changes.run('plan', 'incident_state', ['1', 'false_positive', b64('scanner of a research project')])
        self.assertEqual(len(plan['steps']), 2)
        self.assertTrue(any('7 days' in w for w in plan['warnings']))
        self.assertEqual(self.cases()[0]['state'], 'new')
        result = H.changes.run('apply', 'incident_state', ['1', 'false_positive', b64('scanner of a research project')])
        self.assertTrue(result['journal_id'])
        detail = self.detail(1)
        self.assertEqual(detail['state'], 'false_positive')
        self.assertEqual(detail['notes'][0]['text'], 'scanner of a research project')
        self.assertEqual([l['kind'] for l in detail['log']], ['created', 'state'])
        H.changes.run('apply', 'revert', [result['journal_id']])
        detail = self.detail(1)
        self.assertEqual(detail['state'], 'new')
        self.assertEqual(detail['notes'], [])

    def test_note(self):
        result = H.changes.run('apply', 'incident_note', ['1', b64('called the owner of 192.168.1.10')])
        self.assertTrue(result['done'])
        self.assertEqual(self.detail(1)['notes'][0]['text'], 'called the owner of 192.168.1.10')
        H.changes.run('apply', 'revert', [result['journal_id']])
        self.assertEqual(self.detail(1)['notes'], [])

    def test_invalid_input(self):
        self.assertEqual(H.changes.run('plan', 'incident_state', ['1', 'closed', '-'])['status'], 'error')
        self.assertEqual(H.changes.run('plan', 'incident_state', ['x', 'resolved', '-'])['status'], 'error')
        self.assertEqual(H.changes.run('plan', 'incident_state', ['99', 'resolved', '-'])['status'], 'error')
        self.assertEqual(H.changes.run('plan', 'incident_note', ['1', '-'])['status'], 'error')
        self.assertEqual(H.changes.run('plan', 'incident_note', ['1', '%%%'])['status'], 'error')

    def test_cli_plan_apply_only_own_actions(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            H.cli.main(['cli.py', 'apply', 'quarantine_pause'])
        self.assertEqual(json.loads(buf.getvalue())['status'], 'error')
        buf = io.StringIO()
        with redirect_stdout(buf):
            H.cli.main(['cli.py', 'apply', 'incident_state', '1', 'investigating', '-'])
        self.assertEqual(json.loads(buf.getvalue())['status'], 'ok')
        self.assertEqual(self.cases()[0]['state'], 'investigating')


ANSWER = {
    'summary': 'A scanner probed 12 ports and then reached the web server.',
    'hypothesis': 'Reconnaissance followed by an access attempt on the published web server.',
    'impact': 'The web server 192.168.1.10 may be targeted.',
    'confidence': 'medium',
    'next_steps': ['Check the web server logs', 'Review the NAT rule'],
    'actions': [{'id': 'quarantine_1', 'duration': 'l3', 'why': 'scan + access'},
                {'id': 'evil_action', 'why': 'invented'},
                {'id': 'live_view_1'},
                {'id': 'quarantine_1', 'duration': 'l5'}],
}


class TestTriage(H.IncidentCase):
    def setUp(self):
        super().setUp()
        self.log(*[v4(T0 - 900 + i, SCANNER, WAN_IP, 1000 + i, action='block') for i in range(12)])
        self.log(v4(T0 - 600, SCANNER, WEB, 443))
        self.eve(eve_alert(T0 - 590, SCANNER, severity=2, dport=443))
        self.run_engine()

    def test_candidates_are_closed(self):
        case = self.detail(1)
        cands = H.triage.candidates(case)
        ids = [c['id'] for c in cands]
        self.assertIn('quarantine_1', ids)
        self.assertIn('live_view_1', ids)
        self.assertIn('live_view_host_1', ids)
        self.assertIn('review_rule_1', ids)
        self.assertIn('ids_alerts', ids)
        q = next(c for c in cands if c['id'] == 'quarantine_1')
        self.assertEqual(q['target'], SCANNER)
        rule = next(c for c in cands if c['id'] == 'review_rule_1')
        self.assertEqual(rule['url'], '/ui/firewall/filter#' + H.NAT_RULE)
        lv = next(c for c in cands if c['id'] == 'live_view_1')
        self.assertEqual(lv['url'], '/ui/diagnostics/firewall/log#field=src&operator=%3D&value=' + SCANNER)

    def test_parse_answer_validates_actions(self):
        cands = H.triage.candidates(self.detail(1))
        parsed = H.triage.parse_answer('```json\n%s\n```' % json.dumps(ANSWER), cands)
        self.assertTrue(parsed['parsed'])
        self.assertEqual([a['id'] for a in parsed['actions']], ['quarantine_1', 'live_view_1'])
        self.assertEqual(parsed['actions'][0]['duration'], 'l3')
        self.assertEqual(parsed['actions'][0]['target'], SCANNER)          # from the candidate, not the model
        self.assertEqual(parsed['confidence'], 'medium')
        bad = dict(ANSWER, actions=[{'id': 'quarantine_1', 'duration': 'forever'}], confidence='total')
        parsed = H.triage.parse_answer(json.dumps(bad), cands)
        self.assertEqual(parsed['actions'][0]['duration'], 'l1')
        self.assertIsNone(parsed['confidence'])
        parsed = H.triage.parse_answer('Just text, no JSON.', cands)
        self.assertFalse(parsed['parsed'])
        self.assertEqual(parsed['summary'], 'Just text, no JSON.')
        self.assertEqual(parsed['actions'], [])

    def test_summarize_anonymizes_and_stores(self):
        def answer(messages):
            content = messages[1]['content']
            self.assertNotIn(SCANNER, content)
            self.assertNotIn(WEB, content)
            self.assertNotIn('NAT web server', content)
            self.assertIn('quarantine_1', content)
            token = content.split('Put ')[1].split(' in quarantine')[0]
            return json.dumps(dict(ANSWER, summary='%s probed 12 ports.' % token))
        provider = H.FakeProvider(answer)
        helper = H.assistant(self.tmp, provider)
        out = H.triage.summarize(H.engine.Engine(self.ctx), 1, 'pt_BR', assistant=helper)
        self.assertEqual(out['status'], 'ok')
        summary = out['summary']
        self.assertEqual(summary['summary'], '%s probed 12 ports.' % SCANNER)     # placeholders restored
        self.assertEqual(summary['actions'][0]['kind'], 'quarantine')
        detail = self.detail(1)
        self.assertEqual(detail['summary']['data']['summary'], summary['summary'])
        self.assertEqual(detail['log'][-1]['kind'], 'summary')
        with open(os.path.join(self.tmp, 'ai.log')) as handle:
            audit = handle.read()
        self.assertIn('incident_summary', audit)
        self.assertNotIn(SCANNER, audit)

    def test_preview_sends_nothing(self):
        provider = H.FakeProvider('{}')
        out = H.triage.summarize(H.engine.Engine(self.ctx), 1, 'en_US', preview=True,
                                 assistant=H.assistant(self.tmp, provider))
        self.assertEqual(out['status'], 'ok')
        self.assertIsNone(provider.messages)
        self.assertIn('candidate_actions', out['messages'][1]['content'])

    def test_disabled(self):
        out = H.triage.summarize(H.engine.Engine(self.ctx), 1, 'en_US',
                                 assistant=H.assistant(self.tmp, H.FakeProvider('{}'), enabled=False))
        self.assertEqual(out['status'], 'disabled')

    def test_digest(self):
        eng = H.engine.Engine(self.ctx)
        day = H.common.local_day(T0)
        cached = H.triage.digest(eng, day)
        self.assertEqual(cached['totals']['cases'], 1)
        self.assertIsNone(cached['digest'])
        provider = H.FakeProvider('**Quiet day**: one high case.\nLook at it first.')
        out = H.triage.digest(eng, day, 'en_US', mode='generate', assistant=H.assistant(self.tmp, provider))
        self.assertEqual(out['status'], 'ok')
        self.assertEqual(out['digest']['data']['text'], 'Quiet day: one high case.\nLook at it first.')
        self.assertNotIn(SCANNER, provider.messages[1]['content'])
        again = H.triage.digest(eng, day)
        self.assertEqual(again['digest']['data']['text'], out['digest']['data']['text'])
        with self.assertRaises(ValueError):
            H.triage.digest(eng, '2026-13-45x')


class TestQuarantineView(H.IncidentCase):
    def test_networks_and_missing_db(self):
        view = H.collect.QuarantineView(self.ctx.quarantine_db)
        self.assertFalse(view.available)
        q = self.quarantine()
        q.begin()
        q.create_entry('203.0.113.0/24', 'net', T0 - 100, state='active', level=2, until=T0 + 100, since=T0 - 100)
        q.commit()
        q.close()
        view = H.collect.QuarantineView(self.ctx.quarantine_db)
        view.load_bad(T0)
        self.assertEqual(view.find('203.0.113.77')['addr'], '203.0.113.0/24')
        self.assertIsNone(view.find('198.51.100.1'))
        # read only: no write possible
        import sqlite3
        with self.assertRaises(sqlite3.OperationalError):
            view.store.db.execute("DELETE FROM entries")
        view.close()


if __name__ == '__main__':
    unittest.main()
