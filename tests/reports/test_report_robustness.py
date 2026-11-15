"""
Problems of 2026-11-09: (1) the executive summary of the 6 h report carried the reasoning of qwen3 in English;
(2) "configctl pa_reports send weekly" hit the 120 s of configd while the AI summary took ~30 min, and the
manual run looked dead (nothing in the log or the history until the end). Covers the publish guard of aisum
(new attempt, deterministic text, never English/reasoning), the detached scheduled run (start/lock/log/history)
and the time limit of the AI part. FAKE SMTP and FAKE AI only.
Run: cd tests/reports && TMPDIR=<scratch> /usr/bin/python3 -m unittest test_report_robustness -v
"""

import json
import os

import rhelpers  # noqa: F401  (import path)
import vhelpers
from rhelpers import ReportsCase

from reports import aisum, cli, deliver, settings, store  # noqa: E402

LEAK = ("Okay, let's tackle this. The user wants an executive summary in Brazilian Portuguese for a security report. "
        "First, I need to check the data. Wait, the user said 3 to 5 sentences. Let me count the blocked "
        "connections.")
PT = ("Período com pontos de atenção. Foram bloqueadas 39 conexões de entrada na WAN e há 2 vulnerabilidades P1. "
      "Sugiro revisar as vulnerabilidades P1 no OPNsense.")


class Sequence(vhelpers.FakeProvider):
    """ one answer per call, the last one repeats """

    def __init__(self, answers):
        super().__init__(answers[0])
        self.answers = list(answers)

    def chat(self, messages, stream=False, on_chunk=None):
        from ai.providers.base import GenerateResult
        self.calls.append(messages)
        text = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return GenerateResult(text, 'qwen3:30b-a3b', 5)


def assistant(answers, tmp):
    a = vhelpers.assistant('x', tmp=tmp)
    a._provider = Sequence(answers)
    a.routing = {'version': 1, 'scenarios': {}, 'fallback': {'provider': 'none'}}      # global route: retries 0
    return a


class TestPublishGuard(ReportsCase):
    def test_reasoning_never_reaches_the_report(self):
        a = assistant([LEAK], self.tmp)
        summary = aisum.executive({'kind': '6h', 'cves': {'counts': {'P1': 1}}}, 'pt_BR', assistant=a)
        self.assertFalse(summary['ai'])
        self.assertNotIn('user', summary['text'])
        self.assertIn('crítico', summary['text'])
        self.assertEqual(summary['info']['status'], 'rejected')
        self.assertIn('descartada', summary['note'])
        self.assertEqual(len(a.provider.calls), 2)          # the route had no retry: one new attempt in aisum

    def test_new_attempt_answers_in_portuguese(self):
        a = assistant([LEAK, PT], self.tmp)
        summary = aisum.executive({'kind': '6h'}, 'pt_BR', assistant=a)
        self.assertTrue(summary['ai'])
        self.assertEqual(summary['text'], PT)

    def test_preamble_cut_keeps_the_final_answer(self):
        a = assistant([LEAK + '\n\n' + PT], self.tmp)
        summary = aisum.executive({'kind': '6h'}, 'pt_BR', assistant=a)
        self.assertTrue(summary['ai'])
        self.assertEqual(summary['text'], PT)

    def test_lone_closing_think(self):
        a = assistant([LEAK + '\n</think>\n\n' + PT], self.tmp)
        self.assertEqual(aisum.executive({'kind': 'weekly'}, 'pt_BR', assistant=a)['text'], PT)

    def test_publishable(self):
        self.assertEqual(aisum.publishable(PT, 'pt_BR'), [])
        self.assertTrue(aisum.publishable(LEAK, 'pt_BR'))
        self.assertTrue(aisum.publishable('Quiet period. 39 inbound connections were blocked on the WAN and there '
                                          'is nothing else to review.', 'pt_BR'))

    def test_notification_is_protected(self):
        a = assistant([LEAK], self.tmp)
        ev = [{'type': 'quarantine', 'severity': 'high', 'title': 'Nova origem em quarentena', 'data': {}}]
        out = aisum.notification(ev, 'pt_BR', assistant=a)
        self.assertFalse(out['ai'])
        self.assertIn('Nova origem em quarentena', out['text'])

    def test_the_ai_part_is_bounded(self):
        seen = []

        class Recorder(object):
            config = type('C', (), {'enabled': True})()

            def ask(self, task, data, **kw):
                seen.append(kw.get('max_seconds'))
                return {'text': PT, 'model': 'm', 'provider': 'ollama'}
        aisum.executive({'kind': 'weekly'}, 'pt_BR', assistant=Recorder())
        aisum.executive({'kind': '6h'}, 'pt_BR', assistant=Recorder())
        self.assertAlmostEqual(seen[0], aisum.AI_SECONDS['weekly'], delta=5)
        self.assertAlmostEqual(seen[1], aisum.AI_SECONDS['6h'], delta=5)
        self.assertTrue(all(s and s <= 1800 for s in seen))


class TestDetachedSend(ReportsCase):
    def enable(self):
        cfg = settings.load()
        cfg['email'].update({'mode': 'own', 'host': '127.0.0.1', 'port': self.smtp.port, 'security': 'none',
                             'verify': True, 'username': 'relay@example.test', 'sender': 'fw@example.test',
                             'recipients': ['ops@example.test']})
        cfg['report'].update({'enabled': True, 'weekly': True, 'ai_summary': False})
        settings.save(cfg)

    def log(self):
        with open(self.path('reports.log')) as handle:
            return [json.loads(line) for line in handle if line.startswith('{')]

    def test_send_returns_at_once(self):
        spawned = []
        res = deliver.start_report('weekly', spawn=lambda argv, log: spawned.append((argv, log)) or 4242)
        self.assertEqual(res['status'], 'started')
        self.assertEqual(res['pid'], 4242)
        argv, log = spawned[0]
        self.assertEqual(argv[-2:], ['send_run', 'weekly'])
        self.assertTrue(argv[1].endswith(os.path.join('reports', 'cli.py')))
        self.assertEqual(log, self.path('reports.log'))
        self.assertEqual(self.log()[-1]['event'], 'started')

    def test_cli_send_detaches(self):
        calls = []
        original = deliver.start_report
        deliver.start_report = lambda kind: calls.append(kind) or {'status': 'started', 'pid': 1}
        try:
            self.assertEqual(cli.run(['send', 'weekly'])['status'], 'started')
        finally:
            deliver.start_report = original
        self.assertEqual(calls, ['weekly'])

    def test_second_start_while_running(self):
        fd = deliver._try_lock('weekly')
        os.write(fd, b'777\n')
        try:
            res = deliver.start_report('weekly', spawn=lambda argv, log: self.fail('spawned twice'))
            self.assertEqual(res['status'], 'running')
            self.assertEqual(res['pid'], 777)
            self.assertEqual(deliver.run_report('weekly')['status'], 'running')
            self.assertEqual(deliver.running_reports(), {'weekly': 777})
        finally:
            os.close(fd)
        self.assertEqual(deliver.running_reports(), {})

    def test_run_sends_records_and_logs(self):
        self.enable()
        res = deliver.run_report('weekly', smtp_factory=self.smtp.factory())
        self.assertEqual(res['status'], 'sent', res)
        self.assertEqual(len(self.smtp.messages), 1)
        last = self.log()[-1]
        self.assertEqual((last['event'], last['kind'], last['status']), ('finished', 'weekly', 'sent'))
        self.assertIn('seconds', last)

    def test_unexpected_error_goes_to_history_and_log(self):
        self.enable()
        original = deliver.build_report

        def boom(*a, **k):
            raise RuntimeError('collect exploded')
        deliver.build_report = boom
        try:
            res = deliver.run_report('weekly', smtp_factory=self.smtp.factory())
        finally:
            deliver.build_report = original
        self.assertEqual(res['status'], 'failed')
        db = store.connect(readonly=True)
        _total, rows = store.messages(db, kind='report')
        db.close()
        self.assertEqual(rows[0]['status'], 'failed')
        self.assertIn('collect exploded', rows[0]['error'])
        events = [e['event'] for e in self.log()]
        self.assertIn('traceback', events)
        self.assertEqual(events[-1], 'finished')
        self.assertEqual(deliver.running_reports(), {})      # the lock is released


if __name__ == '__main__':
    import unittest
    unittest.main()
