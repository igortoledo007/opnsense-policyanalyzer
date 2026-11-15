"""
The "avaliacao" plan on the bench runner (ai/bench.py + ai/evaluate.py): rounds per model, steps (simulated
download, setup, fixtures x repetitions), skips, early stop, resuming, the e-mails with the PDF attached and the
pipeline of one evaluation step against a fake Ollama.  No real model, no e-mail, no write outside a temp dir.
"""

import json
import os
import subprocess
import sys
import unittest

from eval_fakes import FIREWALL, EvalCase, doc

import ai_helpers
from ai import bench, eval_fixtures, evaluate


class TestPlan(EvalCase):
    def test_rounds_follow_the_catalog_and_options(self):
        self.installed = {'other:7b': {'digest': 'x'}}
        pid = bench.create_plan(self.db, 'avaliacao', ['reps=2'])
        names = [r['name'] for r in self.db.execute('SELECT name FROM rounds WHERE plan_id = ? ORDER BY idx', (pid,))]
        self.assertEqual(names[0], 'eval:qwen3:30b-a3b-instruct-2507-q4_K_M')
        self.assertEqual(names[-1], 'eval:other:7b')                 # installed outside the catalog: at the end
        self.assertEqual(evaluate.options(self.db, pid)['reps'], 2)
        plan = self.plan(['only=m:1b,n:2b'])
        names = [r['name'] for r in self.db.execute('SELECT name FROM rounds WHERE plan_id = ?', (plan['id'],))]
        self.assertEqual(names, ['eval:m:1b', 'eval:n:2b'])

    def test_invalid_option_creates_nothing(self):
        saved = bench.spawn_runner
        bench.spawn_runner = lambda: True
        try:
            res = bench.cmd_start('avaliacao', db=self.db, tokens=['reps=99'])
        finally:
            bench.spawn_runner = saved
        self.assertEqual(res['status'], 'error')
        self.assertIsNone(self.db.execute("SELECT id FROM plans WHERE name = 'avaliacao'").fetchone())

    def test_missing_model_is_pulled_first_and_reps_are_rep_major(self):
        plan = self.plan(['only=m:1b', 'reps=2'])
        rnd = self.db.execute('SELECT * FROM rounds WHERE plan_id = ?', (plan['id'],)).fetchone()
        steps = bench.expand(self.db, plan, rnd)
        self.assertEqual([s['kind'] for s in steps[:4]], ['pull', 'unload', 'load', 'eval_setup'])
        evals = [s for s in steps if s['kind'] == 'eval']
        self.assertEqual(len(evals), 2 * len(eval_fixtures.FIXTURES))
        reps = [s['params']['rep'] for s in evals]
        self.assertEqual(reps, sorted(reps))                          # all of rep 1, then rep 2 (no prompt cache)
        self.assertEqual(steps[-1], {'kind': 'unload', 'model': 'm:1b'})
        ev = self.db.execute('SELECT * FROM eval_models').fetchone()
        self.assertEqual((ev['model'], ev['status'], ev['reps']), ('m:1b', 'running', 2))

    def test_think_variant_and_scenario_filter(self):
        with self.assertRaises(ValueError):
            evaluate.parse_options(['think=maybe'])
        with self.assertRaises(ValueError):
            evaluate.parse_options(['scenarios=nao_existe'])
        self.installed = {'m:1b': {'digest': 'sha256:abc'}}
        self.evaluation('m:1b', [doc('notify-quarantine')], digest='sha256:abc')   # without reasoning: done
        plan = self.plan(['only=m:1b', 'reps=2', 'think=on', 'scenarios=console_explain_rule,anomaly_host'])
        rnd = self.db.execute('SELECT * FROM rounds WHERE plan_id = ?', (plan['id'],)).fetchone()
        steps = bench.expand(self.db, plan, rnd)                      # a separate history: not skipped
        evals = [s for s in steps if s['kind'] == 'eval']
        self.assertEqual(len(evals), 4)
        self.assertEqual({s['scenario'] for s in evals}, {'console_explain_rule', 'anomaly_host'})
        self.assertTrue(all(s['model'] == 'm:1b' for s in evals))
        p = evals[0]['params']
        self.assertEqual((p['think'], p['timeout'], p['num_ctx']), ('on', 1800, 16384))
        ev = self.db.execute('SELECT model FROM eval_models ORDER BY id DESC').fetchone()
        self.assertEqual(ev['model'], 'm:1b@think')

    def test_installed_model_skips_the_download_and_an_evaluated_one_is_skipped(self):
        self.installed = {'m:1b': {'digest': 'sha256:abc'}}
        plan = self.plan(['only=m:1b'])
        rnd = self.db.execute('SELECT * FROM rounds WHERE plan_id = ?', (plan['id'],)).fetchone()
        steps = bench.expand(self.db, plan, rnd)
        self.assertEqual(steps[0]['kind'], 'unload')
        self.db.execute('DELETE FROM eval_models')
        self.evaluation('m:1b', [doc('notify-quarantine')], digest='sha256:abc')
        self.assertEqual(bench.expand(self.db, plan, rnd), [])        # same digest, fixtures and reps: nothing to do
        plan2 = self.plan(['only=m:1b', 'reeval'])
        rnd2 = self.db.execute('SELECT * FROM rounds WHERE plan_id = ?', (plan2['id'],)).fetchone()
        self.assertTrue(bench.expand(self.db, plan2, rnd2))           # reeval: measured again

    def test_skip_after_a_failed_download_and_early_stop(self):
        plan = self.plan()
        rnd = self.db.execute('SELECT * FROM rounds WHERE plan_id = ?', (plan['id'],)).fetchone()
        bench.add_steps(self.db, rnd['id'], bench.expand(self.db, plan, rnd))
        steps = self.db.execute('SELECT * FROM steps WHERE round_id = ? ORDER BY seq', (rnd['id'],)).fetchall()
        first_eval = [s for s in steps if s['kind'] == 'eval'][0]
        self.assertIsNone(evaluate.should_skip(self.db, first_eval))
        eid = self.db.execute('SELECT id FROM eval_models').fetchone()[0]
        for i in range(2):
            evaluate.record_run(self.db, dict(first_eval, id=900 + i), doc(json.loads(first_eval['params'])['fixture'],
                                                                           text='', error='timeout'), eid)
        self.assertIn('early stop', evaluate.should_skip(self.db, first_eval))
        self.db.execute("UPDATE steps SET status = 'error' WHERE kind = 'pull'")
        self.assertEqual(evaluate.should_skip(self.db, steps[2]), 'model download failed')


class TestPull(unittest.TestCase):
    def setUp(self):
        self.saved = (evaluate.tags, evaluate._run_json)
        self.addCleanup(self.restore)

    def restore(self):
        evaluate.tags, evaluate._run_json = self.saved

    def test_download_through_the_change_action(self):
        calls = []
        have = {}
        script = [{'status': 'started', 'job': 'job-1'},
                  {'status': 'ok', 'job': {'id': 'job-1', 'status': 'running', 'bytes_done': 10}},
                  {'status': 'ok', 'job': {'id': 'job-1', 'status': 'done'}}]

        def run(argv, timeout=120):
            calls.append(argv[2:])
            out = script.pop(0)
            if out.get('job', {}).get('status') == 'done' if isinstance(out.get('job'), dict) else False:
                have['m:1b'] = {'size': 2 * 2 ** 30, 'digest': 'sha256:new'}
            return out
        evaluate._run_json = run
        evaluate.tags = lambda: dict(have)
        res = evaluate.step_pull({'model': 'm:1b'}, sleep=lambda s: None)
        self.assertEqual(calls[0], ['apply', 'pull_model', 'm:1b', 'custom=yes', 'large=yes'])
        self.assertEqual(calls[1], ['status', 'setup_job'])
        self.assertEqual((res['digest'], res['size_gib']), ('sha256:new', 2.0))

    def test_busy_setup_is_transient_and_failure_is_not(self):
        evaluate.tags = lambda: {}
        evaluate._run_json = lambda argv, timeout=120: {'status': 'error', 'message': 'another setup job is running '
                                                                                     '(lock held)'}
        with self.assertRaises(RuntimeError) as ctx:
            evaluate.step_pull({'model': 'm:1b'}, sleep=lambda s: None)
        self.assertTrue(bench.transient_error(str(ctx.exception)))
        evaluate._run_json = lambda argv, timeout=120: {'status': 'error', 'message': 'not enough space'}
        with self.assertRaises(RuntimeError) as ctx:
            evaluate.step_pull({'model': 'm:1b'}, sleep=lambda s: None)
        self.assertFalse(bench.transient_error(str(ctx.exception)))

    def test_installed_model_is_not_downloaded(self):
        evaluate.tags = lambda: {'m:1b': {'size': 2 ** 30, 'digest': 'd'}}
        evaluate._run_json = lambda *a, **k: self.fail('no download expected')
        self.assertTrue(evaluate.step_pull({'model': 'm:1b'})['already'])


class TestRunner(EvalCase):
    def setUp(self):
        super().setUp()
        self.bsaved = {k: getattr(bench, k) for k in ('unload_all', 'SAMPLE_SECONDS', 'production_busy', 'unsafe')}
        bench.unload_all = lambda: None
        bench.SAMPLE_SECONDS = 0
        bench.unsafe = lambda samples: None
        bench.production_busy = lambda check_cpu=True, exclude=None: None
        self.addCleanup(lambda: [setattr(bench, k, v) for k, v in self.bsaved.items()])
        self.sent = []
        self.runner = bench.Runner(os.path.join(self.tmp, 'ai-bench.db'))
        self.addCleanup(self.runner.db.close)
        self.runner.mailer = bench.Mailer(self.runner.db, sender=self.capture, clock=lambda: 0)
        self.runner.run_child = self.child
        self.executed = []

    def capture(self, status, title, text, attachments=None):
        self.sent.append({'status': status, 'title': title, 'text': text, 'attachments': attachments or []})

    def child(self, step):
        self.executed.append(step['kind'])
        params = json.loads(step['params'] or '{}')
        if step['kind'] == 'pull':
            self.installed['m:1b'] = {'digest': 'sha256:abc', 'size': 2 ** 31}
            return {'already': False, 'model': 'm:1b', 'seconds': 3.0, 'size_gib': 2.0, 'digest': 'sha256:abc'}, None
        if step['kind'] == 'eval_setup':
            return {'model': 'm:1b', 'digest': 'sha256:abc', 'ram_gib': 2.0, 'think_mode': 'none',
                    'hardware': FIREWALL, 'routes': {'short': {'num_ctx': 8192}}}, None
        if step['kind'] == 'eval':
            return doc(params['fixture']), None
        return {}, None

    def test_full_model_round_then_final_with_pdfs(self):
        pid = bench.create_plan(self.runner.db, 'avaliacao', ['only=m:1b', 'reps=1'])
        self.runner.loop()
        db = self.runner.db
        self.assertEqual(db.execute('SELECT status FROM plans WHERE id = ?', (pid,)).fetchone()[0], 'done')
        self.assertEqual(self.executed.count('eval'), len(eval_fixtures.FIXTURES))
        self.assertEqual(self.executed[0], 'pull')
        ev = db.execute('SELECT * FROM eval_models').fetchone()
        self.assertEqual((ev['status'], ev['latest'], ev['digest']), ('done', 1, 'sha256:abc'))
        self.assertTrue(os.path.isfile(ev['pdf_path']))
        n = db.execute('SELECT COUNT(*) FROM eval_results WHERE eval_id = ?', (ev['id'],)).fetchone()[0]
        self.assertEqual(n, len({f['scenario'] for f in eval_fixtures.FIXTURES}))
        # start (no attachment), the model (its PDF) and the final one (final PDF); the clock never moves, so the
        # interval merges them: every PDF is still attached
        attached = [os.path.basename(a[0]) for m in self.sent for a in [(x[0],) for x in m['attachments']]]
        self.assertTrue(any(a.startswith('avaliacao-ia-m_1b-') for a in attached), attached)
        self.assertTrue(any(a.startswith('avaliacao-ia-final-') for a in attached), attached)
        texts = '\n'.join(m['text'] for m in self.sent)
        self.assertIn('I started the per scenario evaluation plan', texts)
        self.assertIn('Best so far', texts)
        self.assertIn('Recommended route', texts)
        for m in self.sent:
            for name, data, mime in m['attachments']:
                self.assertTrue(data.startswith(b'%PDF-'))
                self.assertEqual(mime, 'application/pdf')

    def test_resume_after_a_stop_does_not_repeat_runs(self):
        bench.create_plan(self.runner.db, 'avaliacao', ['only=m:1b', 'reps=1'])
        original = self.child
        count = []

        def stop_after(step):
            count.append(1)
            if len(count) == 8:
                self.runner.stop.set()
                return None, 'stopped'
            return original(step)
        self.runner.run_child = stop_after
        self.runner.loop()
        db = self.runner.db
        done_before = db.execute('SELECT COUNT(*) FROM eval_runs').fetchone()[0]
        self.assertGreater(done_before, 0)
        pending = db.execute("SELECT COUNT(*) FROM steps WHERE status = 'pending'").fetchone()[0]
        self.assertGreater(pending, 0)
        runner2 = bench.Runner(os.path.join(self.tmp, 'ai-bench.db'))
        self.addCleanup(runner2.db.close)
        runner2.mailer = bench.Mailer(runner2.db, sender=self.capture, clock=lambda: 0)
        runner2.run_child = self.child
        runner2.loop()
        runs = runner2.db.execute('SELECT COUNT(*) FROM eval_runs').fetchone()[0]
        self.assertEqual(runs, len(eval_fixtures.FIXTURES))           # each fixture scored once
        self.assertEqual(runner2.db.execute("SELECT status FROM eval_models").fetchone()[0], 'done')


class TestMail(EvalCase):
    def test_failed_send_keeps_the_pdf_and_merge_attaches_all(self):
        pdf1 = os.path.join(self.tmp, 'a.pdf')
        pdf2 = os.path.join(self.tmp, 'b.pdf')
        for p in (pdf1, pdf2):
            with open(p, 'wb') as fh:
                fh.write(b'%PDF-1.4 x')
        sent, fail = [], [True]

        def sender(status, title, text, attachments=None):
            if fail[0]:
                raise OSError('smtp down')
            sent.append((title, [a[0] for a in attachments or []]))
        clock = [0]
        m = bench.Mailer(self.db, sender=sender, clock=lambda: clock[0])
        m.queue('OK', 'Modelo avaliado: a', 'texto a', [pdf1])
        self.assertEqual(len(bench.meta_get(self.db, 'mail_pending')), 1)     # kept after the failure
        fail[0] = False
        m.queue('OK', 'Modelo avaliado: b', 'texto b', [pdf2])                 # inside the interval: waits
        self.assertEqual(sent, [])
        clock[0] = bench.MAIL_INTERVAL + 1
        self.assertTrue(m.flush())
        self.assertEqual(sorted(sent[0][1]), ['a.pdf', 'b.pdf'])

    def test_send_mail_builds_the_attachment(self):
        from reports import deliver, mailer
        captured = {}
        saved = (deliver.channel, mailer.send)
        deliver.channel = lambda cfg: {'sender': 'fw@example.org', 'recipients': ['admin@example.org']}
        mailer.send = lambda msg, ch, **k: captured.setdefault('msg', msg)
        try:
            bench.send_mail('OK', 'Modelo avaliado: m', 'texto', [('x.pdf', b'%PDF-1.4 x', 'application/pdf')])
        finally:
            deliver.channel, mailer.send = saved
        msg = captured['msg']
        parts = [p for p in msg.iter_attachments()]
        self.assertEqual(parts[0].get_filename(), 'x.pdf')
        self.assertEqual(parts[0].get_content_type(), 'application/pdf')


PROBE = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
from ai import bench, evaluate, AIConfig
from ai.providers import ollama as prov
bench.OLLAMA_URL = sys.argv[2]
prov.LOCAL_URL = sys.argv[2]
evaluate.config_factory = lambda: AIConfig.from_dict({'ai': {'enabled': '1', 'provider': 'ollama', 'anonymize': '1'},
                                                      'ollama': {'location': 'local', 'model': 'm:1b'}})
bench._sh = lambda cmd, timeout=20: ''
doc = evaluate.step_eval({'model': 'm:1b', 'params': {'fixture': sys.argv[3], 'rep': 1, 'timeout': 60}})
print(json.dumps({'text': doc['text'], 'error': doc['error'], 'scenario': doc['scenario'], 'think': doc['think_mode'],
                  'blocked': doc['blocked_writes'], 'calls': len(doc['calls'])}))
'''


class TestStepPipeline(unittest.TestCase):
    """ one "eval" step through the real Assistant (anonymization, validation) against a fake Ollama, in a child
    process like on the firewall (the step child patches modules and blocks file writes) """

    def test_eval_step_against_fake_ollama(self):
        good = ('O endereço 203.0.113.45 foi colocado em quarentena nível 3 por dois dias após tentativas de login '
                'SSH. Sugiro revisar o acesso SSH pela WAN.')

        def answer(body):
            # the anonymizer replaced the address in the prompt: answer with the placeholder it sent
            import re
            prompt = ' '.join(m['content'] for m in body.get('messages') or [])
            ph = re.search(r'(IP_\w+|<[A-Z_]+\d*>|\bip-[\w-]+)', prompt)
            return good.replace('203.0.113.45', ph.group(1)) if ph and '203.0.113.45' not in prompt else good
        with ai_helpers.FakeOllama(answer=answer, models=('m:1b',),
                                   show={'capabilities': ['completion'], 'template': '{{ .Prompt }}'}) as fake:
            proc = subprocess.run([sys.executable, '-c', PROBE, ai_helpers.SCRIPTS, fake.url, 'notify-quarantine'],
                                  capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        out = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertIsNone(out['error'])
        self.assertEqual(out['scenario'], 'notification_summary')
        self.assertEqual(out['think'], 'none')
        self.assertIn('203.0.113.45', out['text'])
        self.assertGreaterEqual(out['calls'], 1)
        eff, _c, _d = evaluate.score_run({'scenario': out['scenario'], 'text': out['text'], 'problems_final': []},
                                         'notify-quarantine')
        self.assertGreaterEqual(eff, 90)


if __name__ == '__main__':
    unittest.main()
