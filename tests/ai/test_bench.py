"""
Tests of ai/bench.py (the local AI bench runner): plans and rounds, round expansion, the objective quality checks,
the safety guard, the e-mail rate limit, ranking/recommendation/report and the import of earlier measurements.
No network, no Ollama: the database lives in a temporary directory.
"""

import json
import os
import subprocess
import sys
import tempfile
import shutil
import unittest

import ai_helpers  # noqa: F401  (import path)

from ai import bench


# the answer texts are in Portuguese on purpose: the bench evaluates the models in pt_BR (bench.LANG)
def result(scenario, wall=60.0, quality=3, fmt=True, lang=True, error=None, text='Resposta em português.', **extra):
    doc = {'scenario': scenario, 'wall_s': wall, 'quality': quality, 'fmt_first_ok': fmt, 'fmt_final_ok': fmt,
           'lang': {'ok': lang, 'pt': 10, 'en': 0}, 'error': error, 'text': text, 'attempts': 1, 'calls': [
               {'task': scenario, 'prompt_tokens': 700, 'gen_tokens': 120, 'prompt_tps': 14.0, 'gen_tps': 6.0,
                'load_s': 0.1, 'prompt_eval_s': 50.0}], 'main_prompt_tokens': 700, 'gen_tokens': 120}
    doc.update(extra)
    return doc


class BenchCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-bench-test-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, 'ai-bench.db')
        self.db = bench.connect(self.path)
        self.addCleanup(self.db.close)
        self._models = bench.bench_models
        bench.bench_models = lambda: ['small:1b', 'big:8b']
        self.addCleanup(setattr, bench, 'bench_models', self._models)

    def done_steps(self, plan_id, round_name, items):
        rid = self.db.execute('SELECT id FROM rounds WHERE plan_id = ? AND name = ?', (plan_id, round_name)).fetchone()[0]
        for i, (model, scenario, res) in enumerate(items, 1):
            self.db.execute("INSERT INTO steps (round_id, seq, kind, model, scenario, variant, params, status, result) "
                            "VALUES (?, ?, 'scenario', ?, ?, 0, ?, 'done', ?)",
                            (rid, i, model, scenario, json.dumps({'tag': round_name}), json.dumps(res)))
        self.db.execute("UPDATE rounds SET status = 'done' WHERE id = ?", (rid,))
        self.db.commit()


class TestPlans(BenchCase):
    def test_plans_and_rounds(self):
        pid = bench.create_plan(self.db, 'noturno')
        names = [r['name'] for r in self.db.execute('SELECT name FROM rounds WHERE plan_id = ? ORDER BY idx', (pid,))]
        self.assertEqual(names, list(bench.PLANS['noturno']))
        with self.assertRaises(ValueError):
            bench.create_plan(self.db, 'nope')

    def test_matrix_grouped_by_model(self):
        pid = bench.create_plan(self.db, 'matriz')
        plan = self.db.execute('SELECT * FROM plans WHERE id = ?', (pid,)).fetchone()
        rnd = self.db.execute('SELECT * FROM rounds WHERE plan_id = ?', (pid,)).fetchone()
        steps = bench.expand(self.db, plan, rnd)
        scen = [s for s in steps if s['kind'] == 'scenario']
        self.assertEqual(len(scen), 2 * len(bench.scenario_ids()))
        # one group per model, light first: unload, cold load, the scenarios, unload
        self.assertEqual(steps[0]['kind'], 'unload')
        self.assertEqual((steps[1]['kind'], steps[1]['model']), ('load', 'small:1b'))
        models = [s['model'] for s in scen]
        self.assertEqual(models, sorted(models, key=['small:1b', 'big:8b'].index))
        self.assertEqual(steps[-1], {'kind': 'unload', 'model': 'big:8b'})

    def test_repeat_uses_the_ranking(self):
        pid = bench.create_plan(self.db, 'noturno')
        self.done_steps(pid, 'matrix', [
            ('small:1b', 'explain_cve', result('explain_cve', wall=60, quality=3)),
            ('big:8b', 'explain_cve', result('explain_cve', wall=200, quality=3)),
            ('small:1b', 'console_ask', result('console_ask', wall=300, quality=1, fmt=False)),
            ('big:8b', 'console_ask', result('console_ask', wall=900, quality=3)),
        ])
        plan = self.db.execute('SELECT * FROM plans WHERE id = ?', (pid,)).fetchone()
        rnd = self.db.execute("SELECT * FROM rounds WHERE plan_id = ? AND name = 'repeat'", (pid,)).fetchone()
        steps = [s for s in bench.expand(self.db, plan, rnd) if s['kind'] == 'scenario']
        cve = [(s['model'], s['variant']) for s in steps if s['scenario'] == 'explain_cve']
        ask = [(s['model'], s['variant']) for s in steps if s['scenario'] == 'console_ask']
        self.assertEqual(sorted(cve), [('big:8b', 0), ('big:8b', 1), ('small:1b', 0), ('small:1b', 1), ('small:1b', 2)])
        self.assertEqual(sorted(ask), [('big:8b', 0), ('big:8b', 1), ('big:8b', 2), ('small:1b', 0), ('small:1b', 1)])

    def test_params_heaviest_with_mapreduce_variants(self):
        pid = bench.create_plan(self.db, 'noturno')
        self.done_steps(pid, 'matrix', [('big:8b', 'console_ask', result('console_ask', wall=900)),
                                        ('small:1b', 'explain_cve', result('explain_cve', wall=60))])
        plan = self.db.execute('SELECT * FROM plans WHERE id = ?', (pid,)).fetchone()
        rnd = self.db.execute("SELECT * FROM rounds WHERE plan_id = ? AND name = 'params'", (pid,)).fetchone()
        steps = [s for s in bench.expand(self.db, plan, rnd) if s['kind'] == 'scenario']
        variants = [s['params'] for s in steps if s['scenario'] == 'console_ask']
        self.assertTrue(any(v.get('nomr') for v in variants))
        self.assertTrue(any(v.get('num_ctx') == 4096 for v in variants))
        ctx = [s['params'].get('num_ctx', 8192) for s in steps if s['model'] == 'big:8b']
        self.assertEqual(ctx, sorted(ctx))          # same num_ctx together (no reload in between)


class TestQuality(unittest.TestCase):
    def test_invented_cve_port_and_citation(self):
        evidence = '{"cve": "CVE-2026-1111", "port": 443} [filterlog] section'
        ev = bench.evidence_check('A CVE-2026-1111 e a CVE-2025-9999 afetam a porta 443 e a porta 8080 '
                                  '[filterlog: 3 bloqueios] [inventada: x]', evidence)
        self.assertEqual(ev['invented_cves'], ['CVE-2025-9999'])
        self.assertEqual(ev['invented_ports'], ['8080'])
        self.assertEqual((ev['citations'], ev['invalid_citations']), (2, 1))

    def test_unsafe_advice(self):
        ev = bench.evidence_check('Sugiro desativar o firewall por alguns minutos.', '')
        self.assertTrue(ev['unsafe_advice'])

    def test_score(self):
        good = {'text': 'ok', 'fmt_final_ok': True, 'lang': {'ok': True}, 'evidence': {}}
        self.assertEqual(bench.quality(good), 3)
        self.assertEqual(bench.quality(dict(good, fmt_final_ok=False, lang={'ok': False})), 1)
        self.assertEqual(bench.quality(dict(good, evidence={'invented_cves': ['CVE-1']}, truncated=True)), 1)
        self.assertEqual(bench.quality(dict(good, error='timeout')), 0)

    def test_mask_hides_addresses(self):
        self.assertNotIn('192.0.2.7', bench.mask('origem 192.0.2.7 bloqueada'))
        self.assertNotIn('2001:db8::1', bench.mask('origem 2001:db8:0:0:0:0:0:1'))


class TestGuard(unittest.TestCase):
    def sample(self, loss=0.0, delay=3.0, load=1.0):
        return {'wan': {'name': 'WAN_C', 'loss': loss, 'delay_ms': delay}, 'load': [load, load, load]}

    def test_sustained_only(self):
        self.assertIsNone(bench.unsafe([self.sample(loss=5), self.sample(), self.sample()]))
        self.assertIn('loss', bench.unsafe([self.sample(loss=5)] * 3))
        self.assertIn('delay', bench.unsafe([self.sample(delay=80)] * 3))
        self.assertIn('load', bench.unsafe([self.sample(load=3.8)] * 3))
        self.assertIsNone(bench.unsafe([self.sample(load=3.8)] * 2))

    def test_active_wan_lowest_priority_up(self):
        gws = {'WAN_C': {'status': 'down', 'priority': '11', 'delay': '3.3 ms', 'loss': '0.0 %'},
               'WAN_B': {'status': 'none', 'priority': '12', 'delay': '12.9 ms', 'loss': '1.0 %'},
               'VPN': {'status': 'none', 'priority': '198', 'delay': '20 ms', 'loss': '0.0 %'}}
        self.assertEqual(bench.active_wan(gws), {'name': 'WAN_B', 'delay_ms': 12.9, 'loss': 1.0})


class TestMailer(BenchCase):
    def test_rate_limit_merges(self):
        sent = []
        clock = [10000.0]
        m = bench.Mailer(self.db, sender=lambda *a: sent.append(a), clock=lambda: clock[0])
        m.queue('OK', 'Round A finished', 'a')
        m.queue('OK', 'Round B finished', 'b')
        self.assertEqual(len(sent), 1)
        clock[0] += bench.MAIL_INTERVAL + 1
        m.queue('FALHA', 'Round C finished', 'c')
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[1][0], 'FALHA')
        self.assertIn('b', sent[1][2])

    def test_send_error_is_recorded(self):
        def boom(*_a):
            raise OSError('smtp down')
        bench.Mailer(self.db, sender=boom, clock=lambda: 1e9).queue('OK', 't', 'x')
        kinds = [r['kind'] for r in self.db.execute('SELECT kind FROM events')]
        self.assertIn('mail_error', kinds)


class TestReport(BenchCase):
    def test_recommend_and_report(self):
        pid = bench.create_plan(self.db, 'matriz')
        self.db.execute("UPDATE plans SET status = 'done' WHERE id = ?", (pid,))
        self.done_steps(pid, 'matrix', [
            ('small:1b', 'explain_cve', result('explain_cve', wall=60, text='Sem endereço 192.0.2.9 aqui.')),
            ('big:8b', 'explain_cve', result('explain_cve', wall=200)),
            ('small:1b', 'console_ask', result('console_ask', wall=500, quality=0, error='timeout', timeout=True)),
            ('big:8b', 'console_ask', result('console_ask', wall=1700, quality=1, fmt=False)),
        ])
        rec = bench.recommend(self.db, pid)
        self.assertEqual(rec['explain_cve']['model'], 'small:1b')
        self.assertEqual(rec['explain_cve']['mode'], 'sync')
        self.assertEqual(rec['console_ask']['model'], 'claudecode/fable')
        md = bench.report_md(self.db)
        self.assertIn('## 2. Result per scenario and model', md)
        self.assertIn('ai_routing explain_cve provider=ollama+model=small:1b', md)
        self.assertNotIn('192.0.2.9', md)
        self.assertEqual(len(bench.executive_summary(self.db, pid)), 10)

    def test_import(self):
        src = os.path.join(self.tmp, 'run.jsonl')
        with open(src, 'w') as handle:
            handle.write(json.dumps({'scenario': 'explain_cve', 'model': 'fable', 'text': 'A CVE-2026-1 é...',
                                     'format': {'ok': True}, 'lang': {'ok': True},
                                     'messages': [{'role': 'user', 'content': 'CVE-2026-1'}]}) + '\n')
            handle.write(json.dumps({'scenario': 'quicktest', 'model_name': 'small:1b', 'text': 'Oi.', 'wall_s': 9,
                                     'fmt_final_ok': True, 'lang': {'ok': True}}) + '\n')
            handle.write(json.dumps({'event': 'load'}) + '\n')
        res = bench.import_jsonl(src, db=self.db)
        self.assertEqual(res['imported'], 2)
        rows = bench.step_rows(self.db)
        self.assertEqual({r['model'] for r in rows}, {'fable', 'small:1b'})
        self.assertEqual([r['result']['quality'] for r in rows if r['model'] == 'fable'], [3])


class TestIsolation(unittest.TestCase):
    def test_isolate_in_a_child(self):
        """ the bench mode patches the pipeline of its own process only: run it in a child """
        code = r'''
import json, os, sys
sys.path.insert(0, %r)
from ai.providers.base import GenerateResult
from ai.providers import ollama
ollama.OllamaProvider.chat = lambda self, messages, stream=False, on_chunk=None, fmt=None: GenerateResult(
    text='MAPPING: none\nNenhum serviço corresponde a este componente.', model=self.model, duration_ms=1,
    prompt_tokens=10, completion_tokens=5, done_reason='stop')
from ai import bench, scenarios, jobqueue, audit, Assistant, Task, AIConfig
routing, rec = bench.isolate('tiny:1b', {'num_ctx': 4096})
r = scenarios.load_routing()
assert r['fallback']['provider'] == 'none'
assert all(e['model'] == 'tiny:1b' and e['mode'] == 'sync' and e['num_ctx'] == 4096 for e in r['scenarios'].values())
assert jobqueue.cache_get('x') is None
audit.AuditLog(path='/nonexistent/dir/ai.log').record(app='x')        # no-op, no write
cfg = AIConfig.from_dict({'ai': {'enabled': '1', 'provider': 'claudecode'}, 'claudecode': {'model': 'fable'},
                          'ollama': {'location': 'local', 'model': 'tiny:1b'}})
cfg.enabled = True
a = Assistant(cfg, app='t', inline=True)
task = Task('vuln_review_suggest', 'x', 'q', check_ctx={'first_values': ['none', 'unsure']})
res = a.ask(task, {'k': 'v'}, language='pt_BR')
print(json.dumps({'provider': res['provider'], 'calls': len(rec.calls), 'checks': rec.checks,
                  'num_ctx': rec.calls[0]['options'].get('num_ctx')}))
''' % ai_helpers.SCRIPTS
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', POLICYANALYZER_LIMITS='/nonexistent',
                   POLICYANALYZER_AI_ROUTING='/nonexistent')
        proc = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(doc['provider'], 'ollama')
        self.assertEqual(doc['calls'], 1)
        self.assertEqual(doc['num_ctx'], 4096)
        self.assertEqual(doc['checks'], [{'task': 'vuln_review_suggest', 'problems': []}])


if __name__ == '__main__':
    unittest.main()
