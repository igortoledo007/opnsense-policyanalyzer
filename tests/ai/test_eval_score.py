"""
Scoring of the per scenario evaluation (ai/evaluate.py): effectiveness components, performance, the composite with
its stored weights, indication and confidence, the comparison that only accepts firewall measurements, the
recommended route.  No network, no Ollama.
"""

import unittest

from eval_fakes import WORKSTATION, FIREWALL, EvalCase, doc

from ai import eval_fixtures, evaluate


class TestFixtures(unittest.TestCase):
    def test_every_scenario_has_a_synthetic_sample(self):
        from ai import scenarios
        for sid in scenarios.CATALOG:
            self.assertTrue(eval_fixtures.for_scenario(sid), sid)

    def test_samples_build_with_the_module_instructions(self):
        for fx in eval_fixtures.FIXTURES:
            task, data, _ctx = eval_fixtures.build(fx['id'])
            self.assertEqual(task.scenario, fx['scenario'])
            self.assertTrue(task.instructions)
            self.assertTrue(fx['facts'])

    def test_only_fictitious_addresses(self):
        import re
        for fx in eval_fixtures.FIXTURES:
            for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', eval_fixtures.haystack(fx['id'])):
                self.assertTrue(ip.startswith(('192.0.2.', '198.51.100.', '203.0.113.', '10.20.30.')), ip)


class TestThinkMode(unittest.TestCase):
    def test_classification(self):
        import os
        path = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'qwen3-thinking-2507.tmpl')
        with open(path) as fh:
            thinking = fh.read()
        self.assertEqual(evaluate.classify_think('qwen3:30b-a3b', {
            'capabilities': ['completion', 'thinking'], 'template': thinking,
            'model_info': {'general.finetune': 'Thinking'}}), 'forced')
        # the 2507 Instruct lists "thinking" but its template has no <think>: nothing to switch off
        self.assertEqual(evaluate.classify_think('qwen3:30b-a3b-instruct-2507-q4_K_M', {
            'capabilities': ['tools', 'thinking', 'completion'], 'template': "{{- '<|im_start|>assistant\\n' }}",
            'model_info': {'general.finetune': 'Instruct'}}), 'none')
        self.assertEqual(evaluate.classify_think('gpt-oss:20b', {'capabilities': ['thinking'],
                                                                 'template': '<|channel|>analysis'}), 'harmony')
        self.assertEqual(evaluate.think_overrides('harmony'), {'think': 'low', 'think_extra': evaluate.THINK_EXTRA})
        self.assertEqual(evaluate.classify_think('qwen2.5:3b', {'capabilities': ['completion']}), 'none')


class TestRunScore(unittest.TestCase):
    def test_good_answer_scores_100(self):
        eff, comps, _d = evaluate.score_run(doc('notify-quarantine'), 'notify-quarantine')
        self.assertEqual(eff, 100.0)
        self.assertTrue(all(v == 1.0 for v in comps.values()))

    def test_no_answer_is_zero(self):
        eff, comps, det = evaluate.score_run(doc('notify-quarantine', text='', error='ProviderError: timeout'),
                                             'notify-quarantine')
        self.assertEqual(eff, 0.0)
        self.assertIn('timeout', det['error'])

    def test_invented_address_and_port_cost_anchoring(self):
        text = GOOD_INVENTED = ('O endereço 203.0.113.45 e também 198.51.100.200 foram para a quarentena após '
                                'tentativas de login SSH na porta 2200.')
        self.assertTrue(GOOD_INVENTED)
        _eff, comps, det = evaluate.score_run(doc('notify-quarantine', text=text), 'notify-quarantine')
        self.assertEqual(comps['ancoragem'], 0.5)
        self.assertIn('198.51.100.200', det['anchoring']['invented'])
        self.assertIn('port 2200', det['anchoring']['invented'])

    def test_unsafe_advice_zeroes_anchoring(self):
        text = 'O 203.0.113.45 entrou em quarentena por login SSH. Sugiro desativar o firewall por um dia.'
        _eff, comps, _d = evaluate.score_run(doc('notify-quarantine', text=text), 'notify-quarantine')
        self.assertEqual(comps['ancoragem'], 0.0)

    def test_english_and_reasoning(self):
        text = ('Okay, the user wants a summary. Let me check the data. The address 203.0.113.45 was put in '
                'quarantine after SSH logins.')
        _eff, comps, _d = evaluate.score_run(doc('notify-quarantine', text=text), 'notify-quarantine')
        self.assertEqual(comps['idioma'], 0.0)
        self.assertEqual(comps['raciocinio'], 0.0)

    def test_correction_counts_less_than_first_try(self):
        _e, comps, _d = evaluate.score_run(doc('notify-quarantine', fmt_first=False), 'notify-quarantine')
        self.assertEqual(comps['validacao'], 0.6)
        _e, comps, _d = evaluate.score_run(doc('notify-quarantine', problems=['it has 9 sentences; write 1 to 3']),
                                           'notify-quarantine')
        self.assertEqual(comps['validacao'], 0.0)

    def test_truncated_answer_fails_the_size(self):
        _e, comps, _d = evaluate.score_run(doc('notify-quarantine', truncated=True), 'notify-quarantine')
        self.assertEqual(comps['formato'], 0.0)

    def test_structured_expectation(self):
        good = doc('map-unbound', text='MAPPING: a1b2c3d4\nO Unbound é o servidor DNS que carrega a biblioteca.')
        bad = doc('map-unbound', text='MAPPING: b5c6d7e8\nO servidor web usa o unbound para DNS.')
        _e, cg, _d = evaluate.score_run(good, 'map-unbound')
        _e, cb, _d = evaluate.score_run(bad, 'map-unbound')
        self.assertEqual(cg['cobertura'], 1.0)
        self.assertEqual(cb['cobertura'], 0.5)
        self.assertEqual(evaluate.decisive(good, 'vuln_review_suggest'), 'a1b2c3d4')

    def test_forbidden_claim(self):
        text = ('A origem 198.51.100.77 tentou a porta 8443 em varredura e não atingiu nenhum serviço exposto; ela '
                'será bloqueada em seguida.')
        _e, comps, det = evaluate.score_run(doc('focus-8443', text=text), 'focus-8443')
        self.assertEqual(det['coverage']['forbidden'], ['sera bloquead|foi colocad[oa] em quarentena|sera colocad|'
                                                        'vou bloquear'])
        self.assertEqual(comps['cobertura'], 0.75)


class TestAggregate(unittest.TestCase):
    def runs(self, effs, walls, scenario='notification_summary', decisive='ok', **metrics):
        out = []
        for e, w in zip(effs, walls):
            comps = {k: 1.0 for k, _w in evaluate.EFFECT_WEIGHTS if k != 'estabilidade'}
            out.append({'ok': 1 if e else 0, 'effectiveness': e, 'components': comps,
                        'metrics': dict({'wall_s': w, 'gen_tps': 6.0, 'first_token_s': 10.0, 'ram_gib': 2.0,
                                         'load_max': 1.5, 'decisive': decisive}, **metrics)})
        return out

    def test_composite_uses_the_weights(self):
        agg = evaluate.aggregate(self.runs([90, 90, 90], [30, 32, 34]), 'notification_summary', evaluate.WEIGHTS)
        self.assertAlmostEqual(agg['composite'], 0.7 * agg['effectiveness'] + 0.3 * agg['performance'], places=0)
        other = evaluate.aggregate(self.runs([90, 90, 90], [30, 32, 34]), 'notification_summary',
                                   {'effectiveness': 0.5, 'performance': 0.5})
        self.assertEqual(other['weights'], {'effectiveness': 0.5, 'performance': 0.5})

    def test_indicated_needs_effectiveness_time_and_runs(self):
        agg = evaluate.aggregate(self.runs([92, 90, 91], [30, 32, 34]), 'notification_summary', evaluate.WEIGHTS)
        self.assertEqual(agg['indication'], 'indicado')
        self.assertEqual(agg['confidence'], 'média')
        one = evaluate.aggregate(self.runs([92], [30]), 'notification_summary', evaluate.WEIGHTS)
        self.assertEqual(one['indication'], 'promissor')      # good but a single run: an indication only
        self.assertEqual(one['confidence'], 'baixa')
        slow = evaluate.aggregate(self.runs([92, 90, 91], [30, 32, 34], timeout=True), 'notification_summary',
                                  evaluate.WEIGHTS)
        self.assertNotEqual(slow['indication'], 'indicado')
        bad = evaluate.aggregate(self.runs([40, 0, 30], [30, 32, 34]), 'notification_summary', evaluate.WEIGHTS)
        self.assertEqual(bad['indication'], 'não indicado')

    def test_stability_penalises_disagreement(self):
        same = evaluate.aggregate(self.runs([85, 85, 85], [30, 30, 30], decisive='a'), 'explain_device',
                                  evaluate.WEIGHTS)
        runs = self.runs([85, 85, 85], [30, 30, 30])
        for r, d in zip(runs, ('a', 'b', 'c')):
            r['metrics']['decisive'] = d
        diff = evaluate.aggregate(runs, 'explain_device', evaluate.WEIGHTS)
        self.assertGreater(same['components']['estabilidade'], diff['components']['estabilidade'])
        self.assertGreater(same['effectiveness'], diff['effectiveness'])

    def test_performance_against_the_budget(self):
        fast = evaluate.perf_components('explain_cve', 60, 80, 8, 10, 3, 1)
        slow = evaluate.perf_components('explain_cve', 590, 640, 1, 200, 20, 3.4)
        self.assertEqual(fast['p50'], 1.0)
        self.assertEqual(slow['p95'], 0.0)
        self.assertGreater(evaluate.weighted(fast, evaluate.PERF_WEIGHTS), 90)
        self.assertLess(evaluate.weighted(slow, evaluate.PERF_WEIGHTS), 20)


class TestHistory(EvalCase):
    def test_only_firewall_measurements_are_compared(self):
        evaluate.ensure(self.db)
        self.evaluation('fw:3b', [doc('notify-quarantine'), doc('notify-quarantine')], FIREWALL)
        self.evaluation('workstation:3b', [doc('notify-quarantine'), doc('notify-quarantine')], WORKSTATION)
        rows, discarded = evaluate.history(self.db)
        self.assertEqual({r['model'] for r in rows}, {'fw:3b'})
        self.assertEqual([d['model'] for d in discarded], ['workstation:3b'])
        self.assertIn('outside the firewall', discarded[0]['discarded'])

    def test_other_hardware_is_discarded(self):
        self.evaluation('old:3b', [doc('notify-quarantine')], dict(FIREWALL, cpu='Intel(R) Celeron J4125'))
        self.evaluation('new:3b', [doc('notify-quarantine')], FIREWALL)
        rows, discarded = evaluate.history(self.db)
        self.assertEqual([r['model'] for r in rows], ['new:3b'])
        self.assertIn('hardware other than the current one', discarded[0]['discarded'])

    def test_reevaluation_marks_the_latest(self):
        self.evaluation('m:1b', [doc('notify-quarantine', text='curto demais')])
        self.evaluation('m:1b', [doc('notify-quarantine'), doc('notify-quarantine')])
        latest = self.db.execute("SELECT COUNT(*) FROM eval_results WHERE model = 'm:1b' AND latest = 1").fetchone()[0]
        total = self.db.execute("SELECT COUNT(*) FROM eval_results WHERE model = 'm:1b'").fetchone()[0]
        self.assertEqual((latest, total), (1, 2))
        rows, _d = evaluate.history(self.db)
        self.assertEqual(rows[0]['n'], 2)

    def test_recommendation_and_two_model_route(self):
        self.evaluation('a:3b', [doc('notify-quarantine', wall=20), doc('notify-quarantine', wall=22)])
        self.evaluation('b:8b', [doc('notify-quarantine', wall=200, text='Resposta curta sem os fatos.'),
                                 doc('notify-quarantine', wall=210, text='Resposta curta sem os fatos.')])
        rec = evaluate.recommend(evaluate.history(self.db)[0])
        r = rec['per_scenario']['notification_summary']
        self.assertEqual(r['model'], 'a:3b')
        self.assertEqual(r['mode'], 'sync')
        self.assertIn('a:3b', rec['pair'])
        self.assertIsNone(rec['per_scenario']['explain_cve']['model'])


if __name__ == '__main__':
    unittest.main()
