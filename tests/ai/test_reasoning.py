"""
Leaked reasoning of thinking models (qwen3:30b-a3b = Qwen3-30B-A3B-Thinking-2507 on the firewall, 2026-11-09):
the 6 h report e-mail carried "Okay, let's tackle this. The user wants an executive summary in Brazilian
Portuguese ..." instead of the summary. Covers the detector, the cut of the preamble, the lone </think> of the
template, the strict language check of the "publish" scenarios, the fresh new attempt, the rejection
(AnswerRejected -> fallback route -> deterministic text of the caller) and the time limit. No network.
"""

import unittest

import ai_helpers  # noqa: F401  (import path)
from ai_fakes import Factory, FakeProvider, TempDirCase, config, routing

from ai import AnswerRejected, Task, validate

LEAK = ("Okay, let's tackle this. The user wants an executive summary in Brazilian Portuguese for a security report "
        "of an OPNsense firewall. First, I need to check the data. The traffic section shows 1520 blocked inbound "
        "connections. Wait, the user said 3 to 5 sentences. Let me count the quarantine entries: 4 new sources. "
        "So the summary should start with the overall state. Hmm, there are no P1 vulnerabilities, so the state is "
        "attention. Wait, the user said to end with a suggestion")
PT_FINAL = ("Período com pontos de atenção. Foram bloqueadas 1520 conexões de entrada na WAN e 4 origens novas "
            "entraram em quarentena. Não há vulnerabilidades P1 no inventário. Sugiro revisar as origens em "
            "quarentena no OPNsense.")
EN_ADVICE = ("First, check the rule order on the WAN interface. The rule that allows port 443 is above the block "
             "rule, so it matches first. You should move it below and make sure that the alias is correct.")


class TestDetector(unittest.TestCase):
    def test_the_email_of_2026_11_09_is_reasoning(self):
        self.assertTrue(validate.leaked_reasoning(LEAK))
        problems = validate.check('report_summary', LEAK, 'pt_BR')
        self.assertIn(validate.REASONING_PROBLEM, problems)
        self.assertTrue(validate.hard_problems(problems))

    def test_portuguese_answers_are_not_reasoning(self):
        self.assertFalse(validate.leaked_reasoning(PT_FINAL))
        self.assertEqual(validate.check('report_summary', PT_FINAL, 'pt_BR'), [])
        brief = 'Situação estável: 12 bloqueios na última hora e nenhum alerta crítico do Suricata.'
        self.assertEqual(validate.check('war_room_brief', brief, 'pt_BR'), [])

    def test_english_advice_is_not_reasoning(self):
        self.assertFalse(validate.leaked_reasoning(EN_ADVICE))
        self.assertEqual(validate.check_reasoning(EN_ADVICE), [])

    def test_preamble_cut_when_a_final_answer_follows(self):
        text, leaked = validate.strip_reasoning(LEAK + '.\n\n' + PT_FINAL, 'pt_BR')
        self.assertTrue(leaked)
        self.assertEqual(text, PT_FINAL)
        labelled = LEAK + '.\n\nResposta final:\n' + PT_FINAL
        self.assertEqual(validate.strip_reasoning(labelled, 'pt_BR')[0], PT_FINAL)

    def test_reasoning_only_is_kept_and_flagged(self):
        text, leaked = validate.strip_reasoning(LEAK, 'pt_BR')
        self.assertTrue(leaked)
        self.assertEqual(text, LEAK)

    def test_lone_closing_think_of_the_thinking_template(self):
        # the template ends with "<|im_start|>assistant\n<think>\n": the answer only has the closing tag
        self.assertEqual(validate.strip_think(LEAK + '\n</think>\n\n' + PT_FINAL), PT_FINAL)
        self.assertEqual(validate.strip_think('<think>a</think>B'), 'B')
        self.assertEqual(validate.strip_think('texto <think>cortado'), 'texto')

    def test_strict_language_of_published_texts(self):
        mixed = ('O firewall bloqueou 1520 conexões na WAN, que são 4 origens novas com mais tráfego. The next step '
                 'is to review the quarantine, which has the new sources.')
        self.assertEqual(validate.check_language(mixed, 'pt_BR'), [])          # mixed: tolerated in the GUI
        self.assertTrue(validate.check_language(mixed, 'pt_BR', strict=True))
        self.assertTrue(validate.check('report_summary', mixed, 'pt_BR'))
        self.assertEqual(validate.check_language(PT_FINAL, 'pt_BR', strict=True), [])

    def test_publish_flag_on_the_published_scenarios(self):
        from ai import scenarios
        for sid in ('report_summary', 'notification_summary', 'war_room_brief', 'war_room_focus',
                    'posture_summary', 'incident_digest'):
            self.assertTrue(scenarios.CATALOG[sid]['checks'].get('publish'), sid)


class TestAssistant(TempDirCase):
    def local(self, answers, retries=1, model='qwen3:30b-a3b', fallback=None, scenario='report_summary'):
        self.runtime(False)
        prov = FakeProvider('ollama', answers)
        a = self.assistant(config('ollama', model), routing({scenario: {'provider': 'ollama', 'model': model,
                                                                        'retries': retries}},
                                                            fallback=fallback or {'provider': 'none'}),
                           Factory(ollama=prov))
        return a, prov

    def test_preamble_cut_in_one_attempt(self):
        a, prov = self.local([LEAK + '.\n\n' + PT_FINAL])
        res = a.ask(Task('report_summary', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertEqual(res['text'], PT_FINAL)
        self.assertEqual(len(prov.calls), 1)

    def test_fresh_new_attempt_without_the_reasoning(self):
        a, prov = self.local([LEAK, PT_FINAL])
        res = a.ask(Task('report_summary', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertEqual(res['text'], PT_FINAL)
        second = prov.calls[1]['messages']
        self.assertEqual([m['role'] for m in second], ['system', 'user'])      # notes not sent back
        self.assertNotIn("let's tackle", second[-1]['content'])
        self.assertIn('Do not write any reasoning', second[-1]['content'])

    def test_rejected_after_the_retry(self):
        a, prov = self.local([LEAK, LEAK, LEAK])
        with self.assertRaises(AnswerRejected) as ctx:
            a.ask(Task('report_summary', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertIn('after 2 attempt', str(ctx.exception))
        self.assertEqual(len(prov.calls), 2)

    def test_war_room_and_posture_are_protected(self):
        for sid in ('war_room_brief', 'posture_summary', 'notification_summary'):
            a, _prov = self.local([LEAK], retries=0, scenario=sid)
            with self.assertRaises(AnswerRejected):
                a.ask(Task(sid, 'x', 'q'), {'a': 1}, language='pt_BR')

    def test_brief_never_shows_reasoning(self):
        from ai import brief
        a, _prov = self.local([LEAK], retries=0, scenario='war_room_brief')
        rec = brief.generate('pt_BR', None, assistant=a, inputs={'blocks': 12})
        self.assertEqual(rec['status'], 'error')
        self.assertIn('rejected', rec['message'])
        self.assertNotIn('text', rec)
        a2, _p2 = self.local([LEAK + '\n\nSituação estável: 12 bloqueios na última hora e nenhum alerta crítico.'],
                             retries=0, scenario='war_room_brief')
        rec2 = brief.generate('pt_BR', None, assistant=a2, inputs={'blocks': 12})
        self.assertEqual(rec2['status'], 'ok')
        self.assertTrue(rec2['text'].startswith('Situação estável'))

    def test_non_published_scenarios_keep_the_best_answer(self):
        a, _prov = self.local([LEAK], retries=0, scenario='quicktest')
        res = a.ask(Task('quicktest', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertIn(validate.REASONING_PROBLEM, res['problems'])

    def test_rejection_goes_to_the_fallback_route(self):
        self.runtime(True)
        prov = FakeProvider('ollama', [LEAK, PT_FINAL])
        a = self.assistant(config('ollama', 'qwen2.5:3b'),
                           routing({'report_summary': {'provider': 'ollama', 'model': 'qwen3:30b-a3b',
                                                       'retries': 0}}), Factory(ollama=prov))
        res = a.ask(Task('report_summary', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertEqual(res['text'], PT_FINAL)
        self.assertTrue(res['fallback'])

    def test_time_limit_skips_the_retry(self):
        a, prov = self.local([LEAK, PT_FINAL])
        clock = [1000.0]
        a.clock = lambda: clock[0]
        original = prov.chat

        def slow(*args, **kw):
            clock[0] += 900
            return original(*args, **kw)
        prov.chat = slow
        with self.assertRaises(AnswerRejected):
            a.ask(Task('report_summary', 'x', 'q'), {'a': 1}, language='pt_BR', max_seconds=920)
        self.assertEqual(len(prov.calls), 1)
        self.assertIsNone(a.remaining())


if __name__ == '__main__':
    unittest.main()


class TestThinkingModels(unittest.TestCase):
    """ Ollama: think=false is ignored by Qwen3-30B-A3B-Thinking-2507 (template of the firewall, 2026-11-09) """

    @classmethod
    def setUpClass(cls):
        import os
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, '..', 'fixtures', 'qwen3-thinking-2507.tmpl')) as handle:
            cls.template = handle.read()

    def setUp(self):
        from ai.providers import ollama
        ollama._SHOW_CACHE.clear()

    def test_forced_thinking_template(self):
        from ai.providers.ollama import forced_thinking
        self.assertTrue(forced_thinking(self.template))
        hybrid = self.template.replace(
            '{{- if and (ne .Role "assistant") $last }}<|im_start|>assistant\n<think>\n{{ end }}',
            '{{- if and (ne .Role "assistant") $last }}<|im_start|>assistant\n{{ if and $.IsThinkSet (not $.Think) }}'
            '<think>\n\n</think>\n\n{{ end }}{{ end }}')
        self.assertNotEqual(hybrid, self.template)
        self.assertFalse(forced_thinking(hybrid))
        self.assertFalse(forced_thinking('{{ .Prompt }}'))
        self.assertTrue(forced_thinking('', 'Thinking'))

    def answer(self, body):
        # what Ollama 0.34 returns for this template: the reasoning is in "content" unless think=true
        if not body.get('messages'):
            return 'x'
        if body.get('think'):
            return PT_FINAL
        return LEAK + '\n</think>\n\n' + PT_FINAL

    def test_think_true_and_reasoning_budget_for_a_forced_model(self):
        from ai.providers import ollama
        from ai_helpers import FakeOllama
        show = {'capabilities': ['completion', 'thinking'], 'template': self.template,
                'model_info': {'general.finetune': 'Thinking'}}
        with FakeOllama(answer=self.answer, show=show) as fake:
            p = ollama.OllamaProvider({'location': 'lan', 'url': fake.url, 'model': 'qwen3:30b-a3b',
                                       'num_predict': 1200}, timeout=20)
            self.assertEqual(p.thinking_mode(), 'forced')
            res = p.chat([{'role': 'user', 'content': 'q'}])
            body = [r for r in fake.requests if r[1] == '/api/chat'][-1][2]
            self.assertIs(body['think'], True)
            self.assertEqual(body['options']['num_predict'], 1200 + ollama.THINK_BUDGET)
            self.assertEqual(res.text, PT_FINAL)
            self.assertEqual(len([r for r in fake.requests if r[1] == '/api/show']), 1)
            p.chat([{'role': 'user', 'content': 'q'}])          # cached
            self.assertEqual(len([r for r in fake.requests if r[1] == '/api/show']), 1)

    def test_hybrid_and_plain_models_keep_think_false(self):
        from ai.providers import ollama
        from ai_helpers import FakeOllama
        for show in ({'capabilities': ['completion', 'tools'], 'template': '{{ .Prompt }}'},
                     {'capabilities': ['completion', 'thinking'], 'template': '{{ if not .Think }}<think></think>{{ end }}'}):
            with FakeOllama(answer='Resposta em português.', show=show) as fake:
                ollama._SHOW_CACHE.clear()
                p = ollama.OllamaProvider({'location': 'lan', 'url': fake.url, 'model': 'qwen3:8b',
                                           'num_predict': 600}, timeout=20)
                p.chat([{'role': 'user', 'content': 'q'}])
                body = [r for r in fake.requests if r[1] == '/api/chat'][-1][2]
                self.assertIs(body['think'], False)
                self.assertEqual(body['options']['num_predict'], 600)

    def test_think_false_answer_of_the_forced_model_is_cut(self):
        # if Ollama still answered with the reasoning in content (show failed): the lone </think> is handled
        from ai_helpers import FakeOllama
        from ai import Assistant
        from ai.audit import NullAuditLog
        from ai_fakes import routing as mk_routing
        with FakeOllama(answer=lambda body: LEAK + '\n</think>\n\n' + PT_FINAL, show={}) as fake:
            cfg = config('ollama', 'qwen3:30b-a3b')
            cfg.options.update({'location': 'lan', 'url': fake.url})
            a = Assistant(cfg, audit=NullAuditLog(), routing=mk_routing({'report_summary': {
                'provider': 'ollama', 'model': 'qwen3:30b-a3b', 'retries': 0}}, fallback={'provider': 'none'}))
            res = a.ask(Task('report_summary', 'x', 'q'), {'a': 1}, language='pt_BR')
            self.assertEqual(res['text'], PT_FINAL)


class TestDeadlineReserve(TempDirCase):
    def test_primary_leaves_time_for_the_fallback(self):
        self.runtime(True)
        prov = FakeProvider('ollama', [LEAK, PT_FINAL])
        factory = Factory(ollama=prov)
        a = self.assistant(config('ollama', 'qwen2.5:3b'),
                           routing({'report_summary': {'provider': 'ollama', 'model': 'qwen3:30b-a3b',
                                                       'retries': 0, 'timeout': 1800}}), factory)
        a.ask(Task('report_summary', 'x', 'q'), {'a': 1}, language='pt_BR', max_seconds=1000)
        timeouts = [c['timeout'] for c in factory.created]
        self.assertLessEqual(timeouts[0], 600)                 # 60 % of the limit, not the 1800 s of the route
        self.assertGreaterEqual(timeouts[1], 390)              # the rest goes to the fallback
