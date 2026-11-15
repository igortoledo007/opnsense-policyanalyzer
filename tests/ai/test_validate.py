"""
Answer validation, language heuristic, one correction attempt, <think> removal, structured output and the
Ollama payload (think=false, format, num_predict, keep_alive).
"""

import json
import unittest

from ai_fakes import Factory, FakeProvider, TempDirCase, config, routing
from ai_helpers import FakeOllama
from ai import Task, validate
from ai.assistant import Assistant
from ai.providers.ollama import OllamaProvider

PT_TEXT = ('A regra está liberando tráfego da internet para o servidor, o que não é recomendado. '
           'Você deve restringir a origem para os endereços que precisam do serviço.')
EN_TEXT = ('The rule is allowing traffic from the internet to the server and this is not recommended. '
           'You should restrict the source to the addresses that need the service.')


class TestHeuristics(unittest.TestCase):
    def test_language(self):
        self.assertEqual(validate.detect_language(PT_TEXT), 'pt')
        self.assertEqual(validate.detect_language(EN_TEXT), 'en')
        self.assertIsNone(validate.detect_language('OK 42'))
        self.assertEqual(validate.check_language(EN_TEXT, 'pt_BR'), ['the answer is not in Brazilian Portuguese'])
        self.assertEqual(validate.check_language(PT_TEXT, 'pt_BR'), [])
        self.assertEqual(validate.check_language(EN_TEXT, 'de_DE'), [])          # not checked
        self.assertTrue(validate.check_language(PT_TEXT + ' 防火墙', 'pt_BR'))
        doc = json.dumps({'summary': EN_TEXT, 'actions': [{'id': 'resolve'}]})
        self.assertTrue(validate.check_language(doc, 'pt_BR'))

    def test_think(self):
        self.assertEqual(validate.strip_think('<think>hmm\nlong</think>\n\nResposta.'), 'Resposta.')
        self.assertEqual(validate.strip_think('Antes <think>cortado pelo limite'), 'Antes')
        f = validate.ThinkFilter()
        out = ''.join(f.feed(p) for p in ['Olá <thi', 'nk>raciocínio', ' secreto</th', 'ink> mundo', ' <'])
        out += f.flush()
        self.assertEqual(out, 'Olá  mundo <')

    def test_checks(self):
        self.assertEqual(validate.check('war_room_brief', 'Uma. Duas. Três.', None), [])
        self.assertTrue(validate.check('war_room_brief', 'Um. Dois. Três. Quatro. Cinco. Seis. Sete.', None))
        self.assertTrue(validate.check('incident_digest', '- item\n- item. Frase dois.', None))
        self.assertTrue(validate.check('console_ask', 'No citation here.', None))
        self.assertEqual(validate.check('console_ask', 'Blocked [filterlog: 14 blocks].', None), [])
        self.assertTrue(validate.check('console_explain_log', 'x [filterlog: a]', None))   # needs headings
        good = 'TYPE: camera\nIt is a camera.'
        self.assertEqual(validate.check('explain_device', good, None, {'first_values': ['camera']}), [])
        self.assertTrue(validate.check('explain_device', 'TYPE: toaster\nx', None, {'first_values': ['camera']}))
        self.assertTrue(validate.check('vuln_review_suggest', 'I think none', None))
        doc = json.dumps({'summary': 's', 'actions': [{'id': 'bogus'}]})
        problems = validate.check('incident_summary', doc, None, {'valid_ids': ['resolve']})
        self.assertTrue(any('bogus' in p for p in problems))
        sections = ('What it means: a\nWhy it matters: b\nWhat I would check: c\nSuggested change: none')
        self.assertEqual(validate.check('explain_finding', sections, 'en_US'), [])
        self.assertTrue(validate.check('explain_finding', 'just one line', None))
        self.assertTrue(validate.check('posture_check', 'too short', None))
        self.assertEqual(validate.check('quicktest', 'anything', None), [])


class TestCorrection(TempDirCase):
    def test_one_correction_attempt_on_wrong_language(self):
        self.runtime(False)
        local = FakeProvider('ollama', [EN_TEXT, PT_TEXT])
        # quicktest has no format checks: only the language is checked here
        a = self.assistant(config('ollama', 'qwen2.5:3b'), routing({'quicktest': {'provider': 'ollama'}}),
                           Factory(ollama=local))
        res = a.ask(Task('quicktest', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertEqual(res['text'], PT_TEXT)
        self.assertEqual(res['attempts'], 2)
        self.assertEqual(len(local.calls), 2)
        second = local.calls[1]['messages']
        self.assertEqual(second[-2], {'role': 'assistant', 'content': EN_TEXT})
        self.assertIn('Brazilian Portuguese', second[-1]['content'])
        self.assertIn('not in Brazilian Portuguese', second[-1]['content'])

    def test_keeps_the_best_and_stops_after_the_retries(self):
        self.runtime(False)
        bad = 'one line'
        local = FakeProvider('ollama', [bad, bad, bad])
        a = self.assistant(config('ollama', 'qwen2.5:3b'), routing({'explain_finding': {'provider': 'ollama',
                                                                                         'retries': 1}}),
                           Factory(ollama=local))
        res = a.ask(Task('explain_finding', 'x', 'q'), {'a': 1}, language='en_US')
        self.assertEqual(len(local.calls), 2)
        self.assertTrue(res['problems'])
        self.assertEqual(a.audit.records[-1]['attempts'], 2)
        # global routing (no entry): no correction attempt at all
        local2 = FakeProvider('ollama', [bad])
        a2 = self.assistant(config('ollama', 'qwen2.5:3b'), routing(), Factory(ollama=local2))
        a2.ask(Task('explain_finding', 'x', 'q'), {'a': 1}, language='en_US')
        self.assertEqual(len(local2.calls), 1)

    def test_language_reminder_and_no_think(self):
        self.runtime(False)
        local = FakeProvider('ollama', ['<think>plan</think>Resposta final em português, sem dúvida.'])
        a = self.assistant(config('ollama', 'qwen3:30b-a3b'), routing({'quicktest': {'provider': 'ollama',
                                                                                      'retries': 0}}),
                           Factory(ollama=local))
        res = a.ask(Task('quicktest', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertEqual(res['text'], 'Resposta final em português, sem dúvida.')
        user = local.calls[0]['messages'][-1]['content']
        self.assertTrue(user.endswith('Write the whole answer in Brazilian Portuguese. /no_think'), user)
        preview = a.preview(Task('quicktest', 'x', 'q'), {'a': 1}, 'pt_BR')
        self.assertTrue(preview['messages'][-1]['content'].endswith('/no_think'))
        # bridge: messages untouched
        bridge = FakeProvider('claudecode', ['ok'])
        b = self.assistant(config('claudecode', 'fable'), routing(), Factory(claudecode=bridge))
        b.ask(Task('quicktest', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertNotIn('Write the whole answer', bridge.calls[0]['messages'][-1]['content'])

    def test_structured_output_is_rendered_back(self):
        self.runtime(False)
        from devices import explain as dexplain
        from vulns import explain as vexplain
        local = FakeProvider('ollama', [json.dumps({'type': 'camera', 'explanation': 'Uma câmera IP da rede.'})],
                             supports_format=True)
        a = self.assistant(config('ollama', 'qwen2.5:3b'), routing({'explain_device': {'provider': 'ollama'}}),
                           Factory(ollama=local))
        task = Task('explain_device', 'x', 'q', schema=dexplain.type_schema(), render=dexplain.render_type,
                    check_ctx={'first_values': ['camera']})
        res = a.ask(task, {'a': 1}, language='pt_BR')
        self.assertEqual(res['text'], 'TYPE: camera\nUma câmera IP da rede.')
        self.assertEqual(local.calls[0]['fmt']['properties']['type']['enum'][0], 'camera')
        self.assertTrue(a.audit.records[-1]['structured'])
        # a provider without structured output gets no format and the text is kept as is
        bridge = FakeProvider('claudecode', ['MAPPING: none\nSó uma biblioteca.'])
        b = self.assistant(config('claudecode', 'fable'), routing(), Factory(claudecode=bridge))
        t2 = Task('vuln_review_suggest', 'x', 'q', schema=vexplain.mapping_schema(['abc123']),
                  render=vexplain.render_mapping)
        self.assertEqual(b.ask(t2, {'a': 1})['text'], 'MAPPING: none\nSó uma biblioteca.')
        self.assertIsNone(bridge.calls[0]['fmt'])
        # broken JSON from the model: the raw text is kept
        local3 = FakeProvider('ollama', ['not json at all'], supports_format=True)
        c = self.assistant(config('ollama', 'qwen2.5:3b'), routing({'explain_device': {'provider': 'ollama',
                                                                                        'retries': 0}}),
                           Factory(ollama=local3))
        self.assertEqual(c.ask(task, {'a': 1})['text'], 'not json at all')

    def test_incident_schema_keeps_json(self):
        self.runtime(False)
        from incidents import triage
        cands = [{'id': 'resolve', 'kind': 'state'}, {'id': 'quarantine_1', 'kind': 'quarantine'}]
        answer = json.dumps({'summary': 'Varredura comum da internet, sem impacto.', 'hypothesis': 'scan',
                             'impact': 'nenhum', 'confidence': 'low', 'next_steps': [],
                             'actions': [{'id': 'resolve', 'why': 'ruído'}]})
        local = FakeProvider('ollama', [answer], supports_format=True)
        a = self.assistant(config('ollama', 'qwen2.5:3b'), routing({'incident_summary': {'provider': 'ollama',
                                                                                          'mode': 'sync'}}),
                           Factory(ollama=local))
        task = Task('incident_summary', 'x', 'q', schema=triage.summary_schema(cands),
                    check_ctx={'valid_ids': ['resolve', 'quarantine_1']})
        res = a.ask(task, {'a': 1}, language='pt_BR')
        parsed = triage.parse_answer(res['text'], cands)
        self.assertTrue(parsed['parsed'])
        self.assertEqual(parsed['actions'][0]['id'], 'resolve')
        enum = local.calls[0]['fmt']['properties']['actions']['items']['properties']['id']['enum']
        self.assertEqual(enum, ['resolve', 'quarantine_1'])


class TestOllamaPayload(unittest.TestCase):
    def test_think_false_format_and_limits(self):
        with FakeOllama(answer='{"type": "camera", "explanation": "x"}') as fake:
            p = OllamaProvider({'location': 'lan', 'url': fake.url, 'model': 'qwen3:30b-a3b', 'num_predict': 900,
                                'num_ctx': 8192, 'keep_alive': '30m'}, timeout=20)
            p.chat([{'role': 'user', 'content': 'q'}], fmt={'type': 'object'})
            body = fake.requests[-1][2]
            self.assertIs(body['think'], False)
            self.assertEqual(body['format'], {'type': 'object'})
            self.assertEqual(body['options']['num_predict'], 900)
            self.assertEqual(body['options']['num_ctx'], 8192)
            self.assertEqual(body['keep_alive'], '30m')
            p2 = OllamaProvider({'location': 'lan', 'url': fake.url, 'model': 'x:1'}, timeout=20)
            p2.chat([{'role': 'user', 'content': 'q'}])
            self.assertNotIn('format', fake.requests[-1][2])
            self.assertTrue(OllamaProvider.supports_format)

    def test_assistant_over_http_with_think_tags_streamed(self):
        with FakeOllama(answer='<think> pensando muito </think> Resposta.') as fake:
            cfg = config('ollama', 'qwen3:30b-a3b')
            cfg.options.update({'location': 'lan', 'url': fake.url})
            from ai.audit import NullAuditLog
            a = Assistant(cfg, audit=NullAuditLog(), routing=routing())
            chunks = []
            res = a.ask(Task('quicktest', 'x', 'q'), {'a': 1}, language='pt_BR', stream=True, on_chunk=chunks.append)
            self.assertEqual(res['text'], 'Resposta.')
            self.assertNotIn('pensando', ''.join(chunks))
            self.assertIn('/no_think', fake.requests[-1][2]['messages'][-1]['content'])


if __name__ == '__main__':
    unittest.main()
