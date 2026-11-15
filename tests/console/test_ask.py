"""
AI Console end to end with a fake provider: context limit, anonymization of everything that is sent (data,
question, history), restore of the answer, preview = what is sent, language choice, explain items, viewers,
payload validation.  The real AI is never called.
"""

import json
import re
import unittest

from console_helpers import NOW, U_BLOCK_PRINTER, U_SSH_WAN, FakeProvider, Firewall
from ai import AIConfig
from console import ask, context
from console.common import decode_payload, encode_payload

SECRETS = ('192.168.1.50', '198.51.100.20', '203.0.113.9', 'printer', 'Block printer HTTPS', 'nas.example.lan',
           '00:11:22:33:44:55', 'admin@')


def config(**kw):
    base = dict(enabled=True, provider='claudecode', anonymize=True, language='auto', options={'model': 'fable'})
    base.update(kw)
    return AIConfig(**base)


def sent_text(provider):
    return '\n'.join(m['content'] for m in provider.messages)


class Base(unittest.TestCase):
    def setUp(self):
        self.fw = Firewall()
        self.paths = self.fw.paths
        self.clock = ask.CLOCK
        ask.CLOCK = lambda: NOW

    def tearDown(self):
        ask.CLOCK = self.clock
        self.fw.cleanup()


class TestContextLimit(unittest.TestCase):
    def test_trims_lists_then_drops_sections(self):
        big = {'available': True, 'rows': [{'a': 'x' * 50, 'n': i} for i in range(400)]}
        other = {'available': True, 'items': list(range(2000))}
        data = context.build({'intents': ['x']}, [('first', big), ('second', other)], max_tokens=1500)
        self.assertLessEqual(context.size_tokens(data), 1500)
        self.assertTrue(data['context_limits']['trimmed'])
        self.assertTrue(data['context_limits']['trimmed'][0].startswith('second.'))   # lowest priority first
        self.assertEqual(data['question_analysis'], {'intents': ['x']})

    def test_small_context_untouched(self):
        data = context.build({'i': 1}, [('a', {'available': True, 'v': [1, 2]})], max_tokens=1000)
        self.assertEqual(data['context_limits']['trimmed'], [])
        self.assertEqual(data['evidence']['a']['v'], [1, 2])

    def test_budget_by_provider(self):
        self.assertEqual(context.token_budget(config(provider='ollama', options={'location': 'local'})),
                         context.SMALL_TOKENS)
        self.assertEqual(context.token_budget(config(provider='ollama', options={'location': 'lan'})),
                         context.DEFAULT_TOKENS)
        self.assertEqual(context.token_budget(config()), context.DEFAULT_TOKENS)

    def test_ask_respects_small_budget(self):
        fw = Firewall()
        old = ask.CLOCK
        ask.CLOCK = lambda: NOW
        try:
            cfg = config(provider='ollama', options={'location': 'local', 'model': 'qwen2.5:3b'})
            res = ask.cmd_ask({'q': 'quem mais foi bloqueado hoje e o que mudou desde ontem?'}, 'pt_BR', 'preview',
                              paths=fw.paths, config=cfg)
            self.assertLessEqual(res['context']['estimated_tokens'], context.SMALL_TOKENS)
        finally:
            ask.CLOCK = old
            fw.cleanup()


class TestAskAnonymized(Base):
    def test_nothing_identifying_is_sent_and_answer_is_restored(self):
        provider = FakeProvider()
        history = [{'q': 'o que o printer fez?', 'a': 'O printer (192.168.1.50) tentou 198.51.100.20.'}]
        res = ask.cmd_ask({'q': 'Por que o 192.168.1.50 não acessa a porta 443?', 'history': history, 'lang': 'auto'},
                          'pt_BR', 'send', paths=self.paths, config=config(), provider=provider)
        self.assertEqual(res['status'], 'ok')
        text = sent_text(provider)
        for secret in SECRETS:
            self.assertNotIn(secret, text, secret)
        # question, history and data share the same placeholders
        token = re.search(r'IP4_PRIV_\d+', provider.messages[-1]['content'].split('\n')[0]).group(0)
        self.assertIn(token, provider.messages[1]['content'] + provider.messages[2]['content'])
        self.assertEqual([m['role'] for m in provider.messages], ['system', 'user', 'assistant', 'user'])
        # the answer comes back with the real address
        self.assertIn('192.168.1.50', res['text'])
        self.assertEqual(res['sent']['messages'], provider.messages)
        self.assertTrue(res['anonymized'])
        self.assertIn('why_blocked', res['plan']['intents'])
        self.assertEqual(res['language'], 'Brazilian Portuguese')
        # audit: anonymized prompt only, never the mapping
        audit = [json.loads(line) for line in open(self.paths.audit_log)]
        self.assertEqual(audit[-1]['action'], 'console_ask')
        self.assertNotIn('192.168.1.50', audit[-1]['prompt'])

    def test_preview_is_what_would_be_sent(self):
        preview = ask.cmd_ask({'q': 'Quem mais foi bloqueado hoje?'}, 'pt_BR', 'preview', paths=self.paths,
                              config=config())
        provider = FakeProvider()
        sent = ask.cmd_ask({'q': 'Quem mais foi bloqueado hoje?'}, 'pt_BR', 'send', paths=self.paths, config=config(),
                           provider=provider)
        self.assertEqual(preview['messages'], provider.messages)
        self.assertEqual(sent['sent']['messages'], preview['messages'])
        self.assertNotIn('203.0.113.9', json.dumps(preview['messages']))

    def test_not_anonymized_when_disabled(self):
        preview = ask.cmd_ask({'q': 'Quem mais foi bloqueado hoje?'}, 'pt_BR', 'preview', paths=self.paths,
                              config=config(anonymize=False))
        self.assertFalse(preview['anonymized'])
        self.assertIn('203.0.113.9', json.dumps(preview['messages']))

    def test_language_choice(self):
        p = ask.cmd_ask({'q': 'who else got blocked today?', 'lang': 'en_US'}, 'pt_BR', 'preview', paths=self.paths,
                        config=config(language='pt_BR'))
        self.assertIn('Write the answer in English', p['messages'][0]['content'])
        p = ask.cmd_ask({'q': 'who else got blocked today?', 'lang': 'auto'}, 'en_US', 'preview', paths=self.paths,
                        config=config(language='pt_BR'))
        self.assertIn('Brazilian Portuguese', p['messages'][0]['content'])
        p = ask.cmd_ask({'q': 'quem foi bloqueado?', 'lang': 'auto'}, 'pt_BR', 'preview', paths=self.paths,
                        config=config(language='auto'))
        self.assertIn('Brazilian Portuguese', p['messages'][0]['content'])

    def test_prompt_demands_evidence(self):
        p = ask.cmd_ask({'q': 'o que mudou desde ontem?'}, 'pt_BR', 'preview', paths=self.paths, config=config())
        system = p['messages'][0]['content']
        self.assertIn('Cite it inline', system)
        self.assertIn('I do not have', system)
        self.assertIn('Proposal (not applied)', system)
        self.assertIn('You cannot change anything', system)

    def test_disabled(self):
        res = ask.cmd_ask({'q': 'quem foi bloqueado hoje?'}, 'pt_BR', 'send', paths=self.paths,
                          config=config(enabled=False))
        self.assertEqual(res['status'], 'disabled')

    def test_route_mode_and_empty(self):
        self.assertEqual(ask.cmd_ask({'q': 'o que mudou?'}, 'pt_BR', 'route', paths=self.paths)['plan']['intents'],
                         ['changes'])
        self.assertEqual(ask.cmd_ask({'q': ' '}, 'pt_BR', 'send', paths=self.paths)['status'], 'error')

    def test_history_is_bounded(self):
        provider = FakeProvider()
        history = [{'q': 'q%d' % i, 'a': 'a' * 5000} for i in range(10)]
        ask.cmd_ask({'q': 'quem foi bloqueado hoje?', 'history': history}, 'pt_BR', 'send', paths=self.paths,
                    config=config(), provider=provider)
        self.assertEqual(len(provider.messages), 2 + 2 * ask.MAX_HISTORY)
        self.assertLessEqual(len(provider.messages[2]['content']), ask.MAX_HISTORY_A)


class TestExplain(Base):
    def test_explain_log_line(self):
        rows = ask.cmd_log({'ip': '192.168.1.50', 'action': 'block', 'limit': 10}, paths=self.paths)['rows']
        row = rows[0]
        provider = FakeProvider()
        item = {k: row[k] for k in ('ts', 'action', 'dir', 'proto', 'sport', 'dport', 'rid')}
        item.update({'iface': row['interface'], 'src': row['src_ip'], 'dst': row['dst_ip']})
        res = ask.cmd_explain('log', item, 'pt_BR', 'send', paths=self.paths, config=config(), provider=provider)
        self.assertEqual(res['status'], 'ok', res)
        names = [s['name'] for s in res['sources']]
        self.assertEqual(names[:2], ['event', 'rule'])
        self.assertIn('path', names)
        for secret in SECRETS:
            self.assertNotIn(secret, sent_text(provider), secret)
        self.assertIn('console_explain_log', open(self.paths.audit_log).read())

    def test_explain_rule(self):
        provider = FakeProvider()
        res = ask.cmd_explain('rule', {'uuid': U_SSH_WAN}, 'en_US', 'send', paths=self.paths, config=config(),
                              provider=provider)
        self.assertEqual(res['status'], 'ok')
        data = provider.messages[-1]['content']
        self.assertIn('wan_exposed', data)
        self.assertIn('"packets": 0', data)
        self.assertIn('neighbours', data)
        self.assertNotIn(U_SSH_WAN, data)            # data minimisation: no uuids for the model

    def test_explain_alert(self):
        rows = ask.cmd_alerts({'severity': 1}, paths=self.paths)['rows']
        provider = FakeProvider()
        res = ask.cmd_explain('alert', {'timestamp': rows[0]['timestamp'], 'flow_id': rows[0]['flow_id'],
                                        'sid': rows[0]['sid']}, 'en_US', 'send', paths=self.paths, config=config(),
                              provider=provider)
        self.assertEqual(res['status'], 'ok', res)
        self.assertIn('Banker.Delf', sent_text(provider))
        self.assertNotIn('evil.example.com', sent_text(provider))
        self.assertNotIn('203.0.113.9', sent_text(provider))

    def test_explain_rejects_bad_items(self):
        bad = ask.cmd_explain('log', {'src': '1.2.3', 'dst': '192.168.1.1'}, 'en_US', 'preview', paths=self.paths)
        self.assertEqual(bad['status'], 'error')
        self.assertEqual(ask.cmd_explain('rule', {'uuid': '../../etc'}, 'en_US', 'preview',
                                         paths=self.paths)['status'], 'error')
        self.assertEqual(ask.cmd_explain('alert', {'sid': 'x'}, 'en_US', 'preview', paths=self.paths)['status'],
                         'error')
        self.assertEqual(ask.cmd_explain('shell', {}, 'en_US', 'preview', paths=self.paths)['status'], 'error')


class TestViewers(Base):
    def test_log(self):
        res = ask.cmd_log({'iface': 'lan', 'action': 'block'}, paths=self.paths)
        self.assertTrue(res['rows'])
        self.assertTrue(all(r['interface'] == 'igc0' and r['action'] == 'block' for r in res['rows']))
        self.assertEqual(res['rows'][0]['rule'], 'lan #10 block "Block printer HTTPS"')
        self.assertEqual(ask.cmd_log({'ip': 'nope'}, paths=self.paths)['status'], 'error')
        self.assertEqual(ask.cmd_log({'port': '70000'}, paths=self.paths)['status'], 'error')

    def test_rules(self):
        res = ask.cmd_rules({'search': 'printer'}, paths=self.paths)
        self.assertEqual([r['uuid'] for r in res['rows']], [U_BLOCK_PRINTER])

    def test_alerts(self):
        res = ask.cmd_alerts({'severity': 1}, paths=self.paths)
        self.assertEqual(len(res['rows']), 1)
        self.assertEqual(ask.cmd_alerts({'ip': 'x'}, paths=self.paths)['status'], 'error')

    def test_status_and_suggestions(self):
        st = ask.cmd_status(paths=self.paths, config=config())
        self.assertTrue(st['ai']['enabled'])
        self.assertEqual(st['sources']['config_backups'], 3)
        sug = ask.cmd_suggest('pt_BR', paths=self.paths)['suggestions']
        self.assertIn('A regra "SSH to server" está sendo usada?', sug)
        self.assertTrue(any('printer' in s or 'nas' in s for s in sug))
        self.assertTrue(all(isinstance(s, str) for s in ask.cmd_suggest('en_US', paths=self.paths)['suggestions']))


class TestPayload(unittest.TestCase):
    def test_round_trip(self):
        self.assertEqual(decode_payload(encode_payload({'q': 'é 1.2.3.4?'})), {'q': 'é 1.2.3.4?'})
        self.assertEqual(decode_payload('-'), {})

    def test_rejects(self):
        for bad in ('$(id)', 'aGVsbG8=', 'W10=', "a' b"):
            with self.assertRaises(ValueError):
                decode_payload(bad)

    def test_fits_configd_message(self):
        """ the PHP side caps the JSON at 2800 bytes: the whole configd command stays under 4096 bytes """
        payload = {'q': 'é' * 300, 'lang': 'pt_BR', 'history': [{'q': 'x' * 300, 'a': 'y' * 900}]}
        text = json.dumps(payload, ensure_ascii=False)
        self.assertLessEqual(len(text.encode()), 2800)
        line = "pa_console ask '%s' 'pt_BR' 'send'" % encode_payload(payload)
        self.assertLess(len(line.encode()), 4096)


if __name__ == '__main__':
    unittest.main()
