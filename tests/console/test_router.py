"""
Intent router of the AI Console: pt-BR and English questions -> intents, entities, time window, collectors.
"""

import time
import unittest

import console_helpers  # noqa: F401  (import path)
from console import router

NOW = time.mktime((2026, 11, 8, 15, 30, 0, 0, 0, -1))        # local 15:30
MIDNIGHT = time.mktime((2026, 11, 8, 0, 0, 0, 0, 0, -1))
KNOWN = {'interfaces': ['lan', 'wan', 'opt1', 'IoT', 'igc0'], 'hosts': ['printer', 'nas', 'smart-tv']}


def plan(text, history=None):
    return router.route(text, known=KNOWN, now=NOW, history=history)


class TestIntentsPortuguese(unittest.TestCase):
    def test_why_blocked_with_host_and_domain(self):
        p = plan('Por que o host 192.168.10.50 não acessa youtube.com?')
        self.assertEqual(p['intents'][0], 'why_blocked')
        self.assertEqual(p['entities']['ips'], ['192.168.10.50'])
        self.assertEqual(p['entities']['domains'], ['youtube.com'])
        for name in ('filterlog', 'path_rules', 'hosts', 'aliases'):
            self.assertIn(name, p['collectors'])
        self.assertEqual(p['window']['label'], 'last 1 h')
        self.assertFalse(p['window']['explicit'])

    def test_changes_since_yesterday(self):
        p = plan('O que mudou desde ontem?')
        self.assertEqual(p['intents'], ['changes'])
        self.assertEqual(p['collectors'], ['changes'])
        self.assertEqual(p['window']['since'], int(MIDNIGHT - 86400))
        self.assertEqual(p['window']['until'], int(NOW))

    def test_top_blocked_today(self):
        p = plan('Quem mais foi bloqueado hoje?')
        self.assertEqual(p['intents'][0], 'top_blocked')
        self.assertIn('filterlog_top', p['collectors'])
        self.assertNotIn('path_rules', p['collectors'])
        self.assertEqual(p['window']['since'], int(MIDNIGHT))

    def test_rule_usage_quoted(self):
        p = plan('A regra "Allow DNS" está sendo usada?')
        self.assertEqual(p['intents'][0], 'rule_usage')
        self.assertEqual(p['entities']['rules']['texts'], ['Allow DNS'])
        # "dns" inside the rule name is not a port of the question
        self.assertEqual(p['entities']['ports'], [])
        self.assertEqual(p['collectors'][:2], ['rules', 'findings'])

    def test_rule_usage_unquoted(self):
        p = plan('a regra Block IoT to LAN está sendo usada?')
        self.assertEqual(p['intents'][0], 'rule_usage')
        self.assertEqual(p['entities']['rules']['texts'], ['block iot to lan'])

    def test_known_host_name_and_interface(self):
        p = plan('o que o printer fez na rede IoT nas últimas 3 horas?')
        self.assertIn('printer', p['entities']['hosts'])
        self.assertIn('IoT', p['entities']['interfaces'])
        self.assertEqual(p['window']['since'], int(NOW - 3 * 3600))

    def test_port_service_and_protocol(self):
        p = plan('por que 10.0.0.5 não consegue ssh no 10.0.0.9 porta 2222/tcp?')
        self.assertEqual(p['entities']['ips'], ['10.0.0.5', '10.0.0.9'])
        self.assertEqual(p['entities']['ports'][:2], [2222, 22])
        self.assertEqual(p['entities']['protocols'], ['tcp'])

    def test_suricata_severity(self):
        p = plan('Houve alertas do Suricata de severidade 1 hoje?')
        self.assertEqual(p['intents'][0], 'ids')
        self.assertEqual(p['entities']['severity'], 1)
        self.assertEqual(p['collectors'], ['suricata'])

    def test_quarantine_and_exposure(self):
        self.assertEqual(plan('Como está a quarentena agora?')['intents'][0], 'quarantine')
        self.assertEqual(plan('Algum serviço está exposto à internet?')['intents'][0], 'exposure')
        self.assertEqual(plan('Quais achados do Policy Analyzer revisar primeiro?')['intents'][0], 'findings')

    def test_windows(self):
        self.assertEqual(plan('bloqueios na última hora')['window']['since'], int(NOW - 3600))
        y = plan('quem foi bloqueado ontem?')['window']
        self.assertEqual((y['since'], y['until']), (int(MIDNIGHT - 86400), int(MIDNIGHT)))
        self.assertEqual(plan('o que mudou nos últimos 2 dias?')['window']['since'], int(NOW - 2 * 86400))
        self.assertEqual(plan('o que mudou desde as 10h?')['window']['since'], int(MIDNIGHT + 10 * 3600))
        self.assertEqual(plan('o que mudou desde 16:00?')['window']['since'], int(MIDNIGHT - 86400 + 16 * 3600))
        self.assertEqual(plan('o que mudou há 30 minutos?')['window']['since'], int(NOW - 1800))
        self.assertEqual(plan('o que mudou nesta semana?')['window']['label'], 'last 7 days')


class TestIntentsEnglish(unittest.TestCase):
    def test_why_cant_reach(self):
        p = plan("Why can't 10.0.0.5 reach port 443?")
        self.assertEqual(p['intents'][0], 'why_blocked')
        self.assertEqual(p['entities']['ports'], [443])

    def test_what_changed(self):
        p = plan('What changed in the last 3 hours?')
        self.assertEqual(p['intents'], ['changes'])
        self.assertEqual(p['window']['since'], int(NOW - 3 * 3600))

    def test_who_else_blocked(self):
        p = plan('Who else got blocked today?')
        self.assertEqual(p['intents'][0], 'top_blocked')
        self.assertEqual(p['entities']['action'], 'block')

    def test_rule_used(self):
        p = plan('Is the rule "SSH to server" being used?')
        self.assertEqual(p['intents'][0], 'rule_usage')
        self.assertEqual(p['entities']['rules']['texts'], ['SSH to server'])

    def test_rule_uuid(self):
        p = plan('is 11111111-1111-4111-8111-111111111111 unused?')
        self.assertEqual(p['entities']['rules']['uuids'], ['11111111-1111-4111-8111-111111111111'])
        self.assertIn('rules', p['collectors'])

    def test_ipv6_and_cidr(self):
        p = plan('what did 2001:db8::7 and 192.168.20.0/24 do since yesterday?')
        self.assertEqual(p['entities']['ips'], ['192.168.20.0/24', '2001:db8::7'])
        self.assertEqual(p['window']['label'], 'since yesterday')

    def test_unknown_question_is_overview(self):
        p = plan('hello there')
        self.assertEqual(p['intents'], ['overview'])
        self.assertIn('filterlog_top', p['collectors'])


class TestFollowUp(unittest.TestCase):
    HISTORY = ['por que o 192.168.1.50 não acessa a porta 443?']

    def test_time_only_follow_up_keeps_subject_and_intent(self):
        p = plan('e ontem?', history=self.HISTORY)
        self.assertEqual(p['entities']['ips'], ['192.168.1.50'])
        self.assertEqual(p['intents'][0], 'why_blocked')
        self.assertIn('ips', p['carried_from_history'])
        self.assertEqual(p['window']['label'], 'yesterday')

    def test_port_follow_up(self):
        p = plan('and port 22?', history=self.HISTORY)
        self.assertEqual(p['entities']['ips'], ['192.168.1.50'])
        self.assertEqual(p['entities']['ports'], [22])

    def test_new_global_question_does_not_inherit(self):
        p = plan('O que mudou desde ontem?', history=self.HISTORY)
        self.assertEqual(p['entities']['ips'], [])
        self.assertEqual(p['carried_from_history'], [])

    def test_anaphora_inherits(self):
        p = plan('e ele está na quarentena?', history=self.HISTORY)
        self.assertEqual(p['entities']['ips'], ['192.168.1.50'])
        self.assertEqual(p['intents'][0], 'quarantine')

    def test_deterministic(self):
        self.assertEqual(plan('Quem mais foi bloqueado hoje?'), plan('Quem mais foi bloqueado hoje?'))


if __name__ == '__main__':
    unittest.main()
