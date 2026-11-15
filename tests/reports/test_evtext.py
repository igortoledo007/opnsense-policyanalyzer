"""
Event texts in the language of the reports: rebuilt from the facts in "data", stored text when the facts are missing.
"""

import unittest

import rhelpers  # noqa: F401  (sys.path of the plugin scripts)
from reports import evtext  # noqa: E402

Q = {'type': 'quarantine_long', 'severity': 'medium', 'title': '192.0.2.24 in quarantine: 10 days (level 4)',
     'detail': 'enter by auto, country US, AS64500',
     'data': {'level': 4, 'kind': 'enter', 'origin': 'auto', 'country': 'US', 'addr': '192.0.2.24', 'asn': 64500}}


class EventTextTest(unittest.TestCase):
    def test_quarantine_in_portuguese_and_english(self):
        self.assertEqual(evtext.text(Q, 'pt_BR'), ('192.0.2.24 em quarentena: 10 dias (nível 4)',
                                                   'Entrou automaticamente, país US, AS64500'))
        self.assertEqual(evtext.text(Q, 'en_US'), ('192.0.2.24 in quarantine: 10 days (level 4)',
                                                   'Entered automatically, country US, AS64500'))

    def test_severity_label(self):
        out = evtext.localize([Q], 'pt_BR')[0]
        self.assertEqual(out['severity_label'], 'média')
        self.assertEqual(out['severity'], 'medium')                          # colors keep the raw value
        self.assertEqual(evtext.severity('weird', 'pt_BR'), 'weird')

    def test_older_events_keep_the_stored_text(self):
        old = dict(Q, data={'level': 4, 'kind': 'enter', 'origin': 'auto', 'country': 'US'})   # no addr: before
        self.assertEqual(evtext.text(old, 'pt_BR'), (Q['title'], Q['detail']))
        other = {'type': 'anomaly', 'title': 'Scan', 'detail': 'x', 'data': {}}
        self.assertEqual(evtext.text(other, 'pt_BR'), ('Scan', 'x'))

    def test_other_detectors(self):
        dev = {'type': 'device_new', 'title': 'x', 'data': {'label': 'cam-01', 'vendor': None, 'ips': '192.0.2.7',
                                                           'iface': 'LAN', 'type': 'camera', 'risk': 'high'}}
        self.assertEqual(evtext.text(dev, 'pt_BR'), ('Novo dispositivo: cam-01 (fabricante desconhecido)',
                                                     '192.0.2.7 em LAN, tipo camera, risco alta'))
        kev = {'type': 'vuln_kev_p1', 'title': 'x', 'data': {'cve': 'CVE-2026-0001', 'package': 'openssl',
                                                            'kev': True, 'kev_date': '2026-11-01', 'priority': 'P2'}}
        self.assertEqual(evtext.text(kev, 'pt_BR')[0], 'CVE-2026-0001 (openssl) está no CISA KEV')
        ai = {'type': 'ai_down', 'title': 'x', 'detail': 'timeout', 'data': {'provider': 'ollama', 'failures': 3}}
        self.assertEqual(evtext.text(ai, 'pt_BR'), ('Provedor de IA indisponível: ollama (3 falhas seguidas)',
                                                    'timeout'))
        post = {'type': 'posture_drop', 'title': 'x', 'detail': '', 'data': {'before': 80, 'after': 60}}
        self.assertEqual(evtext.text(post, 'pt_BR')[0], 'A nota de postura caiu de 80 para 60')

    def test_every_language_formats(self):
        import i18n
        for code in i18n.LANGUAGES:
            title, detail = evtext.text(Q, code)
            self.assertIn('192.0.2.24', title, code)
            self.assertIn('AS64500', detail, code)


if __name__ == '__main__':
    unittest.main()
