import unittest

import ai_helpers  # noqa: F401  (sets sys.path)
from ai.anonymizer import Anonymizer, StreamRestorer


FINDING = {
    'id': 'a1b2c3d4',
    'type': 'shadowed',
    'title': 'Rule is shadowed by an earlier rule',
    'detail': 'pass in on lan from 192.168.10.5 to 8.8.8.8 port 53 is covered by rule 3 (nas.home.lan)',
    'rules': [
        {'interface': 'lan', 'action': 'pass', 'sequence': 3, 'description': 'Alice laptop to NAS',
         'summary': 'pass in on lan from Alice_Laptop to 192.168.10.0/24 port 445'},
        {'interface': 'wan', 'action': 'block', 'sequence': 7, 'description': 'Block 203.0.113.9',
         'summary': 'block in on wan from 2001:db8::10 to any'},
    ],
    'aliases': ['Alice_Laptop'],
    'evidence': {'hostname': 'printer.office.example.com', 'mac': 'aa:bb:cc:dd:ee:ff', 'contact': 'admin@example.org',
                 'loopback': '127.0.0.1', 'any': '0.0.0.0/0', 'time': '18:06:00', 'file': 'last.json'},
}


class AnonymizerTest(unittest.TestCase):
    def setUp(self):
        self.anon = Anonymizer()
        self.out = self.anon.anonymize(FINDING)
        self.flat = repr(self.out)

    def test_hides_identifying_values(self):
        for secret in ('192.168.10.5', '8.8.8.8', '203.0.113.9', '2001:db8::10', 'nas.home.lan', 'Alice laptop',
                       'Alice_Laptop', 'printer.office.example.com', 'aa:bb:cc:dd:ee:ff', 'admin@example.org'):
            self.assertNotIn(secret, self.flat, secret)

    def test_keeps_semantics(self):
        self.assertEqual(self.out['type'], 'shadowed')
        self.assertEqual(self.out['rules'][0]['interface'], 'lan')
        self.assertEqual(self.out['rules'][0]['sequence'], 3)
        self.assertIn('port 445', self.out['rules'][0]['summary'])
        self.assertEqual(self.out['evidence']['loopback'], '127.0.0.1')
        self.assertEqual(self.out['evidence']['any'], '0.0.0.0/0')
        self.assertEqual(self.out['evidence']['time'], '18:06:00')
        self.assertEqual(self.out['evidence']['file'], 'last.json')

    def test_private_public_hint_and_prefix(self):
        summary = self.out['rules'][0]['summary']
        self.assertRegex(summary, r'IP4_PRIV_\d+/24')
        self.assertRegex(self.out['detail'], r'IP4_PUB_\d+')

    def test_consistent_tokens(self):
        alias_token = self.out['aliases'][0]
        self.assertTrue(alias_token.startswith('ALIAS_'))
        self.assertIn(alias_token, self.out['rules'][0]['summary'])
        anon2 = self.anon.anonymize({'x': '192.168.10.5'})
        self.assertIn(anon2['x'], self.flat)

    def test_description_with_ip_hidden_as_whole(self):
        self.assertTrue(self.out['rules'][1]['description'].startswith('DESC_'))

    def test_roundtrip(self):
        answer = 'Rule %s on lan (%s) shadows traffic from %s; host %s.' % (
            self.out['rules'][0]['sequence'], self.out['rules'][0]['description'], self.out['aliases'][0],
            self.out['evidence']['hostname'])
        restored = self.anon.deanonymize(answer)
        self.assertIn('Alice laptop to NAS', restored)
        self.assertIn('Alice_Laptop', restored)
        self.assertIn('printer.office.example.com', restored)

    def test_token_number_prefixes(self):
        anon = Anonymizer()
        out = anon.anonymize({'a': ' '.join('10.0.0.%d' % i for i in range(1, 13))})
        self.assertIn('IP4_PRIV_12', out['a'])
        self.assertEqual(anon.deanonymize('IP4_PRIV_1 IP4_PRIV_12'), '10.0.0.1 10.0.0.12')

    def test_unknown_token_left_alone(self):
        self.assertEqual(self.anon.deanonymize('see HOST_999'), 'see HOST_999')

    def test_disabled_is_identity(self):
        anon = Anonymizer(enabled=False)
        self.assertEqual(anon.anonymize(FINDING), FINDING)
        self.assertEqual(anon.deanonymize('IP4_PRIV_1'), 'IP4_PRIV_1')

    def test_extra_terms(self):
        anon = Anonymizer(extra_terms=['ACME Corp'])
        self.assertEqual(anon.anonymize({'d': 'owned by ACME Corp'})['d'], 'owned by TERM_1')

    def test_does_not_mutate_input(self):
        self.assertEqual(FINDING['rules'][0]['description'], 'Alice laptop to NAS')

    def test_stream_restorer_never_splits_tokens(self):
        token = self.out['aliases'][0]
        text = 'traffic from %s is shadowed.' % token
        restorer = StreamRestorer(self.anon)
        chunks = [text[i:i + 3] for i in range(0, len(text), 3)]
        restored = ''.join(restorer.feed(c) for c in chunks) + restorer.flush()
        self.assertEqual(restored, 'traffic from Alice_Laptop is shadowed.')


if __name__ == '__main__':
    unittest.main()
