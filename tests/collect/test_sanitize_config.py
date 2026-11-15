"""
config collector: sanitization (no secret reaches config.db, flags stay, HMAC stable and local), revisions
from /conf/backup in order, diff per item with fields, who/when from <revision>, idempotent runs, diff text.
"""

import os
import sqlite3
import unittest
import xml.etree.ElementTree as ET
import zlib

from chelpers import SECRETS, Sandbox, fixture

from collect import config, query, sanitize


def revision(xml, when, user, descr):
    root = ET.fromstring(xml)
    rev = root.find('./revision')
    rev.find('time').text = str(when)
    rev.find('username').text = user
    rev.find('description').text = descr
    return root


def tostring(root):
    return ET.tostring(root, encoding='utf-8')


def all_db_text(path):
    """ every text / blob of the database (XML blobs decompressed) """
    con = sqlite3.connect(path)
    out = []
    for (table,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
        for row in con.execute('SELECT * FROM %s' % table):
            for value in row:
                if isinstance(value, bytes):
                    try:
                        value = zlib.decompress(value)
                    except zlib.error:
                        pass
                    value = value.decode('utf-8', 'replace')
                out.append(str(value))
    con.close()
    with open(path, 'rb') as handle:
        out.append(handle.read().decode('latin-1'))
    return '\n'.join(out)


class TestSanitize(unittest.TestCase):
    def test_every_secret_masked_and_flags_kept(self):
        root = ET.fromstring(fixture('config-secrets.xml'))
        root, masked = sanitize.sanitize(root, b'k' * 32)
        text = tostring(root).decode()
        for secret in SECRETS:
            self.assertNotIn(secret, text, secret)
        self.assertGreaterEqual(masked, len(SECRETS) - 1)
        self.assertIn('<passwordauth>1</passwordauth>', text)       # flag, not a secret
        self.assertIn('<enabled>enabled</enabled>', text)
        self.assertIn('WGSERVERPUBKEY=', text)                        # public key stays
        self.assertIn('LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', text)    # certificate stays
        self.assertIn('<property>api_token</property>', text)
        self.assertRegex(root.find('./OPNsense/telemetry/value').text, r'^REDACTED:[0-9a-f]{16}$')

    def test_hmac_stable_per_key_and_detects_change(self):
        def masked(key, xml):
            return sanitize.sanitize(ET.fromstring(xml), key)[0].find('./system/user/password').text
        xml = fixture('config-secrets.xml')
        other = xml.replace(b'SECRETbcryptHASH', b'OTHERbcryptHASH')
        self.assertEqual(masked(b'a' * 32, xml), masked(b'a' * 32, xml))
        self.assertNotEqual(masked(b'a' * 32, xml), masked(b'a' * 32, other))
        self.assertNotEqual(masked(b'a' * 32, xml), masked(b'b' * 32, xml))

    def test_already_redacted_is_kept(self):
        root = ET.fromstring(b'<opnsense><system><user><password>REDACTED:0123456789abcdef</password></user>'
                             b'</system></opnsense>')
        root, count = sanitize.sanitize(root, b'k' * 32)
        self.assertEqual(count, 0)
        self.assertEqual(root.find('./system/user/password').text, 'REDACTED:0123456789abcdef')

    def test_items_cover_sections(self):
        items = sanitize.extract_items(ET.fromstring(fixture('config-secrets.xml')))
        self.assertIn(('filter.rule_mvc', '55555555-5555-5555-5555-555555555555'), items)
        self.assertIn(('alias', '44444444-4444-4444-4444-444444444444'), items)
        self.assertIn(('interface', 'wan'), items)
        self.assertIn(('usuario', 'root'), items)
        self.assertTrue(any(s.startswith('mvc:') for s, _ in items))


class TestConfigCollector(Sandbox):
    def setUp(self):
        super().setUp()
        xml = fixture('config-secrets.xml')
        r1 = revision(xml, 1792990000.5, 'admin@192.0.2.10', 'baseline')
        r2 = revision(xml, 1792993600.25, 'igor@192.168.1.50', '/firewall_rules_edit.php made changes')
        r2.find('./system/user/password').text = '$2y$11$NEWSECRETHASHvalue'
        rule = r2.find('./OPNsense/Firewall/Filter/rules')
        new = ET.SubElement(rule, 'rule', uuid='aaaaaaaa-0000-0000-0000-000000000001')
        ET.SubElement(new, 'action').text = 'pass'
        ET.SubElement(new, 'description').text = 'Allow WireGuard'
        r3 = revision(tostring(r2), 1792997200.0, '(root)', 'policyanalyzer made changes')
        aliases = r3.find('./OPNsense/Firewall/Alias/aliases')
        aliases.remove(aliases.find('alias'))
        self.revs = (r1, r2, r3)
        for r in self.revs:
            self.write('/conf/backup/config-%s.xml' % r.find('./revision/time').text, tostring(r))
        self.write('/conf/config.xml', tostring(r3))

    def test_history_diff_and_authors(self):
        result = config.run(self.ctx, self.settings)
        self.assertEqual(result['snapshots'], 3)            # config.xml == newest backup: no extra snapshot
        q = query.Query(self.ctx)
        revs = q.config_revisions('2026-10-01', '2026-11-01')
        self.assertEqual([r['author'] for r in revs], ['admin', 'igor', '(root)'])
        self.assertEqual(revs[1]['author_ip'], '192.168.1.50')
        changes = q.config_changes('2026-10-01', '2026-11-01')
        kinds = {(c['section'], c['kind']) for c in changes}
        self.assertIn(('filter.rule_mvc', 'added'), kinds)
        self.assertIn(('usuario', 'changed'), kinds)
        self.assertIn(('alias', 'removed'), kinds)
        user = [c for c in changes if c['section'] == 'usuario'][0]
        self.assertEqual(user['fields'][0]['field'], 'password')
        self.assertRegex(user['fields'][0]['new'], r'^REDACTED:')
        self.assertEqual(user['author'], 'igor')
        diff = q.config_diff(revs[0]['id'], revs[2]['id'])
        self.assertIn('Allow WireGuard', diff)
        self.assertNotIn('NEWSECRETHASH', diff)

    def test_no_secret_in_database(self):
        config.run(self.ctx, self.settings)
        text = all_db_text(self.ctx.db['config'])
        for secret in SECRETS + ('NEWSECRETHASH',):
            self.assertNotIn(secret, text, secret)
        self.assertEqual(os.stat(self.ctx.hmac_key).st_mode & 0o777, 0o600)

    def test_idempotent_and_incremental(self):
        config.run(self.ctx, self.settings)
        again = config.run(self.ctx, self.settings)
        self.assertEqual((again['snapshots'], again['files_new']), (0, 0))
        r4 = revision(tostring(self.revs[2]), 1793000000.0, 'admin@192.0.2.10', 'dns change')
        r4.find('./system/dnsserver').text = '192.0.2.54'
        self.write('/conf/backup/config-1793000000.0.xml', tostring(r4))
        self.write('/conf/config.xml', tostring(r4))
        third = config.run(self.ctx, self.settings)
        self.assertEqual(third['snapshots'], 1)
        self.assertEqual(third['latest']['changes'], 1)
        self.assertEqual(query.Query(self.ctx).config_changes('2026-10-26T00:00:00Z', 'now')[-1]['section'],
                         'sistema.dns')

    def test_split_user(self):
        self.assertEqual(config.split_user('root@2001:db8::1'), ('root', '2001:db8::1'))
        self.assertEqual(config.split_user('(system)'), ('(system)', None))
        self.assertEqual(config.split_user(None), (None, None))


if __name__ == '__main__':
    unittest.main()
