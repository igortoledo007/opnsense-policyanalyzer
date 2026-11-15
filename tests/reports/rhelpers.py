"""
Fixtures of the reports / notification center tests: a fake firewall state (config.xml with a Monit mail server,
quarantine.db, exposure.json, last.json, filter log), a FAKE local SMTP server on 127.0.0.1 (ephemeral port,
records the messages; nothing is ever sent to a real server) and a fake AI provider. Fictitious data only:
example.test domains, documentation addresses, CVE-2099-* ids.
"""

import base64
import json
import os
import shutil
import socket
import socketserver
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
SCRIPTS = os.path.join(os.path.dirname(TESTS), 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
for path in (SCRIPTS, os.path.join(TESTS, 'vulns')):
    if path not in sys.path:
        sys.path.insert(0, path)

import vhelpers  # noqa: E402

MONIT_PASSWORD = 'Fict1cious-Pa55word'


def config_xml(smtp_port=587, ssl='1'):
    return """<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.test</domain>
    <webgui><protocol>https</protocol><port>8443</port></webgui></system>
  <interfaces><wan><if>pppoe1</if><ipaddr>pppoe</ipaddr></wan><lan><if>igc0</if></lan></interfaces>
  <OPNsense>
    <monit version="1.0.14">
      <general><enabled>1</enabled><mailserver>smtp.example.test,smtp2.example.test</mailserver>
        <port>%d</port><username>monit@example.test</username><password>%s</password><ssl>%s</ssl>
        <sslversion>tlsv12</sslversion><sslverify>1</sslverify></general>
      <alert uuid="a1"><enabled>1</enabled><recipient>ops@example.test</recipient>
        <format>from: alerts@example.test
subject: [fw] $SERVICE</format></alert>
      <alert uuid="a2"><enabled>0</enabled><recipient>old@example.test</recipient></alert>
    </monit>
    <cron><jobs></jobs></cron>
  </OPNsense>
</opnsense>
""" % (smtp_port, MONIT_PASSWORD, ssl)


def stamp(epoch):
    return time.strftime('%Y-%m-%dT%H:%M:%S-03:00', time.gmtime(epoch - 3 * 3600))


def block_line(epoch, src, dport, proto='tcp', iface='pppoe1'):
    num = {'tcp': '6', 'udp': '17'}[proto]
    csv = ['55', '', '', 'rid', iface, 'match', 'block', 'in', '4', '0x0', '', '49', '1', '0', 'none', num, proto,
           '52', src, '192.0.2.1', '40000', str(dport), '0']
    if proto == 'tcp':
        csv += ['S', '1', '', '65535', '', 'mss']
    return '<134>1 %s fw.example.test filterlog 40707 - [meta sequenceId="1"] %s' % (stamp(epoch), ','.join(csv))


class FakeSMTP(object):
    """ plain SMTP (EHLO, AUTH PLAIN, MAIL, RCPT, DATA, QUIT) on 127.0.0.1:<ephemeral>; fail=True answers 451 """

    def __init__(self, fail=False):
        self.messages = []
        self.auth = []
        self.fail = fail
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                w = self.wfile.write
                w(b'220 fake.example.test ESMTP\r\n')
                mail = {'from': None, 'to': [], 'data': ''}
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    cmd = line.decode().strip()
                    up = cmd.upper()
                    if up.startswith('EHLO') or up.startswith('HELO'):
                        w(b'250-fake.example.test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n')
                    elif up.startswith('AUTH PLAIN'):
                        outer.auth.append(base64.b64decode(cmd.split()[2]).split(b'\0')[1:])
                        w(b'235 ok\r\n')
                    elif up.startswith('MAIL FROM'):
                        mail['from'] = cmd[10:].strip('<> ')
                        w(b'250 ok\r\n')
                    elif up.startswith('RCPT TO'):
                        mail['to'].append(cmd[8:].strip('<> '))
                        w(b'250 ok\r\n')
                    elif up == 'DATA':
                        w(b'354 go\r\n')
                        chunks = []
                        while True:
                            data = self.rfile.readline()
                            if data in (b'.\r\n', b''):
                                break
                            chunks.append(data.decode('utf-8', 'replace'))
                        mail['data'] = ''.join(chunks)
                        if outer.fail:
                            w(b'451 try later\r\n')
                        else:
                            outer.messages.append(dict(mail))
                            w(b'250 queued\r\n')
                        mail = {'from': None, 'to': [], 'data': ''}
                    elif up == 'QUIT':
                        w(b'221 bye\r\n')
                        return
                    else:
                        w(b'250 ok\r\n')

        self.server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def factory(self):
        """ smtp_factory for mailer.send: always connects to this fake server, whatever the channel says """
        import smtplib
        port = self.port

        def make(kind, host, _port, timeout, ctx):
            return smtplib.SMTP('127.0.0.1', port, timeout=timeout)
        return make


def quarantine_db(path, now):
    from quarantine import store as qstore
    db = sqlite3.connect(path)
    db.executescript(qstore.SCHEMA)
    entries = [(1, '203.0.113.5', 'ip', 64500, 'NL', 5, 'active', 'auto', 2, now - 90000, now - 600, 12),
               (2, '198.51.100.7', 'ip', 64501, 'BR', 1, 'active', 'auto', 1, now - 3000, now - 100, 1),
               (3, '203.0.113.0/24', 'net', 64502, 'CN', 6, 'permanent', 'manual', 5, now - 7000, now - 7000, 3)]
    db.executemany('INSERT INTO entries (id, addr, kind, asn, country, level, state, origin, reason, first_seen, '
                   'last_offense, offenses) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', entries)
    db.executemany('INSERT INTO offenses (ts, entry_id, reason, reasons, level, origin, country) '
                   'VALUES (?, ?, ?, ?, ?, ?, ?)',
                   [(now - 600, 1, 2, 2, 5, 'auto', 'NL'), (now - 1200, 1, 2, 2, 4, 'auto', 'NL'),
                    (now - 100, 2, 1, 1, 1, 'auto', 'BR')])
    db.executemany('INSERT INTO events (ts, entry_id, kind, level, origin) VALUES (?, ?, ?, ?, ?)',
                   [(now - 3000, 2, 'enter', 1, 'auto'), (now - 7000, 3, 'enter', 6, 'manual')])
    db.commit()
    db.close()


def add_quarantine_event(path, now, entry_id, kind, level, origin='auto'):
    db = sqlite3.connect(path)
    db.execute('INSERT INTO events (ts, entry_id, kind, level, origin) VALUES (?, ?, ?, ?, ?)',
               (now, entry_id, kind, level, origin))
    db.commit()
    db.close()


class ReportsCase(unittest.TestCase):
    smtp_port = 587

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-reports-')
        self.now = int(time.time())
        self.env = {k: os.environ.get(k) for k in ('POLICYANALYZER_DB', 'POLICYANALYZER_CONFIG',
                                                    'POLICYANALYZER_FILTERLOG', 'POLICYANALYZER_AILOG',
                                                    'POLICYANALYZER_ROOT', 'POLICYANALYZER_REPORTS_LOG')}
        os.environ['POLICYANALYZER_DB'] = self.tmp
        os.environ['POLICYANALYZER_CONFIG'] = self.path('config.xml')
        os.environ['POLICYANALYZER_FILTERLOG'] = self.path('filter.log')
        os.environ['POLICYANALYZER_AILOG'] = self.path('ai.log')
        os.environ['POLICYANALYZER_ROOT'] = self.path('root')
        os.environ['POLICYANALYZER_REPORTS_LOG'] = self.path('reports.log')
        from ai import journal
        self._undo = journal.UNDO_DIR
        journal.UNDO_DIR = self.path('undo')
        self.write_text('config.xml', config_xml(self.smtp_port))
        # the default language is en_US; these fixtures check the pt_BR strings, so the language is saved explicitly
        self.write_json('reports-settings.json', {'version': 1, 'language': 'pt_BR'})
        self.write_json('exposure.json', vhelpers.exposure_doc())
        self.write_json('vulns/kev.json', vhelpers.KEV)
        self.write_json('last.json', {'generated': '2026-11-08T03:00:00Z', 'summary': {
            'rules': 42, 'findings': 3, 'by_severity': {'high': 1, 'medium': 1, 'low': 1, 'info': 0}}, 'findings': [
            {'severity': 'high', 'type': 'shadowed', 'title': 'Rule is shadowed', 'rules': [{'summary': 'pass in on lan'}]},
            {'severity': 'medium', 'type': 'permissive', 'title': 'Permissive rule', 'rules': []}]})
        quarantine_db(self.path('quarantine.db'), self.now)
        lines = [block_line(self.now - 60 * i, '203.0.113.%d' % (i % 4 + 1), [22, 23, 3389, 443][i % 4])
                 for i in range(1, 40)]
        self.write_text('filter.log', '\n'.join(reversed(lines)) + '\n')
        from reports import actions
        self._runner = actions.RUNNER_FACTORY
        self.php_calls = []
        actions.RUNNER_FACTORY = lambda: self.fake_runner
        self.smtp = FakeSMTP()

    def fake_runner(self, argv, timeout=60):
        self.php_calls.append(list(argv))
        if argv[0].endswith('php'):
            return 0, json.dumps({'status': 'ok', 'uuid': '11111111-2222-3333-4444-555555555555'}) + '\n', ''
        return 0, 'OK\n', ''

    def tearDown(self):
        from ai import journal
        from reports import actions
        actions.RUNNER_FACTORY = self._runner
        journal.UNDO_DIR = self._undo
        self.smtp.close()
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, rel):
        return os.path.join(self.tmp, rel)

    def write_text(self, rel, text):
        os.makedirs(os.path.dirname(self.path(rel)), exist_ok=True)
        with open(self.path(rel), 'w') as handle:
            handle.write(text)

    def write_json(self, rel, data):
        self.write_text(rel, json.dumps(data))

    @staticmethod
    def payload(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
