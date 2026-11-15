"""
Fixtures and fakes for the incident triage tests: a temporary root with config.xml, filter log, eve.json, a
quarantine ledger (written with the quarantine Store) and a fake Unbound "query" table (sqlite3 stands in for
DuckDB: the reader uses plain SQL), a fake command runner (php model.php, configctl) and a fake clock.

Only documentation addresses are external (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32,
through quarantine.common.TEST_EXTERNAL, set by the quarantine helpers); internal hosts are 192.168.1.0/24.
The log lines and alerts are written with the quarantine helpers (same layouts as the real firewall).
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(os.path.dirname(HERE), 'quarantine'))

import qhelpers  # noqa: E402  (sets TEST_EXTERNAL, TZ and the import path)
from qhelpers import T0, WAN_IP, eve_alert, filter_line  # noqa: E402,F401

from ai import changes, journal  # noqa: E402
from incidents import actions, cli, collect, common, engine, rules, store, triage  # noqa: E402,F401
from quarantine import store as qstore  # noqa: E402

LAN_DEV = 'igc0'
NAT_RULE = 'cccccccc-0443-2222-3333-444444444444'
OUT_BLOCK_RULE = 'dddddddd-0666-2222-3333-444444444444'

CONFIG = """<?xml version="1.0"?>
<opnsense>
  <system><webgui><protocol>https</protocol><port>443</port></webgui></system>
  <interfaces>
    <wan><if>pppoe1</if><descr>WAN_A</descr><enable>1</enable><ipaddr>pppoe</ipaddr></wan>
    <lan><if>igc0</if><descr>LAN</descr><enable>1</enable><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <OPNsense>
    <Firewall>
      <Filter version="1.0.6"><rules>
        <rule uuid="%(nat)s"><enabled>1</enabled><sequence>200</sequence><action>pass</action>
          <interface>wan</interface><direction>in</direction><description>NAT web server</description></rule>
        <rule uuid="%(blk)s"><enabled>1</enabled><sequence>300</sequence><action>block</action>
          <interface>lan</interface><direction>in</direction><description>Block Q-feeds outbound</description></rule>
      </rules></Filter>
    </Firewall>
    <cron><jobs>%(cron)s</jobs></cron>
  </OPNsense>
</opnsense>
"""
CRON_UUID = 'eeeeeeee-0005-2222-3333-444444444444'
CRON_XML = ('<job uuid="%s"><origin>PolicyAnalyzer</origin><enabled>1</enabled><minutes>*/5</minutes><hours>*</hours>'
            '<command>pa_incidents run</command><description>Policy Analyzer incidents</description></job>' % CRON_UUID)


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


class FakeRunner:
    """ php model.php cron_add/cron_del editing the config.xml of the test, configctl recorded """

    def __init__(self, case):
        self.case = case
        self.calls = []

    def read(self, argv, timeout=10):
        rc, out, _err = self.run(argv, timeout)
        return out if rc == 0 else ''

    def run(self, argv, timeout=30, stdin=None):
        self.calls.append(list(argv))
        name = os.path.basename(argv[0])
        if name == 'php':
            cmd = argv[2]
            if cmd == 'cron_add':
                created = not self.case.cron
                self.case.cron = True
                self.case.write_config()
                return 0, json.dumps({'status': 'ok', 'uuid': CRON_UUID, 'created': created}) + '\n', ''
            if cmd == 'cron_del':
                deleted = self.case.cron
                self.case.cron = False
                self.case.write_config()
                return 0, json.dumps({'status': 'ok', 'deleted': deleted}) + '\n', ''
            return 1, json.dumps({'status': 'error', 'message': 'usage'}), ''
        if name == 'configctl':
            return 0, 'OK\n', ''
        return 127, '', 'not found'


def v4(ts, src, dst, dport, action='pass', direction='in', iface='pppoe1', proto='tcp', flags='S', rid=NAT_RULE):
    return filter_line(ts, src, dport=dport, action=action, direction=direction, iface=iface, proto=proto,
                       flags=flags, rid=rid, dst=dst)


class IncidentCase(unittest.TestCase):
    installed = True

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-incidents-')
        self.clock = Clock()
        self.runner = FakeRunner(self)
        self.cron = False
        self.ctx = common.Context(root=self.tmp, runner=self.runner, clock=self.clock)
        for path in (self.ctx.state_dir, os.path.dirname(self.ctx.filter_log), os.path.dirname(self.ctx.eve),
                     os.path.dirname(self.ctx.config_xml)):
            os.makedirs(path, exist_ok=True)
        self.log_file = os.path.join(os.path.dirname(self.ctx.filter_log), 'filter_20261026.log')
        open(self.log_file, 'w').close()
        os.symlink(self.log_file, self.ctx.filter_log)
        open(self.ctx.eve, 'w').close()
        self.dns_path = os.path.join(self.tmp, 'unbound.sqlite')
        self.dns_enabled = False
        self.ctx.dns_connect = self.dns_connect
        self.undo = os.path.join(self.tmp, 'undo')
        self._undo_saved = journal.UNDO_DIR
        journal.UNDO_DIR = self.undo
        actions.CONTEXT_FACTORY = lambda: self.ctx
        cli.ENGINE_FACTORY = lambda: engine.Engine(self.ctx)
        self.write_config()
        if self.installed:
            st = store.Store(self.ctx.db, create=True)
            st.begin()
            for name, path in (('marker_filter', self.log_file), ('marker_eve', self.ctx.eve)):
                s = os.stat(path)
                st.set_meta(name, {'dev': s.st_dev, 'ino': s.st_ino, 'offset': 0})
            st.commit()
            st.close()

    def tearDown(self):
        journal.UNDO_DIR = self._undo_saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---------------------------------------------------------- fixtures

    def write_config(self):
        with open(self.ctx.config_xml, 'w') as handle:
            handle.write(CONFIG % {'nat': NAT_RULE, 'blk': OUT_BLOCK_RULE, 'cron': CRON_XML if self.cron else ''})

    def log(self, *lines):
        with open(self.log_file, 'a') as handle:
            handle.write(''.join(lines))

    def eve(self, *lines):
        with open(self.ctx.eve, 'a') as handle:
            handle.write(''.join(lines))

    def dns_connect(self):
        if not self.dns_enabled:
            return None
        return sqlite3.connect(self.dns_path)

    def dns(self, *rows):
        """ rows: (time, client, domain, action, blocklist) """
        self.dns_enabled = True
        db = sqlite3.connect(self.dns_path)
        db.execute('CREATE TABLE IF NOT EXISTS query (uuid TEXT, time INTEGER, client TEXT, family TEXT, type TEXT, '
                   'domain TEXT, action INTEGER, source INTEGER, blocklist TEXT, rcode INTEGER, '
                   'resolve_time_ms INTEGER, dnssec_status INTEGER, ttl INTEGER)')
        db.executemany('INSERT INTO query (time, client, domain, action, blocklist) VALUES (?, ?, ?, ?, ?)', rows)
        db.commit()
        db.close()

    def quarantine(self):
        """ a quarantine ledger written with the quarantine's own Store """
        return qstore.Store(self.ctx.quarantine_db, create=True)

    def run_engine(self, advance=0):
        self.clock.now += advance
        return engine.Engine(self.ctx).run()

    def db(self):
        return store.Store(self.ctx.db)

    def cases(self):
        st = self.db()
        try:
            return [st.case(r['id']) for r in st.db.execute('SELECT id FROM cases ORDER BY id')]
        finally:
            st.close()

    def detail(self, case_id):
        return engine.Engine(self.ctx).case_detail(case_id)['case']


class FakeProvider:
    """ answers with a fixed text (may contain the first placeholder seen); records the messages """

    def __init__(self, answer):
        self.answer = answer
        self.messages = None

    def endpoint(self):
        return 'http://127.0.0.1:11436'

    def chat(self, messages, stream=False, on_chunk=None):
        from ai.providers.base import GenerateResult
        self.messages = messages
        text = self.answer(messages) if callable(self.answer) else self.answer
        return GenerateResult(text=text, model='fable', duration_ms=900, prompt_tokens=500, completion_tokens=80)


def assistant(tmp, provider, enabled=True):
    from ai import AIConfig, Assistant, AuditLog
    config = AIConfig(enabled=enabled, provider='claudecode', anonymize=True, language='auto',
                      options={'model': 'fable'})
    return Assistant(config, app='policyanalyzer', audit=AuditLog(os.path.join(tmp, 'ai.log')), provider=provider)
