"""
Fixtures and fakes for the quarantine tests: a temporary root with config.xml, filter log and eve.json,
a fake command runner (pfctl, php model.php, configctl and the runtime probes) and a fake clock.

Only documentation addresses are used (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32); the
quarantine treats them as public through common.TEST_EXTERNAL (production never sets it).
"""

import ipaddress
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import uuid as uuidlib

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'plugin', 'src', 'opnsense', 'scripts',
                       'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
os.environ.setdefault('PYTHONDONTWRITEBYTECODE', '1')
sys.dont_write_bytecode = True

from quarantine import actions, cli, common, engine, fwconfig, guards, lookup, pf, sources, store  # noqa: E402,F401

common.TEST_EXTERNAL = (ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24'),
                        ipaddress.ip_network('203.0.113.0/24'), ipaddress.ip_network('2001:db8::/32'))

# a fixed local time zone so that years and dates are stable
os.environ['TZ'] = 'America/Sao_Paulo'
time.tzset()

T0 = 1793000000          # 2026-10-26 (a Monday), the fake "now" of the tests
WAN_IP = '198.51.100.1'  # the firewall's own WAN address
RULE_UUID = 'aaaaaaaa-1111-2222-3333-444444444444'
WG_RULE_UUID = 'bbbbbbbb-1731-2222-3333-444444444444'

CONFIG = """<?xml version="1.0"?>
<opnsense>
  <system>
    <dnsserver>198.51.100.53</dnsserver>
    <timeservers>198.51.100.123 ntp.example.org</timeservers>
    <webgui><protocol>https</protocol><port>443</port></webgui>
  </system>
  <interfaces>
    <wan><if>pppoe1</if><descr>WAN_A</descr><enable>1</enable><ipaddr>pppoe</ipaddr></wan>
    <lan><if>igc0</if><descr>LAN</descr><enable>1</enable><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
    <opt6><if>igc2</if><descr>WAN_B</descr><enable>1</enable><ipaddr>192.168.88.2</ipaddr>
      <gateway>WAN_B</gateway></opt6>
    <opt8><if>wg4</if><descr>VPN_Remote</descr><enable>1</enable></opt8>
  </interfaces>
  <gateways>
    <gateway_item><name>WAN_B</name><gateway>192.168.88.1</gateway><interface>opt6</interface>
      <monitor>198.51.100.8</monitor></gateway_item>
  </gateways>
  <OPNsense>
    <wireguard>
      <server><servers><server uuid="w1"><enabled>1</enabled><name>Remote</name><port>51830</port></server>
      </servers></server>
      <client><clients><client uuid="c1"><name>peer</name><serveraddress>198.51.100.77</serveraddress>
      <serverport>51820</serverport></client></clients></client>
    </wireguard>
    <Firewall>
      <Alias version="1.0.1"><aliases>
        %(aliases)s
      </aliases></Alias>
      <Filter version="1.0.6"><rules>
        <rule uuid="r-100"><enabled>1</enabled><sequence>100</sequence><action>block</action><quick>1</quick>
          <interface>wan,opt6</interface><direction>in</direction><source_net>GeoIP</source_net>
          <description>BL GeoIP</description></rule>
        <rule uuid="bbbbbbbb-1731-2222-3333-444444444444"><enabled>1</enabled><sequence>1731</sequence><action>pass</action><quick>1</quick>
          <interface>wan,opt6</interface><direction>in</direction><protocol>UDP</protocol>
          <destination_port>51830</destination_port><log>%(wglog)s</log><description>VPN Remote access</description></rule>
        %(rules)s
      </rules></Filter>
    </Firewall>
    <cron><jobs>%(cron)s</jobs></cron>
  </OPNsense>
</opnsense>
"""

NEVER_ALIAS_XML = ('<alias uuid="a-never"><enabled>1</enabled><name>pa_never_block</name><type>network</type>'
                   '<content>%s</content></alias>')
QUAR_ALIAS_XML = '<alias uuid="a-quar"><enabled>1</enabled><name>pa_quarantine</name><type>external</type></alias>'
RULE_XML = ('<rule uuid="%s"><enabled>%s</enabled><sequence>99</sequence><action>block</action><quick>1</quick>'
            '<interface>wan,opt6</interface><direction>in</direction><source_net>pa_quarantine</source_net>'
            '<log>1</log><description>Max Cyber IA</description></rule>')
CRON_XML = ('<job uuid="j-1"><enabled>1</enabled><minutes>*/5</minutes><hours>*</hours>'
            '<command>policyanalyzer quarantine_run</command><description>x</description></job>')


def filter_line(ts, src, dport=22, action='block', direction='in', iface='pppoe1', proto='tcp', flags='S',
                rid='8faed529-7112-480b-bdcd-159350ed3f4c', dst=WAN_IP, ipver=4):
    """ a filterlog line in the RFC 5424 layout of the firewall """
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S-03:00', time.gmtime(ts - 3 * 3600))
    if ipver == 6:
        csv = '55,,,%s,%s,match,%s,%s,6,0x00,0x00000,64,%s,%s,80,%s,%s,40000,%s,0,%s,1,,65535,,mss' % (
            rid, iface, action, direction, proto, 6 if proto == 'tcp' else 17, src, dst, dport, flags)
    elif proto == 'tcp':
        csv = '55,,,%s,%s,match,%s,%s,4,0x0,,49,30411,0,none,6,tcp,52,%s,%s,33714,%s,0,%s,1840476233,,65535,,mss' % (
            rid, iface, action, direction, src, dst, dport, flags)
    elif proto == 'udp':
        csv = '55,,,%s,%s,match,%s,%s,4,0x0,,49,30411,0,none,17,udp,76,%s,%s,41170,%s,56' % (
            rid, iface, action, direction, src, dst, dport)
    else:
        csv = '55,,,%s,%s,match,%s,%s,4,0x0,,49,30411,0,none,1,icmp,84,%s,%s,request,1,1' % (
            rid, iface, action, direction, src, dst)
    return '<134>1 %s OPNsense.example.lan filterlog 40707 - [meta sequenceId="1"] %s\n' % (stamp, csv)


def eve_alert(ts, src, severity=1, sid=2003933, dport=443, dst=WAN_IP):
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S.123456-0300', time.gmtime(ts - 3 * 3600))
    return json.dumps({'timestamp': stamp, 'event_type': 'alert', 'src_ip': src, 'src_port': 40000,
                       'dest_ip': dst, 'dest_port': dport, 'proto': 'TCP',
                       'alert': {'action': 'allowed', 'signature_id': sid, 'signature': 'ET TEST signature',
                                 'category': 'Attempted Administrator Privilege Gain', 'severity': severity}},
                      separators=(',', ':')) + '\n'


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


class FakeRunner:
    """ pfctl table in memory, php model.php editing the config.xml of the test, recorded calls """

    def __init__(self, case):
        self.case = case
        self.calls = []
        self.table = None              # None: table not loaded
        self.killed = []
        self.outputs = {'ifconfig': '\tinet 198.51.100.1 --> 198.51.100.254 netmask 0xffffffff\n'
                                    '\tinet 192.168.1.1 netmask 0xffffff00\n',
                        'netstat': 'Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n'
                                   'default 198.51.100.254 UGS pppoe1\n',
                        'wg': 'wg4\tKEY=\t198.51.100.66:51820\n', 'ntpq': '', 'sockstat': '', 'tailscale': ''}
        self.fail = set()

    def read(self, argv, timeout=10):
        rc, out, _err = self.run(argv, timeout)
        return out if rc == 0 else ''

    def run(self, argv, timeout=30, stdin=None):
        self.calls.append(list(argv))
        name = os.path.basename(argv[0])
        if name in self.fail:
            return 1, '', '%s failed' % name
        if name == 'pfctl':
            return self._pfctl(argv[1:])
        if name == 'php':
            return self._php(argv[2:])
        if name == 'configctl':
            if argv[1:3] == ['filter', 'reload'] and self.case.has_alias(common.ALIAS) and self.table is None:
                self.table = set()
            return 0, 'OK\n', ''
        if name == 'pgrep':
            return (0, '4242\n', '') if self.case.suricata_running else (1, '', '')
        for key in ('ifconfig', 'netstat', 'wg', 'ntpq', 'sockstat', 'tailscale'):
            if name == key:
                return 0, self.outputs[key], ''
        return 127, '', 'not found'

    def _pfctl(self, args):
        if args[:2] == ['-s', 'Tables']:
            return 0, ('pa_quarantine\n' if self.table is not None else '') + 'bogons\n', ''
        if args[0] == '-k':
            self.killed.append(args[1])
            return 0, '', ''
        if args[0] == '-t' and args[1] == common.ALIAS:
            op, items = args[3], args[4:]
            if self.table is None and op != 'kill':
                return 1, '', 'pfctl: Table does not exist.'
            if op == 'show':
                return 0, ''.join('   %s\n' % e for e in sorted(self.table)), ''
            if op == 'add':
                self.table |= set(items)
            elif op == 'delete':
                self.table -= set(items)
            elif op == 'flush':
                self.table = set()
            elif op == 'kill':
                self.table = None
            return 0, '', ''
        return 1, '', 'unexpected pfctl'

    def _php(self, args):
        cmd = args[0]
        case = self.case
        if cmd == 'alias_add':
            if case.has_alias(args[1]):
                return 0, json.dumps({'status': 'ok', 'uuid': 'a-old', 'created': False}), ''
            content = ''
            if len(args) > 2 and args[2]:
                import base64
                content = base64.b64decode(args[2]).decode()
            case.aliases[args[1]] = content
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'uuid': 'a-' + args[1], 'created': True}), ''
        if cmd == 'alias_del':
            name = {'a-quar': common.ALIAS, 'a-never': common.NEVER_ALIAS, 'a-' + common.ALIAS: common.ALIAS,
                    'a-' + common.NEVER_ALIAS: common.NEVER_ALIAS}.get(args[1])
            case.aliases.pop(name, None)
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'deleted': True}), ''
        if cmd == 'alias_entry':
            items = [i for i in case.aliases.get(args[1], '').split('\n') if i]
            if args[2] == 'add' and args[3] not in items:
                items.append(args[3])
            elif args[2] == 'del' and args[3] in items:
                items.remove(args[3])
            case.aliases[args[1]] = '\n'.join(items)
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'changed': True}), ''
        if cmd == 'rule_add':
            case.rule = {'uuid': RULE_UUID, 'enabled': args[3] if len(args) > 3 else '1', 'sequence': args[1],
                         'interfaces': args[2]}
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'uuid': RULE_UUID, 'created': True}), ''
        if cmd == 'rule_del':
            case.rule = None
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'changed': True}), ''
        if cmd == 'rule_enable':
            case.rule['enabled'] = args[2]
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'changed': True}), ''
        if cmd == 'rule_log':
            if args[1] != WG_RULE_UUID:
                return 1, json.dumps({'status': 'error', 'message': 'only the logging of a pass rule'}), ''
            case.wg_log = args[2]
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'changed': True}), ''
        if cmd == 'cron_add':
            case.cron = True
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'uuid': 'j-1', 'created': True}), ''
        if cmd == 'cron_del':
            case.cron = False
            case.write_config()
            return 0, json.dumps({'status': 'ok', 'deleted': True}), ''
        return 1, json.dumps({'status': 'error', 'message': 'unknown'}), ''


class QuarantineCase(unittest.TestCase):
    """ a temporary root; installed=True creates the ledger, the aliases, the rule and the cron job """

    installed = True

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-quarantine-')
        self.aliases = {}
        self.rule = None
        self.cron = False
        self.wg_log = '1'
        self.suricata_running = False
        self.clock = Clock()
        self.runner = FakeRunner(self)
        self.spawned = []
        self.ctx = common.Context(root=self.tmp, runner=self.runner, clock=self.clock, is_root=True,
                                  spawn=self.spawned.append)
        for path in (self.ctx.state_dir, os.path.dirname(self.ctx.filter_log), os.path.dirname(self.ctx.eve),
                     os.path.dirname(self.ctx.config_xml), self.ctx.geoip_dir, os.path.dirname(self.ctx.asn_csv),
                     os.path.dirname(self.ctx.resolv_conf)):
            os.makedirs(path, exist_ok=True)
        self.log_file = os.path.join(os.path.dirname(self.ctx.filter_log), 'filter_20261026.log')
        open(self.log_file, 'w').close()
        os.symlink(self.log_file, self.ctx.filter_log)
        open(self.ctx.eve, 'w').close()
        with open(self.ctx.resolv_conf, 'w') as handle:
            handle.write('nameserver 198.51.100.54\n')
        actions.CONTEXT_FACTORY = lambda: self.ctx
        actions.ENGINE_OPTIONS = {'runtime_guards': True, 'resolver': self.resolver}
        cli.ENGINE_FACTORY = lambda: self.engine()
        if self.installed:
            self.aliases = {common.ALIAS: None, common.NEVER_ALIAS: ''}
            self.rule = {'uuid': RULE_UUID, 'enabled': '1', 'sequence': '99', 'interfaces': 'wan,opt6'}
            self.cron = True
            self.runner.table = set()
            st = store.Store(self.ctx.db, create=True)
            st.begin()
            st.set_meta('installed', T0)
            st.set_meta('paused', '0')
            st.set_meta('marker_filter', {'dev': os.stat(self.log_file).st_dev, 'ino': os.stat(self.log_file).st_ino,
                                          'offset': 0})
            st.set_meta('marker_eve', {'dev': os.stat(self.ctx.eve).st_dev, 'ino': os.stat(self.ctx.eve).st_ino,
                                       'offset': 0})
            st.commit()
            st.close()
        self.write_config()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def resolver(name):
        return {'ntp.example.org': ['198.51.100.124']}.get(name, [])

    def engine(self):
        return engine.Engine(self.ctx, runtime_guards=True, resolver=self.resolver)

    def has_alias(self, name):
        return name in self.aliases

    def write_config(self):
        aliases = ''
        if common.ALIAS in self.aliases:
            aliases += QUAR_ALIAS_XML
        if common.NEVER_ALIAS in self.aliases:
            aliases += NEVER_ALIAS_XML % (self.aliases[common.NEVER_ALIAS] or '')
        rules = RULE_XML % (self.rule['uuid'], self.rule['enabled']) if self.rule else ''
        with open(self.ctx.config_xml, 'w') as handle:
            handle.write(CONFIG % {'aliases': aliases, 'rules': rules, 'cron': CRON_XML if self.cron else '',
                                   'wglog': self.wg_log})

    def log(self, *lines):
        with open(self.log_file, 'a') as handle:
            handle.write(''.join(lines))

    def eve(self, *lines):
        with open(self.ctx.eve, 'a') as handle:
            handle.write(''.join(lines))

    def run_engine(self, advance=0):
        self.clock.now += advance
        return self.engine().run()

    def db(self):
        return store.Store(self.ctx.db)

    def entry(self, addr):
        st = self.db()
        try:
            return st.entry_by_addr(addr)
        finally:
            st.close()

    def offenses(self, addr):
        st = self.db()
        try:
            entry = st.entry_by_addr(addr)
            return st.offenses(entry_id=entry['id'], rows=0)[1] if entry else []
        finally:
            st.close()

    def set_setting(self, key, value):
        st = self.db()
        st.begin()
        st.set_setting(key, value)
        st.commit()
        st.close()


def new_uuid():
    return str(uuidlib.uuid4())
