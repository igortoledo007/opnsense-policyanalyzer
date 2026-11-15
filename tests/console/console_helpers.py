"""
Shared fixtures of the AI Console tests: a synthetic firewall (config.xml, filter log, eve.json, Kea leases,
config backups, rule counters, Policy Analyzer and exposure reports, quarantine ledger) written into a
temporary directory.  LAN addresses are RFC 1918, internet addresses come from the documentation ranges
(203.0.113.0/24, 198.51.100.0/24); nothing comes from the real firewall.
"""

import json
import os
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
SCRIPTS = os.path.join(ROOT, 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from ai.providers.base import GenerateResult  # noqa: E402
from console.common import Paths  # noqa: E402

U_ALLOW_LAN = '11111111-1111-4111-8111-111111111111'
U_BLOCK_PRINTER = '22222222-2222-4222-8222-222222222222'
U_BLOCK_IOT = '33333333-3333-4333-8333-333333333333'
U_ALLOW_IOT = '44444444-4444-4444-8444-444444444444'
U_SSH_WAN = '55555555-5555-4555-8555-555555555555'
L_DEFAULT_DENY = '02f4bab031b57d1e30553ce08e0ec131'

NOW = 1794200000          # 2026-11-08 (UTC), fixed clock of the tests

RULE = """
      <rule uuid="{uuid}">
        <enabled>1</enabled><sequence>{seq}</sequence><action>{action}</action><quick>1</quick>
        <interface>{iface}</interface><direction>in</direction><ipprotocol>inet</ipprotocol>
        <protocol>{proto}</protocol><source_net>{src}</source_net><destination_net>{dst}</destination_net>
        <destination_port>{dport}</destination_port><log>1</log><description>{descr}</description>
      </rule>"""


def config_xml(extra_rule=True, allow_lan_dst='any', revision_time=NOW - 600, revision_descr='saved a rule'):
    rules = [
        dict(uuid=U_ALLOW_LAN, seq=100, action='pass', iface='lan', proto='any', src='lan', dst=allow_lan_dst,
             dport='', descr='Allow LAN to any'),
        dict(uuid=U_BLOCK_PRINTER, seq=10, action='block', iface='lan', proto='TCP', src='192.168.1.50',
             dst='any', dport='443', descr='Block printer HTTPS'),
        dict(uuid=U_BLOCK_IOT, seq=10, action='block', iface='opt1', proto='any', src='IoT_net', dst='lan',
             dport='', descr='Block IoT to LAN'),
        dict(uuid=U_ALLOW_IOT, seq=20, action='pass', iface='opt1', proto='any', src='IoT_net', dst='any',
             dport='', descr='Allow IoT internet'),
    ]
    if extra_rule:
        rules.append(dict(uuid=U_SSH_WAN, seq=10, action='pass', iface='wan', proto='TCP', src='any',
                          dst='192.168.1.10', dport='22', descr='SSH to server'))
    return """<?xml version="1.0"?>
<opnsense>
  <version>26.7</version>
  <system><hostname>fw</hostname><domain>example.lan</domain>
    <user><name>admin</name><password>$2y$secret</password></user>
  </system>
  <interfaces>
    <wan><if>pppoe1</if><descr>WAN</descr><enable>1</enable><ipaddr>pppoe</ipaddr></wan>
    <lan><if>igc0</if><descr>LAN</descr><enable>1</enable><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
    <opt1><if>igc1</if><descr>IoT</descr><enable>1</enable><ipaddr>192.168.20.1</ipaddr><subnet>24</subnet></opt1>
  </interfaces>
  <revision><username>admin@192.168.1.20</username><description>{rdescr}</description><time>{rtime}</time></revision>
  <OPNsense>
    <Firewall>
      <Alias version="1.0.1"><aliases>
        <alias uuid="a1"><enabled>1</enabled><name>Printers</name><type>host</type><content>192.168.1.50</content>
          <description>office printers</description></alias>
        <alias uuid="a2"><enabled>1</enabled><name>IoT_net</name><type>network</type><content>192.168.20.0/24</content>
          <description>iot devices</description></alias>
        <alias uuid="a3"><enabled>1</enabled><name>Blocklist</name><type>urltable</type>
          <url>https://feeds.example.com/list.txt</url><description>external feed</description></alias>
      </aliases></Alias>
      <Filter version="1.0.4"><rules>{rules}
      </rules></Filter>
    </Firewall>
    <Kea><dhcp4><reservations>
      <reservation uuid="k1"><subnet>s1</subnet><ip_address>192.168.1.50</ip_address>
        <hw_address>00:11:22:33:44:55</hw_address><hostname>printer</hostname><description>hall</description></reservation>
    </reservations></dhcp4></Kea>
    <unboundplus><hosts>
      <host uuid="h1"><enabled>1</enabled><hostname>nas</hostname><domain>example.lan</domain><rr>A</rr>
        <server>192.168.1.10</server><description>storage</description></host>
    </hosts></unboundplus>
  </OPNsense>
</opnsense>
""".format(rules=''.join(RULE.format(**r) for r in rules), rtime='%.2f' % revision_time, rdescr=revision_descr)


def stamp(epoch):
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(epoch))


def v4(ts, iface, action, direction, proto, src, dst, sport='', dport='', rid=U_ALLOW_LAN, flags='S'):
    """ one filterlog line (RFC 5424), IPv4 layout of filterlog/files/description.txt """
    if proto == 'tcp':
        protonum, tail = '6', '60,%s,%s,%s,%s,0,%s,1,,64240,,mss' % (src, dst, sport, dport, flags)
    elif proto == 'udp':
        protonum, tail = '17', '60,%s,%s,%s,%s,40' % (src, dst, sport, dport)
    else:
        protonum, tail = '1', '84,%s,%s,datalength=64' % (src, dst)
    csv = '7,,,%s,%s,match,%s,%s,4,0x0,,64,1234,0,DF,%s,%s,%s' % (rid, iface, action, direction, protonum, proto, tail)
    return '<134>1 %s fw.example.lan filterlog 40707 - [meta sequenceId="1"] %s' % (stamp(ts), csv)


def filter_lines(now=NOW):
    """ oldest first, as filterlog writes them """
    lines = []
    # an internet scanner probing the WAN (blocked by the default deny)
    for i, port in enumerate((22, 23, 445, 3389, 8080, 5900, 1433, 21, 25, 110)):
        lines.append(v4(now - 3000 + i * 10, 'pppoe1', 'block', 'in', 'tcp', '203.0.113.9', '198.51.100.1',
                        '40000', str(port), rid=L_DEFAULT_DENY))
    # the printer is blocked on 443 by its rule, allowed elsewhere
    for i in range(6):
        lines.append(v4(now - 1800 + i * 30, 'igc0', 'block', 'in', 'tcp', '192.168.1.50', '198.51.100.20',
                        '5%04d' % i, '443', rid=U_BLOCK_PRINTER))
    lines.append(v4(now - 1500, 'igc0', 'pass', 'in', 'udp', '192.168.1.50', '192.168.1.1', '5353', '53',
                    rid=U_ALLOW_LAN))
    # IoT tries to reach the LAN
    for i in range(3):
        lines.append(v4(now - 900 + i, 'igc1', 'block', 'in', 'tcp', '192.168.20.7', '192.168.1.10', '6000%d' % i,
                        '445', rid=U_BLOCK_IOT))
    lines.append(v4(now - 600, 'igc1', 'pass', 'in', 'icmp', '192.168.20.7', '198.51.100.30', rid=U_ALLOW_IOT))
    lines.append('<38>1 %s fw.example.lan sshd 1 - [meta] not a filter line' % stamp(now - 500))
    lines.append(v4(now - 60, 'pppoe1', 'block', 'in', 'udp', '198.51.100.77', '198.51.100.1', '1234', '5060',
                    rid=L_DEFAULT_DENY))
    return lines


def eve_lines(now=NOW):
    """ compact JSON, as Suricata writes it """
    def dumps(obj):
        return json.dumps(obj, separators=(',', ':'))

    def ts(epoch):
        return time.strftime('%Y-%m-%dT%H:%M:%S.000000+0000', time.gmtime(epoch))
    out = [dumps({'timestamp': ts(now - 4000), 'flow_id': 1, 'event_type': 'flow', 'src_ip': '192.168.1.50'})]
    out.append(dumps({
        'timestamp': ts(now - 2000), 'flow_id': 1442201202389147, 'in_iface': 'pppoe1', 'event_type': 'alert',
        'src_ip': '203.0.113.9', 'src_port': 58574, 'dest_ip': '198.51.100.1', 'dest_port': 80, 'proto': 'TCP',
        'alert': {'action': 'blocked', 'gid': 1, 'signature_id': 2003933, 'rev': 12,
                  'signature': 'ET MALWARE Banker.Delf User-Agent (Ms)', 'category': 'A Network Trojan was detected',
                  'severity': 1, 'metadata': {'signature_severity': ['Major'], 'confidence': ['High']}},
        'http': {'hostname': 'evil.example.com', 'url': '/'}, 'app_proto': 'http', 'direction': 'to_server'}))
    out.append(dumps({'timestamp': ts(now - 1000), 'flow_id': 2, 'event_type': 'tls', 'src_ip': '192.168.1.50'}))
    out.append(dumps({
        'timestamp': ts(now - 300), 'flow_id': 77, 'in_iface': 'igc0', 'event_type': 'alert',
        'src_ip': '192.168.1.50', 'src_port': 5000, 'dest_ip': '198.51.100.20', 'dest_port': 443, 'proto': 'TCP',
        'alert': {'action': 'allowed', 'gid': 1, 'signature_id': 2210000, 'rev': 1, 'signature': 'SURICATA STREAM test',
                  'category': 'Generic Protocol Command Decode', 'severity': 3}}))
    return out


def quarantine_db(path, now=NOW):
    con = sqlite3.connect(path)
    con.executescript("""
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE entries (id INTEGER PRIMARY KEY, addr TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, asn INTEGER, country TEXT,
  level INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'expired', origin TEXT NOT NULL DEFAULT 'auto',
  reason INTEGER, first_seen INTEGER NOT NULL, last_offense INTEGER, since INTEGER, until INTEGER,
  offenses INTEGER NOT NULL DEFAULT 0, hits INTEGER NOT NULL DEFAULT 0, iface TEXT, comment TEXT, resolved_at INTEGER);
CREATE TABLE offenses (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, entry_id INTEGER NOT NULL, reason INTEGER NOT NULL,
  reasons INTEGER NOT NULL, level INTEGER NOT NULL, until INTEGER, origin TEXT NOT NULL, events INTEGER, ports TEXT,
  detail TEXT, iface TEXT, country TEXT, limited INTEGER NOT NULL DEFAULT 0);
""")
    con.execute("INSERT INTO meta VALUES ('installed', ?), ('paused', '0')", (str(now - 86400 * 3),))
    con.execute("INSERT INTO entries (id, addr, kind, country, level, state, reason, first_seen, last_offense, since, "
                "until, offenses, hits, iface) VALUES (1, '203.0.113.9', 'ip', 'ZZ', 2, 'active', 2, ?, ?, ?, ?, 3, 9, "
                "'wan')", (now - 7200, now - 2900, now - 2900, now + 4300))
    con.execute("INSERT INTO offenses (ts, entry_id, reason, reasons, level, until, origin, events, ports, detail, iface)"
                " VALUES (?, 1, 2, 3, 2, ?, 'auto', 10, '22/tcp 23/tcp', '10 ports in 300 s', 'wan')",
                (now - 2900, now + 4300))
    con.commit()
    con.close()


class Firewall:
    """ the synthetic firewall in a temporary directory (TMPDIR decides where; see README) """

    def __init__(self, now=NOW, with_backups=True, with_eve=True):
        self.tmp = tempfile.TemporaryDirectory(prefix='pa-console-')
        d = self.tmp.name
        self.dir = d
        join = os.path.join
        logdir = join(d, 'filter')
        os.makedirs(logdir)
        os.makedirs(join(d, 'backup'))
        with open(join(d, 'config.xml'), 'w') as handle:
            handle.write(config_xml())
        day = time.strftime('%Y%m%d', time.localtime(now))
        prev = time.strftime('%Y%m%d', time.localtime(now - 86400))
        with open(join(logdir, 'filter_%s.log' % prev), 'w') as handle:
            handle.write(v4(now - 86400 - 100, 'igc0', 'block', 'in', 'tcp', '192.168.1.50', '198.51.100.20', '1',
                            '443', rid=U_BLOCK_PRINTER) + '\n')
        with open(join(logdir, 'filter_%s.log' % day), 'w') as handle:
            handle.write('\n'.join(filter_lines(now)) + '\n')
        os.symlink(join(logdir, 'filter_%s.log' % day), join(logdir, 'latest.log'))
        if with_eve:
            with open(join(d, 'eve.json'), 'w') as handle:
                handle.write('\n'.join(eve_lines(now)) + '\n')
        if with_backups:
            older = config_xml(extra_rule=False, revision_time=now - 3 * 86400, revision_descr='initial')
            mid = config_xml(extra_rule=False, allow_lan_dst='any', revision_time=now - 2 * 86400,
                             revision_descr='/api/firewall/filter/set made changes')
            with open(join(d, 'backup', 'config-%d.1234.xml' % (now - 3 * 86400)), 'w') as handle:
                handle.write(older)
            with open(join(d, 'backup', 'config-%d.5678.xml' % (now - 2 * 86400)), 'w') as handle:
                handle.write(mid)
            with open(join(d, 'backup', 'config-%d.9999.xml' % (now - 600)), 'w') as handle:
                handle.write(config_xml())
        with open(join(d, 'kea-leases4.csv'), 'w') as handle:
            handle.write('address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,'
                         'user_context,pool_id\n')
            handle.write('192.168.20.7,aa:bb:cc:dd:ee:ff,,86400,%d,2,0,0,smart-tv,0,,0\n' % (now + 3600))
        with open(join(d, 'stats.json'), 'w') as handle:
            json.dump({U_ALLOW_LAN: {'pf_rules': 1, 'evaluations': 900, 'packets': 500, 'bytes': 9000, 'states': 3},
                       U_BLOCK_PRINTER: {'pf_rules': 1, 'evaluations': 400, 'packets': 7, 'bytes': 420, 'states': 0},
                       U_BLOCK_IOT: {'pf_rules': 1, 'evaluations': 50, 'packets': 3, 'bytes': 180, 'states': 0},
                       U_ALLOW_IOT: {'pf_rules': 1, 'evaluations': 50, 'packets': 40, 'bytes': 4000, 'states': 1},
                       U_SSH_WAN: {'pf_rules': 1, 'evaluations': 10000, 'packets': 0, 'bytes': 0, 'states': 0}},
                      handle)
        with open(join(d, 'rules.debug'), 'w') as handle:
            handle.write('block in log inet from {any} to {any} label "%s" # Default deny / state violation rule\n'
                         % L_DEFAULT_DENY)
            handle.write('# pass in quick inet6 proto ipv6-icmp label "fdc0d4140dde5aad7dc76e6017cd7934" # commented\n')
        with open(join(d, 'last.json'), 'w') as handle:
            json.dump({'version': 1, 'generated': '2026-11-08T03:00:00+00:00',
                       'summary': {'rules': 5, 'enabled': 5, 'findings': 2,
                                   'by_severity': {'high': 1, 'medium': 0, 'low': 1, 'info': 0}},
                       'stats_available': True, 'stats': {'counters_since': '2026-11-08T00:00:00+00:00'},
                       'findings': [
                           {'id': 'abc123', 'type': 'unused', 'severity': 'low', 'title': 'Rule never matched',
                            'detail': 'no packets since the counters started', 'recommendation': 'review it',
                            'rules': [{'uuid': U_SSH_WAN, 'interface': 'wan', 'action': 'pass', 'sequence': 10,
                                       'description': 'SSH to server', 'summary': 'pass in quick on wan ...'}]},
                           {'id': 'def456', 'type': 'wan_exposed', 'severity': 'high', 'title': 'SSH open to the internet',
                            'detail': 'any source may reach port 22', 'recommendation': 'restrict the source',
                            'rules': [{'uuid': U_SSH_WAN, 'interface': 'wan', 'action': 'pass', 'sequence': 10,
                                       'description': 'SSH to server', 'summary': 'pass in quick on wan ...'}]}]},
                      handle)
        with open(join(d, 'exposure.json'), 'w') as handle:
            json.dump({'generated': '2026-11-08T02:00:00Z',
                       'summary': {'posture': 'fair', 'reachable': 1, 'cves_total': 0, 'kev': 0,
                                   'attack_surface': [{'label': 'OpenSSH', 'port': 22, 'proto': 'TCP',
                                                       'internet_reachable': 'yes', 'admin': True, 'cves': 0}]}},
                      handle)
        quarantine_db(join(d, 'quarantine.db'), now)
        # pfctl stand-in: only "Blocklist" holds 198.51.100.77 (reads nothing, writes nothing)
        fake = join(d, 'pfctl')
        with open(fake, 'w') as handle:
            handle.write('#!/bin/sh\n[ "$2" = "Blocklist" ] && [ "$5" = "198.51.100.77" ] && exit 0\n'
                         '[ "$2" = "Blocklist" ] && exit 1\necho "pfctl: Table does not exist." >&2; exit 1\n')
        os.chmod(fake, 0o755)
        self.paths = Paths(
            config=join(d, 'config.xml'), backups=join(d, 'backup'), filter_log=join(logdir, 'latest.log'),
            eve=join(d, 'eve.json'), report=join(d, 'last.json'), exposure=join(d, 'exposure.json'),
            quarantine_db=join(d, 'quarantine.db'), kea_leases=join(d, 'kea-leases4.csv'),
            hostwatch_db=join(d, 'none.db'), hostwatch_rc=join(d, 'none.rc'), rules_debug=join(d, 'rules.debug'),
            audit_log=join(d, 'ai.log'), pfctl=fake, stats_file=join(d, 'stats.json'), manage=join(d, 'none'))

    def cleanup(self):
        self.tmp.cleanup()


class FakeProvider:
    """ records the messages; echoes the first placeholder of the user message (restore check) """

    def __init__(self, answer=None):
        self.messages = None
        self.answer = answer

    def endpoint(self):
        return 'http://127.0.0.1:1'

    def chat(self, messages, stream=False, on_chunk=None):
        import re
        self.messages = messages
        tokens = re.findall(r'IP4_(?:PUB|PRIV)_\d+', messages[-1]['content'])
        text = self.answer or '### Answer\n**%s** was blocked [filterlog: rule].' % (tokens[0] if tokens else '?')
        return GenerateResult(text=text, model='fable', duration_ms=5000, prompt_tokens=100, completion_tokens=20)
