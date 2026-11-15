"""
Fixtures of the device inventory tests: a fake firewall root (POLICYANALYZER_ROOT) with a Host discovery
database, Kea leases, an IEEE OUI excerpt and config.xml; a fake runner for arp/drill. Fictitious MAC addresses
(locally administered or documentation-like prefixes) and documentation addresses only.
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

CONFIG = """<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.test</domain><webgui><protocol>https</protocol></webgui></system>
  <interfaces>
    <wan><if>igc9</if><ipaddr>dhcp</ipaddr></wan>
    <lan><if>igc0</if><descr>LAN</descr><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan>
    <opt1><if>igc1</if><descr>IOT</descr><ipaddr>198.51.100.1</ipaddr><subnet>24</subnet></opt1>
  </interfaces>
  <nat>
    <rule><interface>wan</interface><protocol>tcp</protocol><target>198.51.100.20</target><local-port>554</local-port>
      <descr>camera RTSP</descr></rule>
  </nat>
  <OPNsense>
    <Kea><dhcp4><reservations>
      <reservation uuid="r1"><hw_address>02:00:00:00:00:01</hw_address><ip_address>192.0.2.10</ip_address>
        <hostname>desktop-igor</hostname><description>PC</description></reservation>
    </reservations></dhcp4></Kea>
    <unboundplus><hosts><host uuid="h1"><enabled>1</enabled><hostname>printer</hostname><domain>example.test</domain>
      <rr>A</rr><server>192.0.2.30</server></host></hosts></unboundplus>
  </OPNsense>
</opnsense>
"""

OUI = """Registry,Assignment,Organization Name,Organization Address
MA-L,A41437,Hangzhou Hikvision Digital Technology Co.,Ltd.,"CN"
MA-L,001B21,Intel Corporate,"US"
MA-L,3C2AF4,Brother Industries LTD.,"JP"
MA-L,F0B4D2,D-Link International,"TW"
MA-L,B827EB,Raspberry Pi Foundation,"GB"
"""

# mac, ip, proto, iface, first, last
HOSTS = [
    ('02:00:00:00:00:01', '192.0.2.10', 'inet', 'igc0', '2026-07-04 05:55:01', '2026-11-08 03:00:00'),
    ('a4:14:37:00:00:02', '198.51.100.20', 'inet', 'igc1', '2026-11-07 22:00:00', '2026-11-08 03:10:00'),
    ('3c:2a:f4:00:00:03', '192.0.2.30', 'inet', 'igc0', '2026-01-01 10:00:00', '2026-11-08 02:00:00'),
    ('ba:aa:00:00:00:04', '192.0.2.40', 'inet', 'igc0', '2026-11-08 01:00:00', '2026-11-08 03:12:00'),
    ('b8:27:eb:00:00:05', '192.0.2.50', 'inet', 'igc0', '2026-11-08 02:00:00', '2026-11-08 02:30:00'),
    ('b8:27:eb:00:00:05', '2001:db8::50', 'inet6', 'igc0', '2026-11-08 02:00:00', '2026-11-08 02:31:00'),
    ('00:aa:bb:00:00:09', '203.0.113.1', 'inet', 'igc9', '2026-11-01 00:00:00', '2026-11-08 03:00:00'),   # WAN
]

LEASES = """address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.0.2.40,ba:aa:00:00:00:04,,3600,1794110000,1,0,0,Galaxy-S24,0,,0
192.0.2.50,b8:27:eb:00:00:05,,3600,1794106000,1,0,0,,0,,0
"""

NOW = 1794107600          # 2026-11-08 03:13:20 UTC


class FakeRun(object):
    def __init__(self):
        self.calls = []

    def __call__(self, argv, timeout=10):
        self.calls.append(list(argv))
        if argv[0] == 'arp':
            return 0, ('? (192.0.2.40) at ba:aa:00:00:00:04 on igc0 expires in 1100 seconds [ethernet]\n'
                       '? (192.0.2.1) at 00:11:22:33:44:55 on igc0 permanent [ethernet]\n'), ''
        if argv[0] == 'drill':
            return (0, 'rpi-garagem.example.test.\n', '') if argv[3] == '192.0.2.50' else (0, '', '')
        return 1, '', 'unexpected'


class DevicesCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-devices-')
        self.root = os.path.join(self.tmp, 'root')
        self.db = os.path.join(self.tmp, 'db')
        for d in ('var/db/hostwatch', 'var/db/kea', 'usr/local/opnsense/contrib/ieee', 'conf'):
            os.makedirs(os.path.join(self.root, d))
        os.makedirs(self.db)
        with open(os.path.join(self.root, 'conf/config.xml'), 'w') as h:
            h.write(CONFIG)
        with open(os.path.join(self.root, 'usr/local/opnsense/contrib/ieee/oui.csv'), 'w') as h:
            h.write(OUI)
        with open(os.path.join(self.root, 'var/db/kea/kea-leases4.csv'), 'w') as h:
            h.write(LEASES)
        hw = sqlite3.connect(os.path.join(self.root, 'var/db/hostwatch/hosts.db'))
        hw.executescript('CREATE TABLE hosts (id integer primary key, interface_name text, ip_address text, '
                         'protocol text, ether_address text, real_ether_address text, first_seen timestamp, '
                         'last_seen timestamp); CREATE TABLE oui (assignment TEXT PRIMARY KEY, organization_name '
                         'TEXT, organization_address TEXT);')
        hw.executemany('INSERT INTO hosts (ether_address, ip_address, protocol, interface_name, first_seen, last_seen) '
                       'VALUES (?, ?, ?, ?, ?, ?)', HOSTS)
        hw.commit()
        hw.close()
        self.env = {k: os.environ.get(k) for k in ('POLICYANALYZER_DB', 'POLICYANALYZER_ROOT', 'POLICYANALYZER_CONFIG')}
        os.environ['POLICYANALYZER_DB'] = self.db
        os.environ['POLICYANALYZER_ROOT'] = self.root
        os.environ.pop('POLICYANALYZER_CONFIG', None)
        from ai import journal
        self._undo = journal.UNDO_DIR
        journal.UNDO_DIR = os.path.join(self.tmp, 'undo')
        self.run_ = FakeRun()

    def tearDown(self):
        from ai import journal
        journal.UNDO_DIR = self._undo
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_kev(self):
        os.makedirs(os.path.join(self.db, 'vulns'), exist_ok=True)
        with open(os.path.join(self.db, 'vulns', 'kev.json'), 'w') as h:
            json.dump({'items': {'CVE-2099-7777': {'vendor': 'Hikvision'}, 'CVE-2099-7778': {'vendor': 'Hikvision'},
                                 'CVE-2099-7779': {'vendor': 'Apple'}}}, h)
