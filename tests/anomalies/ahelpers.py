"""
Fixtures for the anomaly tests: a temporary root with a synthetic config.xml, injected sources (flows, DNS
rows, hosts, TLS events, filter records, country/ASN lookup), a fake command runner and synthetic traffic
generators.  Only private and documentation addresses are used (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32 are treated as the internet through common.TEST_EXTERNAL).
"""

import ipaddress
import json
import math
import os
import random
import shutil
import string
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'plugin', 'src', 'opnsense', 'scripts',
                       'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
sys.dont_write_bytecode = True

from anomalies import actions, cli, common, detectors, dnsfeat, engine, netcfg, sources, store  # noqa: E402,F401

common.TEST_EXTERNAL = (ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24'),
                        ipaddress.ip_network('203.0.113.0/24'), ipaddress.ip_network('2001:db8::/32'))
os.environ['TZ'] = 'America/Sao_Paulo'
time.tzset()

T0 = 1793000000          # 2026-10-26, the fake "now"
LAN = '192.168.1.%d'
FW_LAN = '192.168.1.1'

CONFIG = """<?xml version="1.0"?>
<opnsense>
  <system><domain>home.example</domain><dnsserver>198.51.100.53</dnsserver></system>
  <interfaces>
    <wan><if>pppoe1</if><descr>WAN</descr><enable>1</enable><ipaddr>pppoe</ipaddr></wan>
    <lan><if>igc0</if><descr>LAN</descr><enable>1</enable><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
    <opt1><if>igc1</if><descr>IOT</descr><enable>1</enable><ipaddr>192.168.2.1</ipaddr><subnet>24</subnet></opt1>
    <opt2><if>wg0</if><descr>VPN_OUT</descr><enable>1</enable></opt2>
    <opt6><if>igc2</if><descr>WAN_B</descr><enable>1</enable><ipaddr>192.168.88.2</ipaddr><subnet>30</subnet>
      <gateway>WAN_B</gateway></opt6>
  </interfaces>
  <virtualip><vip><interface>lan</interface><subnet>192.168.1.254</subnet><subnet_bits>24</subnet_bits>
    <mode>carp</mode></vip></virtualip>
  <nat><rule><interface>lan</interface><protocol>tcp/udp</protocol><target>(self)</target>
    <local-port>53</local-port><destination><network>lanip</network><port>53</port><not>1</not></destination>
    <descr>Redirect DNS</descr></rule></nat>
  <OPNsense>
    <Gateways><gateway_item><name>VPN_OUT</name><interface>opt2</interface></gateway_item></Gateways>
    <wireguard><server><servers>
      <server><enabled>1</enabled><name>out</name><instance>0</instance><tunneladdress>10.99.0.2/32</tunneladdress>
        <gateway>10.99.0.1</gateway></server>
      <server><enabled>1</enabled><name>Remote</name><instance>4</instance>
        <tunneladdress>192.168.77.1/29</tunneladdress></server>
    </servers></server></wireguard>
    %CRON%
  </OPNsense>
</opnsense>
"""

CRON_JOB = """<cron><jobs><job uuid="cccccccc-1111-2222-3333-444444444444"><origin>PolicyAnalyzer</origin>
<enabled>1</enabled><minutes>*/15</minutes><command>pa_anomalies run</command></job></jobs></cron>"""

COUNTRY = {'192.0.2.': 'US', '198.51.100.': 'BR', '203.0.113.': 'NL'}
ASN = {'192.0.2.': 64500, '198.51.100.': 64501, '203.0.113.': 64502}


def lookup(ip):
    """ fake country/ASN: 203.0.113.200-250 is a rare country (KP) and ASN 64999 """
    if ip.startswith('203.0.113.') and int(ip.rsplit('.', 1)[1]) >= 200:
        return 'KP', 64999
    for prefix, cc in COUNTRY.items():
        if ip.startswith(prefix):
            return cc, ASN[prefix]
    return None, None


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.cron = None

    def run(self, argv, timeout=30, stdin=None):
        self.calls.append(list(argv))
        if argv[-1] == 'cron_add' or (len(argv) > 2 and argv[2] == 'cron_add'):
            self.cron = 'cccccccc-1111-2222-3333-444444444444'
            return 0, json.dumps({'status': 'ok', 'uuid': self.cron, 'created': True}), ''
        if len(argv) > 2 and argv[2] == 'cron_del':
            self.cron = None
            return 0, json.dumps({'status': 'ok', 'deleted': True}), ''
        return 0, '', ''


def flow(ts, src, dst, dport, octets=600, proto=6, sport=None, packets=6, dur=1.0, if_in='igc0', if_out='pppoe1',
         flags=0x1b):
    return {'ts': float(ts), 'end': float(ts) + dur, 'src': src, 'dst': dst, 'sport': sport or 40000 + int(ts) % 20000,
            'dport': dport, 'proto': proto, 'octets': octets, 'packets': packets, 'if_in': if_in, 'if_out': if_out,
            'flags': flags}


def dns_row(ts, client, name, qtype='A', rcode=0, action=0):
    return (int(ts), client, qtype, name + '.', rcode, action)


def random_label(rnd, low=10, high=18, digits=0.3):
    alphabet = string.ascii_lowercase + (string.digits if rnd.random() < digits else '')
    return ''.join(rnd.choice(alphabet) for _ in range(rnd.randint(low, high)))


BENIGN_DOMAINS = ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'whatsapp.net', 'netflix.com',
                  'spotify.com', 'microsoft.com', 'apple.com', 'amazon.com', 'globo.com', 'uol.com.br',
                  'mercadolivre.com.br', 'wikipedia.org', 'github.com', 'cloudflare.com', 'akamaiedge.net',
                  'doubleclick.net', 'googleapis.com', 'gstatic.com', 'office.com', 'live.com', 'twitch.tv',
                  'reddit.com', 'discord.com', 'steampowered.com', 'samsung.com', 'xiaomi.com', 'tiktok.com',
                  'linkedin.com', 'nubank.com.br', 'itau.com.br', 'bradesco.com.br', 'americanas.com.br',
                  'magazineluiza.com.br', 'shopee.com.br', 'outlook.com', 'icloud.com', 'dropbox.com', 'zoom.us']
SUBS = ['www', 'api', 'cdn', 'static', 'img', 'm', 'login', 'accounts', 'mail', 'play', 'edge', 'video']


def benign_dns(rnd, client, start, minutes, rate_per_min=8, typo_nx=0.01):
    """ ordinary browsing: known domains, hashed CDN subdomains, the local search domain appended, a few typos """
    rows = []
    t = start
    end = start + minutes * 60
    while t < end:
        t += rnd.expovariate(rate_per_min / 60.0)
        dom = rnd.choice(BENIGN_DOMAINS)
        r = rnd.random()
        if r < 0.15:
            name = '%s.%s' % (''.join(rnd.choice('0123456789abcdef') for _ in range(12)), 'akamaiedge.net')
        elif r < 0.75:
            name = '%s.%s' % (rnd.choice(SUBS), dom)
        else:
            name = dom
        rows.append(dns_row(t, client, name, rnd.choice(['A', 'AAAA', 'HTTPS'])))
        if rnd.random() < 0.05:   # blocked by the DNSBL, then the stub resolver appends the local domain
            rows.append(dns_row(t, client, 'ads.%s' % dom, rcode=3, action=1))
            rows.append(dns_row(t + 0.1, client, 'ads.%s.home.example' % dom, rcode=3))
        if rnd.random() < typo_nx:
            rows.append(dns_row(t, client, '%s.%s' % (rnd.choice(SUBS), dom.replace('o', '0', 1)), rcode=3))
    return rows


def dga_dns(rnd, client, start, n=40, tlds=('com', 'net', 'org', 'info', 'biz')):
    return [dns_row(start + i * 20, client, '%s.%s' % (random_label(rnd), rnd.choice(tlds)), rcode=3)
            for i in range(n)]


def tunnel_dns(rnd, client, start, n=120, domain='t.example-tunnel.net', qtype='TXT'):
    rows = []
    for i in range(n):
        payload = ''.join(rnd.choice('abcdefghijklmnopqrstuvwxyz234567') for _ in range(rnd.randint(40, 60)))
        rows.append(dns_row(start + i * 5, client, '%s.%s.%s' % (payload[:30], payload[30:], domain), qtype))
    return rows


def beacon_times(rnd, start, interval, n, jitter=0.02):
    t = start
    out = []
    for _ in range(n):
        out.append(t)
        t += interval * (1 + rnd.uniform(-jitter, jitter))
    return out


def poisson_times(rnd, start, mean_interval, n):
    t = start
    out = []
    for _ in range(n):
        out.append(t)
        t += rnd.expovariate(1.0 / mean_interval)
    return out


class AnomalyCase(unittest.TestCase):
    """ temporary root, injected sources, fake clock and runner """

    cron = False

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-anomalies-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.makedirs(self.tmp + '/conf')
        self.write_config(self.cron)
        self.now = T0
        self.runner = FakeRunner()
        self.data = {'flows': [], 'dns': [], 'hours': [], 'hosts': [], 'tls': [], 'filter': [], 'dns_seed': [],
                     'insight': []}
        self.ctx = common.Context(root=self.tmp, runner=self.runner, clock=lambda: self.now, sources={
            'flows': self._flows, 'dns': self._dns, 'hosts': lambda: (list(self.data['hosts']), {'test': True}),
            'tls': self._tls, 'filter': lambda marker, now: (list(self.data['filter']), {'n': 1}, {'records': 0}),
            'lookup': lookup, 'dns_seed': lambda: list(self.data['dns_seed']),
            'insight': lambda: list(self.data['insight']),
        })
        self.cfg = netcfg.NetConfig(self.ctx.config_xml)
        actions.CONTEXT_FACTORY = lambda: self.ctx
        from ai import journal
        self._undo = journal.UNDO_DIR
        journal.UNDO_DIR = os.path.join(self.tmp, 'undo')
        self.addCleanup(setattr, journal, 'UNDO_DIR', self._undo)
        self.settings = dict(common.DEFAULTS)

    def write_config(self, cron):
        with open(self.tmp + '/conf/config.xml', 'w') as handle:
            handle.write(CONFIG.replace('%CRON%', CRON_JOB if cron else ''))

    def _flows(self, marker, now, settings):
        flows = [f for f in self.data['flows'] if f['ts'] > (marker or {}).get('recv', 0) and f['ts'] <= now]
        newest = max([f['ts'] for f in flows] + [(marker or {}).get('recv', 0)])
        return flows, {'recv': newest}, {'records': len(flows), 'complete': True}

    def _dns(self, marker, now, settings):
        start = now - settings['dga_window_m'] * 60
        rows = [r for r in self.data['dns'] if start <= r[0] <= now]
        return rows, list(self.data['hours']), {'hour': int(now // 3600 * 3600) - 3600}, {'rows': len(rows)}

    def _tls(self, marker, now):
        events = [e for e in self.data['tls'] if e['ts'] > (marker or {}).get('ts', 0) and e['ts'] <= now]
        return events, {'ts': now}, {'events': len(events)}

    def engine(self):
        return engine.Engine(self.ctx)

    def run_at(self, ts):
        self.now = ts
        return self.engine().run(now=ts)

    def store(self):
        return store.Store(self.ctx.db)

    def findings(self, kind=None):
        st = self.store()
        try:
            sql = 'SELECT * FROM findings' + (' WHERE type = ?' if kind else '')
            return [store.decode(r) for r in st.db.execute(sql, (kind,) if kind else ())]
        finally:
            st.close()

    def cli(self, *args):
        import io
        buf = io.StringIO()
        cli.main(list(args), out=buf, ctx=self.ctx)
        return json.loads(buf.getvalue())

    def age_hosts(self, hosts, days=30):
        """ mark hosts as learned for a long time (learning period over) """
        st = self.store()
        for h in hosts:
            st.db.execute('INSERT OR REPLACE INTO hosts_seen VALUES (?, ?, ?)', (h, int(self.now - days * 86400),
                                                                                 int(self.now)))
        for kind in ('dest', 'dns', 'tls'):
            st.set_meta('learn_' + kind, int(self.now - days * 86400))
        st.close()
