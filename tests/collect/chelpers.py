"""
Sandbox for the collector tests: a temporary root (under $TMPDIR) with config.xml, /conf/backup, the logs of
fixtures/ and an empty /var/db/policyanalyzer, a fake command runner with FreeBSD-shaped outputs and a fake
clock.  No network, no real firewall.  Only documentation / private test addresses are used.
"""

import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'plugin', 'src', 'opnsense', 'scripts',
                       'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
os.environ.setdefault('PYTHONDONTWRITEBYTECODE', '1')
sys.dont_write_bytecode = True

os.environ['TZ'] = 'America/Sao_Paulo'
time.tzset()

from collect import common  # noqa: E402

T0 = common.parse_time('2026-10-26T12:00:00-03:00')     # fake "now": after every fixture line
SECRETS = ('SECRETbcryptHASH', 'SECRETOTPSEED42', 'SECRETAPIHASH', 'SECRETLDAPBIND', 'U0VDUkVUUFBQT0U=',
           'SECRETCOMMUNITY', 'SECRETPRIVATEKEYPEM', 'SECRETTLSSTATICKEY', 'SECRETWGPRIVATEKEY', 'SECRETWGPSK',
           'SECRETIPSECPSK', 'SECRETTELEMETRYTOKEN', 'APIKEYPUBLICPART')


def fixture(name):
    with open(os.path.join(FIXTURES, name), 'rb') as handle:
        return handle.read()


class FakeRunner:
    """ argv tuple prefix -> stdout; unknown commands fail (rc 1) like a missing tool """

    def __init__(self):
        self.outputs = {}
        self.calls = []

    def set(self, argv, out):
        self.outputs[tuple(argv)] = out

    def run(self, argv, timeout=20, stdin=None):
        self.calls.append(list(argv))
        key = tuple(argv)
        if key in self.outputs:
            out = self.outputs[key]
            return 0, out() if callable(out) else out, ''
        if argv and argv[0] == '/sbin/sysctl':
            return 0, '\n'.join('%s: %s' % (n, self.sysctl[n]) for n in argv[2:] if n in self.sysctl), ''
        return 1, '', 'not found'

    def read(self, argv, timeout=20):
        rc, out, _ = self.run(argv, timeout)
        return out if rc == 0 else ''

    sysctl = {}


HEALTH_OUTPUTS = {
    ('/usr/sbin/swapinfo', '-k'): 'Device          1K-blocks     Used    Avail Capacity\n/dev/nda0p3  8388608  1024  8387584  0%\n',
    ('/sbin/zpool', 'list', '-Hp'): 'zroot\t502511173632\t35852169216\t466659004416\t-\t-\t16\t7\t1.00\tONLINE\t-\n',
    ('/sbin/pfctl', '-si'): (
        'Status: Enabled for 9 days 15:20:11           Debug: Urgent\n\n'
        'State Table                          Total             Rate\n'
        '  current entries                     1415               \n'
        '  searches                       681191026          817.9/s\n'
        '  inserts                          2323822            2.8/s\n'
        '  removals                         2322407            2.8/s\n'
        'Counters\n'
        '  match                            2585985            3.1/s\n'
        '  state-mismatch                      1602            0.0/s\n'
        '  memory                                 0            0.0/s\n'),
    ('/sbin/pfctl', '-sm'): 'states        hard limit  3246000\nsrc-nodes     hard limit  3246000\n',
    ('/usr/bin/netstat', '-ibdn'): (
        'Name       Mtu Network           Address                Ipkts Ierrs Idrop        Ibytes      Opkts Oerrs        Obytes  Coll  Drop\n'
        'igc0      1500 <Link#1>          00:00:5e:00:53:01   51501615     0     0   33545458234  141308893     0  164055480789     0     0\n'
        'igc0         - 192.168.1.0/24    192.168.1.1            19385     -     -       2881567   10560401     -   11921049832     -     -\n'
        'pppoe1    1492 <Link#9>                              1000     2     3        500000       2000     1        900000     0     4\n'
        'lo0      16384 <Link#5>                                10     0     0          1000         10     0          1000     0     0\n'),
    ('/usr/bin/netstat', '-m'): '100769/14296/115065 mbufs in use (current/cache/total)\n'
                                '82103/9591/91694/2029337 mbuf clusters in use (current/cache/total/max)\n',
    ('/usr/local/sbin/pluginctl', '-S'): (
        '[{"description": "Unbound DNS", "name": "unbound", "status": "unbound is running as pid 1."},'
        ' {"description": "Suricata", "name": "suricata", "status": "suricata is not running."},'
        ' {"description": "Gateway monitor", "name": "dpinger", "id": "WAN_C",'
        '  "status": "dpinger is not running."}]'),
    ('/bin/ps', '-axww', '-o', 'rss=', '-o', 'pcpu=', '-o', 'comm='): ' 204800  1.5 /usr/local/sbin/unbound\n 10240 0.0 sshd\n'
                                                ' 1048576 12.0 suricata\n',
    ('/usr/bin/wg', 'show', 'all', 'dump'): (
        'wg0\tSECRETWGPRIVATEKEY=\tWGSERVERPUBKEY=\t51820\toff\n'
        'wg0\tPEERPUBKEYPHONE1234=\tSECRETWGPSK=\t192.0.2.99:4500\t10.10.0.2/32\t%d\t1000\t2000\t0\n'
        'wg0\tUNKNOWNPEERKEY5678=\t(none)\t(none)\t10.10.0.3/32\t0\t0\t0\t0\n'),
    ('/usr/sbin/arp', '-an'): '? (192.168.1.50) at 00:00:5e:00:53:01 on igc0 expires in 1041 seconds [ethernet]\n'
                              '? (192.168.1.51) at 00:00:5e:00:53:02 on igc0 permanent [ethernet]\n',
}

SYSCTL = {
    'kern.cp_time': '1000 0 500 100 8400',
    'vm.loadavg': '{ 0.74 0.71 0.55 }',
    'hw.physmem': '34036920320',
    'hw.ncpu': '4',
    'vm.stats.vm.v_page_size': '4096',
    'vm.stats.vm.v_page_count': '8117348',
    'vm.stats.vm.v_free_count': '5821505',
    'vm.stats.vm.v_inactive_count': '895889',
    'vm.stats.vm.v_active_count': '266550',
    'vm.stats.vm.v_wire_count': '1121530',
    'vm.stats.vm.v_laundry_count': '0',
    'kstat.zfs.misc.arcstats.size': '2353699976',
    'kern.boottime': '{ sec = 1793360192, usec = 217765 } Fri Oct 30 08:36:32 2026',
    'dev.cpu.0.temperature': '50.0C',
    'dev.cpu.1.temperature': '52.0C',
    'dev.cpu.2.temperature': '51.0C',
    'dev.cpu.3.temperature': '51.0C',
    'hw.acpi.thermal.tz0.temperature': '27.9C',
}


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


class Sandbox(unittest.TestCase):
    """ a fresh firewall-like tree per test """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-collect-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for d in ('/conf/backup', '/var/log/filter', '/var/log/resolver', '/var/log/dnsmasq', '/var/log/gateways',
                  '/var/db/policyanalyzer', '/var/unbound/data', '/var/run', '/tmp', '/usr/local/opnsense/version'):
            os.makedirs(self.tmp + d, exist_ok=True)
        self.write('/conf/config.xml', fixture('config-secrets.xml'))
        self.write('/usr/local/opnsense/version/core', b'{"product_version": "26.7.8_2"}')
        self.runner = FakeRunner()
        self.runner.sysctl = dict(SYSCTL)
        for argv, out in HEALTH_OUTPUTS.items():
            self.runner.set(argv, out.replace('%d', str(int(T0 - 60))))
        self.clock = Clock()
        self.ctx = common.Context(root=self.tmp, runner=self.runner, clock=self.clock)
        self.ctx.sources['no_sleep'] = True
        self.ctx.sources['dpinger'] = lambda: [('WAN_B', 14427.0, 3602.0, 0.0), ('WAN_C', 3850.0, 2113.0, 5.0)]
        self.ctx.sources['unbound_rows'] = lambda since, until, limit: []
        self.settings = common.load_settings(self.ctx)

    def path(self, p):
        return self.tmp + p

    def write(self, p, data, mode='wb'):
        with open(self.tmp + p, mode) as handle:
            handle.write(data)

    def append(self, p, data):
        with open(self.tmp + p, 'ab') as handle:
            handle.write(data)

    def link_filter(self, day='20261026', data=None):
        name = '/var/log/filter/filter_%s.log' % day
        if data is not None:
            self.write(name, data)
        latest = self.path('/var/log/filter/latest.log')
        if os.path.lexists(latest):
            os.unlink(latest)
        os.symlink(self.path(name), latest)
        return name
