"""
Helpers of the minimal rule tests: a temporary root with the fictional config.xml, daily filter log files and a
NetFlow JSON lines file (+ interface index map). Documentation addresses only.
"""

import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
sys.dont_write_bytecode = True
os.environ['TZ'] = 'UTC'
time.tzset()

from posture.common import Paths  # noqa: E402

NOW = 1793000000
DAY = 86400
LAN_ANY = '00000000-0000-4000-8000-0000000000a1'
SRV_ANY = '00000000-0000-4000-8000-0000000000a2'
WG = '00000000-0000-4000-8000-0000000000a3'
BLOCK = '00000000-0000-4000-8000-0000000000a4'
SSH = '00000000-0000-4000-8000-0000000000a5'


def log_line(ts, label, src, dst, proto='tcp', dport=443, action='pass', device='vtnet1', ipver=4):
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(ts))
    num = {'tcp': 6, 'udp': 17, 'icmp': 1}[proto]
    if ipver == 4:
        fields = ['10', '', '', label, device, 'match', action, 'in', '4', '0x0', '', '64', '1', '0', 'DF', str(num),
                  proto, '60', src, dst]
    else:
        fields = ['10', '', '', label, device, 'match', action, 'in', '6', '0x00', '0x00000', '64', proto, str(num),
                  '60', src, dst]
    if proto in ('tcp', 'udp'):
        fields += ['50000', str(dport), '0']
        if proto == 'tcp':
            fields += ['S', '1', '', '64240', '', 'mss']
    else:
        fields += ['request', '1', '1']
    return '<134>1 %s fw.example.test filterlog 4242 - [meta sequenceId="1"] %s' % (stamp, ','.join(fields))


class Root:
    def __init__(self, lines=(), flows=(), ifindex=None):
        self.dir = tempfile.mkdtemp(prefix='pa-minrule-')
        os.makedirs(os.path.join(self.dir, 'db'))
        os.makedirs(os.path.join(self.dir, 'filter'))
        shutil.copy(os.path.join(HERE, 'fixtures', 'config.xml'), os.path.join(self.dir, 'config.xml'))
        by_day = {}
        for ts, text in sorted(lines):
            by_day.setdefault(time.strftime('%Y%m%d', time.gmtime(ts)), []).append(text)
        for day, items in by_day.items():
            with open(os.path.join(self.dir, 'filter', 'filter_%s.log' % day), 'w') as handle:
                handle.write('\n'.join(items) + '\n')
        flowd = os.path.join(self.dir, 'flowd.jsonl')
        with open(flowd, 'w') as handle:
            for f in flows:
                handle.write(json.dumps(f) + '\n')
        with open(os.path.join(self.dir, 'flowd.ifindex.json'), 'w') as handle:
            json.dump(ifindex if ifindex is not None else {'1': 'vtnet0', '2': 'vtnet1', '3': 'vtnet2'}, handle)
        self.paths = Paths(config=os.path.join(self.dir, 'config.xml'), db_dir=os.path.join(self.dir, 'db'),
                           filter_log_dir=os.path.join(self.dir, 'filter'), flowd_log=flowd,
                           report=os.path.join(self.dir, 'last.json'), audit_log=os.path.join(self.dir, 'ai.log'))

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def lan_traffic():
    """ 6 days of LAN traffic for the logged LAN-to-any rule """
    lines = []
    for day in range(6):
        base = NOW - (6 - day) * DAY + 3600
        for i, host in enumerate(('198.51.100.10', '198.51.100.11', '198.51.100.12', '198.51.100.13')):
            lines.append((base + i, log_line(base + i, LAN_ANY, '192.0.2.10', host, 'tcp', 443)))
        lines.append((base + 10, log_line(base + 10, LAN_ANY, '192.0.2.11', '203.0.113.53', 'udp', 53)))
        lines.append((base + 11, log_line(base + 11, LAN_ANY, '192.0.2.11', '203.0.113.53', 'tcp', 853)))
        lines.append((base + 12, log_line(base + 12, LAN_ANY, '192.0.2.10', '203.0.113.5', 'icmp')))
        # other rules in the same file must be ignored
        lines.append((base + 13, log_line(base + 13, BLOCK, '192.0.2.10', '203.0.113.99', 'tcp', 25,
                                          action='block')))
    # one rare destination (only once) and a line outside the window
    lines.append((NOW - 3 * DAY, log_line(NOW - 3 * DAY, LAN_ANY, '192.0.2.12', '203.0.113.200', 'tcp', 8443)))
    lines.append((NOW - 20 * DAY, log_line(NOW - 20 * DAY, LAN_ANY, '192.0.2.12', '203.0.113.201', 'tcp', 9999)))
    return lines
