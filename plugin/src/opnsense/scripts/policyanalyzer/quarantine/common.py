"""
    Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    Shared pieces of the quarantine: paths and system interfaces (Context, overridable by the tests),
    the command runner, constants, settings, target parsing and an interval set for address lookups.
"""

import bisect
import ipaddress
import os
import re
import subprocess
import time

# ------------------------------------------------------------------ names fixed by the design

ALIAS = 'pa_quarantine'                     # External (advanced) alias, the pf table filled at run time
NEVER_ALIAS = 'pa_never_block'              # host/network alias edited by the owner, never quarantined
RULE_DESCR = 'Max Cyber IA'                 # the block rule, found by this exact description
CRON_DESCR = 'Policy Analyzer quarantine (Max Cyber IA)'
CRON_COMMAND = 'policyanalyzer quarantine_run'
CRON_ORIGIN = 'PolicyAnalyzer'
CRON_MINUTES = '*/5'
SYSHOOK_NAME = '90-policyanalyzer-quarantine'
DETACHED_PREFIX = 'quarantine-detached-'      # ledgers disconnected by the assistant (kept, never deleted)

# ladder: level 1..5 -> seconds; level 6 = permanent (no expiry, only set by a human)
LADDER = (1800, 7200, 172800, 864000, 2592000)
PERMANENT = 6
LEVEL_LABELS = {1: '30 min', 2: '2 h', 3: '2 days', 4: '10 days', 5: '30 days', 6: 'permanent'}
DURATIONS = {'l1': 1, 'l2': 2, 'l3': 3, 'l4': 4, 'l5': 5, 'permanent': PERMANENT}

# reasons: code (stored), name, minimum level when the scenario fires, bit for the yearly mask
REASONS = {'base': 1, 'scan': 2, 'bait': 3, 'suricata': 4, 'manual': 5}
REASON_NAMES = {v: k for k, v in REASONS.items()}
MIN_LEVEL = {'base': 1, 'scan': 2, 'bait': 2, 'suricata': 3, 'manual': 1}
STATES = ('active', 'expired', 'released', 'permanent')
KINDS = ('ip', 'net', 'asn')

DEFAULTS = {
    'reset_days': 90,            # the level goes back to zero after this many days without offenses
    'scan_ports': 10,            # distinct destination ports ...
    'scan_window': 300,          # ... within this many seconds = port scan
    'bait_ports': '23+3389+5900+445+1433',
    'suricata': 1,               # use the Suricata alerts
    'suricata_severity': 1,      # alert.severity <= this (1 = highest)
    'max_active': 20000,         # pf entries at most (alert above it)
    'syn_only': 1,               # TCP counts only connection attempts (SYN without ACK)
    'budget': 20,                # seconds per run
}
SETTING_RULES = {
    'reset_days': (1, 3650), 'scan_ports': (2, 1000), 'scan_window': (60, 3600), 'suricata': (0, 1),
    'suricata_severity': (1, 3), 'max_active': (100, 1000000), 'syn_only': (0, 1), 'budget': (5, 120),
}

MAX_BACKLOG = 86400              # log events older than this are ignored (after a long downtime)
FIRST_RUN_TAIL = 4 * 1024 * 1024 # first run: start this many bytes before the end of the log
MAX_READ = 48 * 1024 * 1024      # bytes per source and run (the rest is read by the next run)
BATCH_MAX = 30                   # entries per batch action (configd tokens are at most 255 chars)
COMMENT_MAX = 120
RANGE_CIDRS_MAX = 64
V4_CONFIRM_PREFIX = 16           # shorter (bigger) networks need the double confirmation
V6_CONFIRM_PREFIX = 32
V4_MIN_PREFIX = 8                # shorter ones are refused
V6_MIN_PREFIX = 16
ASN_CONFIRM_PREFIXES = 256


class QuarantineError(ValueError):
    """ a ValueError, so the plugin dispatcher (ai/changes.py) reports it as a plan/apply error """


class BusyError(QuarantineError):
    pass


# ------------------------------------------------------------------ runner


class Runner:
    """ argv only, never a shell; :return: (rc, stdout, stderr) """

    def run(self, argv, timeout=30, stdin=None):
        if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
            raise QuarantineError('invalid command')
        try:
            proc = subprocess.run(list(argv), input=stdin, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return 127, '', '%s: not found' % argv[0]
        except subprocess.TimeoutExpired:
            return 124, '', '%s: timeout' % argv[0]
        return proc.returncode, proc.stdout, proc.stderr

    def read(self, argv, timeout=10):
        rc, out, _err = self.run(argv, timeout=timeout)
        return out if rc == 0 else ''


class Context:
    """ every path and system interface used by the quarantine """

    def __init__(self, root='', runner=None, clock=None, is_root=None, spawn=None):
        def p(path):
            return root + path if root else path
        self.root = root
        self.state_dir = p('/var/db/policyanalyzer')
        self.db = p('/var/db/policyanalyzer/quarantine.db')
        self.lookup_db = p('/var/db/policyanalyzer/quarantine-lookup.db')
        self.lock_file = p('/var/db/policyanalyzer/quarantine.lock')
        self.index_lock = p('/var/db/policyanalyzer/quarantine-lookup.lock')
        self.config_xml = os.environ.get('POLICYANALYZER_CONFIG') if not root and \
            os.environ.get('POLICYANALYZER_CONFIG') else p('/conf/config.xml')
        self.filter_log = p('/var/log/filter/latest.log')
        self.eve = p('/var/log/suricata/eve.json')
        self.geoip_dir = p('/usr/local/share/GeoIP/alias')
        self.asn_csv = p('/usr/local/share/bgp/asn.csv')
        self.resolv_conf = p('/etc/resolv.conf')
        self.syshook_dir = p('/usr/local/etc/rc.syshook.d/start')
        self.syshook = os.path.join(self.syshook_dir, SYSHOOK_NAME)
        here = os.path.dirname(os.path.abspath(__file__))
        self.syshook_script = os.path.join(here, 'syshook.sh')
        self.model_php = os.path.join(here, 'model.php')
        self.manage_py = os.path.join(os.path.dirname(here), 'manage.py')
        self.php = '/usr/local/bin/php'
        self.configctl = '/usr/local/sbin/configctl'
        self.pfctl = '/sbin/pfctl'
        self.ifconfig = '/sbin/ifconfig'
        self.netstat = '/usr/bin/netstat'
        self.wg = '/usr/bin/wg'
        self.tailscale = '/usr/local/bin/tailscale'
        self.ntpq = '/usr/local/sbin/ntpq'
        self.sockstat = '/usr/bin/sockstat'
        self.pgrep = '/bin/pgrep'
        self.runner = runner or Runner()
        self.clock = clock or time.time
        self._is_root = is_root
        self.spawn = spawn                     # callable(argv) for the background index build, None = default

    @property
    def is_root(self):
        return os.geteuid() == 0 if self._is_root is None else self._is_root


# ------------------------------------------------------------------ settings


def parse_ports(value):
    """ "23+3389,445" -> sorted tuple of ints (1..65535); ValueError when invalid """
    ports = set()
    for token in re.split(r'[+, ]+', str(value or '').strip()):
        if not token:
            continue
        if not token.isdigit() or not 0 < int(token) < 65536:
            raise ValueError('invalid port: %s' % token)
        ports.add(int(token))
    if len(ports) > 64:
        raise ValueError('at most 64 bait ports')
    return tuple(sorted(ports))


def validate_setting(key, value):
    """ :return: the normalized value (int, or "a+b+c" for bait_ports); ValueError when invalid """
    if key == 'bait_ports':
        return '+'.join(str(p) for p in parse_ports(value))
    if key not in SETTING_RULES:
        raise ValueError('unknown setting')
    low, high = SETTING_RULES[key]
    if not re.match(r'^\d{1,7}$', str(value)) or not low <= int(value) <= high:
        raise ValueError('%s must be between %d and %d' % (key, low, high))
    return int(value)


def effective_settings(stored):
    """ defaults overlaid with the stored values that still validate """
    result = dict(DEFAULTS)
    for key, value in (stored or {}).items():
        if key in DEFAULTS:
            try:
                result[key] = validate_setting(key, value)
            except ValueError:
                continue
    result['bait_ports_list'] = parse_ports(result['bait_ports'])
    return result


def ttl(level):
    return None if level >= PERMANENT else LADDER[max(1, min(level, 5)) - 1]


# ------------------------------------------------------------------ addresses


def addr(value):
    """ address or None; IPv4 mapped IPv6 becomes IPv4 """
    try:
        ip = ipaddress.ip_address(str(value).strip().split('%')[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


# tests only: documentation ranges treated as public so that no real address appears in the test data
TEST_EXTERNAL = ()


def is_external(ip):
    """ public unicast only: private, reserved, CGNAT, loopback, link local, multicast and documentation are not """
    if ip is None:
        return False
    if TEST_EXTERNAL and any(ip.version == n.version and ip in n for n in TEST_EXTERNAL):
        return True
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or
                                 ip.is_unspecified)


def network_is_external(net):
    """ a network is acceptable as a quarantine target only when it does not touch any non global space """
    if TEST_EXTERNAL and any(net.version == n.version and net.subnet_of(n) for n in TEST_EXTERNAL):
        return True
    if net.is_multicast or net.is_reserved or net.is_loopback or net.is_link_local or net.is_private or \
            not net.is_global:
        return False
    first, last = net.network_address, net.broadcast_address
    return is_external(first) and is_external(last)


def pf_text(net):
    """ pf table spelling: single addresses without the prefix """
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


ASN_RE = re.compile(r'^(?:AS|as)?(\d{1,10})$')


def parse_target(text):
    """
    manual target -> {"kind": "ip"|"net"|"asn", "nets": [ip_network], "asn": int|None, "label": str}
    accepts an address, a CIDR, a range "first-last" (summarized into CIDRs) or "AS<number>"
    """
    text = str(text or '').strip()
    match = ASN_RE.match(text)
    if match and text.upper().startswith('AS'):
        number = int(match.group(1))
        if not 0 < number < 4294967296:
            raise ValueError('invalid ASN')
        return {'kind': 'asn', 'nets': [], 'asn': number, 'label': 'AS%d' % number}
    if '-' in text and '/' not in text:
        first, _sep, last = text.partition('-')
        a, b = addr(first), addr(last)
        if a is None or b is None or a.version != b.version or a > b:
            raise ValueError('invalid range')
        nets = list(ipaddress.summarize_address_range(a, b))
        if len(nets) > RANGE_CIDRS_MAX:
            raise ValueError('the range needs more than %d networks, use a CIDR' % RANGE_CIDRS_MAX)
        return {'kind': 'net' if len(nets) > 1 or nets[0].prefixlen != nets[0].max_prefixlen else 'ip',
                'nets': nets, 'asn': None, 'label': text}
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError('not an address, network, range or ASN')
    if net.version == 6 and net.network_address.ipv4_mapped is not None:
        raise ValueError('use the IPv4 form')
    kind = 'ip' if net.prefixlen == net.max_prefixlen else 'net'
    return {'kind': kind, 'nets': [net], 'asn': None, 'label': pf_text(net)}


def check_network_size(net):
    """ :return: True when the double confirmation is needed; ValueError when too big """
    minimum = V4_MIN_PREFIX if net.version == 4 else V6_MIN_PREFIX
    if net.prefixlen < minimum:
        raise ValueError('%s is too big (shorter than /%d)' % (net, minimum))
    return net.prefixlen < (V4_CONFIRM_PREFIX if net.version == 4 else V6_CONFIRM_PREFIX)


class IntervalSet:
    """ address intervals per label and IP version, merged per label; lookups by bisect """

    def __init__(self):
        self._raw = {}
        self._built = None

    def add(self, net, label):
        if not isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            net = ipaddress.ip_network(net, strict=False)
        self._raw.setdefault((label, net.version), []).append(
            (int(net.network_address), int(net.broadcast_address)))
        self._built = None

    def __len__(self):
        return sum(len(v) for v in self._raw.values())

    def labels(self):
        return sorted({label for label, _version in self._raw})

    def _build(self):
        built = {}
        for key, items in self._raw.items():
            merged = []
            for start, end in sorted(items):
                if merged and start <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            built[key] = ([m[0] for m in merged], merged)
        self._built = built

    def lookup(self, ip):
        """ first label (sorted) of an interval containing ip, or None """
        if self._built is None:
            self._build()
        value = int(ip)
        for (label, version) in sorted(self._built):
            if version != ip.version:
                continue
            starts, merged = self._built[(label, version)]
            idx = bisect.bisect_right(starts, value) - 1
            if idx >= 0 and merged[idx][1] >= value:
                return label
        return None

    def overlapping(self, net):
        """ [(label, ip_network)] of the intervals overlapping net (clipped to net) """
        if self._built is None:
            self._build()
        low, high = int(net.network_address), int(net.broadcast_address)
        found = []
        for (label, version) in sorted(self._built):
            if version != net.version:
                continue
            starts, merged = self._built[(label, version)]
            idx = max(0, bisect.bisect_right(starts, low) - 1)
            while idx < len(merged) and merged[idx][0] <= high:
                start, end = merged[idx]
                if end >= low:
                    for sub in interval_to_nets(version, max(start, low), min(end, high)):
                        found.append((label, sub))
                idx += 1
        return found


def interval_to_nets(version, start, end):
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return list(ipaddress.summarize_address_range(cls(start), cls(end)))


def iso(epoch):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch)) if epoch else None
