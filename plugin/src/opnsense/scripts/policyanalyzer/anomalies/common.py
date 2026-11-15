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

    Names, parameters (with their limits), the context with every path and system interface, the command
    runner and small helpers shared by the anomaly modules.
"""

import hashlib
import math
import os
import re
import subprocess
import time

CRON_COMMAND = 'pa_anomalies run'
CRON_DESCR = 'Policy Analyzer anomalies (LAN NDR, every 15 minutes)'
CRON_ORIGIN = 'PolicyAnalyzer'

TYPES = ('beaconing', 'dga', 'dns_tunnel', 'volume', 'rare_destination', 'new_device', 'internal_scan',
         'dns_bypass', 'new_domain', 'tls')
TYPE_TITLES = {
    'beaconing': 'Periodic connections (beaconing)',
    'dga': 'Algorithmically generated domains (DGA)',
    'dns_tunnel': 'DNS tunnel',
    'volume': 'Outbound volume above the baseline',
    'rare_destination': 'New rare destination (country / ASN)',
    'new_device': 'New device on the network',
    'internal_scan': 'Internal scan',
    'dns_bypass': 'DNS outside the firewall resolver',
    'new_domain': 'Domain never seen before',
    'tls': 'TLS fingerprint / certificate',
}
SEVERITIES = ('high', 'medium', 'low', 'info')
SEV_RANK = {'high': 3, 'medium': 2, 'low': 1, 'info': 0}
STATUSES = ('open', 'expected', 'resolved')

# ------------------------------------------------------------------ parameters
# key: (default, low, high, description).  Everything a detector compares against lives here so that the
# finding can show "value vs. threshold" and the owner can tune it (action anomaly_settings, journaled).
PARAMS = {
    # run budget
    'budget_s': (60, 10, 600, 'wall clock budget of one run (seconds); the rest waits for the next run'),
    'cpu_s': (120, 20, 1200, 'CPU time limit of one run (RLIMIT_CPU, seconds)'),
    'max_flows': (400000, 10000, 5000000, 'NetFlow records read per run at most'),
    'max_dns_rows': (300000, 10000, 3000000, 'Unbound query rows read per run at most'),
    'first_hours': (6, 1, 72, 'hours of NetFlow history read by the first run (baseline seed)'),
    'learning_days': (7, 0, 60, 'days a host is only learned (no volume / rare destination findings)'),
    'reoccur_s': (3600, 300, 86400, 'a finding seen again within this time updates the same occurrence'),
    # (a) beaconing
    'beacon_window_h': (24, 2, 72, 'connection history kept per host/destination pair (hours)'),
    'beacon_min_conn': (12, 6, 1000, 'connections a pair needs before it is scored'),
    'beacon_min_interval_s': (10, 1, 3600, 'median interval below this is streaming, not beaconing'),
    'beacon_max_jitter_pct': (20, 1, 100, 'relative jitter (MAD / median interval, %) that still scores'),
    'beacon_min_span_h': (2, 1, 48, 'the connections must cover at least this time (hours)'),
    'beacon_score_pct': (80, 50, 99, 'score (%) from which a pair is reported'),
    'beacon_high_pct': (92, 50, 100, 'score (%) from which the finding is high'),
    # (b) DGA
    'dga_window_m': (60, 15, 1440, 'window of DNS queries evaluated per host (minutes)'),
    'dga_min_nx': (15, 3, 10000, 'distinct NXDOMAIN names of a host in the window'),
    'dga_min_ratio_pct': (50, 10, 100, 'share (%) of those names that look generated'),
    'dga_name_pct': (60, 30, 99, 'per name score (%) from which a name looks generated'),
    # (c) DNS tunnel
    'tunnel_min_subs': (30, 5, 100000, 'distinct subdomains of one registrable domain in the window'),
    'tunnel_min_len': (20, 8, 200, 'average length of those subdomain labels (characters)'),
    'tunnel_min_entropy_x10': (35, 10, 60, 'average Shannon entropy of the subdomains (x10, bits/char)'),
    'tunnel_txt_min': (40, 5, 100000, 'TXT/NULL queries to one domain in the window'),
    'tunnel_qname_bytes': (60, 20, 255, 'average query name size (bytes) that adds to the score'),
    # (d) volume
    'vol_min_mb': (200, 1, 1000000, 'outbound MiB in one hour below which nothing is reported'),
    'vol_z_x10': (40, 10, 200, 'z-score (x10) over the baseline of that hour of the day'),
    'vol_ratio_x10': (50, 11, 1000, 'ratio (x10) over the baseline mean'),
    'vol_min_samples': (5, 2, 60, 'samples of that hour of the day before the hour baseline is used'),
    'vol_alpha_pct': (15, 1, 90, 'EWMA weight of a new hour (%)'),
    # (e) rare destination
    'rare_max_hosts': (1, 1, 50, 'a country/ASN seen by at most this many hosts in 30 days is rare'),
    'rare_min_kb': (100, 1, 10000000, 'KiB exchanged with the new destination before it is reported'),
    'rare_min_conn': (3, 1, 10000, 'connections to the new destination before it is reported'),
    # (f) new device: no numeric parameter (the first run learns every device present)
    'device_random_info': (1, 0, 1, '1: a new randomized (locally administered) MAC is only info'),
    # (g) internal scan
    'scan_window_s': (300, 30, 3600, 'sliding window of the scan detector (seconds)'),
    'scan_min_hosts': (20, 3, 65535, 'distinct internal addresses touched in the window'),
    'scan_min_ports': (50, 5, 65535, 'distinct ports of one internal address in the window'),
    # (h) DNS bypass
    'bypass_doh': (1, 0, 1, '1: also report HTTPS to well known public DoH resolvers'),
    # (i) new domain / (j) TLS
    'newdom_min': (3, 1, 1000, 'never seen registrable domains of a host in one day before it is reported'),
    'tls_enabled': (1, 0, 1, '1: read the TLS events of Suricata (eve.json) for JA4 and certificates'),
}
DEFAULTS = {k: v[0] for k, v in PARAMS.items()}

# documentation networks the tests treat as public (production never sets it)
TEST_EXTERNAL = ()

ID_RE = re.compile(r'^[0-9a-f]{16}$')
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')


class AnomalyError(Exception):
    pass


class BusyError(AnomalyError):
    pass


def validate_setting(key, value):
    if key not in PARAMS:
        raise ValueError('unknown setting: %s' % key)
    _default, low, high, _descr = PARAMS[key]
    if not re.match(r'^\d{1,8}$', str(value)) or not low <= int(value) <= high:
        raise ValueError('%s must be between %d and %d' % (key, low, high))
    return int(value)


def effective_settings(stored):
    result = dict(DEFAULTS)
    for key, value in (stored or {}).items():
        try:
            result[key] = validate_setting(key, value)
        except ValueError:
            continue
    return result


# ------------------------------------------------------------------ runner / context


class Runner:
    """ argv only, never a shell; :return: (rc, stdout, stderr) """

    def run(self, argv, timeout=30, stdin=None):
        if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
            raise AnomalyError('invalid command')
        try:
            proc = subprocess.run(list(argv), input=stdin, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return 127, '', '%s: not found' % argv[0]
        except subprocess.TimeoutExpired:
            return 124, '', '%s: timeout' % argv[0]
        return proc.returncode, proc.stdout, proc.stderr


class Context:
    """ every path and system interface used by the anomaly detection (root='' in production) """

    def __init__(self, root='', runner=None, clock=None, sources=None):
        def p(path):
            return root + path if root else path
        self.root = root
        self.state_dir = p('/var/db/policyanalyzer')
        self.db = os.environ.get('POLICYANALYZER_ANOMALIES_DB') if not root and \
            os.environ.get('POLICYANALYZER_ANOMALIES_DB') else p('/var/db/policyanalyzer/anomalies.db')
        self.lock_file = p('/var/db/policyanalyzer/anomalies.lock')
        self.config_xml = os.environ.get('POLICYANALYZER_CONFIG') if not root and \
            os.environ.get('POLICYANALYZER_CONFIG') else p('/conf/config.xml')
        self.flowd_log = p('/var/log/flowd.log')
        self.netflow_dir = p('/var/netflow')
        self.unbound_db = p('/var/unbound/data/unbound.duckdb')
        self.hostwatch_db = p('/var/db/hostwatch/hosts.db')
        self.kea_leases = p('/var/db/kea/kea-leases4.csv')
        self.dnsmasq_leases = p('/var/db/dnsmasq.leases')
        self.filter_log = p('/var/log/filter/latest.log')
        self.eve = p('/var/log/suricata/eve.json')
        self.geoip_dir = p('/usr/local/share/GeoIP/alias')
        self.asn_csv = p('/usr/local/share/bgp/asn.csv')
        self.quarantine_lookup_db = p('/var/db/policyanalyzer/quarantine-lookup.db')
        self.lookup_db = p('/var/db/policyanalyzer/anomalies-lookup.db')
        self.index_lock = p('/var/db/policyanalyzer/anomalies-lookup.lock')
        self.site_python = '/usr/local/opnsense/site-python'
        self.netflow_lib = '/usr/local/opnsense/scripts/netflow'
        here = os.path.dirname(os.path.abspath(__file__))
        self.model_php = os.path.join(here, 'model.php')
        self.cli_py = os.path.join(here, 'cli.py')
        self.php = '/usr/local/bin/php'
        self.configctl = '/usr/local/sbin/configctl'
        self.nice = '/usr/bin/nice'
        self.runner = runner or Runner()
        self.clock = clock or time.time
        # optional source overrides (tests): {"flows": callable, "dns": callable, ...}, see sources.py
        self.sources = sources or {}


# ------------------------------------------------------------------ helpers


def iso(epoch):
    if epoch is None:
        return None
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch))


def finding_id(kind, host, key=''):
    return hashlib.sha1(('%s|%s|%s' % (kind, host, key)).encode()).hexdigest()[:16]


def entropy(text):
    """ Shannon entropy in bits per character """
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(text))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def median(values):
    data = sorted(values)
    n = len(data)
    if not n:
        return 0.0
    mid = n // 2
    return float(data[mid]) if n % 2 else (data[mid - 1] + data[mid]) / 2.0


def quantile(sorted_values, q):
    """ linear interpolation quantile of an already sorted list """
    n = len(sorted_values)
    if not n:
        return 0.0
    pos = (n - 1) * q
    low = int(math.floor(pos))
    high = min(low + 1, n - 1)
    frac = pos - low
    return sorted_values[low] * (1 - frac) + sorted_values[high] * frac


def mad(values, center=None):
    """ median absolute deviation """
    if not values:
        return 0.0
    center = median(values) if center is None else center
    return median([abs(v - center) for v in values])


def bowley(values):
    """ Bowley (quartile) skewness in [-1, 1]; 0 for symmetric or degenerate data """
    data = sorted(values)
    if len(data) < 3:
        return 0.0
    q1, q2, q3 = quantile(data, 0.25), quantile(data, 0.5), quantile(data, 0.75)
    if q3 - q1 <= 0 or q2 == q1 or q2 == q3:
        return 0.0
    return (q3 + q1 - 2 * q2) / (q3 - q1)


def fmt_bytes(value):
    value = float(value or 0)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(value) < 1024 or unit == 'TiB':
            return ('%d %s' % (value, unit)) if unit == 'B' else ('%.1f %s' % (value, unit))
        value /= 1024.0
    return '%.1f TiB' % value


def fmt_duration(seconds):
    seconds = int(seconds or 0)
    if seconds < 120:
        return '%d s' % seconds
    if seconds < 7200:
        return '%d min' % (seconds // 60)
    if seconds < 172800:
        return '%.1f h' % (seconds / 3600.0)
    return '%.1f days' % (seconds / 86400.0)


def factor(name, value, threshold=None, met=None, weight=None, text='', unit=''):
    """
    one explainable factor of a finding: what was measured, against what, and whether it counted.
    :param met: True when the factor pushed the decision (shown highlighted), False when it was checked but
                did not, None for context
    """
    out = {'name': name, 'value': value, 'text': text}
    if threshold is not None:
        out['threshold'] = threshold
    if met is not None:
        out['met'] = bool(met)
    if weight is not None:
        out['weight'] = weight
    if unit:
        out['unit'] = unit
    return out
