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

    Shared pieces of the incident triage: paths and system interfaces (Context, overridable by the tests),
    names fixed by the design, the correlation rules and their weights, the settings and small helpers.
"""

import ipaddress
import os
import re
import time

from quarantine import common as qcommon

# ------------------------------------------------------------------ names fixed by the design

CONFIGD_SERVICE = 'pa_incidents'                    # service/conf/actions.d/actions_pa_incidents.conf
CRON_COMMAND = 'pa_incidents run'
CRON_DESCR = 'Policy Analyzer incidents (correlation every 5 minutes)'
CRON_ORIGIN = 'PolicyAnalyzer'
CRON_MINUTES = '*/5'

STATES = ('new', 'investigating', 'resolved', 'false_positive')
OPEN_STATES = ('new', 'investigating')
SEVERITIES = ('critical', 'high', 'medium', 'low')
ENTITY_KINDS = ('ext', 'int', 'own', 'port', 'rule')     # own: an address of the firewall itself

# correlation rules: id -> (base points, title template, primary entity kind)
RULES = {
    'scan_then_allowed': (50, 'Port scan followed by an allowed connection from {primary}', 'ext'),
    'ids_and_allowed': (40, 'IDS alert and allowed traffic between {primary} and {related}', 'ext'),
    'internal_to_bad': (35, '{primary} contacted a quarantined or blocklisted destination', 'int'),
    'campaign': (25, 'Campaign: {sources} sources against {primary}', 'port'),
    'repeat_offender': (20, 'Repeat offender {primary} is back after its quarantine expired', 'ext'),
    'port_spike': (20, 'Anomalous traffic spike on {primary}', 'port'),
}
RULE_ORDER = ('scan_then_allowed', 'ids_and_allowed', 'internal_to_bad', 'repeat_offender', 'campaign',
              'port_spike')
SCORE_MAX = 100
SEVERITY_LEVELS = ((70, 'critical'), (50, 'high'), (30, 'medium'), (0, 'low'))

DEFAULTS = {
    'scan_ports': 10,            # distinct destination ports blocked ...
    'scan_window': 600,          # ... within this many seconds = port scan
    'follow_window': 3600,       # an allowed connection up to this long after the scan correlates
    'pair_window': 1800,         # IDS alert and allowed traffic of the same pair within +- this
    'campaign_sources': 20,      # distinct external sources against one port in one hour ...
    'campaign_factor': 3,        # ... and this many times the usual hourly number of sources
    'spike_min': 200,            # events on one port in one hour ...
    'spike_factor': 5,           # ... and this many times the median hour (plus mean + 4 sigma)
    'baseline_hours': 24,        # hours of history needed before spikes are judged
    'dns_min': 5,                # blocked DNS queries of one internal client in the lookback
    'case_gap': 21600,           # quiet time after which new activity opens a new case
    'fp_suppress': 604800,       # a false positive absorbs new matches of its entity this long
    'budget': 20,                # seconds per run
    'repeat_min_level': 3,       # a repeat offender opens a case from this quarantine level on (3 = 2 days);
                                 # lower levels stay visible in the Quarantine tab and the digest counts
}
SETTING_RULES = {
    'scan_ports': (2, 1000), 'scan_window': (60, 3600), 'follow_window': (300, 86400), 'pair_window': (60, 86400),
    'campaign_sources': (3, 100000), 'campaign_factor': (1, 100), 'spike_min': (10, 10000000),
    'spike_factor': (2, 1000), 'baseline_hours': (6, 168), 'dns_min': (1, 100000), 'case_gap': (900, 604800),
    'fp_suppress': (0, 7776000), 'budget': (5, 120), 'repeat_min_level': (1, 6),
}

LOOKBACK = 7200                  # correlation window of every run (seconds before now)
OBS_RETENTION = 48 * 3600        # compact observations kept this long (never raw log lines)
HOURLY_RETENTION = 8 * 86400     # per port hourly counters (baseline of spikes and campaigns)
BUCKET = 300                     # observations are aggregated per 5 minutes
QUARANTINE_RECENT = 30 * 86400   # an address quarantined in the last 30 days is "bad"
MAX_EVIDENCE = 400               # evidence rows per case (later ones update the last similar row)
NOTE_MAX = 1000
EVIDENCE_TEXT = 200
DNS_MAX_ROWS = 5000

ID_RE = re.compile(r'^\d{1,9}$')


class IncidentError(ValueError):
    """ a ValueError, so the plugin dispatcher (ai/changes.py) reports it as a plan/apply error """


class BusyError(IncidentError):
    pass


class Context:
    """ every path and system interface used by the incident triage """

    def __init__(self, root='', runner=None, clock=None):
        def p(path):
            return root + path if root else path
        self.root = root
        self.state_dir = p('/var/db/policyanalyzer')
        self.db = p('/var/db/policyanalyzer/incidents.db')
        self.lock_file = p('/var/db/policyanalyzer/incidents.lock')
        self.quarantine_db = p('/var/db/policyanalyzer/quarantine.db')
        self.lookup_db = p('/var/db/policyanalyzer/quarantine-lookup.db')
        self.exposure = p('/var/db/policyanalyzer/exposure.json')
        self.config_xml = os.environ.get('POLICYANALYZER_CONFIG') if not root and \
            os.environ.get('POLICYANALYZER_CONFIG') else p('/conf/config.xml')
        self.filter_log = p('/var/log/filter/latest.log')
        self.eve = p('/var/log/suricata/eve.json')
        self.unbound_db = p('/var/unbound/data/unbound.duckdb')
        self.site_python = '/usr/local/opnsense/site-python'
        here = os.path.dirname(os.path.abspath(__file__))
        self.model_php = os.path.join(here, 'model.php')
        self.php = '/usr/local/bin/php'
        self.configctl = '/usr/local/sbin/configctl'
        self.runner = runner or qcommon.Runner()
        self.clock = clock or time.time
        self.dns_connect = None                 # tests: callable() -> DB-API connection with a "query" table


# ------------------------------------------------------------------ settings


def validate_setting(key, value):
    if key not in SETTING_RULES:
        raise IncidentError('unknown setting')
    low, high = SETTING_RULES[key]
    if not re.match(r'^\d{1,9}$', str(value)) or not low <= int(value) <= high:
        raise IncidentError('%s must be between %d and %d' % (key, low, high))
    return int(value)


def effective_settings(stored):
    result = dict(DEFAULTS)
    for key, value in (stored or {}).items():
        if key in DEFAULTS:
            try:
                result[key] = validate_setting(key, value)
            except ValueError:
                continue
    return result


# ------------------------------------------------------------------ helpers


def severity_of(score):
    for limit, name in SEVERITY_LEVELS:
        if score >= limit:
            return name
    return 'low'


def iso(epoch):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch)) if epoch else None


def addr(value):
    return qcommon.addr(value)


def is_external(ip):
    """ the same notion as the quarantine (documentation ranges are external only in its tests) """
    return qcommon.is_external(ip)


def is_internal(ip):
    """ private / CGNAT / ULA space of the local networks (never the documentation ranges in production) """
    if ip is None or is_external(ip):
        return False
    return ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def port_key(port, proto):
    port = str(port or '')
    proto = str(proto or '').lower()
    return '%s/%s' % (port, proto) if port else (proto or '?')


def valid_case_id(value):
    if not isinstance(value, str) or not ID_RE.match(value):
        raise IncidentError('invalid case id')
    return int(value)


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise IncidentError('invalid address')


def clean_text(value, limit):
    text = ''.join(ch for ch in str(value or '') if ch.isprintable() or ch == '\n').strip()
    return text[:limit]


def local_day_bounds(day):
    """ "YYYY-MM-DD" (local time) -> (start, end) epoch """
    match = re.match(r'^(\d{4})-(\d{2})-(\d{2})$', day or '')
    if not match:
        raise IncidentError('invalid day')
    y, m, d = (int(x) for x in match.groups())
    start = int(time.mktime((y, m, d, 0, 0, 0, 0, 0, -1)))
    end = int(time.mktime((y, m, d + 1, 0, 0, 0, 0, 0, -1)))
    return start, end


def local_day(epoch):
    return time.strftime('%Y-%m-%d', time.localtime(epoch))
