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

    Shared helpers of the AI Console: file locations (overridable for tests), time budgets, argument
    decoding and small formatting helpers.  Read only.
"""

import base64
import binascii
import ipaddress
import json
import os
import re
import sys
import time

DB_DIR = '/var/db/policyanalyzer'


class Paths:
    """ every file the console reads; the defaults are the firewall locations, tests pass their own """

    def __init__(self, **overrides):
        env = os.environ.get
        self.config = env('POLICYANALYZER_CONFIG', '/conf/config.xml')
        self.backups = env('POLICYANALYZER_BACKUPS', '/conf/backup')
        self.filter_log = env('POLICYANALYZER_FILTERLOG', '/var/log/filter/latest.log')
        self.eve = env('POLICYANALYZER_EVE', '/var/log/suricata/eve.json')
        self.report = env('POLICYANALYZER_REPORT', DB_DIR + '/last.json')
        self.exposure = env('POLICYANALYZER_EXPOSURE', DB_DIR + '/exposure.json')
        self.quarantine_db = env('POLICYANALYZER_QUARANTINE_DB', DB_DIR + '/quarantine.db')
        self.manage = env('POLICYANALYZER_MANAGE', '/usr/local/opnsense/scripts/policyanalyzer/manage.py')
        self.kea_leases = env('POLICYANALYZER_KEA_LEASES', '/var/db/kea/kea-leases4.csv')
        self.hostwatch_db = env('POLICYANALYZER_HOSTWATCH_DB', '/var/db/hostwatch/hosts.db')
        self.hostwatch_rc = env('POLICYANALYZER_HOSTWATCH_RC', '/etc/rc.conf.d/hostwatch')
        self.rules_debug = env('POLICYANALYZER_RULES_DEBUG', '/tmp/rules.debug')
        self.audit_log = env('POLICYANALYZER_AILOG', '/var/log/policyanalyzer/ai.log')
        self.pfctl = env('POLICYANALYZER_PFCTL', '/sbin/pfctl')
        # rule counters as a JSON file (rule_stats.py format) instead of configctl, tests only
        self.stats_file = env('POLICYANALYZER_STATS', '') or None
        for key, value in overrides.items():
            if not hasattr(self, key):
                raise AttributeError(key)
            setattr(self, key, value)


class Budget:
    """ wall clock budget shared by the collectors of one request """

    def __init__(self, seconds):
        self.started = time.monotonic()
        self.deadline = self.started + seconds

    def left(self):
        return max(0.0, self.deadline - time.monotonic())

    def expired(self):
        return time.monotonic() >= self.deadline

    def slice(self, seconds):
        """ a sub budget that never ends after this one """
        sub = Budget(0)
        sub.deadline = min(self.deadline, time.monotonic() + seconds)
        return sub

    def elapsed_ms(self):
        return int((time.monotonic() - self.started) * 1000)


def emit(data):
    sys.stdout.write(json.dumps(data, ensure_ascii=False) + '\n')
    sys.stdout.flush()


def decode_payload(token, max_bytes=4096):
    """ base64 JSON object passed by the API (configd parameters carry no free text) """
    if token in (None, '', '-'):
        return {}
    if len(token) > max_bytes * 2 or not re.match(r'^[A-Za-z0-9+/=_-]+$', token):
        raise ValueError('invalid payload')
    try:
        raw = base64.b64decode(token.replace('-', '+').replace('_', '/') + '=' * (-len(token) % 4))
        data = json.loads(raw.decode('utf-8'))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise ValueError('invalid payload')
    if not isinstance(data, dict):
        raise ValueError('invalid payload')
    return data


def encode_payload(data):
    return base64.b64encode(json.dumps(data, ensure_ascii=False).encode('utf-8')).decode('ascii')


def load_json(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def iso_local(epoch):
    """ local time with offset, as the GUI shows it """
    if epoch is None:
        return None
    return time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(epoch))


def ip_or_none(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def net_or_none(value):
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


# documentation ranges stand for internet addresses in examples and tests
DOC_NETS = tuple(ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24',
                                                  '2001:db8::/32'))


def is_public(ip):
    """ an internet address (documentation ranges count as internet addresses) """
    ip = ip_or_none(ip) if isinstance(ip, str) else ip
    if ip is None:
        return False
    return ip.is_global or any(ip.version == n.version and ip in n for n in DOC_NETS)


def clip(text, limit):
    text = '' if text is None else str(text)
    return text if len(text) <= limit else text[:max(0, limit - 1)].rstrip() + '…'


def clean_text(value, limit=200):
    """ single line, no control characters (data copied from logs and config) """
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', '' if value is None else str(value))
    return clip(re.sub(r'\s{2,}', ' ', text).strip(), limit)


PORT_RE = re.compile(r'^\d{1,5}$')
IFACE_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,32}$')
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
LABEL_RE = re.compile(r'^[0-9a-f]{32}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')


def valid_port(value):
    value = str(value or '').strip()
    if not PORT_RE.match(value) or not 0 < int(value) < 65536:
        return None
    return int(value)
