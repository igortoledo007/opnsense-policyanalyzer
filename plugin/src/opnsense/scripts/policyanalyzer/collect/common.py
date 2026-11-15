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

    Shared pieces of the local collectors: paths (Context), settings, command runner, locks, SQLite
    helpers and time conversions.  Everything runs on the firewall itself: no HTTP API, no token.
"""

import calendar
import fcntl
import json
import os
import re
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET

KINDS = ('config', 'health', 'flows')

DEFAULTS = {
    'retention_days': 90,          # flows and health: rows older than this are deleted
    'compact_after_days': 7,       # hourly rows older than this are folded into daily rows
    'config_retention_days': 0,    # config history: 0 = forever (only the size limit applies)
    'max_mb_flows': 1024,          # size limit per database (MiB); oldest days are dropped first
    'max_mb_health': 256,
    'max_mb_config': 512,
    'dns_source': 'auto',          # auto | unbound | dnsmasq | none
    'ignore_services': [],         # service ids (pluginctl -S "name"[/"id"]) never reported as stopped
    'processes': ['suricata', 'unbound', 'ollama', 'php-cgi'],
}
SETTING_LIMITS = {
    'retention_days': (1, 3650), 'compact_after_days': (1, 90), 'config_retention_days': (0, 36500),
    'max_mb_flows': (16, 65536), 'max_mb_health': (8, 65536), 'max_mb_config': (8, 65536),
}
SETTING_CHOICES = {'dns_source': ('auto', 'unbound', 'dnsmasq', 'none')}
NAME_RE = re.compile(r'^[A-Za-z0-9_.:/-]{1,64}$')

BUDGET = {'config': 100, 'health': 60, 'flows': 80}     # seconds per run (below the configctl timeout)
MAX_READ = 48 * 1024 * 1024                             # bytes per log source and run
FIRST_RUN_TAIL = 1 << 40                                # first run reads the whole current (daily) log file
DNS_LAG = 120                                           # the Unbound logger flushes every 10 s: stay behind
DNS_MAX_ROWS = 400000                                   # rows of the Unbound DuckDB per run


class Runner:
    """ subprocess wrapper; tests replace it """

    def run(self, argv, timeout=20, stdin=None):
        try:
            proc = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            return 127, '', str(exc)
        return proc.returncode, proc.stdout.decode('utf-8', 'replace'), proc.stderr.decode('utf-8', 'replace')

    def read(self, argv, timeout=20):
        rc, out, _err = self.run(argv, timeout=timeout)
        return out if rc == 0 else ''


class Context:
    """ every path and system interface used by the collectors (root = test sandbox prefix) """

    def __init__(self, root='', runner=None, clock=None):
        def p(path):
            return root + path if root else path
        self.root = root
        self.state_dir = p('/var/db/policyanalyzer')
        self.dir = p('/var/db/policyanalyzer/collect')
        self.import_dir = os.path.join(self.dir, 'import')
        self.db = {k: os.path.join(self.dir, '%s.db' % k) for k in KINDS}
        self.settings_file = os.path.join(self.dir, 'settings.json')
        self.hmac_key = os.path.join(self.dir, 'hmac.key')
        self.config_xml = os.environ.get('POLICYANALYZER_CONFIG') if not root and \
            os.environ.get('POLICYANALYZER_CONFIG') else p('/conf/config.xml')
        self.backup_dir = p('/conf/backup')
        self.version_file = p('/usr/local/opnsense/version/core')
        self.filter_log = p('/var/log/filter/latest.log')
        self.gateways_log = p('/var/log/gateways/latest.log')
        self.resolver_log = p('/var/log/resolver/latest.log')
        self.dnsmasq_log = p('/var/log/dnsmasq/latest.log')
        self.unbound_db = p('/var/unbound/data/unbound.duckdb')
        self.site_python = '/usr/local/opnsense/site-python'
        self.rules_debug = p('/tmp/rules.debug')
        self.lookup_db = p('/var/db/policyanalyzer/quarantine-lookup.db')
        self.dpinger_glob = p('/var/run/dpinger_*.sock')
        self.undo_dir = p('/var/db/policyanalyzer/undo')
        here = os.path.dirname(os.path.abspath(__file__))
        self.model_php = os.path.join(here, 'model.php')
        self.php = '/usr/local/bin/php'
        self.configctl = '/usr/local/sbin/configctl'
        self.runner = runner or Runner()
        self.clock = clock or time.time
        self.sources = {}          # tests: replace a reader by name ("unbound_rows", "dpinger")

    def ensure_dirs(self):
        for path in (self.state_dir, self.dir, self.import_dir):
            if not os.path.isdir(path):
                os.makedirs(path, 0o750, exist_ok=True)

    def read(self, argv, timeout=20):
        return self.runner.read(argv, timeout=timeout)


# ------------------------------------------------------------------ settings


def load_settings(ctx):
    data = {}
    try:
        with open(ctx.settings_file) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    result = dict(DEFAULTS)
    for key, value in (data if isinstance(data, dict) else {}).items():
        try:
            result[key] = validate_setting(key, value)
        except ValueError:
            continue
    return result


def validate_setting(key, value):
    if key in SETTING_LIMITS:
        low, high = SETTING_LIMITS[key]
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise ValueError('%s: integer expected' % key) from None
        if not low <= value <= high:
            raise ValueError('%s: %d..%d' % (key, low, high))
        return value
    if key in SETTING_CHOICES:
        if value not in SETTING_CHOICES[key]:
            raise ValueError('%s: one of %s' % (key, ', '.join(SETTING_CHOICES[key])))
        return value
    if key in ('ignore_services', 'processes'):
        if isinstance(value, str):
            value = [v for v in value.split(',') if v]
        if not isinstance(value, list) or len(value) > 32 or not all(
                isinstance(v, str) and NAME_RE.match(v) for v in value):
            raise ValueError('%s: list of names' % key)
        return value
    raise ValueError('unknown setting %s' % key)


def write_json_atomic(path, data, mode=0o640):
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=1, sort_keys=True)
        handle.write('\n')
    os.replace(tmp, path)


# ------------------------------------------------------------------ locks


class Lock:
    """ non blocking flock; .acquired is False when another run holds it """

    def __init__(self, path):
        self.path = path
        self.handle = None
        self.acquired = False

    def __enter__(self):
        self.handle = open(self.path, 'a')
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.acquired = True
        except OSError:
            self.acquired = False
        return self

    def __exit__(self, *exc):
        if self.handle is not None:
            self.handle.close()
        return False


# ------------------------------------------------------------------ SQLite


def connect(path, schema=None):
    new = not os.path.exists(path)
    con = sqlite3.connect(path, timeout=30)
    if new:
        os.chmod(path, 0o640)
        # set before the first table: lets the size limit give pages back without a full VACUUM
        con.execute('PRAGMA auto_vacuum = INCREMENTAL')
    con.execute('PRAGMA journal_mode = WAL')
    con.execute('PRAGMA synchronous = NORMAL')
    con.execute('PRAGMA foreign_keys = ON')
    if schema:
        con.executescript(schema)
    return con


def connect_ro(path):
    """ read only connection or None (no database yet) """
    if not os.path.exists(path):
        return None
    try:
        con = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=10)
        con.execute('SELECT 1')
        return con
    except sqlite3.Error:
        return None


def meta_get(con, key, default=None):
    try:
        row = con.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
    except sqlite3.Error:
        return default
    if not row:
        return default
    try:
        return json.loads(row[0])
    except ValueError:
        return row[0]


def meta_set(con, key, value):
    con.execute('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)', (key, json.dumps(value)))


def db_size_mb(path):
    total = 0
    for suffix in ('', '-wal'):
        try:
            total += os.path.getsize(path + suffix)
        except OSError:
            pass
    return round(total / 1048576.0, 2)


# ------------------------------------------------------------------ time


_TS_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$')
_REL_RE = re.compile(r'^(\d{1,5})([hdw])$')


def parse_time(value, now=None, end=False):
    """
    epoch (int/float or digits), ISO 8601 (zone optional: local time), AAAA-MM-DD (local midnight; with
    end=True the next midnight, so "2026-11-01..2026-11-01" is the whole day) or relative "24h", "7d", "2w"
    (before now).  None / "" / "-" -> None.
    """
    if value is None or value in ('', '-'):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    value = str(value).strip()
    if re.match(r'^\d{9,11}(\.\d+)?$', value):
        return float(value)
    now = time.time() if now is None else now
    rel = _REL_RE.match(value)
    if rel:
        return now - int(rel.group(1)) * {'h': 3600, 'd': 86400, 'w': 7 * 86400}[rel.group(2)]
    if value == 'now':
        return now
    match = _TS_RE.match(value)
    if not match:
        raise ValueError('invalid time "%s" (epoch, AAAA-MM-DD, ISO 8601 or 24h/7d)' % value)
    y, mo, d, h, mi, s, tz = match.groups()
    if h is None:
        epoch = time.mktime((int(y), int(mo), int(d), 0, 0, 0, 0, 0, -1))
        if end:
            epoch = time.mktime((int(y), int(mo), int(d) + 1, 0, 0, 0, 0, 0, -1))
        return float(epoch)
    fields = (int(y), int(mo), int(d), int(h), int(mi), int(s or 0))
    if tz:
        epoch = calendar.timegm(fields + (0, 0, 0))
        if tz != 'Z':
            sign = 1 if tz[0] == '+' else -1
            tz = tz[1:].replace(':', '')
            epoch -= sign * (int(tz[:2]) * 3600 + int(tz[2:]) * 60)
        return float(epoch)
    return float(time.mktime(fields + (0, 0, -1)))


def iso(epoch):
    """ local ISO 8601 with offset (what the reports print) """
    if epoch is None:
        return None
    t = time.localtime(epoch)
    off = time.strftime('%z', t)
    return time.strftime('%Y-%m-%dT%H:%M:%S', t) + off[:3] + ':' + off[3:]


def iso_utc(epoch):
    return None if epoch is None else time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch))


def hour_of(epoch):
    return int(epoch // 3600 * 3600)


def day_of(epoch):
    """ local calendar day AAAA-MM-DD """
    return time.strftime('%Y-%m-%d', time.localtime(epoch))


def day_start(day):
    y, m, d = (int(x) for x in day.split('-'))
    return time.mktime((y, m, d, 0, 0, 0, 0, 0, -1))


def local_midnight(epoch):
    return day_start(day_of(epoch))


# ------------------------------------------------------------------ config.xml helpers


def load_config(ctx):
    try:
        return ET.parse(ctx.config_xml).getroot()
    except (OSError, ET.ParseError):
        return None


_DYNAMIC = ('dhcp', 'pppoe', 'pptp', 'l2tp', 'dhcp6', 'slaac')


def interfaces(root):
    """ device -> {"key": "wan", "descr": "WAN_A", "wan": bool} """
    result = {}
    if root is None:
        return result
    node = root.find('./interfaces')
    for item in (list(node) if node is not None else []):
        dev = (item.findtext('if') or '').strip()
        if not dev:
            continue
        descr = (item.findtext('descr') or '').strip() or item.tag.upper()
        wan = item.tag == 'wan' or bool((item.findtext('gateway') or '').strip()) or \
            (item.findtext('ipaddr') or '').strip() in _DYNAMIC
        result[dev] = {'key': item.tag, 'descr': descr, 'wan': wan}
    return result


def wan_devices(root):
    return sorted(dev for dev, info in interfaces(root).items() if info['wan'])
