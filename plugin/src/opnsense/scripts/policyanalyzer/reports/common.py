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

    Paths and helpers of the reports and the notification center.
"""

import base64
import datetime
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

MOUNT = 'OPNsense/policyanalyzer'
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')
SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')


def paths():
    """ resolved at call time (tests point POLICYANALYZER_DB elsewhere) """
    base = os.environ.get('POLICYANALYZER_DB', '/var/db/policyanalyzer')
    return {
        'db': base,
        'reports_db': os.path.join(base, 'reports.db'),
        'settings': os.path.join(base, 'reports-settings.json'),
        'secret': os.path.join(base, 'reports-secret.json'),
        'exposure': os.path.join(base, 'exposure.json'),
        'findings': os.path.join(base, 'last.json'),
        'quarantine_db': os.path.join(base, 'quarantine.db'),
        'quarantine_lookup': os.path.join(base, 'quarantine-lookup.db'),
        'events_dir': os.path.join(base, 'events'),
        'incidents': os.path.join(base, 'incidents.json'),
        'anomalies': os.path.join(base, 'anomalies.json'),
        'posture': os.path.join(base, 'posture.json'),
        'incidents_db': os.path.join(base, 'incidents.db'),
        'anomalies_db': os.path.join(base, 'anomalies.db'),
        'devices_db': os.path.join(base, 'devices.db'),
        'posture_db': os.path.join(base, 'posture.db'),
        'shadowai_db': os.path.join(base, 'shadowai.db'),
        'ai_queue': os.environ.get('POLICYANALYZER_AI_QUEUE', os.path.join(base, 'ai-queue.db')),
        'collect_dir': os.path.join(base, 'collect'),
        'config': os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml'),
        'filter_log': os.environ.get('POLICYANALYZER_FILTERLOG', '/var/log/filter/latest.log'),
        'ai_log': os.environ.get('POLICYANALYZER_AILOG', '/var/log/policyanalyzer/ai.log'),
        'reports_log': os.environ.get('POLICYANALYZER_REPORTS_LOG', '/var/log/policyanalyzer/reports.log'),
        'scripts': os.environ.get('POLICYANALYZER_SCRIPTS', os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'php': '/usr/local/bin/php',
        'configctl': '/usr/local/sbin/configctl',
    }


def now():
    return time.time()


def iso(ts=None):
    ts = time.time() if ts is None else ts
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).replace(microsecond=0).isoformat() \
        .replace('+00:00', 'Z')


def local_text(ts, fmt='%d/%m/%Y %H:%M'):
    return time.strftime(fmt, time.localtime(ts))


def parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def load_json(path, default=None):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=0o640):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.pa-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(data, handle, indent=1, sort_keys=True)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def token():
    return time.strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(3)


def b64decode_json(value, limit=16384):
    if not value or len(value) > limit or not re.match(r'^[A-Za-z0-9_+/=-]+$', value):
        raise ValueError('invalid payload')
    try:
        raw = base64.urlsafe_b64decode(value.replace('+', '-').replace('/', '_') + '=' * (-len(value) % 4))
        data = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise ValueError('invalid payload')
    if not isinstance(data, dict):
        raise ValueError('invalid payload')
    return data


def valid_language(value, default='en_US'):
    value = (value or '').strip()
    return value if LANG_RE.match(value) else default


def config_root(path=None):
    try:
        return ET.parse(path or paths()['config']).getroot()
    except (OSError, ET.ParseError):
        return None


def gui_base(root=None, override=None):
    """ https://<hostname>.<domain>[:port] of the web GUI, for the links in the e-mails """
    if override:
        return override.rstrip('/')
    root = root if root is not None else config_root()
    if root is None:
        return ''
    host = (root.findtext('./system/hostname') or 'firewall').strip()
    domain = (root.findtext('./system/domain') or '').strip()
    proto = (root.findtext('./system/webgui/protocol') or 'https').strip() or 'https'
    port = (root.findtext('./system/webgui/port') or '').strip()
    default = '443' if proto == 'https' else '80'
    return '%s://%s%s%s' % (proto, host, ('.' + domain) if domain else '',
                            (':' + port) if port and port != default else '')


def severity_rank(value):
    try:
        return SEVERITIES.index(value)
    except ValueError:
        return 0


class Runner(object):
    def __call__(self, argv, timeout=60):
        try:
            proc = subprocess.run(list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                                  check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return None, '', str(exc)
        return proc.returncode, proc.stdout.decode('utf-8', 'replace'), proc.stderr.decode('utf-8', 'replace')
