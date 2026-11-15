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

    Paths, runner and helpers of the passive LAN device inventory.
"""

import base64
import datetime
import json
import os
import re
import subprocess
import tempfile
import time

MOUNT = 'OPNsense/policyanalyzer'
AUDIT_LOG = os.environ.get('POLICYANALYZER_AILOG', '/var/log/policyanalyzer/ai.log')
MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')
TYPES = ('camera', 'tv', 'phone', 'pc', 'ap', 'iot', 'printer', 'nvr', 'console', 'unknown')
NEW_DAYS = 7


def paths():
    """ resolved at call time (tests point POLICYANALYZER_DB / POLICYANALYZER_ROOT elsewhere) """
    base = os.environ.get('POLICYANALYZER_DB', '/var/db/policyanalyzer')
    root = os.environ.get('POLICYANALYZER_ROOT', '')
    return {
        'db': base,
        'devices_db': os.path.join(base, 'devices.db'),
        'local_oui': os.path.join(base, 'oui.csv'),
        'kev': os.path.join(base, 'vulns', 'kev.json'),
        'config': os.environ.get('POLICYANALYZER_CONFIG', root + '/conf/config.xml'),
        'hostwatch': root + '/var/db/hostwatch/hosts.db',
        'kea4': [root + '/var/db/kea/kea-leases4.csv', root + '/var/db/kea/kea-leases4.csv.2',
                 root + '/var/db/kea/kea-leases4.csv.1'],
        'dnsmasq': root + '/var/db/dnsmasq.leases',
        'core_oui': root + '/usr/local/opnsense/contrib/ieee/oui.csv',
    }


class Runner(object):
    """ (rc, stdout, stderr), never a shell; the tests replace it """

    def __call__(self, argv, timeout=10):
        try:
            proc = subprocess.run(list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                                  check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return None, '', str(exc)
        return proc.returncode, proc.stdout.decode('utf-8', 'replace'), proc.stderr.decode('utf-8', 'replace')


def now():
    return time.time()


def iso(ts=None):
    if ts is None:
        ts = time.time()
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).replace(microsecond=0).isoformat() \
        .replace('+00:00', 'Z')


def norm_mac(value):
    value = (value or '').strip().lower().replace('-', ':')
    if re.match(r'^[0-9a-f]{12}$', value):
        value = ':'.join(value[i:i + 2] for i in range(0, 12, 2))
    parts = value.split(':')
    if len(parts) == 6:
        value = ':'.join(p.zfill(2) for p in parts)
    return value if MAC_RE.match(value) and value not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff') else None


def randomized(mac):
    """ locally administered bit: phones/tablets/PCs with private (random) MAC addresses """
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except (ValueError, AttributeError, IndexError):
        return False


def load_json(path, default=None):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_bytes(path, data, mode=0o640):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.pa-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def decode_text(token, limit=80):
    if token in (None, '', '-'):
        return ''
    if not re.match(r'^[A-Za-z0-9_+/=-]{1,512}$', token):
        raise ValueError('invalid text')
    try:
        text = base64.urlsafe_b64decode(token.replace('+', '-').replace('/', '_') + '=' * (-len(token) % 4)) \
            .decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise ValueError('invalid text')
    return re.sub(r'[\x00-\x1f\x7f<>]+', ' ', text).strip()[:limit]


def valid_language(value):
    value = (value or '').strip()
    return value if LANG_RE.match(value) else 'en_US'
