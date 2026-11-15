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

    Paths, JSON helpers and thresholds of the vulnerability prioritisation.
"""

import datetime
import hashlib
import json
import os
import re
import tempfile
import time

DB_DIR = os.environ.get('POLICYANALYZER_DB', '/var/db/policyanalyzer')
CONFIG_XML = os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')
MOUNT = 'OPNsense/policyanalyzer'
AUDIT_LOG = os.environ.get('POLICYANALYZER_AILOG', '/var/log/policyanalyzer/ai.log')

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')
REVIEW_ID_RE = re.compile(r'^[0-9a-f]{12}$')
SERVICE_ID_RE = re.compile(r'^[0-9a-f]{6,32}$')

# P1..P4 thresholds (proposta-bloqueio-automatico.md 6.4); vulns-settings.json may override them
DEFAULT_THRESHOLDS = {'epss_high': 0.5, 'epss_medium': 0.1, 'cvss_high': 7.0}
IGNORE_DAYS_DEFAULT = 90
IGNORE_DAYS_MAX = 365


def paths():
    """ resolved at call time: the tests point POLICYANALYZER_DB elsewhere """
    base = os.environ.get('POLICYANALYZER_DB', DB_DIR)
    return {
        'db': base,
        'exposure': os.environ.get('POLICYANALYZER_EXPOSURE', os.path.join(base, 'exposure.json')),
        'intel': os.path.join(base, 'vulns'),
        'kev': os.path.join(base, 'vulns', 'kev.json'),
        'epss': os.path.join(base, 'vulns', 'epss.json'),
        'review': os.path.join(base, 'vulns-review.json'),
        'settings': os.path.join(base, 'vulns-settings.json'),
        'explain': os.path.join(base, 'vulns-explain'),
        # cache of the exposure feeds (exposure/feeds.py Fetcher), read only here
        'feed_cache': os.path.join(base, 'vuln-cache'),
    }


def now():
    return time.time()


def iso(ts=None):
    ts = time.time() if ts is None else ts
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).replace(microsecond=0).isoformat() \
        .replace('+00:00', 'Z')


def parse_iso(value):
    if not value:
        return None
    try:
        text = str(value).replace('Z', '+00:00')
        dt = datetime.datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def short_id(*parts):
    return hashlib.sha1('|'.join(str(p) for p in parts).encode('utf-8')).hexdigest()[:12]


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
            json.dump(data, handle)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def thresholds():
    values = dict(DEFAULT_THRESHOLDS)
    data = load_json(paths()['settings'], {}) or {}
    for key in values:
        try:
            if key in data:
                values[key] = max(0.0, min(10.0 if key == 'cvss_high' else 1.0, float(data[key])))
        except (TypeError, ValueError):
            continue
    return values


def valid_cve(value):
    value = (value or '').strip().upper()
    if not CVE_RE.match(value):
        raise ValueError('invalid CVE id')
    return value


def valid_language(value):
    value = (value or '').strip()
    return value if LANG_RE.match(value) else 'en_US'


def decode_comment(token, limit=300):
    """ '-' or base64url (padding optional) of a UTF-8 comment -> clean text """
    import base64
    if token in (None, '', '-'):
        return ''
    if not re.match(r'^[A-Za-z0-9_+/=-]{1,1024}$', token):
        raise ValueError('invalid comment')
    try:
        raw = base64.urlsafe_b64decode(token.replace('+', '-').replace('/', '_') + '=' * (-len(token) % 4))
        text = raw.decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise ValueError('invalid comment')
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', text).strip()
    return text[:limit]
