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

    Shared helpers of the read-only analysis modules posture/, shadowai/ and minrule/: file locations
    (overridable by environment variables, the tests point them at fixtures), JSON output, the base64
    payload of configd parameters, atomic writes and the AI explanation helper (text only, cached).

    Nothing here writes the configuration: the only files written are the module's own reports and
    caches in /var/db/policyanalyzer (root:wheel, 0640).
"""

import base64
import binascii
import hashlib
import json
import os
import re
import sys
import tempfile
import time

DB_DIR = '/var/db/policyanalyzer'
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
CHECK_ID_RE = re.compile(r'^[A-Z]{2,4}-[A-Z]{2,4}-[0-9]{2}$')


class Paths:
    """ every file the three modules read or write; defaults are the firewall locations """

    DEFAULTS = {
        'config': ('POLICYANALYZER_CONFIG', '/conf/config.xml'),
        'report': ('POLICYANALYZER_REPORT', DB_DIR + '/last.json'),
        'exposure': ('POLICYANALYZER_EXPOSURE', DB_DIR + '/exposure.json'),
        'db_dir': ('POLICYANALYZER_DBDIR', DB_DIR),
        'firmware': ('POLICYANALYZER_FIRMWARE', '/tmp/pkg_upgrade.json'),
        'sshd_dir': ('POLICYANALYZER_SSHD', '/conf/sshd'),
        'unbound_db': ('POLICYANALYZER_UNBOUND_DB', '/var/unbound/data/unbound.duckdb'),
        'unbound_conf_dir': ('POLICYANALYZER_UNBOUND_ETC', '/var/unbound/etc'),
        'eve': ('POLICYANALYZER_EVE', '/var/log/suricata/eve.json'),
        'filter_log_dir': ('POLICYANALYZER_FILTERLOG_DIR', '/var/log/filter'),
        'flowd_log': ('POLICYANALYZER_FLOWD', '/var/log/flowd.log'),
        'kea_leases': ('POLICYANALYZER_KEA_LEASES', '/var/db/kea/kea-leases4.csv'),
        'hostwatch_db': ('POLICYANALYZER_HOSTWATCH_DB', '/var/db/hostwatch/hosts.db'),
        'audit_log': ('POLICYANALYZER_AILOG', '/var/log/policyanalyzer/ai.log'),
        'site_python': ('POLICYANALYZER_SITE_PYTHON', '/usr/local/opnsense/site-python'),
        'netflow_lib': ('POLICYANALYZER_NETFLOW_LIB', '/usr/local/opnsense/scripts/netflow/lib'),
        'local_catalog': ('POLICYANALYZER_AI_CATALOG_LOCAL', '/usr/local/etc/policyanalyzer/ai-services.local.json'),
    }

    def __init__(self, **overrides):
        for key, (env, default) in self.DEFAULTS.items():
            setattr(self, key, os.environ.get(env, default))
        for key, value in overrides.items():
            if key not in self.DEFAULTS:
                raise AttributeError(key)
            setattr(self, key, value)

    def db(self, name):
        return os.path.join(self.db_dir, name)


def emit(data):
    sys.stdout.write(json.dumps(data, ensure_ascii=False, default=str) + '\n')
    sys.stdout.flush()


def now():
    """ the clock of the modules (tests set POLICYANALYZER_NOW) """
    fixed = os.environ.get('POLICYANALYZER_NOW')
    return float(fixed) if fixed else time.time()


def iso_utc(epoch):
    if epoch is None:
        return None
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch))


def day_of(epoch):
    """ local calendar day, as the GUI shows it """
    return time.strftime('%Y-%m-%d', time.localtime(epoch))


def decode_payload(token, max_bytes=8192):
    """ base64 (url safe accepted) JSON object passed by the API: configd parameters carry no free text """
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
    return base64.b64encode(json.dumps(data).encode('utf-8')).decode('ascii')


def load_json(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data


def write_json(path, data, mode=0o640):
    """ atomic write (temporary file in the same directory + rename) """
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.tmp-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(data, handle, ensure_ascii=False, default=str)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def clean_text(value, limit=200):
    """ single line, no control characters (data copied from logs and config) """
    text = re.sub(r'[\x00-\x1f\x7f]+', ' ', '' if value is None else str(value))
    text = re.sub(r'\s{2,}', ' ', text).strip()
    return text if len(text) <= limit else text[:max(0, limit - 1)].rstrip() + '…'


def valid_language(value):
    return value if value and LANG_RE.match(value) else None


# ------------------------------------------------------------------------------------------ AI (text only)

AI_MOUNT = 'OPNsense/policyanalyzer'
AI_CACHE_ENTRIES = 40


def _cache_key(task_name, data, language, config):
    material = json.dumps([task_name, data, language, config.provider, config.options.get('model'),
                           config.anonymize], sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


def ai_explain(paths, cache_name, task_name, instructions, question, data, language=None, mode='send',
               subject=None, assistant=None):
    """
    Ask the configured AI to explain deterministic results. Returns the Assistant answer (status ok) or a
    status disabled/refusal/error document. mode=preview returns what would be sent (nothing leaves the box).
    Answers are cached per data hash in <db_dir>/<cache_name> (the same data never costs two calls).
    :param assistant: Assistant instance override (tests use a fake provider)
    """
    from ai import AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task
    task = Task(task_name, instructions, question)
    if assistant is None:
        config = AIConfig.from_opnsense(AI_MOUNT, path=paths.config)
        assistant = Assistant(config, app='policyanalyzer', audit=AuditLog(paths.audit_log))
    if mode == 'preview':
        result = assistant.preview(task, data, language)
        result['task'] = task_name
        return result
    if not assistant.config.enabled:
        return {'status': 'disabled', 'message': 'AI assistance is disabled in the settings'}
    cache_path = paths.db(cache_name)
    key = _cache_key(task_name, data, language, assistant.config)
    cache = load_json(cache_path)
    cache = cache if isinstance(cache, dict) and isinstance(cache.get('entries'), dict) else {'entries': {}}
    hit = cache['entries'].get(key)
    if isinstance(hit, dict) and hit.get('status') == 'ok':
        answer = dict(hit)
        answer['cached'] = True
        return answer
    try:
        answer = assistant.ask(task, data, language=language, subject=subject)
    except AIDisabled as exc:
        return {'status': 'disabled', 'message': str(exc)}
    except ProviderRefusal as exc:
        return {'status': 'refusal', 'message': str(exc)}
    except ProviderError as exc:
        return {'status': 'error', 'message': str(exc)}
    if answer.get('status') == 'queued':
        # the local queue answers later: the worker runs this command again and fills the cache
        return dict(answer, task=task_name)
    answer['task'] = task_name
    answer['generated_at'] = iso_utc(now())
    answer['cached'] = False
    entries = cache['entries']
    entries[key] = answer
    if len(entries) > AI_CACHE_ENTRIES:
        for old in sorted(entries, key=lambda k: entries[k].get('generated_at') or '')[:len(entries) - AI_CACHE_ENTRIES]:
            del entries[old]
    try:
        write_json(cache_path, {'version': 1, 'entries': entries})
    except OSError:
        pass
    return answer
