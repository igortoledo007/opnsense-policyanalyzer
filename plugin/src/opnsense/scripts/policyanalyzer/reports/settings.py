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

    Settings of the reports and of the notification center: <db>/reports-settings.json (0640), changed only by
    the change action reports_settings / reports_import_monit (simulation + journal + revert).
    The own SMTP password (mode "own") lives in <db>/reports-secret.json (0600) and is never returned: the API
    shows only "****" + the last 4 characters, like the other secrets of the plugin.

    E-mail channel, two modes chosen in the GUI:
      monit   "Use Monit settings": server, port, TLS, user, password, sender and recipients are read from
              //OPNsense/monit at every send (always in sync, nothing copied). Own recipients, when set,
              replace the Monit ones.
      own     "Import from Monit" copies them into the plugin settings, which become independent and editable;
              the password is copied into the secret file. Re-importing overwrites (double confirmation).
"""

import copy
import os
import re

from . import common, monit

EMAIL_RE = re.compile(r'^[^@\s<>",;]{1,64}@[A-Za-z0-9.-]{1,253}$')
HOST_RE = re.compile(r'^[A-Za-z0-9.-]{1,253}$|^\[?[0-9a-fA-F:.]{2,45}\]?$')
SECTIONS_V1 = ('posture', 'quarantine', 'findings', 'traffic', 'cves', 'devices', 'notifications', 'ai_summary')
CHART_SECTIONS = ('incidents', 'anomalies', 'ai_usage', 'collectors')       # chart-only sections of the PDF (v2)
SECTIONS = SECTIONS_V1 + CHART_SECTIONS

EVENTS = {
    # type: (label, default minimum severity, default throttle minutes, source module)
    'incident': ('High / critical incident', 'high', 30, 'incidents'),
    'quarantine_long': ('Address reached 10 or 30 days of quarantine, or manual permanent entry', 'medium', 60,
                        'quarantine'),
    'vuln_kev_p1': ('Our CVE entered CISA KEV or became P1', 'high', 0, 'vulns'),
    'anomaly': ('High anomaly in the LAN', 'high', 60, 'anomalies'),
    'posture_drop': ('Posture score dropped', 'medium', 360, 'posture'),
    'ai_down': ('AI provider unavailable (repeated failures, bridge down)', 'high', 360, 'ai'),
    'device_new': ('New device in the LAN', 'medium', 120, 'devices'),
    'report': ('Periodic report (6 h / daily / weekly)', 'info', 0, 'reports'),
}

DEFAULTS = {
    'version': 1,
    'language': 'en_US',
    'gui_url': '',
    'email': {'mode': 'monit', 'host': '', 'port': 587, 'security': 'starttls', 'verify': True, 'min_tls': 'auto',
              'username': '', 'sender': '', 'recipients': [], 'imported_at': None},
    'report': {'enabled': False, 'every_6h': True, 'daily': True, 'daily_hour': 7, 'only_with_events': True,
               'sections': list(SECTIONS), 'ai_summary': True, 'attach_pdf': True, 'charts': True,
               'weekly': True, 'weekly_day': 1, 'weekly_hour': 7, 'weekly_minute': 30},
    'notify': {'enabled': False, 'ai_summary': True, 'max_per_hour': 6, 'attach_pdf': True,
               'events': {k: {'enabled': k in ('incident', 'quarantine_long', 'vuln_kev_p1', 'ai_down'),
                              'min_severity': v[1], 'throttle_minutes': v[2]} for k, v in EVENTS.items()}},
}


def _merge(base, extra):
    out = copy.deepcopy(base)
    for key, value in (extra or {}).items():
        if isinstance(out.get(key), dict) and isinstance(value, dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load():
    return validate(_merge(DEFAULTS, common.load_json(common.paths()['settings'], {}) or {}))


def _bool(value):
    return value if isinstance(value, bool) else str(value).lower() in ('1', 'true', 'yes', 'on')


def _int(value, low, high, name):
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError('%s must be a number' % name)
    if not low <= value <= high:
        raise ValueError('%s must be between %d and %d' % (name, low, high))
    return value


def _emails(values, name):
    if isinstance(values, str):
        values = [v for v in re.split(r'[\s,;]+', values) if v]
    out = []
    for value in values or []:
        value = str(value).strip()
        if not EMAIL_RE.match(value):
            raise ValueError('%s: invalid e-mail address "%s"' % (name, value[:80]))
        if value not in out:
            out.append(value)
    if len(out) > 20:
        raise ValueError('%s: at most 20 addresses' % name)
    return out


def validate(data):
    """ normalized copy (raises ValueError); unknown keys are dropped; no password here """
    data = _merge(DEFAULTS, data or {})
    out = {'version': 1, 'language': common.valid_language(data.get('language'), 'en_US')}
    url = str(data.get('gui_url') or '').strip()
    if url and not re.match(r'^https?://[A-Za-z0-9.:\[\]-]{1,260}/?$', url):
        raise ValueError('GUI address must be like https://firewall.example:8443')
    out['gui_url'] = url.rstrip('/')
    em = data['email']
    mode = em.get('mode')
    if mode not in ('monit', 'own'):
        raise ValueError('e-mail mode must be "monit" or "own"')
    email = {'mode': mode, 'recipients': _emails(em.get('recipients'), 'recipients'),
             'imported_at': em.get('imported_at') if isinstance(em.get('imported_at'), str) else None}
    host = str(em.get('host') or '').strip()
    if mode == 'own' or host:
        if not HOST_RE.match(host):
            raise ValueError('invalid SMTP server')
        email['host'] = host
    else:
        email['host'] = ''
    email['port'] = _int(em.get('port') or 587, 1, 65535, 'port')
    if em.get('security') not in ('starttls', 'ssl', 'none'):
        raise ValueError('security must be starttls, ssl or none')
    email['security'] = em['security']
    email['verify'] = _bool(em.get('verify', True))
    email['min_tls'] = em.get('min_tls') if em.get('min_tls') in ('auto', 'tlsv12', 'tlsv13') else 'auto'
    user = str(em.get('username') or '').strip()
    if len(user) > 128 or any(c in user for c in '\r\n'):
        raise ValueError('invalid SMTP user')
    email['username'] = user
    sender = str(em.get('sender') or '').strip()
    if sender and not EMAIL_RE.match(sender):
        raise ValueError('invalid sender address')
    if mode == 'own' and not sender:
        raise ValueError('the sender address is required')
    email['sender'] = sender
    out['email'] = email
    rp = data['report']
    sections = [s for s in rp.get('sections') or [] if s in SECTIONS]
    if int(rp.get('sections_version') or 1) < 2 and set(SECTIONS_V1) <= set(sections):
        sections += [s for s in CHART_SECTIONS if s not in sections]     # whole v1 list: the new sections too
    out['report'] = {'enabled': _bool(rp.get('enabled')), 'every_6h': _bool(rp.get('every_6h')),
                     'daily': _bool(rp.get('daily')), 'daily_hour': _int(rp.get('daily_hour', 7), 0, 23, 'daily hour'),
                     'only_with_events': _bool(rp.get('only_with_events')), 'sections': sections or list(SECTIONS),
                     'ai_summary': _bool(rp.get('ai_summary', True)),
                     'sections_version': 2,
                     'attach_pdf': _bool(rp.get('attach_pdf', True)), 'charts': _bool(rp.get('charts', True)),
                     'weekly': _bool(rp.get('weekly', True)),
                     'weekly_day': _int(rp.get('weekly_day', 1), 0, 6, 'weekly day (0 = Sunday)'),
                     'weekly_hour': _int(rp.get('weekly_hour', 7), 0, 23, 'weekly hour'),
                     'weekly_minute': _int(rp.get('weekly_minute', 30), 0, 59, 'weekly minute')}
    nt = data['notify']
    events = {}
    for key, (_label, sev, thr, _src) in EVENTS.items():
        item = (nt.get('events') or {}).get(key) or {}
        minimum = item.get('min_severity', sev)
        if minimum not in common.SEVERITIES:
            raise ValueError('invalid minimum severity for %s' % key)
        events[key] = {'enabled': _bool(item.get('enabled', False)), 'min_severity': minimum,
                       'throttle_minutes': _int(item.get('throttle_minutes', thr), 0, 10080, 'throttle')}
    out['notify'] = {'enabled': _bool(nt.get('enabled')), 'ai_summary': _bool(nt.get('ai_summary', True)),
                     'attach_pdf': _bool(nt.get('attach_pdf', True)),
                     'max_per_hour': _int(nt.get('max_per_hour', 6), 1, 60, 'notifications per hour'),
                     'events': events}
    return out


def save(data):
    common.write_json(common.paths()['settings'], validate(data))


# ------------------------------------------------------------------ secret (mode "own")

def secret():
    return (common.load_json(common.paths()['secret'], {}) or {}).get('password') or ''


def set_secret(value):
    path = common.paths()['secret']
    if value:
        common.write_json(path, {'password': value}, mode=0o600)
    elif os.path.exists(path):
        os.unlink(path)


def hint(value):
    return ('****' + value[-4:]) if value and len(value) >= 8 else ('****' if value else '')


# ------------------------------------------------------------------ effective channel

def effective_smtp(cfg=None, root=None, with_password=False):
    """ the server actually used now, with the origin of every value; password only when with_password """
    cfg = cfg or load()
    em = cfg['email']
    if em['mode'] == 'monit':
        mon = monit.read(root)
        if mon is None:
            return {'available': False, 'mode': 'monit', 'origin': 'monit',
                    'message': 'Monit has no mail server configured (Services > Monit > Settings)'}
        out = {k: mon[k] for k in ('host', 'port', 'security', 'verify', 'min_tls', 'username', 'sender')}
        out.update(available=True, mode='monit', origin='monit (read at every send)',
                   password_set=mon['password_set'], password_hint='(Monit password, never shown)',
                   recipients=em['recipients'] or mon['recipients'],
                   recipients_origin='plugin' if em['recipients'] else 'monit alerts')
        if with_password:
            out['password'] = monit.password(root)
    else:
        pwd = secret()
        out = {k: em[k] for k in ('host', 'port', 'security', 'verify', 'min_tls', 'username', 'sender')}
        out.update(available=bool(em['host'] and em['sender']), mode='own',
                   origin='plugin (imported from Monit %s)' % em['imported_at'] if em['imported_at'] else 'plugin',
                   password_set=bool(pwd), password_hint=hint(pwd), recipients=em['recipients'],
                   recipients_origin='plugin')
        if with_password:
            out['password'] = pwd
    if not out.get('recipients'):
        out['available'] = False
        out['message'] = 'no recipient: set the recipients (or the Monit alert recipient)'
    return out


def public(cfg=None, root=None):
    cfg = cfg or load()
    return {'status': 'ok', 'settings': cfg, 'effective': effective_smtp(cfg, root),
            'monit': monit.public(root), 'password_hint': hint(secret()),
            'events': {k: {'label': v[0], 'source': v[3]} for k, v in EVENTS.items()},
            'sections': list(SECTIONS)}
