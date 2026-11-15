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

    Notification center: detects events, queues them in reports.db, applies the subscriptions (minimum severity),
    throttles/digests them and sends one e-mail per type and window, each with a short AI summary (fixed text when
    the AI is off) and a direct link to the OPNsense screen. Run by cron (*/5) through "configctl pa_reports notify"
    when the center is enabled (change action reports_settings).

    Sources (tolerant: a source that is not installed shows as unavailable and its event as disabled):
      built in     quarantine.db (levels 4/5 = 10/30 days, manual permanent), vulns/ (KEV, P1),
                   devices/ (new device), the AI audit log (repeated provider failures, bridge down)
      inbox        <db>/events/<source>.jsonl written by other modules (incidents, anomalies, posture, ...):
                   one JSON object per line {"id", "ts", "type", "severity", "title", "detail", "link", "data"}
      summaries    <db>/incidents.json {"cases": [...]}, <db>/anomalies.json {"items": [...]},
                   <db>/posture.json {"score": 0-100, "generated"} (read when present)

    The first run of a detector records what already exists as "baseline" (suppressed): enabling the center does
    not flood the inbox with old events. Failures are retried (5, 15, 60, 180 min) up to 5 attempts.
"""

import json
import os
import sqlite3

from . import aisum, common, deliver, render, settings, store

RETRY = (300, 900, 3600, 10800)
MAX_ATTEMPTS = 5
INBOX_MAX = 1024 * 1024
AI_FAILURES = 3
AI_RECENT = 7200
POSTURE_DROP = 10
TYPE_LINK = {'incident': '/ui/policyanalyzer/incidents', 'quarantine_long': '/ui/policyanalyzer/#quarantine',
             'vuln_kev_p1': '/ui/policyanalyzer/vulns', 'anomaly': '/ui/policyanalyzer/anomalies',
             'posture_drop': '/ui/policyanalyzer/#exposure', 'ai_down': '/ui/policyanalyzer/#settings',
             'device_new': '/ui/policyanalyzer/devices', 'report': '/ui/policyanalyzer/reports'}
SEVERITY_MAP = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low', 'info': 'info',
                'warning': 'medium', 'error': 'high', 'crit': 'critical', '1': 'critical', '2': 'high', '3': 'medium'}


def _sev(value):
    return SEVERITY_MAP.get(str(value or '').lower(), 'medium')


def _ts(value):
    if isinstance(value, (int, float)):
        return int(value)
    return int(common.parse_iso(value) or common.now())


# ------------------------------------------------------------------ detectors

def detect_quarantine(db, now):
    path = common.paths()['quarantine_db']
    if not os.path.exists(path):
        return None
    marker = int(store.meta_get(db, 'marker:quarantine', -1) or -1)
    q = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=5)
    try:
        if marker < 0:
            marker = q.execute('SELECT coalesce(max(id), 0) FROM events').fetchone()[0]
            store.meta_set(db, 'marker:quarantine', marker)
            return []
        rows = q.execute("SELECT v.id, v.ts, v.kind, v.level, v.until, v.origin, e.addr, e.country, e.asn "
                         "FROM events v JOIN entries e ON e.id = v.entry_id WHERE v.id > ? AND v.level >= 4 "
                         "AND v.kind IN ('enter', 'upgrade', 'extend', 'permanent') ORDER BY v.id LIMIT 500",
                         (marker,)).fetchall()
        last = q.execute('SELECT coalesce(max(id), 0) FROM events').fetchone()[0]
    finally:
        q.close()
    store.meta_set(db, 'marker:quarantine', last)
    events = []
    for vid, ts, kind, level, until, origin, addr, country, asn in rows:
        if level == 6 and origin != 'manual':
            continue
        days = {4: '10 days', 5: '30 days', 6: 'permanent'}[min(level, 6)]
        events.append({'key': 'quarantine:%d' % vid, 'type': 'quarantine_long', 'source': 'quarantine', 'ts': ts,
                       'severity': 'medium' if level == 4 else 'high',
                       'title': '%s in quarantine: %s (level %d)' % (addr, days, level),
                       'detail': '%s by %s%s%s' % (kind, origin, (', country %s' % country) if country else '',
                                                   (', AS%s' % asn) if asn else ''),
                       'link': '/ui/policyanalyzer/#quarantine',
                       'data': {'level': level, 'kind': kind, 'origin': origin, 'country': country}})
    return events


def detect_vulns(db, now):
    try:
        from vulns import prioritize
    except ImportError:
        return None
    result = prioritize.build()
    if result.get('status') != 'ok':
        return []
    events = []
    for item in result['items']:
        if item['priority'] == 'P1':
            events.append({'key': 'vuln:P1:%s' % item['cve'], 'type': 'vuln_kev_p1', 'source': 'vulns',
                           'severity': 'critical', 'title': '%s became P1 (%s %s)' % (item['cve'], item['package'],
                                                                                     item['version'] or ''),
                           'detail': item['explanation'], 'link': '/ui/policyanalyzer/vulns#%s' % item['cve'],
                           'data': {'cve': item['cve'], 'priority': 'P1', 'kev': bool(item['kev']),
                                    'epss': item['epss'], 'exposure': item['exposure']['class']}})
        if item['kev'] and item['priority'] != 'P1':
            events.append({'key': 'vuln:KEV:%s' % item['cve'], 'type': 'vuln_kev_p1', 'source': 'vulns',
                           'severity': 'high',
                           'title': '%s (%s) is in CISA KEV' % (item['cve'], item['package']),
                           'detail': 'added %s; priority %s' % (item['kev'].get('date_added') or '?', item['priority']),
                           'link': '/ui/policyanalyzer/vulns#%s' % item['cve'],
                           'data': {'cve': item['cve'], 'priority': item['priority'], 'kev': True}})
    return events


def detect_devices(db, now):
    try:
        from devices import view
    except ImportError:
        return None
    if not os.path.exists(os.path.join(common.paths()['db'], 'devices.db')):
        return None
    since = int(store.meta_get(db, 'marker:devices', 0) or 0)
    store.meta_set(db, 'marker:devices', int(now))
    if not since:
        return []
    events = []
    for dev in view.new_since(since):
        events.append({'key': 'device:%d' % dev['id'], 'type': 'device_new', 'source': 'devices',
                       'ts': dev['first_seen'] or now, 'severity': 'high' if dev['risk'] == 'high' else 'medium',
                       'title': 'New device: %s (%s)' % (dev['name'] or dev['mac'], dev['vendor'] or 'unknown vendor'),
                       'detail': '%s on %s, type %s, risk %s' % (', '.join(dev['ip4']) or '-', dev['iface_descr'],
                                                                 dev['type'], dev['risk']),
                       'link': '/ui/policyanalyzer/devices#%d' % dev['id'],
                       'data': {'type': dev['type'], 'vendor': dev['vendor'], 'risk': dev['risk']}})
    return events


def _tail_json(path, max_bytes=262144):
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            lines = handle.read().decode('utf-8', 'replace').splitlines()[1 if size > max_bytes else 0:]
    except OSError:
        return None
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def detect_ai(db, now):
    records = _tail_json(common.paths()['ai_log'])
    if records is None:
        return None
    calls = [r for r in records if r.get('status') in ('ok', 'error')][-AI_FAILURES:]
    if len(calls) < AI_FAILURES or any(r.get('status') != 'error' for r in calls):
        return []
    newest = _ts(calls[-1].get('ts') or now)
    if now - newest > AI_RECENT:
        return []
    first = _ts(calls[0].get('ts') or now)
    provider = calls[-1].get('provider') or '?'
    error = str(calls[-1].get('error') or '')[:200]
    bridge = provider == 'claudecode'
    return [{'key': 'ai_down:%d' % first, 'type': 'ai_down', 'source': 'ai', 'ts': newest, 'severity': 'high',
             'title': 'AI provider unavailable: %s (%d failures in a row)' % (
                 'Claude Code bridge (claude-bridge)' if bridge else provider, len(calls)),
             'detail': error, 'link': '/ui/policyanalyzer/#settings',
             'data': {'provider': provider, 'failures': len(calls), 'endpoint': calls[-1].get('endpoint')}}]


def detect_inbox(db, now):
    """ <db>/events/*.jsonl from other modules; marker inode:offset per file """
    directory = common.paths()['events_dir']
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith('.jsonl'))
    except OSError:
        return None
    events = []
    for name in names:
        source = name[:-6]
        path = os.path.join(directory, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        key = 'marker:inbox:%s' % source
        marker = store.meta_get(db, key)
        if marker is None:
            store.meta_set(db, key, '%d:%d' % (st.st_ino, st.st_size))
            continue                      # first sight: start at the end (baseline)
        try:
            ino, offset = (int(x) for x in marker.split(':'))
        except ValueError:
            ino, offset = st.st_ino, 0
        if ino != st.st_ino or offset > st.st_size:
            offset = 0                    # rotated or truncated: read the new file from the start
        with open(path, 'rb') as handle:
            handle.seek(offset)
            chunk = handle.read(INBOX_MAX)
        end = chunk.rfind(b'\n') + 1
        store.meta_set(db, 'marker:inbox:%s' % source, '%d:%d' % (st.st_ino, offset + end))
        for line in chunk[:end].decode('utf-8', 'replace').splitlines():
            try:
                raw = json.loads(line)
            except ValueError:
                continue
            ev = _from_external(raw, source, now)
            if ev:
                events.append(ev)
    return events


def _from_external(raw, source, now):
    if not isinstance(raw, dict) or not raw.get('id') or not raw.get('title'):
        return None
    etype = raw.get('type') or {'incidents': 'incident', 'anomalies': 'anomaly', 'posture': 'posture_drop'}.get(
        source, source)
    if etype not in settings.EVENTS:
        return None
    link = str(raw.get('link') or TYPE_LINK.get(etype, ''))
    if not link.startswith('/ui/'):
        link = TYPE_LINK.get(etype, '')
    return {'key': '%s:%s' % (source, str(raw['id'])[:120]), 'type': etype, 'source': source,
            'ts': _ts(raw.get('ts') or now), 'severity': _sev(raw.get('severity')),
            'title': str(raw['title'])[:300], 'detail': str(raw.get('detail') or '')[:1000], 'link': link,
            'data': raw.get('data') if isinstance(raw.get('data'), dict) else {}}


def detect_summaries(db, now):
    """ incidents.json / anomalies.json / posture.json when those modules write them """
    p = common.paths()
    events = []
    seen = False
    doc = common.load_json(p['incidents'])
    if isinstance(doc, dict):
        seen = True
        for case in doc.get('cases') or []:
            if isinstance(case, dict) and case.get('id') and _sev(case.get('severity')) in ('high', 'critical'):
                ev = _from_external(dict(case, type='incident', id='%s:%s' % (case['id'], _sev(case.get('severity'))),
                                         ts=case.get('updated') or case.get('opened')), 'incidents', now)
                if ev:
                    events.append(ev)
    doc = common.load_json(p['anomalies'])
    if isinstance(doc, dict):
        seen = True
        for item in doc.get('items') or []:
            if isinstance(item, dict) and item.get('id') and _sev(item.get('severity')) in ('high', 'critical'):
                ev = _from_external(dict(item, type='anomaly'), 'anomalies', now)
                if ev:
                    events.append(ev)
    doc = common.load_json(p['posture'])
    if isinstance(doc, dict) and isinstance(doc.get('score'), (int, float)):
        seen = True
        previous = store.meta_get(db, 'posture_score')
        store.meta_set(db, 'posture_score', doc['score'])
        if previous is not None and float(previous) - doc['score'] >= POSTURE_DROP:
            events.append({'key': 'posture:%s' % (doc.get('generated') or int(now)), 'type': 'posture_drop',
                           'source': 'posture', 'ts': int(now),
                           'severity': 'high' if float(previous) - doc['score'] >= 25 else 'medium',
                           'title': 'Posture score dropped from %.0f to %.0f' % (float(previous), doc['score']),
                           'detail': str(doc.get('reason') or '')[:300], 'link': TYPE_LINK['posture_drop'],
                           'data': {'before': float(previous), 'after': doc['score']}})
    return events if seen else None


DETECTORS = (('quarantine', detect_quarantine), ('vulns', detect_vulns), ('devices', detect_devices),
             ('ai', detect_ai), ('inbox', detect_inbox), ('summaries', detect_summaries))


def sources_state():
    """ which event types can fire on this firewall (the GUI greys out the others) """
    p = common.paths()
    here = p['scripts']
    exists = os.path.exists
    inbox = set()
    try:
        inbox = {n[:-6] for n in os.listdir(p['events_dir']) if n.endswith('.jsonl')}
    except OSError:
        pass
    return {
        'incident': exists(os.path.join(here, 'incidents')) or exists(p['incidents']) or 'incidents' in inbox,
        'quarantine_long': exists(p['quarantine_db']),
        'vuln_kev_p1': exists(os.path.join(here, 'vulns')) and exists(p['exposure']),
        'anomaly': exists(os.path.join(here, 'anomalies')) or exists(p['anomalies']) or 'anomalies' in inbox,
        'posture_drop': exists(os.path.join(here, 'posture')) or exists(p['posture']) or 'posture' in inbox,
        'ai_down': True,
        'device_new': exists(os.path.join(here, 'devices')),
        'report': True,
    }


# ------------------------------------------------------------------ queue

def enqueue(db, events, cfg, baseline=False):
    added = 0
    for ev in events:
        sub = cfg['notify']['events'].get(ev['type'], {})
        ev['link'] = ev.get('link') or TYPE_LINK.get(ev['type'], '')
        if baseline:
            status, reason = 'suppressed', 'baseline (existed before the notifications were enabled)'
        elif not sub.get('enabled'):
            status, reason = 'suppressed', 'not subscribed'
        elif common.severity_rank(ev['severity']) < common.severity_rank(sub.get('min_severity', 'high')):
            status, reason = 'suppressed', 'below the minimum severity (%s)' % sub.get('min_severity')
        else:
            status, reason = 'queued', None
        if store.add_notification(db, ev, status, reason):
            added += 1
    return added


def collect(db, cfg, now):
    stats = {}
    for name, func in DETECTORS:
        try:
            events = func(db, now)
        except Exception as exc:            # noqa: BLE001 - one broken source never stops the others
            stats[name] = {'error': str(exc)[:200]}
            continue
        if events is None:
            stats[name] = {'available': False}
            continue
        first = store.meta_get(db, 'baseline:%s' % name) is None
        stats[name] = {'available': True, 'events': len(events),
                       'added': enqueue(db, events, cfg, baseline=first)}
        store.meta_set(db, 'baseline:%s' % name, common.iso(now))
    db.commit()
    return stats


def _sent_last_hour(db, now):
    return db.execute("SELECT count(*) FROM messages WHERE kind IN ('notification', 'digest') AND status = 'sent' "
                      'AND ts >= ?', (int(now) - 3600,)).fetchone()[0]


def process(db, cfg, now, smtp_factory=None, assistant=None, only_ids=None, force=False):
    """ send what is due; :return: list of {type, ids, status} """
    rows = db.execute('SELECT %s FROM notifications WHERE status IN (\'queued\', \'held\') %s ORDER BY ts'
                      % (', '.join(store.NOTE_COLS),
                         'AND id IN (%s)' % ','.join(str(int(i)) for i in only_ids) if only_ids else '')).fetchall()
    pending = [store.note(r) for r in rows if force or not r[13] or r[13] <= now]
    by_type = {}
    for item in pending:
        by_type.setdefault(item['type'], []).append(item)
    results = []
    root = common.config_root()
    base = common.gui_base(root, cfg.get('gui_url'))
    host = deliver.hostname(root)
    for etype, items in sorted(by_type.items()):
        throttle = cfg['notify']['events'].get(etype, {}).get('throttle_minutes', 60) * 60
        last = db.execute("SELECT max(sent_at) FROM notifications WHERE type = ? AND status = 'sent' AND "
                          "type != 'report'", (etype,)).fetchone()[0]
        ids = [i['id'] for i in items]
        if not force and throttle and last and now - last < throttle:
            until = last + throttle
            db.execute("UPDATE notifications SET status = 'held', reason = ? WHERE id IN (%s)" % ','.join('?' * len(ids)),
                       ['throttled until %s (digest)' % common.iso(until)] + ids)
            results.append({'type': etype, 'ids': ids, 'status': 'held'})
            continue
        if not force and _sent_last_hour(db, now) >= cfg['notify']['max_per_hour']:
            db.execute("UPDATE notifications SET status = 'held', reason = 'hourly limit reached' WHERE id IN (%s)"
                       % ','.join('?' * len(ids)), ids)
            results.append({'type': etype, 'ids': ids, 'status': 'held'})
            continue
        events = [{'type': i['type'], 'severity': i['severity'], 'title': i['title'], 'detail': i['detail'],
                   'link': i['link'], 'ts': i['ts'], 'data': i['data']} for i in items]
        summary = aisum.notification(events, cfg['language'], cfg['notify']['ai_summary'], assistant)
        subject, html_body, text = render.notification(events, summary, cfg['language'], base, host)
        attachments, short = None, {'type': etype, 'events': len(items)}
        if cfg['notify'].get('attach_pdf', True):
            name, blob, pdf_error = deliver.build_notification_pdf(events, summary, cfg, host, base, now)
            if blob:
                attachments = [(name, blob, 'application/pdf')]
                short['pdf'] = {'name': name, 'size': len(blob)}
            else:
                short['pdf'] = {'error': pdf_error}
        sent = deliver.send_and_record(db, 'digest' if len(items) > 1 else 'notification', subject, html_body, text,
                                       cfg, (min(i['ts'] for i in items), int(now)), short, summary['ai'],
                                       smtp_factory, attachments=attachments)
        if sent['status'] == 'sent':
            db.execute("UPDATE notifications SET status = 'sent', reason = NULL, sent_at = ?, message_id = ?, "
                       'attempts = attempts + 1 WHERE id IN (%s)' % ','.join('?' * len(ids)),
                       [int(now), sent['message_id']] + ids)
        else:
            for item in items:
                attempts = item['attempts'] + 1
                failed = attempts >= MAX_ATTEMPTS
                db.execute('UPDATE notifications SET status = ?, reason = ?, attempts = ?, next_try = ?, '
                           'message_id = ? WHERE id = ?',
                           ('failed' if failed else 'queued', sent['error'], attempts,
                            None if failed else int(now) + RETRY[min(attempts - 1, len(RETRY) - 1)],
                            sent['message_id'], item['id']))
        results.append({'type': etype, 'ids': ids, 'status': sent['status'], 'error': sent.get('error'),
                        'ai_summary': summary['ai']})
        db.commit()
    db.commit()
    return results


def run(now=None, smtp_factory=None, assistant=None, scheduled=True):
    cfg = settings.load()
    now = int(common.now() if now is None else now)
    if scheduled and not cfg['notify']['enabled']:
        return {'status': 'skipped', 'reason': 'the notification center is disabled'}
    db = store.connect()
    try:
        stats = collect(db, cfg, now)
        sent = process(db, cfg, now, smtp_factory, assistant)
        store.meta_set(db, 'last_notify_run', common.iso(now))
        db.commit()
    finally:
        db.close()
    return {'status': 'ok', 'sources': stats, 'deliveries': sent}


def resend(note_id, now=None, smtp_factory=None, assistant=None):
    cfg = settings.load()
    now = int(common.now() if now is None else now)
    db = store.connect()
    try:
        row = db.execute('SELECT status FROM notifications WHERE id = ?', (note_id,)).fetchone()
        if row is None:
            raise ValueError('notification not found')
        db.execute("UPDATE notifications SET status = 'queued', reason = 'resend requested', next_try = NULL "
                   'WHERE id = ?', (note_id,))
        db.commit()
        result = process(db, cfg, now, smtp_factory, assistant, only_ids=[note_id], force=True)
    finally:
        db.close()
    return {'status': 'ok', 'deliveries': result}


def overview(page=1, rows=50, status=None):
    db = store.connect(readonly=True)
    cfg = settings.load()
    avail = sources_state()
    events = [{'type': k, 'label': v[0], 'source': v[3], 'available': avail.get(k, False),
               'subscription': cfg['notify']['events'][k]} for k, v in settings.EVENTS.items()]
    if db is None:
        return {'status': 'ok', 'enabled': cfg['notify']['enabled'], 'events': events, 'total': 0, 'rows': [],
                'counts': {}, 'last_run': None}
    try:
        total, items = store.notifications(db, status, page, rows)
        counts = dict(db.execute('SELECT status, count(*) FROM notifications GROUP BY status').fetchall())
        last = store.meta_get(db, 'last_notify_run')
    finally:
        db.close()
    return {'status': 'ok', 'enabled': cfg['notify']['enabled'], 'events': events, 'total': total, 'rows': items,
            'counts': counts, 'last_run': last}
