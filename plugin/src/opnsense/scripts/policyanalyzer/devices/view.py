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

    Read only views of devices.db: list (filters + page), one device with history, summary for the Max Cyber
    and the reports.
"""

import json

from . import common, store

RISK_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}


def _public(rec, now):
    rec = dict(rec)
    rec['first_seen_iso'] = common.iso(rec['first_seen']) if rec['first_seen'] else None
    rec['last_seen_iso'] = common.iso(rec['last_seen']) if rec['last_seen'] else None
    rec['is_new'] = bool(rec['first_seen'] and now - rec['first_seen'] < common.NEW_DAYS * 86400 and
                         not rec['known'])
    rec['ai'] = {'type': rec.pop('ai_type'), 'text': rec.pop('ai_text'),
                 'at': common.iso(rec['ai_at']) if rec.get('ai_at') else None}
    rec.pop('ai_at', None)
    return rec


def parse_filters(token):
    """ 'type=camera+risk=high+known=0+present=1+new=1+search=abc' """
    out = {}
    for part in (token or '').split('+'):
        if '=' not in part:
            continue
        key, value = part.split('=', 1)
        if key == 'type' and value in common.TYPES:
            out[key] = value
        elif key == 'risk' and value in RISK_ORDER:
            out[key] = value
        elif key in ('known', 'present', 'new') and value in ('0', '1'):
            out[key] = value == '1'
        elif key == 'search':
            out[key] = value[:64].lower()
    return out


def match(rec, flt):
    if 'type' in flt and rec['type'] != flt['type']:
        return False
    if 'risk' in flt and rec['risk'] != flt['risk']:
        return False
    for key in ('known', 'present'):
        if key in flt and rec[key] != flt[key]:
            return False
    if 'new' in flt and rec['is_new'] != flt['new']:
        return False
    if flt.get('search'):
        hay = ' '.join(str(x) for x in (rec['name'], rec['hostname'], rec['vendor'], rec['mac'], ' '.join(rec['ip4']),
                                        rec['iface_descr'], rec['type'])).lower()
        if flt['search'] not in hay:
            return False
    return True


def listing(filters=None, sort='risk', page=1, rows=50, now=None):
    now = common.now() if now is None else now
    db = store.connect(readonly=True)
    if db is None:
        return {'status': 'none', 'message': 'no scan yet', 'rows': [], 'total': 0}
    try:
        items = [_public(r, now) for r in store.all_devices(db)]
        last = store.meta_get(db, 'last_scan')
        state = json.loads(store.meta_get(db, 'sources', '{}') or '{}')
    finally:
        db.close()
    flt = parse_filters(filters)
    items = [i for i in items if match(i, flt)]
    keys = {'risk': lambda i: (RISK_ORDER.get(i['risk'], 9), not i['is_new'], -(i['last_seen'] or 0)),
            'last_seen': lambda i: -(i['last_seen'] or 0), 'first_seen': lambda i: -(i['first_seen'] or 0),
            'name': lambda i: ((i['name'] or '~').lower(), i['mac']), 'type': lambda i: (i['type'], i['mac'])}
    items.sort(key=keys.get(sort, keys['risk']))
    rows = max(1, min(500, rows))
    start = (max(1, page) - 1) * rows
    return {'status': 'ok', 'total': len(items), 'page': page, 'rows_per_page': rows,
            'rows': items[start:start + rows], 'last_scan': common.iso(int(last)) if last else None,
            'sources': state}


def device(device_id, now=None):
    now = common.now() if now is None else now
    db = store.connect(readonly=True)
    if db is None:
        return {'status': 'error', 'message': 'no scan yet'}
    try:
        rec = store.get(db, device_id)
        if rec is None:
            return {'status': 'error', 'message': 'device not found'}
        out = _public(rec, now)
        out['history'] = store.history(db, device_id)
        out['addresses'] = store.addresses(db, device_id)
    finally:
        db.close()
    return {'status': 'ok', 'device': out}


def summary(now=None):
    now = common.now() if now is None else now
    db = store.connect(readonly=True)
    if db is None:
        return {'status': 'none', 'total': 0}
    try:
        items = [_public(r, now) for r in store.all_devices(db)]
        last = store.meta_get(db, 'last_scan')
        new_24h = db.execute("SELECT count(*) FROM events WHERE kind = 'new' AND ts >= ?", (now - 86400,)).fetchone()[0]
    finally:
        db.close()
    by_type, by_risk = {}, {k: 0 for k in RISK_ORDER}
    for i in items:
        by_type[i['type']] = by_type.get(i['type'], 0) + 1
        by_risk[i['risk'] or 'info'] = by_risk.get(i['risk'] or 'info', 0) + 1
    ranked = sorted((i for i in items if i['risk'] in ('high', 'medium')),
                    key=lambda i: (RISK_ORDER[i['risk']], -(i['last_seen'] or 0)))
    return {'status': 'ok', 'last_scan': common.iso(int(last)) if last else None, 'total': len(items),
            'present': sum(1 for i in items if i['present']), 'known': sum(1 for i in items if i['known']),
            'unknown': sum(1 for i in items if not i['known']), 'new_7d': sum(1 for i in items if i['is_new']),
            'new_24h': new_24h, 'by_type': by_type, 'by_risk': by_risk,
            'top_risk': [{'id': i['id'], 'name': i['name'], 'type': i['type'], 'vendor': i['vendor'],
                          'risk': i['risk'], 'interface': i['iface_descr'],
                          'reason': (i['risk_reasons'][0]['text'] if i['risk_reasons'] else None)} for i in ranked[:5]]}


def new_since(since):
    """ devices first seen after since (epoch): used by the reports and the notifications """
    db = store.connect(readonly=True)
    if db is None:
        return []
    try:
        rows = db.execute("SELECT d.id FROM events e JOIN devices d ON d.id = e.device_id WHERE e.kind = 'new' "
                          'AND e.ts >= ? ORDER BY e.ts', (since,)).fetchall()
        return [_public(store.get(db, r[0]), common.now()) for r in rows]
    finally:
        db.close()
