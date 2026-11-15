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

    Change actions of the device inventory (plan / apply / revert, journal in /var/db/policyanalyzer/undo/).
    They change only the plugin database / files, never the firewall configuration:

      devices_mark_known <ids 1+2+3> <1|0>          mark as known (or not): the "new device" risk goes away
      devices_set <id> <type|-> <name base64|->     the owner's type and/or name (wins over heuristic and AI)
      devices_oui_update                            download the IEEE OUI registry to <db>/oui.csv (network)
"""

import os
import re
import shutil

from ai import changes

from . import common, oui, risk, store

IDS_RE = re.compile(r'^\d{1,9}(\+\d{1,9}){0,99}$')


def _ids(token):
    if not IDS_RE.match(token or ''):
        raise ValueError('invalid device ids')
    return sorted({int(x) for x in token.split('+')})


def _db_devices(ids):
    db = store.connect(readonly=True)
    if db is None:
        raise ValueError('no scan yet')
    try:
        found = [store.get(db, i) for i in ids]
    finally:
        db.close()
    missing = [i for i, d in zip(ids, found) if d is None]
    if missing:
        raise ValueError('device(s) not found: %s' % ', '.join(map(str, missing)))
    return found


def _rerisk(db, device_id):
    """ recompute the risk after a change of known/type, with the same inputs as the last scan """
    from . import inventory
    dev = store.get(db, device_id)
    assessed = risk.assess({'vendor': dev['vendor'], 'type': dev['type'], 'known': dev['known'],
                            'first_seen': dev['first_seen'], 'ips': dev['ip4'] + dev['ip6']},
                           inventory._kev_counts(), _forwards(), common.now())
    import json
    db.execute('UPDATE devices SET risk = ?, risk_reasons = ? WHERE id = ?',
               (assessed['level'], json.dumps(assessed['reasons']), device_id))


def _forwards():
    from . import sources
    return sources.port_forwards(sources.load_config())


@changes.register
class DevicesMarkKnown(changes.ChangeAction):
    name = 'devices_mark_known'
    description = 'Devices: mark devices as known (or not known); only the plugin database changes'

    def parse_args(self, args):
        args = list(args) + ['', '']
        if args[1] not in ('0', '1'):
            raise ValueError('known must be 1 or 0')
        return {'ids': _ids(args[0]), 'known': args[1] == '1'}

    def plan(self, ids, known):
        devs = _db_devices(ids)
        todo = [d for d in devs if d['known'] != known]
        steps = [{'description': '%s %s (%s, %s)' % ('Mark as known' if known else 'Mark as not known',
                                                    d['name'] or d['mac'], d['vendor'] or 'unknown vendor',
                                                    ', '.join(d['ip4']) or '-'),
                  'command': 'UPDATE devices.db SET known=%d WHERE id=%d' % (known, d['id']),
                  'effect': 'the "new device" risk is %s' % ('removed' if known else 'considered again')}
                 for d in todo]
        return {'status': 'ok', 'steps': steps, 'risk': 'low' if steps else 'none', 'warnings': [],
                'revert': ['Undo restores the previous known flag of these devices.'],
                'args': {'ids': ids, 'known': known}}

    def apply(self, ids, known):
        devs = _db_devices(ids)
        db = store.connect()
        prev = {}
        try:
            now = int(common.now())
            for d in devs:
                if d['known'] == known:
                    continue
                prev[str(d['id'])] = {'known': d['known'], 'known_at': d['known_at']}
                db.execute('UPDATE devices SET known = ?, known_at = ? WHERE id = ?',
                           (int(known), now if known else None, d['id']))
                store.event(db, now, d['id'], 'known' if known else 'unknown', int(d['known']), int(known))
                _rerisk(db, d['id'])
            db.commit()
        finally:
            db.close()
        return {'status': 'ok', 'done': True, 'steps': [], 'args': {'ids': ids, 'known': known},
                'completed': ['%d device(s) updated' % len(prev)], 'state': {'previous': prev}}

    def revert_plan(self, entry):
        prev = (entry.get('state') or {}).get('previous') or {}
        return {'status': 'ok', 'risk': 'low', 'warnings': [], 'revert': [],
                'steps': [{'description': 'Restore the known flag of device %s' % i, 'command': 'UPDATE devices.db',
                           'effect': 'known = %s' % int(p['known'])} for i, p in prev.items()]}

    def revert_apply(self, entry):
        prev = (entry.get('state') or {}).get('previous') or {}
        db = store.connect()
        try:
            now = int(common.now())
            for i, p in prev.items():
                db.execute('UPDATE devices SET known = ?, known_at = ? WHERE id = ?',
                           (int(p['known']), p['known_at'], int(i)))
                store.event(db, now, int(i), 'known' if p['known'] else 'unknown', None, int(p['known']), 'revert')
                _rerisk(db, int(i))
            db.commit()
        finally:
            db.close()
        return {'status': 'ok', 'done': True, 'steps': [], 'completed': ['%d device(s) restored' % len(prev)]}


@changes.register
class DevicesSet(changes.ChangeAction):
    name = 'devices_set'
    description = "Devices: the owner's type and name of a device"

    def parse_args(self, args):
        args = list(args) + ['', '', '']
        if not re.match(r'^\d{1,9}$', args[0]):
            raise ValueError('invalid device id')
        dtype = args[1] or '-'
        if dtype not in ('-', 'auto') and dtype not in common.TYPES:
            raise ValueError('invalid type')
        name = common.decode_text(args[2]) if args[2] not in ('', '-') else None
        if dtype == '-' and name is None:
            raise ValueError('nothing to change')
        return {'device_id': int(args[0]), 'dtype': dtype, 'name': name}

    def plan(self, device_id, dtype, name):
        dev = _db_devices([device_id])[0]
        steps = []
        if dtype != '-':
            new = None if dtype == 'auto' else dtype
            if new != dev['user_type']:
                steps.append({'description': 'Type of %s: %s -> %s' % (dev['name'] or dev['mac'], dev['type'],
                                                                       new or 'automatic (%s)' % dev['auto_type']),
                              'command': 'UPDATE devices.db SET user_type', 'effect': 'the owner type wins'})
        if name is not None and name != (dev['user_name'] or ''):
            steps.append({'description': 'Name of %s: %s -> %s' % (dev['mac'], dev['name'] or '-', name or
                                                                   'automatic (%s)' % (dev['hostname'] or '-')),
                          'command': 'UPDATE devices.db SET user_name', 'effect': 'shown in lists and reports'})
        return {'status': 'ok', 'steps': steps, 'risk': 'low' if steps else 'none', 'warnings': [],
                'revert': ['Undo restores the previous type and name.'],
                'args': {'device_id': device_id, 'dtype': dtype, 'name': name}}

    def apply(self, device_id, dtype, name):
        dev = _db_devices([device_id])[0]
        db = store.connect()
        try:
            now = int(common.now())
            if dtype != '-':
                new = None if dtype == 'auto' else dtype
                db.execute('UPDATE devices SET user_type = ? WHERE id = ?', (new, device_id))
                store.event(db, now, device_id, 'type', dev['user_type'], new)
            if name is not None:
                db.execute('UPDATE devices SET user_name = ? WHERE id = ?', (name or None, device_id))
                store.event(db, now, device_id, 'name', dev['user_name'], name or None)
            _rerisk(db, device_id)
            db.commit()
        finally:
            db.close()
        return {'status': 'ok', 'done': True, 'steps': [], 'completed': ['device %d updated' % device_id],
                'args': {'device_id': device_id, 'dtype': dtype, 'name': name},
                'state': {'device_id': device_id, 'user_type': dev['user_type'], 'user_name': dev['user_name']}}

    def revert_plan(self, entry):
        st = entry.get('state') or {}
        return {'status': 'ok', 'risk': 'low', 'warnings': [], 'revert': [],
                'steps': [{'description': 'Restore type/name of device %s' % st.get('device_id'),
                           'command': 'UPDATE devices.db', 'effect': 'type %s, name %s' % (
                               st.get('user_type') or 'automatic', st.get('user_name') or 'automatic')}]}

    def revert_apply(self, entry):
        st = entry.get('state') or {}
        db = store.connect()
        try:
            db.execute('UPDATE devices SET user_type = ?, user_name = ? WHERE id = ?',
                       (st.get('user_type'), st.get('user_name'), int(st['device_id'])))
            store.event(db, int(common.now()), int(st['device_id']), 'type', None, st.get('user_type'), 'revert')
            _rerisk(db, int(st['device_id']))
            db.commit()
        finally:
            db.close()
        return {'status': 'ok', 'done': True, 'steps': [], 'completed': ['type and name restored']}


@changes.register
class DevicesOuiUpdate(changes.ChangeAction):
    name = 'devices_oui_update'
    description = 'Devices: download the IEEE OUI registry (manufacturer names) to the plugin directory'

    def parse_args(self, args):
        return {}

    def plan(self):
        current = oui.OUI().status()
        target = common.paths()['local_oui']
        return {'status': 'ok', 'risk': 'low',
                'steps': [{'description': 'Download the IEEE MA-L registry (public CSV, ~4 MB)',
                           'command': 'GET %s' % oui.IEEE_URL,
                           'effect': 'stored in %s; used before the copy shipped with OPNsense' % target}],
                'warnings': ['Uses the internet (HTTPS, verified certificate, no redirect, 16 MiB cap); nothing '
                             'about this network is sent.'],
                'info': [{'title': 'Manufacturer database now',
                          'items': ['%s: %d entries, updated %s' % (current['source'] or 'none', current['entries'],
                                                                     current['updated'] or '-'),
                                    'OPNsense already ships this registry and updates it with the firmware; the '
                                    'download is only useful when that copy is old.']}],
                'revert': ['Undo restores the previous file (or removes it).'], 'args': {}}

    def apply(self, get=None):
        body, count = oui.fetch(get)
        target = common.paths()['local_oui']
        backup = None
        if os.path.exists(target):
            backup = target + '.previous'
            shutil.copy2(target, backup)
        common.write_bytes(target, body)
        return {'status': 'ok', 'done': True, 'steps': [], 'args': {},
                'completed': ['IEEE registry stored (%d prefixes)' % count],
                'state': {'path': target, 'backup': backup}}

    def revert_plan(self, entry):
        st = entry.get('state') or {}
        return {'status': 'ok', 'risk': 'low', 'warnings': [], 'revert': [],
                'steps': [{'description': 'Restore the previous registry' if st.get('backup') else
                           'Remove the downloaded registry', 'command': 'file %s' % st.get('path'),
                           'effect': 'manufacturer names come from the previous source'}]}

    def revert_apply(self, entry):
        st = entry.get('state') or {}
        path = st.get('path')
        if path != common.paths()['local_oui']:
            raise ValueError('unexpected path in the journal')
        if st.get('backup') and os.path.exists(st['backup']):
            os.replace(st['backup'], path)
        elif os.path.exists(path):
            os.unlink(path)
        return {'status': 'ok', 'done': True, 'steps': [], 'completed': ['registry restored']}
