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

    Quarantine collector (read only).

    Reads the quarantine ledger (/var/db/policyanalyzer/quarantine.db, schema in CONTRACT.md, "Quarantine
    ledger") with a read-only SQLite connection (mode=ro): nothing is locked, migrated or written, and the
    console never starts a quarantine run.  When the ledger does not exist the quarantine is reported as not installed.
"""

import ipaddress
import json
import os
import sqlite3
import time

from ..common import clean_text

LEVELS = {1: '30 min', 2: '2 h', 3: '2 days', 4: '10 days', 5: '30 days', 6: 'permanent'}
REASONS = {1: 'base', 2: 'scan', 3: 'bait', 4: 'suricata', 5: 'manual'}


def _connect(path):
    if not os.path.exists(path):
        return None
    con = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=2.0)
    con.row_factory = sqlite3.Row
    return con


def _meta(con, key):
    try:
        row = con.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
    except sqlite3.Error:
        return None
    return row['value'] if row else None


def _ts(epoch):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(epoch)) if epoch else None


def summary(paths, now=None):
    now = time.time() if now is None else now
    try:
        con = _connect(paths.quarantine_db)
    except sqlite3.Error:
        con = None
    if con is None:
        return {'available': False, 'installed': False, 'message': 'the quarantine is not installed'}
    try:
        active = con.execute("SELECT level, count(*) n FROM entries WHERE state IN ('active', 'permanent') "
                             "GROUP BY level").fetchall()
        offenses = con.execute('SELECT reason, count(*) n FROM offenses WHERE ts >= ? GROUP BY reason',
                               (int(now - 86400),)).fetchall()
        new = con.execute('SELECT count(*) n FROM entries WHERE first_seen >= ?', (int(now - 86400),)).fetchone()
        latest = con.execute("SELECT addr, kind, level, reason, country, since, until FROM entries "
                             "WHERE state IN ('active', 'permanent') ORDER BY since DESC LIMIT 8").fetchall()
        paused = _meta(con, 'paused') == '1'
        installed = _meta(con, 'installed') is not None
        last_run = _meta(con, 'last_run')
    except sqlite3.Error as exc:
        return {'available': False, 'message': 'quarantine ledger not readable: %s' % exc.__class__.__name__}
    finally:
        con.close()
    try:
        last = json.loads(last_run) if last_run else None
    except ValueError:
        last = None
    return {
        'available': True,
        'source': 'quarantine ledger (read only)',
        'installed': installed,
        'paused': paused,
        'active': sum(r['n'] for r in active),
        'active_by_level': {LEVELS.get(r['level'], str(r['level'])): r['n'] for r in active},
        'offenses_24h': sum(r['n'] for r in offenses),
        'offenses_24h_by_reason': {REASONS.get(r['reason'], str(r['reason'])): r['n'] for r in offenses},
        'new_sources_24h': new['n'] if new else 0,
        'last_run': _ts(last.get('ts') or last.get('finished')) if isinstance(last, dict) else None,
        'latest_active': [{'address': r['addr'], 'kind': r['kind'], 'level': LEVELS.get(r['level'], r['level']),
                           'reason': REASONS.get(r['reason'], r['reason']), 'country': r['country'],
                           'since': _ts(r['since']), 'until': _ts(r['until']) or 'permanent'} for r in latest],
    }


def entry(paths, address, now=None):
    """ the ledger record of one address (exact entry or a network/ASN entry that holds it) """
    now = time.time() if now is None else now
    try:
        ip = ipaddress.ip_address(str(address).split('/')[0])
    except ValueError:
        return {'available': False, 'message': 'invalid address'}
    try:
        con = _connect(paths.quarantine_db)
    except sqlite3.Error:
        con = None
    if con is None:
        return {'available': False, 'installed': False, 'address': str(ip),
                'message': 'the quarantine is not installed'}
    try:
        rows = con.execute('SELECT * FROM entries WHERE addr = ?', (str(ip),)).fetchall()
        if not rows:
            for row in con.execute("SELECT * FROM entries WHERE kind = 'net' AND state IN ('active', 'permanent')"):
                try:
                    if ip in ipaddress.ip_network(row['addr'], strict=False):
                        rows = [row]
                        break
                except ValueError:
                    continue
        if not rows:
            return {'available': True, 'address': str(ip), 'in_ledger': False,
                    'message': 'this address was never quarantined'}
        row = rows[0]
        offenses = con.execute('SELECT ts, reason, level, ports, detail, iface FROM offenses WHERE entry_id = ? '
                               'ORDER BY ts DESC LIMIT 5', (row['id'],)).fetchall()
    except sqlite3.Error as exc:
        return {'available': False, 'message': 'quarantine ledger not readable: %s' % exc.__class__.__name__}
    finally:
        con.close()
    active = row['state'] in ('active', 'permanent') and (row['until'] is None or row['until'] > now)
    return {
        'available': True,
        'source': 'quarantine ledger (read only)',
        'address': str(ip),
        'in_ledger': True,
        'entry': row['addr'],
        'kind': row['kind'],
        'state': row['state'],
        'blocked_now': active,
        'level': LEVELS.get(row['level'], row['level']),
        'reason': REASONS.get(row['reason'], row['reason']),
        'origin': row['origin'],
        'country': row['country'],
        'asn': row['asn'],
        'first_seen': _ts(row['first_seen']),
        'last_offense': _ts(row['last_offense']),
        'until': _ts(row['until']) if row['until'] else ('permanent' if row['state'] == 'permanent' else None),
        'offenses': row['offenses'],
        'hits_while_quarantined': row['hits'],
        'recent_offenses': [{'time': _ts(o['ts']), 'reason': REASONS.get(o['reason'], o['reason']),
                             'level': LEVELS.get(o['level'], o['level']), 'ports': o['ports'],
                             'detail': clean_text(o['detail'], 120), 'interface': o['iface']} for o in offenses],
        'note': 'quarantined sources are blocked by the floating rule "Max Cyber IA" (alias pa_quarantine)',
    }
