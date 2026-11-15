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

    Quarantine ledger: SQLite3 database /var/db/policyanalyzer/quarantine.db (WAL, short transactions).

    The history is kept forever (yearly or older queries with the sqlite3 shell): every offense and every
    entry/exit of the quarantine stays, with a compact summary only (never raw log lines).  The schema is
    documented in CONTRACT.md ("Quarantine ledger") with example queries.

        entries       one row per quarantined address, network or ASN (current state)
        asn_prefixes  prefixes resolved for an ASN entry (pf receives them)
        offenses      history: one row per offense (reason, level, evidence summary, interface, country)
        events        history: enter / upgrade / extend / expire / release / permanent / never_block /
                      guard_release / limit / uninstall / pause / resume / settings
        yearly        aggregate per entry and year (updated in the same transaction as the offenses)
        wg_allowed    addresses with an allowed inbound connection to a WireGuard port (last 24 h guard)
        meta          schema version, log position markers, pause flag, last run
        settings      owner settings (validated, see common.DEFAULTS)
    Views (human readable, local time): v_entries, v_offenses, v_events, v_yearly.
"""

import json
import os
import sqlite3
import time

from . import common

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    addr TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    asn INTEGER,
    country TEXT,
    level INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'expired',
    origin TEXT NOT NULL DEFAULT 'auto',
    reason INTEGER,
    first_seen INTEGER NOT NULL,
    last_offense INTEGER,
    since INTEGER,
    until INTEGER,
    offenses INTEGER NOT NULL DEFAULT 0,
    hits INTEGER NOT NULL DEFAULT 0,
    iface TEXT,
    comment TEXT,
    resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS entries_state ON entries (state, until);
CREATE INDEX IF NOT EXISTS entries_last ON entries (last_offense);
CREATE TABLE IF NOT EXISTS asn_prefixes (
    entry_id INTEGER NOT NULL, prefix TEXT NOT NULL, PRIMARY KEY (entry_id, prefix)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS offenses (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    entry_id INTEGER NOT NULL,
    reason INTEGER NOT NULL,
    reasons INTEGER NOT NULL,
    level INTEGER NOT NULL,
    until INTEGER,
    origin TEXT NOT NULL,
    events INTEGER,
    ports TEXT,
    detail TEXT,
    iface TEXT,
    country TEXT,
    limited INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS offenses_entry ON offenses (entry_id, ts);
CREATE INDEX IF NOT EXISTS offenses_ts ON offenses (ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    entry_id INTEGER,
    kind TEXT NOT NULL,
    level INTEGER,
    until INTEGER,
    origin TEXT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS events_entry ON events (entry_id, ts);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS yearly (
    entry_id INTEGER NOT NULL,
    year INTEGER NOT NULL,
    offenses INTEGER NOT NULL,
    first_seen INTEGER,
    last_seen INTEGER,
    max_level INTEGER,
    reasons INTEGER,
    PRIMARY KEY (entry_id, year)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS yearly_year ON yearly (year);
CREATE TABLE IF NOT EXISTS wg_allowed (ip TEXT PRIMARY KEY, last_seen INTEGER NOT NULL) WITHOUT ROWID;

CREATE VIEW IF NOT EXISTS v_entries AS
    SELECT id, addr, kind, asn, country, level, state, origin,
           CASE reason WHEN 1 THEN 'base' WHEN 2 THEN 'scan' WHEN 3 THEN 'bait' WHEN 4 THEN 'suricata'
                       WHEN 5 THEN 'manual' END AS reason,
           datetime(first_seen, 'unixepoch', 'localtime') AS first_seen,
           datetime(last_offense, 'unixepoch', 'localtime') AS last_offense,
           datetime(since, 'unixepoch', 'localtime') AS since,
           datetime(until, 'unixepoch', 'localtime') AS until,
           offenses, hits, iface, comment
    FROM entries;
CREATE VIEW IF NOT EXISTS v_offenses AS
    SELECT o.id, datetime(o.ts, 'unixepoch', 'localtime') AS time, o.ts,
           CAST(strftime('%Y', o.ts, 'unixepoch', 'localtime') AS INTEGER) AS year,
           e.addr, e.kind, e.asn,
           CASE o.reason WHEN 1 THEN 'base' WHEN 2 THEN 'scan' WHEN 3 THEN 'bait' WHEN 4 THEN 'suricata'
                         WHEN 5 THEN 'manual' END AS reason,
           o.reasons, o.level, datetime(o.until, 'unixepoch', 'localtime') AS until, o.origin, o.events,
           o.ports, o.detail, o.iface, o.country, o.limited
    FROM offenses o JOIN entries e ON e.id = o.entry_id;
CREATE VIEW IF NOT EXISTS v_events AS
    SELECT v.id, datetime(v.ts, 'unixepoch', 'localtime') AS time, v.ts,
           CAST(strftime('%Y', v.ts, 'unixepoch', 'localtime') AS INTEGER) AS year,
           e.addr, v.kind, v.level, datetime(v.until, 'unixepoch', 'localtime') AS until, v.origin, v.note
    FROM events v LEFT JOIN entries e ON e.id = v.entry_id;
CREATE VIEW IF NOT EXISTS v_yearly AS
    SELECT y.year, e.addr, e.kind, e.asn, e.country, y.offenses,
           datetime(y.first_seen, 'unixepoch', 'localtime') AS first_seen,
           datetime(y.last_seen, 'unixepoch', 'localtime') AS last_seen, y.max_level,
           trim((CASE WHEN y.reasons & 1 THEN 'base ' ELSE '' END) ||
                (CASE WHEN y.reasons & 2 THEN 'scan ' ELSE '' END) ||
                (CASE WHEN y.reasons & 4 THEN 'bait ' ELSE '' END) ||
                (CASE WHEN y.reasons & 8 THEN 'suricata ' ELSE '' END) ||
                (CASE WHEN y.reasons & 16 THEN 'manual' ELSE '' END)) AS reasons
    FROM yearly y JOIN entries e ON e.id = y.entry_id;
"""

ENTRY_FIELDS = ('id', 'addr', 'kind', 'asn', 'country', 'level', 'state', 'origin', 'reason', 'first_seen',
                'last_offense', 'since', 'until', 'offenses', 'hits', 'iface', 'comment', 'resolved_at')
SORTABLE = {'addr': 'addr', 'first_seen': 'first_seen', 'last_offense': 'last_offense', 'level': 'level',
            'until': 'until', 'offenses': 'offenses', 'country': 'country', 'asn': 'asn', 'state': 'state',
            'reason': 'reason', 'origin': 'origin', 'hits': 'hits'}


def reason_bit(code):
    return 1 << (int(code) - 1) if code else 0


def reasons_from_mask(mask):
    return [name for name, code in sorted(common.REASONS.items(), key=lambda x: x[1]) if mask & reason_bit(code)]


def year_bounds(year):
    start = int(time.mktime((int(year), 1, 1, 0, 0, 0, 0, 0, -1)))
    end = int(time.mktime((int(year) + 1, 1, 1, 0, 0, 0, 0, 0, -1)))
    return start, end


def local_year(epoch):
    return time.localtime(epoch).tm_year


class Store:
    def __init__(self, path, create=False):
        self.path = path
        if not create and not os.path.exists(path):
            raise common.QuarantineError('the quarantine database does not exist (not installed)')
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, mode=0o750, exist_ok=True)
        new = not os.path.exists(path)
        if new:
            # 0640 root:wheel like the other files of the plugin
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o640))
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.execute('PRAGMA busy_timeout=5000')
        if create or new:
            self.db.executescript(SCHEMA)
            if self.meta('schema') is None:
                self.set_meta('schema', SCHEMA_VERSION)
        self._in_tx = False

    def close(self):
        try:
            self.db.close()
        except sqlite3.Error:
            pass

    # ---------------------------------------------------------- transactions

    def begin(self):
        self.db.execute('BEGIN IMMEDIATE')
        self._in_tx = True

    def commit(self):
        if self._in_tx:
            self.db.execute('COMMIT')
            self._in_tx = False

    def rollback(self):
        if self._in_tx:
            self.db.execute('ROLLBACK')
            self._in_tx = False

    # ---------------------------------------------------------- meta / settings

    def meta(self, key, default=None):
        row = self.db.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
        return row[0] if row is not None else default

    def meta_json(self, key, default=None):
        value = self.meta(key)
        try:
            return json.loads(value) if value is not None else default
        except ValueError:
            return default

    def set_meta(self, key, value):
        if not isinstance(value, str):
            value = json.dumps(value, sort_keys=True)
        self.db.execute('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = '
                        'excluded.value', (key, value))

    def del_meta(self, key):
        self.db.execute('DELETE FROM meta WHERE key = ?', (key,))

    def stored_settings(self):
        return {r[0]: r[1] for r in self.db.execute('SELECT key, value FROM settings')}

    def settings(self):
        return common.effective_settings(self.stored_settings())

    def set_setting(self, key, value):
        self.db.execute('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = '
                        'excluded.value', (key, str(value)))

    # ---------------------------------------------------------- entries

    @staticmethod
    def _entry(row):
        return dict(row) if row is not None else None

    def entry(self, entry_id):
        return self._entry(self.db.execute('SELECT * FROM entries WHERE id = ?', (int(entry_id),)).fetchone())

    def entry_by_addr(self, address):
        return self._entry(self.db.execute('SELECT * FROM entries WHERE addr = ?', (address,)).fetchone())

    def create_entry(self, address, kind, now, **fields):
        cols = {'addr': address, 'kind': kind, 'first_seen': int(now)}
        cols.update({k: v for k, v in fields.items() if k in ENTRY_FIELDS and k != 'id'})
        keys = sorted(cols)
        cur = self.db.execute('INSERT INTO entries (%s) VALUES (%s)' % (', '.join(keys), ', '.join('?' * len(keys))),
                              [cols[k] for k in keys])
        return self.entry(cur.lastrowid)

    def update_entry(self, entry_id, **fields):
        fields = {k: v for k, v in fields.items() if k in ENTRY_FIELDS and k != 'id'}
        if fields:
            keys = sorted(fields)
            self.db.execute('UPDATE entries SET %s WHERE id = ?' % ', '.join('%s = ?' % k for k in keys),
                            [fields[k] for k in keys] + [int(entry_id)])

    def add_hits(self, entry_id, count):
        self.db.execute('UPDATE entries SET hits = hits + ? WHERE id = ?', (int(count), int(entry_id)))

    def active_entries(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM entries WHERE state IN ('active', 'permanent')")]

    def entries_covering_since(self, since):
        """ entries whose quarantine was in force at some point after `since` (event time checks) """
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM entries WHERE state = 'permanent' OR (since IS NOT NULL AND until IS NOT NULL AND "
            "until > ?)", (int(since),))]

    def asn_prefixes(self, entry_id):
        return [r[0] for r in self.db.execute('SELECT prefix FROM asn_prefixes WHERE entry_id = ? ORDER BY prefix',
                                              (int(entry_id),))]

    def set_asn_prefixes(self, entry_id, prefixes, now):
        self.db.execute('DELETE FROM asn_prefixes WHERE entry_id = ?', (int(entry_id),))
        self.db.executemany('INSERT OR IGNORE INTO asn_prefixes (entry_id, prefix) VALUES (?, ?)',
                            [(int(entry_id), p) for p in prefixes])
        self.update_entry(entry_id, resolved_at=int(now))

    # ---------------------------------------------------------- history

    def add_offense(self, entry_id, ts, reason, reasons, level, until, origin, events=None, ports=None,
                    detail=None, iface=None, country=None, limited=False):
        reason_code = common.REASONS[reason] if isinstance(reason, str) else int(reason)
        mask = 0
        for name in reasons or [reason]:
            mask |= reason_bit(common.REASONS[name] if isinstance(name, str) else name)
        self.db.execute(
            'INSERT INTO offenses (ts, entry_id, reason, reasons, level, until, origin, events, ports, detail, '
            'iface, country, limited) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (int(ts), int(entry_id), reason_code, mask, int(level), until, origin, events,
             (ports or '')[:120] or None, (detail or '')[:160] or None, iface, country, 1 if limited else 0))
        year = local_year(ts)
        self.db.execute(
            'INSERT INTO yearly (entry_id, year, offenses, first_seen, last_seen, max_level, reasons) '
            'VALUES (?, ?, 1, ?, ?, ?, ?) ON CONFLICT(entry_id, year) DO UPDATE SET '
            'offenses = offenses + 1, first_seen = min(first_seen, excluded.first_seen), '
            'last_seen = max(last_seen, excluded.last_seen), max_level = max(max_level, excluded.max_level), '
            'reasons = reasons | excluded.reasons',
            (int(entry_id), year, int(ts), int(ts), int(level), mask))

    def add_event(self, entry_id, ts, kind, level=None, until=None, origin=None, note=None):
        self.db.execute('INSERT INTO events (ts, entry_id, kind, level, until, origin, note) VALUES '
                        '(?, ?, ?, ?, ?, ?, ?)', (int(ts), entry_id, kind, level, until, origin,
                                                  (note or '')[:common.COMMENT_MAX] or None))

    # ---------------------------------------------------------- wireguard guard

    def wg_seen(self, items):
        self.db.executemany('INSERT INTO wg_allowed (ip, last_seen) VALUES (?, ?) ON CONFLICT(ip) DO UPDATE SET '
                            'last_seen = max(last_seen, excluded.last_seen)', items)

    def wg_recent(self, since):
        return [r[0] for r in self.db.execute('SELECT ip FROM wg_allowed WHERE last_seen >= ?', (int(since),))]

    def wg_prune(self, before):
        self.db.execute('DELETE FROM wg_allowed WHERE last_seen < ?', (int(before),))

    # ---------------------------------------------------------- queries for the GUI

    def _filters(self, filters, now, alias='e'):
        where, params = [], []
        f = filters or {}
        state = f.get('state')
        if state in ('active', 'permanent', 'expired', 'released'):
            where.append('%s.state = ?' % alias)
            params.append(state)
        elif state == 'blocked':
            where.append("%s.state IN ('active', 'permanent')" % alias)
        if f.get('reason') in common.REASONS:
            where.append('%s.reason = ?' % alias)
            params.append(common.REASONS[f['reason']])
        if f.get('origin') in ('auto', 'manual'):
            where.append('%s.origin = ?' % alias)
            params.append(f['origin'])
        if f.get('country'):
            where.append('%s.country = ?' % alias)
            params.append(f['country'])
        if f.get('asn'):
            where.append('%s.asn = ?' % alias)
            params.append(int(f['asn']))
        if f.get('level'):
            where.append('%s.level = ?' % alias)
            params.append(int(f['level']))
        if f.get('search'):
            where.append('(%s.addr LIKE ? OR %s.comment LIKE ?)' % (alias, alias))
            params.extend(['%' + f['search'] + '%'] * 2)
        if f.get('year'):
            start, end = year_bounds(f['year'])
            where.append('%s.id IN (SELECT entry_id FROM yearly WHERE year = ?)' % alias)
            params.append(int(f['year']))
        return where, params

    def search(self, filters=None, sort=None, page=1, rows=20, now=None):
        where, params = self._filters(filters, now)
        sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
        total = self.db.execute('SELECT count(*) FROM entries e' + sql_where, params).fetchone()[0]
        field, direction = (sort or ('last_offense', 'desc'))
        order = '%s %s, id DESC' % (SORTABLE.get(field, 'last_offense'), 'ASC' if direction == 'asc' else 'DESC')
        sql = 'SELECT e.* FROM entries e%s ORDER BY %s' % (sql_where, order)
        if rows > 0:
            sql += ' LIMIT %d OFFSET %d' % (int(rows), max(0, int(page) - 1) * int(rows))
        return total, [dict(r) for r in self.db.execute(sql, params)]

    def offenses(self, entry_id=None, address=None, start=None, end=None, page=1, rows=50):
        where, params = [], []
        if entry_id is not None:
            where.append('o.entry_id = ?')
            params.append(int(entry_id))
        if address:
            where.append('(e.addr = ? OR e.addr LIKE ?)')
            params.extend([address, address + '%'])
        if start is not None:
            where.append('o.ts >= ?')
            params.append(int(start))
        if end is not None:
            where.append('o.ts < ?')
            params.append(int(end))
        sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
        base = ' FROM offenses o JOIN entries e ON e.id = o.entry_id' + sql_where
        total = self.db.execute('SELECT count(*)' + base, params).fetchone()[0]
        sql = 'SELECT o.*, e.addr, e.kind, e.asn' + base + ' ORDER BY o.ts DESC, o.id DESC'
        if rows > 0:
            sql += ' LIMIT %d OFFSET %d' % (int(rows), max(0, int(page) - 1) * int(rows))
        return total, [dict(r) for r in self.db.execute(sql, params)]

    def events(self, entry_id=None, address=None, start=None, end=None, page=1, rows=50):
        where, params = [], []
        if entry_id is not None:
            where.append('v.entry_id = ?')
            params.append(int(entry_id))
        if address:
            where.append('(e.addr = ? OR e.addr LIKE ?)')
            params.extend([address, address + '%'])
        if start is not None:
            where.append('v.ts >= ?')
            params.append(int(start))
        if end is not None:
            where.append('v.ts < ?')
            params.append(int(end))
        sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
        base = ' FROM events v LEFT JOIN entries e ON e.id = v.entry_id' + sql_where
        total = self.db.execute('SELECT count(*)' + base, params).fetchone()[0]
        sql = 'SELECT v.*, e.addr' + base + ' ORDER BY v.ts DESC, v.id DESC'
        if rows > 0:
            sql += ' LIMIT %d OFFSET %d' % (int(rows), max(0, int(page) - 1) * int(rows))
        return total, [dict(r) for r in self.db.execute(sql, params)]

    def years(self):
        return [r[0] for r in self.db.execute('SELECT DISTINCT year FROM yearly ORDER BY year DESC')]

    def yearly(self, year, address=None, page=1, rows=50):
        where, params = ['y.year = ?'], [int(year)]
        if address:
            where.append('(e.addr = ? OR e.addr LIKE ?)')
            params.extend([address, address + '%'])
        base = ' FROM yearly y JOIN entries e ON e.id = y.entry_id WHERE ' + ' AND '.join(where)
        total = self.db.execute('SELECT count(*)' + base, params).fetchone()[0]
        sql = 'SELECT y.*, e.addr, e.kind, e.asn, e.country' + base + ' ORDER BY y.offenses DESC, y.last_seen DESC'
        if rows > 0:
            sql += ' LIMIT %d OFFSET %d' % (int(rows), max(0, int(page) - 1) * int(rows))
        return total, [dict(r) for r in self.db.execute(sql, params)]

    def counts(self, now):
        by_level = {str(r[0]): r[1] for r in self.db.execute(
            "SELECT level, count(*) FROM entries WHERE state IN ('active', 'permanent') GROUP BY level")}
        by_state = {r[0]: r[1] for r in self.db.execute('SELECT state, count(*) FROM entries GROUP BY state')}
        since = int(now) - 86400
        offenses_24h = self.db.execute('SELECT count(*) FROM offenses WHERE ts >= ?', (since,)).fetchone()[0]
        new_24h = self.db.execute('SELECT count(*) FROM entries WHERE first_seen >= ?', (since,)).fetchone()[0]
        by_reason = {common.REASON_NAMES.get(r[0], str(r[0])): r[1] for r in self.db.execute(
            'SELECT reason, count(*) FROM offenses WHERE ts >= ? GROUP BY reason', (since,))}
        expired_24h = self.db.execute("SELECT count(*) FROM events WHERE kind = 'expire' AND ts >= ?",
                                      (since,)).fetchone()[0]
        top_countries = [{'country': r[0], 'count': r[1]} for r in self.db.execute(
            "SELECT country, count(*) c FROM entries WHERE state IN ('active', 'permanent') AND country IS NOT NULL "
            "GROUP BY country ORDER BY c DESC LIMIT 5")]
        top_asns = [{'asn': r[0], 'count': r[1]} for r in self.db.execute(
            "SELECT asn, count(*) c FROM entries WHERE state IN ('active', 'permanent') AND asn IS NOT NULL "
            "GROUP BY asn ORDER BY c DESC LIMIT 5")]
        totals = self.db.execute('SELECT count(*), min(ts) FROM offenses').fetchone()
        return {'active_by_level': by_level, 'by_state': by_state, 'offenses_24h': offenses_24h,
                'new_24h': new_24h, 'offenses_24h_by_reason': by_reason, 'expired_24h': expired_24h,
                'top_countries': top_countries, 'top_asns': top_asns,
                'offenses_total': totals[0], 'history_since': totals[1],
                'active': sum(by_level.values())}

    def latest_active(self, limit=20):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM entries WHERE state IN ('active', 'permanent') ORDER BY since DESC, id DESC LIMIT ?",
            (int(limit),))]

    def latest_offenses(self, limit=10):
        return [dict(r) for r in self.db.execute(
            'SELECT o.*, e.addr, e.kind FROM offenses o JOIN entries e ON e.id = o.entry_id '
            'ORDER BY o.ts DESC, o.id DESC LIMIT ?', (int(limit),))]

    def size(self):
        try:
            return sum(os.path.getsize(self.path + s) for s in ('', '-wal') if os.path.exists(self.path + s))
        except OSError:
            return None
