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

    Incident cases: SQLite3 database /var/db/policyanalyzer/incidents.db (WAL, short transactions).

    The cases, their evidence, notes, state changes, AI summaries and daily digests are kept forever (like the
    quarantine ledger).  The compact observations the correlation works on (aggregated per 5 minutes, never raw
    log lines) are kept 48 h, the per port hourly counters of the baselines 8 days.

        cases          one row per case: title, primary rule and entity, score, factors, state, times
        case_entities  external / internal / own addresses, ports and rules of a case
        case_rules     the correlation rules that matched a case (first, last, hits)
        evidence       timeline: one summarized line per fact (source, rule, count, first/last)
        notes          notes of the operator
        case_log       history of a case: created, state, note, summary, reopened, suppressed
        summaries      AI summaries (JSON: summary, hypothesis, impact, next steps, actions)
        digests        AI daily digests, one per local day
        obs            observations (5 minute buckets), port_hourly baselines, meta (markers), settings
"""

import json
import os
import sqlite3

from . import common

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS obs (
    bucket INTEGER NOT NULL,
    kind TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    port TEXT NOT NULL,
    rid TEXT NOT NULL,
    iface TEXT,
    sev INTEGER,
    label TEXT,
    n INTEGER NOT NULL,
    first INTEGER NOT NULL,
    last INTEGER NOT NULL,
    PRIMARY KEY (bucket, kind, src, dst, port, rid)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS obs_src ON obs (src, kind, bucket);
CREATE INDEX IF NOT EXISTS obs_dst ON obs (dst, kind, bucket);
CREATE INDEX IF NOT EXISTS obs_port ON obs (port, kind, bucket);
CREATE TABLE IF NOT EXISTS port_hourly (
    hour INTEGER NOT NULL,
    port TEXT NOT NULL,
    events INTEGER NOT NULL,
    blocked INTEGER NOT NULL,
    passed INTEGER NOT NULL,
    sources INTEGER NOT NULL,
    PRIMARY KEY (port, hour)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    rule TEXT NOT NULL,
    primary_kind TEXT NOT NULL,
    primary_value TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    factors TEXT,
    state TEXT NOT NULL DEFAULT 'new',
    created INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    matches INTEGER NOT NULL DEFAULT 0,
    suppressed INTEGER NOT NULL DEFAULT 0,
    previous_id INTEGER,
    summary_ts INTEGER
);
CREATE INDEX IF NOT EXISTS cases_entity ON cases (primary_kind, primary_value, last_activity);
CREATE INDEX IF NOT EXISTS cases_activity ON cases (last_activity);
CREATE INDEX IF NOT EXISTS cases_state ON cases (state, last_activity);
CREATE TABLE IF NOT EXISTS case_entities (
    case_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    role TEXT NOT NULL,
    info TEXT,
    PRIMARY KEY (case_id, kind, value)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS case_entities_value ON case_entities (value);
CREATE TABLE IF NOT EXISTS case_rules (
    case_id INTEGER NOT NULL,
    rule TEXT NOT NULL,
    first INTEGER NOT NULL,
    last INTEGER NOT NULL,
    hits INTEGER NOT NULL,
    PRIMARY KEY (case_id, rule)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    source TEXT NOT NULL,
    rule TEXT,
    key TEXT,
    text TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    first INTEGER,
    last INTEGER,
    data TEXT
);
CREATE INDEX IF NOT EXISTS evidence_case ON evidence (case_id, ts);
CREATE INDEX IF NOT EXISTS evidence_key ON evidence (case_id, key);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    text TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS notes_case ON notes (case_id, ts);
CREATE TABLE IF NOT EXISTS case_log (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT,
    note TEXT,
    journal_id TEXT
);
CREATE INDEX IF NOT EXISTS case_log_case ON case_log (case_id, ts);
CREATE TABLE IF NOT EXISTS summaries (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    language TEXT,
    provider TEXT,
    model TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS summaries_case ON summaries (case_id, ts);
CREATE TABLE IF NOT EXISTS digests (
    day TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    language TEXT,
    provider TEXT,
    model TEXT,
    data TEXT NOT NULL
) WITHOUT ROWID;

CREATE VIEW IF NOT EXISTS v_cases AS
    SELECT id, title, rule, primary_kind, primary_value, severity, score, state,
           datetime(first_seen, 'unixepoch', 'localtime') AS first_seen,
           datetime(last_activity, 'unixepoch', 'localtime') AS last_activity,
           datetime(created, 'unixepoch', 'localtime') AS created, matches, suppressed, previous_id
    FROM cases;
CREATE VIEW IF NOT EXISTS v_evidence AS
    SELECT e.id, e.case_id, datetime(e.ts, 'unixepoch', 'localtime') AS time, e.source, e.rule, e.text, e.count,
           datetime(e.first, 'unixepoch', 'localtime') AS first, datetime(e.last, 'unixepoch', 'localtime') AS last
    FROM evidence e;
"""

CASE_FIELDS = ('title', 'rule', 'primary_kind', 'primary_value', 'severity', 'score', 'factors', 'state',
               'created', 'first_seen', 'last_activity', 'updated', 'matches', 'suppressed', 'previous_id',
               'summary_ts')
SORTABLE = {'last_activity': 'last_activity', 'score': 'score', 'created': 'created', 'id': 'id',
            'state': 'state', 'first_seen': 'first_seen'}


def _loads(value, default=None):
    try:
        return json.loads(value) if value else default
    except ValueError:
        return default


class Store:
    def __init__(self, path, create=False, readonly=False):
        self.path = path
        if not create and not os.path.exists(path):
            raise common.IncidentError('the incidents database does not exist (not installed)')
        if readonly:
            self.db = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=10, isolation_level=None)
        else:
            directory = os.path.dirname(path)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o750, exist_ok=True)
            new = not os.path.exists(path)
            if new:
                os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o640))
            self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA busy_timeout=5000')
        if not readonly:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=NORMAL')
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
        return _loads(self.meta(key), default)

    def set_meta(self, key, value):
        if not isinstance(value, str):
            value = json.dumps(value, sort_keys=True)
        self.db.execute('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = '
                        'excluded.value', (key, value))

    def stored_settings(self):
        return {r[0]: r[1] for r in self.db.execute('SELECT key, value FROM settings')}

    def settings(self):
        return common.effective_settings(self.stored_settings())

    def set_setting(self, key, value):
        self.db.execute('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = '
                        'excluded.value', (key, str(value)))

    # ---------------------------------------------------------- observations

    def add_obs(self, rows):
        """ rows: dicts {bucket, kind, src, dst, port, rid, iface, sev, label, n, first, last} """
        self.db.executemany(
            'INSERT INTO obs (bucket, kind, src, dst, port, rid, iface, sev, label, n, first, last) '
            'VALUES (:bucket, :kind, :src, :dst, :port, :rid, :iface, :sev, :label, :n, :first, :last) '
            'ON CONFLICT(bucket, kind, src, dst, port, rid) DO UPDATE SET n = n + excluded.n, '
            'first = min(first, excluded.first), last = max(last, excluded.last), '
            'iface = coalesce(excluded.iface, iface), sev = coalesce(min(sev, excluded.sev), excluded.sev, sev), '
            'label = coalesce(excluded.label, label)', rows)

    def obs(self, kinds, since, src=None, dst=None, port=None, until=None):
        where, params = ['bucket >= ?'], [int(since) - int(since) % common.BUCKET]
        where.append('kind IN (%s)' % ','.join('?' * len(kinds)))
        params.extend(kinds)
        for col, value in (('src', src), ('dst', dst), ('port', port)):
            if value is not None:
                where.append('%s = ?' % col)
                params.append(value)
        if until is not None:
            where.append('bucket <= ?')
            params.append(int(until))
        return [dict(r) for r in self.db.execute('SELECT * FROM obs WHERE %s ORDER BY first' % ' AND '.join(where),
                                                 params)]

    def prune_obs(self, before):
        self.db.execute('DELETE FROM obs WHERE bucket < ?', (int(before),))

    def set_hourly(self, hour, port, events, blocked, passed, sources):
        self.db.execute('INSERT INTO port_hourly (hour, port, events, blocked, passed, sources) VALUES '
                        '(?, ?, ?, ?, ?, ?) ON CONFLICT(port, hour) DO UPDATE SET events = excluded.events, '
                        'blocked = excluded.blocked, passed = excluded.passed, sources = excluded.sources',
                        (int(hour), port, int(events), int(blocked), int(passed), int(sources)))

    def hourly(self, port, since, before):
        return [dict(r) for r in self.db.execute(
            'SELECT * FROM port_hourly WHERE port = ? AND hour >= ? AND hour < ? ORDER BY hour',
            (port, int(since), int(before)))]

    def hourly_span(self):
        row = self.db.execute('SELECT min(hour), max(hour) FROM port_hourly').fetchone()
        return (row[0], row[1]) if row else (None, None)

    def prune_hourly(self, before):
        self.db.execute('DELETE FROM port_hourly WHERE hour < ?', (int(before),))

    # ---------------------------------------------------------- cases

    @staticmethod
    def _case(row):
        if row is None:
            return None
        case = dict(row)
        case['factors'] = _loads(case.get('factors'), [])
        return case

    def case(self, case_id):
        return self._case(self.db.execute('SELECT * FROM cases WHERE id = ?', (int(case_id),)).fetchone())

    def latest_case_for(self, kind, value):
        return self._case(self.db.execute(
            'SELECT * FROM cases WHERE primary_kind = ? AND primary_value = ? ORDER BY last_activity DESC, id DESC '
            'LIMIT 1', (kind, value)).fetchone())

    def create_case(self, now, **fields):
        cols = {'created': int(now), 'updated': int(now)}
        cols.update({k: v for k, v in fields.items() if k in CASE_FIELDS})
        if isinstance(cols.get('factors'), (list, dict)):
            cols['factors'] = json.dumps(cols['factors'], sort_keys=True)
        keys = sorted(cols)
        cur = self.db.execute('INSERT INTO cases (%s) VALUES (%s)' % (', '.join(keys), ', '.join('?' * len(keys))),
                              [cols[k] for k in keys])
        return self.case(cur.lastrowid)

    def update_case(self, case_id, **fields):
        fields = {k: v for k, v in fields.items() if k in CASE_FIELDS}
        if isinstance(fields.get('factors'), (list, dict)):
            fields['factors'] = json.dumps(fields['factors'], sort_keys=True)
        if fields:
            keys = sorted(fields)
            self.db.execute('UPDATE cases SET %s WHERE id = ?' % ', '.join('%s = ?' % k for k in keys),
                            [fields[k] for k in keys] + [int(case_id)])

    def set_entity(self, case_id, kind, value, role='related', info=None):
        self.db.execute(
            'INSERT INTO case_entities (case_id, kind, value, role, info) VALUES (?, ?, ?, ?, ?) '
            'ON CONFLICT(case_id, kind, value) DO UPDATE SET info = coalesce(excluded.info, info), '
            "role = CASE WHEN role = 'primary' THEN role ELSE excluded.role END",
            (int(case_id), kind, value, role, json.dumps(info, sort_keys=True) if info else None))

    def entities(self, case_id):
        out = []
        for r in self.db.execute("SELECT * FROM case_entities WHERE case_id = ? ORDER BY role = 'primary' DESC, "
                                 'kind, value', (int(case_id),)):
            item = dict(r)
            item['info'] = _loads(item.get('info'), {})
            out.append(item)
        return out

    def touch_rule(self, case_id, rule, first, last):
        self.db.execute('INSERT INTO case_rules (case_id, rule, first, last, hits) VALUES (?, ?, ?, ?, 1) '
                        'ON CONFLICT(case_id, rule) DO UPDATE SET hits = hits + 1, first = min(first, excluded.first), '
                        'last = max(last, excluded.last)', (int(case_id), rule, int(first), int(last)))

    def case_rules(self, case_id):
        return [dict(r) for r in self.db.execute('SELECT * FROM case_rules WHERE case_id = ? ORDER BY first',
                                                 (int(case_id),))]

    def has_rule(self, case_id, rule):
        return self.db.execute('SELECT 1 FROM case_rules WHERE case_id = ? AND rule = ?',
                               (int(case_id), rule)).fetchone() is not None

    # ---------------------------------------------------------- evidence / notes / log

    def add_evidence(self, case_id, ts, source, text, rule=None, key=None, count=1, first=None, last=None,
                     data=None, replace=False):
        """
        same key in the same case: the existing row is updated (count added, or replaced when `replace`: the
        text then carries the absolute numbers); :return: True when a row was inserted
        """
        text = common.clean_text(text, common.EVIDENCE_TEXT)
        if key:
            row = self.db.execute('SELECT id FROM evidence WHERE case_id = ? AND key = ? ORDER BY id DESC LIMIT 1',
                                  (int(case_id), key)).fetchone()
            if row is not None:
                self.db.execute('UPDATE evidence SET count = %s, last = max(coalesce(last, 0), ?), text = ?, '
                                'ts = max(ts, ?), data = coalesce(?, data) WHERE id = ?' %
                                ('?' if replace else 'count + ?'),
                                (int(count), int(last or ts), text, int(ts),
                                 json.dumps(data, sort_keys=True) if data else None, row[0]))
                return False
        total = self.db.execute('SELECT count(*) FROM evidence WHERE case_id = ?', (int(case_id),)).fetchone()[0]
        if total >= common.MAX_EVIDENCE:
            row = self.db.execute('SELECT id FROM evidence WHERE case_id = ? AND source = ? ORDER BY id DESC LIMIT 1',
                                  (int(case_id), source)).fetchone()
            if row is not None:
                self.db.execute('UPDATE evidence SET count = count + ?, last = max(coalesce(last, 0), ?) WHERE id = ?',
                                (int(count), int(last or ts), row[0]))
            return False
        self.db.execute('INSERT INTO evidence (case_id, ts, source, rule, key, text, count, first, last, data) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (int(case_id), int(ts), source, rule, key, text, int(count), first, last,
                         json.dumps(data, sort_keys=True) if data else None))
        return True

    def has_evidence(self, case_id, key):
        return self.db.execute('SELECT 1 FROM evidence WHERE case_id = ? AND key = ? LIMIT 1',
                               (int(case_id), key)).fetchone() is not None

    def evidence(self, case_id, limit=200):
        out = []
        for r in self.db.execute('SELECT * FROM evidence WHERE case_id = ? ORDER BY coalesce(first, ts), id LIMIT ?',
                                 (int(case_id), int(limit))):
            item = dict(r)
            item['data'] = _loads(item.get('data'), None)
            out.append(item)
        return out

    def evidence_count(self, case_id):
        return self.db.execute('SELECT count(*), coalesce(sum(count), 0) FROM evidence WHERE case_id = ?',
                               (int(case_id),)).fetchone()

    def add_note(self, case_id, ts, text):
        cur = self.db.execute('INSERT INTO notes (case_id, ts, text) VALUES (?, ?, ?)',
                              (int(case_id), int(ts), common.clean_text(text, common.NOTE_MAX)))
        return cur.lastrowid

    def delete_note(self, note_id):
        self.db.execute('UPDATE notes SET deleted = 1 WHERE id = ?', (int(note_id),))

    def notes(self, case_id):
        return [dict(r) for r in self.db.execute('SELECT * FROM notes WHERE case_id = ? AND deleted = 0 ORDER BY ts, id',
                                                 (int(case_id),))]

    def log(self, case_id, ts, kind, from_state=None, to_state=None, note=None, journal_id=None):
        self.db.execute('INSERT INTO case_log (case_id, ts, kind, from_state, to_state, note, journal_id) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?)', (int(case_id), int(ts), kind, from_state, to_state,
                                                         common.clean_text(note, 200) or None, journal_id))

    def case_log(self, case_id):
        return [dict(r) for r in self.db.execute('SELECT * FROM case_log WHERE case_id = ? ORDER BY ts, id',
                                                 (int(case_id),))]

    # ---------------------------------------------------------- AI results

    def add_summary(self, case_id, ts, data, language=None, provider=None, model=None):
        self.db.execute('INSERT INTO summaries (case_id, ts, language, provider, model, data) VALUES (?, ?, ?, ?, ?, ?)',
                        (int(case_id), int(ts), language, provider, model, json.dumps(data, sort_keys=True)))
        self.update_case(case_id, summary_ts=int(ts))

    def last_summary(self, case_id):
        row = self.db.execute('SELECT * FROM summaries WHERE case_id = ? ORDER BY ts DESC, id DESC LIMIT 1',
                              (int(case_id),)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item['data'] = _loads(item['data'], {})
        return item

    def set_digest(self, day, ts, data, language=None, provider=None, model=None):
        self.db.execute('INSERT INTO digests (day, ts, language, provider, model, data) VALUES (?, ?, ?, ?, ?, ?) '
                        'ON CONFLICT(day) DO UPDATE SET ts = excluded.ts, language = excluded.language, '
                        'provider = excluded.provider, model = excluded.model, data = excluded.data',
                        (day, int(ts), language, provider, model, json.dumps(data, sort_keys=True)))

    def digest(self, day):
        row = self.db.execute('SELECT * FROM digests WHERE day = ?', (day,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item['data'] = _loads(item['data'], {})
        return item

    # ---------------------------------------------------------- queries for the GUI

    def search(self, filters=None, sort=None, page=1, rows=25):
        f = filters or {}
        where, params = [], []
        if f.get('state') in common.STATES:
            where.append('c.state = ?')
            params.append(f['state'])
        elif f.get('state') == 'open':
            where.append("c.state IN ('new', 'investigating')")
        if f.get('severity') in common.SEVERITIES:
            where.append('c.severity = ?')
            params.append(f['severity'])
        if f.get('rule') in common.RULES:
            where.append('c.id IN (SELECT case_id FROM case_rules WHERE rule = ?)')
            params.append(f['rule'])
        if f.get('since'):
            where.append('c.last_activity >= ?')
            params.append(int(f['since']))
        if f.get('until'):
            where.append('c.last_activity < ?')
            params.append(int(f['until']))
        if f.get('search'):
            where.append('(c.title LIKE ? OR c.id IN (SELECT case_id FROM case_entities WHERE value LIKE ?))')
            params.extend(['%' + f['search'] + '%'] * 2)
        sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
        total = self.db.execute('SELECT count(*) FROM cases c' + sql_where, params).fetchone()[0]
        field, direction = sort or ('last_activity', 'desc')
        order = '%s %s, id DESC' % (SORTABLE.get(field, 'last_activity'), 'ASC' if direction == 'asc' else 'DESC')
        sql = 'SELECT c.* FROM cases c%s ORDER BY %s' % (sql_where, order)
        if rows > 0:
            sql += ' LIMIT %d OFFSET %d' % (int(rows), max(0, int(page) - 1) * int(rows))
        return total, [self._case(r) for r in self.db.execute(sql, params)]

    def counts(self, now):
        since = int(now) - 86400
        by_state = {r[0]: r[1] for r in self.db.execute('SELECT state, count(*) FROM cases GROUP BY state')}
        open_by_sev = {r[0]: r[1] for r in self.db.execute(
            "SELECT severity, count(*) FROM cases WHERE state IN ('new', 'investigating') GROUP BY severity")}
        new_24h = self.db.execute('SELECT count(*) FROM cases WHERE created >= ?', (since,)).fetchone()[0]
        active_24h = self.db.execute('SELECT count(*) FROM cases WHERE last_activity >= ?', (since,)).fetchone()[0]
        by_rule_24h = {r[0]: r[1] for r in self.db.execute(
            'SELECT rule, count(*) FROM case_rules WHERE last >= ? GROUP BY rule', (since,))}
        return {'by_state': by_state, 'open_by_severity': open_by_sev, 'new_24h': new_24h,
                'active_24h': active_24h, 'by_rule_24h': by_rule_24h,
                'open': sum(open_by_sev.values()), 'total': sum(by_state.values())}

    def size(self):
        try:
            return sum(os.path.getsize(self.path + s) for s in ('', '-wal') if os.path.exists(self.path + s))
        except OSError:
            return None
