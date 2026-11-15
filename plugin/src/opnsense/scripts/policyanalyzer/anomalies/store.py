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

    SQLite store /var/db/policyanalyzer/anomalies.db (WAL, 0640).

    Permanent (never pruned): findings, occurrences, exceptions, devices.
    Baselines and learning state, with retention (prune() once per run):
      pairs          connection times per host/destination/port (beaconing)        beacon_window_h
      host_hour      bytes/flows per host and hour                                 35 days
      vol_base       EWMA mean/variance per host and hour of the day (-1: any hour)  kept while the host is
      host_dns_hour  queries / NXDOMAIN / TXT per host and hour                    35 days
      host_dest      countries and ASNs per host                                   180 days
      host_domain    registrable domains per host (new domain detector)            90 days
      host_ja4       TLS client fingerprints per host                              180 days
      tls_issuer     certificate issuers seen                                      180 days
      hosts_seen     first/last activity per host (learning period)                180 days
      runs           cost and result of every run                                  60 days
"""

import json
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, type TEXT NOT NULL, host TEXT NOT NULL, key TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL, score INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open',
    title TEXT, detail TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1, factors TEXT, evidence TEXT, params TEXT,
    mac TEXT, hostname TEXT, exception_id INTEGER, max_score INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS findings_last ON findings (last_seen);
CREATE INDEX IF NOT EXISTS findings_host ON findings (host, last_seen);
CREATE TABLE IF NOT EXISTS occurrences (
    id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL, ts INTEGER NOT NULL, last_ts INTEGER NOT NULL,
    severity TEXT NOT NULL, score INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', factors TEXT
);
CREATE INDEX IF NOT EXISTS occ_finding ON occurrences (finding_id, ts);
CREATE INDEX IF NOT EXISTS occ_ts ON occurrences (ts);
CREATE TABLE IF NOT EXISTS exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, host TEXT NOT NULL, key TEXT NOT NULL,
    comment TEXT, created INTEGER NOT NULL, journal_id TEXT, finding_id TEXT, active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER, ip TEXT, hostname TEXT, vendor TEXT,
    iface TEXT, source TEXT, learned INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS pairs (
    host TEXT NOT NULL, dst TEXT NOT NULL, dport INTEGER NOT NULL, proto INTEGER NOT NULL,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, times TEXT NOT NULL, sizes TEXT NOT NULL,
    durs TEXT NOT NULL, sports TEXT NOT NULL DEFAULT '[]', PRIMARY KEY (host, dst, dport, proto)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS pairs_last ON pairs (last_seen);
CREATE TABLE IF NOT EXISTS host_hour (
    host TEXT NOT NULL, hour INTEGER NOT NULL, bytes_out INTEGER NOT NULL DEFAULT 0,
    bytes_in INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0, dsts INTEGER NOT NULL DEFAULT 0,
    top TEXT, evaluated INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (host, hour)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS host_hour_hour ON host_hour (hour);
CREATE TABLE IF NOT EXISTS vol_base (
    host TEXT NOT NULL, slot INTEGER NOT NULL, n INTEGER NOT NULL, mean REAL NOT NULL, var REAL NOT NULL,
    updated INTEGER NOT NULL, PRIMARY KEY (host, slot)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS host_dns_hour (
    host TEXT NOT NULL, hour INTEGER NOT NULL, queries INTEGER NOT NULL, nx INTEGER NOT NULL, txt INTEGER NOT NULL,
    PRIMARY KEY (host, hour)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS host_dest (
    host TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL, conns INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host, kind, value)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS host_dest_value ON host_dest (kind, value);
CREATE TABLE IF NOT EXISTS host_domain (
    host TEXT NOT NULL, domain TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    queries INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (host, domain)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS host_domain_domain ON host_domain (domain);
CREATE TABLE IF NOT EXISTS host_ja4 (
    host TEXT NOT NULL, ja4 TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0, sni TEXT, PRIMARY KEY (host, ja4)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS host_ja4_ja4 ON host_ja4 (ja4);
CREATE TABLE IF NOT EXISTS tls_issuer (
    issuer TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, count INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hosts_seen (
    host TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, duration_ms INTEGER, cpu_ms INTEGER,
    status TEXT, findings INTEGER, info TEXT
);
"""

RETENTION = {
    'host_hour': ('hour', 35 * 86400),
    'host_dns_hour': ('hour', 35 * 86400),
    'host_dest': ('last_seen', 180 * 86400),
    'host_domain': ('last_seen', 90 * 86400),
    'host_ja4': ('last_seen', 180 * 86400),
    'tls_issuer': ('last_seen', 180 * 86400),
    'hosts_seen': ('last_seen', 180 * 86400),
    'runs': ('ts', 60 * 86400),
}


class Store:
    def __init__(self, path, readonly=False):
        self.path = path
        if readonly:
            if not os.path.exists(path):
                raise sqlite3.OperationalError('no anomaly database yet')
            self.db = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=10)
        else:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, mode=0o750, exist_ok=True)
            new = not os.path.exists(path)
            self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
            if new:
                os.chmod(path, 0o640)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=NORMAL')
            self.db.executescript(SCHEMA)
        self.db.row_factory = sqlite3.Row

    def close(self):
        self.db.close()

    def begin(self):
        self.db.execute('BEGIN IMMEDIATE')

    def commit(self):
        self.db.execute('COMMIT')

    def rollback(self):
        try:
            self.db.execute('ROLLBACK')
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------ meta / settings
    def get_meta(self, key, default=None):
        row = self.db.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except ValueError:
            return default

    def set_meta(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?, ?)', (key, json.dumps(value)))

    def settings(self):
        return {r[0]: r[1] for r in self.db.execute('SELECT key, value FROM settings')}

    def set_setting(self, key, value):
        if value is None:
            self.db.execute('DELETE FROM settings WHERE key = ?', (key,))
        else:
            self.db.execute('INSERT OR REPLACE INTO settings VALUES (?, ?)', (key, str(value)))

    # ------------------------------------------------------------------ exceptions
    def exceptions(self, active_only=True):
        sql = 'SELECT * FROM exceptions' + (' WHERE active = 1' if active_only else '') + ' ORDER BY id DESC'
        return [dict(r) for r in self.db.execute(sql)]

    def add_exception(self, kind, host, key, comment, now, journal_id=None, finding_id=None):
        cur = self.db.execute('INSERT INTO exceptions (type, host, key, comment, created, journal_id, finding_id) '
                              'VALUES (?, ?, ?, ?, ?, ?, ?)', (kind, host, key, comment, int(now), journal_id,
                                                               finding_id))
        return cur.lastrowid

    def set_exception_active(self, exc_id, active):
        self.db.execute('UPDATE exceptions SET active = ? WHERE id = ?', (1 if active else 0, exc_id))

    # ------------------------------------------------------------------ findings
    def finding(self, fid):
        row = self.db.execute('SELECT * FROM findings WHERE id = ?', (fid,)).fetchone()
        return decode(row) if row else None

    def upsert_finding(self, cand, now, status, exception_id, reoccur_s):
        """ :return: "new" | "update" | "reoccur" """
        old = self.db.execute('SELECT * FROM findings WHERE id = ?', (cand['id'],)).fetchone()
        factors = json.dumps(cand.get('factors') or [])
        evidence = json.dumps(cand.get('evidence') or {})
        params = json.dumps(cand.get('params') or {})
        ts = int(cand.get('ts') or now)
        if old is None:
            self.db.execute(
                'INSERT INTO findings (id, type, host, key, severity, score, status, title, detail, first_seen, '
                'last_seen, occurrences, factors, evidence, params, mac, hostname, exception_id, max_score) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)',
                (cand['id'], cand['type'], cand['host'], cand.get('key') or '', cand['severity'], cand['score'],
                 status, cand['title'], cand['detail'], ts, ts, factors, evidence, params, cand.get('mac'),
                 cand.get('hostname'), exception_id, cand['score']))
            self._occurrence(cand, ts, status, factors)
            return 'new'
        last_occ = self.db.execute('SELECT id, last_ts FROM occurrences WHERE finding_id = ? ORDER BY id DESC LIMIT 1',
                                   (cand['id'],)).fetchone()
        kind = 'update'
        if last_occ is None or ts - last_occ['last_ts'] > reoccur_s:
            self._occurrence(cand, ts, status, factors)
            kind = 'reoccur'
        else:
            self.db.execute('UPDATE occurrences SET last_ts = ?, score = max(score, ?), severity = ?, factors = ? '
                            'WHERE id = ?', (ts, cand['score'], cand['severity'], factors, last_occ['id']))
        new_status = status
        if old['status'] == 'resolved' and status == 'open':
            new_status = 'open'
        elif old['status'] == 'expected' and status == 'open' and old['exception_id']:
            new_status = 'open'
        self.db.execute(
            'UPDATE findings SET severity = ?, score = ?, status = ?, title = ?, detail = ?, last_seen = ?, '
            'occurrences = occurrences + ?, factors = ?, evidence = ?, params = ?, mac = coalesce(?, mac), '
            'hostname = coalesce(?, hostname), exception_id = ?, max_score = max(max_score, ?) WHERE id = ?',
            (cand['severity'], cand['score'], new_status, cand['title'], cand['detail'], max(ts, old['last_seen']),
             1 if kind == 'reoccur' else 0, factors, evidence, params, cand.get('mac'), cand.get('hostname'),
             exception_id, cand['score'], cand['id']))
        return kind

    def _occurrence(self, cand, ts, status, factors):
        self.db.execute('INSERT INTO occurrences (finding_id, ts, last_ts, severity, score, status, factors) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?)', (cand['id'], ts, ts, cand['severity'], cand['score'],
                                                         status, factors))

    def set_status(self, fid, status, exception_id=None):
        self.db.execute('UPDATE findings SET status = ?, exception_id = ? WHERE id = ?', (status, exception_id, fid))

    # ------------------------------------------------------------------ maintenance
    def prune(self, now, beacon_window_s):
        removed = {}
        for table, (column, keep) in RETENTION.items():
            cur = self.db.execute('DELETE FROM %s WHERE %s < ?' % (table, column), (int(now - keep),))
            removed[table] = cur.rowcount
        cur = self.db.execute('DELETE FROM pairs WHERE last_seen < ?', (int(now - beacon_window_s),))
        removed['pairs'] = cur.rowcount
        cur = self.db.execute('DELETE FROM vol_base WHERE updated < ?', (int(now - 180 * 86400),))
        removed['vol_base'] = cur.rowcount
        return removed


def decode(row):
    out = dict(row)
    for key in ('factors', 'evidence', 'params'):
        if out.get(key):
            try:
                out[key] = json.loads(out[key])
            except ValueError:
                out[key] = None
    return out
