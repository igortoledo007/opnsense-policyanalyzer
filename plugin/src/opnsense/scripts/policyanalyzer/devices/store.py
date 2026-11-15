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

    devices.db (SQLite, permanent history, no automatic cleanup). Times are epoch UTC.

      devices  one row per MAC address: first/last seen, current IPs, hostname (and its source), manufacturer,
               automatic type (+ confidence, why), the owner's type/name, the AI suggestion, known flag, risk
      ips      every address a device used (first/last seen)
      events   new, ip, hostname, vendor, known, unknown, type, name, ai  (old -> new)
      dns      reverse lookup cache of the local resolver
      meta     last scan, sources state
"""

import json
import os
import sqlite3

from . import common

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    mac TEXT NOT NULL UNIQUE,
    first_seen INTEGER, last_seen INTEGER,
    hostname TEXT, hostname_source TEXT,
    vendor TEXT, randomized INTEGER NOT NULL DEFAULT 0,
    iface TEXT, iface_descr TEXT,
    ip4 TEXT, ip6 TEXT,
    auto_type TEXT, auto_confidence TEXT, auto_why TEXT,
    user_type TEXT, user_name TEXT,
    ai_type TEXT, ai_text TEXT, ai_at INTEGER,
    known INTEGER NOT NULL DEFAULT 0, known_at INTEGER,
    risk TEXT, risk_reasons TEXT,
    present INTEGER NOT NULL DEFAULT 0,
    updated INTEGER
);
CREATE INDEX IF NOT EXISTS devices_last ON devices (last_seen);
CREATE TABLE IF NOT EXISTS ips (
    device_id INTEGER NOT NULL, ip TEXT NOT NULL, first_seen INTEGER, last_seen INTEGER,
    PRIMARY KEY (device_id, ip)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ips_ip ON ips (ip);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, device_id INTEGER NOT NULL, kind TEXT NOT NULL,
    old TEXT, new TEXT, note TEXT);
CREATE INDEX IF NOT EXISTS events_device ON events (device_id, ts);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS dns (ip TEXT PRIMARY KEY, name TEXT, resolved_at INTEGER) WITHOUT ROWID;
CREATE VIEW IF NOT EXISTS v_devices AS
    SELECT id, mac, COALESCE(user_name, hostname) AS name, COALESCE(user_type, auto_type) AS type, vendor,
           ip4, ip6, iface_descr AS interface, datetime(first_seen, 'unixepoch', 'localtime') AS first_seen,
           datetime(last_seen, 'unixepoch', 'localtime') AS last_seen, known, risk FROM devices;
"""

COLUMNS = ('id', 'mac', 'first_seen', 'last_seen', 'hostname', 'hostname_source', 'vendor', 'randomized', 'iface',
           'iface_descr', 'ip4', 'ip6', 'auto_type', 'auto_confidence', 'auto_why', 'user_type', 'user_name',
           'ai_type', 'ai_text', 'ai_at', 'known', 'known_at', 'risk', 'risk_reasons', 'present', 'updated')


def connect(path=None, readonly=False):
    path = path or common.paths()['devices_db']
    if readonly:
        if not os.path.exists(path):
            return None
        return sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=5)
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    fresh = not os.path.exists(path)
    db = sqlite3.connect(path, timeout=10)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript(SCHEMA)
    if fresh:
        for suffix in ('', '-wal', '-shm'):
            try:
                os.chmod(path + suffix, 0o640)
            except OSError:
                pass
    return db


def meta_get(db, key, default=None):
    row = db.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
    return row[0] if row else default


def meta_set(db, key, value):
    db.execute('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)', (key, str(value)))


def row_dict(row):
    rec = dict(zip(COLUMNS, row))
    for key in ('auto_why', 'risk_reasons'):
        try:
            rec[key] = json.loads(rec[key]) if rec[key] else []
        except ValueError:
            rec[key] = []
    rec['ip6'] = [x for x in (rec['ip6'] or '').split(',') if x]
    rec['ip4'] = [x for x in (rec['ip4'] or '').split(',') if x]
    rec['type'] = rec['user_type'] or rec['auto_type'] or 'unknown'
    rec['type_source'] = 'owner' if rec['user_type'] else 'heuristic'
    rec['name'] = rec['user_name'] or rec['hostname']
    rec['known'] = bool(rec['known'])
    rec['present'] = bool(rec['present'])
    rec['randomized'] = bool(rec['randomized'])
    return rec


def get(db, device_id):
    row = db.execute('SELECT %s FROM devices WHERE id = ?' % ', '.join(COLUMNS), (device_id,)).fetchone()
    return row_dict(row) if row else None


def all_devices(db):
    return [row_dict(r) for r in db.execute('SELECT %s FROM devices ORDER BY last_seen DESC' % ', '.join(COLUMNS))]


def event(db, ts, device_id, kind, old=None, new=None, note=None):
    db.execute('INSERT INTO events (ts, device_id, kind, old, new, note) VALUES (?, ?, ?, ?, ?, ?)',
               (ts, device_id, kind, None if old is None else str(old)[:200], None if new is None else str(new)[:200],
                note))


def history(db, device_id, limit=100):
    rows = db.execute('SELECT ts, kind, old, new, note FROM events WHERE device_id = ? ORDER BY ts DESC, id DESC '
                      'LIMIT ?', (device_id, limit)).fetchall()
    return [{'ts': common.iso(r[0]), 'kind': r[1], 'old': r[2], 'new': r[3], 'note': r[4]} for r in rows]


def addresses(db, device_id):
    rows = db.execute('SELECT ip, first_seen, last_seen FROM ips WHERE device_id = ? ORDER BY last_seen DESC',
                      (device_id,)).fetchall()
    return [{'ip': r[0], 'first_seen': common.iso(r[1]) if r[1] else None,
             'last_seen': common.iso(r[2]) if r[2] else None} for r in rows]
