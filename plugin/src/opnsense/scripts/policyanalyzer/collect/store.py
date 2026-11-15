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

    SQLite schemas of the collectors and the retention / compaction / size limit.

    Times: "hour" and "ts" are epoch UTC (INTEGER/REAL); "day" is the local calendar day AAAA-MM-DD.
    "origin" is "local" for what the firewall collected and "import:<id>" for imported history (the import
    only brings buckets older than the first local one, so the two never overlap).
"""

import os
import time

from . import common

CONFIG_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS snapshots (
    id                INTEGER PRIMARY KEY,
    collected_at      REAL NOT NULL,
    origin            TEXT NOT NULL DEFAULT 'local',   -- local | backup | current | import:<id>
    source_file       TEXT,                            -- config-1792976146.6525.xml / config.xml
    sha256            TEXT NOT NULL UNIQUE,            -- of the sanitized XML
    revision_time     REAL,                            -- <revision><time>
    revision_user     TEXT,                            -- <revision><username>, e.g. "root@192.0.2.10"
    author            TEXT,                            -- user part
    author_ip         TEXT,                            -- address part (GUI/API sessions)
    revision_descr    TEXT,                            -- <revision><description>
    hostname          TEXT,
    version           TEXT,
    size              INTEGER,
    masked            INTEGER,                         -- secrets masked in this snapshot
    xml               BLOB                             -- zlib of the sanitized XML (NULL: dropped by size limit)
);
CREATE INDEX IF NOT EXISTS ix_snapshots_rev ON snapshots(revision_time);
CREATE TABLE IF NOT EXISTS blobs (sha256 TEXT PRIMARY KEY, content TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS items (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    section     TEXT NOT NULL,
    key         TEXT NOT NULL,
    descr       TEXT,
    sha256      TEXT NOT NULL,                         -- -> blobs
    PRIMARY KEY (snapshot_id, section, key)
);
CREATE TABLE IF NOT EXISTS changes (
    id              INTEGER PRIMARY KEY,
    occurred_at     REAL,                              -- revision time of the snapshot after
    author          TEXT,
    author_ip       TEXT,
    revision_descr  TEXT,
    section         TEXT NOT NULL,
    key             TEXT,
    kind            TEXT NOT NULL CHECK (kind IN ('added', 'removed', 'changed')),
    item_descr      TEXT,
    fields          TEXT,                              -- JSON [{"field", "old", "new"}] (sanitized)
    snapshot_before INTEGER,
    snapshot_after  INTEGER,
    origin          TEXT NOT NULL DEFAULT 'local'
);
CREATE INDEX IF NOT EXISTS ix_changes_time ON changes(occurred_at);
CREATE INDEX IF NOT EXISTS ix_changes_section ON changes(section, key);
CREATE TABLE IF NOT EXISTS seen_files (name TEXT PRIMARY KEY, size INTEGER, mtime REAL, sha256 TEXT);
CREATE TABLE IF NOT EXISTS imports (id TEXT PRIMARY KEY, file TEXT, sha256 TEXT UNIQUE, imported_at REAL,
                                    counts TEXT, undone_at REAL);
"""

HEALTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS metrics (
    ts     INTEGER NOT NULL,                           -- sample time (one sample per hourly run)
    key    TEXT NOT NULL,                              -- cpu_idle_pct, gw:WAN_B:rtt_ms, if:igc0:rx_bps ...
    value  REAL,
    origin TEXT NOT NULL DEFAULT 'local',
    PRIMARY KEY (ts, key)
);
CREATE INDEX IF NOT EXISTS ix_metrics_key ON metrics(key, ts);
CREATE TABLE IF NOT EXISTS metrics_daily (
    day    TEXT NOT NULL, key TEXT NOT NULL, avg REAL, min REAL, max REAL, last REAL, n INTEGER,
    origin TEXT NOT NULL DEFAULT 'local',
    PRIMARY KEY (day, key)
);
CREATE INDEX IF NOT EXISTS ix_metrics_daily_key ON metrics_daily(key, day);
CREATE TABLE IF NOT EXISTS events (
    ts     REAL NOT NULL,
    kind   TEXT NOT NULL,                              -- gateway | service_stopped | reboot
    source TEXT,
    text   TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'local',
    PRIMARY KEY (ts, kind, text)
);
CREATE TABLE IF NOT EXISTS hosts (
    mac TEXT PRIMARY KEY, ip TEXT, name TEXT, vendor TEXT, iface TEXT, first_seen REAL, last_seen REAL,
    origin TEXT NOT NULL DEFAULT 'local'
);
CREATE TABLE IF NOT EXISTS imports (id TEXT PRIMARY KEY, file TEXT, sha256 TEXT UNIQUE, imported_at REAL,
                                    counts TEXT, undone_at REAL);
"""

FLOWS_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS blocks_hourly (
    hour INTEGER NOT NULL, iface TEXT NOT NULL, dir TEXT NOT NULL, action TEXT NOT NULL, proto TEXT NOT NULL,
    src TEXT NOT NULL, dst TEXT NOT NULL, dport TEXT NOT NULL, rid TEXT NOT NULL,
    cc TEXT,                                           -- country of src (quarantine GeoIP index), NULL unknown
    n INTEGER NOT NULL, first REAL, last REAL,
    origin TEXT NOT NULL DEFAULT 'local',
    PRIMARY KEY (hour, iface, dir, action, proto, src, dst, dport, rid, origin)
);
CREATE INDEX IF NOT EXISTS ix_blocks_hourly_src ON blocks_hourly(src, hour);
CREATE TABLE IF NOT EXISTS blocks_daily (
    day TEXT NOT NULL, iface TEXT NOT NULL, dir TEXT NOT NULL, action TEXT NOT NULL, proto TEXT NOT NULL,
    src TEXT NOT NULL, dst TEXT NOT NULL, dport TEXT NOT NULL, rid TEXT NOT NULL, cc TEXT,
    n INTEGER NOT NULL, origin TEXT NOT NULL DEFAULT 'local',
    PRIMARY KEY (day, iface, dir, action, proto, src, dst, dport, rid, origin)
);
CREATE INDEX IF NOT EXISTS ix_blocks_daily_src ON blocks_daily(src, day);
CREATE TABLE IF NOT EXISTS dns_hourly (
    hour INTEGER NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL, action TEXT NOT NULL,   -- pass|block|drop
    n INTEGER NOT NULL, nx INTEGER NOT NULL DEFAULT 0,
    origin TEXT NOT NULL DEFAULT 'local',
    PRIMARY KEY (hour, client, domain, action, origin)
);
CREATE INDEX IF NOT EXISTS ix_dns_hourly_domain ON dns_hourly(domain, hour);
CREATE TABLE IF NOT EXISTS dns_daily (
    day TEXT NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL, action TEXT NOT NULL,
    n INTEGER NOT NULL, nx INTEGER NOT NULL DEFAULT 0, origin TEXT NOT NULL DEFAULT 'local',
    PRIMARY KEY (day, client, domain, action, origin)
);
CREATE INDEX IF NOT EXISTS ix_dns_daily_domain ON dns_daily(domain, day);
CREATE TABLE IF NOT EXISTS runs (                      -- one row per run: totals for the series and the audit
    ts REAL PRIMARY KEY, blocks INTEGER, dns INTEGER, filter_lines INTEGER, filter_bytes INTEGER,
    dns_source TEXT, complete INTEGER, seconds REAL
);
CREATE TABLE IF NOT EXISTS imports (id TEXT PRIMARY KEY, file TEXT, sha256 TEXT UNIQUE, imported_at REAL,
                                    counts TEXT, undone_at REAL);
"""

SCHEMAS = {'config': CONFIG_SCHEMA, 'health': HEALTH_SCHEMA, 'flows': FLOWS_SCHEMA}


def open_db(ctx, kind):
    ctx.ensure_dirs()
    return common.connect(ctx.db[kind], SCHEMAS[kind])


# ------------------------------------------------------------------ retention


def _days_before(now, days):
    return common.day_of(now - days * 86400)


def compact_flows(con, now, settings):
    """ fold hourly rows older than compact_after_days into daily rows (local day) """
    cut = common.local_midnight(now - settings['compact_after_days'] * 86400)
    moved = {}
    con.execute("""
        INSERT INTO blocks_daily (day, iface, dir, action, proto, src, dst, dport, rid, cc, n, origin)
        SELECT date(hour, 'unixepoch', 'localtime'), iface, dir, action, proto, src, dst, dport, rid, max(cc),
               sum(n), origin
          FROM blocks_hourly WHERE hour < ?
         GROUP BY 1, iface, dir, action, proto, src, dst, dport, rid, origin
        ON CONFLICT (day, iface, dir, action, proto, src, dst, dport, rid, origin)
        DO UPDATE SET n = n + excluded.n, cc = coalesce(blocks_daily.cc, excluded.cc)""", (cut,))
    moved['blocks'] = con.execute('DELETE FROM blocks_hourly WHERE hour < ?', (cut,)).rowcount
    con.execute("""
        INSERT INTO dns_daily (day, client, domain, action, n, nx, origin)
        SELECT date(hour, 'unixepoch', 'localtime'), client, domain, action, sum(n), sum(nx), origin
          FROM dns_hourly WHERE hour < ?
         GROUP BY 1, client, domain, action, origin
        ON CONFLICT (day, client, domain, action, origin)
        DO UPDATE SET n = n + excluded.n, nx = nx + excluded.nx""", (cut,))
    moved['dns'] = con.execute('DELETE FROM dns_hourly WHERE hour < ?', (cut,)).rowcount
    return moved


def compact_health(con, now, settings):
    cut = int(common.local_midnight(now - settings['compact_after_days'] * 86400))
    con.execute("""
        INSERT INTO metrics_daily (day, key, avg, min, max, last, n, origin)
        SELECT date(ts, 'unixepoch', 'localtime') AS d, key, avg(value), min(value), max(value),
               (SELECT m2.value FROM metrics m2 WHERE m2.key = m.key
                   AND date(m2.ts, 'unixepoch', 'localtime') = date(m.ts, 'unixepoch', 'localtime')
                 ORDER BY m2.ts DESC LIMIT 1),
               count(*), max(origin)
          FROM metrics m WHERE ts < ? GROUP BY d, key
        ON CONFLICT (day, key) DO UPDATE SET
            avg = (avg * n + excluded.avg * excluded.n) / (n + excluded.n),
            min = min(min, excluded.min), max = max(max, excluded.max), last = excluded.last,
            n = n + excluded.n""", (cut,))
    return {'metrics': con.execute('DELETE FROM metrics WHERE ts < ?', (cut,)).rowcount}


def prune(con, kind, now, settings):
    """ delete what is older than the retention """
    out = {}
    if kind == 'flows':
        days = settings['retention_days']
        cut = now - days * 86400
        out['blocks_daily'] = con.execute('DELETE FROM blocks_daily WHERE day < ?', (_days_before(now, days),)).rowcount
        out['dns_daily'] = con.execute('DELETE FROM dns_daily WHERE day < ?', (_days_before(now, days),)).rowcount
        out['blocks_hourly'] = con.execute('DELETE FROM blocks_hourly WHERE hour < ?', (cut,)).rowcount
        out['dns_hourly'] = con.execute('DELETE FROM dns_hourly WHERE hour < ?', (cut,)).rowcount
        out['runs'] = con.execute('DELETE FROM runs WHERE ts < ?', (cut,)).rowcount
    elif kind == 'health':
        days = settings['retention_days']
        cut = now - days * 86400
        out['metrics'] = con.execute('DELETE FROM metrics WHERE ts < ?', (cut,)).rowcount
        out['metrics_daily'] = con.execute('DELETE FROM metrics_daily WHERE day < ?',
                                           (_days_before(now, days),)).rowcount
        out['events'] = con.execute('DELETE FROM events WHERE ts < ?', (cut,)).rowcount
        out['hosts'] = con.execute('DELETE FROM hosts WHERE last_seen < ?', (cut,)).rowcount
    elif kind == 'config' and settings['config_retention_days']:
        cut = now - settings['config_retention_days'] * 86400
        out['changes'] = con.execute('DELETE FROM changes WHERE occurred_at < ?', (cut,)).rowcount
        keep = con.execute('SELECT max(id) FROM snapshots').fetchone()[0] or 0
        out['snapshots'] = con.execute('DELETE FROM snapshots WHERE revision_time < ? AND id <> ?',
                                       (cut, keep)).rowcount
        _drop_orphan_blobs(con)
    return out


def _drop_orphan_blobs(con):
    return con.execute('DELETE FROM blobs WHERE sha256 NOT IN (SELECT DISTINCT sha256 FROM items)').rowcount


def _oldest_day(con, kind):
    if kind == 'flows':
        rows = [con.execute('SELECT min(day) FROM blocks_daily').fetchone()[0],
                con.execute('SELECT min(day) FROM dns_daily').fetchone()[0]]
        hourly = [con.execute('SELECT min(hour) FROM blocks_hourly').fetchone()[0],
                  con.execute('SELECT min(hour) FROM dns_hourly').fetchone()[0]]
    else:
        rows = [con.execute('SELECT min(day) FROM metrics_daily').fetchone()[0]]
        hourly = [con.execute('SELECT min(ts) FROM metrics').fetchone()[0]]
    days = [d for d in rows if d] + [common.day_of(h) for h in hourly if h]
    return min(days) if days else None


def enforce_size(con, kind, path, settings, now):
    """ drop the oldest day (flows/health) or the oldest XML blobs (config) until the file fits """
    limit = settings['max_mb_%s' % kind]
    dropped = []
    for _ in range(400):
        con.commit()
        con.execute('PRAGMA incremental_vacuum').fetchall()     # one page per step: fetch them all
        con.commit()
        con.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
        if common.db_size_mb(path) <= limit:
            break
        if kind == 'config':
            ids = [r[0] for r in con.execute(
                'SELECT id FROM snapshots WHERE xml IS NOT NULL ORDER BY revision_time LIMIT 20').fetchall()]
            if not ids or len(ids) <= 1:
                break
            con.execute('UPDATE snapshots SET xml = NULL WHERE id IN (%s)' % ','.join('?' * len(ids)), ids)
            dropped.append('xml of %d snapshots' % len(ids))
            continue
        day = _oldest_day(con, kind)
        if day is None or day >= common.day_of(now):
            break                       # never drop today
        start = common.day_start(day)
        end = start + 86400 + 7200      # DST safe: everything of that local day
        if kind == 'flows':
            con.execute('DELETE FROM blocks_daily WHERE day = ?', (day,))
            con.execute('DELETE FROM dns_daily WHERE day = ?', (day,))
            con.execute("DELETE FROM blocks_hourly WHERE date(hour, 'unixepoch', 'localtime') = ? AND hour < ?",
                        (day, end))
            con.execute("DELETE FROM dns_hourly WHERE date(hour, 'unixepoch', 'localtime') = ? AND hour < ?",
                        (day, end))
        else:
            con.execute('DELETE FROM metrics_daily WHERE day = ?', (day,))
            con.execute("DELETE FROM metrics WHERE date(ts, 'unixepoch', 'localtime') = ?", (day,))
            con.execute("DELETE FROM events WHERE date(ts, 'unixepoch', 'localtime') = ?", (day,))
        dropped.append(day)
    con.commit()
    return dropped


def maintain(ctx, kind, con, settings, now, force=False):
    """ once per local day (or forced): compaction, retention and size limit """
    today = common.day_of(now)
    if not force and common.meta_get(con, 'maintenance_day') == today:
        return None
    started = time.monotonic()
    out = {'compacted': {}, 'pruned': {}, 'size_dropped': []}
    if kind == 'flows':
        out['compacted'] = compact_flows(con, now, settings)
    elif kind == 'health':
        out['compacted'] = compact_health(con, now, settings)
    out['pruned'] = prune(con, kind, now, settings)
    common.meta_set(con, 'maintenance_day', today)
    con.commit()
    out['size_dropped'] = enforce_size(con, kind, ctx.db[kind], settings, now)
    out['size_mb'] = common.db_size_mb(ctx.db[kind])
    out['seconds'] = round(time.monotonic() - started, 2)
    common.meta_set(con, 'last_maintenance', dict(out, ts=now))
    con.commit()
    return out


def file_mode(path):
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass
