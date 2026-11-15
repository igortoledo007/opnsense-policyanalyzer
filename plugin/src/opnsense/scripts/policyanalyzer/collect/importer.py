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

    One-time import of the history collected by the old remote scripts (opn.py on a LAN computer), from an
    export made by scripts/export-collect.py and copied to /var/db/policyanalyzer/collect/import/.

        import <file> plan      what would be imported / skipped (nothing is written)
        import <file> apply     import (rows get origin "import:<id>")
        import_undo <id>        delete every row of that import

    Formats: SQLite (tables below) or JSON {"meta": {...}, "tables": {name: [row dicts]}} (optionally .gz;
    "xml" as base64 of zlib).  meta.format must be "pa-collect-export", meta.version 1.

        config_snapshots (id, revision_time, revision_user, revision_descr, hostname, version, sha256, xml)
        config_changes   (occurred_at, author, section, key, kind, item_descr, snapshot_before,
                          snapshot_after, reason)
        health_metrics   (ts, key, value)               opn.py keys, mapped by HEALTH_KEYS
        health_events    (ts, kind, source, text)
        health_hosts     (mac, ip, name, vendor, iface, first_seen, last_seen)
        flow_blocks      (hour, iface, dir, action, proto, src, dst, dport, rid, n)
        dns_daily        (day, client, domain, action, n)

    No overlap: each part only brings what is older than the first local data of that collector
    (flows.blocks_since, flows.dns_since -> whole days before it, health.local_since, the oldest local
    config revision); a part whose collector never ran is skipped (run the schedule first).  The XML of
    imported snapshots is sanitized again with the local key (values already REDACTED stay as they are).
"""

import base64
import gzip
import hashlib
import json
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
import zlib

from . import common, sanitize, store

FORMAT = 'pa-collect-export'
MAX_SIZE = 4 * 1024 * 1024 * 1024
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
ID_RE = re.compile(r'^imp\d{8}T\d{6}$')
TABLES = ('config_snapshots', 'config_changes', 'health_metrics', 'health_events', 'health_hosts',
          'flow_blocks', 'dns_daily')

# opn.py metric keys -> collector keys (anything else keeps its name)
HEALTH_KEYS = {
    'cpu_ocioso': 'cpu_idle_pct', 'mem_usada_mb': 'mem_used_mb', 'mem_total_mb': 'mem_total_mb',
    'zfs_arc_mb': 'zfs_arc_mb', 'pf_estados': 'pf_states', 'temp_cpu': 'temp_cpu', 'carga_1min': 'load_1m',
    'netisr_drops': 'netisr_drops', 'servicos_parados': 'services_stopped', 'hosts_arp': 'hosts_arp',
}
EVENT_KINDS = {'servico_parado': 'service_stopped', 'gateway': 'gateway'}
CHANGE_KINDS = {'adicionado': 'added', 'removido': 'removed', 'alterado': 'changed', 'outro': 'changed',
                'added': 'added', 'removed': 'removed', 'changed': 'changed'}


def map_health_key(key):
    if key in HEALTH_KEYS:
        return HEALTH_KEYS[key]
    if key.startswith('if:') and key.endswith(':erros'):
        return key[:-len(':erros')] + ':errors'
    return key


def _epoch(value):
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value)
    if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}$', text):          # opn.py hour keys "2026-10-17T12" (UTC)
        text += ':00:00Z'
    try:
        return common.parse_time(text)
    except ValueError:
        return None


# ------------------------------------------------------------------ reading the export


def resolve(ctx, name):
    if not NAME_RE.match(name or '') or '..' in name:
        raise ValueError('file name: letters, digits, ".", "_" and "-" only (no directories)')
    path = os.path.join(ctx.import_dir, name)
    if os.path.dirname(os.path.realpath(path)) != os.path.realpath(ctx.import_dir):
        raise ValueError('the file must be inside %s' % ctx.import_dir)
    if not os.path.isfile(path):
        raise ValueError('%s not found (copy the export to %s/)' % (name, ctx.import_dir))
    if os.path.getsize(path) > MAX_SIZE:
        raise ValueError('file larger than 4 GiB')
    return path


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


class Export:
    """ uniform access to an export file: .meta and .rows(table) -> iterator of dicts """

    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as handle:
            head = handle.read(16)
        self._db = None
        self._json = None
        if head.startswith(b'SQLite format 3\x00'):
            self._db = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
            self._db.row_factory = sqlite3.Row
            try:
                self.meta = dict(self._db.execute('SELECT key, value FROM meta').fetchall())
            except sqlite3.Error:
                raise ValueError('SQLite file without the meta table of an export') from None
        else:
            opener = gzip.open if head[:2] == b'\x1f\x8b' else open
            try:
                with opener(path, 'rt', encoding='utf-8') as handle:
                    self._json = json.load(handle)
            except (OSError, ValueError, EOFError) as exc:
                raise ValueError('not a SQLite or JSON export: %s' % exc) from None
            if not isinstance(self._json, dict):
                raise ValueError('JSON export must be an object')
            self.meta = {k: str(v) for k, v in (self._json.get('meta') or {}).items()}
        if self.meta.get('format') != FORMAT or str(self.meta.get('version')) != '1':
            raise ValueError('not a %s version 1 file' % FORMAT)

    def rows(self, table):
        if self._db is not None:
            try:
                for row in self._db.execute('SELECT * FROM %s' % table):
                    yield dict(row)
            except sqlite3.OperationalError:
                return
        else:
            for row in (self._json.get('tables') or {}).get(table) or []:
                if isinstance(row, dict):
                    if table == 'config_snapshots' and isinstance(row.get('xml'), str):
                        row = dict(row, xml=base64.b64decode(row['xml']))
                    yield row

    def count(self, table):
        if self._db is not None:
            try:
                return self._db.execute('SELECT count(*) FROM %s' % table).fetchone()[0]
            except sqlite3.OperationalError:
                return 0
        return len((self._json.get('tables') or {}).get(table) or [])

    def close(self):
        if self._db is not None:
            self._db.close()


# ------------------------------------------------------------------ cut points


def cutoffs(ctx):
    """ first local data per part (None = the collector never ran: that part is skipped) """
    out = {'blocks': None, 'dns_day': None, 'health': None, 'config': None}
    con = common.connect_ro(ctx.db['flows'])
    if con is not None:
        out['blocks'] = common.meta_get(con, 'blocks_since')
        dns = common.meta_get(con, 'dns_since')
        if dns is not None:
            # whole days only: the first local day may be partial on the import side
            out['dns_day'] = common.day_of(dns) if dns == common.local_midnight(dns) else \
                common.day_of(dns + 86400)
            out['dns_local_first_day'] = common.day_of(dns)
        con.close()
    con = common.connect_ro(ctx.db['health'])
    if con is not None:
        out['health'] = common.meta_get(con, 'local_since')
        con.close()
    con = common.connect_ro(ctx.db['config'])
    if con is not None:
        r = con.execute("SELECT min(revision_time) FROM snapshots WHERE origin NOT LIKE 'import:%'").fetchone()
        out['config'] = r[0] if r else None
        con.close()
    return out


def _ifmap(ctx):
    """ interface description (opn.py stored the Live View "interface_name") -> device """
    result = {}
    for dev, info in common.interfaces(common.load_config(ctx)).items():
        result[info['descr'].lower()] = dev
        result[info['key'].lower()] = dev
        result[dev.lower()] = dev
    return result


# ------------------------------------------------------------------ plan / apply


def _parts(exp, cut):
    """ per part: rows to import / skipped, with the reason """
    parts = {}

    def add(part, keep, total, reason):
        parts[part] = {'rows': keep, 'skipped': total - keep, 'reason': reason}

    if cut['blocks'] is None:
        add('flow_blocks', 0, exp.count('flow_blocks'), 'flows collector never ran (no local start point)')
    else:
        keep = sum(1 for r in exp.rows('flow_blocks') if (_epoch(r.get('hour')) or 0) < cut['blocks'])
        add('flow_blocks', keep, exp.count('flow_blocks'), 'only hours before %s' % common.iso(cut['blocks']))
    if cut['dns_day'] is None:
        add('dns_daily', 0, exp.count('dns_daily'), 'flows collector has no DNS start point yet')
    else:
        keep = sum(1 for r in exp.rows('dns_daily') if str(r.get('day') or '') < cut['dns_day'])
        add('dns_daily', keep, exp.count('dns_daily'), 'only days before %s' % cut['dns_day'])
    for table in ('health_metrics', 'health_events'):
        if cut['health'] is None:
            add(table, 0, exp.count(table), 'health collector never ran')
        else:
            keep = sum(1 for r in exp.rows(table) if (_epoch(r.get('ts')) or 0) < cut['health'])
            add(table, keep, exp.count(table), 'only before %s' % common.iso(cut['health']))
    add('health_hosts', exp.count('health_hosts') if cut['health'] is not None else 0, exp.count('health_hosts'),
        'hosts not seen locally (local rows win)' if cut['health'] is not None else 'health collector never ran')
    if cut['config'] is None:
        add('config_snapshots', 0, exp.count('config_snapshots'), 'config collector never ran')
        add('config_changes', 0, exp.count('config_changes'), 'config collector never ran')
    else:
        snaps = {r.get('id') for r in exp.rows('config_snapshots') if (_epoch(r.get('revision_time')) or 0) < cut['config']}
        add('config_snapshots', len(snaps), exp.count('config_snapshots'),
            'only revisions before the oldest local one (%s)' % common.iso(cut['config']))
        keep = sum(1 for r in exp.rows('config_changes') if r.get('snapshot_after') in snaps)
        add('config_changes', keep, exp.count('config_changes'), 'changes of the imported revisions')
    return parts


def plan(ctx, name):
    path = resolve(ctx, name)
    sha = _sha256(path)
    exp = Export(path)
    try:
        cut = cutoffs(ctx)
        parts = _parts(exp, cut)
    finally:
        exp.close()
    warnings = []
    done = _already(ctx, sha)
    if done:
        warnings.append('this file was already imported as %s' % done)
    for part, info in parts.items():
        if info['rows'] == 0 and info['skipped']:
            warnings.append('%s: nothing to import (%s)' % (part, info['reason']))
    return {'status': 'ok', 'file': name, 'sha256': sha, 'meta': exp.meta, 'cutoffs': {
        k: (common.iso(v) if isinstance(v, (int, float)) else v) for k, v in cut.items()},
        'parts': parts, 'warnings': warnings, 'can_apply': not done and any(p['rows'] for p in parts.values())}


def _already(ctx, sha):
    for kind in common.KINDS:
        con = common.connect_ro(ctx.db[kind])
        if con is None:
            continue
        try:
            row = con.execute('SELECT id FROM imports WHERE sha256 = ? AND undone_at IS NULL', (sha,)).fetchone()
        except sqlite3.Error:
            row = None
        con.close()
        if row:
            return row[0]
    return None


def apply(ctx, name, settings):
    info = plan(ctx, name)
    if not info['can_apply']:
        return dict(info, status='error', message='; '.join(info['warnings']) or 'nothing to import')
    path = resolve(ctx, name)
    import_id = time.strftime('imp%Y%m%dT%H%M%S')
    origin = 'import:%s' % import_id
    cut = cutoffs(ctx)
    exp = Export(path)
    counts = {}
    now = ctx.clock()
    try:
        # ---- flows
        con = store.open_db(ctx, 'flows')
        ifmap = _ifmap(ctx)
        with con:
            n = 0
            for r in exp.rows('flow_blocks'):
                hour = _epoch(r.get('hour'))
                if hour is None or hour >= cut['blocks']:
                    continue
                iface = str(r.get('iface') or '')
                con.execute("""
                    INSERT INTO blocks_hourly (hour, iface, dir, action, proto, src, dst, dport, rid, n, origin)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT (hour, iface, dir, action, proto, src, dst, dport, rid, origin)
                    DO UPDATE SET n = n + excluded.n""", (
                    common.hour_of(hour), ifmap.get(iface.lower(), iface), str(r.get('dir') or ''),
                    str(r.get('action') or 'block').lower(), str(r.get('proto') or '').lower(),
                    str(r.get('src') or ''), str(r.get('dst') or ''), str(r.get('dport') or ''),
                    str(r.get('rid') or ''), int(r.get('n') or 1), origin))
                n += 1
            counts['flow_blocks'] = n
            n = 0
            for r in exp.rows('dns_daily') if cut['dns_day'] else []:
                day = str(r.get('day') or '')
                if not re.match(r'^\d{4}-\d{2}-\d{2}$', day) or day >= cut['dns_day']:
                    continue
                action = str(r.get('action') or 'pass').lower()
                con.execute("""
                    INSERT INTO dns_daily (day, client, domain, action, n, nx, origin) VALUES (?,?,?,?,?,0,?)
                    ON CONFLICT (day, client, domain, action, origin) DO UPDATE SET n = n + excluded.n""", (
                    day, str(r.get('client') or ''), str(r.get('domain') or '').rstrip('.').lower(),
                    action, int(r.get('n') or 1), origin))
                n += 1
            counts['dns_daily'] = n
            _record(con, import_id, name, info['sha256'], counts, now, ('flow_blocks', 'dns_daily'))
        store.maintain(ctx, 'flows', con, settings, now, force=True)
        con.close()
        # ---- health
        if cut['health'] is not None:
            con = store.open_db(ctx, 'health')
            with con:
                n = 0
                for r in exp.rows('health_metrics'):
                    ts = _epoch(r.get('ts'))
                    if ts is None or ts >= cut['health'] or r.get('value') is None:
                        continue
                    con.execute('INSERT OR IGNORE INTO metrics (ts, key, value, origin) VALUES (?,?,?,?)',
                                (int(ts), map_health_key(str(r.get('key'))), float(r['value']), origin))
                    n += 1
                counts['health_metrics'] = n
                n = 0
                for r in exp.rows('health_events'):
                    ts = _epoch(r.get('ts'))
                    if ts is None or ts >= cut['health']:
                        continue
                    con.execute('INSERT OR IGNORE INTO events (ts, kind, source, text, origin) VALUES (?,?,?,?,?)',
                                (ts, EVENT_KINDS.get(r.get('kind'), str(r.get('kind'))), r.get('source'),
                                 str(r.get('text') or '')[:300], origin))
                    n += 1
                counts['health_events'] = n
                n = 0
                for r in exp.rows('health_hosts'):
                    if not r.get('mac'):
                        continue
                    n += con.execute('INSERT OR IGNORE INTO hosts (mac, ip, name, vendor, iface, first_seen, last_seen,'
                                     ' origin) VALUES (?,?,?,?,?,?,?,?)', (
                                         str(r['mac']).lower(), r.get('ip'), r.get('name'), r.get('vendor'),
                                         r.get('iface'), _epoch(r.get('first_seen')), _epoch(r.get('last_seen')),
                                         origin)).rowcount
                counts['health_hosts'] = n
                _record(con, import_id, name, info['sha256'], counts, now,
                        ('health_metrics', 'health_events', 'health_hosts'))
            store.maintain(ctx, 'health', con, settings, now, force=True)
            con.close()
        # ---- config
        if cut['config'] is not None:
            con = store.open_db(ctx, 'config')
            key = sanitize.hmac_key(ctx.hmac_key)
            ids = {}
            with con:
                for r in exp.rows('config_snapshots'):
                    rt = _epoch(r.get('revision_time'))
                    if rt is None or rt >= cut['config']:
                        continue
                    if con.execute("SELECT 1 FROM snapshots WHERE revision_time = ? AND coalesce(revision_descr, '')"
                                   ' = ?', (rt, r.get('revision_descr') or '')).fetchone():
                        continue
                    blob = r.get('xml')
                    masked = None
                    if blob:
                        try:
                            raw = zlib.decompress(blob) if blob[:1] == b'x' else bytes(blob)
                            root, masked = sanitize.sanitize(ET.fromstring(raw), key)
                            blob = zlib.compress(ET.tostring(root, encoding='utf-8'), 9)
                        except (zlib.error, ET.ParseError, TypeError):
                            blob, masked = None, None
                    author, author_ip = _split(r.get('revision_user'))
                    cur = con.execute(
                        'INSERT INTO snapshots (collected_at, origin, source_file, sha256, revision_time, revision_user,'
                        ' author, author_ip, revision_descr, hostname, version, masked, xml) '
                        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', (
                            now, origin, 'export:%s' % r.get('id'), '%s:%s' % (origin, r.get('sha256') or r.get('id')),
                            rt, r.get('revision_user'), author, author_ip, r.get('revision_descr'), r.get('hostname'),
                            r.get('version'), masked, blob))
                    ids[r.get('id')] = cur.lastrowid
                counts['config_snapshots'] = len(ids)
                n = 0
                for r in exp.rows('config_changes'):
                    after = ids.get(r.get('snapshot_after'))
                    if after is None:
                        continue
                    fields = [{'field': 'reason', 'old': None, 'new': str(r['reason'])[:300]}] if r.get('reason') else []
                    author, author_ip = _split(r.get('author'))
                    con.execute(
                        'INSERT INTO changes (occurred_at, author, author_ip, section, key, kind, item_descr, fields,'
                        ' snapshot_before, snapshot_after, origin) VALUES (?,?,?,?,?,?,?,?,?,?,?)', (
                            _epoch(r.get('occurred_at')), author, author_ip, str(r.get('section') or '?'),
                            r.get('key'), CHANGE_KINDS.get(str(r.get('kind')), 'changed'), r.get('item_descr'),
                            json.dumps(fields), ids.get(r.get('snapshot_before')), after, origin))
                    n += 1
                counts['config_changes'] = n
                _record(con, import_id, name, info['sha256'], counts, now, ('config_snapshots', 'config_changes'))
            con.close()
    finally:
        exp.close()
    return {'status': 'ok', 'id': import_id, 'file': name, 'counts': counts, 'parts': info['parts'],
            'undo': 'configctl pa_collect import_undo %s' % import_id}


def _split(user):
    from .config import split_user
    return split_user(user)


def _record(con, import_id, name, sha, counts, now, parts):
    mine = {k: counts.get(k, 0) for k in parts}
    con.execute('INSERT OR REPLACE INTO imports (id, file, sha256, imported_at, counts) VALUES (?,?,?,?,?)',
                (import_id, name, sha, now, json.dumps(mine)))


def undo(ctx, import_id):
    if not ID_RE.match(import_id or ''):
        raise ValueError('invalid import id')
    origin = 'import:%s' % import_id
    removed = {}
    tables = {'flows': ('blocks_hourly', 'blocks_daily', 'dns_hourly', 'dns_daily'),
              'health': ('metrics', 'metrics_daily', 'events', 'hosts'),
              'config': ('changes', 'snapshots')}
    found = False
    for kind, names in tables.items():
        if not os.path.exists(ctx.db[kind]):
            continue
        con = store.open_db(ctx, kind)
        with con:
            row = con.execute('SELECT undone_at FROM imports WHERE id = ?', (import_id,)).fetchone()
            if row is None:
                con.close()
                continue
            found = True
            for table in names:
                removed['%s.%s' % (kind, table)] = con.execute('DELETE FROM %s WHERE origin = ?' % table,
                                                               (origin,)).rowcount
            con.execute('UPDATE imports SET undone_at = ? WHERE id = ?', (ctx.clock(), import_id))
        con.close()
    if not found:
        raise ValueError('import %s not found' % import_id)
    return {'status': 'ok', 'id': import_id, 'removed': removed}
