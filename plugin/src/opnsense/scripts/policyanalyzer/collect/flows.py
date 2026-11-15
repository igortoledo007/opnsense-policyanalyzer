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

    Flows collector (port of "opn.py fluxos"), every 5 minutes, incremental, in flows.db:

      blocks  /var/log/filter/latest.log (daily filter_YYYYMMDD.log) read forward from the marker
              {dev, ino, offset} (the incremental reader of the quarantine: rotation found by the inode, only
              complete lines, truncated file restarts at 0); block/reject lines aggregated per hour by
              interface, direction, action, protocol, source, destination, destination port and rule (rid),
              with the source country from the quarantine GeoIP index when present.  First run: the whole
              current daily file (since local midnight).
      DNS     Unbound: /var/unbound/data/unbound.duckdb table "query" (what Reporting > Unbound DNS and the
              opn.py API call read), through the core DbConnection (read only, same flock as the GUI); cursor
              = last complete second, staying DNS_LAG s behind the logger.  First run: since local midnight.
              Without the DuckDB (statistics off): the resolver log (log-queries / log-local-actions lines).
              dnsmasq: /var/log/dnsmasq/latest.log "query[...] ... from ..." lines (needs log_queries).
              Aggregated per hour by client, domain (no trailing dot) and action (pass | block | drop),
              with the NXDOMAIN count.

    The aggregates and the markers are committed in the same transaction: nothing is lost or counted twice.
"""

import collections
import glob
import ipaddress
import os
import re
import sys
import time

from . import common, store

ACTIONS = {0: 'pass', 1: 'block', 2: 'drop'}
BLOCKING_LOCAL = {'always_nxdomain', 'always_refuse', 'always_null', 'deny', 'refuse', 'inform_deny',
                  'always_deny'}


# ------------------------------------------------------------------ filter log


def _qsources():
    from quarantine import sources as qsources            # shared incremental reader and filterlog parser
    return qsources


class _LookupCtx:
    def __init__(self, path):
        self.lookup_db = path


def _country_lookup(ctx):
    try:
        from quarantine import lookup as qlookup
    except ImportError:
        return None
    lk = qlookup.Lookup(_LookupCtx(ctx.lookup_db))
    return lk if lk.db is not None else None


def read_blocks(ctx, marker, deadline, now):
    qs = _qsources()
    lines, new_marker, info = qs.read_new(ctx.filter_log, qs.filter_candidates(ctx.filter_log), marker,
                                          max_bytes=common.MAX_READ, deadline=deadline,
                                          first_tail=common.FIRST_RUN_TAIL, prefilter=b'filterlog')
    records = []
    for line in lines:
        rec = qs.parse_filter_line(line, now)
        if rec is not None and rec['action'] in ('block', 'reject'):
            records.append(rec)
    info['lines'] = len(lines)
    return records, new_marker, info


def aggregate_blocks(records, lookup=None):
    agg = {}
    cc_cache = {}
    for r in records:
        key = (common.hour_of(r['ts']), r['iface'] or '', r['dir'] or '', r['action'], r['proto'] or '',
               r['src'] or '', r['dst'] or '', r['dport'] or '', r['rid'] or '')
        cur = agg.get(key)
        if cur is None:
            src = r['src'] or ''
            if src not in cc_cache:
                cc = None
                if lookup is not None and src:
                    try:
                        cc = lookup.lookup(ipaddress.ip_address(src))[0]
                    except ValueError:
                        cc = None
                cc_cache[src] = cc
            agg[key] = [1, r['ts'], r['ts'], cc_cache[src]]
        else:
            cur[0] += 1
            cur[1] = min(cur[1], r['ts'])
            cur[2] = max(cur[2], r['ts'])
    return agg


def store_blocks(con, agg):
    con.executemany("""
        INSERT INTO blocks_hourly (hour, iface, dir, action, proto, src, dst, dport, rid, cc, n, first, last)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT (hour, iface, dir, action, proto, src, dst, dport, rid, origin)
        DO UPDATE SET n = n + excluded.n, first = min(first, excluded.first), last = max(last, excluded.last),
                      cc = coalesce(blocks_hourly.cc, excluded.cc)""",
                    [k + (v[3], v[0], v[1], v[2]) for k, v in agg.items()])


# ------------------------------------------------------------------ DNS


def dns_source(ctx, settings, root):
    choice = settings.get('dns_source', 'auto')
    if choice != 'auto':
        return choice
    if root is not None:
        if (root.findtext('./OPNsense/unboundplus/general/enabled') or '').strip() == '1':
            return 'unbound'
        if (root.findtext('./dnsmasq/enable') or root.findtext('./OPNsense/dnsmasq/enable') or '').strip() == '1':
            return 'dnsmasq'
    return 'none'


def _unbound_rows(ctx, since, until, limit):
    """ [(time, client, domain, action, rcode)] from the DuckDB of the Unbound logger; None = unavailable """
    if 'unbound_rows' in ctx.sources:
        return ctx.sources['unbound_rows'](since, until, limit)
    if not os.path.exists(ctx.unbound_db):
        return None
    if ctx.site_python not in sys.path:
        sys.path.insert(0, ctx.site_python)
    try:
        from duckdb_helper import DbConnection      # noqa: E402  (core module)
    except ImportError:
        return None
    with DbConnection(ctx.unbound_db, read_only=True) as db:
        if db is None or db.connection is None or not db.table_exists('query'):
            return None
        return db.connection.execute(
            'SELECT time, client, domain, action, rcode FROM query WHERE time > ? AND time <= ? '
            'ORDER BY time LIMIT ?', [int(since), int(until), int(limit)]).fetchall()


_UNBOUND_QUERY_RE = re.compile(r'\binfo: ([0-9a-fA-F:.]+) (\S+)\. (\S+) IN\s*$')
_UNBOUND_LOCAL_RE = re.compile(r'\binfo: \S+ ([a-z_]+) ([0-9a-fA-F:.]+)@\d+ (\S+)\. (\S+) IN\s*$')
_DNSMASQ_QUERY_RE = re.compile(r'\bquery\[[A-Za-z0-9]+\] (\S+) from ([0-9a-fA-F:.]+)\s*$')
_DNSMASQ_BLOCK_RE = re.compile(r'\b(?:config|reply) (\S+) is (0\.0\.0\.0|::|NXDOMAIN)\s*$')


def _line_ts(line, now):
    parts = line.split(' ', 2)
    if len(parts) >= 2 and parts[0].startswith('<'):
        try:
            return common.parse_time(parts[1])
        except ValueError:
            return None
    return now


def parse_resolver_lines(lines, kind, now):
    """ text logs -> [(time, client, domain, action, rcode)] """
    rows = []
    last = {}
    for line in lines:
        ts = _line_ts(line, now)
        if ts is None:
            continue
        if kind == 'unbound':
            match = _UNBOUND_LOCAL_RE.search(line)
            if match:
                action = 1 if match.group(1) in BLOCKING_LOCAL else 0
                rows.append((ts, match.group(2), match.group(3), action, 3 if match.group(1) == 'always_nxdomain'
                             else 0))
                continue
            match = _UNBOUND_QUERY_RE.search(line)
            if match:
                rows.append((ts, match.group(1), match.group(2), 0, 0))
        else:
            match = _DNSMASQ_QUERY_RE.search(line)
            if match:
                rows.append([ts, match.group(2), match.group(1).rstrip('.'), 0, 0])
                last[match.group(1).rstrip('.').lower()] = rows[-1]
                continue
            match = _DNSMASQ_BLOCK_RE.search(line)
            if match:
                row = last.get(match.group(1).rstrip('.').lower())
                if row is not None:
                    if line.find(' config ') >= 0 or match.group(2) != 'NXDOMAIN':
                        row[3] = 1
                    if match.group(2) == 'NXDOMAIN':
                        row[4] = 3
    return [tuple(r) for r in rows]


def read_dns(ctx, settings, root, con, now, deadline):
    """ :return: (rows, cursor updates {meta key: value}, info) """
    source = dns_source(ctx, settings, root)
    info = {'source': source, 'complete': True}
    if source == 'none':
        return [], {}, info
    if source == 'unbound':
        cursor = common.meta_get(con, 'dns_cursor')
        first = cursor is None
        since = int(cursor) if cursor is not None else int(common.local_midnight(now)) - 1
        until = int(now) - common.DNS_LAG
        if until > since:
            rows = _unbound_rows(ctx, since, until, common.DNS_MAX_ROWS)
        else:
            rows = []
        if rows is not None:
            info['source'] = 'unbound-duckdb'
            new_cursor = until
            if len(rows) >= common.DNS_MAX_ROWS:
                top = rows[-1][0]
                trimmed = [r for r in rows if r[0] < top]
                if trimmed:
                    rows, new_cursor = trimmed, top - 1
                info['complete'] = False
            info['first_run'] = first
            updates = {'dns_cursor': new_cursor}
            if first:
                updates['dns_since_hint'] = since + 1
            return rows, updates, info
        log, kind, key = ctx.resolver_log, 'unbound', 'resolver_marker'
        info['source'] = 'unbound-log'
    else:
        log, kind, key = ctx.dnsmasq_log, 'dnsmasq', 'dnsmasq_marker'
        info['source'] = 'dnsmasq-log'
    qs = _qsources()
    marker = common.meta_get(con, key)
    pattern = 'resolver_*.log' if kind == 'unbound' else 'dnsmasq_*.log'
    lines, new_marker, rinfo = qs.read_new(
        log, lambda: sorted(glob.glob(os.path.join(os.path.dirname(os.path.realpath(log)), pattern)),
                            reverse=True)[:3],
        marker, max_bytes=common.MAX_READ, deadline=deadline, first_tail=common.FIRST_RUN_TAIL,
        prefilter=b'info: ' if kind == 'unbound' else None)
    info.update({'complete': rinfo['complete'], 'missing': rinfo.get('missing', False), 'lines': len(lines)})
    return parse_resolver_lines(lines, kind, now), ({key: new_marker} if new_marker else {}), info


def aggregate_dns(rows):
    agg = collections.defaultdict(lambda: [0, 0])
    for ts, client, domain, action, rcode in rows:
        domain = str(domain or '').rstrip('.').lower()
        key = (common.hour_of(ts), str(client or ''), domain,
               ACTIONS.get(action, str(action)) if isinstance(action, int) else str(action).lower())
        agg[key][0] += 1
        if rcode == 3:
            agg[key][1] += 1
    return agg


def store_dns(con, agg):
    con.executemany("""
        INSERT INTO dns_hourly (hour, client, domain, action, n, nx) VALUES (?,?,?,?,?,?)
        ON CONFLICT (hour, client, domain, action, origin) DO UPDATE SET n = n + excluded.n, nx = nx + excluded.nx
        """, [k + (v[0], v[1]) for k, v in agg.items()])


# ------------------------------------------------------------------ run


def run(ctx, settings, deadline=None):
    started = time.monotonic()
    con = store.open_db(ctx, 'flows')
    now = ctx.clock()
    root = common.load_config(ctx)
    errors = []
    result = {'status': 'ok', 'kind': 'flows', 'ts': common.iso(now)}
    marker = common.meta_get(con, 'filter_marker')
    try:
        records, new_marker, finfo = read_blocks(ctx, marker, deadline, now)
    except Exception as exc:              # noqa: BLE001
        records, new_marker, finfo = [], marker, {'complete': False, 'error': str(exc)}
        errors.append('filter log: %s' % exc)
    lookup = _country_lookup(ctx) if records else None
    agg = aggregate_blocks(records, lookup)
    if lookup is not None:
        lookup.close()
    try:
        dns_rows, dns_updates, dinfo = read_dns(ctx, settings, root, con, now, deadline)
    except Exception as exc:              # noqa: BLE001
        dns_rows, dns_updates, dinfo = [], {}, {'source': 'error', 'complete': False}
        errors.append('dns: %s' % exc)
    dagg = aggregate_dns(dns_rows)
    with con:
        store_blocks(con, agg)
        if new_marker:
            common.meta_set(con, 'filter_marker', new_marker)
        store_dns(con, dagg)
        for key, value in dns_updates.items():
            if key == 'dns_since_hint':
                continue
            common.meta_set(con, key, value)
        if records and not common.meta_get(con, 'blocks_since'):
            common.meta_set(con, 'blocks_since', common.hour_of(min(r['ts'] for r in records)))
        if not common.meta_get(con, 'dns_since'):
            if 'dns_since_hint' in dns_updates:
                common.meta_set(con, 'dns_since', dns_updates['dns_since_hint'])
            elif dns_rows:
                common.meta_set(con, 'dns_since', common.hour_of(min(r[0] for r in dns_rows)))
        con.execute('INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?)', (
            now, len(records), len(dns_rows), finfo.get('lines', 0), finfo.get('bytes', 0), dinfo.get('source'),
            int(bool(finfo.get('complete', True)) and bool(dinfo.get('complete', True))),
            round(time.monotonic() - started, 3)))
    result.update({
        'blocks': len(records), 'block_buckets': len(agg), 'filter': {k: finfo.get(k) for k in (
            'lines', 'bytes', 'files', 'complete', 'first_run', 'missing') if k in finfo},
        'dns': len(dns_rows), 'dns_buckets': len(dagg), 'dns_info': dinfo, 'errors': errors,
    })
    maintenance = store.maintain(ctx, 'flows', con, settings, now)
    if maintenance:
        result['maintenance'] = maintenance
    result['seconds'] = round(time.monotonic() - started, 2)
    common.meta_set(con, 'last_run', result)
    con.commit()
    con.close()
    return result
