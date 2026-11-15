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

    Event sources of the incident triage (all read only):

      filter log   /var/log/filter/latest.log, read forward from a position marker by the quarantine reader
                   (quarantine/sources.py, same rotation handling, only complete lines)
      Suricata     /var/log/suricata/eve.json alerts, same reader and marker logic
      quarantine   /var/db/policyanalyzer/quarantine.db opened read only (mode=ro): offenses after the last
                   offense id seen, and the addresses in quarantine now or in the last 30 days
      DNS          /var/unbound/data/unbound.duckdb (Unbound reporting, when present): blocked queries per
                   client and domain after the last query time seen, through the core's DbConnection helper
                   (the same reader/writer synchronization the Unbound reporting page uses)

    Every source turns into compact observations (obs rows aggregated per 5 minutes), never raw lines.
"""

import contextlib
import ipaddress
import os
import sqlite3
import sys

from quarantine import common as qcommon, engine as qengine, sources as qsources, store as qstore

from . import common

# ------------------------------------------------------------------ filter log and Suricata (quarantine readers)


def read_filter(ctx, marker, deadline=None, now=None):
    return qsources.read_filter(ctx, marker, deadline=deadline, now=now)


def read_suricata(ctx, marker, deadline=None):
    return qsources.read_suricata(ctx, marker, deadline=deadline)


def end_marker(path):
    try:
        st = os.stat(os.path.realpath(path))
    except OSError:
        return None
    return {'dev': st.st_dev, 'ino': st.st_ino, 'offset': st.st_size}


class Obs:
    """ in memory aggregation of one run (the delta), flushed into the obs table """

    def __init__(self):
        self.rows = {}

    def add(self, kind, ts, src='', dst='', port='', rid='', iface=None, sev=None, label=None, n=1):
        bucket = int(ts) - int(ts) % common.BUCKET
        key = (bucket, kind, src or '', dst or '', port or '', rid or '')
        row = self.rows.get(key)
        if row is None:
            self.rows[key] = {'bucket': bucket, 'kind': kind, 'src': src or '', 'dst': dst or '', 'port': port or '',
                              'rid': rid or '', 'iface': iface, 'sev': sev, 'label': label, 'n': int(n),
                              'first': int(ts), 'last': int(ts)}
        else:
            row['n'] += int(n)
            row['first'] = min(row['first'], int(ts))
            row['last'] = max(row['last'], int(ts))
            if sev is not None:
                row['sev'] = sev if row['sev'] is None else min(row['sev'], sev)
            if label:
                row['label'] = label

    def values(self):
        return list(self.rows.values())

    def __len__(self):
        return len(self.rows)


def classify_filter(records, wan_devs, oldest, obs):
    """
    filter log records -> observations:
      in_block / in_pass    inbound on a WAN interface from an external source (TCP: connection attempts only)
      out_pass / out_block  inbound on an internal interface from an internal host to an external destination
    :return: counters
    """
    counts = {'records': 0, 'used': 0}
    for rec in records:
        counts['records'] += 1
        if rec['ts'] < oldest or rec['dir'] != 'in' or rec['action'] not in ('pass', 'block'):
            continue
        src, dst = common.addr(rec['src']), common.addr(rec['dst'])
        if src is None or dst is None:
            continue
        port = common.port_key(rec['dport'], rec['proto'])
        if rec['iface'] in wan_devs:
            if not common.is_external(src) or not qengine.counts_as_connection(rec, 1):
                continue
            kind = 'in_block' if rec['action'] == 'block' else 'in_pass'
        else:
            if not common.is_internal(src) or not common.is_external(dst):
                continue
            if rec['action'] == 'pass' and not qengine.counts_as_connection(rec, 1):
                continue
            kind = 'out_block' if rec['action'] == 'block' else 'out_pass'
        obs.add(kind, rec['ts'], str(src), str(dst), port, rec.get('rid') or '', iface=rec['iface'])
        counts['used'] += 1
    return counts


def classify_alerts(alerts, oldest, obs):
    used = 0
    for alert in alerts:
        if alert['ts'] < oldest:
            continue
        src, dst = common.addr(alert['src']), common.addr(alert['dst'])
        if src is None or dst is None or not (common.is_external(src) or common.is_external(dst)):
            continue
        obs.add('ids', alert['ts'], str(src), str(dst), common.port_key(alert['dport'], alert['proto']),
                str(alert.get('sid') or ''), iface=alert.get('iface') or None, sev=alert.get('severity'),
                label=(alert.get('signature') or '')[:100] or None)
        used += 1
    return used


# ------------------------------------------------------------------ quarantine ledger (read only)


class QuarantineView:
    """ the quarantine ledger through its own Store class, on a read only connection """

    def __init__(self, path):
        self.store = None
        self.bad = {}
        self._intervals = None
        if not path or not os.path.exists(path):
            return
        try:
            st = qstore.Store.__new__(qstore.Store)
            st.path = path
            st.db = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=5, isolation_level=None)
            st.db.row_factory = sqlite3.Row
            st.db.execute('PRAGMA busy_timeout=5000')
            st._in_tx = False
            st.db.execute('SELECT 1 FROM entries LIMIT 1')
            self.store = st
        except sqlite3.Error:
            self.store = None

    @property
    def available(self):
        return self.store is not None

    def close(self):
        if self.store is not None:
            self.store.close()
            self.store = None

    def load_bad(self, now):
        """ addresses (and networks / ASN prefixes) in quarantine now or in the last 30 days """
        self.bad = {}
        self._intervals = qcommon.IntervalSet()
        if self.store is None:
            return self.bad
        try:
            entries = self.store.entries_covering_since(now - common.QUARANTINE_RECENT)
            for e in entries:
                info = {'addr': e['addr'], 'kind': e['kind'], 'level': e['level'], 'state': e['state'],
                        'reason': qcommon.REASON_NAMES.get(e['reason']), 'country': e['country'], 'asn': e['asn'],
                        'until': e['until'], 'offenses': e['offenses'],
                        'active': e['state'] == 'permanent' or (e['state'] == 'active' and (e['until'] or 0) > now)}
                self.bad[e['addr']] = info
                nets = []
                if e['kind'] == 'asn':
                    nets = self.store.asn_prefixes(e['id'])
                elif e['kind'] == 'net':
                    nets = [e['addr']]
                for net in nets:
                    try:
                        self._intervals.add(ipaddress.ip_network(net, strict=False), e['addr'])
                    except ValueError:
                        continue
        except sqlite3.Error:
            pass
        return self.bad

    def find(self, text):
        """ quarantine info of an address (own entry or a network / ASN covering it), None when clean """
        if text in self.bad:
            return self.bad[text]
        if self._intervals is not None and len(self._intervals):
            ip = common.addr(text)
            if ip is not None:
                label = self._intervals.lookup(ip)
                if label:
                    return self.bad.get(label)
        return None

    def entry(self, text):
        if self.store is None:
            return None
        try:
            return self.store.entry_by_addr(text)
        except sqlite3.Error:
            return None

    def new_offenses(self, last_id, now):
        """ offenses with id > last_id (newest two days), oldest first, each with the previous one of the entry """
        if self.store is None:
            return [], last_id
        try:
            _total, rows = self.store.offenses(start=now - 2 * 86400, rows=-1)
        except sqlite3.Error:
            return [], last_id
        rows = sorted([r for r in rows if r['id'] > (last_id or 0)], key=lambda r: r['id'])
        out = []
        for row in rows:
            item = dict(row)
            item['reason_name'] = qcommon.REASON_NAMES.get(row['reason'])
            item['reasons_list'] = qstore.reasons_from_mask(row['reasons'] or 0)
            try:
                _t, prev = self.store.offenses(entry_id=row['entry_id'], end=row['ts'], rows=2)
            except sqlite3.Error:
                prev = []
            prev = [p for p in prev if p['id'] != row['id']]
            item['previous'] = dict(prev[0]) if prev else None
            out.append(item)
        if rows:
            last_id = rows[-1]['id']
        elif last_id is None:
            try:
                row = self.store.db.execute('SELECT max(id) FROM offenses').fetchone()
                last_id = row[0] or 0
            except sqlite3.Error:
                last_id = 0
        return out, last_id


def classify_offenses(offenses, obs):
    """ quarantine offenses -> q_offense observations (label: reasons, sev: level, port: ports) """
    for o in offenses:
        obs.add('q_offense', o['ts'], o['addr'], '', (o.get('ports') or '')[:60], 'q%d' % o['id'],
                sev=o.get('level'), label='+'.join(o.get('reasons_list') or [o.get('reason_name') or '?']),
                n=o.get('events') or 1)


# ------------------------------------------------------------------ DNS (Unbound reporting, DuckDB)


@contextlib.contextmanager
def dns_connection(ctx):
    """ yields a DB-API like connection with the "query" table, or None (no database, no duckdb) """
    if ctx.dns_connect is not None:
        conn = ctx.dns_connect()
        try:
            yield conn
        finally:
            if conn is not None:
                conn.close()
        return
    if not os.path.exists(ctx.unbound_db):
        yield None
        return
    try:
        if ctx.site_python not in sys.path:
            sys.path.append(ctx.site_python)
        from duckdb_helper import DbConnection      # the core's helper (writer/reader synchronization)
    except ImportError:
        yield None
        return
    try:
        with DbConnection(ctx.unbound_db, read_only=True) as db:
            if db is None or db.connection is None or not db.table_exists('query'):
                yield None
            else:
                yield db.connection
    except Exception:                                # noqa: BLE001 - storage version, locks: no DNS this run
        yield None


def read_dns(ctx, since, now):
    """
    blocked / dropped queries (action 1 / 2) of internal clients after `since` (epoch, exclusive) up to now - 1
    :return: (rows [{client, domain, blocklist, n, first, last}], new mark, info)
    """
    until = int(now) - 1
    info = {'available': False, 'rows': 0}
    with dns_connection(ctx) as conn:
        if conn is None:
            return [], since, info
        info['available'] = True
        try:
            cur = conn.execute(
                'SELECT client, domain, blocklist, count(*) AS n, min(time) AS first, max(time) AS last FROM query '
                'WHERE time > ? AND time <= ? AND action IN (1, 2) GROUP BY client, domain, blocklist '
                'ORDER BY n DESC LIMIT %d' % common.DNS_MAX_ROWS, (int(since), until))
            rows = cur.fetchall()
        except Exception as exc:                     # noqa: BLE001
            info.update({'available': False, 'error': str(exc)[:120]})
            return [], since, info
    out = []
    for client, domain, blocklist, n, first, last in rows:
        ip = common.addr(client)
        if ip is None or not common.is_internal(ip) or not domain:
            continue
        out.append({'client': str(ip), 'domain': str(domain)[:120], 'blocklist': str(blocklist or '')[:40] or None,
                    'n': int(n), 'first': int(first), 'last': int(last)})
    info['rows'] = len(out)
    return out, until, info


def classify_dns(rows, obs):
    for row in rows:
        # one observation per client and domain at the time of the last query (counts kept)
        obs.add('dns_block', row['last'], row['client'], row['domain'], '', '', label=row['blocklist'], n=row['n'])
