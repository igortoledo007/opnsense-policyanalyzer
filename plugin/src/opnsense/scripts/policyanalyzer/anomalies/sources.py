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

    Read only data sources (all of them already kept by the core; nothing here writes to them):

      NetFlow     /var/log/flowd.log* (flowd binary log, decoded with the core parser
                  scripts/netflow/lib/flowparser.py), read forward from the last receive time (marker); the
                  first run reads the last "first_hours" hours
      Unbound     /var/unbound/data/unbound.duckdb, table "query" (time, client, type, domain, rcode, action),
                  opened read only through the core helper site-python/duckdb_helper.DbConnection (the same
                  flock protocol as the Unbound reports, so the logger is never blocked for long); the DGA and
                  tunnel window is re-read every run (a few thousand rows), the hourly counters only for hours
                  that completed since the last run
      Hosts       /var/db/hostwatch/hosts.db (Host discovery, SQLite, opened with mode=ro) plus the Kea
                  (/var/db/kea/kea-leases4.csv) and dnsmasq (/var/db/dnsmasq.leases) leases
      Filter log  /var/log/filter/latest.log, the incremental reader of the quarantine (marker dev/ino/offset)
      Suricata    /var/log/suricata/eve.json, only "event_type":"tls" (JA4, SNI, certificate subject/issuer/
                  validity; TLS 1.3 hides the certificate), same marker reader
      Insight     /var/netflow/src_addr_details_086400.sqlite (daily host/destination totals), used once to
                  seed the destinations each host already talks to

    Tests replace any reader through ctx.sources[<name>].
"""

import csv
import glob
import os
import sqlite3
import sys
import time

FLOW_CHECK_EVERY = 5000


# ------------------------------------------------------------------ NetFlow


def _flow_parser(ctx):
    if ctx.netflow_lib not in sys.path:
        sys.path.insert(0, ctx.netflow_lib)
    from lib.flowparser import FlowParser    # noqa: E402  (core module)
    try:
        from lib.parse import Interfaces      # noqa: E402
        interfaces = Interfaces()
    except Exception:                         # noqa: BLE001  ifinfo missing: keep the indexes
        interfaces = None
    return FlowParser, interfaces


def read_flows(ctx, marker, now, settings, deadline=None):
    """
    :return: (flows [dict], new marker {"recv": epoch}, info)
    flow: {ts, end, src, dst, sport, dport, proto, octets, packets, if_in, if_out, flags}
    """
    if 'flows' in ctx.sources:
        return ctx.sources['flows'](marker, now, settings)
    info = {'source': 'flowd', 'complete': True, 'records': 0, 'files': 0, 'first_run': not marker}
    stamp = int(marker.get('recv')) if marker and marker.get('recv') else int(now - settings['first_hours'] * 3600)
    files = sorted(glob.glob(ctx.flowd_log + '*'))
    if not files:
        info['missing'] = True
        return [], marker, info
    try:
        FlowParser, interfaces = _flow_parser(ctx)
    except ImportError as exc:
        info.update({'missing': True, 'error': 'core NetFlow parser not available: %s' % exc})
        return [], marker, info
    flows = []
    newest = stamp
    limit = settings['max_flows']
    for filename in files:
        older = False
        info['files'] += 1
        try:
            for rec in FlowParser(filename, stamp):
                recv = rec.get('recv_sec') or 0
                if recv <= stamp:
                    older = True
                    continue
                newest = max(newest, recv)
                if_in, if_out = rec.get('if_ndx_in'), rec.get('if_ndx_out')
                if interfaces is not None:
                    if_in, if_out = interfaces.if_device(if_in), interfaces.if_device(if_out)
                flows.append({
                    'ts': float(rec.get('flow_start') or recv), 'end': float(rec.get('flow_end') or recv),
                    'src': rec.get('src_addr') or '', 'dst': rec.get('dst_addr') or '',
                    'sport': rec.get('src_port') or 0, 'dport': rec.get('dst_port') or 0,
                    'proto': rec.get('protocol') or 0, 'octets': rec.get('octets') or 0,
                    'packets': rec.get('packets') or 0, 'if_in': str(if_in), 'if_out': str(if_out),
                    'flags': rec.get('tcp_flags') or 0,
                })
                if len(flows) % FLOW_CHECK_EVERY == 0:
                    if len(flows) >= limit or (deadline is not None and time.monotonic() > deadline):
                        info['complete'] = False
                        break
        except (OSError, ValueError) as exc:
            info.setdefault('errors', []).append('%s: %s' % (os.path.basename(filename), exc))
        if older or not info['complete']:
            break
    flows.sort(key=lambda f: f['ts'])
    info['records'] = len(flows)
    return flows, {'recv': newest}, info


# ------------------------------------------------------------------ Unbound


def _duckdb(ctx):
    if ctx.site_python not in sys.path:
        sys.path.insert(0, ctx.site_python)
    from duckdb_helper import DbConnection   # noqa: E402  (core module)
    return DbConnection


def read_dns(ctx, marker, now, settings, deadline=None):
    """
    :return: (rows [(time, client, type, domain, rcode, action)] of the detection window,
              hours [(client, hour, queries, nx, txt)] completed since the marker, new marker, info)
    """
    if 'dns' in ctx.sources:
        return ctx.sources['dns'](marker, now, settings)
    info = {'source': 'unbound', 'complete': True}
    window_start = int(now - settings['dga_window_m'] * 60)
    current_hour = int(now // 3600 * 3600)
    last_hour = int(marker.get('hour')) if marker and marker.get('hour') else current_hour - 48 * 3600
    if not os.path.exists(ctx.unbound_db):
        info['missing'] = True
        return [], [], marker, info
    try:
        DbConnection = _duckdb(ctx)
    except ImportError as exc:
        info.update({'missing': True, 'error': 'duckdb not available: %s' % exc})
        return [], [], marker, info
    rows, hours = [], []
    started = time.monotonic()
    with DbConnection(ctx.unbound_db, read_only=True) as db:
        if db is None or db.connection is None or not db.table_exists('query'):
            info['missing'] = True
            return [], [], marker, info
        con = db.connection
        rows = con.execute(
            'SELECT time, client, type, domain, rcode, action FROM query WHERE time >= ? ORDER BY time LIMIT ?',
            [window_start, int(settings['max_dns_rows'])]).fetchall()
        if current_hour > last_hour + 3600 - 1:
            hours = con.execute(
                "SELECT client, (time // 3600) * 3600 AS hour, count(*), "
                "sum(CASE WHEN rcode = 3 AND action = 0 THEN 1 ELSE 0 END), "
                "sum(CASE WHEN type IN ('TXT', 'NULL') THEN 1 ELSE 0 END) "
                "FROM query WHERE time >= ? AND time < ? GROUP BY 1, 2",
                [last_hour + 3600, current_hour]).fetchall()
    info['rows'] = len(rows)
    info['complete'] = len(rows) < settings['max_dns_rows']
    info['held_ms'] = int((time.monotonic() - started) * 1000)
    new_marker = {'hour': current_hour - 3600} if current_hour > last_hour + 3600 - 1 else marker
    return rows, hours, new_marker or {'hour': current_hour - 3600}, info


def read_dns_seed(ctx, limit=500000):
    """ first run: every (client, domain) of the Unbound history (up to 7 days): [(client, domain, first, last, n)] """
    if 'dns_seed' in ctx.sources:
        return ctx.sources['dns_seed']()
    if not os.path.exists(ctx.unbound_db):
        return []
    try:
        DbConnection = _duckdb(ctx)
    except ImportError:
        return []
    with DbConnection(ctx.unbound_db, read_only=True) as db:
        if db is None or db.connection is None or not db.table_exists('query'):
            return []
        return db.connection.execute(
            'SELECT client, domain, min(time), max(time), count(*) FROM query WHERE action = 0 '
            'GROUP BY 1, 2 LIMIT ?', [limit]).fetchall()


# ------------------------------------------------------------------ hosts


def read_hosts(ctx):
    """ :return: (hosts [{mac, ip, iface, first_seen, last_seen, vendor, hostname, source}], info) """
    if 'hosts' in ctx.sources:
        return ctx.sources['hosts']()
    hosts, info = [], {'hostwatch': False, 'kea': False, 'dnsmasq': False}
    if os.path.exists(ctx.hostwatch_db):
        try:
            db = sqlite3.connect('file:%s?mode=ro' % ctx.hostwatch_db, uri=True, timeout=5)
            try:
                try:
                    cur = db.execute('SELECT ether_address, ip_address, interface_name, first_seen, last_seen, '
                                     'organization_name FROM v_hosts')
                except sqlite3.Error:
                    cur = db.execute('SELECT ether_address, ip_address, interface_name, first_seen, last_seen, '
                                     'NULL FROM hosts')
                for mac, ip, iface, first, last, vendor in cur:
                    hosts.append({'mac': (mac or '').lower(), 'ip': ip or '', 'iface': iface or '',
                                  'first_seen': _sqlite_ts(first), 'last_seen': _sqlite_ts(last),
                                  'vendor': vendor or None, 'hostname': None, 'source': 'hostwatch'})
                info['hostwatch'] = True
            finally:
                db.close()
        except sqlite3.Error as exc:
            info['hostwatch_error'] = str(exc)
    for path in sorted(glob.glob(ctx.kea_leases + '*')):
        try:
            with open(path, newline='') as handle:
                for row in csv.DictReader(handle):
                    mac = (row.get('hwaddr') or '').lower()
                    if not mac:
                        continue
                    expire = _int(row.get('expire'))
                    lifetime = _int(row.get('valid_lifetime'))
                    hosts.append({'mac': mac, 'ip': row.get('address') or '', 'iface': '',
                                  'first_seen': (expire - lifetime) if expire and lifetime else None,
                                  'last_seen': (expire - lifetime) if expire and lifetime else None,
                                  'vendor': None, 'hostname': (row.get('hostname') or '').strip('.') or None,
                                  'source': 'kea'})
            info['kea'] = True
        except (OSError, csv.Error):
            continue
    try:
        with open(ctx.dnsmasq_leases) as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 4 and ':' in parts[1]:
                    hosts.append({'mac': parts[1].lower(), 'ip': parts[2], 'iface': '',
                                  'first_seen': None, 'last_seen': None, 'vendor': None,
                                  'hostname': parts[3] if parts[3] != '*' else None, 'source': 'dnsmasq'})
        info['dnsmasq'] = True
    except OSError:
        pass
    return hosts, info


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sqlite_ts(value):
    """ "2026-11-08 05:55:06" (UTC, SQLite current_timestamp) -> epoch """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    try:
        import calendar
        return calendar.timegm(time.strptime(str(value)[:19], '%Y-%m-%d %H:%M:%S'))
    except ValueError:
        return None


# ------------------------------------------------------------------ filter log


def read_filter(ctx, marker, now, deadline=None):
    """ :return: (records [quarantine.sources.parse_filter_line], new marker, info) """
    if 'filter' in ctx.sources:
        return ctx.sources['filter'](marker, now)
    try:
        from quarantine import sources as qsources   # the incremental reader of the quarantine
    except ImportError:
        return [], marker, {'missing': True}
    lines, new_marker, info = qsources.read_new(ctx.filter_log, qsources.filter_candidates(ctx.filter_log), marker,
                                                max_bytes=32 << 20, deadline=deadline, first_tail=1 << 20,
                                                prefilter=b'filterlog')
    records = []
    for line in lines:
        rec = qsources.parse_filter_line(line, now)
        if rec is not None and rec['action'] in ('block', 'reject'):
            records.append(rec)
    info['records'] = len(records)
    return records, new_marker, info


# ------------------------------------------------------------------ Suricata TLS


def _cert_time(value):
    """ "2027-02-06T23:59:59" (UTC) -> epoch """
    if not value:
        return None
    try:
        import calendar
        return calendar.timegm(time.strptime(str(value)[:19], '%Y-%m-%dT%H:%M:%S'))
    except ValueError:
        return None


def parse_tls_line(line):
    import json
    try:
        doc = json.loads(line)
    except ValueError:
        return None
    if not isinstance(doc, dict) or doc.get('event_type') != 'tls' or not isinstance(doc.get('tls'), dict):
        return None
    try:
        from quarantine import sources as qsources
        ts = qsources._eve_ts(doc.get('timestamp'))
    except ImportError:
        ts = None
    tls = doc['tls']
    ja4 = tls.get('ja4')
    return {'ts': ts, 'src': str(doc.get('src_ip') or ''), 'dst': str(doc.get('dest_ip') or ''),
            'dport': doc.get('dest_port'), 'sni': str(tls.get('sni') or '')[:255],
            'ja4': ja4 if isinstance(ja4, str) else (ja4.get('hash') if isinstance(ja4, dict) else None),
            'subject': str(tls.get('subject') or '')[:300], 'issuerdn': str(tls.get('issuerdn') or '')[:300],
            'subjectaltname': [str(x) for x in (tls.get('subjectaltname') or [])][:50],
            'fingerprint': tls.get('fingerprint'), 'notafter': tls.get('notafter'),
            'notafter_epoch': _cert_time(tls.get('notafter')), 'notbefore_epoch': _cert_time(tls.get('notbefore')),
            'version': tls.get('version')}


def read_tls(ctx, marker, now, deadline=None):
    """ TLS events of the Suricata EVE log, read forward from the marker """
    if 'tls' in ctx.sources:
        return ctx.sources['tls'](marker, now)
    try:
        from quarantine import sources as qsources
    except ImportError:
        return [], marker, {'missing': True}
    if not os.path.exists(ctx.eve):
        return [], marker, {'missing': True}
    lines, new_marker, info = qsources.read_new(ctx.eve, qsources.eve_candidates(ctx.eve), marker,
                                                max_bytes=48 << 20, deadline=deadline, first_tail=4 << 20,
                                                prefilter=b'"event_type":"tls"')
    events = [e for e in (parse_tls_line(line) for line in lines) if e is not None and e['ts'] is not None]
    info['events'] = len(events)
    return events, new_marker, info


# ------------------------------------------------------------------ Insight seed


def read_insight_pairs(ctx, limit=300000):
    """ daily host/destination totals of the Insight aggregator: [(src, dst, octets, first, last)] """
    if 'insight' in ctx.sources:
        return ctx.sources['insight']()
    path = os.path.join(ctx.netflow_dir, 'src_addr_details_086400.sqlite')
    if not os.path.exists(path):
        return []
    try:
        db = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=5)
        try:
            return db.execute('SELECT src_addr, dst_addr, sum(octets), min(mtime), max(last_seen) FROM timeserie '
                              'GROUP BY 1, 2 LIMIT ?', (limit,)).fetchall()
        finally:
            db.close()
    except sqlite3.Error:
        return []
