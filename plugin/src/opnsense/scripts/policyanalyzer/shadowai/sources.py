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

    Read-only sources of the AI usage panel.

    DNS: the Unbound query database (/var/unbound/data/unbound.duckdb, table "query": time (epoch), client,
    domain with a trailing dot, action 0 pass / 1 block / 2 drop, ...), opened read only through the core's
    duckdb_helper.DbConnection (it serialises with the Unbound logger). The SQL pre-filters with one regular
    expression and aggregates per client, domain and hour, so only a few thousand rows reach Python. The
    tests use a JSON lines file with the same columns instead (path ending in .jsonl).

    TLS: Suricata eve.json "tls" events (sni, ja4, src_ip, dest_ip), read backwards from the end of the
    current file (and eve.json.0 when the window needs it) with a byte and time budget; only lines with an SNI
    of the catalogue are decoded.

    Names: Kea leases and reservations, the Unbound client table, hostwatch (MAC + vendor) and the config's
    static host overrides: nothing is resolved on the network.
"""

import csv
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time

TLS_HINT = '"event_type":"tls"'
SNI_RE = re.compile(r'"sni":"([^"]{1,253})"')


class Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def expired(self):
        return time.monotonic() > self.deadline


# ------------------------------------------------------------------------------------------ DNS

def dns_rows(paths, catalog, since, until):
    """
    :return: (rows, meta) rows = [{client, domain, hour (epoch), queries, blocked, first, last}]
    """
    path = paths.unbound_db
    meta = {'source': path, 'available': False, 'rows': 0}
    if path.endswith('.jsonl') or path.endswith('.json'):
        return _dns_jsonl(path, catalog, since, until, meta)
    if not os.path.exists(path):
        meta['message'] = 'Unbound query database not found (enable Reporting › Settings › Unbound DNS)'
        return [], meta
    try:
        if paths.site_python not in sys.path:
            sys.path.append(paths.site_python)
        from duckdb_helper import DbConnection  # noqa: E402 - only on the firewall
    except ImportError as exc:
        meta['message'] = 'duckdb not available: %s' % exc
        return [], meta
    sql = (
        "SELECT client, rtrim(lower(domain), '.') AS d, (time // 3600) * 3600 AS hour, count(*) AS n, "
        "sum(CASE WHEN action <> 0 THEN 1 ELSE 0 END) AS blocked, min(time), max(time) "
        "FROM query WHERE time >= ? AND time < ? AND regexp_matches(lower(domain), ?) "
        "GROUP BY 1, 2, 3"
    )
    rows = []
    try:
        with DbConnection(path, read_only=True) as db:
            if db is None or db.connection is None or not db.table_exists('query'):
                meta['message'] = 'no query table yet'
                return [], meta
            span = db.connection.execute('SELECT min(time), max(time), count(*) FROM query').fetchone()
            for client, domain, hour, count, blocked, first, last in db.connection.execute(
                    sql, [int(since), int(until), catalog.regex()]).fetchall():
                rows.append({'client': client or '', 'domain': domain, 'hour': int(hour), 'queries': int(count),
                             'blocked': int(blocked or 0), 'first': int(first), 'last': int(last)})
    except Exception as exc:  # noqa: BLE001 - duckdb raises its own exception hierarchy
        meta['message'] = 'query database not readable: %s' % str(exc)[:160]
        return [], meta
    meta.update({'available': True, 'rows': len(rows), 'from': span[0], 'to': span[1], 'total_queries': span[2]})
    return rows, meta


def _dns_jsonl(path, catalog, since, until, meta):
    """ test fixture: one query per line {time, client, domain, action} """
    buckets = {}
    total = 0
    first_seen, last_seen = None, None
    try:
        with open(path) as handle:
            for line in handle:
                try:
                    q = json.loads(line)
                except ValueError:
                    continue
                total += 1
                t = int(q.get('time', 0))
                first_seen = t if first_seen is None else min(first_seen, t)
                last_seen = t if last_seen is None else max(last_seen, t)
                if not since <= t < until:
                    continue
                domain = str(q.get('domain', '')).lower().rstrip('.')
                if catalog.match(domain) is None:
                    continue
                key = (q.get('client') or '', domain, (t // 3600) * 3600)
                b = buckets.setdefault(key, {'queries': 0, 'blocked': 0, 'first': t, 'last': t})
                b['queries'] += 1
                b['blocked'] += 1 if int(q.get('action', 0)) != 0 else 0
                b['first'] = min(b['first'], t)
                b['last'] = max(b['last'], t)
    except OSError as exc:
        meta['message'] = str(exc)
        return [], meta
    rows = [dict(client=k[0], domain=k[1], hour=k[2], **v) for k, v in buckets.items()]
    meta.update({'available': True, 'rows': len(rows), 'from': first_seen, 'to': last_seen, 'total_queries': total})
    return rows, meta


# ------------------------------------------------------------------------------------------ TLS (eve.json)

def _parse_ts(text):
    """ 2026-11-01T23:00:01.226172-0300 -> epoch """
    try:
        base, frac_tz = text[:19], text[19:]
        match = re.match(r'^(?:\.\d+)?([+-])(\d{2}):?(\d{2})$', frac_tz)
        epoch = time.mktime(time.strptime(base, '%Y-%m-%dT%H:%M:%S'))
        if match:
            import calendar
            offset = (int(match.group(2)) * 3600 + int(match.group(3)) * 60) * (1 if match.group(1) == '+' else -1)
            epoch = calendar.timegm(time.strptime(base, '%Y-%m-%dT%H:%M:%S')) - offset
        return epoch
    except (ValueError, TypeError):
        return None


def _lines_backwards(path, max_bytes, chunk=1 << 20):
    try:
        handle = open(path, 'rb')
    except OSError:
        return
    with handle:
        handle.seek(0, os.SEEK_END)
        pos = handle.tell()
        read = 0
        tail = b''
        while pos > 0 and read < max_bytes:
            size = min(chunk, pos)
            pos -= size
            handle.seek(pos)
            data = handle.read(size) + tail
            read += size
            lines = data.split(b'\n')
            tail = lines[0]
            for line in reversed(lines[1:]):
                if line:
                    yield line
        if pos == 0 and tail:
            yield tail


def tls_events(paths, catalog, since, until, max_bytes=96 << 20, seconds=8.0):
    """
    :return: (events, meta) events = [{time, src, dst, sni, ja4, service, domain}]
    """
    budget = Budget(seconds)
    files = [paths.eve, paths.eve + '.0']
    meta = {'source': paths.eve, 'available': False, 'events': 0, 'tls_lines': 0, 'complete': True, 'files': []}
    events = []
    left = max_bytes
    for path in files:
        if not os.path.exists(path):
            continue
        meta['available'] = True
        meta['files'].append(os.path.basename(path))
        reached_start = False
        size = os.path.getsize(path)
        for raw in _lines_backwards(path, left):
            if budget.expired():
                meta['complete'] = False
                break
            if TLS_HINT.encode() not in raw:
                continue
            meta['tls_lines'] += 1
            text = raw.decode('utf-8', 'replace')
            match = SNI_RE.search(text)
            ts = _parse_ts(text[14:45]) if text.startswith('{"timestamp":"') else None
            if ts is not None and ts < since:
                reached_start = True
                break
            if not match:
                continue
            hit = catalog.match(match.group(1))
            if hit is None:
                continue
            try:
                ev = json.loads(text)
            except ValueError:
                continue
            ts = ts if ts is not None else _parse_ts(ev.get('timestamp', ''))
            if ts is None or ts >= until:
                continue
            tls = ev.get('tls') or {}
            events.append({'time': int(ts), 'src': ev.get('src_ip'), 'dst': ev.get('dest_ip'),
                           'sni': match.group(1).lower(), 'ja4': tls.get('ja4'), 'service': hit[0], 'domain': hit[1]})
        left -= size
        if reached_start or not meta['complete'] or left <= 0:
            if left <= 0 and not reached_start:
                meta['complete'] = False
            break
    meta['events'] = len(events)
    return events, meta


# ------------------------------------------------------------------------------------------ names

def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def host_names(paths, ctx_root=None, unbound_clients=None):
    """
    :return: {ip: {name, mac, vendor, source}} from Kea leases/reservations, Unbound clients, hostwatch and the
             static host overrides of config.xml (ctx_root: parsed config root, optional)
    """
    names = {}

    def put(ip, name=None, mac=None, vendor=None, source=None):
        ip = _ip(ip)
        if not ip:
            return
        entry = names.setdefault(ip, {'name': None, 'mac': None, 'vendor': None, 'source': None})
        if name and not entry['name']:
            entry['name'] = str(name).strip().rstrip('.')[:80]
            entry['source'] = source
        if mac and not entry['mac']:
            entry['mac'] = str(mac).lower()
        if vendor and not entry['vendor']:
            entry['vendor'] = str(vendor).strip()[:60]

    if ctx_root is not None:
        for res in ctx_root.findall('OPNsense/Kea/dhcp4/reservations/reservation'):
            put(res.findtext('ip_address'), res.findtext('hostname') or res.findtext('description'),
                res.findtext('hw_address'), source='kea reservation')
        for host in ctx_root.findall('OPNsense/unboundplus/hosts/host'):
            if (host.findtext('enabled') or '1') == '1' and (host.findtext('rr') or 'A') in ('A', 'AAAA'):
                fqdn = '.'.join(x for x in (host.findtext('hostname'), host.findtext('domain')) if x)
                put(host.findtext('server'), fqdn, source='dns override')
    try:
        with open(paths.kea_leases, newline='') as handle:
            for row in csv.DictReader(handle):
                put(row.get('address'), row.get('hostname'), row.get('hwaddr'), source='kea lease')
    except (OSError, csv.Error):
        pass
    for ip, hostname in (unbound_clients or {}).items():
        put(ip, hostname, source='dns client')
    if os.path.exists(paths.hostwatch_db):
        try:
            db = sqlite3.connect('file:%s?mode=ro' % paths.hostwatch_db, uri=True, timeout=2)
            try:
                rows = db.execute('SELECT ip_address, ether_address, organization_name FROM v_hosts '
                                  'ORDER BY last_seen').fetchall()
            except sqlite3.Error:
                rows = db.execute('SELECT ip_address, ether_address, NULL FROM hosts').fetchall()
            db.close()
            for ip, mac, vendor in rows:
                entry = names.get(_ip(ip) or '')
                # newest sighting last: the MAC of the current owner of the address wins
                if entry is not None:
                    entry['mac'] = (mac or entry['mac'] or '').lower() or None
                    entry['vendor'] = vendor or entry['vendor']
                else:
                    put(ip, None, mac, vendor)
        except sqlite3.Error:
            pass
    return names


def unbound_clients(paths):
    """ ip -> hostname from the Unbound "client" table (reverse names Unbound already resolved) """
    path = paths.unbound_db
    if path.endswith('.jsonl') or path.endswith('.json'):
        side = path.rsplit('.', 1)[0] + '.clients.json'
        try:
            with open(side) as handle:
                data = json.load(handle)
            return {k: v for k, v in data.items() if v}
        except (OSError, ValueError):
            return {}
    try:
        if paths.site_python not in sys.path:
            sys.path.append(paths.site_python)
        from duckdb_helper import DbConnection  # noqa: E402
        with DbConnection(path, read_only=True) as db:
            if db is None or db.connection is None or not db.table_exists('client'):
                return {}
            return {ip: host for ip, host in db.connection.execute(
                'SELECT ipaddr, hostname FROM client WHERE hostname IS NOT NULL').fetchall()}
    except Exception:  # noqa: BLE001
        return {}
