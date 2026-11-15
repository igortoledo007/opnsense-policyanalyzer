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

    Country and ASN of an address, from data the core already keeps on the firewall (nothing is
    downloaded here):
      /usr/local/share/GeoIP/alias/<CC>-IPv4|IPv6   networks per country (GeoIP aliases of the core)
      /usr/local/share/bgp/asn.csv                   "prefix,asn" (BGP ASN aliases of the core, refreshed
                                                     daily by the core while an ASN alias exists, or by
                                                     the plugin action update_asn_db)
    They are indexed into /var/db/policyanalyzer/quarantine-lookup.db (built in the background, with
    nice, when a source is newer than the index; the old index is used meanwhile).
"""

import glob
import ipaddress
import os
import socket
import sqlite3
import time

from . import common

INDEX_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE geo4 (start INTEGER PRIMARY KEY, end INTEGER NOT NULL, cc TEXT NOT NULL);
CREATE TABLE geo6 (start BLOB PRIMARY KEY, end BLOB NOT NULL, cc TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE asn4 (start INTEGER NOT NULL, end INTEGER NOT NULL, asn INTEGER NOT NULL, PRIMARY KEY (start, end))
    WITHOUT ROWID;
CREATE TABLE asn6 (start BLOB NOT NULL, end BLOB NOT NULL, asn INTEGER NOT NULL, PRIMARY KEY (start, end))
    WITHOUT ROWID;
"""
ASN_SOURCE = 'https://rulesets.opnsense.org/alias/asn.gz'     # the same source as the core (bgpasn.py)


def _range(cidr):
    """ "1.2.3.0/24" -> (4, start, end) with ints (v4) or 16 byte strings (v6); None when invalid """
    cidr = cidr.strip()
    addr_text, _sep, plen = cidr.partition('/')
    try:
        if ':' in addr_text:
            value = int.from_bytes(socket.inet_pton(socket.AF_INET6, addr_text), 'big')
            bits = int(plen) if plen else 128
            if not 0 <= bits <= 128:
                return None
            start = value & ~((1 << (128 - bits)) - 1) & ((1 << 128) - 1)
            end = start | ((1 << (128 - bits)) - 1)
            return 6, start.to_bytes(16, 'big'), end.to_bytes(16, 'big')
        value = int.from_bytes(socket.inet_aton(addr_text), 'big')
        bits = int(plen) if plen else 32
        if not 0 <= bits <= 32:
            return None
        start = value & ~((1 << (32 - bits)) - 1) & 0xffffffff
        return 4, start, start | ((1 << (32 - bits)) - 1)
    except (OSError, ValueError):
        return None


def sources(ctx):
    """ {"geoip": mtime|None, "asn": mtime|None} """
    result = {'geoip': None, 'asn': None}
    files = glob.glob(os.path.join(ctx.geoip_dir, '*-IPv4')) + glob.glob(os.path.join(ctx.geoip_dir, '*-IPv6'))
    if files:
        try:
            result['geoip'] = int(max(os.path.getmtime(f) for f in files))
        except OSError:
            pass
    try:
        if os.path.getsize(ctx.asn_csv) > 1024:
            result['asn'] = int(os.path.getmtime(ctx.asn_csv))
    except OSError:
        pass
    return result


def index_meta(ctx):
    try:
        db = sqlite3.connect('file:%s?mode=ro' % ctx.lookup_db, uri=True, timeout=2)
        try:
            return {k: v for k, v in db.execute('SELECT key, value FROM meta')}
        finally:
            db.close()
    except sqlite3.Error:
        return {}


def needs_build(ctx):
    src = sources(ctx)
    meta = index_meta(ctx)
    for key in ('geoip', 'asn'):
        if src[key] is not None and str(src[key]) != meta.get(key):
            return True
    return False


def build(ctx, deadline=None):
    """ (re)build the index into a temporary file, then rename it over the old one """
    src = sources(ctx)
    tmp = ctx.lookup_db + '.%d.tmp' % os.getpid()
    if os.path.exists(tmp):
        os.unlink(tmp)
    db = sqlite3.connect(tmp)
    counts = {'geo': 0, 'asn': 0}
    try:
        db.executescript('PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;' + INDEX_SCHEMA)
        if src['geoip'] is not None:
            for path in sorted(glob.glob(os.path.join(ctx.geoip_dir, '*-IPv[46]'))):
                cc = os.path.basename(path).split('-')[0][:2].upper()
                rows4, rows6 = [], []
                with open(path) as handle:
                    for line in handle:
                        rng = _range(line)
                        if rng is None:
                            continue
                        (rows4 if rng[0] == 4 else rows6).append((rng[1], rng[2], cc))
                db.executemany('INSERT OR REPLACE INTO geo4 VALUES (?, ?, ?)', rows4)
                db.executemany('INSERT OR REPLACE INTO geo6 VALUES (?, ?, ?)', rows6)
                counts['geo'] += len(rows4) + len(rows6)
        if src['asn'] is not None:
            rows4, rows6 = [], []
            with open(ctx.asn_csv) as handle:
                for line in handle:
                    prefix, _sep, asn = line.strip().partition(',')
                    rng = _range(prefix)
                    if rng is None or not asn.isdigit():
                        continue
                    (rows4 if rng[0] == 4 else rows6).append((rng[1], rng[2], int(asn)))
                    if len(rows4) >= 50000:
                        db.executemany('INSERT OR REPLACE INTO asn4 VALUES (?, ?, ?)', rows4)
                        rows4 = []
            db.executemany('INSERT OR REPLACE INTO asn4 VALUES (?, ?, ?)', rows4)
            db.executemany('INSERT OR REPLACE INTO asn6 VALUES (?, ?, ?)', rows6)
            counts['asn'] = db.execute('SELECT (SELECT count(*) FROM asn4) + (SELECT count(*) FROM asn6)').fetchone()[0]
        db.executemany('INSERT INTO meta VALUES (?, ?)', [('geoip', str(src['geoip'] or '')),
                                                         ('asn', str(src['asn'] or '')),
                                                         ('built', str(int(time.time())))])
        db.commit()
    finally:
        db.close()
    os.chmod(tmp, 0o640)
    os.replace(tmp, ctx.lookup_db)
    return {'status': 'ok', 'counts': counts, 'sources': src}


class Lookup:
    """ country / ASN of an address from the index (missing index: None) """

    def __init__(self, ctx):
        self.db = None
        try:
            if os.path.exists(ctx.lookup_db):
                self.db = sqlite3.connect('file:%s?mode=ro' % ctx.lookup_db, uri=True, timeout=2)
        except sqlite3.Error:
            self.db = None
        self._cache = {}

    def _find(self, table, ip):
        if ip.version == 4:
            key = int(ip)
        else:
            key = int(ip).to_bytes(16, 'big')
        rows = self.db.execute('SELECT start, end, %s FROM %s%d WHERE start <= ? ORDER BY start DESC LIMIT 64' % (
            'cc' if table == 'geo' else 'asn', table, ip.version), (key,)).fetchall()
        best = None
        for start, end, value in rows:
            if end >= key:
                size = (int.from_bytes(end, 'big') - int.from_bytes(start, 'big')) if ip.version == 6 else end - start
                if best is None or size < best[0]:
                    best = (size, value)
        return best[1] if best else None

    def lookup(self, ip):
        """ :return: (country or None, asn or None) """
        if self.db is None or ip is None:
            return None, None
        if ip in self._cache:
            return self._cache[ip]
        try:
            result = (self._find('geo', ip), self._find('asn', ip))
        except sqlite3.Error:
            result = (None, None)
        self._cache[ip] = result
        return result

    def close(self):
        if self.db is not None:
            self.db.close()


def asn_prefixes(ctx, asn, deadline=None):
    """ prefixes announced by an ASN, from asn.csv; :return: (prefixes [ip_network], source mtime) """
    try:
        mtime = int(os.path.getmtime(ctx.asn_csv))
        handle = open(ctx.asn_csv)
    except OSError:
        raise common.QuarantineError('no local ASN database (%s): run "Update the ASN database" first' % ctx.asn_csv)
    suffix = ',%d' % int(asn)
    found = []
    with handle:
        for line in handle:
            line = line.strip()
            if line.endswith(suffix) and line[:-len(suffix)].count(',') == 0:
                try:
                    found.append(ipaddress.ip_network(line[:-len(suffix)], strict=False))
                except ValueError:
                    continue
            if deadline is not None and len(found) % 1000 == 0 and time.monotonic() > deadline:
                raise common.QuarantineError('the ASN lookup took too long')
    collapsed = list(ipaddress.collapse_addresses([n for n in found if n.version == 4])) + \
        list(ipaddress.collapse_addresses([n for n in found if n.version == 6]))
    return collapsed, mtime
