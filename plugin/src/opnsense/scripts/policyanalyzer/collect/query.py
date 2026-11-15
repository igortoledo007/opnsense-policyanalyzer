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

    Read interface of the local collectors (for the PDF charts, the reports and the GUI).  Read only:
    every database is opened with mode=ro; a missing database gives empty results, never an error.

        from collect import query
        q = query.Query()                         # Query(ctx) in tests
        q.blocks_series('7d', 'now', bucket='hour', wan_only=True, direction='in')

    Times (since / until): epoch, 'AAAA-MM-DD' (local midnight; until = end of that day), ISO 8601,
    relative '24h' / '7d' / '2w' or 'now'.  The range is [since, until).  Every point / row carries "t"
    (local ISO 8601) and "ts" (epoch).  Hourly detail exists for the last compact_after_days (7) days;
    older data is daily (a bucket='hour' series returns those days as one point at local midnight with
    "daily": true).  Results are plain lists / dicts (JSON serialisable).

    Functions (all methods of Query; module level shortcuts with the same names use a default Query):
      coverage()                                         ranges per source: local since, imported ranges
      blocks_series(since, until, bucket, wan_only, direction, iface)   [{t, ts, blocks, daily?}]
      top_sources(since, until, limit, wan_only, direction)   [{ip, blocks, ports, country}]
      top_countries(since, until, limit, wan_only, direction) [{country, blocks, sources}]
      top_ports(since, until, limit, wan_only, direction)     [{port, proto, label, blocks, sources}]
      top_rules(since, until, limit)                     [{rid, label, blocks}]
      top_interfaces(since, until, limit)                [{iface, name, wan, blocks}]
      dns_series(since, until, bucket)                   [{t, ts, queries, blocked, nxdomain, daily?}]
      top_domains(since, until, limit, action, client)   [{domain, queries, clients}]   action: pass|blocked|all
      top_dns_clients(since, until, limit, action)       [{client, queries, blocked, domains}]
      health_keys(pattern)                               ['cpu_idle_pct', 'gw:WAN_B:rtt_ms', ...]
      health_series(keys, since, until, bucket, agg)     {key: [{t, ts, value}]}   keys may use * (glob)
      health_latest()                                    {ts, t, metrics {key: value}}
      health_events(since, until, kind)                  [{t, ts, kind, source, text}]
      config_revisions(since, until)                     [{id, t, ts, author, author_ip, description, changes}]
      config_changes(since, until, section)              [{t, ts, author, author_ip, revision, section, key,
                                                           kind, item, fields [{field, old, new}]}]
      config_diff(snapshot_a, snapshot_b, context)       unified diff of the sanitized XML (text)
      summary(since, until)                              everything above in one small dict (for a report)
      compare(since, until)                              per day totals, same shape as
                                                         scripts/export-collect.py resumo
"""

import difflib
import fnmatch
import json
import re
import time
import zlib

from . import common

PORT_LABELS = {
    '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS', '80': 'HTTP', '110': 'POP3',
    '123': 'NTP', '135': 'MSRPC', '137': 'NetBIOS', '139': 'NetBIOS', '143': 'IMAP', '161': 'SNMP',
    '389': 'LDAP', '443': 'HTTPS', '445': 'SMB', '465': 'SMTPS', '587': 'Submission', '993': 'IMAPS',
    '1433': 'MSSQL', '1723': 'PPTP', '1900': 'SSDP', '3306': 'MySQL', '3389': 'RDP', '5060': 'SIP',
    '5432': 'PostgreSQL', '5900': 'VNC', '6379': 'Redis', '8080': 'HTTP-alt', '8443': 'HTTPS-alt',
    '51820': 'WireGuard',
}
_LABEL_RE = re.compile(r'label "([0-9a-f]{32}|[0-9a-f-]{36})"\s*(?:#\s*(.*))?$')


class Query:
    def __init__(self, ctx=None):
        self.ctx = ctx or common.Context()
        self._cfg = None
        self._settings = None

    # -------------------------------------------------------------- helpers

    def _con(self, kind):
        return common.connect_ro(self.ctx.db[kind])

    def _range(self, since, until):
        now = self.ctx.clock()
        s = common.parse_time(since, now)
        u = common.parse_time(until, now, end=True)
        if u is None or until == 'now':
            u = now + 1                    # "until now" includes the sample taken right now
        if s is None:
            s = u - 86400
        if s >= u:
            raise ValueError('empty range')
        return s, u

    def _config(self):
        if self._cfg is None:
            self._cfg = common.load_config(self.ctx)
        return self._cfg

    def _ifaces(self):
        return common.interfaces(self._config())

    def _blocks_where(self, wan_only=False, direction=None, iface=None):
        clauses, args = [], []
        if wan_only:
            wan = common.wan_devices(self._config())
            if wan:
                clauses.append('iface IN (%s)' % ','.join('?' * len(wan)))
                args.extend(wan)
        if direction:
            clauses.append('dir = ?')
            args.append(direction)
        if iface:
            clauses.append('iface = ?')
            args.append(iface)
        return clauses, args

    def _union(self, table, s, u, columns, clauses, args):
        """ SELECT over the hourly table (hour in range) UNION ALL the daily table (day in range) """
        hourly_where = ' AND '.join(['hour >= ? AND hour < ?'] + clauses)
        daily_where = ' AND '.join(['day >= ? AND day <= ?'] + clauses)
        sql = ('SELECT %s FROM %s_hourly WHERE %s UNION ALL SELECT %s FROM %s_daily WHERE %s' % (
            columns.replace('{T}', 'hour'), table, hourly_where,
            columns.replace('{T}', "CAST(strftime('%s', day, 'utc') AS INTEGER)"), table, daily_where))
        return sql, [int(s), int(u)] + args + [common.day_of(s), common.day_of(u - 1)] + args

    @staticmethod
    def _point(ts, **values):
        return dict(t=common.iso(ts), ts=int(ts), **values)

    def _series(self, rows, s, u, bucket, names):
        """ rows: [(epoch, is_daily, values...)] -> filled list of points """
        if bucket not in ('hour', 'day'):
            raise ValueError('bucket: hour or day')
        acc = {}
        daily_keys = set()
        for row in rows:
            ts, daily = row[0], row[1]
            if daily:
                key = int(ts)                      # daily rows carry their local midnight
                if bucket == 'hour':
                    daily_keys.add(key)
            elif bucket == 'day':
                key = int(common.local_midnight(ts))
            else:
                key = common.hour_of(ts)
            cur = acc.setdefault(key, [0] * len(names))
            for i, v in enumerate(row[2:]):
                cur[i] += v or 0
        out = []
        if bucket == 'hour':
            t = common.hour_of(s)
            keys = set(range(t, int(u), 3600)) | set(acc)
        else:
            keys = set()
            t = common.local_midnight(s)
            while t < u:
                keys.add(int(t))
                t = common.day_start(common.day_of(t + 90000))
            keys |= set(acc)
        for key in sorted(keys):
            values = acc.get(key, [0] * len(names))
            point = self._point(key, **dict(zip(names, values)))
            if key in daily_keys:
                point['daily'] = True
            out.append(point)
        return out

    # -------------------------------------------------------------- coverage

    def coverage(self):
        out = {}
        for kind in common.KINDS:
            con = self._con(kind)
            info = {'available': con is not None, 'size_mb': common.db_size_mb(self.ctx.db[kind])}
            if con is not None:
                try:
                    info['last_run'] = common.meta_get(con, 'last_run')
                    if kind == 'flows':
                        info['blocks_since'] = common.iso(common.meta_get(con, 'blocks_since'))
                        info['dns_since'] = common.iso(common.meta_get(con, 'dns_since'))
                        for table in ('blocks', 'dns'):
                            h = con.execute('SELECT min(hour), max(hour) FROM %s_hourly' % table).fetchone()
                            d = con.execute('SELECT min(day), max(day) FROM %s_daily' % table).fetchone()
                            info[table] = {'hourly': [common.iso(h[0]), common.iso(h[1])] if h[0] else None,
                                           'daily': list(d) if d[0] else None}
                    elif kind == 'health':
                        info['local_since'] = common.iso(common.meta_get(con, 'local_since'))
                        r = con.execute('SELECT min(ts), max(ts), count(DISTINCT ts) FROM metrics').fetchone()
                        info['hourly'] = [common.iso(r[0]), common.iso(r[1]), r[2]] if r[0] else None
                        d = con.execute('SELECT min(day), max(day) FROM metrics_daily').fetchone()
                        info['daily'] = list(d) if d[0] else None
                    else:
                        r = con.execute('SELECT min(revision_time), max(revision_time), count(*) FROM snapshots'
                                        ).fetchone()
                        info['snapshots'] = [common.iso(r[0]), common.iso(r[1]), r[2]] if r[2] else None
                        info['changes'] = con.execute('SELECT count(*) FROM changes').fetchone()[0]
                    info['imports'] = [{'id': i, 'file': f, 'imported_at': common.iso(a), 'counts': json.loads(c or '{}'),
                                        'undone_at': common.iso(un)} for i, f, a, c, un in con.execute(
                        'SELECT id, file, imported_at, counts, undone_at FROM imports ORDER BY imported_at')]
                finally:
                    con.close()
            out[kind] = info
        return out

    # -------------------------------------------------------------- blocks

    def blocks_series(self, since='24h', until=None, bucket='hour', wan_only=False, direction=None, iface=None):
        s, u = self._range(since, until)
        con = self._con('flows')
        if con is None:
            return self._series([], s, u, bucket, ['blocks'])
        clauses, args = self._blocks_where(wan_only, direction, iface)
        where = ''.join(' AND ' + c for c in clauses)
        rows = [(r[0], False, r[1]) for r in con.execute(
            'SELECT hour, sum(n) FROM blocks_hourly WHERE hour >= ? AND hour < ?%s GROUP BY hour' % where,
            [int(s), int(u)] + args).fetchall()]
        rows += [(common.day_start(r[0]), True, r[1]) for r in con.execute(
            'SELECT day, sum(n) FROM blocks_daily WHERE day >= ? AND day <= ?%s GROUP BY day' % where,
            [common.day_of(s), common.day_of(u - 1)] + args).fetchall()]
        con.close()
        return self._series(rows, s, u, bucket, ['blocks'])

    def _top(self, table, s, u, select, group, order, limit, clauses, args):
        con = self._con('flows')
        if con is None:
            return []
        inner, params = self._union(table, s, u, select, clauses, args)
        sql = 'SELECT %s FROM (%s) GROUP BY %s ORDER BY %s LIMIT ?' % (group[1], inner, group[0], order)
        try:
            return con.execute(sql, params + [int(limit)]).fetchall()
        finally:
            con.close()

    def top_sources(self, since='24h', until=None, limit=10, wan_only=True, direction='in'):
        s, u = self._range(since, until)
        clauses, args = self._blocks_where(wan_only, direction)
        rows = self._top('blocks', s, u, 'src, dport, proto, cc, n', ('src', 'src, sum(n), count(DISTINCT dport '
                         "|| '/' || proto), max(cc)"), '2 DESC, 1', limit, clauses, args)
        return [{'ip': r[0], 'blocks': r[1], 'ports': r[2], 'country': r[3]} for r in rows]

    def top_countries(self, since='24h', until=None, limit=10, wan_only=True, direction='in'):
        s, u = self._range(since, until)
        clauses, args = self._blocks_where(wan_only, direction)
        rows = self._top('blocks', s, u, 'src, cc, n', ("coalesce(cc, '??')",
                         "coalesce(cc, '??'), sum(n), count(DISTINCT src)"), '2 DESC, 1', limit, clauses, args)
        return [{'country': r[0], 'blocks': r[1], 'sources': r[2]} for r in rows]

    def top_ports(self, since='24h', until=None, limit=10, wan_only=True, direction='in'):
        s, u = self._range(since, until)
        clauses, args = self._blocks_where(wan_only, direction)
        rows = self._top('blocks', s, u, 'src, dport, proto, n', ('dport, proto',
                         'dport, proto, sum(n), count(DISTINCT src)'), '3 DESC, 1', limit, clauses, args)
        return [{'port': r[0], 'proto': r[1], 'label': PORT_LABELS.get(r[0]) if r[0] else r[1],
                 'blocks': r[2], 'sources': r[3]} for r in rows]

    def rule_labels(self):
        labels = {}
        root = self._config()
        if root is not None:
            for xpath, field in (('./OPNsense/Firewall/Filter/rules/rule', 'description'), ('./filter/rule', 'descr')):
                for rule in root.findall(xpath):
                    if rule.get('uuid'):
                        labels[rule.get('uuid')] = (rule.findtext(field) or '').strip() or rule.get('uuid')
        try:
            with open(self.ctx.rules_debug, errors='replace') as handle:
                for line in handle:
                    if 'label "' not in line or line.lstrip().startswith('#'):
                        continue
                    m = _LABEL_RE.search(line.rstrip())
                    if m and m.group(1) not in labels:
                        labels[m.group(1)] = (m.group(2) or '').strip() or m.group(1)
        except OSError:
            pass
        return labels

    def top_rules(self, since='24h', until=None, limit=10):
        s, u = self._range(since, until)
        rows = self._top('blocks', s, u, 'rid, n', ('rid', 'rid, sum(n)'), '2 DESC, 1', limit, [], [])
        labels = self.rule_labels()
        return [{'rid': r[0], 'label': labels.get(r[0]), 'blocks': r[1]} for r in rows]

    def top_interfaces(self, since='24h', until=None, limit=10):
        s, u = self._range(since, until)
        rows = self._top('blocks', s, u, 'iface, n', ('iface', 'iface, sum(n)'), '2 DESC, 1', limit, [], [])
        ifaces = self._ifaces()
        return [{'iface': r[0], 'name': (ifaces.get(r[0]) or {}).get('descr'),
                 'wan': bool((ifaces.get(r[0]) or {}).get('wan')), 'blocks': r[1]} for r in rows]

    # -------------------------------------------------------------- DNS

    def dns_series(self, since='24h', until=None, bucket='hour'):
        s, u = self._range(since, until)
        con = self._con('flows')
        names = ['queries', 'blocked', 'nxdomain']
        if con is None:
            return self._series([], s, u, bucket, names)
        cols = "sum(n), sum(CASE WHEN action <> 'pass' THEN n ELSE 0 END), sum(nx)"
        rows = [(r[0], False) + tuple(r[1:]) for r in con.execute(
            'SELECT hour, %s FROM dns_hourly WHERE hour >= ? AND hour < ? GROUP BY hour' % cols,
            (int(s), int(u))).fetchall()]
        rows += [(common.day_start(r[0]), True) + tuple(r[1:]) for r in con.execute(
            'SELECT day, %s FROM dns_daily WHERE day >= ? AND day <= ? GROUP BY day' % cols,
            (common.day_of(s), common.day_of(u - 1))).fetchall()]
        con.close()
        return self._series(rows, s, u, bucket, names)

    @staticmethod
    def _dns_action(action):
        if action in (None, '', 'all'):
            return [], []
        if action in ('blocked', 'block'):
            return ["action <> 'pass'"], []
        if action == 'pass':
            return ["action = 'pass'"], []
        raise ValueError('action: all, pass or blocked')

    def top_domains(self, since='24h', until=None, limit=10, action='all', client=None):
        s, u = self._range(since, until)
        clauses, args = self._dns_action(action)
        if client:
            clauses.append('client = ?')
            args.append(client)
        rows = self._top('dns', s, u, 'domain, client, n', ('domain', 'domain, sum(n), count(DISTINCT client)'),
                         '2 DESC, 1', limit, clauses, args)
        return [{'domain': r[0], 'queries': r[1], 'clients': r[2]} for r in rows]

    def top_dns_clients(self, since='24h', until=None, limit=10, action='all'):
        s, u = self._range(since, until)
        clauses, args = self._dns_action(action)
        rows = self._top('dns', s, u, 'client, domain, action, n', (
            'client', "client, sum(n), sum(CASE WHEN action <> 'pass' THEN n ELSE 0 END), count(DISTINCT domain)"),
            '2 DESC, 1', limit, clauses, args)
        return [{'client': r[0], 'queries': r[1], 'blocked': r[2], 'domains': r[3]} for r in rows]

    # -------------------------------------------------------------- health

    def health_keys(self, pattern=None):
        con = self._con('health')
        if con is None:
            return []
        keys = sorted({r[0] for r in con.execute('SELECT DISTINCT key FROM metrics')} |
                      {r[0] for r in con.execute('SELECT DISTINCT key FROM metrics_daily')})
        con.close()
        return [k for k in keys if pattern is None or fnmatch.fnmatchcase(k, pattern)]

    def health_series(self, keys, since='7d', until=None, bucket='hour', agg='avg'):
        s, u = self._range(since, until)
        if isinstance(keys, str):
            keys = [k for k in keys.split(',') if k]
        if agg not in ('avg', 'max', 'min', 'last'):
            raise ValueError('agg: avg, max, min or last')
        if bucket not in ('hour', 'day'):
            raise ValueError('bucket: hour or day')
        all_keys = self.health_keys()
        wanted = []
        for k in keys:
            wanted.extend([x for x in all_keys if fnmatch.fnmatchcase(x, k)] if '*' in k else [k])
        con = self._con('health')
        out = {k: [] for k in wanted}
        if con is None:
            return out
        for key in wanted:
            points = {}
            rows = con.execute('SELECT ts, value FROM metrics WHERE key = ? AND ts >= ? AND ts < ? ORDER BY ts',
                               (key, int(s), int(u))).fetchall()
            for ts, value in rows:
                b = common.hour_of(ts) if bucket == 'hour' else int(common.local_midnight(ts))
                points.setdefault(b, []).append(value)
            col = {'avg': 'avg', 'max': 'max', 'min': 'min', 'last': 'last'}[agg]
            for day, value in con.execute('SELECT day, %s FROM metrics_daily WHERE key = ? AND day >= ? AND day <= ?'
                                          ' ORDER BY day' % col, (key, common.day_of(s), common.day_of(u - 1))):
                points.setdefault(int(common.day_start(day)), []).append(value)
            series = []
            for b in sorted(points):
                vals = [v for v in points[b] if v is not None]
                if not vals:
                    continue
                value = {'avg': sum(vals) / len(vals), 'max': max(vals), 'min': min(vals), 'last': vals[-1]}[agg]
                series.append(self._point(b, value=round(value, 3)))
            out[key] = series
        con.close()
        return out

    def health_latest(self):
        con = self._con('health')
        if con is None:
            return {'ts': None, 't': None, 'metrics': {}}
        ts = con.execute('SELECT max(ts) FROM metrics').fetchone()[0]
        metrics = dict(con.execute('SELECT key, value FROM metrics WHERE ts = ?', (ts,)).fetchall()) if ts else {}
        con.close()
        return {'ts': ts, 't': common.iso(ts), 'metrics': metrics}

    def health_events(self, since='7d', until=None, kind=None, limit=500):
        s, u = self._range(since, until)
        con = self._con('health')
        if con is None:
            return []
        sql = 'SELECT ts, kind, source, text FROM events WHERE ts >= ? AND ts < ?'
        args = [s, u]
        if kind:
            sql += ' AND kind = ?'
            args.append(kind)
        rows = con.execute(sql + ' ORDER BY ts LIMIT ?', args + [int(limit)]).fetchall()
        con.close()
        return [self._point(r[0], kind=r[1], source=r[2], text=r[3]) for r in rows]

    # -------------------------------------------------------------- config

    def config_revisions(self, since='30d', until=None):
        s, u = self._range(since, until)
        con = self._con('config')
        if con is None:
            return []
        rows = con.execute(
            'SELECT s.id, s.revision_time, s.author, s.author_ip, s.revision_descr, s.origin, '
            '(SELECT count(*) FROM changes c WHERE c.snapshot_after = s.id) FROM snapshots s '
            'WHERE s.revision_time >= ? AND s.revision_time < ? ORDER BY s.revision_time', (s, u)).fetchall()
        con.close()
        return [self._point(r[1], id=r[0], author=r[2], author_ip=r[3], description=r[4], origin=r[5],
                            changes=r[6]) for r in rows]

    def config_changes(self, since='30d', until=None, section=None, limit=2000):
        s, u = self._range(since, until)
        con = self._con('config')
        if con is None:
            return []
        sql = ('SELECT occurred_at, author, author_ip, revision_descr, section, key, kind, item_descr, fields, '
               'snapshot_before, snapshot_after, origin FROM changes WHERE occurred_at >= ? AND occurred_at < ?')
        args = [s, u]
        if section:
            sql += ' AND section LIKE ?'
            args.append(section.replace('*', '%'))
        rows = con.execute(sql + ' ORDER BY occurred_at, id LIMIT ?', args + [int(limit)]).fetchall()
        con.close()
        out = []
        for r in rows:
            try:
                fields = json.loads(r[8]) if r[8] else []
            except ValueError:
                fields = []
            out.append(self._point(r[0] or 0, author=r[1], author_ip=r[2], revision=r[3], section=r[4], key=r[5],
                                   kind=r[6], item=r[7], fields=fields, snapshot_before=r[9],
                                   snapshot_after=r[10], origin=r[11]))
        return out

    def config_diff(self, snapshot_a, snapshot_b, context=3, max_lines=4000):
        con = self._con('config')
        if con is None:
            return ''
        texts = []
        for sid in (snapshot_a, snapshot_b):
            row = con.execute('SELECT xml, revision_time FROM snapshots WHERE id = ?', (int(sid),)).fetchone()
            if row is None or row[0] is None:
                con.close()
                raise ValueError('snapshot %s has no stored XML' % sid)
            texts.append((zlib.decompress(row[0]).decode('utf-8', 'replace'), row[1]))
        con.close()
        a = _pretty(texts[0][0]).splitlines()
        b = _pretty(texts[1][0]).splitlines()
        diff = list(difflib.unified_diff(a, b, 'snapshot %s (%s)' % (snapshot_a, common.iso(texts[0][1])),
                                         'snapshot %s (%s)' % (snapshot_b, common.iso(texts[1][1])),
                                         n=int(context), lineterm=''))
        if len(diff) > max_lines:
            diff = diff[:max_lines] + ['... (%d more lines)' % (len(diff) - max_lines)]
        return '\n'.join(diff)

    # -------------------------------------------------------------- composites

    def summary(self, since='24h', until=None, limit=5):
        s, u = self._range(since, until)
        blocks = sum(p['blocks'] for p in self.blocks_series(s, u, bucket='day'))
        wan_in = sum(p['blocks'] for p in self.blocks_series(s, u, bucket='day', wan_only=True, direction='in'))
        dns = self.dns_series(s, u, bucket='day')
        health = self.health_series(['cpu_idle_pct', 'mem_used_pct', 'temp_cpu_max', 'pf_states'], s, u,
                                    bucket='day', agg='max')
        gw_loss = self.health_series(['gw:*:loss_pct'], s, u, bucket='day', agg='avg')
        return {
            'since': common.iso(s), 'until': common.iso(u),
            'blocks': {'total': blocks, 'wan_inbound': wan_in,
                       'top_sources': self.top_sources(s, u, limit), 'top_countries': self.top_countries(s, u, limit),
                       'top_ports': self.top_ports(s, u, limit), 'top_rules': self.top_rules(s, u, limit)},
            'dns': {'queries': sum(p['queries'] for p in dns), 'blocked': sum(p['blocked'] for p in dns),
                    'nxdomain': sum(p['nxdomain'] for p in dns),
                    'top_domains': self.top_domains(s, u, limit), 'top_blocked': self.top_domains(s, u, limit, 'blocked'),
                    'top_clients': self.top_dns_clients(s, u, limit)},
            'health': {'max_per_day': health, 'gateway_loss_avg': gw_loss,
                       'events': len(self.health_events(s, u))},
            'config': {'revisions': len(self.config_revisions(s, u)), 'changes': len(self.config_changes(s, u))},
        }

    def compare(self, since='7d', until=None):
        """ per local day totals (validation against the workstation while both collect) """
        s, u = self._range(since, until)
        days = {}
        for p in self.blocks_series(s, u, bucket='day'):
            days.setdefault(p['t'][:10], {})['blocks'] = p['blocks']
        for p in self.blocks_series(s, u, bucket='day', wan_only=True, direction='in'):
            days.setdefault(p['t'][:10], {})['blocks_wan_in'] = p['blocks']
        for p in self.dns_series(s, u, bucket='day'):
            d = days.setdefault(p['t'][:10], {})
            d['dns'] = p['queries']
            d['dns_blocked'] = p['blocked']
        for r in self.config_revisions(s, u):
            d = days.setdefault(r['t'][:10], {})
            d['config_revisions'] = d.get('config_revisions', 0) + 1
            d['config_changes'] = d.get('config_changes', 0) + r['changes']
        con = self._con('health')
        if con is not None:
            for day, n in con.execute("SELECT date(ts, 'unixepoch', 'localtime'), count(DISTINCT ts) FROM metrics "
                                      'WHERE ts >= ? AND ts < ? GROUP BY 1', (int(s), int(u))):
                days.setdefault(day, {})['health_samples'] = n
            con.close()
        for d in days.values():
            for k in ('blocks', 'blocks_wan_in', 'dns', 'dns_blocked', 'config_revisions', 'config_changes',
                      'health_samples'):
                d.setdefault(k, 0)
        return {'source': 'firewall', 'since': common.iso(s), 'until': common.iso(u),
                'days': dict(sorted(days.items()))}


def _pretty(xml_text):
    """ one element per line (the stored XML keeps the core's indentation already) """
    if xml_text.count('\n') > 10:
        return xml_text
    return re.sub(r'>\s*<', '>\n<', xml_text)


_DEFAULT = None


def _default():
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Query()
    return _DEFAULT


def _shortcut(name):
    def call(*args, **kwargs):
        return getattr(_default(), name)(*args, **kwargs)
    call.__name__ = name
    call.__doc__ = getattr(Query, name).__doc__
    return call


for _name in ('coverage', 'blocks_series', 'top_sources', 'top_countries', 'top_ports', 'top_rules',
              'top_interfaces', 'dns_series', 'top_domains', 'top_dns_clients', 'health_keys', 'health_series',
              'health_latest', 'health_events', 'config_revisions', 'config_changes', 'config_diff', 'summary',
              'compare'):
    globals()[_name] = _shortcut(_name)


# names usable from configd (cli.py query <name> ...): positional string arguments only
CLI = {
    'coverage': ('coverage', []),
    'blocks_series': ('blocks_series', ['since', 'until', 'bucket', 'wan_only', 'direction', 'iface']),
    'top_sources': ('top_sources', ['since', 'until', 'limit', 'wan_only', 'direction']),
    'top_countries': ('top_countries', ['since', 'until', 'limit', 'wan_only', 'direction']),
    'top_ports': ('top_ports', ['since', 'until', 'limit', 'wan_only', 'direction']),
    'top_rules': ('top_rules', ['since', 'until', 'limit']),
    'top_interfaces': ('top_interfaces', ['since', 'until', 'limit']),
    'dns_series': ('dns_series', ['since', 'until', 'bucket']),
    'top_domains': ('top_domains', ['since', 'until', 'limit', 'action', 'client']),
    'top_dns_clients': ('top_dns_clients', ['since', 'until', 'limit', 'action']),
    'health_keys': ('health_keys', ['pattern']),
    'health_series': ('health_series', ['keys', 'since', 'until', 'bucket', 'agg']),
    'health_latest': ('health_latest', []),
    'health_events': ('health_events', ['since', 'until', 'kind']),
    'config_revisions': ('config_revisions', ['since', 'until']),
    'config_changes': ('config_changes', ['since', 'until', 'section']),
    'config_diff': ('config_diff', ['snapshot_a', 'snapshot_b', 'context']),
    'summary': ('summary', ['since', 'until', 'limit']),
    'compare': ('compare', ['since', 'until']),
}
_ARG_RE = re.compile(r'^[A-Za-z0-9_.:*,/+-]{0,128}$')


def run_cli(q, name, args):
    if name not in CLI:
        raise ValueError('unknown query (%s)' % ', '.join(sorted(CLI)))
    method, params = CLI[name]
    kwargs = {}
    for param, value in zip(params, args):
        if value in ('', '-'):
            continue
        if not _ARG_RE.match(value):
            raise ValueError('invalid argument %s' % param)
        if param in ('limit', 'context'):
            value = int(value)
        elif param == 'wan_only':
            value = value in ('1', 'yes', 'true', 'wan')
        kwargs[param] = value
    started = time.monotonic()
    data = getattr(q, method)(**kwargs)
    return {'status': 'ok', 'query': name, 'args': kwargs, 'ms': int((time.monotonic() - started) * 1000),
            'data': data}
