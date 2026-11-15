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

    Data of one report period, read only (every source is optional: a missing module gives
    {"available": false} and the section says so):

      posture        exposure.json summary (+ change since the previous report)
      quarantine     quarantine.db (read only): active entries per level, new / expired in the period,
                     offenses per reason, top repeat offenders
      findings       last.json of the Policy Analyzer: counts and the most severe titles
      traffic        filter log of the period (same reader as the AI brief, with a budget): blocked totals,
                     top ports, top sources, top countries (quarantine country index or quarantine offenses)
      cves           vulns/ prioritisation (P1..P4, KEV)
      devices        devices/ summary and the devices first seen in the period
      notifications  notifications sent in the period
      metrics        aggregated series for the charts of the PDF (metrics() below): every local SQLite base,
                     read only, short timeout, a missing base / table / column only drops that chart
"""

import bisect
import collections
import ipaddress
import json
import os
import sqlite3
import time

from . import common

LOG_BUDGET = {'max_bytes': 96 * 1024 * 1024, 'max_lines': 2000000, 'max_seconds': 25.0}
TOP = 5
REASONS = {1: 'base', 2: 'scan', 3: 'bait', 4: 'suricata', 5: 'manual'}


def _ro(path):
    if not os.path.exists(path):
        return None
    return sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=5)


def posture(previous=None):
    doc = common.load_json(common.paths()['exposure'])
    if not isinstance(doc, dict) or 'summary' not in doc:
        return {'available': False}
    s = doc['summary']
    gen = common.parse_iso(doc.get('generated'))
    out = {'available': True, 'posture': s.get('posture'), 'confidence': s.get('posture_confidence'),
           'services': s.get('services') or 0, 'reachable': s.get('reachable') or 0,
           'maybe_reachable': s.get('maybe_reachable') or 0, 'admin_reachable': s.get('admin_reachable') or 0,
           'cves_total': s.get('cves_total') or 0, 'kev': s.get('kev') or 0,
           'by_severity': s.get('by_severity') or {},
           'attack_surface': [{'service': a.get('label') or a.get('service'), 'proto': a.get('proto'),
                               'port': a.get('port'), 'reachable': a.get('internet_reachable'),
                               'cves': a.get('cves', 0), 'kev': a.get('kev', 0)}
                              for a in (s.get('attack_surface') or [])[:8]],
           'generated': doc.get('generated'),
           'age_hours': None if gen is None else round((common.now() - gen) / 3600.0, 1)}
    if previous:
        out['changed'] = previous.get('posture') != out['posture'] or previous.get('kev') != out['kev']
        out['previous'] = {'posture': previous.get('posture'), 'kev': previous.get('kev')}
    return out


def quarantine(since, until):
    db = _ro(common.paths()['quarantine_db'])
    if db is None:
        return {'available': False, 'installed': False}
    try:
        levels = dict(db.execute("SELECT level, count(*) FROM entries WHERE state IN ('active', 'permanent') "
                                 'GROUP BY level').fetchall())
        new = db.execute("SELECT count(*) FROM events WHERE kind = 'enter' AND ts >= ? AND ts < ?",
                         (since, until)).fetchone()[0]
        expired = db.execute("SELECT count(*) FROM events WHERE kind IN ('expire', 'release', 'guard_release') "
                             'AND ts >= ? AND ts < ?', (since, until)).fetchone()[0]
        reasons = dict(db.execute('SELECT reason, count(*) FROM offenses WHERE ts >= ? AND ts < ? GROUP BY reason',
                                  (since, until)).fetchall())
        top = db.execute('SELECT e.addr, e.level, e.country, e.asn, count(o.id) AS n, e.offenses '
                         'FROM offenses o JOIN entries e ON e.id = o.entry_id WHERE o.ts >= ? AND o.ts < ? '
                         'GROUP BY o.entry_id ORDER BY n DESC, e.offenses DESC LIMIT ?', (since, until, TOP)).fetchall()
        repeat = db.execute('SELECT addr, level, country, offenses FROM entries WHERE offenses > 1 '
                            "AND state IN ('active', 'permanent') ORDER BY offenses DESC, level DESC LIMIT ?",
                            (TOP,)).fetchall()
        countries = db.execute("SELECT country, count(*) FROM offenses WHERE ts >= ? AND ts < ? AND country != '' "
                               'GROUP BY country ORDER BY 2 DESC LIMIT ?', (since, until, TOP)).fetchall()
        paused = None
        try:
            row = db.execute("SELECT value FROM meta WHERE key = 'paused'").fetchone()
            paused = bool(row and row[0] in ('1', 'true'))
        except sqlite3.Error:
            pass
    except sqlite3.Error as exc:
        return {'available': False, 'installed': True, 'message': str(exc)}
    finally:
        db.close()
    return {'available': True, 'installed': True, 'paused': paused,
            'active': sum(levels.values()), 'by_level': {str(k): v for k, v in sorted(levels.items())},
            'new': new, 'expired': expired,
            'offenses': sum(reasons.values()), 'by_reason': {REASONS.get(k, str(k)): v for k, v in reasons.items()},
            'top_period': [{'addr': r[0], 'level': r[1], 'country': r[2], 'asn': r[3], 'offenses': r[4],
                            'total': r[5]} for r in top],
            'top_repeat': [{'addr': r[0], 'level': r[1], 'country': r[2], 'offenses': r[3]} for r in repeat],
            'countries': [{'country': r[0], 'offenses': r[1]} for r in countries]}


def findings():
    doc = common.load_json(common.paths()['findings'])
    if not isinstance(doc, dict) or 'summary' not in doc:
        return {'available': False}
    order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
    items = sorted(doc.get('findings') or [], key=lambda f: order.get(f.get('severity'), 9))
    return {'available': True, 'generated': doc.get('generated'), 'rules': doc['summary'].get('rules'),
            'findings': doc['summary'].get('findings'), 'by_severity': doc['summary'].get('by_severity') or {},
            'top': [{'severity': f.get('severity'), 'type': f.get('type'), 'title': f.get('title'),
                     'rule': ((f.get('rules') or [{}])[0]).get('summary')} for f in items[:TOP]
                    if f.get('severity') in ('high', 'medium')]}


class _Ctx(object):
    def __init__(self, path):
        self.lookup_db = path


def traffic(since, until, quarantine_data=None, now=None):
    try:
        from ai import brief
    except ImportError:
        return {'available': False}
    path = common.paths()['filter_log']
    if not os.path.exists(path):
        return {'available': False, 'message': 'filter log not found'}
    records, meta = brief.read_window(path, now=until, window=until - since, **LOG_BUDGET)
    wan = brief.wan_interfaces(common.paths()['config'])
    blocked = [r for r in records if r['action'] == 'block' and r['dir'] == 'in' and (not wan or r['iface'] in wan)]
    ports = collections.Counter('%s/%s' % (r['dport'], r['proto']) if r['dport'] else r['proto'] or '?'
                                for r in blocked)
    srcs = collections.Counter(r['src'] for r in blocked if r['src'])
    countries = collections.Counter()
    lookup = None
    if os.path.exists(common.paths()['quarantine_lookup']):
        try:
            from quarantine import lookup as qlookup
            lookup = qlookup.Lookup(_Ctx(common.paths()['quarantine_lookup']))
        except ImportError:
            lookup = None
    if lookup is not None and lookup.db is not None:
        for ip, count in srcs.items():
            try:
                cc, _asn = lookup.lookup(ipaddress.ip_address(ip))
            except ValueError:
                cc = None
            countries[cc or '??'] += count
        lookup.close()
        country_source = 'GeoIP index of the quarantine'
    elif quarantine_data and quarantine_data.get('countries'):
        for item in quarantine_data['countries']:
            countries[item['country']] += item['offenses']
        country_source = 'quarantine offenses'
    else:
        country_source = None
    hourly = collections.Counter(int(r['ts']) // 3600 * 3600 for r in blocked if r.get('ts'))
    return {'available': True, 'events': len(records), 'blocked_in': len(blocked),
            'timeline': sorted([k, v] for k, v in hourly.items()),
            'passed': sum(1 for r in records if r['action'] == 'pass'), 'distinct_sources': len(srcs),
            'top_ports': [{'port': k, 'blocked': v} for k, v in ports.most_common(TOP)],
            'top_sources': [{'addr': k, 'blocked': v} for k, v in srcs.most_common(TOP)],
            'top_countries': [{'country': k, 'blocked': v} for k, v in countries.most_common(TOP)],
            'country_source': country_source, 'complete': meta.get('complete'), 'lines_read': meta.get('lines_read')}


def cves():
    try:
        from vulns import prioritize
    except ImportError:
        return {'available': False}
    result = prioritize.build()
    if result.get('status') != 'ok':
        return {'available': False, 'message': result.get('message')}
    top = [i for i in result['items'] if i['priority'] in ('P1', 'P2')][:TOP] or result['items'][:3]
    matrix = {}
    for item in result['items']:
        cell = matrix.setdefault(cve_age(item.get('cve')), {})
        sev = cve_severity(item)
        cell[sev] = cell.get(sev, 0) + 1
    return {'available': True, 'counts': result['counts'], 'total': result['total'], 'kev': result['kev'],
            'by_age_severity': matrix,
            'review_pending': result['review_pending'],
            'top': [{'cve': i['cve'], 'package': i['package'], 'version': i['version'], 'priority': i['priority'],
                     'kev': bool(i['kev']), 'epss': i['epss'], 'cvss': i['cvss'], 'exposure': i['exposure']['class'],
                     'why': i['explanation'], 'fixed_in': i['fixed_in']} for i in top],
            'intel_kev': ((result.get('intel') or {}).get('kev') or {}).get('fetched')}


def cve_severity(item):
    """ severity of a CVE item: the feed value, else from the CVSS base score """
    sev = str(item.get('severity') or '').lower()
    if sev in ('critical', 'high', 'medium', 'low'):
        return sev
    if sev == 'moderate':
        return 'medium'
    try:
        cvss = float(item.get('cvss'))
    except (TypeError, ValueError):
        return 'info'
    return 'critical' if cvss >= 9 else 'high' if cvss >= 7 else 'medium' if cvss >= 4 else 'low'


def cve_age(cve, now=None):
    """ age bucket from the year of the id (the feeds carry no publication date): y0 | y1_2 | y3_5 | y6p | unknown """
    try:
        year = int(str(cve).split('-')[1])
    except (IndexError, ValueError):
        return 'unknown'
    age = time.localtime(now or common.now()).tm_year - year
    return 'y0' if age <= 0 else 'y1_2' if age <= 2 else 'y3_5' if age <= 5 else 'y6p'


def devices(since):
    try:
        from devices import inventory, view
    except ImportError:
        return {'available': False}
    try:
        inventory.ensure_fresh()
        summary = view.summary()
        new = view.new_since(since)
    except Exception as exc:                 # noqa: BLE001 - never break the report for one section
        return {'available': False, 'message': str(exc)[:200]}
    if summary.get('status') != 'ok':
        return {'available': False}
    return {'available': True, 'total': summary['total'], 'present': summary['present'],
            'unknown': summary['unknown'], 'by_risk': summary['by_risk'],
            'new': [{'name': d['name'] or '-', 'vendor': d['vendor'] or '-', 'type': d['type'],
                     'ip': ', '.join(d['ip4'][:2]), 'interface': d['iface_descr'], 'risk': d['risk']}
                    for d in new[:10]], 'new_count': len(new),
            'top_risk': summary['top_risk']}


def notifications(db, since, until):
    if db is None:
        return {'available': False}
    rows = db.execute('SELECT type, severity, count(*) FROM notifications WHERE ts >= ? AND ts < ? '
                      "AND status = 'sent' GROUP BY type, severity", (since, until)).fetchall()
    return {'available': True, 'sent': sum(r[2] for r in rows),
            'by_type': [{'type': r[0], 'severity': r[1], 'count': r[2]} for r in rows]}


# ------------------------------------------------------------------ metrics of the charts (local SQLite, read only)

METRIC_BUDGET = 3.0             # seconds of SQL per base (progress handler interrupts a longer query)
AUDIT_FILES = 4                 # ai.log + ai.log.1..3 (the audit log rotates at 1 MB)
AUDIT_MAX_BYTES = 6 * 1024 * 1024
CLOSED_STATES = ('resolved', 'false_positive')
QUARANTINE_LEVELS = ('1', '2', '3', '4', '5', '6')


def open_ro(path, budget=METRIC_BUDGET):
    """ read-only connection with a short lock timeout and a time budget; None when the base is missing """
    if not path or not os.path.exists(path):
        return None
    try:
        db = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=2)
    except sqlite3.Error:
        return None
    deadline = time.monotonic() + budget
    db.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 5000)
    return db


def query(db, sql, args=()):
    """ rows, or None when the table / column does not exist (old schema), the base is locked or the budget ran out """
    if db is None:
        return None
    try:
        return db.execute(sql, args).fetchall()
    except sqlite3.Error:
        return None


class Buckets(object):
    """ time buckets of a report period: 1 h up to 36 h (6 h / daily), 1 local day above (weekly) """

    def __init__(self, since, until):
        self.since, self.until = int(since), int(until)
        span = max(1, self.until - self.since)
        self.step = 3600 if span <= 36 * 3600 else 86400
        if self.step == 3600:
            first = self.since // 3600 * 3600
            self.starts = list(range(first, self.until, 3600))
        else:
            tm = time.localtime(self.since)
            day = time.mktime((tm.tm_year, tm.tm_mon, tm.tm_mday, 0, 0, 0, 0, 0, -1))
            self.starts = []
            offset = 0
            while True:
                start = int(time.mktime((tm.tm_year, tm.tm_mon, tm.tm_mday + offset, 0, 0, 0, 0, 0, -1)))
                if start >= self.until:
                    break
                self.starts.append(start)
                offset += 1
            if not self.starts:
                self.starts = [int(day)]

    def index(self, ts):
        ts = int(ts)
        if ts < self.since or ts >= self.until:
            return None
        return max(0, bisect.bisect_right(self.starts, ts) - 1)

    def series(self, pairs):
        """ [(ts, count)] -> counts per bucket """
        out = [0] * len(self.starts)
        for ts, count in pairs or []:
            i = self.index(ts)
            if i is not None:
                out[i] += count or 0
        return out

    def public(self):
        return {'step': self.step, 'starts': list(self.starts)}


def percentile(values, pct):
    """ nearest rank """
    values = sorted(v for v in values if v is not None)
    if not values:
        return None
    rank = max(1, int(-(-pct * len(values) // 100)))
    return values[min(rank, len(values)) - 1]


def _audit_ts(value):
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or '')
    for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S'):
        try:
            import datetime
            dt = datetime.datetime.strptime(text, fmt)
            return dt.timestamp() if dt.tzinfo else time.mktime(dt.timetuple())
        except ValueError:
            continue
    return common.parse_iso(text)


def audit_records(since, until):
    """ ok / error calls of the AI audit log in the period (only the numeric / route fields are kept) """
    base = common.paths()['ai_log']
    out = []
    budget = AUDIT_MAX_BYTES
    for idx in range(AUDIT_FILES):
        path = base if idx == 0 else '%s.%d' % (base, idx)
        try:
            with open(path, 'rb') as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - budget))
                chunk = handle.read(budget)
        except OSError:
            continue
        budget -= len(chunk)
        oldest = None
        for raw in chunk.decode('utf-8', 'replace').splitlines():
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get('status') not in ('ok', 'error'):
                continue
            ts = _audit_ts(rec.get('ts'))
            if ts is None:
                continue
            oldest = ts if oldest is None else min(oldest, ts)
            if since <= ts < until:
                out.append({'ts': ts, 'status': rec['status'], 'provider': rec.get('provider') or '?',
                            'model': rec.get('model') or '', 'scenario': rec.get('scenario') or rec.get('action') or '?',
                            'duration_ms': rec.get('duration_ms'), 'format_ok': not rec.get('problems')})
        if budget <= 0 or (oldest is not None and oldest < since):
            break
    return out


def _m_traffic(b, since, until, traffic_data):
    out = {}
    timeline = (traffic_data or {}).get('timeline')
    if traffic_data and traffic_data.get('available') and timeline:
        out = {'blocked': b.series(timeline), 'source': 'filter_log'}
    db = open_ro(common.paths()['incidents_db'])
    try:
        if not out:
            rows = query(db, "SELECT hour, blocked FROM port_hourly WHERE port = '*' AND hour >= ? AND hour < ?",
                         (since // 3600 * 3600, until))
            if rows:
                out = {'blocked': b.series(rows), 'source': 'incidents'}
        if out.get('source') == 'incidents':        # same source in both periods (the filter log has no past)
            span = until - since
            rows = query(db, "SELECT sum(blocked) FROM port_hourly WHERE port = '*' AND hour >= ? AND hour < ?",
                         (since - span, since))
            if rows and rows[0][0] is not None:
                out['previous'] = rows[0][0]
    finally:
        if db is not None:
            db.close()
    return out


def _m_quarantine(b, since, until):
    db = open_ro(common.paths()['quarantine_db'])
    if db is None:
        return {}
    out = {}
    try:
        rows = query(db, "SELECT v.ts, v.kind = 'upgrade' OR EXISTS (SELECT 1 FROM events p WHERE p.entry_id = v.entry_id "
                         "AND p.kind = 'enter' AND p.id < v.id) FROM events v WHERE v.kind IN ('enter', 'upgrade') "
                         'AND v.ts >= ? AND v.ts < ?', (since, until))
        if rows is not None:
            out['new'] = b.series((ts, 1) for ts, rep in rows if not rep)
            out['repeat'] = b.series((ts, 1) for ts, rep in rows if rep)
        rows = query(db, "SELECT ts / 900 * 900, count(*) FROM events WHERE kind IN ('expire', 'release', "
                         "'guard_release') AND ts >= ? AND ts < ? GROUP BY 1", (since, until))
        if rows is not None:
            out['released'] = b.series(rows)
        rows = query(db, "SELECT level, count(*) FROM events WHERE kind IN ('enter', 'upgrade', 'extend', 'permanent') "
                         'AND ts >= ? AND ts < ? GROUP BY level', (since, until))
        if rows is not None:
            out['by_duration'] = {str(min(int(k or 1), 6)): v for k, v in rows if k}
        rows = query(db, 'SELECT e.asn, count(*), count(DISTINCT o.entry_id) FROM offenses o JOIN entries e '
                         'ON e.id = o.entry_id WHERE o.ts >= ? AND o.ts < ? AND e.asn IS NOT NULL AND e.asn > 0 '
                         'GROUP BY e.asn ORDER BY 2 DESC LIMIT 8', (since, until))
        if rows:
            out['top_asn'] = [{'asn': r[0], 'offenses': r[1], 'sources': r[2]} for r in rows]
        rows = query(db, "SELECT count(*) FROM events WHERE kind = 'enter' AND ts >= ? AND ts < ?",
                     (since - (until - since), since))
        if rows:
            out['previous_new'] = rows[0][0]
    finally:
        db.close()
    return out


def _m_incidents(b, since, until):
    db = open_ro(common.paths()['incidents_db'])
    if db is None:
        return {}
    out = {}
    try:
        rows = query(db, 'SELECT created, severity FROM cases WHERE created >= ? AND created < ?', (since, until))
        if rows is None:
            return {}
        out['opened'] = dict(collections.Counter(r[1] for r in rows))
        out['opened_series'] = b.series((r[0], 1) for r in rows)
        closed = query(db, "SELECT c.severity, count(DISTINCT l.case_id) FROM case_log l JOIN cases c ON c.id = l.case_id "
                           "WHERE l.kind = 'state' AND l.to_state IN (?, ?) AND l.ts >= ? AND l.ts < ? GROUP BY c.severity",
                       CLOSED_STATES + (since, until))
        if closed is None:
            closed = query(db, 'SELECT severity, count(*) FROM cases WHERE state IN (?, ?) AND updated >= ? AND '
                               'updated < ? GROUP BY severity', CLOSED_STATES + (since, until))
        out['closed'] = dict(closed or [])
        rows = query(db, "SELECT severity, count(*) FROM cases WHERE state IN ('new', 'investigating') GROUP BY severity")
        out['open_now'] = dict(rows or [])
        rows = query(db, 'SELECT count(*) FROM cases WHERE created >= ? AND created < ?', (since - (until - since), since))
        if rows:
            out['previous'] = rows[0][0]
    finally:
        db.close()
    return out


def _m_anomalies(b, since, until):
    db = open_ro(common.paths()['anomalies_db'])
    if db is None:
        return {}
    out = {}
    try:
        rows = query(db, 'SELECT hour, sum(bytes_out) FROM host_hour WHERE hour >= ? AND hour < ? GROUP BY hour',
                     (since // 3600 * 3600, until))
        if rows:
            vol = [0] * len(b.starts)
            seen = [False] * len(b.starts)
            for hour, total in rows:
                i = b.index(max(hour, since))
                if i is not None:
                    vol[i] += total or 0
                    seen[i] = True
            out['volume'] = [v if seen[i] else None for i, v in enumerate(vol)]
        rows = query(db, 'SELECT ts, severity FROM occurrences WHERE ts >= ? AND ts < ?', (since, until))
        if rows is None:
            rows = query(db, 'SELECT last_seen, severity FROM findings WHERE last_seen >= ? AND last_seen < ?',
                         (since, until))
        if rows is not None:
            out['occurrences'] = b.series((r[0], 1) for r in rows)
            out['by_severity'] = dict(collections.Counter(r[1] for r in rows))
            flagged = set()
            for ts, sev in rows:
                i = b.index(ts)
                if i is not None and sev in ('high', 'medium', 'critical'):
                    flagged.add(i)
            out['flagged'] = sorted(flagged)
    finally:
        db.close()
    return out


def _m_devices(b, since, until):
    db = open_ro(common.paths()['devices_db'])
    if db is None:
        return {}
    out = {}
    try:
        rows = query(db, "SELECT first_seen, COALESCE(user_type, auto_type, 'unknown') FROM devices "
                         'WHERE first_seen >= ? AND first_seen < ?', (since, until))
        if rows is None:
            rows = query(db, "SELECT first_seen, COALESCE(auto_type, 'unknown') FROM devices WHERE first_seen >= ? "
                             'AND first_seen < ?', (since, until))
        if rows is not None:
            types = collections.Counter(r[1] for r in rows)
            out['new_by_type'] = {k: b.series((r[0], 1) for r in rows if r[1] == k) for k in types}
        rows = query(db, "SELECT COALESCE(user_type, auto_type, 'unknown'), count(*) FROM devices GROUP BY 1")
        if rows is None:
            rows = query(db, "SELECT COALESCE(auto_type, 'unknown'), count(*) FROM devices GROUP BY 1")
        if rows:
            out['by_type'] = dict(rows)
    finally:
        db.close()
    return out


def _m_posture(since, until):
    db = open_ro(common.paths()['posture_db'])
    if db is None:
        return {}
    window = max(14 * 86400, 4 * (until - since))
    try:
        rows = query(db, 'SELECT ts, score, grade, pass, warn, fail FROM runs WHERE ts >= ? AND ts < ? AND score IS NOT '
                         'NULL ORDER BY ts', (until - window, until))
        if rows is None:
            rows = [r + (None, None, None, None) for r in
                    query(db, 'SELECT ts, score FROM runs WHERE ts >= ? AND ts < ? ORDER BY ts',
                          (until - window, until)) or []]
    finally:
        db.close()
    if not rows:
        return {}
    daily = collections.OrderedDict()
    for row in rows:
        daily[time.strftime('%Y-%m-%d', time.localtime(row[0]))] = row          # the last run of each day
    last = rows[-1]
    return {'points': [[r[0], float(r[1])] for r in daily.values()], 'window_days': int(window // 86400),
            'last': {'score': float(last[1]), 'grade': last[2], 'pass': last[3], 'warn': last[4], 'fail': last[5]}}


def _m_ai(b, since, until):
    out = {}
    records = audit_records(since, until)
    jobs = []
    db = open_ro(common.paths()['ai_queue'])
    if db is not None:
        try:
            jobs = query(db, 'SELECT scenario, status, IFNULL(provider_used, provider), IFNULL(model_used, model), '
                             'created, started, finished, format_ok FROM jobs WHERE IFNULL(finished, created) >= ? '
                             'AND IFNULL(finished, created) < ?', (since, until)) or []
        finally:
            db.close()
    routes = {}
    latency = collections.defaultdict(list)
    formats = {}
    stamps = []
    for rec in records:
        label = rec['provider'] + (' · ' + rec['model'] if rec['model'] else '')
        cell = routes.setdefault(label, {'ok': 0, 'error': 0})
        cell[rec['status']] += 1
        stamps.append((rec['ts'], 1))
        if rec['status'] == 'ok':
            if rec['duration_ms'] is not None:
                latency[rec['scenario']].append(rec['duration_ms'] / 1000.0)
            fmt = formats.setdefault(rec['scenario'], {'ok': 0, 'total': 0})
            fmt['total'] += 1
            fmt['ok'] += 1 if rec['format_ok'] else 0
    if not records:
        for scenario, status, provider, model, created, started, finished, format_ok in jobs:
            if status not in ('done', 'error'):
                continue
            label = (provider or '?') + (' · ' + model if model else '')
            cell = routes.setdefault(label, {'ok': 0, 'error': 0})
            cell['ok' if status == 'done' else 'error'] += 1
            stamps.append((finished or created, 1))
            if status == 'done' and started and finished:
                latency[scenario].append(float(finished - started))
            if status == 'done' and format_ok is not None:
                fmt = formats.setdefault(scenario, {'ok': 0, 'total': 0})
                fmt['total'] += 1
                fmt['ok'] += 1 if format_ok else 0
    if routes:
        out['by_route'] = routes
        out['requests'] = b.series(stamps)
        out['source'] = 'audit' if records else 'queue'
    if latency:
        out['latency'] = {k: {'p50': percentile(v, 50), 'p90': percentile(v, 90), 'n': len(v)}
                          for k, v in latency.items()}
    if formats:
        out['format'] = formats
    if jobs:
        counts = collections.Counter(r[1] for r in jobs)
        waits = [r[5] - r[4] for r in jobs if r[5] and r[4]]
        out['queue'] = {'counts': dict(counts), 'wait_p50': percentile(waits, 50), 'jobs': len(jobs)}
    prev = audit_records(since - (until - since), since)
    if prev or records:
        out['previous'] = len(prev)
    db = open_ro(common.paths()['shadowai_db'])
    if db is not None:
        try:
            first = time.strftime('%Y-%m-%d', time.localtime(since))
            last = time.strftime('%Y-%m-%d', time.localtime(until - 1))
            rows = query(db, 'SELECT service, sum(IFNULL(dns, 0)) + sum(IFNULL(tls, 0)), sum(IFNULL(blocked, 0)), '
                             'count(DISTINCT host) FROM daily WHERE day >= ? AND day <= ? GROUP BY service '
                             'ORDER BY 2 DESC LIMIT 8', (first, last))
            if rows:
                out['shadow'] = [{'service': r[0], 'hits': r[1] or 0, 'blocked': r[2] or 0, 'hosts': r[3]}
                                 for r in rows if (r[1] or r[2])]
        finally:
            db.close()
    return out


def _m_collectors(b, since, until):
    """
    bases of the local collectors (<db>/collect/*.db): a base that exposes a table or view
    report_series(ts INTEGER, series TEXT, value REAL) is plotted (sum per bucket, up to 4 series per base)
    """
    directory = common.paths()['collect_dir']
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith('.db'))[:6]
    except OSError:
        return []
    out = []
    for name in names:
        db = open_ro(os.path.join(directory, name))
        if db is None:
            continue
        try:
            rows = query(db, 'SELECT series, ts / 900 * 900, sum(value) FROM report_series WHERE ts >= ? AND ts < ? '
                             'GROUP BY 1, 2', (since, until))
        finally:
            db.close()
        if not rows:
            continue
        per = collections.OrderedDict()
        for series, ts, value in rows:
            per.setdefault(str(series), []).append((ts, value or 0))
        top = sorted(per.items(), key=lambda kv: -sum(v for _t, v in kv[1]))[:4]
        out.append({'base': name[:-3], 'series': {k: b.series(v) for k, v in top}})
    return out


METRICS = (('traffic', 'traffic'), ('quarantine', 'quarantine'), ('incidents', 'incidents'),
           ('anomalies', 'anomalies'), ('devices', 'devices'), ('posture', 'posture'), ('ai', 'ai_usage'),
           ('collectors', 'collectors'))


def metrics(since, until, sections=None, traffic_data=None):
    """
    aggregated series of the charts (counts only, no address): every part is optional and an error in one never
    stops the others. sections=None collects everything (notification attachments)
    """
    b = Buckets(since, until)
    out = {'buckets': b.public()}
    for key, section in METRICS:
        if sections is not None and section not in sections:
            continue
        try:
            if key == 'traffic':
                value = _m_traffic(b, since, until, traffic_data)
            elif key == 'posture':
                value = _m_posture(since, until)
            else:
                value = globals()['_m_' + key](b, since, until)
        except Exception as exc:            # noqa: BLE001 - a broken base never breaks the report
            value = {'error': str(exc)[:200]}
        if value:
            out[key] = value
    return out


def build(kind, since, until, sections, db=None, previous_posture=None, charts=True):
    started = time.monotonic()
    data = {'kind': kind, 'since': since, 'until': until, 'generated': common.iso()}
    if 'posture' in sections:
        data['posture'] = posture(previous_posture)
    q = quarantine(since, until) if 'quarantine' in sections or 'traffic' in sections else None
    if 'quarantine' in sections:
        data['quarantine'] = q
    if 'findings' in sections:
        data['findings'] = findings()
    if 'traffic' in sections:
        data['traffic'] = traffic(since, until, q)
    if 'cves' in sections:
        data['cves'] = cves()
    if 'devices' in sections:
        data['devices'] = devices(since)
    if 'notifications' in sections:
        data['notifications'] = notifications(db, since, until)
    if charts:
        data['metrics'] = metrics(since, until, sections, data.get('traffic'))
    data['duration_ms'] = int((time.monotonic() - started) * 1000)
    return data


def has_events(data):
    """ "only when something happened" for the 6 h report """
    q = data.get('quarantine') or {}
    c = data.get('cves') or {}
    d = data.get('devices') or {}
    p = data.get('posture') or {}
    return bool(q.get('new') or (c.get('counts') or {}).get('P1') or d.get('new_count') or p.get('changed') or
                (data.get('notifications') or {}).get('sent'))
