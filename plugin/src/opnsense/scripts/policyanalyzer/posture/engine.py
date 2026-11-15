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

    Runs the checks, computes the posture score and keeps its history.

    Score (0-100): weighted share of the applicable checks that pass. Weight by the severity of the result
    (high 10, medium 5, low 2, info 0.5); credit pass 1, warn 0.5, fail 0; "na" is left out. A check that
    crashes counts as "na" with the error in its evidence (a bug never lowers or raises the score).
    Grade: A >= 90, B >= 80, C >= 70, D >= 60, else F.

    History: SQLite <db_dir>/posture.db, one row per run (score, counts) + one row per check result, so the
    page draws the trend and lists what changed since the previous run. Kept for 400 days.
"""

import os
import sqlite3
import time

from . import checks as checks_mod
from .common import iso_utc, load_json, now, write_json
from .sources import Context

VERSION = 1
WEIGHTS = {'high': 10.0, 'medium': 5.0, 'low': 2.0, 'info': 0.5}
CREDIT = {'pass': 1.0, 'warn': 0.5, 'fail': 0.0}
KEEP_DAYS = 400


def grade(score):
    if score is None:
        return None
    for limit, letter in ((90, 'A'), (80, 'B'), (70, 'C'), (60, 'D')):
        if score >= limit:
            return letter
    return 'F'


def score_of(results):
    total = 0.0
    got = 0.0
    for item in results:
        if item['result'] not in CREDIT:
            continue
        weight = WEIGHTS.get(item['severity'], 1.0)
        total += weight
        got += weight * CREDIT[item['result']]
    return round(100.0 * got / total, 1) if total else None


def counts_of(results):
    counts = {r: 0 for r in checks_mod.RESULTS}
    for item in results:
        counts[item['result']] = counts.get(item['result'], 0) + 1
    return counts


def run_checks(ctx, only=None):
    results = []
    for chk in checks_mod.CHECKS:
        if only and chk.id not in only:
            continue
        started = time.monotonic()
        try:
            out = chk.func(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
            out = {'result': 'na', 'summary': 'check failed: %s' % exc.__class__.__name__,
                   'evidence': {'error': str(exc)[:200]}}
        item = {
            'id': chk.id,
            'category': chk.category,
            'category_label': checks_mod.CATEGORIES.get(chk.category, chk.category),
            'title': chk.title,
            'severity': out.get('severity') or chk.severity,
            'default_severity': chk.severity,
            'result': out['result'],
            'summary': out.get('summary', ''),
            'evidence': out.get('evidence', {}),
            'recommendation': out.get('recommendation') or chk.recommendation,
            'references': chk.references,
            'page': chk.page,
            'ms': int((time.monotonic() - started) * 1000),
        }
        if out.get('fix') and out['result'] in ('fail', 'warn'):
            item['fix'] = out['fix']
        results.append(item)
    return results


def by_category(results):
    groups = {}
    for item in results:
        groups.setdefault(item['category'], []).append(item)
    out = {}
    for cat, items in groups.items():
        out[cat] = dict(counts_of(items), label=checks_mod.CATEGORIES.get(cat, cat), score=score_of(items))
    return out


SEV_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
RES_ORDER = {'fail': 0, 'warn': 1, 'pass': 2, 'na': 3}


def build_report(paths, runner=None, only=None):
    started = time.monotonic()
    ctx = Context(paths, runner)
    if ctx.root is None:
        return {'version': VERSION, 'kind': 'posture', 'status': 'error',
                'message': 'configuration not readable: %s' % paths.config}
    results = run_checks(ctx, only)
    results.sort(key=lambda r: (RES_ORDER.get(r['result'], 9), SEV_ORDER.get(r['severity'], 9), r['id']))
    score = score_of(results)
    fw = ctx.firmware if isinstance(ctx.firmware, dict) else {}
    return {
        'version': VERSION,
        'kind': 'posture',
        'status': 'ok',
        'generated': iso_utc(now()),
        'duration_ms': int((time.monotonic() - started) * 1000),
        'score': score,
        'grade': grade(score),
        'counts': counts_of(results),
        'by_category': by_category(results),
        'system': {'hostname': '%s.%s' % (ctx.text('system/hostname'), ctx.text('system/domain')),
                   'version': fw.get('product_version'), 'wan_interfaces': ctx.wan_interfaces},
        'policy_report': (ctx.report or {}).get('generated') if isinstance(ctx.report, dict) else None,
        'checks': results,
    }


# ------------------------------------------------------------------------------------------ history

class Store:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or '.', mode=0o750, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, score REAL, grade TEXT,
                pass INTEGER, warn INTEGER, fail INTEGER, na INTEGER, version TEXT);
            CREATE TABLE IF NOT EXISTS results (
                run_id INTEGER NOT NULL, check_id TEXT NOT NULL, result TEXT NOT NULL, severity TEXT,
                PRIMARY KEY (run_id, check_id));
            CREATE INDEX IF NOT EXISTS runs_ts ON runs (ts);
        ''')
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass

    def close(self):
        self.db.close()

    def record(self, report, ts=None):
        ts = int(ts if ts is not None else now())
        c = report['counts']
        with self.db:
            cur = self.db.execute('INSERT INTO runs (ts, score, grade, pass, warn, fail, na, version) VALUES '
                                  '(?, ?, ?, ?, ?, ?, ?, ?)', (ts, report['score'], report['grade'], c.get('pass', 0),
                                                               c.get('warn', 0), c.get('fail', 0), c.get('na', 0),
                                                               (report.get('system') or {}).get('version')))
            run_id = cur.lastrowid
            self.db.executemany('INSERT INTO results (run_id, check_id, result, severity) VALUES (?, ?, ?, ?)',
                                [(run_id, r['id'], r['result'], r['severity']) for r in report['checks']])
            limit = ts - KEEP_DAYS * 86400
            old = [row[0] for row in self.db.execute('SELECT id FROM runs WHERE ts < ?', (limit,))]
            if old:
                self.db.executemany('DELETE FROM results WHERE run_id = ?', [(i,) for i in old])
                self.db.execute('DELETE FROM runs WHERE ts < ?', (limit,))
        return run_id

    def previous(self, before_id):
        row = self.db.execute('SELECT id, ts, score, grade FROM runs WHERE id < ? ORDER BY id DESC LIMIT 1',
                              (before_id,)).fetchone()
        if not row:
            return None
        results = dict(self.db.execute('SELECT check_id, result FROM results WHERE run_id = ?', (row[0],)))
        return {'id': row[0], 'generated': iso_utc(row[1]), 'score': row[2], 'grade': row[3], 'results': results}

    def history(self, days=90, ts=None):
        since = int((ts if ts is not None else now()) - days * 86400)
        rows = self.db.execute('SELECT ts, score, grade, pass, warn, fail, na FROM runs WHERE ts >= ? ORDER BY ts',
                               (since,)).fetchall()
        return [{'ts': r[0], 'generated': iso_utc(r[0]), 'score': r[1], 'grade': r[2], 'pass': r[3], 'warn': r[4],
                 'fail': r[5], 'na': r[6]} for r in rows]


def changes(report, previous):
    """ what got worse / better since the previous run """
    if not previous:
        return {'new_failures': [], 'fixed': [], 'previous_score': None, 'delta': None}
    old = previous['results']
    worse, better = [], []
    rank = {'pass': 0, 'na': 0, 'warn': 1, 'fail': 2}
    for item in report['checks']:
        before = old.get(item['id'])
        if before is None:
            continue
        if rank.get(item['result'], 0) > rank.get(before, 0):
            worse.append({'id': item['id'], 'title': item['title'], 'from': before, 'to': item['result']})
        elif rank.get(item['result'], 0) < rank.get(before, 0):
            better.append({'id': item['id'], 'title': item['title'], 'from': before, 'to': item['result']})
    delta = None
    if report.get('score') is not None and previous.get('score') is not None:
        delta = round(report['score'] - previous['score'], 1)
    return {'new_failures': worse, 'fixed': better, 'previous_score': previous.get('score'),
            'previous_generated': previous.get('generated'), 'delta': delta}


def run(paths, runner=None, write=True):
    report = build_report(paths, runner)
    if report.get('status') != 'ok':
        return report
    if write:
        store = Store(paths.db('posture.db'))
        try:
            run_id = store.record(report)
            report['changes'] = changes(report, store.previous(run_id))
            report['trend'] = [h['score'] for h in store.history(30)][-30:]
        finally:
            store.close()
        write_json(paths.db('posture.json'), report)
    else:
        report['changes'] = changes(report, None)
        report['trend'] = []
    return report


def last(paths, runner=None):
    report = load_json(paths.db('posture.json'))
    if not isinstance(report, dict) or report.get('kind') != 'posture':
        return run(paths, runner)
    report['age_seconds'] = int(now() - _parse_iso(report.get('generated')))
    return report


def _parse_iso(text):
    try:
        import calendar
        return calendar.timegm(time.strptime(text, '%Y-%m-%dT%H:%M:%SZ'))
    except (TypeError, ValueError):
        return 0


def summary(report):
    """ light document for widgets (Max Cyber): score, grade, counts, the worst open items """
    if not isinstance(report, dict) or report.get('status') != 'ok':
        return {'status': (report or {}).get('status', 'none'), 'message': (report or {}).get('message')}
    worst = [c for c in report['checks'] if c['result'] == 'fail']
    worst.sort(key=lambda c: SEV_ORDER.get(c['severity'], 9))
    ch = report.get('changes') or {}
    return {
        'status': 'ok', 'kind': 'posture_summary', 'version': VERSION,
        'generated': report.get('generated'), 'age_seconds': report.get('age_seconds'),
        'score': report.get('score'), 'grade': report.get('grade'), 'counts': report.get('counts'),
        'delta': ch.get('delta'), 'new_failures': len(ch.get('new_failures') or []),
        'top': [{'id': c['id'], 'title': c['title'], 'severity': c['severity'], 'summary': c['summary']}
                for c in worst[:3]],
        'categories': {k: {'label': v['label'], 'score': v['score'], 'fail': v['fail']}
                       for k, v in (report.get('by_category') or {}).items()},
        'trend': (report.get('trend') or [])[-14:],
    }
