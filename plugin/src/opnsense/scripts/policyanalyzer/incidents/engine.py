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

    The 5 minute correlation run and the read only views of the incident cases.

    Run (flock on incidents.lock, budget 20 s): read the new lines of the filter log and eve.json from their
    markers, the new quarantine offenses and the new blocked DNS queries; aggregate them into observations;
    refresh the per port hourly counters; evaluate the correlation rules; merge the matches into cases.  The
    observations, the markers and the cases are written in one transaction, so nothing is lost or counted twice.

    Case merging, by primary entity (external address, internal host or port):
      * an open case (new / investigating) of the entity, active within case_gap (6 h): updated;
      * a false positive of the entity active within fp_suppress (7 days): absorbs the match (evidence kept,
        "suppressed" counter, state unchanged);
      * otherwise a new case (previous_id = the last case of the entity, if any; factor "recurrence").

    Score (0-100, explainable: every point comes from a listed factor): the base points of the strongest rule of
    the case, +10 for every other rule that matched the same case, plus the factors of the matches (the highest
    value of each factor id is kept), +10 recurrence, -10 when the external address is already contained by the
    quarantine.  Severity: >= 70 critical, >= 50 high, >= 30 medium, else low.
"""

import fcntl
import json
import os
import time

from ai import brief as ai_brief
from quarantine import fwconfig, lookup as qlookup

from . import collect, common, rules as rules_mod, store as store_mod


class Lock:
    def __init__(self, path):
        self.path = path
        self.handle = None

    def acquire(self):
        os.makedirs(os.path.dirname(self.path), mode=0o750, exist_ok=True)
        self.handle = open(self.path, 'a+')
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            self.handle = None
            raise common.BusyError('another incidents run is in progress, try again in a moment')
        return self

    def release(self):
        if self.handle is not None:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None


def compute_score(rule_names, factors_by_id, recurrence=False, contained=False):
    """ :return: (score, factors list) with every point explained """
    ranked = sorted(rule_names, key=lambda r: (-common.RULES[r][0], common.RULE_ORDER.index(r)))
    factors = []
    if ranked:
        top = ranked[0]
        factors.append({'id': 'rule:' + top, 'label': 'Rule: %s' % top, 'points': common.RULES[top][0],
                        'detail': 'base points of the strongest rule'})
        for other in ranked[1:]:
            factors.append({'id': 'also:' + other, 'label': 'Also matched: %s' % other, 'points': 10,
                            'detail': 'more than one correlation rule for the same entity'})
    for fid in sorted(factors_by_id):
        if fid.startswith(('rule:', 'also:')) or fid in ('recurrence', 'contained'):
            continue
        factors.append(factors_by_id[fid])
    if recurrence:
        factors.append({'id': 'recurrence', 'label': 'Recurrence', 'points': 10,
                        'detail': 'the entity already had an earlier case'})
    if contained:
        factors.append({'id': 'contained', 'label': 'Already contained', 'points': -10,
                        'detail': 'the external address is in quarantine now'})
    score = max(0, min(common.SCORE_MAX, sum(f['points'] for f in factors)))
    return score, factors


def title_for(rule, vars_):
    template = common.RULES[rule][1]
    values = {'primary': '?', 'related': '?', 'sources': '?'}
    values.update({k: v for k, v in (vars_ or {}).items() if v is not None})
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template


class Engine:
    def __init__(self, ctx=None):
        self.ctx = ctx or common.Context()

    def now(self):
        return self.ctx.clock()

    def installed(self):
        return os.path.exists(self.ctx.db)

    def open(self, create=False, readonly=False):
        return store_mod.Store(self.ctx.db, create=create, readonly=readonly)

    def config(self):
        return fwconfig.FirewallConfig(self.ctx.config_xml)

    # ---------------------------------------------------------- enrichment

    def _rule_names(self, cfg):
        names = {}
        try:
            for r in cfg.rules():
                if r.get('uuid'):
                    names[r['uuid']] = r['description'] or ('%s rule %s' % (r['action'], r['uuid'][:8]))
        except Exception:                        # noqa: BLE001 - enrichment only
            pass
        return names

    def _exposure(self):
        report = ai_brief.load_json(self.ctx.exposure)
        out = {}
        try:
            for sv in ai_brief.exposure_inputs(report).get('internet_reachable_services') or []:
                key = common.port_key(sv.get('port'), sv.get('proto'))
                out[key] = str(sv.get('service') or '?')
        except Exception:                        # noqa: BLE001
            pass
        return out

    # ---------------------------------------------------------- the 5 minute run

    def run(self):
        started = time.monotonic()
        if not self.installed():
            return {'status': 'not_installed', 'message': 'the incident triage is not installed'}
        lock = Lock(self.ctx.lock_file)
        try:
            lock.acquire()
        except common.BusyError as exc:
            return {'status': 'busy', 'message': str(exc)}
        st = self.open()
        qv = collect.QuarantineView(self.ctx.quarantine_db)
        try:
            return self._run(st, qv, started)
        finally:
            qv.close()
            st.close()
            lock.release()

    def _run(self, st, qv, started):
        now = self.now()
        settings = st.settings()
        deadline = started + settings['budget']
        try:
            cfg = self.config()
            wan_devs = {w['dev'] for w in cfg.wan_interfaces()}
            own = set(cfg.static_addresses())
            rule_names = self._rule_names(cfg)
        except ValueError:
            cfg, wan_devs, own, rule_names = None, set(), set(), {}
        oldest = now - common.OBS_RETENTION
        obs = collect.Obs()

        records, f_marker, f_info = collect.read_filter(self.ctx, st.meta_json('marker_filter'), deadline=deadline,
                                                        now=now)
        f_counts = collect.classify_filter(records, wan_devs, oldest, obs)
        alerts, e_marker, e_info = collect.read_suricata(self.ctx, st.meta_json('marker_eve'), deadline=deadline)
        e_used = collect.classify_alerts(alerts, oldest, obs)
        qv.load_bad(now)
        offenses, q_mark = qv.new_offenses(st.meta_json('q_offense_id'), now)
        collect.classify_offenses(offenses, obs)
        dns_mark = st.meta_json('dns_mark')
        dns_rows, dns_mark_new, dns_info = collect.read_dns(
            self.ctx, dns_mark if dns_mark is not None else now - common.LOOKBACK, now)
        collect.classify_dns(dns_rows, obs)
        delta = obs.values()

        st.begin()
        try:
            st.add_obs(delta)
            hours = self._refresh_hourly(st, delta, now)
            w = rules_mod.Window(st, now, settings, delta, qv, rule_names=rule_names, own=own,
                                 exposure=self._exposure())
            matches = rules_mod.evaluate(w, offenses)
            merged = self._merge(st, w, matches, now)
            st.prune_obs(now - common.OBS_RETENTION)
            st.prune_hourly(now - common.HOURLY_RETENTION)
            st.set_meta('marker_filter', f_marker)
            st.set_meta('marker_eve', e_marker)
            st.set_meta('q_offense_id', q_mark)
            st.set_meta('dns_mark', dns_mark_new)
            result = {
                'status': 'ok', 'ts': common.iso(now), 'duration_ms': int((time.monotonic() - started) * 1000),
                'filter_log': dict({k: f_info.get(k) for k in ('records', 'bytes', 'complete', 'first_run', 'missing')},
                                   used=f_counts['used']),
                'suricata': dict({k: e_info.get(k) for k in ('alerts', 'bytes', 'complete', 'first_run', 'missing')},
                                 used=e_used),
                'quarantine': {'available': qv.available, 'offenses': len(offenses), 'watched': len(qv.bad)},
                'dns': dns_info, 'observations': len(delta), 'hours': hours, 'matches': len(matches),
                'cases_new': merged['new'], 'cases_updated': merged['updated'], 'suppressed': merged['suppressed'],
            }
            st.set_meta('last_run', result)
            st.commit()
        except Exception:
            st.rollback()
            raise
        return result

    def _refresh_hourly(self, st, delta, now):
        """ per port hourly counters of the hours touched by this run (+ the "*" row: the hour was observed) """
        hours = sorted({r['bucket'] - r['bucket'] % 3600 for r in delta if r['kind'] in ('in_block', 'in_pass')})
        if not hours:
            hour = int(now) - int(now) % 3600
            if not st.hourly('*', hour, hour + 1):
                st.set_hourly(hour, '*', 0, 0, 0, 0)      # a quiet hour is part of the baseline too
            return 0
        for hour in hours:
            rows = st.db.execute(
                "SELECT port, sum(n) AS events, sum(CASE WHEN kind = 'in_block' THEN n ELSE 0 END) AS blocked, "
                "sum(CASE WHEN kind = 'in_pass' THEN n ELSE 0 END) AS passed, count(DISTINCT src) AS sources "
                "FROM obs WHERE kind IN ('in_block', 'in_pass') AND bucket >= ? AND bucket < ? GROUP BY port",
                (hour, hour + 3600)).fetchall()
            total = [0, 0, 0]
            for r in rows:
                total[0] += r['events']
                total[1] += r['blocked']
                total[2] += r['passed']
                if r['events'] >= 5 or r['sources'] >= 3:
                    st.set_hourly(hour, r['port'], r['events'], r['blocked'], r['passed'], r['sources'])
            srcs = st.db.execute("SELECT count(DISTINCT src) FROM obs WHERE kind IN ('in_block', 'in_pass') AND "
                                 "bucket >= ? AND bucket < ?", (hour, hour + 3600)).fetchone()[0]
            st.set_hourly(hour, '*', total[0], total[1], total[2], srcs)
        return len(hours)

    # ---------------------------------------------------------- matches -> cases

    def _merge(self, st, w, matches, now):
        counts = {'new': 0, 'updated': 0, 'suppressed': 0}
        settings = w.settings
        applied = set()                 # (case, evidence key) already counted in this run (two rules, one fact)
        for m in matches:
            kind, value = m['primary']
            case = st.latest_case_for(kind, value)
            if case and case['state'] in common.OPEN_STATES and case['last_activity'] >= m['first'] - settings['case_gap']:
                mode = 'update'
            elif case and case['state'] == 'false_positive' and now - case['last_activity'] <= settings['fp_suppress']:
                mode = 'suppress'
            else:
                mode = 'new'
            if mode == 'new':
                case = st.create_case(now, title=title_for(m['rule'], m.get('vars')), rule=m['rule'],
                                      primary_kind=kind, primary_value=value, severity='low', score=0, factors=[],
                                      state='new', first_seen=int(m['first']), last_activity=int(m['last']),
                                      previous_id=case['id'] if case else None)
                st.set_entity(case['id'], kind, value, 'primary', m.get('primary_info'))
                st.log(case['id'], now, 'created', to_state='new',
                       note=('previous case #%d' % case['previous_id']) if case.get('previous_id') else None)
                counts['new'] += 1
            elif mode == 'suppress':
                counts['suppressed'] += 1
            else:
                counts['updated'] += 1
            first_time = not st.has_rule(case['id'], m['rule'])
            st.touch_rule(case['id'], m['rule'], m['first'], m['last'])
            if m.get('primary_info'):
                st.set_entity(case['id'], kind, value, 'primary', m['primary_info'])
            for rkind, rvalue, info in m.get('related') or []:
                if rvalue and (rkind, rvalue) != (kind, value):
                    st.set_entity(case['id'], rkind, rvalue, 'related', info)
            items = [(ev, False) for ev in m.get('evidence') or []]
            if first_time:
                items = [(ev, True) for ev in m.get('context') or []] + items
            for ev, is_context in items:
                mark = (case['id'], ev.get('key'))
                if ev.get('key') and not ev.get('replace'):
                    if mark in applied or (is_context and st.has_evidence(case['id'], ev['key'])):
                        continue
                    applied.add(mark)
                st.add_evidence(case['id'], ev.get('last') or now, ev['source'], ev['text'], rule=m['rule'],
                                key=ev.get('key'), count=ev.get('count') or 1, first=ev.get('first'),
                                last=ev.get('last'), data=ev.get('data'), replace=bool(ev.get('replace')))
            self._rescore(st, w, case['id'], m, now, suppressed=(mode == 'suppress'))
        return counts

    def _rescore(self, st, w, case_id, m, now, suppressed=False):
        case = st.case(case_id)
        factors = {f['id']: f for f in case['factors'] or []}
        for f in m.get('factors') or []:
            if f['id'] not in factors or f['points'] > factors[f['id']]['points']:
                factors[f['id']] = f
        rule_names = [r['rule'] for r in st.case_rules(case_id)]
        contained = False
        if case['primary_kind'] == 'ext' and w.quarantine:
            contained = bool((w.quarantine.find(case['primary_value']) or {}).get('active'))
        score, flist = compute_score(rule_names, factors, recurrence=bool(case['previous_id']), contained=contained)
        top = sorted(rule_names, key=lambda r: (-common.RULES[r][0], common.RULE_ORDER.index(r)))[0]
        fields = {'score': score, 'severity': common.severity_of(score), 'factors': flist, 'updated': int(now),
                  'last_activity': max(case['last_activity'], int(m['last'])),
                  'first_seen': min(case['first_seen'], int(m['first'])), 'matches': case['matches'] + 1}
        if top == m['rule'] and (top != case['rule'] or case['matches'] == 0):
            fields.update({'rule': top, 'title': title_for(top, m.get('vars'))})
        if suppressed:
            fields['suppressed'] = case['suppressed'] + 1
        if case['severity'] != fields['severity'] and case['matches'] > 0 and not suppressed and \
                common.SEVERITIES.index(fields['severity']) < common.SEVERITIES.index(case['severity']):
            st.log(case_id, now, 'escalated', note='%s -> %s (score %d)' % (case['severity'], fields['severity'], score))
        st.update_case(case_id, **fields)

    # ---------------------------------------------------------- read only views

    def _row(self, case, st=None):
        out = dict(case)
        for key in ('created', 'first_seen', 'last_activity', 'updated', 'summary_ts'):
            out[key + '_iso'] = common.iso(case.get(key))
        if st is not None:
            ents = st.entities(case['id'])
            out['entities'] = [{'kind': e['kind'], 'value': e['value'], 'role': e['role']} for e in ents[:8]]
            out['entity_count'] = len(ents)
            out['rules'] = [r['rule'] for r in st.case_rules(case['id'])]
        return out

    def status(self):
        now = self.now()
        out = {'status': 'ok', 'installed': self.installed(), 'generated': common.iso(now)}
        try:
            cfg = self.config()
            out['cron'] = [j for j in cfg.cron_jobs() if j['command'] == common.CRON_COMMAND]
        except ValueError:
            out['cron'] = []
        out['sources'] = {
            'filter_log': os.path.exists(self.ctx.filter_log), 'suricata': os.path.exists(self.ctx.eve),
            'quarantine': os.path.exists(self.ctx.quarantine_db), 'dns': os.path.exists(self.ctx.unbound_db)}
        if not out['installed']:
            return out
        st = self.open(readonly=True)
        try:
            out['counts'] = st.counts(now)
            out['last_run'] = st.meta_json('last_run')
            out['settings'] = st.settings()
            out['size'] = st.size()
            out['next_run'] = common.iso(now - now % 300 + 300)
        finally:
            st.close()
        return out

    def summary(self, limit=10):
        """ light, for the Max Cyber widget """
        now = self.now()
        if not self.installed():
            return {'status': 'ok', 'installed': False}
        st = self.open(readonly=True)
        try:
            counts = st.counts(now)
            _total, latest = st.search({'state': 'open'}, ('last_activity', 'desc'), 1, limit)
            return {'status': 'ok', 'installed': True, 'generated': common.iso(now),
                    'open': counts['open'], 'open_by_severity': counts['open_by_severity'],
                    'new_24h': counts['new_24h'], 'active_24h': counts['active_24h'], 'by_state': counts['by_state'],
                    'last_run': (st.meta_json('last_run') or {}).get('ts'),
                    'latest': [{'id': c['id'], 'title': c['title'], 'severity': c['severity'], 'score': c['score'],
                                'state': c['state'], 'rule': c['rule'],
                                'primary': {'kind': c['primary_kind'], 'value': c['primary_value']},
                                'last_activity': common.iso(c['last_activity'])} for c in latest]}
        finally:
            st.close()

    def search(self, filters, sort, page, rows):
        st = self.open(readonly=True)
        try:
            total, items = st.search(filters, sort, page, rows)
            return {'status': 'ok', 'total': total, 'rowCount': len(items), 'current': page,
                    'rows': [self._row(c, st) for c in items]}
        finally:
            st.close()

    def case_detail(self, case_id):
        st = self.open(readonly=True)
        try:
            case = st.case(case_id)
            if case is None:
                return {'status': 'error', 'message': 'case not found'}
            out = self._row(case)
            out['entities'] = st.entities(case_id)
            out['rules'] = st.case_rules(case_id)
            out['evidence'] = st.evidence(case_id)
            out['evidence_total'] = st.evidence_count(case_id)[0]
            out['notes'] = st.notes(case_id)
            out['log'] = st.case_log(case_id)
            out['summary'] = st.last_summary(case_id)
            return {'status': 'ok', 'case': out}
        finally:
            st.close()

    def country_of(self, text):
        """ country / ASN from the quarantine index (optional) """
        lk = qlookup.Lookup(self.ctx)
        try:
            return lk.lookup(common.addr(text))
        finally:
            lk.close()


def dumps(data):
    return json.dumps(data, ensure_ascii=False)
