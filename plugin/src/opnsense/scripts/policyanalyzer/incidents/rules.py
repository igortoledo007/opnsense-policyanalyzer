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

    Correlation rules (deterministic).  Every rule looks at the observations of the lookback window (2 h, plus
    the history it needs) but only fires for entities touched by the data of this run (the delta), and its
    evidence is built from the delta (plus, the first time the rule matches a case, from the earlier rows of
    the window), so counts are never added twice.

      scan_then_allowed  external source: >= scan_ports distinct blocked ports within scan_window (or a "scan"
                         offense of the quarantine), then an allowed inbound connection within follow_window
      ids_and_allowed    Suricata alert involving an external address and allowed traffic of the same address
                         (inbound on the WAN, or outbound from an internal host) within +- pair_window
      internal_to_bad    internal host: allowed or blocked traffic to an address quarantined now or in the last
                         30 days, >= 3 outbound connections blocked by a rule, or >= dns_min blocked DNS queries
      campaign           >= campaign_sources distinct external sources against one port in the last hour and
                         >= campaign_factor times the usual hourly number (median of the baseline)
      repeat_offender    quarantine offense of an address whose previous quarantine had already ended
      port_spike         events on one port in the last hour >= spike_min, >= spike_factor x the median hour and
                         > mean + 4 standard deviations of the baseline (needs baseline_hours of history)

    A match: {rule, primary: (kind, value), related: [(kind, value, info)], first, last, factors: [{id, label,
    points, detail}], evidence: [{source, key, text, count, first, last, data, replace}], vars (title)}.
"""

import collections
import statistics

from . import common

MAX_MATCHES = 50                 # per rule and run (strongest first)
OUT_BLOCK_MIN = 3


class Window:
    """ observations of the lookback window, the delta of this run and the enrichment sources """

    def __init__(self, store, now, settings, delta, quarantine, rule_names=None, own=None, exposure=None):
        self.store = store
        self.now = int(now)
        self.settings = settings
        self.since = self.now - common.LOOKBACK
        self.delta = {self.key(r): r for r in delta}
        self.quarantine = quarantine
        self.rule_names = rule_names or {}
        self.own = set(own or ())
        self.exposure = exposure or {}              # "port/proto" -> service label (internet reachable)
        self.touched_ext = set()
        self.touched_int = set()
        self.touched_ports = set()
        for r in delta:
            kind = r['kind']
            if kind in ('in_block', 'in_pass'):
                self.touched_ext.add(r['src'])
                self.touched_ports.add(r['port'])
                if r['dst'] and not common.is_external(common.addr(r['dst'])):
                    self.touched_int.add(r['dst'])
                elif r['dst']:
                    self.own.add(r['dst'])      # public address receiving inbound on the WAN: the firewall itself
            elif kind in ('out_pass', 'out_block'):
                self.touched_int.add(r['src'])
                self.touched_ext.add(r['dst'])
            elif kind == 'ids':
                self.touched_ext.update(a for a in (r['src'], r['dst']) if common.is_external(common.addr(a)))
                self.touched_int.update(a for a in (r['src'], r['dst']) if common.is_internal(common.addr(a)))
            elif kind == 'dns_block':
                self.touched_int.add(r['src'])
            elif kind == 'q_offense':
                self.touched_ext.add(r['src'])

    @staticmethod
    def key(r):
        return (r['bucket'], r['kind'], r['src'], r['dst'], r['port'], r['rid'])

    def split(self, rows):
        """ (prior rows: the window without this run's counts, new rows: the delta) """
        prior, new = [], []
        for r in rows:
            d = self.delta.get(self.key(r))
            if d is None:
                prior.append(r)
                continue
            new.append(d)
            rest = r['n'] - d['n']
            if rest > 0:
                p = dict(r)
                p['n'] = rest
                prior.append(p)
        return prior, new

    def rule_label(self, rid):
        if not rid:
            return None
        return self.rule_names.get(rid) or ('rule %s' % rid[:12])

    def entity_kind(self, text):
        ip = common.addr(text)
        if text in self.own:
            return 'own'
        if common.is_internal(ip):
            return 'int'
        return 'ext'


# ------------------------------------------------------------------ evidence text


def _top(counter, n=5):
    return ', '.join(k for k, _v in counter.most_common(n))


def _span(rows):
    return min(r['first'] for r in rows), max(r['last'] for r in rows)


def evidence_rows(w, rule, rows, group='default'):
    """ rows of one kind -> evidence items, aggregated so that a scan is one line, not one per port """
    items = []
    by = collections.defaultdict(list)
    for r in rows:
        kind = r['kind']
        if kind == 'in_block':
            key = (kind, r['src'])
        elif kind == 'in_pass' or kind == 'out_pass':
            key = (kind, r['src'], r['dst'], r['port'], r['rid'])
        elif kind == 'out_block':
            key = (kind, r['src'], r['dst'], r['rid'])
        elif kind == 'ids':
            key = (kind, r['src'], r['dst'], r['rid'])
        elif kind == 'dns_block':
            key = (kind, r['src'], r['label'] or '')
        elif kind == 'q_offense':
            key = (kind, r['src'], r['rid'])
        else:
            continue
        by[key].append(r)
    for key, group_rows in sorted(by.items(), key=lambda kv: _span(kv[1])[0]):
        kind = key[0]
        n = sum(r['n'] for r in group_rows)
        first, last = _span(group_rows)
        sample = group_rows[0]
        data = {'kind': kind}
        if kind == 'in_block':
            ports = collections.Counter()
            ifaces = collections.Counter()
            for r in group_rows:
                ports[r['port']] += r['n']
                if r.get('iface'):
                    ifaces[r['iface']] += r['n']
            text = '%d blocked inbound connection(s) from %s to %d port(s): %s' % (
                n, sample['src'], len(ports), _top(ports, 6))
            if ifaces:
                text += ' on %s' % _top(ifaces, 2)
            source = 'filter'
            data.update({'src': sample['src'], 'ports': len(ports)})
        elif kind == 'in_pass':
            rule_name = w.rule_label(sample['rid'])
            text = '%d allowed inbound connection(s) %s -> %s %s%s' % (
                n, sample['src'], sample['dst'], sample['port'], (' by rule "%s"' % rule_name) if rule_name else '')
            source = 'filter'
            data.update({'src': sample['src'], 'dst': sample['dst'], 'port': sample['port'], 'rid': sample['rid']})
        elif kind == 'out_pass':
            q = w.quarantine.find(sample['dst']) if w.quarantine else None
            text = '%d allowed outbound connection(s) %s -> %s %s%s' % (
                n, sample['src'], sample['dst'], sample['port'],
                (' (in quarantine, level %s)' % q['level'] if q and q.get('active') else
                 ' (quarantined in the last 30 days)' if q else ''))
            source = 'filter'
            data.update({'src': sample['src'], 'dst': sample['dst'], 'port': sample['port'], 'rid': sample['rid']})
        elif kind == 'out_block':
            ports = collections.Counter()
            for r in group_rows:
                ports[r['port']] += r['n']
            rule_name = w.rule_label(sample['rid'])
            text = '%d blocked outbound connection(s) %s -> %s (%s)%s' % (
                n, sample['src'], sample['dst'], _top(ports, 4), (' by rule "%s"' % rule_name) if rule_name else '')
            source = 'filter'
            data.update({'src': sample['src'], 'dst': sample['dst'], 'rid': sample['rid']})
        elif kind == 'ids':
            sev = min((r['sev'] for r in group_rows if r['sev'] is not None), default=None)
            text = 'IDS alert sid %s severity %s: %s (%s -> %s %s, %d time(s))' % (
                sample['rid'] or '?', sev if sev is not None else '?', sample['label'] or '?', sample['src'],
                sample['dst'], sample['port'], n)
            source = 'suricata'
            data.update({'src': sample['src'], 'dst': sample['dst'], 'sid': sample['rid'], 'severity': sev})
        elif kind == 'dns_block':
            domains = collections.Counter()
            for r in group_rows:
                domains[r['dst']] += r['n']
            text = '%d blocked DNS quer%s from %s for %d domain(s): %s%s' % (
                n, 'y' if n == 1 else 'ies', sample['src'], len(domains), _top(domains, 4),
                (' (blocklist %s)' % sample['label']) if sample['label'] else '')
            source = 'dns'
            data.update({'src': sample['src'], 'domains': [k for k, _v in domains.most_common(8)]})
        else:  # q_offense
            text = 'Quarantine offense (%s), level %s%s' % (
                sample['label'] or '?', sample['sev'] if sample['sev'] is not None else '?',
                (', ports %s' % sample['port']) if sample['port'] else '')
            source = 'quarantine'
            data.update({'src': sample['src'], 'level': sample['sev']})
        # the key does not depend on the rule: one fact is one line of the case, whatever rules saw it
        items.append({'source': source, 'key': 'ev|%s' % '|'.join(str(k) for k in key),
                      'text': text, 'count': n, 'first': first, 'last': last, 'data': data})
    return items


def _evidence(w, rule, rows, group='default'):
    """ (evidence of the new rows, evidence of the earlier rows of the window) """
    prior, new = w.split(rows)
    return evidence_rows(w, rule, new, group), evidence_rows(w, rule, prior, group)


def _factor(fid, label, points, detail=None):
    return {'id': fid, 'label': label, 'points': int(points), 'detail': detail}


def _volume_factor(n, label='volume'):
    points = 0
    for limit, value in ((1000, 10), (100, 6), (20, 3)):
        if n >= limit:
            points = value
            break
    return [_factor('volume', 'Event volume', points, '%d events' % n)] if points else []


def _exposure_factor(w, ports):
    hit = sorted({w.exposure[p] + ' (' + p + ')' for p in ports if p in w.exposure})
    if not hit:
        return []
    return [_factor('exposed', 'Internet reachable service of the firewall involved', 10, ', '.join(hit[:3]))]


def _related_ip(w, text, role_info=None):
    kind = w.entity_kind(text)
    info = dict(role_info or {})
    if kind == 'ext' and w.quarantine:
        q = w.quarantine.find(text)
        if q:
            info['quarantine'] = {k: q.get(k) for k in ('level', 'state', 'active', 'reason', 'until')}
    return (kind, text, info or None)


# ------------------------------------------------------------------ rules


def scan_windows(rows, window):
    """ earliest window of `window` seconds with the most distinct blocked ports: (distinct, first, last, ports) """
    by_bucket = collections.defaultdict(set)
    times = {}
    for r in rows:
        by_bucket[r['bucket']].add(r['port'])
        lo, hi = times.get(r['bucket'], (r['first'], r['last']))
        times[r['bucket']] = (min(lo, r['first']), max(hi, r['last']))
    buckets = sorted(by_bucket)
    best = (0, None, None, set())
    span = max(1, window // common.BUCKET)
    for i, start in enumerate(buckets):
        ports = set()
        last = start
        for b in buckets[i:]:
            if b >= start + span * common.BUCKET:
                break
            ports |= by_bucket[b]
            last = b
        if len(ports) > best[0]:
            best = (len(ports), times[start][0], times[last][1], ports)
    return best


def rule_scan_then_allowed(w):
    s = w.settings
    matches = []
    candidates = {r['src'] for r in w.store.obs(['in_pass'], w.since)} & w.touched_ext
    for src in sorted(candidates):
        passes = w.store.obs(['in_pass'], w.since, src=src)
        blocks = w.store.obs(['in_block'], w.since - s['follow_window'], src=src)
        distinct, s_first, s_last, ports = scan_windows(blocks, s['scan_window'])
        scan_source = 'filter'
        qscan = [r for r in w.store.obs(['q_offense'], w.since - s['follow_window'], src=src)
                 if 'scan' in (r['label'] or '').split('+')]
        if distinct < s['scan_ports']:
            if not qscan:
                continue
            s_first, s_last = _span(qscan)
            scan_source = 'quarantine'
        later = [p for p in passes if p['last'] >= s_first and p['first'] <= s_last + s['follow_window']]
        if not later:
            continue
        scan_rows = [b for b in blocks if b['last'] >= s_first - common.BUCKET and b['first'] <= s_last + common.BUCKET]
        new_pass, old_pass = _evidence(w, 'scan_then_allowed', later, 'pass')
        new_scan, old_scan = _evidence(w, 'scan_then_allowed', scan_rows + qscan, 'scan')
        if not new_pass and not new_scan:
            continue
        dsts = collections.Counter()
        rids = set()
        for p in later:
            dsts[p['dst']] += p['n']
            if p['rid']:
                rids.add(p['rid'])
        internal = [d for d in dsts if w.entity_kind(d) == 'int']
        factors = []
        if internal:
            factors.append(_factor('allowed_internal', 'The allowed connection reached an internal host', 15,
                                   ', '.join(sorted(internal)[:3])))
        if distinct >= 3 * s['scan_ports']:
            factors.append(_factor('wide_scan', 'Wide port scan', 5, '%d distinct ports' % distinct))
        factors += _exposure_factor(w, {p['port'] for p in later})
        related = [_related_ip(w, d, {'connections': n}) for d, n in dsts.most_common(5)]
        related += [('rule', rid, {'description': w.rule_label(rid)}) for rid in sorted(rids)[:5]]
        related += [('port', p['port'], None) for p in later[:5]]
        matches.append({
            'rule': 'scan_then_allowed', 'primary': ('ext', src), 'related': related,
            'first': min(s_first, min(p['first'] for p in later)), 'last': max(p['last'] for p in later),
            'factors': factors, 'evidence': new_scan + new_pass, 'context': old_scan + old_pass,
            'vars': {'primary': src}, 'strength': len(later) + distinct,
            'detail': {'scan_ports': distinct, 'scan_source': scan_source},
        })
    return matches


def rule_ids_and_allowed(w):
    s = w.settings
    matches = []
    alerts = w.store.obs(['ids'], w.since - s['pair_window'])
    by_ext = collections.defaultdict(list)
    for a in alerts:
        src_ip, dst_ip = common.addr(a['src']), common.addr(a['dst'])
        if common.is_external(src_ip) and a['src'] not in w.own:
            by_ext[a['src']].append(a)
        elif common.is_external(dst_ip) and a['dst'] not in w.own:
            by_ext[a['dst']].append(a)
    for ext in sorted(by_ext):
        if ext not in w.touched_ext and not any(a['src'] in w.touched_int or a['dst'] in w.touched_int
                                               for a in by_ext[ext]):
            continue
        ext_alerts = by_ext[ext]
        a_first, a_last = _span(ext_alerts)
        lo, hi = a_first - s['pair_window'], a_last + s['pair_window']
        inbound = [r for r in w.store.obs(['in_pass'], lo, src=ext) if r['first'] <= hi]
        outbound = [r for r in w.store.obs(['out_pass'], lo, dst=ext) if r['first'] <= hi]
        if not inbound and not outbound:
            continue
        new_ids, old_ids = _evidence(w, 'ids_and_allowed', ext_alerts, 'ids')
        new_t, old_t = _evidence(w, 'ids_and_allowed', inbound + outbound, 'traffic')
        if not new_ids and not new_t:
            continue
        sev = min((a['sev'] for a in ext_alerts if a['sev'] is not None), default=3)
        hosts = collections.Counter()
        for r in inbound:
            hosts[r['dst']] += r['n']
        for r in outbound:
            hosts[r['src']] += r['n']
        factors = []
        if sev <= 1:
            factors.append(_factor('ids_sev1', 'IDS severity 1', 20, None))
        elif sev == 2:
            factors.append(_factor('ids_sev2', 'IDS severity 2', 10, None))
        alert_ports = {a['port'] for a in ext_alerts}
        same_port = sorted({r['port'] for r in inbound if r['port'] in alert_ports})
        if same_port:
            factors.append(_factor('same_port', 'Allowed traffic on the port of the alert', 10, ', '.join(same_port[:3])))
        internal = [h for h in hosts if w.entity_kind(h) == 'int']
        if internal:
            factors.append(_factor('allowed_internal', 'Traffic with an internal host was allowed', 15,
                                   ', '.join(sorted(internal)[:3])))
        factors += _exposure_factor(w, alert_ports | {r['port'] for r in inbound})
        sigs = collections.Counter()
        for a in ext_alerts:
            sigs['%s (sid %s)' % (a['label'] or '?', a['rid'] or '?')] += a['n']
        related = [_related_ip(w, h, {'connections': n}) for h, n in hosts.most_common(5)]
        related += [('rule', r['rid'], {'description': w.rule_label(r['rid'])}) for r in inbound if r['rid']][:3]
        matches.append({
            'rule': 'ids_and_allowed', 'primary': ('ext', ext), 'related': related,
            'first': min(a_first, min(r['first'] for r in inbound + outbound)),
            'last': max(a_last, max(r['last'] for r in inbound + outbound)),
            'factors': factors, 'evidence': new_ids + new_t, 'context': old_ids + old_t,
            'vars': {'primary': ext, 'related': (hosts.most_common(1)[0][0] if hosts else '?')},
            'strength': (4 - sev) * 100 + sum(hosts.values()),
            'detail': {'severity': sev, 'signatures': [k for k, _v in sigs.most_common(3)]},
        })
    return matches


def rule_internal_to_bad(w):
    s = w.settings
    matches = []
    for host in sorted(w.touched_int):
        if w.entity_kind(host) != 'int':
            continue
        out_pass = w.store.obs(['out_pass'], w.since, src=host)
        out_block = w.store.obs(['out_block'], w.since, src=host)
        dns = w.store.obs(['dns_block'], w.since, src=host)
        bad_pass = [r for r in out_pass if w.quarantine and w.quarantine.find(r['dst'])]
        bad_block = [r for r in out_block if w.quarantine and w.quarantine.find(r['dst'])]
        blocked_n = sum(r['n'] for r in out_block)
        dns_n = sum(r['n'] for r in dns)
        reasons = []
        rows = []
        factors = []
        if bad_pass:
            reasons.append('allowed traffic to a quarantined address')
            rows += bad_pass
            factors.append(_factor('allowed_to_bad', 'Traffic to a quarantined address was allowed', 15,
                                   ', '.join(sorted({r['dst'] for r in bad_pass})[:3])))
        if bad_block:
            reasons.append('blocked traffic to a quarantined address')
            rows += bad_block
        if blocked_n >= OUT_BLOCK_MIN:
            reasons.append('outbound connections blocked by a rule')
            rows += [r for r in out_block if r not in bad_block]
        if dns_n >= s['dns_min']:
            reasons.append('blocked DNS queries')
            rows += dns
            factors.append(_factor('dns', 'Blocked DNS queries (blocklist)', 5 if dns_n < 50 else 10,
                                   '%d queries' % dns_n))
        if not reasons:
            continue
        new, old = _evidence(w, 'internal_to_bad', rows)
        if not new:
            continue
        dsts = collections.Counter()
        for r in rows:
            if r['kind'] in ('out_pass', 'out_block'):
                dsts[r['dst']] += r['n']
        active_q = [d for d in dsts if w.quarantine and (w.quarantine.find(d) or {}).get('active')]
        if active_q:
            factors.append(_factor('active_quarantine', 'Destination is in quarantine right now', 5,
                                   ', '.join(sorted(active_q)[:3])))
        factors += _volume_factor(sum(r['n'] for r in rows))
        related = [_related_ip(w, d, {'connections': n}) for d, n in dsts.most_common(6)]
        related += [('rule', rid, {'description': w.rule_label(rid)})
                    for rid in sorted({r['rid'] for r in out_block if r['rid']})[:3]]
        matches.append({
            'rule': 'internal_to_bad', 'primary': ('int', host), 'related': related,
            'first': min(r['first'] for r in rows), 'last': max(r['last'] for r in rows),
            'factors': factors, 'evidence': new, 'context': old, 'vars': {'primary': host},
            'strength': len(bad_pass) * 100 + blocked_n + dns_n, 'detail': {'reasons': reasons},
        })
    return matches


def _baseline(w, port, hour, metric):
    """ values of the metric for every observed hour before `hour` (missing rows of observed hours = 0) """
    start = hour - 7 * 86400
    observed = {r['hour'] for r in w.store.hourly('*', start, hour)}
    values = {r['hour']: r[metric] for r in w.store.hourly(port, start, hour)}
    return [values.get(h, 0) for h in sorted(observed)]


def _port_window(w, since):
    """ per port: distinct sources, events, blocked, passed in [since, now] (inbound on the WAN) """
    rows = w.store.db.execute(
        "SELECT port, count(DISTINCT src) AS sources, sum(n) AS events, "
        "sum(CASE WHEN kind = 'in_block' THEN n ELSE 0 END) AS blocked, "
        "sum(CASE WHEN kind = 'in_pass' THEN n ELSE 0 END) AS passed, min(first) AS first, max(last) AS last "
        "FROM obs WHERE kind IN ('in_block', 'in_pass') AND bucket >= ? GROUP BY port",
        (int(since) - int(since) % common.BUCKET,)).fetchall()
    return {r['port']: dict(r) for r in rows}


def _top_sources(w, port, since, n=5):
    rows = w.store.db.execute(
        "SELECT src, sum(n) AS c FROM obs WHERE kind IN ('in_block', 'in_pass') AND port = ? AND bucket >= ? "
        "GROUP BY src ORDER BY c DESC LIMIT ?", (port, int(since) - int(since) % common.BUCKET, int(n))).fetchall()
    return [(r['src'], r['c']) for r in rows]


def rule_campaign(w, ports=None):
    s = w.settings
    matches = []
    hour = w.now - w.now % 3600
    since = w.now - 3600
    ports = ports if ports is not None else _port_window(w, since)
    for port in sorted(w.touched_ports):
        p = ports.get(port)
        if not p or p['sources'] < s['campaign_sources']:
            continue
        base = _baseline(w, port, hour, 'sources')
        enough = len(base) >= s['baseline_hours']
        median = statistics.median(base) if base else 0
        need = s['campaign_factor'] * max(1, median) if enough else s['campaign_sources'] * s['campaign_factor']
        if p['sources'] < need:
            continue
        top = _top_sources(w, port, since)
        factors = []
        if p['passed']:
            factors.append(_factor('some_allowed', 'Part of the campaign was allowed', 15, '%d allowed' % p['passed']))
        factors += _exposure_factor(w, {port})
        factors += _volume_factor(p['events'])
        text = '%d distinct sources against %s in the last hour (usual: %s per hour), %d blocked, %d allowed; ' \
               'top sources: %s' % (p['sources'], port, ('%g' % median) if enough else 'no baseline yet',
                                    p['blocked'], p['passed'], ', '.join(a for a, _c in top))
        evidence = [{'source': 'filter', 'key': 'campaign|%d' % hour, 'text': text, 'count': p['sources'],
                     'first': p['first'], 'last': p['last'], 'replace': True,
                     'data': {'kind': 'campaign', 'port': port, 'sources': p['sources'], 'events': p['events'],
                              'blocked': p['blocked'], 'passed': p['passed'], 'baseline_median': median,
                              'baseline_hours': len(base)}}]
        related = [_related_ip(w, a, {'events': c}) for a, c in top]
        matches.append({
            'rule': 'campaign', 'primary': ('port', port), 'related': related, 'first': p['first'], 'last': p['last'],
            'factors': factors, 'evidence': evidence, 'context': [], 'vars': {'primary': port, 'sources': p['sources']},
            'strength': p['sources'], 'detail': {'sources': p['sources'], 'baseline_median': median},
        })
    return matches


def rule_port_spike(w, ports=None):
    s = w.settings
    matches = []
    hour = w.now - w.now % 3600
    since = w.now - 3600
    ports = ports if ports is not None else _port_window(w, since)
    for port in sorted(w.touched_ports):
        p = ports.get(port)
        if not p or p['events'] < s['spike_min']:
            continue
        base = _baseline(w, port, hour, 'events')
        if len(base) < s['baseline_hours']:
            continue
        median = statistics.median(base)
        mean = statistics.fmean(base)
        sigma = statistics.pstdev(base)
        if p['events'] < s['spike_factor'] * max(1, median) or p['events'] <= mean + 4 * sigma:
            continue
        factors = _exposure_factor(w, {port})
        if p['passed']:
            factors.append(_factor('some_allowed', 'Part of the traffic was allowed', 10, '%d allowed' % p['passed']))
        ratio = p['events'] / max(1.0, median)
        if ratio >= 20:
            factors.append(_factor('spike_ratio', 'Far above the usual hour', 10, '%.0fx the median' % ratio))
        text = '%d events on %s in the last hour (median %g, mean %.1f, sigma %.1f over %d hours), %d sources, ' \
               '%d allowed' % (p['events'], port, median, mean, sigma, len(base), p['sources'], p['passed'])
        evidence = [{'source': 'filter', 'key': 'spike|%d' % hour, 'text': text, 'count': p['events'],
                     'first': p['first'], 'last': p['last'], 'replace': True,
                     'data': {'kind': 'spike', 'port': port, 'events': p['events'], 'median': median, 'mean': mean,
                              'sigma': sigma, 'hours': len(base)}}]
        related = [_related_ip(w, a, {'events': c}) for a, c in _top_sources(w, port, since, 3)]
        matches.append({
            'rule': 'port_spike', 'primary': ('port', port), 'related': related, 'first': p['first'],
            'last': p['last'], 'factors': factors, 'evidence': evidence, 'context': [], 'vars': {'primary': port},
            'strength': int(ratio), 'detail': {'events': p['events'], 'median': median},
        })
    return matches


def rule_repeat_offender(w, offenses):
    matches = []
    for o in offenses:
        prev = o.get('previous')
        if o.get('kind') != 'ip' or not prev or not prev.get('until') or prev['until'] > o['ts']:
            continue
        level = int(o.get('level') or 0)
        if level < int((w.settings or {}).get('repeat_min_level', 3)):
            continue                    # short repeat quarantines are routine noise: no case of their own
        factors = []
        if level >= 3:
            factors.append(_factor('level', 'High quarantine level', 10, 'level %d' % level))
        q = w.quarantine.find(o['addr']) if w.quarantine else None
        text = 'Back in quarantine at level %d (%s) %s after the previous quarantine ended; %s' % (
            level, '+'.join(o.get('reasons_list') or [o.get('reason_name') or '?']),
            _ago(o['ts'] - prev['until']), o.get('detail') or 'no detail')
        evidence = [{'source': 'quarantine', 'key': 'repeat|%d' % o['id'], 'text': text, 'count': o.get('events') or 1,
                     'first': o['ts'], 'last': o['ts'],
                     'data': {'kind': 'repeat', 'level': level, 'previous_until': prev['until'],
                              'offense_id': o['id']}}]
        info = {'quarantine': {k: q.get(k) for k in ('level', 'state', 'active', 'reason', 'until')}} if q else None
        matches.append({
            'rule': 'repeat_offender', 'primary': ('ext', o['addr']), 'related': [], 'primary_info': info,
            'first': o['ts'], 'last': o['ts'], 'factors': factors, 'evidence': evidence, 'context': [],
            'vars': {'primary': o['addr'], 'level': level}, 'strength': level,
            'detail': {'level': level},
        })
    return matches


def _ago(seconds):
    seconds = max(0, int(seconds))
    if seconds >= 86400:
        return '%d day(s)' % (seconds // 86400)
    if seconds >= 3600:
        return '%d hour(s)' % (seconds // 3600)
    return '%d minute(s)' % (seconds // 60)


def evaluate(w, offenses=()):
    """ :return: matches of every rule (at most MAX_MATCHES per rule, strongest first) """
    ports = _port_window(w, w.now - 3600) if w.touched_ports else {}
    found = {
        'scan_then_allowed': rule_scan_then_allowed(w),
        'ids_and_allowed': rule_ids_and_allowed(w),
        'internal_to_bad': rule_internal_to_bad(w),
        'campaign': rule_campaign(w, ports),
        'repeat_offender': rule_repeat_offender(w, offenses),
        'port_spike': rule_port_spike(w, ports),
    }
    out = []
    for rule in common.RULE_ORDER:
        items = sorted(found[rule], key=lambda m: -m['strength'])[:MAX_MATCHES]
        out.extend(items)
    return out
