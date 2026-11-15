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

    The detectors: deterministic functions of aggregated inputs and the stored baselines.  Each one returns
    candidates {type, host, key, severity, score 0-100, title, detail, factors[], evidence{}, params{}} where
    every factor says what was measured, the threshold and whether it counted (common.factor).  Nothing here
    reads files or the database: the engine prepares the inputs, the tests call these directly.

      beaconing          RITA style regularity of the intervals and sizes of one host/destination/port pair
      dga                many distinct NXDOMAIN names of one host, most of them looking generated
      dns_tunnel         many long, high entropy subdomains (or TXT/NULL queries) of one registrable domain
      volume             outbound bytes of an hour far above the EWMA baseline of that hour of the day
      rare_destination   a country / ASN this host never talked to and (almost) no other host either
      new_device         a MAC address never seen before (after the first run learned the network)
      internal_scan      one host touching many internal addresses / ports in a sliding window
      dns_bypass         DNS (53), DoT (853) or DoH resolvers on the internet instead of the firewall
      new_domain         first query of registrable domains this host (and the network) never asked for
      tls                new TLS client fingerprint (JA4) of a host; suspicious certificate (self signed,
                         expired, rare issuer, missing or mismatched SNI)
"""

from . import common, dnsfeat
from .common import factor

SCAN_FAIL_PACKETS = 2        # a TCP flow with at most this many packets and no ACK is a probe


def _cand(kind, host, key, severity, score, detail, factors, evidence=None, params=None, ts=None, title=None):
    return {
        'id': common.finding_id(kind, host, key), 'type': kind, 'host': host, 'key': key,
        'severity': severity, 'score': int(round(max(0, min(100, score)))),
        'title': title or common.TYPE_TITLES[kind], 'detail': detail, 'factors': factors,
        'evidence': evidence or {}, 'params': params or {}, 'ts': ts,
    }


def _pick(settings, *keys):
    return {k: settings[k] for k in keys}


# ================================================================== (a) beaconing


def beacon_score(times, sizes, durs, settings):
    """
    :param times: sorted connection start times (epoch) of one pair
    :return: (score 0..1, factors, stats) or None when there is not enough data / it is streaming
    """
    n = len(times)
    if n < settings['beacon_min_conn']:
        return None
    deltas = [b - a for a, b in zip(times, times[1:]) if b - a > 0.5]
    if len(deltas) < settings['beacon_min_conn'] - 1:
        return None
    med = common.median(deltas)
    if med < settings['beacon_min_interval_s']:
        return None
    jitter = common.mad(deltas, med) / med if med else 1.0
    skew = abs(common.bowley(deltas))
    span = times[-1] - times[0]
    max_jitter = settings['beacon_max_jitter_pct'] / 100.0
    s_jitter = dnsfeat.clamp(1.0 - jitter / max_jitter)
    s_skew = dnsfeat.clamp(1.0 - skew)
    expected = span / med + 1 if med else n
    coverage = min(1.0, n / expected) if expected else 0.0
    s_span = dnsfeat.clamp(span / (settings['beacon_min_span_h'] * 3600.0))
    s_cov = dnsfeat.clamp((coverage - 0.3) / 0.5)
    size_med = common.median(sizes)
    size_rel = common.mad(sizes, size_med) / size_med if size_med else 1.0
    s_size = dnsfeat.clamp(1.0 - size_rel / 0.3)
    dur_med = common.median(durs)
    score = 0.35 * s_jitter + 0.1 * s_skew + 0.2 * s_size + 0.2 * min(s_span, 1.0) + 0.15 * s_cov
    if s_span < 1.0:
        score *= 0.6 + 0.4 * s_span      # a short burst is not a beacon yet
    stats = {'connections': n, 'median_interval_s': round(med, 1), 'jitter': round(jitter, 3),
             'skew': round(skew, 3), 'span_s': int(span), 'coverage': round(coverage, 3),
             'median_bytes': int(size_med), 'size_variation': round(size_rel, 3),
             'median_duration_s': round(dur_med, 1)}
    factors = [
        factor('interval regularity', round(jitter * 100, 1), settings['beacon_max_jitter_pct'],
               jitter <= max_jitter, 0.35, 'median absolute deviation of the intervals relative to the median '
               'interval of %s (lower = more regular)' % common.fmt_duration(med), '%'),
        factor('interval symmetry', round(skew, 2), 1, skew < 0.5, 0.10,
               'Bowley skewness of the intervals (0 = symmetric, as a timer produces)'),
        factor('size regularity', round(size_rel * 100, 1), 30, size_rel <= 0.3, 0.20,
               'variation of the bytes per connection around %s' % common.fmt_bytes(size_med), '%'),
        factor('duration', round(span / 3600.0, 1), settings['beacon_min_span_h'],
               span >= settings['beacon_min_span_h'] * 3600, 0.20,
               '%d connections over %s' % (n, common.fmt_duration(span)), 'h'),
        factor('coverage', round(coverage * 100), 80, coverage >= 0.8, 0.15,
               'connections present vs. expected at that interval (gaps lower it)', '%'),
    ]
    return round(score, 3), factors, stats


def beaconing(host, dst, dport, proto, times, sizes, durs, settings, dst_info=None, ts=None):
    result = beacon_score(times, sizes, durs, settings)
    if result is None:
        return None
    score, factors, stats = result
    if score * 100 < settings['beacon_score_pct']:
        return None
    severity = 'high' if score * 100 >= settings['beacon_high_pct'] else 'medium'
    proto_name = {6: 'tcp', 17: 'udp'}.get(proto, str(proto))
    where = dst + (':%d/%s' % (dport, proto_name) if dport else '/%s' % proto_name)
    extra = ''
    if dst_info and (dst_info.get('country') or dst_info.get('asn')):
        extra = ' (%s)' % ', '.join(x for x in (dst_info.get('country'), dst_info.get('asn') and
                                                ('AS%s' % dst_info['asn'])) if x)
    detail = '%s connected %d times to %s%s every %s (jitter %.0f%%, %s per connection) over %s.' % (
        host, stats['connections'], where, extra, common.fmt_duration(stats['median_interval_s']),
        stats['jitter'] * 100, common.fmt_bytes(stats['median_bytes']), common.fmt_duration(stats['span_s']))
    evidence = dict(stats, destination=dst, port=dport, proto=proto_name,
                    recent=[int(t) for t in times[-12:]], dst_info=dst_info or {})
    return _cand('beaconing', host, where, severity, score * 100, detail, factors, evidence,
                 _pick(settings, 'beacon_min_conn', 'beacon_min_interval_s', 'beacon_max_jitter_pct',
                       'beacon_min_span_h', 'beacon_score_pct', 'beacon_high_pct'), ts)


# ================================================================== DNS preparation


def dns_prepare(rows, netcfg):
    """
    :param rows: [(time, client, type, domain, rcode, action)] of the window
    :return: {host: {"queries", "nx_names": {name: (reg, score, features)}, "suffix_nx", "blocked",
                     "domains": {reg: {"subs": set, "txt", "queries", "qbytes", "first"}}, "doh": set,
                     "regs": {reg: first time}}}
    """
    hosts = {}
    score_cache = {}
    for ts, client, qtype, domain, rcode, action in rows:
        if not client or not domain:
            continue
        h = hosts.get(client)
        if h is None:
            h = hosts[client] = {'queries': 0, 'nx_names': {}, 'suffix_nx': 0, 'blocked': 0, 'domains': {},
                                 'doh': set(), 'regs': {}, 'nx': 0}
        h['queries'] += 1
        name = domain.lower().rstrip('.')
        stripped, appended = netcfg.strip_local(name) if netcfg is not None else (name, False)
        if appended and '.' in stripped:
            if rcode == 3:
                h['suffix_nx'] += 1          # "www.example.com.example.lan": the stub resolver appended the domain
            continue
        if action not in (0, None):
            h['blocked'] += 1                # answered by the block list: not this detector's business
            continue
        if appended or dnsfeat.skip_name(name):
            continue
        reg, sub, label = dnsfeat.registrable(name)
        if reg in netcfg_doh_names():
            h['doh'].add(reg if reg == name else name)
        elif name in netcfg_doh_names():
            h['doh'].add(name)
        if rcode != 3 and reg not in h['regs']:
            h['regs'][reg] = ts          # resolved names only: the NXDOMAIN ones are the DGA detector's
        if dnsfeat.is_random_by_design(reg):
            continue
        d = h['domains'].get(reg)
        if d is None:
            d = h['domains'][reg] = {'subs': set(), 'txt': 0, 'queries': 0, 'qbytes': 0, 'first': ts}
        d['queries'] += 1
        d['qbytes'] += len(name) + 2
        if sub:
            d['subs'].add(sub)
        if qtype in ('TXT', 'NULL'):
            d['txt'] += 1
        if rcode == 3:
            h['nx'] += 1
            if name not in h['nx_names']:
                if label not in score_cache:
                    score_cache[label] = dnsfeat.name_score(label)
                s, f = score_cache[label]
                h['nx_names'][name] = (reg, s, f)
    return hosts


_DOH = None


def netcfg_doh_names():
    global _DOH
    if _DOH is None:
        from .netcfg import DOH_NAMES
        _DOH = frozenset(DOH_NAMES)
    return _DOH


# ================================================================== (b) DGA


def dga(host, h, settings, baseline_nx=None, ts=None):
    """ :param baseline_nx: (mean, std) NXDOMAIN per hour of this host, or None while learning """
    names = h['nx_names']
    distinct = len(names)
    if distinct < settings['dga_min_nx']:
        return None
    threshold = settings['dga_name_pct'] / 100.0
    generated = sorted(((n, v) for n, v in names.items() if v[1] >= threshold), key=lambda x: -x[1][1])
    ratio = len(generated) / float(distinct)
    if ratio * 100 < settings['dga_min_ratio_pct']:
        return None
    regs = {v[0] for _n, v in generated}
    tlds = {r.rsplit('.', 1)[-1] for r in regs}
    avg_score = sum(v[1] for _n, v in generated) / len(generated)
    score = 50 + 30 * min(1.0, ratio) + 20 * min(1.0, len(generated) / (3.0 * settings['dga_min_nx']))
    factors = [
        factor('distinct NXDOMAIN names', distinct, settings['dga_min_nx'], True, None,
               'names that do not exist, asked by this host in the last %d min (block list answers and names '
               'with the local domain appended are left out)' % settings['dga_window_m']),
        factor('look generated', round(ratio * 100), settings['dga_min_ratio_pct'], True, None,
               '%d of them score >= %d%% (character bigrams, entropy, consonant runs, digits)' % (
                   len(generated), settings['dga_name_pct']), '%'),
        factor('average name score', round(avg_score * 100), settings['dga_name_pct'], None, None,
               'average "generated" score of those names', '%'),
        factor('registrable domains', len(regs), None, None, None,
               'different domains under %d top level domain(s): %s' % (len(tlds), ', '.join(sorted(tlds)[:8]))),
    ]
    if baseline_nx is not None:
        mean, std = baseline_nx
        z = (h['nx'] - mean) / std if std > 0 else 0.0
        factors.append(factor('NXDOMAIN vs. baseline', round(z, 1), 3, z >= 3, None,
                              '%d NXDOMAIN now, usually %.0f per hour (z-score)' % (h['nx'], mean)))
        if z >= 3:
            score += 5
    severity = 'high' if len(generated) >= 3 * settings['dga_min_nx'] or (ratio >= 0.8 and len(regs) >= 10) \
        else 'medium'
    detail = '%s asked for %d names that do not exist in the last %d min; %d (%d%%) look machine generated, ' \
             'spread over %d domains. Malware uses generated domains to find its command server.' % (
                 host, distinct, settings['dga_window_m'], len(generated), ratio * 100, len(regs))
    evidence = {'samples': [{'name': n, 'score': round(v[1] * 100), 'features': v[2]} for n, v in generated[:12]],
                'nx_names': distinct, 'generated': len(generated), 'domains': sorted(regs)[:20],
                'suffix_nx': h['suffix_nx'], 'blocked': h['blocked'], 'queries': h['queries']}
    return _cand('dga', host, '', severity, score, detail, factors, evidence,
                 _pick(settings, 'dga_window_m', 'dga_min_nx', 'dga_min_ratio_pct', 'dga_name_pct'), ts)


# ================================================================== (c) DNS tunnel


def dns_tunnel(host, h, settings, ts=None):
    out = []
    for reg, d in h['domains'].items():
        subs = d['subs']
        n = len(subs)
        txt_heavy = d['txt'] >= settings['tunnel_txt_min']
        if n < settings['tunnel_min_subs'] and not (txt_heavy and n >= 5):
            continue
        labels = [s.replace('.', '') for s in subs]
        avg_len = sum(len(x) for x in labels) / float(n) if n else 0.0
        avg_ent = sum(common.entropy(x) for x in labels) / float(n) if n else 0.0
        qbytes = d['qbytes'] / float(d['queries']) if d['queries'] else 0.0
        min_ent = settings['tunnel_min_entropy_x10'] / 10.0
        long_enough = avg_len >= settings['tunnel_min_len']
        random_enough = avg_ent >= min_ent
        if not ((long_enough and random_enough and n >= settings['tunnel_min_subs']) or
                (txt_heavy and (long_enough or random_enough))):
            continue
        score = 55 + 15 * min(1.0, n / (5.0 * settings['tunnel_min_subs'])) + \
            10 * min(1.0, avg_len / 50.0) + 10 * (1 if txt_heavy else 0) + \
            10 * (1 if qbytes >= settings['tunnel_qname_bytes'] else 0)
        severity = 'high' if score >= 80 else 'medium'
        factors = [
            factor('distinct subdomains', n, settings['tunnel_min_subs'], n >= settings['tunnel_min_subs'], None,
                   'different names under %s in the last %d min' % (reg, settings['dga_window_m'])),
            factor('subdomain length', round(avg_len, 1), settings['tunnel_min_len'], long_enough, None,
                   'average characters of the subdomain part (data is encoded there)'),
            factor('subdomain entropy', round(avg_ent, 2), min_ent, random_enough, None,
                   'average Shannon entropy, bits per character (base32/base64/hex ~ 4)'),
            factor('TXT/NULL queries', d['txt'], settings['tunnel_txt_min'], txt_heavy, None,
                   'record types that carry the most data back'),
            factor('bytes per query', round(qbytes), settings['tunnel_qname_bytes'],
                   qbytes >= settings['tunnel_qname_bytes'], None,
                   'average query name size (Unbound keeps no answer size; the name is what leaves)', 'B'),
            factor('queries', d['queries'], None, None, None, 'queries to this domain in the window'),
        ]
        detail = '%s sent %d queries with %d different subdomains of %s (average %.0f characters, entropy %.1f ' \
                 'bits/char, %d TXT/NULL). This is how DNS tunnels move data past the firewall.' % (
                     host, d['queries'], n, reg, avg_len, avg_ent, d['txt'])
        sample = sorted(subs, key=len, reverse=True)[:8]
        evidence = {'domain': reg, 'subdomains': n, 'samples': ['%s.%s' % (s, reg) for s in sample],
                    'txt': d['txt'], 'queries': d['queries'], 'avg_len': round(avg_len, 1),
                    'avg_entropy': round(avg_ent, 2), 'bytes_per_query': round(qbytes)}
        out.append(_cand('dns_tunnel', host, reg, severity, score, detail, factors, evidence,
                         _pick(settings, 'tunnel_min_subs', 'tunnel_min_len', 'tunnel_min_entropy_x10',
                               'tunnel_txt_min', 'tunnel_qname_bytes'), ts))
    return out


# ================================================================== (d) volume


def ewma_update(base, value, alpha):
    """ :param base: (n, mean, var) or None; :return: new (n, mean, var) """
    if base is None or base[0] == 0:
        return 1, float(value), 0.0
    n, mean, var = base
    diff = value - mean
    incr = alpha * diff
    mean = mean + incr
    var = (1 - alpha) * (var + diff * incr)
    return n + 1, mean, var


def volume(host, hour, bytes_out, bytes_in, base_slot, base_all, settings, top=None, partial=False, ts=None):
    """
    :param base_slot: (n, mean, var) of this hour of the day, base_all: of every hour (or None)
    """
    min_bytes = settings['vol_min_mb'] * 1048576
    if bytes_out < min_bytes:
        return None
    use = None
    label = ''
    if base_slot and base_slot[0] >= settings['vol_min_samples']:
        use, label = base_slot, 'this hour of the day'
    elif base_all and base_all[0] >= 24:
        use, label = base_all, 'any hour'
    if use is None:
        return None                         # still learning
    n, mean, var = use
    std = max(var, 0.0) ** 0.5
    floor_std = max(std, mean * 0.25, 1048576.0)    # a flat baseline does not make every spike infinite
    z = (bytes_out - mean) / floor_std
    ratio = bytes_out / mean if mean > 0 else float('inf')
    z_min = settings['vol_z_x10'] / 10.0
    r_min = settings['vol_ratio_x10'] / 10.0
    if z < z_min or ratio < r_min:
        return None
    score = 55 + min(25, (z - z_min) * 2.5) + min(20, (ratio - r_min) * 2)
    out_ratio = bytes_out / float(bytes_in) if bytes_in else None
    severity = 'high' if (z >= 2 * z_min and ratio >= 2 * r_min) or bytes_out >= 10 * min_bytes else 'medium'
    factors = [
        factor('outbound bytes', common.fmt_bytes(bytes_out), common.fmt_bytes(min_bytes), True, None,
               'sent to the internet in the hour starting %s%s' % (common.iso(hour), ' (so far)' if partial else '')),
        factor('z-score', round(z, 1), z_min, True, None,
               'distance from the baseline of %s in standard deviations (EWMA, %d samples)' % (label, n)),
        factor('ratio to baseline', round(ratio, 1) if ratio != float('inf') else 'new', r_min, True, None,
               'baseline mean %s' % common.fmt_bytes(mean), 'x'),
    ]
    if out_ratio is not None:
        factors.append(factor('sent / received', round(out_ratio, 2), 1, out_ratio > 1, None,
                              'an upload sends more than it receives (received %s)' % common.fmt_bytes(bytes_in)))
    detail = '%s sent %s to the internet in one hour, %.1fx its usual %s for %s (z-score %.1f).' % (
        host, common.fmt_bytes(bytes_out), ratio, common.fmt_bytes(mean), label, z)
    evidence = {'hour': hour, 'bytes_out': bytes_out, 'bytes_in': bytes_in, 'baseline_mean': int(mean),
                'baseline_std': int(std), 'baseline_samples': n, 'baseline': label, 'top': top or [], 'partial': partial}
    return _cand('volume', host, 'hour', severity, score, detail, factors, evidence,
                 _pick(settings, 'vol_min_mb', 'vol_z_x10', 'vol_ratio_x10', 'vol_min_samples', 'vol_alpha_pct'), ts)


# ================================================================== (e) rare destination


def rare_destination(host, items, settings, host_age_s, ts=None):
    """
    :param items: [{kind: country|asn, value, hosts (other hosts that saw it in 30 days), bytes, conns,
                    sample (address), asn_name?}] new for this host in this run
    """
    if host_age_s < settings['learning_days'] * 86400:
        return None
    rare = [i for i in items if i['hosts'] < settings['rare_max_hosts'] and
            (i['bytes'] >= settings['rare_min_kb'] * 1024 or i['conns'] >= settings['rare_min_conn'])]
    if not rare:
        return None
    countries = [i for i in rare if i['kind'] == 'country']
    asns = [i for i in rare if i['kind'] == 'asn']
    total = sum(i['bytes'] for i in rare)
    severity = 'medium' if countries and total >= 1048576 else ('low' if countries else 'info')
    score = 40 + 15 * min(2, len(countries)) + 5 * min(3, len(asns)) + (10 if total >= 1048576 else 0)
    factors = [
        factor('new countries', len(countries), 1, bool(countries), None,
               ', '.join(i['value'] for i in countries) or 'none'),
        factor('new ASNs', len(asns), 1, bool(asns), None, ', '.join('AS%s' % i['value'] for i in asns[:8]) or 'none'),
        factor('other hosts', max(i['hosts'] for i in rare), settings['rare_max_hosts'], True, None,
               'internal hosts that talked to it in the last 30 days (fewer = rarer)'),
        factor('exchanged', common.fmt_bytes(total), common.fmt_bytes(settings['rare_min_kb'] * 1024), None, None,
               'bytes exchanged with the new destinations in this run'),
        factor('host history', common.fmt_duration(host_age_s), '%d days' % settings['learning_days'], True, None,
               'how long this host has been learned'),
    ]
    detail = '%s talked for the first time to %s; no other internal host did in the last 30 days.' % (
        host, ', '.join(['country %s' % i['value'] for i in countries] + ['AS%s' % i['value'] for i in asns][:6]))
    evidence = {'items': rare}
    key = '+'.join(sorted('%s:%s' % (i['kind'], i['value']) for i in rare))[:200]
    return _cand('rare_destination', host, key, severity, score, detail, factors, evidence,
                 _pick(settings, 'rare_max_hosts', 'rare_min_kb', 'rare_min_conn', 'learning_days'), ts)


# ================================================================== (f) new device


def is_random_mac(mac):
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def new_device(dev, settings, ts=None):
    random_mac = is_random_mac(dev['mac'])
    severity = 'info' if random_mac and settings['device_random_info'] else 'low'
    if not dev.get('vendor') and not random_mac:
        severity = 'low'
    factors = [
        factor('MAC address', dev['mac'], None, True, None, 'never seen on this network before'),
        factor('randomized MAC', 'yes' if random_mac else 'no', None, random_mac, None,
               'locally administered: phones and laptops use a private address per network'),
        factor('vendor', dev.get('vendor') or 'unknown', None, None, None, 'OUI organization (Host discovery)'),
        factor('address', dev.get('ip') or '-', None, None, None, 'interface %s, source %s' % (
            dev.get('iface') or '-', dev.get('source'))),
    ]
    if dev.get('hostname'):
        factors.append(factor('DHCP host name', dev['hostname'], None, None, None, 'name sent in the DHCP request'))
    detail = 'A device never seen before joined the network: %s%s%s.' % (
        dev['mac'], (' (%s)' % dev['vendor']) if dev.get('vendor') else '',
        (' at %s' % dev['ip']) if dev.get('ip') else '')
    host = dev.get('ip') or dev['mac']
    return _cand('new_device', host, dev['mac'], severity, 60 if severity == 'low' else 30, detail, factors,
                 dict(dev, random=random_mac), _pick(settings, 'device_random_info'), ts)


# ================================================================== (g) internal scan


def internal_scan(host, events, settings, baseline=None, blocked=0, ts=None):
    """
    :param events: [(ts, dst, dport, proto, failed bool)] of this host towards internal addresses, sorted
    :param baseline: usual max distinct internal addresses per window (EWMA) or None
    """
    window = settings['scan_window_s']
    best_hosts, best_ports, best_t = 0, 0, None
    best_set, best_port_dst = set(), None
    dst_count = {}              # dst -> events in the window
    port_count = {}             # dst -> {(port, proto): events in the window}
    start = 0
    for i, ev in enumerate(events):
        while events[start][0] < ev[0] - window:
            old = events[start]
            dst_count[old[1]] -= 1
            if not dst_count[old[1]]:
                del dst_count[old[1]]
            ports = port_count[old[1]]
            ports[(old[2], old[3])] -= 1
            if not ports[(old[2], old[3])]:
                del ports[(old[2], old[3])]
            if not ports:
                del port_count[old[1]]
            start += 1
        dst_count[ev[1]] = dst_count.get(ev[1], 0) + 1
        ports = port_count.setdefault(ev[1], {})
        ports[(ev[2], ev[3])] = ports.get((ev[2], ev[3]), 0) + 1
        if len(dst_count) > best_hosts:
            best_hosts, best_set, best_t = len(dst_count), set(dst_count), ev[0]
        if len(ports) > best_ports:
            best_ports, best_port_dst = len(ports), ev[1]
            best_t = best_t or ev[0]
    hosts_hit = best_hosts >= settings['scan_min_hosts']
    ports_hit = best_ports >= settings['scan_min_ports']
    if not hosts_hit and not ports_hit:
        return None
    failed = sum(1 for e in events if e[4])
    fail_ratio = failed / float(len(events)) if events else 0.0
    score = 55 + 20 * min(1.0, best_hosts / (5.0 * settings['scan_min_hosts'])) + \
        15 * min(1.0, best_ports / (5.0 * settings['scan_min_ports'])) + 10 * fail_ratio
    if baseline:
        score += 5 if best_hosts > 3 * baseline else -10
    severity = 'high' if (hosts_hit and ports_hit) or (fail_ratio >= 0.7 and score >= 75) else 'medium'
    kind = 'sweep' if hosts_hit else 'port scan'
    factors = [
        factor('internal addresses', best_hosts, settings['scan_min_hosts'], hosts_hit, None,
               'distinct internal addresses in %s' % common.fmt_duration(window)),
        factor('ports of one address', best_ports, settings['scan_min_ports'], ports_hit, None,
               'distinct ports of %s in %s' % (best_port_dst or '-', common.fmt_duration(window))),
        factor('failed attempts', round(fail_ratio * 100), 50, fail_ratio >= 0.5, None,
               'TCP attempts without an answer (<= %d packets, no ACK)' % SCAN_FAIL_PACKETS, '%'),
        factor('blocked by the filter', blocked, None, None, None, 'blocked internal attempts in the filter log'),
    ]
    if baseline is not None:
        factors.append(factor('usual reach', round(baseline, 1), None, best_hosts > 3 * baseline, None,
                              'internal addresses per window this host usually touches (EWMA)'))
    detail = '%s touched %d internal addresses and up to %d ports of %s within %s (%s, %d%% unanswered). ' \
             'Malware spreading inside the network starts like this; so do inventory tools.' % (
                 host, best_hosts, best_ports, best_port_dst or '-', common.fmt_duration(window), kind,
                 fail_ratio * 100)
    evidence = {'max_hosts': best_hosts, 'max_ports': best_ports, 'port_target': best_port_dst,
                'targets': sorted(best_set)[:30], 'events': len(events), 'failed': failed, 'blocked': blocked,
                'at': best_t}
    return _cand('internal_scan', host, '', severity, score, detail, factors, evidence,
                 _pick(settings, 'scan_window_s', 'scan_min_hosts', 'scan_min_ports'), ts)


# ================================================================== (h) DNS bypass


def dns_bypass(host, items, settings, redirect=None, doh_lookups=None, ts=None):
    """
    :param items: {(dst, dport, proto): {"flows", "bytes", "kind": dns|dot|doh}}
    :param redirect: description of a NAT rule that sends port 53 back to the firewall (or None)
    """
    plain = {k: v for k, v in items.items() if v['kind'] == 'dns'}
    dot = {k: v for k, v in items.items() if v['kind'] == 'dot'}
    doh = {k: v for k, v in items.items() if v['kind'] == 'doh'} if settings['bypass_doh'] else {}
    doh_lookups = sorted(doh_lookups or [])
    if not plain and not dot and not doh and not doh_lookups:
        return None
    if dot:
        severity, score = 'medium', 70
    elif plain and not redirect:
        severity, score = 'medium', 70
    elif doh:
        severity, score = 'low', 50
    elif plain:
        severity, score = 'info', 35
    else:
        severity, score = 'info', 25
    resolvers = sorted({k[0] for k in list(plain) + list(dot) + list(doh)})
    factors = [
        factor('plain DNS (53) to the internet', sum(v['flows'] for v in plain.values()), 0, bool(plain), None,
               ('redirected to the firewall by "%s": the attempt is neutralized, the device has a hard coded '
                'resolver' % redirect) if (plain and redirect) else
               'queries that skip Unbound and its block lists'),
        factor('DNS over TLS (853)', sum(v['flows'] for v in dot.values()), 0, bool(dot), None,
               'encrypted DNS the firewall can neither see nor redirect'),
        factor('DoH resolvers (443)', sum(v['flows'] for v in doh.values()), 0, bool(doh), None,
               'HTTPS to well known public DNS over HTTPS resolvers'),
        factor('DoH name lookups', len(doh_lookups), 0, bool(doh_lookups), None,
               ', '.join(doh_lookups[:5]) or 'none'),
    ]
    detail = '%s used resolvers on the internet (%s) instead of the firewall%s.' % (
        host, ', '.join(resolvers[:6]) or 'DoH name lookups only',
        ' (port 53 is redirected to the firewall, so only DoT/DoH really bypass it)' if redirect else '')
    evidence = {'resolvers': resolvers, 'flows': [{'dst': k[0], 'port': k[1], 'proto': k[2], 'kind': v['kind'],
                                                   'flows': v['flows'], 'bytes': v['bytes']}
                                                  for k, v in sorted(items.items())][:30],
                'doh_lookups': doh_lookups[:20], 'redirect': redirect}
    return _cand('dns_bypass', host, '', severity, score, detail, factors, evidence, _pick(settings, 'bypass_doh'), ts)


# ================================================================== (i) new domain


def new_domain(host, new_regs, settings, host_age_s, ts=None, min_new=1):
    """
    :param new_regs: [{domain, hosts (other hosts that asked in 90 days), queries, label_score}]
    first query of registrable domains nobody on the network asked for before; CDNs and lookup services
    (random by design) never count
    """
    if host_age_s < settings['learning_days'] * 86400:
        return None
    unique = [d for d in new_regs if d['hosts'] == 0 and not dnsfeat.is_random_by_design(d['domain'])]
    if len(unique) < min_new:
        return None
    odd = [d for d in unique if d['label_score'] >= settings['dga_name_pct'] / 100.0]
    severity = 'low' if odd or len(unique) >= 10 else 'info'
    score = 30 + 3 * min(10, len(unique)) + 15 * min(2, len(odd))
    factors = [
        factor('never seen domains', len(unique), min_new, True, None,
               'registrable domains no internal host asked for in the last 90 days'),
        factor('odd looking', len(odd), 1, bool(odd), None, 'of them also look generated'),
        factor('host history', common.fmt_duration(host_age_s), '%d days' % settings['learning_days'], True, None,
               'how long this host has been learned'),
    ]
    detail = '%s asked for %d domain(s) never seen on the network before: %s.' % (
        host, len(unique), ', '.join(d['domain'] for d in unique[:6]))
    evidence = {'domains': unique[:30]}
    day = int((ts or 0) // 86400)
    return _cand('new_domain', host, 'day:%d' % day, severity, score, detail, factors, evidence,
                 _pick(settings, 'learning_days', 'dga_name_pct'), ts, title='Domain never seen before')


# ================================================================== (j) TLS


def new_ja4(host, ja4, others, sni, settings, host_age_s, ts=None):
    """ a TLS client fingerprint new for this host; :param others: hosts that used it in 180 days """
    if host_age_s < settings['learning_days'] * 86400:
        return None
    severity = 'low' if others == 0 else 'info'
    factors = [
        factor('JA4', ja4, None, True, None, 'TLS client hello fingerprint (client software and library)'),
        factor('other hosts', others, 0, others == 0, None, 'internal hosts that used this fingerprint (180 days)'),
        factor('first SNI', sni or '(none)', None, not sni, None, 'server name of the first connection'),
    ]
    detail = '%s started a TLS client never seen on it before (JA4 %s%s)%s.' % (
        host, ja4, (', to %s' % sni) if sni else '', '' if others else '; no other host uses it')
    return _cand('tls', host, 'ja4:' + ja4, severity, 45 if others == 0 else 25, detail, factors,
                 {'ja4': ja4, 'sni': sni, 'other_hosts': others}, _pick(settings, 'learning_days'), ts,
                 title='New TLS client (JA4)')


def _san_match(sni, names):
    sni = sni.lower().rstrip('.')
    for name in names:
        name = name.lower().strip()
        if name == sni:
            return True
        if name.startswith('*.') and sni.endswith(name[1:]) and sni.count('.') == name.count('.'):
            return True
    return False


def cert_issues(tls, ts, issuer_seen):
    """ :param issuer_seen: times the issuer was seen before (None = first time) :return: [(name, text)] """
    issues = []
    subject = tls.get('subject') or ''
    issuer = tls.get('issuerdn') or ''
    if not subject and not issuer:
        return issues                   # TLS 1.3: the certificate is encrypted, nothing to judge
    if subject and subject == issuer:
        issues.append(('self signed', 'subject and issuer are the same'))
    not_after = tls.get('notafter_epoch')
    not_before = tls.get('notbefore_epoch')
    if not_after is not None and not_after < ts:
        issues.append(('expired', 'valid until %s' % common.iso(not_after)))
    if not_before is not None and not_before > ts + 86400:
        issues.append(('not yet valid', 'valid from %s' % common.iso(not_before)))
    sni = tls.get('sni') or ''
    names = list(tls.get('subjectaltname') or [])
    cn = ''
    for part in subject.split(','):
        part = part.strip()
        if part.startswith('CN='):
            cn = part[3:]
    if cn:
        names.append(cn)
    if not sni:
        issues.append(('no SNI', 'the client did not say which server it wanted'))
    elif names and not _san_match(sni, names):
        issues.append(('SNI mismatch', 'asked for %s, certificate is for %s' % (sni, ', '.join(names[:3]))))
    if issuer and (issuer_seen is None or issuer_seen < 2):
        issues.append(('rare issuer', 'issuer seen %d time(s) on this network' % (issuer_seen or 0)))
    return issues


def tls_certificate(host, dst, tls, issues, ts=None):
    if not issues:
        return None
    names = {i[0] for i in issues}
    weight = {'self signed': 25, 'expired': 20, 'SNI mismatch': 20, 'not yet valid': 15, 'rare issuer': 10,
              'no SNI': 5}
    score = 30 + sum(weight.get(n, 5) for n in names)
    strong = names & {'self signed', 'expired', 'SNI mismatch', 'not yet valid'}
    if not strong:
        return None                     # a rare issuer or a missing SNI alone is context, not a finding
    severity = 'medium' if len(strong) >= 2 or ('self signed' in strong and 'rare issuer' in names) else 'low'
    factors = [factor(name, 'yes', None, True, weight.get(name), text) for name, text in issues]
    detail = '%s accepted a suspicious certificate from %s (%s).' % (host, dst, ', '.join(sorted(names)))
    evidence = {'destination': dst, 'sni': tls.get('sni'), 'subject': tls.get('subject'),
                'issuer': tls.get('issuerdn'), 'notafter': tls.get('notafter'), 'ja4': tls.get('ja4'),
                'fingerprint': tls.get('fingerprint')}
    return _cand('tls', host, 'cert:%s' % (tls.get('fingerprint') or dst), severity, score, detail, factors,
                 evidence, {}, ts, title='Suspicious TLS certificate')
