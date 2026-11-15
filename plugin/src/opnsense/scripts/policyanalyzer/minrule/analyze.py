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

    "Minimal rule from the observed traffic": for one permissive pass rule, what it really matched in the last
    N days and the narrowest rule that still covers it.

    Observations (sources.py): filter log lines labelled with the rule (exact, needs "log" on the rule) or,
    otherwise, NetFlow flows that entered on the rule's interface inside its match space and that no earlier
    quick rule certainly decides (approximate: pf state and NAT are not replayed).

    Proposal (deterministic):
      protocols   the observed set (TCP and UDP together become TCP/UDP; ICMP observed beside TCP/UDP gets a
                  separate ICMP rule because ports do not apply to it)
      destination only narrowed when the rule has "any" (or a negation): a configured interface network when
                  every destination is inside it ("lan" -> LAN net), otherwise the observed hosts, a /24 (/64)
                  when COLLAPSE_HOSTS or more hosts share it, a /16 (/48) when still above MAX_ENTRIES, and the
                  least used entries left out beyond MAX_ENTRIES (they are reported as "would be blocked")
      ports       only narrowed when the rule has no port: the observed destination ports, consecutive ports
                  merged into ranges, the least used ones beyond MAX_PORTS folded into one range
      source      only narrowed to a configured interface network ("LAN net") when every source is inside it;
                  never to single observed addresses (VPN road warriors and DHCP clients move)
      broad use   more than BROAD_HOSTS distinct destinations, or more than BROAD_PORTS distinct ports / a
                  folded range wider than BROAD_RANGE, means general access: that field is kept as it is and
                  the result says so (the honest minimal rule of "LAN to the internet" is not a host list)
    Coverage = share of the observed connections (filter log) or flows (NetFlow) the proposal still matches.
    Everything the window did not show (new destinations, rare monthly jobs) would be blocked: the window
    length and the confidence are part of the result.
"""

import hashlib
import ipaddress
import os
import time

from engine import ipset
from engine.config import FirewallConfig
from engine.report import rule_ref
from engine.resolve import Resolver
from engine.rules import RuleNormalizer, evaluation_order

from . import sources

COLLAPSE_HOSTS = 4
MAX_ENTRIES = 32
MAX_PORTS = 16
MAX_SOURCES = 8
TOP_BLOCKED = 20
# beyond these the traffic is "general access" and narrowing would only produce a meaningless list
BROAD_HOSTS = 256
BROAD_PORTS = 64
BROAD_RANGE = 1024


def load_rules(config_path):
    cfg = FirewallConfig(config_path)
    resolver = Resolver(cfg)
    normalizer = RuleNormalizer(cfg, resolver)
    rules = evaluation_order([normalizer.normalize(raw) for raw in cfg.rules])
    return cfg, rules


def device_map(cfg):
    """ device (igc0, pppoe1, wg0) -> logical interface name (lan, wan, opt8) """
    return {iface.device: name for name, iface in cfg.interfaces.items() if iface.device}


def iface_may(rule, name):
    s = rule.ifset
    if s.all:
        return True
    if s.neg:
        return name not in s.atoms
    return name in s.atoms or bool(s.opaque)


def iface_sure(rule, name):
    s = rule.ifset
    if s.all:
        return True
    if s.neg:
        return name not in s.atoms and not s.opaque
    return name in s.atoms


def _addr_in(pair, ip):
    fam = 6 if ip.version == 6 else 4
    value = int(ip)
    return ipset.is_subset(((value, value),), pair[ipset.fidx(fam)])


def _port_in(intervals, port):
    return port is not None and ipset.is_subset(((port, port),), intervals)


def matches(rule, ip_src, ip_dst, proto, dport, iface, bound='upper'):
    """ may (upper) / does certainly (lower) this rule match the packet """
    fam = ip_src.version
    if fam not in rule.active_fams:
        return False
    if iface is not None and not (iface_may if bound == 'upper' else iface_sure)(rule, iface):
        return False
    protos = rule.protos.get(fam)
    if protos is not None and proto not in protos:
        return False
    src = rule.src.upper if bound == 'upper' else rule.src.lower
    dst = rule.dst.upper if bound == 'upper' else rule.dst.lower
    if not _addr_in(src, ip_src) or not _addr_in(dst, ip_dst):
        return False
    if rule.dport is not None:
        if proto not in ('tcp', 'udp'):
            return False
        bounds = rule.dport.upper if bound == 'upper' else rule.dport.lower
        if not _port_in(bounds, dport):
            return False
    if rule.sport is not None and bound == 'lower':
        return False  # source ports are not in the observations: never "certain"
    if bound == 'lower' and rule.extra:
        return False  # extra conditions (icmp types, tags, schedules) can not be checked here
    return True


# ------------------------------------------------------------------------------------------ observations

def _ip(value):
    try:
        return ipaddress.ip_address(str(value).split('%')[0])
    except ValueError:
        return None


def observe(paths, cfg, rules, rule, days, budget_seconds=20.0, use_netflow=True):
    ts = time.time() if not os.environ.get('POLICYANALYZER_NOW') else float(os.environ['POLICYANALYZER_NOW'])
    since = ts - days * 86400
    budget = sources.Budget(budget_seconds)
    devmap = device_map(cfg)
    obs = []
    meta = {}
    if rule.source == 'mvc' and rule.log:
        records, meta = sources.scan_label(paths.filter_log_dir, rule.uuid, since, ts + 60, budget)
        for rec in records:
            if rec['action'] != 'pass':
                continue
            src, dst = _ip(rec['src']), _ip(rec['dst'])
            if src is None or dst is None:
                continue
            obs.append({'time': rec['time'], 'src': src, 'dst': dst, 'proto': rec['proto'], 'dport': rec['dport'],
                        'weight': 1, 'octets': None, 'iface': devmap.get(rec['device'], rec['device'])})
        meta['unit'] = 'connections'
    if not obs and use_netflow:
        reason = 'the rule does not log' if not rule.log else \
            ('legacy rules are labelled with a hash the analyzer does not map' if rule.source != 'mvc' else
             'no labelled log line in the window')
        flows, fmeta = sources.flows(paths, since, ts + 60, budget)
        idx = sources.interface_indexes(paths)
        position = rules.index(rule)
        earlier = [r for r in rules[:position] if r.quick and r.enabled and r.loaded and
                   r.action in ('pass', 'block', 'reject') and 'in' in r.directions]
        skipped = 0
        for fl in flows:
            src, dst = _ip(fl.get('src')), _ip(fl.get('dst'))
            if src is None or dst is None:
                continue
            device = idx.get(fl.get('ifin'))
            iface = devmap.get(device) if device else None
            if iface is None and idx:
                continue  # entered on an interface that is not configured (or egress only capture)
            proto = fl.get('proto')
            dport = fl.get('dport') if proto in ('tcp', 'udp') else None
            if not matches(rule, src, dst, proto, dport, iface, 'upper'):
                continue
            if any(matches(r, src, dst, proto, dport, iface, 'lower') for r in earlier):
                skipped += 1
                continue
            obs.append({'time': fl.get('time'), 'src': src, 'dst': dst, 'proto': proto, 'dport': dport,
                        'weight': 1, 'octets': fl.get('octets'), 'iface': iface})
        fmeta.update({'unit': 'flows', 'fallback_reason': reason, 'decided_by_earlier_rules': skipped,
                      'interface_map': bool(idx)})
        meta = {'filterlog': meta or None, **fmeta} if meta else fmeta
        if obs:
            meta['first'] = min(o['time'] for o in obs if o['time'] is not None)
            meta['last'] = max(o['time'] for o in obs if o['time'] is not None)
    meta['window_days'] = days
    meta['since'] = since
    return obs, meta


# ------------------------------------------------------------------------------------------ proposal

def _net_of(ip, bits):
    return ipaddress.ip_network('%s/%d' % (ip, bits), strict=False)


def interface_networks(cfg):
    """ logical name -> networks of the interface (for "<if> net" tokens) """
    nets = {}
    for name, iface in cfg.interfaces.items():
        out = []
        for addr, bits in ((iface.ipaddr, iface.subnet), (iface.ipaddrv6, iface.subnetv6)):
            if addr and bits and bits.isdigit():
                try:
                    out.append(ipaddress.ip_network('%s/%s' % (addr, bits), strict=False))
                except ValueError:
                    pass
        if out:
            nets[name] = out
    return nets


def group_addresses(weights, ifnets, collapse=None, max_entries=None):
    """
    :param weights: {ip_address: weight}
    :return: (entries [{value, kind, weight, hosts}], left_out [{value, weight}], token or None)
    """
    collapse = COLLAPSE_HOSTS if collapse is None else collapse
    max_entries = MAX_ENTRIES if max_entries is None else max_entries
    if not weights:
        return [], [], None
    for name, nets in sorted(ifnets.items()):
        for net in nets:
            if all(ip.version == net.version and ip in net for ip in weights):
                return [{'value': '%s net' % name, 'kind': 'ifnet', 'weight': sum(weights.values()),
                         'hosts': len(weights), 'network': str(net)}], [], name
    entries = {}
    by_prefix = {}
    for ip, w in weights.items():
        by_prefix.setdefault(_net_of(ip, 24 if ip.version == 4 else 64), []).append((ip, w))
    for net, members in by_prefix.items():
        if len(members) >= collapse:
            entries[str(net)] = {'value': str(net), 'kind': 'network', 'weight': sum(w for _, w in members),
                                 'hosts': len(members), 'net': net}
        else:
            for ip, w in members:
                entries[str(ip)] = {'value': str(ip), 'kind': 'host', 'weight': w, 'hosts': 1,
                                    'net': _net_of(ip, ip.max_prefixlen)}
    if len(entries) > max_entries:
        wide = {}
        for item in entries.values():
            parent = item['net'].supernet(new_prefix=16 if item['net'].version == 4 else 48) \
                if item['net'].prefixlen > (16 if item['net'].version == 4 else 48) else item['net']
            wide.setdefault(parent, []).append(item)
        merged = {}
        for parent, items in wide.items():
            if len(items) >= collapse:
                merged[str(parent)] = {'value': str(parent), 'kind': 'network', 'net': parent,
                                       'weight': sum(i['weight'] for i in items),
                                       'hosts': sum(i['hosts'] for i in items)}
            else:
                for i in items:
                    merged[i['value']] = i
        entries = merged
    ordered = sorted(entries.values(), key=lambda e: (-e['weight'], e['value']))
    keep, left = ordered[:max_entries], ordered[max_entries:]
    for e in keep + left:
        e.pop('net', None)
    return keep, [{'value': e['value'], 'weight': e['weight']} for e in left], None


def group_ports(weights, max_ports=None):
    """ {port: weight} -> (ranges [{lo, hi, weight}], wide flag) """
    max_ports = MAX_PORTS if max_ports is None else max_ports
    ports = sorted(weights)
    ranges = []
    for port in ports:
        if ranges and port == ranges[-1]['hi'] + 1:
            ranges[-1]['hi'] = port
            ranges[-1]['weight'] += weights[port]
        else:
            ranges.append({'lo': port, 'hi': port, 'weight': weights[port]})
    wide = False
    if len(ranges) > max_ports:
        ranges.sort(key=lambda r: -r['weight'])
        keep, rest = ranges[:max_ports - 1], ranges[max_ports - 1:]
        fold = {'lo': min(r['lo'] for r in rest), 'hi': max(r['hi'] for r in rest),
                'weight': sum(r['weight'] for r in rest), 'folded': len(rest)}
        ranges = sorted(keep + [fold], key=lambda r: r['lo'])
        # folded range overlapping kept ones: merge into one interval list
        merged = []
        for r in ranges:
            if merged and r['lo'] <= merged[-1]['hi'] + 1:
                merged[-1]['hi'] = max(merged[-1]['hi'], r['hi'])
                merged[-1]['weight'] += r['weight']
                merged[-1]['folded'] = merged[-1].get('folded', 0) + r.get('folded', 0)
            else:
                merged.append(dict(r))
        ranges = merged
        wide = True
    return ranges, wide


def _port_text(r):
    return str(r['lo']) if r['lo'] == r['hi'] else '%d:%d' % (r['lo'], r['hi'])


def _in_entries(ip, entries, ifnets):
    for e in entries:
        if e['kind'] == 'ifnet':
            name = e['value'][:-4]
            if any(ip.version == n.version and ip in n for n in ifnets.get(name, [])):
                return True
        else:
            net = ipaddress.ip_network(e['value'], strict=False)
            if ip.version == net.version and ip in net:
                return True
    return False


def _in_ranges(port, ranges):
    return any(r['lo'] <= port <= r['hi'] for r in ranges)


def propose(cfg, rule, obs, meta, days):
    ifnets = interface_networks(cfg)
    total = sum(o['weight'] for o in obs)
    short = hashlib.sha1(rule.uuid.encode()).hexdigest()[:6]
    base = {'rule': {'uuid': rule.uuid, 'summary': rule.summary, 'description': rule.description,
                     'interface': ','.join(rule.interfaces_raw) or 'floating', 'sequence': rule.sequence,
                     'log': rule.log, 'ref': rule_ref(rule)},
            'window_days': days, 'observed': {'total': total, 'unit': meta.get('unit', 'connections')}}
    if not obs:
        base.update({'status': 'ok', 'proposal': None, 'coverage': None,
                     'message': 'No traffic was attributed to this rule in the last %d days.' % days,
                     'confidence': 'none'})
        return base

    protos = {}
    for o in obs:
        protos[o['proto']] = protos.get(o['proto'], 0) + o['weight']
    port_protos = {p for p in protos if p in ('tcp', 'udp')}
    other_protos = sorted(p for p in protos if p not in ('tcp', 'udp'))

    dst_any = rule.dst.is_any or rule.dst.neg
    src_any = rule.src.is_any
    ports_any = rule.dport is None

    dst_w, src_w, port_w = {}, {}, {}
    for o in obs:
        dst_w[o['dst']] = dst_w.get(o['dst'], 0) + o['weight']
        src_w[o['src']] = src_w.get(o['src'], 0) + o['weight']
        if o['proto'] in ('tcp', 'udp') and o['dport'] is not None:
            port_w[o['dport']] = port_w.get(o['dport'], 0) + o['weight']

    notes = []
    broad_dst = dst_any and len(dst_w) > BROAD_HOSTS
    if broad_dst:
        notes.append('%d distinct destinations: general access, the destination is kept as it is' % len(dst_w))
    dst_entries, dst_left, dst_token = group_addresses(dst_w, ifnets) if dst_any and not broad_dst else \
        ([], [], None)
    src_entries, src_left, src_token = ([], [], None)
    if src_any:
        cand = group_addresses(src_w, ifnets, max_entries=MAX_SOURCES)
        if cand[2]:
            src_entries, src_left, src_token = cand
        else:
            notes.append('%d distinct source(s): sources are not narrowed to observed addresses (clients move)'
                         % len(src_w))
    port_ranges, wide = group_ports(port_w) if (ports_any and port_protos) else ([], False)
    if port_ranges and (len(port_w) > BROAD_PORTS or
                        any(r['hi'] - r['lo'] + 1 > BROAD_RANGE for r in port_ranges)):
        notes.append('%d distinct destination ports: general access, the ports are kept as they are' % len(port_w))
        port_ranges, wide = [], False

    def covered(o):
        if o['proto'] not in protos:
            return False
        if dst_entries and not _in_entries(o['dst'], dst_entries, ifnets):
            return False
        if src_entries and not _in_entries(o['src'], src_entries, ifnets):
            return False
        if port_ranges and o['proto'] in ('tcp', 'udp') and (o['dport'] is None or
                                                             not _in_ranges(o['dport'], port_ranges)):
            return False
        return True

    blocked = {}
    covered_w = 0
    for o in obs:
        if covered(o):
            covered_w += o['weight']
        else:
            key = (o['proto'], str(o['src']), str(o['dst']), o['dport'])
            blocked[key] = blocked.get(key, 0) + o['weight']
    coverage = round(100.0 * covered_w / total, 2) if total else None

    aliases = []
    changes = []
    proto_new = None
    if rule.protocol_raw == 'any':
        if port_protos == {'tcp', 'udp'}:
            proto_new = 'TCP/UDP'
        elif len(port_protos) == 1:
            proto_new = next(iter(port_protos)).upper()
        elif len(other_protos) == 1 and not port_protos:
            proto_new = other_protos[0].upper()
        if proto_new:
            changes.append({'field': 'Protocol', 'from': 'any', 'to': proto_new})
    if dst_entries:
        if dst_token:
            value = '%s net' % dst_token
        elif len(dst_entries) == 1 and dst_entries[0]['kind'] == 'host':
            value = dst_entries[0]['value']
        else:
            value = 'pa_min_%s_dst' % short
            aliases.append({'name': value, 'type': 'network' if any(e['kind'] == 'network' for e in dst_entries)
                            else 'host', 'content': [e['value'] for e in dst_entries],
                            'description': 'Minimal rule: destinations seen in %d days for "%s"' % (
                                days, rule.description or rule.uuid)})
        changes.append({'field': 'Destination', 'from': rule.dst.raw if not rule.dst.neg else 'not ' + rule.dst.raw,
                        'to': value})
    if src_entries:
        if src_token:
            value = '%s net' % src_token
        elif len(src_entries) == 1 and src_entries[0]['kind'] == 'host':
            value = src_entries[0]['value']
        else:
            value = 'pa_min_%s_src' % short
            aliases.append({'name': value, 'type': 'network' if any(e['kind'] == 'network' for e in src_entries)
                            else 'host', 'content': [e['value'] for e in src_entries],
                            'description': 'Minimal rule: sources seen in %d days' % days})
        if value != rule.src.raw:
            changes.append({'field': 'Source', 'from': rule.src.raw, 'to': value})
    if port_ranges and (proto_new in ('TCP', 'UDP', 'TCP/UDP') or rule.protocol_raw in ('tcp', 'udp', 'tcp/udp')):
        if len(port_ranges) == 1:
            value = _port_text(port_ranges[0])
        else:
            value = 'pa_min_%s_ports' % short
            aliases.append({'name': value, 'type': 'port', 'content': [_port_text(r) for r in port_ranges],
                            'description': 'Minimal rule: destination ports seen in %d days' % days})
        changes.append({'field': 'Destination port', 'from': 'any', 'to': value})
    extra_rules = []
    if rule.protocol_raw == 'any' and (port_protos and other_protos or len(other_protos) > 1):
        rest = other_protos if port_protos else other_protos[1:]
        for proto in rest:
            extra_rules.append({'protocol': proto.upper(),
                                'destination': next((c['to'] for c in changes if c['field'] == 'Destination'),
                                                    rule.dst.raw),
                                'connections': protos[proto],
                                'why': 'one protocol per rule: %s was seen beside %s (keep it in its own rule, or '
                                       'leave it out if it is not needed)' % (proto.upper(), proto_new or 'the rest')})

    first, last = meta.get('first'), meta.get('last')
    observed_days = round((last - first) / 86400.0, 1) if first and last else 0
    unit = meta.get('unit', 'connections')
    if total < 20 or observed_days < min(3, days) or not meta.get('complete', True):
        confidence = 'low'
    elif unit == 'flows' or days < 7:
        confidence = 'medium'
    else:
        confidence = 'high'

    diff = []
    for alias in aliases:
        diff.append('# Firewall › Aliases › + %s (%s)' % (alias['name'], {'host': 'Host(s)', 'network': 'Network(s)',
                                                                          'port': 'Port(s)'}[alias['type']]))
        diff.append('+ Content: %s' % ', '.join(alias['content']))
        diff.append('+ Description: %s' % alias['description'])
        diff.append('')
    diff.append('# Firewall › Rules › %s › %s (sequence %d)' % (base['rule']['interface'],
                                                              rule.description or rule.uuid, rule.sequence))
    for c in changes:
        diff.append('- %s: %s' % (c['field'], c['from']))
        diff.append('+ %s: %s' % (c['field'], c['to']))
    if not rule.log:
        diff.append('- Log: unchecked')
        diff.append('+ Log: checked (so the next analysis is exact)')
    for extra in extra_rules:
        diff.append('')
        diff.append('# Firewall › Rules › %s › + (copy of the rule)' % base['rule']['interface'])
        diff.append('+ Protocol: %s' % extra['protocol'])
        diff.append('+ Destination: %s' % extra['destination'])

    blocked_list = [{'proto': k[0], 'src': k[1], 'dst': k[2], 'dport': k[3], 'count': v}
                    for k, v in sorted(blocked.items(), key=lambda kv: -kv[1])[:TOP_BLOCKED]]
    steps = [{'description': 'Create alias %s (%d entries)' % (a['name'], len(a['content'])),
              'command': 'GUI: Firewall › Aliases (ui/firewall/alias)', 'effect': 'no traffic change until used'}
             for a in aliases]
    steps.append({'description': 'Edit the rule: %s' % '; '.join('%s %s → %s' % (c['field'], c['from'], c['to'])
                                                                 for c in changes) if changes else
                  'Edit the rule (nothing to narrow)',
                  'command': 'GUI: Firewall › Rules (%s)' % base['rule']['ref'],
                  'effect': '%.2f%% of the observed %s keep passing; the rest and anything new is blocked by the '
                            'rules below (default deny)' % (coverage or 0, unit)})
    for extra in extra_rules:
        steps.append({'description': 'Add a %s rule to %s' % (extra['protocol'], extra['destination']),
                      'command': 'GUI: Firewall › Rules', 'effect': extra['why']})
    steps.append({'description': 'Apply, then watch the live log for blocks from this interface for a while',
                  'command': 'GUI: Apply; Firewall › Log Files › Live View', 'effect': 'filter reload'})
    warnings = []
    if unit == 'flows':
        warnings.append('Based on NetFlow (the rule does not log): flows are attributed by the rule\'s match space, '
                        'not by pf; enable logging on the rule and repeat for an exact result.')
    if confidence == 'low':
        warnings.append('Low confidence: little traffic or a short window (%s %s over %.1f days).' % (
            total, unit, observed_days))
    if wide:
        warnings.append('Many distinct destination ports: the least used were folded into one range.')
    uncertain = [t.name for t in list(rule.src.tokens) + list(rule.dst.tokens)
                 if t.opaque and t.kind in ('alias', 'unknown')]
    if unit == 'flows' and uncertain:
        warnings.append('The content of %s is only known at run time (dynamic/MAC/URL alias or interface group): '
                        'flows were attributed with the widest possible match.' % ', '.join(sorted(set(uncertain))))
    warnings.extend(n[0].upper() + n[1:] + '.' for n in notes)
    if dst_left:
        warnings.append('%d rarely used destination entries were left out (see "would be blocked").' % len(dst_left))
    warnings.append('Traffic not seen in the last %d days (monthly jobs, updates, new services) would be blocked.' %
                    days)
    base.update({
        'status': 'ok',
        'confidence': confidence,
        'observed': {'total': total, 'unit': unit, 'first': first, 'last': last, 'days_with_data': observed_days,
                     'protocols': protos, 'destinations': len(dst_w), 'sources': len(src_w), 'ports': len(port_w),
                     'top_destinations': [{'value': str(k), 'count': v} for k, v in
                                          sorted(dst_w.items(), key=lambda kv: -kv[1])[:10]],
                     'top_ports': [{'port': k, 'count': v} for k, v in sorted(port_w.items(), key=lambda kv: -kv[1])
                                   [:10]]},
        'notes': notes,
        'proposal': {'changes': changes, 'aliases': aliases, 'extra_rules': extra_rules,
                     'destination_entries': dst_entries, 'source_entries': src_entries, 'port_ranges': port_ranges},
        'coverage': {'percent': coverage, 'covered': covered_w, 'total': total,
                     'not_covered': total - covered_w},
        'would_block': blocked_list,
        'diff': '\n'.join(diff),
        'plan': {'status': 'ok', 'steps': steps, 'warnings': warnings, 'irreversible': [],
                 'revert': ['Restore the previous rule fields (Firewall › Rules) and delete the pa_min_* aliases; '
                            'the configuration history (System › Configuration › History) also has the old version.'],
                 'risk': 'medium' if coverage is not None and coverage < 100 else 'low',
                 'requires_confirmation': True,
                 'message': 'Proposal only: open the rule and change it yourself; nothing is applied from here.'},
    })
    return base


# ------------------------------------------------------------------------------------------ entry points

def candidates(paths):
    from posture.common import load_json
    cfg, rules = load_rules(paths.config)
    report = load_json(paths.report) or {}
    by_uuid = {}
    for f in report.get('findings', []):
        if f.get('type') in ('permissive', 'wan_exposed') and f.get('rules'):
            by_uuid.setdefault(f['rules'][0]['uuid'], []).append({'id': f['id'], 'type': f['type'],
                                                                   'severity': f['severity']})
    wan = [n for n, i in cfg.interfaces.items() if i.is_wan and not i.is_group]
    out = []
    for r in rules:
        if r.action != 'pass' or not r.enabled:
            continue
        reasons = []
        if r.dst.is_any or r.dst.neg:
            reasons.append('destination any')
        if r.dport is None and r.protocol_raw in ('any', 'tcp', 'udp', 'tcp/udp'):
            reasons.append('any port')
        if r.protocol_raw == 'any':
            reasons.append('any protocol')
        if r.src.is_any and 'in' in r.directions and r.ifset.touches(wan):
            reasons.append('any source on WAN')
        if not reasons and r.uuid not in by_uuid:
            continue
        out.append({'uuid': r.uuid, 'summary': r.summary, 'description': r.description, 'log': r.log,
                    'source': r.source, 'interface': ','.join(r.interfaces_raw) or 'floating',
                    'sequence': r.sequence, 'reasons': reasons, 'findings': by_uuid.get(r.uuid, []),
                    'ref': rule_ref(r), 'exact': r.log and r.source == 'mvc'})
    out.sort(key=lambda c: (0 if c['findings'] else 1, -len(c['reasons'])))
    return {'status': 'ok', 'candidates': out}


def analyze(paths, uuid, days=7, use_netflow=True):
    cfg, rules = load_rules(paths.config)
    rule = next((r for r in rules if r.uuid == uuid), None)
    if rule is None:
        return {'status': 'error', 'message': 'rule not found'}
    if rule.action != 'pass':
        return {'status': 'error', 'message': 'only pass rules can be narrowed'}
    started = time.monotonic()
    obs, meta = observe(paths, cfg, rules, rule, days, use_netflow=use_netflow)
    result = propose(cfg, rule, obs, meta, days)
    result['sources'] = {k: v for k, v in meta.items() if k not in ('since',)}
    result['duration_ms'] = int((time.monotonic() - started) * 1000)
    return result
