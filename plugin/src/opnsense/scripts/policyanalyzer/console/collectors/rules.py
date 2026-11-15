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

    Firewall rules collector (read only).

    Rules come from config.xml through the Policy Analyzer engine (MVC + legacy, evaluation order, summaries),
    counters through the same source the core GUI uses (configctl filter rule stats -> rule_stats.py, see
    engine/stats.py).  MVC rules are labelled with their uuid; automatic rules (anti-lockout, default deny,
    bogons, plugins) carry an md5 label that only /tmp/rules.debug knows, together with the description.

        index(paths)                  label -> {display, ...} for log lines (rid field)
        table(paths, budget, flt)     rule list with counters and findings (Rules tab)
        find(paths, refs)             rules named in a question (uuid, label or description text)
        evidence(paths, budget, ids)  rules + counters + findings, for the model
        path(paths, packet)           static evaluation of a packet against the rules (approximate)
"""

import ipaddress
import os
import re
import unicodedata

from engine import ipset
from engine.config import FirewallConfig
from engine.report import priority_group, rule_ref, stats_block
from engine.resolve import Resolver
from engine.rules import RuleNormalizer, evaluation_order
from engine.stats import load_stats

from ..common import clean_text, is_public, load_json
from . import fwinfo

_CACHE = {}
_DEBUG_LABEL = re.compile(r'label "([0-9a-f]{32}|[0-9a-f-]{36})"\s*(?:#\s*(.*))?$')


def _norm(text):
    text = unicodedata.normalize('NFKD', str(text or '').lower())
    return ''.join(c for c in text if not unicodedata.combining(c)).strip()


def _mtime(path):
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def load(paths):
    """ (cfg, normalized rules in evaluation order), cached by config mtime; (None, []) when unreadable """
    key = (paths.config, _mtime(paths.config))
    if key in _CACHE:
        return _CACHE[key]
    try:
        cfg = FirewallConfig(paths.config)
    except (OSError, SyntaxError):
        return None, []
    normalizer = RuleNormalizer(cfg, Resolver(cfg))
    rules = evaluation_order([normalizer.normalize(raw) for raw in cfg.rules])
    _CACHE.clear()
    _CACHE[key] = (cfg, rules)
    return cfg, rules


def display(rule, position=None):
    """ short, stable way to cite a rule: interface, position, action and description """
    where = 'floating' if rule.floating else (','.join(rule.interfaces_raw) or 'any')
    text = '%s #%s %s' % (where, position if position is not None else rule.sequence, rule.action)
    if rule.description:
        text += ' "%s"' % clean_text(rule.description, 80)
    return text


def automatic_labels(path):
    """ labels of /tmp/rules.debug that are not MVC uuids: label -> {description, pf} """
    result = {}
    try:
        with open(path, 'r', errors='replace') as handle:
            for line in handle:
                if 'label "' not in line or line.lstrip().startswith('#'):
                    continue
                m = _DEBUG_LABEL.search(line.rstrip())
                if not m or m.group(1) in result:
                    continue
                pf = line.split(' label "')[0].strip()
                result[m.group(1)] = {'description': clean_text(m.group(2) or '', 100), 'pf': clean_text(pf, 160)}
    except OSError:
        pass
    return result


def index(paths):
    """ label (rid of the log) -> {display, uuid, action, interface, automatic} """
    cfg, rules = load(paths)
    result = {}
    for pos, rule in enumerate(rules, 1):
        if rule.source == 'mvc' and rule.uuid:
            result[rule.uuid] = {'display': display(rule), 'uuid': rule.uuid, 'action': rule.action,
                                 'interface': ','.join(rule.interfaces_raw), 'automatic': False}
    for label, info in automatic_labels(paths.rules_debug).items():
        if label not in result:
            text = info['description'] or info['pf']
            result[label] = {'display': 'automatic "%s"' % text, 'uuid': None, 'automatic': True,
                             'pf': info['pf']}
    return result


def counters(paths, budget):
    """ :return: (stats dict or None, meta) """
    seconds = max(3, min(20, int(budget.left())))
    try:
        return load_stats(paths.stats_file, timeout=seconds)
    except Exception as exc:                        # noqa: BLE001
        return None, {'source': None, 'error': 'counters not available: %s' % exc.__class__.__name__}


def findings_by_rule(paths):
    report = load_json(paths.report) or {}
    result = {}
    for finding in report.get('findings') or []:
        if not isinstance(finding, dict):
            continue
        for pos, rule in enumerate(finding.get('rules') or []):
            uuid = rule.get('uuid') if isinstance(rule, dict) else None
            if uuid:
                result.setdefault(uuid, []).append({
                    'id': finding.get('id'), 'type': finding.get('type'), 'severity': finding.get('severity'),
                    'title': finding.get('title'), 'role': 'affected' if pos == 0 else 'related',
                })
    return result, report.get('generated')


def entry(rule, position, stats, findings, legacy_page=False, brief=False):
    """ one rule as a dict; brief=True leaves out what the model does not need (uuid, edit link) """
    item = {
        'uuid': rule.uuid,
        'position': position,
        'source': rule.source,
        'interface': '' if rule.ifset.all else ('!' if rule.ifset.neg else '') + ','.join(rule.interfaces_raw),
        'direction': rule.direction_raw,
        'action': rule.action,
        'quick': rule.quick,
        'enabled': rule.enabled,
        'loaded': rule.loaded,
        'log': rule.log,
        'sequence': rule.sequence,
        'priority_group': priority_group(rule),
        'description': rule.description,
        'summary': rule.summary,
        'display': display(rule),
        'ref': rule_ref(rule, legacy_page),
    }
    if rule.inactive_reasons:
        item['inactive_reasons'] = rule.inactive_reasons[:3]
    if stats is not None:
        c = stats.get(rule.uuid) if rule.source == 'mvc' else None
        item['counters'] = {k: c.get(k, 0) for k in ('evaluations', 'packets', 'bytes', 'states')} if c else None
    if findings.get(rule.uuid):
        item['findings'] = findings[rule.uuid][:6]
    if brief:
        for key in ('uuid', 'ref', 'description', 'priority_group'):
            item.pop(key, None)
        if item.get('loaded'):
            item.pop('loaded')
        if item.get('source') == 'mvc':
            item.pop('source')
        for f in item.get('findings') or []:
            f.pop('id', None)
    return item


def table(paths, budget, search='', interface='', unused=False, action='', with_counters=True):
    cfg, rules = load(paths)
    if cfg is None:
        return {'status': 'error', 'message': 'unable to read the configuration'}
    stats, meta = counters(paths, budget) if with_counters else (None, {})
    findings, generated = findings_by_rule(paths)
    needle = _norm(search)
    rows = []
    for pos, rule in enumerate(rules, 1):
        item = entry(rule, pos, stats, findings)
        if interface and interface not in rule.interfaces_raw and not (interface == 'floating' and rule.floating):
            continue
        if action and rule.action != action and not (action == 'block' and rule.action == 'reject'):
            continue
        if needle and needle not in _norm(' '.join([rule.description, rule.summary, rule.uuid])):
            continue
        if unused and not (rule.enabled and stats is not None and rule.source == 'mvc' and
                           (item.get('counters') or {}).get('packets', 0) == 0):
            continue
        rows.append(item)
    return {
        'status': 'ok',
        'rows': rows,
        'total': len(rules),
        'stats_available': stats is not None,
        'stats': stats_block(cfg, stats, meta or {}),
        'report_generated': generated,
        'interfaces': [{'name': i['name'], 'descr': i['descr']} for i in fwinfo.interfaces(paths.config)],
    }


def find(paths, refs, limit=5):
    """ rules named by uuid, log label or description words; [(position, rule)] """
    cfg, rules = load(paths)
    found = []
    uuids = set(refs.get('uuids') or []) | set(refs.get('labels') or [])
    texts = [_norm(t) for t in refs.get('texts') or [] if t]
    for pos, rule in enumerate(rules, 1):
        if rule.uuid in uuids:
            found.append((pos, rule, 3))
            continue
        desc = _norm(rule.description)
        if not desc:
            continue
        for text in texts:
            if text == desc:
                found.append((pos, rule, 2))
                break
            if len(text) >= 3 and (text in desc or (len(desc) >= 4 and desc in text)):
                found.append((pos, rule, 1))
                break
            words = [w for w in re.findall(r'\w+', text) if len(w) >= 3]
            if words and all(w in desc for w in words):
                found.append((pos, rule, 1))
                break
    found.sort(key=lambda item: (-item[2], item[0]))
    return [(pos, rule) for pos, rule, _ in found[:limit]]


def automatic_matches(paths, refs):
    labels = automatic_labels(paths.rules_debug)
    out = []
    for label in (refs.get('labels') or []) + (refs.get('uuids') or []):
        if label in labels:
            out.append({'label': label, 'display': 'automatic "%s"' % (labels[label]['description'] or ''),
                        'pf': labels[label]['pf'], 'automatic': True})
    return out


def evidence(paths, budget, refs):
    cfg, _rules = load(paths)
    if cfg is None:
        return {'available': False, 'message': 'unable to read the configuration'}
    matched = find(paths, refs)
    stats, meta = counters(paths, budget) if matched else (None, {})
    findings, generated = findings_by_rule(paths)
    result = {
        'available': True,
        'source': 'config.xml + configctl filter rule stats',
        'asked_for': {'texts': refs['texts']} if refs.get('texts') else 'rule id',
        'matched_rules': [entry(rule, pos, stats, findings, brief=True) for pos, rule in matched],
        'matched_uuids': [rule.uuid for _pos, rule in matched],
        'automatic_rules': automatic_matches(paths, refs),
        'stats_available': stats is not None,
        'counters_since': stats_block(cfg, stats, meta or {}).get('counters_since'),
        'keepcounters': bool(cfg.keepcounters),
        'findings_report_generated': generated,
    }
    if not matched and not result['automatic_rules']:
        result['message'] = 'no rule matches the reference given in the question'
    return result


# ------------------------------------------------------------------------------------------------ path

def _contains(ranges, value):
    return ipset.is_subset(((value, value),), ranges)


def candidates(rules, iface, direction, src, dst, dport, proto, limit=12):
    """
    Walk the rules in evaluation order for one packet.  :return: (candidates, decision)
    candidates: [(position, rule, certain)]; decision: (position, rule) of the rule that decides, or None
    certain = the packet is inside the lower bound of every field (no alias, schedule or option that could
    exclude it); otherwise the rule only may match.
    """
    fam = (src or dst).version if (src or dst) else 4
    idx = ipset.fidx(fam)
    out = []
    decision = None
    last = None
    for pos, rule in enumerate(rules, 1):
        if not rule.enabled or not rule.loaded or fam not in rule.active_fams:
            continue
        if direction not in rule.directions:
            continue
        if iface and not rule.ifset.touches([iface]):
            continue
        certain = not rule.ifset.opaque
        protos = rule.protos.get(fam)
        if protos is not None:
            if proto and proto not in protos:
                continue
            if not proto:
                certain = False
        ok = True
        for value, field in ((src, rule.src), (dst, rule.dst)):
            if value is None:
                if not field.is_any:
                    certain = False
                continue
            if not _contains(field.upper[idx], int(value)):
                ok = False
                break
            if not _contains(field.lower[idx], int(value)):
                certain = False
        if not ok:
            continue
        if rule.dport is not None:
            if dport is None:
                certain = False
            elif not _contains(rule.dport.upper, dport):
                continue
            elif not _contains(rule.dport.lower, dport):
                certain = False
        if rule.sport is not None or rule.extra:
            certain = False
        out.append((pos, rule, certain))
        if certain and rule.verdict != 'match':
            if rule.quick:
                decision = (pos, rule)
                break
            last = (pos, rule)
    if decision is None:
        decision = last
    if len(out) > limit:
        keep = [c for c in out if c[2]][-limit // 2:]
        out = (out[:limit - len(keep)] + keep) if keep else out[:limit]
        out = sorted(set(out), key=lambda c: c[0])
    return out, decision


def path(paths, src=None, dst=None, dport=None, proto=None, budget=None, assumed=None):
    """ which configured rules a packet src -> dst:dport/proto meets on its inbound interface """
    cfg, rules = load(paths)
    if cfg is None:
        return {'available': False, 'message': 'unable to read the configuration'}
    try:
        src_ip = ipaddress.ip_address(src) if src else None
        dst_ip = ipaddress.ip_address(dst) if dst else None
    except ValueError:
        return {'available': False, 'message': 'invalid address'}
    if src_ip and dst_ip and src_ip.version != dst_ip.version:
        dst_ip = None
    findings, _generated = findings_by_rule(paths)
    ifaces = []
    if src_ip is not None:
        item = fwinfo.interface_of(paths.config, src_ip)
        if item:
            ifaces = [item]
        elif is_public(src_ip):
            ifaces = [i for i in fwinfo.interfaces(paths.config) if i['wan']][:2]
    if not ifaces and dst_ip is not None and not is_public(dst_ip):
        ifaces = [i for i in fwinfo.interfaces(paths.config) if i['wan']][:2]
    result = {
        'available': True,
        'method': 'static evaluation of the configured rules in pf order (approximate)',
        'packet': {'src': str(src_ip) if src_ip else 'unknown', 'dst': str(dst_ip) if dst_ip else 'unknown',
                   'dport': dport, 'proto': proto or 'unknown'},
        'assumptions': assumed or [],
        'paths': [],
        'notes': [
            'automatic rules (anti-lockout, bogon and private network blocks, default deny, plugin rules) are '
            'not in the configuration and are not part of this evaluation',
            'without a matching pass rule the default deny rule blocks the packet',
            'certain=false: an alias, schedule, option or unknown field may exclude the packet',
        ],
    }
    if not ifaces:
        result['message'] = 'the inbound interface of this packet could not be determined from the subnets'
    for item in ifaces:
        cands, decision = candidates(rules, item['name'], 'in', src_ip, dst_ip, dport, proto)
        result['paths'].append({
            'interface': '%s (%s, %s)' % (item['name'], item['descr'], item['device']),
            'direction': 'in',
            'candidates': [dict(entry(rule, pos, None, findings, brief=True), certain=certain)
                           for pos, rule, certain in cands],
            'likely_decision': (entry(decision[1], decision[0], None, findings, brief=True)
                                if decision else 'default deny (no certain pass/block rule matched)'),
        })
    return result
