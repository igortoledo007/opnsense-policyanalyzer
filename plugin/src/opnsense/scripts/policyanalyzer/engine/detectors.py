"""
    Copyright (c) 2026 Igor Toledo
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

    Detectors. Each detector returns a list of Finding objects; the exact logic of each one is documented
    in tests/README.md.
"""

import datetime

from .config import EFFECT_FIELDS
from .rules import ports_include

DAY = 86400.0


class Finding(object):
    def __init__(self, ftype, severity, title, detail, recommendation, rules=(), aliases=(), evidence=None,
                 key=''):
        self.type = ftype
        self.severity = severity
        self.title = title
        self.detail = detail
        self.recommendation = recommendation
        self.rules = list(rules)
        self.aliases = sorted(set(aliases))
        self.evidence = evidence or {}
        self.key = key


def _ref(rule):
    """ short human reference to a rule inside detail texts """
    if rule.description:
        return '"%s"' % rule.description
    return '%s rule #%d' % (rule.source.upper() if rule.source == 'mvc' else 'legacy', rule.sequence)


def _effect_diff(a, b):
    if a.action != b.action and 'pass' in (a.action, b.action):
        return ['action']  # options of a pass rule are meaningless next to a block/reject rule
    diff = []
    for idx, key in enumerate(('action',) + EFFECT_FIELDS):
        if a.effect[idx] != b.effect[idx]:
            diff.append(key)
    return diff


def _parse_time(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return None


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).replace(microsecond=0).isoformat()


class Context(object):
    def __init__(self, cfg, resolver, rules, stats, stats_meta, now=None):
        self.cfg = cfg
        self.res = resolver
        self.rules = rules
        self.stats = stats
        self.stats_meta = stats_meta
        self.now = now if now is not None else datetime.datetime.now(datetime.timezone.utc).timestamp()
        self.wan = frozenset(n for n, i in cfg.interfaces.items() if i.is_wan and not i.is_group)
        if stats is not None:
            # the loaded ruleset is the ground truth: a labelled pf rule means the generator did load it
            for rule in rules:
                if rule.enabled and not rule.loaded and rule.uuid in stats:
                    rule.loaded = True
                    rule.notes.extend(rule.inactive_reasons)
                    rule.inactive_reasons = []
        self.evaluated = [r for r in rules if r.enabled and r.loaded and not r.matches_nothing]
        # 27.1 "match" rules apply options but never decide pass/block: they neither cover nor are covered by
        # pass/block rules in the order analysis. A *quick* match rule still ends the evaluation
        # (pf.conf: "this rule is considered the last matching rule"), see detect_quick_match().
        self.matching = [r for r in self.evaluated if r.verdict == 'match']
        self.decisive = [r for r in self.evaluated if r.verdict != 'match']

    def wan_inbound(self, rule):
        return 'in' in rule.directions and bool(self.wan) and rule.ifset.touches(self.wan)


# ------------------------------------------------------------------ order based detectors

def detect_order(ctx):
    """ shadowed / redundant / duplicate (pass/block/reject rules only) """
    findings = []
    ev = ctx.decisive
    for i, rule in enumerate(ev):
        cover = None
        mode = None
        for prev in ev[:i]:
            if prev.quick and prev.covers(rule):
                cover, mode = prev, 'earlier_quick'
                break
        if cover is None and not rule.quick:
            for nxt in ev[i + 1:]:
                if nxt.covers(rule):
                    cover, mode = nxt, 'later_overrides'
                    break
        if cover is not None:
            findings.append(_classify_cover(rule, cover, mode))
            continue
        if rule.quick:
            later = _covered_by_later(ev, i)
            if later is not None:
                findings.append(Finding(
                    'redundant', 'low',
                    'Rule is redundant with a later rule',
                    'Every packet matched by %s is also matched by the later rule %s with the same action and '
                    'options, and no rule in between with a different outcome can match the same traffic. '
                    'Removing it would not change the policy.' % (_ref(rule), _ref(later)),
                    'Remove the rule or merge it into the broader rule after confirming the intent.',
                    rules=[rule, later], aliases=rule.aliases | later.aliases,
                    evidence={'mode': 'later_covers', 'covering_uuid': later.uuid},
                    key='later'
                ))
    return findings


def _covered_by_later(ev, i):
    rule = ev[i]
    for j in range(i + 1, len(ev)):
        cand = ev[j]
        if not cand.quick or cand.effect != rule.effect or not cand.covers(rule):
            continue
        for between in ev[i + 1:j]:
            if between.quick and between.effect != rule.effect and between.may_overlap(rule):
                return None
        return cand
    return None


def _classify_cover(rule, cover, mode):
    diff = _effect_diff(cover, rule)
    evidence = {'mode': mode, 'covering_uuid': cover.uuid, 'covering_quick': cover.quick,
                'same_match': rule.same_match(cover), 'differences': diff}
    if rule.log != cover.log:
        evidence['log_differs'] = True
    aliases = rule.aliases | cover.aliases
    if mode == 'earlier_quick':
        how = 'the earlier quick rule %s matches every packet this rule matches, so evaluation always stops ' \
              'there' % _ref(cover)
    else:
        how = 'this rule is not "quick" and the later rule %s matches every packet it matches, so its ' \
              'decision is always overridden (pf uses the last matching rule)' % _ref(cover)
    rules = [rule, cover]
    if not diff:
        if evidence['same_match']:
            return Finding('duplicate', 'medium', 'Duplicate rule',
                           'Rule %s is identical in match and effect to %s: %s.' % (_ref(rule), _ref(cover), how),
                           'Remove one of the duplicate rules.',
                           rules=rules, aliases=aliases, evidence=evidence, key=mode)
        return Finding('redundant', 'medium', 'Rule is redundant',
                       'Rule %s never decides anything: %s, and both rules have the same action and options.'
                       % (_ref(rule), how),
                       'Remove the rule, or move it above the broader rule if it was meant to be more specific.',
                       rules=rules, aliases=aliases, evidence=evidence, key=mode)
    if rule.verdict != cover.verdict:
        severity = 'high'
        title = 'Rule is shadowed by a rule with the opposite action'
    else:
        severity = 'medium'
        title = 'Rule is shadowed by a rule with different options'
    return Finding('shadowed', severity, title,
                   'Rule %s (%s) can never take effect: %s (%s). Differences: %s.'
                   % (_ref(rule), rule.action, how, cover.action, ', '.join(diff)),
                   'Move the rule above %s if it is meant to apply, otherwise disable or remove it.' % _ref(cover),
                   rules=rules, aliases=aliases, evidence=evidence, key=mode)


def detect_quick_match(ctx):
    """ a quick match rule ends the evaluation: later pass/block rules it covers are never evaluated """
    findings = []
    ev = ctx.evaluated
    for i, rule in enumerate(ev):
        if rule.verdict != 'match' or not rule.quick:
            continue
        for later in ev[i + 1:]:
            if later.verdict == 'match' or not rule.covers(later):
                continue
            findings.append(Finding(
                'shadowed', 'high', 'Rule is never evaluated after a quick match rule',
                'The quick match rule %s matches every packet %s matches; pf stops evaluating there and keeps '
                'the decision of the last pass/block rule matched before it (or the default rule), so %s (%s) '
                'never takes effect.' % (_ref(rule), _ref(later), _ref(later), later.action),
                'Clear "quick" on the match rule (match rules are normally not quick) or move the rule above it.',
                rules=[later, rule], aliases=rule.aliases | later.aliases,
                evidence={'mode': 'quick_match', 'covering_uuid': rule.uuid, 'covering_quick': True},
                key='quick_match'))
    return findings


def detect_match_duplicates(ctx):
    """ two match rules with the same match space and the same options: the second adds nothing """
    findings = []
    ev = ctx.matching
    for i, rule in enumerate(ev):
        for prev in ev[:i]:
            if prev.effect == rule.effect and prev.quick == rule.quick and rule.same_match(prev):
                findings.append(Finding(
                    'duplicate', 'medium', 'Duplicate match rule',
                    'Match rule %s is identical in match and options to the earlier match rule %s; pf applies '
                    'the same options twice.' % (_ref(rule), _ref(prev)),
                    'Remove one of the duplicate rules.',
                    rules=[rule, prev], aliases=rule.aliases | prev.aliases,
                    evidence={'mode': 'match_duplicate', 'covering_uuid': prev.uuid, 'same_match': True,
                              'differences': []},
                    key='match_duplicate'))
                break
    return findings


# ------------------------------------------------------------------ per rule detectors

def detect_disabled(ctx):
    findings = []
    for rule in ctx.rules:
        if rule.enabled:
            continue
        evidence = {}
        severity = 'info'
        updated = (rule.audit.get('updated') or rule.audit.get('created') or {}).get('time')
        ts = _parse_time(updated) if updated else None
        detail = 'Rule %s is disabled and is not part of the active ruleset.' % _ref(rule)
        if ts:
            days = int((ctx.now - ts) / DAY)
            evidence['last_change'] = _iso(ts)
            evidence['days_since_change'] = days
            if days >= 90:
                severity = 'low'
                detail += ' It was last changed %d days ago.' % days
        findings.append(Finding('disabled', severity, 'Disabled rule', detail,
                                'Remove the rule if it is no longer needed; keep disabled rules only with a '
                                'description of why they are kept.',
                                rules=[rule], aliases=rule.aliases, evidence=evidence))
    return findings


def detect_inactive(ctx):
    findings = []
    for rule in ctx.rules:
        if rule.enabled and not rule.loaded:
            findings.append(Finding(
                'inactive', 'medium', 'Enabled rule is not loaded',
                'Rule %s is enabled but the rule generator skips or disables it: %s.'
                % (_ref(rule), '; '.join(rule.inactive_reasons)),
                'Fix the reference (interface, alias or port) or remove the rule.',
                rules=[rule], aliases=rule.aliases, evidence={'reasons': rule.inactive_reasons}))
    return findings


def detect_never_matches(ctx, empty_aliases):
    findings = []
    for rule in ctx.rules:
        if not (rule.enabled and rule.loaded and rule.matches_nothing):
            continue
        if rule.aliases & empty_aliases:
            continue  # reported by empty_alias
        findings.append(Finding(
            'never_matches', 'medium', 'Rule can never match',
            'Rule %s can not match any packet: its addresses or ports do not exist for the selected IP '
            'version(s) (%s).' % (_ref(rule), rule.ipprotocol),
            'Check the TCP/IP version and the address/port fields of the rule.',
            rules=[rule], aliases=rule.aliases, evidence={'ipprotocol': rule.ipprotocol}))
    return findings


def detect_no_description(ctx):
    return [
        Finding('no_description', 'info', 'Rule has no description',
                'Rule #%d (%s) has no description, which makes reviews and log analysis harder.'
                % (rule.sequence, rule.summary),
                'Add a description that states the purpose and the owner of the rule.',
                rules=[rule], aliases=rule.aliases)
        for rule in ctx.rules if rule.enabled and not rule.description.strip()
    ]


def detect_permissive(ctx):
    findings = []
    for rule in ctx.evaluated:
        if rule.action != 'pass':
            continue
        src_any = rule.src.is_any
        dst_any = rule.dst.is_any
        all_protocols = rule.protocol_raw == 'any'
        all_ports = all_protocols or rule.dport is None
        wan_in = ctx.wan_inbound(rule)
        reasons = []
        severity = None
        if src_any and dst_any and all_protocols:
            reasons.append('any_any')
            severity = 'high' if wan_in else 'medium'
        elif wan_in and src_any and all_ports:
            reasons.append('wan_any_source_any_port')
            severity = 'medium'
        elif wan_in and src_any and dst_any:
            reasons.append('wan_any_source_any_destination')
            severity = 'medium'
        elif src_any and dst_any:
            reasons.append('any_any_protocol_limited')
            severity = 'low'
        elif wan_in and src_any:
            reasons.append('wan_any_source')
            severity = 'info'
        if severity is None:
            continue
        texts = {
            'any_any': 'passes any source to any destination on every protocol and port',
            'wan_any_source_any_port': 'accepts traffic from any source on an internet facing interface '
                                       'without restricting the destination port',
            'wan_any_source_any_destination': 'accepts traffic from any source to any destination on an '
                                              'internet facing interface',
            'any_any_protocol_limited': 'passes any source to any destination (only the protocol or port '
                                        'is restricted)',
            'wan_any_source': 'accepts traffic from any source on an internet facing interface',
        }
        findings.append(Finding(
            'permissive', severity, 'Overly permissive rule',
            'Rule %s %s.' % (_ref(rule), texts[reasons[0]]),
            'Restrict the source, destination and ports to what is actually needed.',
            rules=[rule], aliases=rule.aliases,
            evidence={'reasons': reasons, 'wan_inbound': wan_in, 'source_any': src_any,
                      'destination_any': dst_any, 'all_ports': all_ports},
            key=reasons[0]))
    return findings


def detect_wan_exposed(ctx):
    findings = []
    admin_ports = ctx.cfg.admin_ports
    for rule in ctx.evaluated:
        if rule.action != 'pass' or not ctx.wan_inbound(rule):
            continue
        tcp_possible = any(p is None or 'tcp' in p for f, p in rule.protos.items() if f in rule.active_fams)
        admin = sorted(p for p in admin_ports if tcp_possible and ports_include(rule.dport, p))
        explicit_self = not rule.dst.neg and any(t.is_self for t in rule.dst.tokens)
        includes_self = explicit_self or rule.dst.neg or any(
            t.kind in ('any', 'ifnet', 'alias', 'unknown') for t in rule.dst.tokens)
        src_any = rule.src.is_any
        severity = None
        if explicit_self and admin:
            severity = 'high' if src_any else 'medium'
            what = 'the firewall management service(s) %s' % ', '.join(
                '%s/%d' % (admin_ports[p], p) for p in admin)
        elif explicit_self:
            if not src_any:
                continue
            severity = 'low'
            what = 'a service running on the firewall itself'
        elif includes_self and admin and rule.dport is not None:
            severity = 'high' if src_any else 'medium'
            what = 'destinations that include the firewall, on its management port(s) %s' % ', '.join(
                '%s/%d' % (admin_ports[p], p) for p in admin)
        if severity is None:
            continue
        findings.append(Finding(
            'wan_exposed', severity, 'Firewall service exposed on an internet facing interface',
            'Rule %s accepts inbound traffic%s on %s to %s.'
            % (_ref(rule), ' from any source' if src_any else '', ','.join(sorted(
                ctx.wan & (rule.ifset.atoms if not rule.ifset.all and not rule.ifset.neg else ctx.wan))), what),
            'Limit the source to trusted addresses (or use a VPN) and avoid exposing management ports.',
            rules=[rule], aliases=rule.aliases,
            evidence={'admin_ports': admin, 'explicit_self': explicit_self, 'source_any': src_any}))
    return findings


def _counters_since(ctx, rule):
    """ start of the counting window for a rule (epoch) and a text describing it """
    meta = ctx.stats_meta
    if ctx.cfg.keepcounters:
        # "set keepcounters": counters survive reloads for unchanged rules; they restart at boot or when the
        # rule itself is changed
        candidates = [_parse_time(meta.get('boot_time'))]
        changed = (rule.audit.get('updated') or rule.audit.get('created') or {}).get('time')
        candidates.append(_parse_time(changed) if changed else None)
        candidates = [c for c in candidates if c]
        if not candidates:
            return None, 'since the counters were last reset (keepcounters is enabled)'
        since = max(candidates)
        return since, 'since %s (boot or last change of the rule, keepcounters is enabled)' % _iso(since)
    since = _parse_time(meta.get('ruleset_loaded')) if meta.get('ruleset_loaded') else None
    if since:
        return since, 'since the ruleset was last loaded at %s' % _iso(since)
    return None, 'since the ruleset was last loaded'


def detect_unused(ctx):
    if ctx.stats is None:
        return []
    findings = []
    keep = ctx.cfg.keepcounters
    for rule in ctx.evaluated:
        if rule.source != 'mvc':
            continue  # legacy rules are labelled with a PHP md5 hash, not mapped here
        counters = ctx.stats.get(rule.uuid)
        if counters is None:
            if ctx.cfg.filter_settings.get('skip_rules_gw_down') == '1' and rule.fields.get('gateway'):
                why = 'for example its gateway is down and "skip rules when gateway is down" is enabled, ' \
                      'or the change is still pending apply'
            else:
                why = 'for example the change is still pending apply'
            findings.append(Finding(
                'inactive', 'low', 'Rule is not present in the loaded ruleset',
                'Rule %s is enabled but no pf rule carries its label, so it is not active right now (%s).'
                % (_ref(rule), why),
                'Apply the firewall changes and check the rule\'s gateway and interface.',
                rules=[rule], aliases=rule.aliases, evidence={'reasons': ['label not found in pf ruleset']},
                key='not_loaded'))
            continue
        if int(counters.get('packets', 0) or 0) == 0 and int(counters.get('states', 0) or 0) == 0:
            since, window = _counters_since(ctx, rule)
            age_days = int((ctx.now - since) / DAY) if since else None
            severity = 'info' if age_days is None or age_days < 7 else 'low'
            findings.append(Finding(
                'unused', severity, 'Rule has no hits',
                'Rule %s matched 0 packets %s (evaluated %s times). pf counters restart on every filter '
                'reload unless "keepcounters" is enabled, so a short window is not conclusive.'
                % (_ref(rule), window, counters.get('evaluations', 0)),
                'Watch the counters over a representative period (or enable "keep counters" in %s) before '
                'removing the rule.' % ctx.cfg.settings_page,
                rules=[rule], aliases=rule.aliases,
                evidence={'packets': counters.get('packets', 0), 'evaluations': counters.get('evaluations', 0),
                          'states': counters.get('states', 0), 'pf_rules': counters.get('pf_rules', 0),
                          'counters_since': _iso(since) if since else None, 'keepcounters': keep,
                          'window_days': age_days}))
    return findings


# ------------------------------------------------------------------ alias detectors

def detect_aliases(ctx):
    """ empty_alias and unused_alias; returns (findings, set of empty alias names) """
    findings = []
    empty = set()
    referencing = {}
    for rule in ctx.rules:
        for name in rule.aliases:
            referencing.setdefault(name, []).append(rule)
    tokens = ctx.cfg.text_tokens()
    for name in sorted(ctx.cfg.aliases):
        alias = ctx.cfg.aliases[name]
        if alias.builtin:
            continue
        if ctx.res.alias_is_empty(name):
            empty.add(name)
            users = [r for r in referencing.get(name, []) if r.enabled]
            if users:
                detail = 'Alias "%s" (%s) has no entries in the configuration; %d enabled rule(s) using it ' \
                         'can not match anything through it.' % (name, alias.type, len(users))
                if alias.type == 'port':
                    severity = 'medium'
                else:
                    # host/network tables can still be filled at runtime through the alias API
                    severity = 'low'
                    detail += ' Entries added at runtime (alias API, scripts) are not visible to this analysis.'
            else:
                severity = 'info'
                detail = 'Alias "%s" (%s) has no entries in the configuration.' % (name, alias.type)
            findings.append(Finding('empty_alias', severity, 'Alias is empty', detail,
                                    'Add the intended entries or remove the alias and the rules that use it.',
                                    rules=users, aliases=[name],
                                    evidence={'alias_type': alias.type, 'referencing_rules': len(users)}))
        if name not in tokens and (not alias.uuid or alias.uuid not in tokens):
            findings.append(Finding('unused_alias', 'info', 'Alias is not used',
                                    'Alias "%s" (%s) is not referenced by any rule, NAT entry, other alias or '
                                    'setting in the configuration.' % (name, alias.type),
                                    'Remove the alias if it is no longer needed.',
                                    aliases=[name], evidence={'alias_type': alias.type}))
    return findings, empty


def run_all(ctx):
    findings = []
    alias_findings, empty = detect_aliases(ctx)
    findings.extend(detect_order(ctx))
    findings.extend(detect_quick_match(ctx))
    findings.extend(detect_match_duplicates(ctx))
    exposed = detect_wan_exposed(ctx)
    exposed_uuids = set(f.rules[0].uuid for f in exposed)
    findings.extend(exposed)
    # "any source on WAN" (info) adds nothing when the same rule is already reported as wan_exposed
    findings.extend(f for f in detect_permissive(ctx)
                    if not (f.key == 'wan_any_source' and f.rules[0].uuid in exposed_uuids))
    findings.extend(detect_unused(ctx))
    findings.extend(detect_inactive(ctx))
    findings.extend(detect_never_matches(ctx, empty))
    findings.extend(alias_findings)
    findings.extend(detect_disabled(ctx))
    findings.extend(detect_no_description(ctx))
    return findings
