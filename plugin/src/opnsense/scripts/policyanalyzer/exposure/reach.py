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

    Internet reachability of each listening service, decided with the rule engine (engine/):

      1. the service must listen on a wildcard address or on an address of a WAN interface
         (loopback only or a LAN address only -> "no");
      2. a probe packet "from any internet host, in on <wan>, <proto> to <wan address> port <port>" is walked
         through the user rules in pf evaluation order (quick rules stop, otherwise last match wins).
         A pass rule that may match opens the service:
           yes   the rule certainly matches: any source, destination certainly includes the WAN address
                 ((self), the WAN address, any, a static network that contains it), port certainly included,
                 no extra match conditions;
           maybe the rule may match: opaque alias (url, GeoIP, FQDN...), restricted source, extra conditions,
                 dynamic WAN address that the engine can only bound from above;
           no    no pass rule can match (pf default deny on the WAN).
         A block/reject rule that certainly matches every such packet stops the walk when it is quick and
         cancels the earlier non quick pass rules otherwise.

    Automatic rules (anti-lockout, IPsec/OpenVPN automatic rules, plugin rules) and NAT port forwards to the
    firewall itself are not in the user rule set and are not seen (README, limitations).
"""

from engine import ipset
from engine.config import FirewallConfig
from engine.detectors import Context
from engine.report import rule_entry
from engine.resolve import Resolver
from engine.rules import RuleNormalizer, evaluation_order, ports_include

LEVEL = {'no': 0, 'maybe': 1, 'yes': 2}


class RuleSet(object):
    """ the engine view of the configuration, built once per run """

    def __init__(self, config):
        self.cfg = config if isinstance(config, FirewallConfig) else FirewallConfig(config)
        self.res = Resolver(self.cfg)
        normalizer = RuleNormalizer(self.cfg, self.res)
        self.rules = evaluation_order([normalizer.normalize(raw) for raw in self.cfg.rules])
        self.ctx = Context(self.cfg, self.res, self.rules, None, {})
        self.wan = sorted(self.ctx.wan)


def _host(addr):
    if not addr:
        return None
    return ipset.host_pair(addr)


def _self_token_for(tok, wan):
    """ does this destination token certainly mean "this WAN address" """
    if tok.kind == 'self':
        return True
    return tok.kind == 'ifaddr' and tok.name == '%sip' % wan


def _dst_level(rule, wan, host, fam):
    """ 'yes' (certainly includes the address), 'maybe' or None (excludes it) """
    i = ipset.fidx(fam)
    if host is not None:
        if not ipset.is_subset(host[i], rule.dst.upper[i]):
            return None
        if ipset.is_subset(host[i], rule.dst.lower[i]):
            return 'yes'
    elif not rule.dst.upper[i]:
        return None
    if rule.dst.is_any:
        return 'yes'
    if not rule.dst.neg and any(_self_token_for(t, wan) for t in rule.dst.tokens):
        return 'yes'
    return 'maybe'


def _iface_certain(rule, wan):
    s = rule.ifset
    if s.all:
        return True
    if s.neg:
        return wan not in s.atoms and not s.opaque
    return wan in s.atoms and wan not in s.opaque


def evaluate(rs, wan, addr, fam, proto, port):
    """ walk the rules for one probe packet. :return: (level, [(rule, level, notes)]) """
    host = _host(addr)
    quick_openers = []
    later_openers = []
    for rule in rs.ctx.decisive:
        if 'in' not in rule.directions or not rule.ifset.touches({wan}):
            continue
        if fam not in rule.active_fams:
            continue
        protos = rule.protos.get(fam)
        if protos is not None and proto not in protos:
            continue
        if not ports_include(rule.dport, port):
            continue
        dst = _dst_level(rule, wan, host, fam)
        if dst is None:
            continue
        port_certain = rule.dport is None or ipset.is_subset(((port, port),), rule.dport.lower)
        src_any = rule.src.is_any and rule.sport is None
        certain = (dst == 'yes' and src_any and port_certain and not rule.extra and _iface_certain(rule, wan))
        if rule.verdict == 'deny':
            if certain:
                if rule.quick:
                    break
                later_openers = []
            continue
        notes = []
        if not src_any:
            notes.append('source restricted')
        if any(t.opaque for t in rule.src.tokens + rule.dst.tokens):
            notes.append('opaque alias or dynamic address')
        if rule.extra:
            notes.append('extra match conditions: %s' % ', '.join(sorted(rule.extra)))
        if dst == 'maybe':
            notes.append('destination may not include the WAN address')
        level = 'yes' if certain else 'maybe'
        if rule.quick:
            quick_openers.append((rule, level, notes))
            if certain:
                break
        else:
            later_openers.append((rule, level, notes))
    openers = quick_openers + later_openers
    best = 'no'
    for _rule, level, _notes in openers:
        if LEVEL[level] > LEVEL[best]:
            best = level
    return best, openers


def wan_targets(service, interfaces, wan_names):
    """ (wan, address or None, family) the service can be reached at; [] when it never listens on a WAN """
    by_name = {i['name']: i for i in interfaces}
    wan_addrs = {}
    for name in wan_names:
        intf = by_name.get(name, {})
        wan_addrs[name] = {4: list(intf.get('ipv4') or []), 6: list(intf.get('ipv6') or [])}
    targets = []
    for bind in service['bind']:
        fam = bind['family']
        if bind['scope'] == 'loopback':
            continue
        for name in wan_names:
            addrs = [a for a in wan_addrs[name][fam] if not a.lower().startswith('fe80')]
            if bind['scope'] == 'any':
                if addrs:
                    targets.extend((name, a, fam) for a in addrs)
                else:
                    targets.append((name, None, fam))
            elif bind['address'] in addrs:
                targets.append((name, bind['address'], fam))
    seen = []
    for t in targets:
        if t not in seen:
            seen.append(t)
    return seen


def assess(rs, service, interfaces):
    """ adds internet_reachable / reach / rules to a service dict (in place) and returns it """
    targets = wan_targets(service, interfaces, rs.wan)
    reach = {'targets': [], 'reason': None}
    rules = {}
    best = 'no'
    source_restricted = True
    if not rs.wan:
        reach['reason'] = 'no WAN interface found in the configuration'
    elif service['scope'] == 'loopback':
        reach['reason'] = 'listens on loopback only'
    elif not targets:
        reach['reason'] = 'listens only on addresses of non WAN interfaces'
    for wan, addr, fam in targets:
        level, openers = evaluate(rs, wan, addr, fam, service['proto'], service['port'])
        reach['targets'].append({'interface': wan, 'family': fam, 'address_known': addr is not None,
                                 'level': level, 'rules': [r.uuid for r, _l, _n in openers]})
        for rule, rlevel, notes in openers:
            item = rules.setdefault(rule.uuid, dict(rule_entry(rule, legacy_page=False), level=rlevel, notes=notes))
            if LEVEL[rlevel] > LEVEL[item['level']]:
                item['level'] = rlevel
            if 'source restricted' not in notes:
                source_restricted = False
        if LEVEL[level] > LEVEL[best]:
            best = level
    if targets and best == 'no':
        reach['reason'] = 'no pass rule on the WAN matches this port (default deny)'
    service['internet_reachable'] = best
    service['reach'] = reach
    service['rules'] = sorted(rules.values(), key=lambda r: (-LEVEL[r['level']], r['sequence']))
    service['source_restricted'] = bool(rules) and source_restricted
    return service
