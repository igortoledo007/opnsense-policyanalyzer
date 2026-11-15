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

    Rule normalization and match space containment.

    Evaluation order mirrors the rule generator (filter.inc / Plugin.php / FilterRuleContainerField):
      priority 200000 floating (MVC rules with zero or several interfaces, or an inverted interface;
                        legacy rules flagged <floating>),
      priority 300000 + group sequence for rules on an interface group,
      priority 400000 for single interface rules,
    inside a priority MVC rules (ordered by sequence) precede legacy rules (config order).
    pf is last-match, "quick" stops evaluation.
"""

from . import ipset
from .config import MATCH_EXTRA_FIELDS, MATCH_EXTRA_SET_FIELDS, EFFECT_FIELDS, BOOL_FIELDS, MATCH_EFFECT_FIELDS



class IfSet(object):
    """ set of logical interfaces a rule applies to: everything, a list, or everything except a list """
    __slots__ = ('all', 'neg', 'atoms', 'opaque')

    def __init__(self, all_=False, neg=False, atoms=(), opaque=()):
        self.all = all_
        self.neg = neg
        self.atoms = frozenset(atoms)
        self.opaque = frozenset(opaque)

    def covers(self, other):
        if self.all:
            return True
        if other.all:
            return False
        if not self.neg and not other.neg:
            return other.atoms <= self.atoms
        if self.neg and not other.neg:
            return not (other.atoms & self.atoms) and not other.opaque and not self.opaque
        if self.neg and other.neg:
            return self.atoms <= other.atoms and not self.opaque and not other.opaque
        return False

    def may_overlap(self, other):
        if self.all or other.all:
            return True
        if not self.neg and not other.neg:
            if self.opaque or other.opaque:
                return True
            return bool(self.atoms & other.atoms)
        if self.neg and not other.neg:
            return not other.atoms <= self.atoms or bool(other.opaque)
        if other.neg and not self.neg:
            return not self.atoms <= other.atoms or bool(self.opaque)
        return True

    def touches(self, names):
        """ may this set include any of the given interfaces """
        if self.all:
            return True
        if self.neg:
            return not set(names) <= self.atoms
        return bool(self.atoms & set(names))


class AddrField(object):
    """ address field of a rule (list of tokens, optionally inverted), bounded per family """
    __slots__ = ('tokens', 'neg', 'lower', 'upper', 'raw')

    def __init__(self, tokens, neg, raw):
        self.tokens = tokens
        self.neg = neg
        self.raw = raw
        lower = ipset.ADDR_EMPTY
        upper = ipset.ADDR_EMPTY
        for tok in tokens:
            lower = ipset.addr_union(lower, tok.lower)
            upper = ipset.addr_union(upper, tok.upper)
        if neg:
            lower, upper = ipset.addr_complement(upper), ipset.addr_complement(lower)
        self.lower = lower
        self.upper = upper

    @property
    def is_any(self):
        return not self.neg and any(t.kind == 'any' for t in self.tokens)

    def names(self):
        return frozenset(t.name for t in self.tokens)

    def covers(self, other, fam):
        """ is other (restricted to family fam) contained in self """
        i = ipset.fidx(fam)
        if not self.neg and not other.neg:
            if self.is_any:
                return True
            names = self.names()
            for tok in other.tokens:
                if tok.name in names:
                    continue
                if not ipset.is_subset(tok.upper[i], self.lower[i]):
                    return False
            return True
        if self.neg and other.neg and self.names() == other.names():
            return True
        return ipset.is_subset(other.upper[i], self.lower[i])


class PortField(object):
    __slots__ = ('tokens', 'lower', 'upper', 'raw')

    def __init__(self, tokens, raw):
        self.tokens = tokens
        self.raw = raw
        lower = ipset.EMPTY
        upper = ipset.EMPTY
        for tok in tokens:
            lower = ipset.union(lower, tok.lower)
            upper = ipset.union(upper, tok.upper)
        self.lower = lower
        self.upper = upper

    def covers(self, other):
        names = frozenset(t.name for t in self.tokens)
        for tok in other.tokens:
            if tok.name in names:
                continue
            if not ipset.is_subset(tok.upper, self.lower):
                return False
        return True


def port_covers(outer, inner):
    """ None means every port """
    if outer is None:
        return True
    if inner is None:
        return False
    return outer.covers(inner)


def port_may_overlap(a, b):
    if a is None or b is None:
        return True
    return ipset.overlaps(a.upper, b.upper)


def ports_include(field, port):
    """ may this port field match port """
    if field is None:
        return True
    return ipset.is_subset(((port, port),), field.upper)


class Rule(object):
    def __init__(self):
        self.uuid = ''
        self.source = 'mvc'
        self.index = 0
        self.sequence = 0
        self.priority = 400000
        self.order = None
        self.enabled = True
        self.loaded = True
        self.inactive_reasons = []
        self.action = 'pass'
        self.quick = True
        self.log = False
        self.floating = False
        self.interfaces_raw = []
        self.ifset = None
        self.directions = frozenset(('in',))
        self.direction_raw = 'in'
        self.afs = frozenset((4,))
        self.ipprotocol = 'inet'
        self.protocol_raw = 'any'
        self.protos = {}
        self.src = None
        self.dst = None
        self.sport = None
        self.dport = None
        self.extra = {}
        self.effect = ()
        self.description = ''
        self.aliases = set()
        self.notes = []
        self.audit = {}
        self.fields = {}
        self.active_fams = frozenset()
        self.summary = ''

    @property
    def verdict(self):
        """ 'pass', 'deny' (block/reject) or 'match' (27.1: applies options, never decides pass/block) """
        if self.action == 'match':
            return 'match'
        return 'pass' if self.action == 'pass' else 'deny'

    @property
    def matches_nothing(self):
        return not self.active_fams or (self.dport is not None and not self.dport.upper) or \
            (self.sport is not None and not self.sport.upper)

    def covers(self, other):
        """ True when every packet matched by other is certainly matched by self """
        if not self.ifset.covers(other.ifset):
            return False
        if not other.directions <= self.directions:
            return False
        if not other.active_fams:
            return False
        for fam in other.active_fams:
            if fam not in self.afs:
                return False
            sp = self.protos[fam]
            if sp is not None:
                op = other.protos[fam]
                if op is None or not op <= sp:
                    return False
            if not self.src.covers(other.src, fam) or not self.dst.covers(other.dst, fam):
                return False
        if not port_covers(self.dport, other.dport) or not port_covers(self.sport, other.sport):
            return False
        for key, value in self.extra.items():
            ovalue = other.extra.get(key)
            if key in MATCH_EXTRA_SET_FIELDS:
                if not ovalue or not ovalue <= value:
                    return False
            elif ovalue != value:
                return False
        return True

    def may_overlap(self, other):
        """ False only when the two rules provably never match the same packet """
        if not self.ifset.may_overlap(other.ifset):
            return False
        if not (self.directions & other.directions):
            return False
        common = False
        for fam in self.active_fams & other.active_fams:
            sp, op = self.protos[fam], other.protos[fam]
            if sp is not None and op is not None and not (sp & op):
                continue
            i = ipset.fidx(fam)
            if not ipset.overlaps(self.src.upper[i], other.src.upper[i]):
                continue
            if not ipset.overlaps(self.dst.upper[i], other.dst.upper[i]):
                continue
            common = True
            break
        if not common:
            return False
        return port_may_overlap(self.dport, other.dport) and port_may_overlap(self.sport, other.sport)

    def same_match(self, other):
        return self.covers(other) and other.covers(self)


def _split(value):
    return [x.strip() for x in (value or '').split(',') if x.strip()]


class RuleNormalizer(object):
    def __init__(self, cfg, resolver):
        self.cfg = cfg
        self.res = resolver

    def interface_set(self, names, negate):
        if not names:
            return IfSet(all_=True)
        atoms = set()
        opaque = set()
        for name in names:
            if name in self.cfg.groups:
                members = self.cfg.groups[name]['members']
                atoms.update(members)
                if not members:
                    opaque.add(name)
            elif name in self.cfg.interfaces and self.cfg.interfaces[name].is_group:
                atoms.add(name)
                opaque.add(name)
            else:
                atoms.add(name)
        return IfSet(neg=negate, atoms=atoms, opaque=opaque)

    def priority(self, raw, names):
        if raw.source == 'legacy':
            if raw.get('floating') == '1':
                return 200000
            if raw.get('interface') in self.cfg.groups:
                return 300000 + self.cfg.groups[raw.get('interface')]['sequence']
            return 400000
        if len(names) != 1 or raw.get('interfacenot') == '1':
            return 200000
        name = names[0]
        if name in self.cfg.groups:
            return 300000 + self.cfg.groups[name]['sequence']
        if name in self.cfg.interfaces and self.cfg.interfaces[name].is_group:
            return 300000
        return 400000

    def normalize(self, raw):
        r = Rule()
        f = raw.fields
        r.fields = f
        r.source = raw.source
        r.uuid = raw.uuid or ('legacy-%d' % raw.index if raw.source == 'legacy' else 'mvc-%d' % raw.index)
        r.index = raw.index
        r.audit = raw.audit
        seq = f.get('sequence', '')
        r.sequence = int(seq) if seq.isdigit() else (raw.index + 1)
        r.enabled = f.get('enabled', '1') == '1'
        r.action = (f.get('action') or 'pass').lower()
        r.quick = f.get('quick', '1') == '1'
        r.log = f.get('log', '0') == '1'
        r.description = f.get('description', '')
        names = _split(f.get('interface'))
        r.interfaces_raw = names
        negate = f.get('interfacenot') == '1'
        r.ifset = self.interface_set(names, negate)
        r.priority = self.priority(raw, names)
        r.floating = r.priority == 200000
        if raw.source == 'legacy':
            r.sequence = raw.index + 1
        r.order = (r.priority, 0 if raw.source == 'mvc' else 1, r.sequence, raw.index)
        # interface validation (FilterRuleContainerField::getPriority / Rule::reader)
        for name in names:
            if not self.res.is_interface_name(name):
                r.loaded = False
                r.inactive_reasons.append('interface "%s" does not exist' % name)
        # direction
        direction = (f.get('direction') or 'in').lower()
        r.direction_raw = direction
        r.directions = frozenset(('in', 'out')) if direction in ('any', 'both') else frozenset((direction,))
        # families
        ipp = (f.get('ipprotocol') or 'inet').lower()
        r.ipprotocol = ipp
        r.afs = frozenset((4, 6)) if ipp == 'inet46' else (frozenset((6,)) if ipp == 'inet6' else frozenset((4,)))
        # protocols
        proto = (f.get('protocol') or 'any').lower()
        r.protocol_raw = proto
        for fam in r.afs:
            if proto == 'any':
                r.protos[fam] = None
            elif proto == 'tcp/udp':
                r.protos[fam] = frozenset(('tcp', 'udp'))
            elif proto == 'icmp' and fam == 6:
                r.protos[fam] = frozenset(('ipv6-icmp',))
            else:
                r.protos[fam] = frozenset((proto,))
        port_capable = proto in ('tcp', 'udp', 'tcp/udp')
        # addresses
        for side in ('source', 'destination'):
            raw_net = f.get(side + '_net') or 'any'
            tokens = [self.res.address_token(t) for t in (_split(raw_net) or ['any'])]
            field = AddrField(tokens, f.get(side + '_not') == '1' and raw_net != 'any', raw_net)
            for tok in tokens:
                r.aliases |= tok.aliases
                r.notes.extend(tok.notes)
                if tok.unresolved:
                    r.loaded = False
                    r.inactive_reasons.append('%s "%s" can not be resolved' % (side, tok.name))
            if side == 'source':
                r.src = field
            else:
                r.dst = field
            port_raw = f.get(side + '_port', '') if port_capable else ''
            pfield = None
            if port_raw:
                ptoks = [self.res.port_token(p) for p in _split(port_raw)]
                if all(p is not None for p in ptoks) and ptoks:
                    pfield = PortField(ptoks, port_raw)
                    for tok in ptoks:
                        r.aliases |= tok.aliases
                        r.notes.extend(tok.notes)
                        if tok.unresolved:
                            r.loaded = False
                            r.inactive_reasons.append('%s port "%s" can not be resolved' % (side, tok.name))
            if side == 'source':
                r.sport = pfield
            else:
                r.dport = pfield
        # active families: those where both addresses may contain something
        active = set()
        for fam in r.afs:
            i = ipset.fidx(fam)
            if r.src.upper[i] and r.dst.upper[i]:
                active.add(fam)
        r.active_fams = frozenset(active)
        # extra match conditions
        for key in MATCH_EXTRA_SET_FIELDS:
            value = f.get(key, '')
            if value and proto in ('icmp', 'ipv6-icmp'):
                r.extra[key] = frozenset(_split(value))
        for key in MATCH_EXTRA_FIELDS:
            value = f.get(key, '')
            if key in BOOL_FIELDS:
                value = '1' if value == '1' else ''
            if value:
                r.extra[key] = value
        if 'tcpflags_any' in r.extra and proto not in ('tcp', 'tcp/udp'):
            del r.extra['tcpflags_any']
        effect = [r.action]
        for key in EFFECT_FIELDS:
            value = f.get(key, '')
            if key in BOOL_FIELDS:
                value = '1' if value == '1' else ''
            if r.action == 'match' and key not in MATCH_EFFECT_FIELDS:
                value = ''  # FilterRule drops route-to/reply-to and state options on non-pass rules
            elif r.action not in ('pass', 'match') and key not in ('tag',):
                value = ''  # route-to / state options are ignored for block rules
            effect.append(value)
        r.effect = tuple(effect)
        r.summary = self.summary(r)
        return r

    # ---------------------------------------------------------------- text
    def _addr_text(self, field):
        parts = [t.display for t in field.tokens]
        text = parts[0] if len(parts) == 1 else '{%s}' % ', '.join(parts)
        return ('not ' + text) if field.neg else text

    def summary(self, r):
        words = [r.action]
        if r.direction_raw in ('in', 'out'):
            words.append(r.direction_raw)
        if r.quick:
            words.append('quick')
        if r.ifset.all:
            words.append('on any interface')
        else:
            words.append('on %s%s' % ('not ' if r.ifset.neg else '', ','.join(r.interfaces_raw)))
        words.append({'inet': 'inet', 'inet6': 'inet6', 'inet46': 'inet/inet6'}.get(r.ipprotocol, r.ipprotocol))
        if r.protocol_raw != 'any':
            words.append('proto %s' % r.protocol_raw)
        words.append('from %s' % self._addr_text(r.src))
        if r.sport is not None:
            words.append('port %s' % r.sport.raw)
        words.append('to %s' % self._addr_text(r.dst))
        if r.dport is not None:
            words.append('port %s' % r.dport.raw)
        for key in ('icmptype', 'icmp6type'):
            if key in r.extra:
                words.append('%s %s' % (key, ','.join(sorted(r.extra[key]))))
        if 'tagged' in r.extra:
            words.append('tagged %s' % r.extra['tagged'])
        if 'sched' in r.extra:
            words.append('schedule %s' % r.extra['sched'])
        if r.fields.get('gateway') and r.action == 'pass':
            words.append('gateway %s' % r.fields.get('gateway'))
        return ' '.join(words)


def evaluation_order(rules):
    return sorted(rules, key=lambda x: x.order)
