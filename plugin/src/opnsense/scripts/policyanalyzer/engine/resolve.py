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

    Conservative resolution of addresses and ports.

    Every token resolves to a lower bound (addresses it certainly matches) and an upper bound (addresses it may
    match). Statically known content (literals, host/network aliases) has lower == upper. Content that can not be
    known from config.xml alone (url tables, GeoIP, FQDNs, dynamic interface addresses, ...) is "opaque": its
    lower bound is empty and its upper bound is everything. Containment tests always compare the upper bound of
    the inner rule with the lower bound of the outer rule, so opaque content can never produce a false
    shadowing result; the only exception is the very same token on both sides (same alias = same table).
"""

import re

from . import ipset

OPAQUE_ALIAS_TYPES = ('url', 'urltable', 'urljson', 'geoip', 'asn', 'mac', 'dynipv6host', 'authgroup',
                      'external', 'internal')
STATIC_ALIAS_TYPES = ('host', 'network', 'networkgroup')

WELL_KNOWN_PORTS = {
    'afs3-fileserver': 7000, 'aol': 5190, 'auth': 113, 'avt-profile-1': 5004, 'cvsup': 5999, 'domain': 53,
    'domain-s': 853, 'ftp': 21, 'hbci': 3000, 'http': 80, 'https': 443, 'igmpv3lite': 465, 'imap': 143,
    'imaps': 993, 'ipsec-msft': 10000, 'ipsec-nat-t': 4500, 'isakmp': 500, 'l2f': 1701, 'ldap': 389,
    'ldaps': 636, 'microsoft-ds': 445, 'ms-streaming': 1755, 'ms-wbt-server': 3389, 'msnp': 1863,
    'nat-stun-port': 3478, 'netbios-dgm': 138, 'netbios-ns': 137, 'netbios-ssn': 139, 'nntp': 119, 'ntp': 123,
    'openvpn': 1194, 'pop3': 110, 'pop3s': 995, 'pptp': 1723, 'radius': 1812, 'radius-acct': 1813, 'rfb': 5900,
    'sip': 5060, 'sip-tls': 5061, 'smtp': 25, 'snmp': 161, 'snmptrap': 162, 'ssh': 22, 'submission': 587,
    'submissions': 465, 'telnet': 23, 'teredo': 3544, 'tftp': 69, 'urd': 465, 'wins': 1512,
}

LEGACY_IF_ADDR = re.compile(r'^(wan|lan|opt[0-9]+)ip$')
FE80 = ipset.parse_address('fe80::/10')
LOOPBACK = ipset.addr_union(ipset.parse_address('127.0.0.0/8'), ipset.parse_address('::1/128'))


class AddrTok(object):
    __slots__ = ('name', 'kind', 'lower', 'upper', 'aliases', 'unresolved', 'notes', 'is_self', 'display')

    def __init__(self, name, kind, lower, upper, aliases=(), unresolved=False, notes=(), is_self=False,
                 display=None):
        self.name = name
        self.kind = kind
        self.lower = lower
        self.upper = upper
        self.aliases = frozenset(aliases)
        self.unresolved = unresolved
        self.notes = tuple(notes)
        self.is_self = is_self
        self.display = display or name

    @property
    def opaque(self):
        return self.lower != self.upper


class PortTok(object):
    __slots__ = ('name', 'kind', 'lower', 'upper', 'aliases', 'unresolved', 'notes')

    def __init__(self, name, kind, lower, upper, aliases=(), unresolved=False, notes=()):
        self.name = name
        self.kind = kind
        self.lower = lower
        self.upper = upper
        self.aliases = frozenset(aliases)
        self.unresolved = unresolved
        self.notes = tuple(notes)

    @property
    def opaque(self):
        return self.lower != self.upper


def _is_fqdn(value):
    return bool(re.match(r'^(?=.{1,253}$)([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$',
                         value))


class Resolver(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self._alias_cache = {}
        self._port_alias_cache = {}
        self._if_cache = {}
        self.self_lower = self._compute_self_lower()

    # ---------------------------------------------------------------- interfaces
    def _vips_for(self, ifname, mode_filter=('ipalias', 'carp')):
        hosts = ipset.ADDR_EMPTY
        nets = ipset.ADDR_EMPTY
        for vif, addr, bits, mode in self.cfg.vips:
            if vif != ifname or (mode and mode not in mode_filter):
                continue
            host = ipset.host_pair(addr)
            if host is None:
                continue
            hosts = ipset.addr_union(hosts, host)
            net = ipset.network_pair(addr, bits) if bits else host
            if net is not None:
                nets = ipset.addr_union(nets, net)
        return hosts, nets

    def interface_bounds(self, ifname):
        """ :return: dict with net_lower, net_upper, addr_lower, addr_upper for an interface (or group) """
        if ifname in self._if_cache:
            return self._if_cache[ifname]
        result = None
        if ifname in self.cfg.groups:
            members = [m for m in self.cfg.groups[ifname]['members'] if m != ifname]
            agg = {'net_lower': ipset.ADDR_EMPTY, 'net_upper': ipset.ADDR_EMPTY,
                   'addr_lower': ipset.ADDR_EMPTY, 'addr_upper': ipset.ADDR_EMPTY}
            self._if_cache[ifname] = {k: (ipset.ADDR_EMPTY if 'lower' in k else ipset.ADDR_ALL) for k in agg}
            for member in members:
                bounds = self.interface_bounds(member)
                for key in agg:
                    agg[key] = ipset.addr_union(agg[key], bounds[key])
            result = agg
        elif ifname in self.cfg.interfaces and not self.cfg.interfaces[ifname].is_group:
            intf = self.cfg.interfaces[ifname]
            vip_hosts, vip_nets = self._vips_for(ifname)
            v4_static = ipset.host_pair(intf.ipaddr) if intf.ipaddr else None
            v6_static = ipset.host_pair(intf.ipaddrv6) if intf.ipaddrv6 else None
            if v4_static is not None and v4_static[0] == ipset.EMPTY:
                v4_static = None
            if v6_static is not None and v6_static[1] == ipset.EMPTY:
                v6_static = None
            addr_lower = vip_hosts
            net_lower = vip_nets
            if v4_static is not None:
                addr_lower = ipset.addr_union(addr_lower, v4_static)
                net = ipset.network_pair(intf.ipaddr, intf.subnet or 32)
                net_lower = ipset.addr_union(net_lower, net or v4_static)
            if v6_static is not None:
                addr_lower = ipset.addr_union(addr_lower, v6_static)
                net = ipset.network_pair(intf.ipaddrv6, intf.subnetv6 or 128)
                net_lower = ipset.addr_union(net_lower, net or v6_static)
            # pf: (if:network) for inet6 is always extended with fe80::/10 by the rule generator
            net_lower = ipset.addr_union(net_lower, FE80)
            net_upper = (net_lower[0] if v4_static is not None else ipset.ALL4,
                         net_lower[1] if v6_static is not None else ipset.ALL6)
            addr_upper = (addr_lower[0] if v4_static is not None else ipset.ALL4,
                          ipset.ALL6)  # link-local and SLAAC/privacy addresses can always exist on IPv6
            result = {'net_lower': net_lower, 'net_upper': net_upper,
                      'addr_lower': addr_lower, 'addr_upper': addr_upper}
        else:
            # opaque groups (wireguard, openvpn, enc0) or unknown names
            result = {'net_lower': ipset.ADDR_EMPTY, 'net_upper': ipset.ADDR_ALL,
                      'addr_lower': ipset.ADDR_EMPTY, 'addr_upper': ipset.ADDR_ALL}
        self._if_cache[ifname] = result
        return result

    def _compute_self_lower(self):
        lower = LOOPBACK
        for ifname in self.cfg.interfaces:
            if self.cfg.interfaces[ifname].is_group:
                continue
            lower = ipset.addr_union(lower, self.interface_bounds(ifname)['addr_lower'])
        return lower

    def is_interface_name(self, name):
        return name in self.cfg.interfaces or name in self.cfg.groups

    # ---------------------------------------------------------------- addresses
    def address_token(self, token):
        token = token.strip()
        if token in ('', 'any'):
            return AddrTok('any', 'any', ipset.ADDR_ALL, ipset.ADDR_ALL, display='any')
        if token == '(self)':
            return AddrTok(token, 'self', self.self_lower, ipset.ADDR_ALL, is_self=True, display='This Firewall')
        literal = ipset.parse_address(token)
        if literal is not None:
            is_self = ipset.overlaps(literal[0], self.self_lower[0]) or ipset.overlaps(literal[1], self.self_lower[1])
            return AddrTok(token, 'literal', literal, literal, is_self=is_self)
        if self.is_interface_name(token):
            bounds = self.interface_bounds(token)
            return AddrTok(token, 'ifnet', bounds['net_lower'], bounds['net_upper'],
                           display='%s net' % self.cfg.interface_display(token))
        match = LEGACY_IF_ADDR.match(token)
        if match and match.group(1) in self.cfg.interfaces:
            bounds = self.interface_bounds(match.group(1))
            return AddrTok(token, 'ifaddr', bounds['addr_lower'], bounds['addr_upper'], is_self=True,
                           display='%s address' % self.cfg.interface_display(match.group(1)))
        if token in self.cfg.aliases:
            lower, upper, involved, notes = self.resolve_alias(token)
            return AddrTok(token, 'alias', lower, upper, aliases=involved, notes=notes)
        if token.startswith('__'):
            # dynamic aliases registered by plugins at runtime (DynamicAliases: Q-Feeds, captive portal, ...)
            return AddrTok(token, 'alias', ipset.ADDR_EMPTY, ipset.ADDR_ALL,
                           notes=('dynamic alias "%s" is resolved at runtime' % token,))
        # Rule::mapAddressInfo(): unknown values disable the rule in pf ("Unable to convert address")
        return AddrTok(token, 'unknown', ipset.ADDR_EMPTY, ipset.ADDR_ALL, unresolved=True,
                       notes=('unknown address or alias "%s"' % token,))

    def resolve_alias(self, name, stack=()):
        """ :return: (lower, upper, aliases involved, notes) """
        if name in self._alias_cache:
            return self._alias_cache[name]
        alias = self.cfg.aliases.get(name)
        involved = {name}
        notes = []
        if alias is None:
            return ipset.ADDR_EMPTY, ipset.ADDR_ALL, involved, ['unknown alias "%s"' % name]
        if name in stack:
            return ipset.ADDR_EMPTY, ipset.ADDR_ALL, involved, ['alias loop at "%s"' % name]
        if not alias.enabled:
            result = (ipset.ADDR_EMPTY, ipset.ADDR_ALL, involved, ['alias "%s" is disabled' % name])
        elif alias.type == 'internal' and name.startswith('__') and name.endswith('_network'):
            bounds = self.interface_bounds(name[2:-8])
            result = (bounds['net_lower'], bounds['net_upper'], involved, [])
        elif alias.type in STATIC_ALIAS_TYPES:
            lower = ipset.ADDR_EMPTY
            upper = ipset.ADDR_EMPTY
            excludes = ipset.ADDR_EMPTY
            for item in alias.content:
                if item.startswith('!'):
                    excl = ipset.parse_address(item[1:])
                    if excl is not None:
                        excludes = ipset.addr_union(excludes, excl)
                    continue
                literal = ipset.parse_address(item)
                if literal is not None:
                    lower = ipset.addr_union(lower, literal)
                    upper = ipset.addr_union(upper, literal)
                elif item in self.cfg.aliases:
                    sub_lower, sub_upper, sub_inv, sub_notes = self.resolve_alias(item, stack + (name,))
                    if self.cfg.aliases[item].type == 'port':
                        sub_lower, sub_upper = ipset.ADDR_EMPTY, ipset.ADDR_ALL
                    lower = ipset.addr_union(lower, sub_lower)
                    upper = ipset.addr_union(upper, sub_upper)
                    involved |= sub_inv
                    notes.extend(sub_notes)
                else:
                    # FQDN (resolved at runtime), wildcard mask or anything unknown: opaque
                    upper = ipset.ADDR_ALL
                    notes.append('alias "%s" contains dynamic entry' % name if _is_fqdn(item)
                                 else 'alias "%s" contains unsupported entry' % name)
            lower = ipset.addr_subtract(lower, excludes)
            result = (lower, upper, involved, notes)
        else:
            # url, urltable, geoip, asn, mac, dynamic, external... content known only at runtime
            result = (ipset.ADDR_EMPTY, ipset.ADDR_ALL, involved, ['alias "%s" (%s) is resolved at runtime' %
                                                                 (name, alias.type)])
        if not stack:
            self._alias_cache[name] = result
        return result

    def alias_is_empty(self, name, stack=()):
        """ True when an alias provably resolves to nothing (static alias without content) """
        alias = self.cfg.aliases.get(name)
        if alias is None or alias.builtin or not alias.enabled:
            return False
        if alias.type in ('external', 'internal', 'dynipv6host', 'authgroup'):
            return False
        if not alias.content:
            return True
        if alias.type == 'port':
            lower, upper, _inv, _n = self.resolve_port_alias(name)
            return not upper
        if alias.type in STATIC_ALIAS_TYPES:
            lower, upper, _inv, _n = self.resolve_alias(name)
            return ipset.addr_is_empty(upper)
        return False

    # ---------------------------------------------------------------- ports
    def port_token(self, token):
        """ :return: PortTok or None for "any" """
        token = (token or '').strip()
        if token in ('', 'any'):
            return None
        literal = ipset.parse_port(token)
        if literal is not None:
            if literal == ((1, 65535),) or literal == ((0, 65535),):
                return None
            return PortTok(token, 'literal', literal, literal)
        if token in WELL_KNOWN_PORTS:
            value = ((WELL_KNOWN_PORTS[token], WELL_KNOWN_PORTS[token]),)
            return PortTok(token, 'literal', value, value)
        if token in self.cfg.aliases:
            lower, upper, involved, notes = self.resolve_port_alias(token)
            return PortTok(token, 'alias', lower, upper, aliases=involved, notes=notes)
        return PortTok(token, 'unknown', ipset.EMPTY, ipset.ALL_PORTS, unresolved=True,
                       notes=('unknown port or alias "%s"' % token,))

    def resolve_port_alias(self, name, stack=()):
        if name in self._port_alias_cache:
            return self._port_alias_cache[name]
        alias = self.cfg.aliases.get(name)
        involved = {name}
        if alias is None or name in stack:
            return ipset.EMPTY, ipset.ALL_PORTS, involved, ['unresolvable port alias "%s"' % name]
        if not alias.enabled:
            result = (ipset.EMPTY, ipset.ALL_PORTS, involved, ['alias "%s" is disabled' % name])
        elif alias.type != 'port':
            result = (ipset.EMPTY, ipset.ALL_PORTS, involved, ['alias "%s" (%s) used as port' % (name, alias.type)])
        else:
            lower = ipset.EMPTY
            upper = ipset.EMPTY
            notes = []
            for item in alias.content:
                literal = ipset.parse_port(item)
                if literal is None and item in WELL_KNOWN_PORTS:
                    literal = ((WELL_KNOWN_PORTS[item], WELL_KNOWN_PORTS[item]),)
                if literal is not None:
                    lower = ipset.union(lower, literal)
                    upper = ipset.union(upper, literal)
                elif item in self.cfg.aliases:
                    sub_lower, sub_upper, sub_inv, sub_notes = self.resolve_port_alias(item, stack + (name,))
                    lower = ipset.union(lower, sub_lower)
                    upper = ipset.union(upper, sub_upper)
                    involved |= sub_inv
                    notes.extend(sub_notes)
                else:
                    upper = ipset.ALL_PORTS
                    notes.append('port alias "%s" contains unsupported entry' % name)
            result = (lower, upper, involved, notes)
        if not stack:
            self._port_alias_cache[name] = result
        return result
