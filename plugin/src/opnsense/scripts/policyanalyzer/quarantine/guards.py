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

    Guards: what is never put in quarantine, checked on every automatic and manual entry.

      not external        private, reserved, CGNAT (100.64/10), loopback, link local, multicast,
                          documentation and every other non global range (common.is_external)
      firewall            addresses of this firewall (ifconfig, interfaces and virtual IPs of the config)
      gateway             gateways and monitor addresses (config), default routes and PPP peers (runtime)
      dns                 configured DNS servers, Unbound DoT/forwarders, /etc/resolv.conf
      ntp                 configured time servers (resolved) and the current ntpd peers (ntpq -pn)
      wireguard_peer      WireGuard peer endpoints (config, resolved, and "wg show all endpoints")
      tailscale_peer      Tailscale peers (tailscale status --json), when Tailscale is enabled
      wireguard_allowed   any address with an ALLOWED inbound connection to a WireGuard port in 24 h
      never_block         the pa_never_block alias (edited by the owner)
      admin_session       remote ends of the open SSH / web GUI connections to this firewall
"""

import concurrent.futures
import ipaddress
import json
import re
import socket

from . import common

LABELS = ('firewall', 'gateway', 'dns', 'ntp', 'wireguard_peer', 'tailscale_peer', 'wireguard_allowed',
          'never_block', 'admin_session')
RESOLVE_TTL = 3600
RESOLVE_TIMEOUT = 2.0
RESOLVE_MAX = 16


def _nets(value):
    """ "1.2.3.4", "1.2.3.0/24", "[2001:db8::1]:51820", "1.2.3.4:51820" -> [ip_network] """
    value = (value or '').strip()
    if not value or value == '(none)':
        return []
    match = re.match(r'^\[([0-9a-fA-F:.]+)\](?::\d+)?$', value)
    if match:
        value = match.group(1)
    elif value.count(':') == 1 and '.' in value:
        value = value.split(':')[0]
    try:
        net = ipaddress.ip_network(value.split('%')[0], strict=False)
    except ValueError:
        return []
    if net.version == 6 and net.network_address.ipv4_mapped is not None and net.prefixlen == 128:
        net = ipaddress.ip_network(net.network_address.ipv4_mapped)
    return [net]


def _is_ip(value):
    return bool(_nets(value))


class Guards:
    def __init__(self):
        self.set = common.IntervalSet()
        self.items = {label: [] for label in LABELS}
        self.notes = []

    def add(self, label, value, note=None):
        for net in _nets(value):
            self.set.add(net, label)
            text = common.pf_text(net)
            if not any(i['addr'] == text for i in self.items[label]):
                self.items[label].append({'addr': text, 'note': note})

    def check(self, ip):
        """ :return: why the address is protected, or None """
        if not common.is_external(ip):
            return 'not_external'
        return self.set.lookup(ip)

    def overlapping(self, net):
        return self.set.overlapping(net)

    def describe(self):
        return {'labels': {label: self.items[label] for label in LABELS},
                'counts': {label: len(self.items[label]) for label in LABELS},
                'implicit': ['private', 'reserved', 'cgnat', 'loopback', 'link_local', 'multicast', 'documentation'],
                'notes': self.notes}


# ------------------------------------------------------------------ runtime probes


def ifconfig_addresses(output):
    """ :return: (own addresses, point to point peers) """
    own, peers = [], []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ('inet', 'inet6'):
            own.append(parts[1].split('%')[0])
            if len(parts) >= 4 and parts[2] == '-->':
                peers.append(parts[3].split('%')[0])
    return own, peers


def netstat_gateways(output, wan_devs):
    result = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        dest, gw, flags, netif = parts[0], parts[1], parts[2], parts[3]
        if dest == 'default' and _is_ip(gw):
            result.append(gw)
        elif 'H' in flags and netif in wan_devs and _is_ip(dest) and gw.startswith('link#') is False and \
                not _is_ip(gw):
            result.append(dest)
    return result


def wg_endpoints(output):
    result = []
    for line in output.splitlines():
        parts = line.split('\t')
        if len(parts) >= 3:
            result.append(parts[2].strip())
    return result


def tailscale_peers(output):
    try:
        doc = json.loads(output or '{}')
    except ValueError:
        return []
    result = []
    for peer in (doc.get('Peer') or {}).values():
        if not isinstance(peer, dict):
            continue
        for value in [peer.get('CurAddr')] + list(peer.get('Addrs') or []):
            if isinstance(value, str) and value:
                result.append(value)
    return result


def ntpq_peers(output):
    result = []
    for line in output.splitlines()[2:]:
        parts = line.split()
        if parts:
            result.append(parts[0].lstrip('*+-#ox.'))
    return result


def sockstat_admin(output, ports):
    result = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        local, foreign = parts[-2], parts[-1]
        port = local.rsplit(':', 1)[-1]
        if port.isdigit() and int(port) in ports and foreign != '*:*':
            result.append(foreign.rsplit(':', 1)[0].strip('[]'))
    return result


def resolv_nameservers(path):
    try:
        with open(path) as handle:
            return [line.split()[1] for line in handle if line.startswith('nameserver') and len(line.split()) > 1]
    except OSError:
        return []


def resolve_names(names, store, now, resolver=None):
    """ hostnames -> {name: [ips]}, cached for an hour in the meta table, 2 s per name at most """
    cache = (store.meta_json('guard_resolve', {}) if store is not None else {}) or {}
    result, todo = {}, []
    for name in names[:RESOLVE_MAX]:
        hit = cache.get(name)
        if hit and now - hit.get('ts', 0) < RESOLVE_TTL:
            result[name] = hit.get('ips', [])
        else:
            todo.append(name)
    if todo:
        resolver = resolver or (lambda n: sorted({ai[4][0] for ai in socket.getaddrinfo(n, None)}))
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(todo)))
        futures = {name: pool.submit(resolver, name) for name in todo}
        for name, future in futures.items():
            try:
                ips = future.result(timeout=RESOLVE_TIMEOUT)
            except Exception:  # noqa: BLE001 - resolution failures only cost the guard of that name
                ips = (cache.get(name) or {}).get('ips', [])
            result[name] = ips
            cache[name] = {'ips': ips, 'ts': now}
        pool.shutdown(wait=False)
        if store is not None:
            store.set_meta('guard_resolve', {k: v for k, v in cache.items() if now - v.get('ts', 0) < 86400})
    return result


def build(ctx, cfg, store, now, runtime=True, resolver=None):
    """ :return: Guards """
    g = Guards()
    wan = cfg.wan_interfaces()
    wan_devs = {w['dev'] for w in wan}
    run = ctx.runner
    for value in cfg.static_addresses():
        g.add('firewall', value, 'config')
    for value in cfg.gateways():
        g.add('gateway', value, 'config')
    names = []
    for value in cfg.dns_servers() + resolv_nameservers(ctx.resolv_conf):
        g.add('dns', value)
    for value in cfg.ntp_servers():
        if _is_ip(value):
            g.add('ntp', value)
        else:
            names.append(('ntp', value))
    wg = cfg.wireguard()
    for value in wg['peers']:
        if _is_ip(value):
            g.add('wireguard_peer', value, 'config')
        else:
            names.append(('wireguard_peer', value))
    if names:
        resolved = resolve_names([n for _label, n in names], store, now, resolver)
        for label, name in names:
            for ip in resolved.get(name, []):
                g.add(label, ip, name)
    if runtime:
        own, peers = ifconfig_addresses(run.read([ctx.ifconfig, '-a']))
        for value in own:
            g.add('firewall', value, 'ifconfig')
        for value in peers:
            g.add('gateway', value, 'ppp peer')
        for value in netstat_gateways(run.read([ctx.netstat, '-rn']), wan_devs):
            g.add('gateway', value, 'route')
        for value in wg_endpoints(run.read([ctx.wg, 'show', 'all', 'endpoints'], timeout=5)):
            g.add('wireguard_peer', value, 'wg show')
        if cfg.tailscale()['enabled']:
            for value in tailscale_peers(run.read([ctx.tailscale, 'status', '--json'], timeout=5)):
                g.add('tailscale_peer', value)
        for value in ntpq_peers(run.read([ctx.ntpq, '-pn'], timeout=5)):
            g.add('ntp', value, 'ntpd peer')
        ports = {cfg.ssh_port(), cfg.webgui_port()}
        for value in sockstat_admin(run.read([ctx.sockstat, '-c', '-4', '-6', '-P', 'tcp'], timeout=5), ports):
            g.add('admin_session', value)
    if store is not None:
        for value in store.wg_recent(now - 86400):
            g.add('wireguard_allowed', value, 'allowed inbound to a WireGuard port in the last 24 h')
    never = cfg.aliases().get(common.NEVER_ALIAS)
    if never is not None:
        for value in never['content']:
            if _is_ip(value):
                g.add('never_block', value)
            else:
                g.notes.append('%s: "%s" is not an address or network and is ignored by the quarantine' % (
                    common.NEVER_ALIAS, value))
    return g
