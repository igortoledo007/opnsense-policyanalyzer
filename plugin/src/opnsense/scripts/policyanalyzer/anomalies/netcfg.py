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

    Read only facts of config.xml the detectors need:

      internal networks   subnets of the interfaces that are not uplinks (no gateway, no dynamic address),
                          CARP/IP alias VIPs, and WireGuard instances without a gateway (road warrior
                          servers); outbound VPN tunnels (instances with a gateway) are uplinks, their
                          tunnel addresses are NAT sources, not hosts
      internal devices    the interface devices of those networks (igc0, wg4...): a flow counts as
                          "leaving a host" only when it entered on one of them (NetFlow sees a routed flow
                          on every captured interface)
      firewall addresses  interface addresses, VIPs and tunnel addresses (a host talking to the firewall is
                          not talking to the internet)
      local domains       system/domain and the search domains of the resolver (NXDOMAIN noise of the stub
                          resolvers appending them is not DGA)
      DNS redirect        NAT port forwards of port 53 to the firewall (a bypass attempt is neutralized)
"""

import ipaddress
import xml.etree.ElementTree as ET

from . import common

DYNAMIC = {'dhcp', 'dhcp6', 'pppoe', 'pptp', 'l2tp', 'slaac', 'track6', 'ppp'}

# well known public DoH/DoT resolvers (addresses) and DoH host names
DOH_ADDRESSES = frozenset((
    '1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3', '8.8.8.8', '8.8.4.4', '9.9.9.9',
    '149.112.112.112', '9.9.9.10', '149.112.112.10', '9.9.9.11', '208.67.222.222', '208.67.220.220',
    '94.140.14.14', '94.140.15.15', '76.76.2.0', '76.76.10.0', '45.90.28.0', '45.90.30.0', '185.228.168.9',
    '185.228.169.9', '194.242.2.2', '194.242.2.3', '2606:4700:4700::1111', '2606:4700:4700::1001',
    '2001:4860:4860::8888', '2001:4860:4860::8844', '2620:fe::fe', '2620:fe::9', '2620:119:35::35',
    '2a10:50c0::ad1:ff', '2a07:e340::2',
))
DOH_NAMES = (
    'cloudflare-dns.com', 'one.one.one.one', 'dns.google', 'dns.google.com', 'dns.quad9.net', 'dns9.quad9.net',
    'doh.opendns.com', 'dns.adguard.com', 'dns.adguard-dns.com', 'dns.nextdns.io', 'doh.cleanbrowsing.org',
    'doh.mullvad.net', 'dns.mullvad.net', 'dns.controld.com', 'freedns.controld.com', 'doh.dns.sb',
    'use-application-dns.net',
)


def _net(addr, bits):
    try:
        return ipaddress.ip_network('%s/%s' % (addr, bits), strict=False)
    except ValueError:
        return None


def _addr(text):
    try:
        return ipaddress.ip_address((text or '').split('/')[0].strip())
    except ValueError:
        return None


class NetConfig:
    def __init__(self, path=None, root=None):
        self.internal = []          # ip_network
        self.internal_ifaces = set()  # devices (igc0, wg4)
        self.internal_keys = set()    # lan, opt8
        self.uplink_ifaces = set()
        self.firewall = set()       # ip_address
        self.domains = set()
        self.dns_redirect = {}      # interface key -> description
        self.dns_servers = set()
        self.ok = False
        if root is None and path is not None:
            try:
                root = ET.parse(path).getroot()
            except (OSError, ET.ParseError):
                root = None
        if root is not None:
            self._load(root)
            self.ok = True

    # ------------------------------------------------------------------ loading
    def _load(self, root):
        gw_ifaces = set()
        for path in ('gateways/gateway_item', 'OPNsense/Gateways/gateway_item'):
            for gw in root.findall(path):
                if (gw.findtext('interface') or '').strip():
                    gw_ifaces.add(gw.findtext('interface').strip())
        ifaces = root.find('interfaces')
        dev_of = {}
        for node in list(ifaces) if ifaces is not None else []:
            key, dev = node.tag, (node.findtext('if') or '').strip()
            dev_of[key] = dev
            if node.find('enable') is None and key not in ('lan', 'wan'):
                continue
            ipaddr = (node.findtext('ipaddr') or '').strip()
            uplink = key == 'wan' or key in gw_ifaces or ipaddr in DYNAMIC or bool((node.findtext('gateway') or '')
                                                                                    .strip())
            if uplink:
                if dev:
                    self.uplink_ifaces.add(dev)
                continue
            if dev == 'lo0' or key == 'lo0':
                continue
            for addr_tag, bits_tag in (('ipaddr', 'subnet'), ('ipaddrv6', 'subnetv6')):
                addr = (node.findtext(addr_tag) or '').strip()
                net = _net(addr, (node.findtext(bits_tag) or '').strip() or ('32' if ':' not in addr else '128')) \
                    if _addr(addr) else None
                if net is not None:
                    self.internal.append(net)
                    self.firewall.add(_addr(addr))
                    if dev:
                        self.internal_ifaces.add(dev)
                    self.internal_keys.add(key)
        for vip in root.findall('virtualip/vip'):
            addr = _addr(vip.findtext('subnet'))
            if addr is None:
                continue
            self.firewall.add(addr)
            if (vip.findtext('interface') or '') in self.internal_keys:
                net = _net(str(addr), vip.findtext('subnet_bits') or '32')
                if net is not None and net.prefixlen < net.max_prefixlen:
                    self.internal.append(net)
        for srv in root.findall('OPNsense/wireguard/server/servers/server'):
            if (srv.findtext('enabled') or '1') != '1':
                continue
            tunnels = [t.strip() for t in (srv.findtext('tunneladdress') or '').split(',') if t.strip()]
            for tunnel in tunnels:
                addr = _addr(tunnel)
                if addr is not None:
                    self.firewall.add(addr)
            if (srv.findtext('gateway') or '').strip():
                continue                    # outbound VPN: an uplink
            instance = (srv.findtext('instance') or '').strip()
            if instance.isdigit():
                self.internal_ifaces.add('wg%s' % instance)
            for tunnel in tunnels:
                try:
                    net = ipaddress.ip_network(tunnel, strict=False)
                except ValueError:
                    continue
                if net.prefixlen < net.max_prefixlen:
                    self.internal.append(net)
        domain = (root.findtext('system/domain') or '').strip().lower().strip('.')
        if domain:
            self.domains.add(domain)
        for search in (root.findtext('system/dnssearchdomain') or '').split():
            if search.strip('.'):
                self.domains.add(search.strip('.').lower())
        for dns in root.findall('system/dnsserver'):
            addr = _addr(dns.text)
            if addr is not None:
                self.dns_servers.add(addr)
        for rule in root.findall('nat/rule'):
            dst = rule.find('destination')
            port = (dst.findtext('port') if dst is not None else '') or ''
            target = (rule.findtext('target') or '').strip()
            local_port = (rule.findtext('local-port') or '').strip()
            if rule.find('disabled') is not None:
                continue
            if port.strip() == '53' and local_port in ('53', '') and \
                    (target in ('(self)', '127.0.0.1', '::1') or _addr(target) in self.firewall):
                for key in (rule.findtext('interface') or '').split(','):
                    self.dns_redirect[key.strip()] = (rule.findtext('descr') or 'port forward 53 -> %s' % target)
        self.internal = list(ipaddress.collapse_addresses([n for n in self.internal if n.version == 4])) + \
            list(ipaddress.collapse_addresses([n for n in self.internal if n.version == 6]))
        self._dev_of = dev_of

    # ------------------------------------------------------------------ classification
    def is_internal(self, ip):
        """ a host of one of the internal networks (not the firewall itself) """
        if ip is None or ip in self.firewall:
            return False
        return any(ip in net for net in self.internal if net.version == ip.version)

    def is_firewall(self, ip):
        return ip is not None and ip in self.firewall

    @staticmethod
    def is_external(ip):
        """ a global unicast address (the internet) """
        if ip is None:
            return False
        if common.TEST_EXTERNAL and any(ip in net for net in common.TEST_EXTERNAL if net.version == ip.version):
            return True
        return ip.is_global and not ip.is_multicast

    def redirect_for(self, iface_dev):
        """ description of a NAT rule that sends port 53 of this interface to the firewall, or None """
        for key, descr in self.dns_redirect.items():
            if self._dev_of.get(key) == iface_dev or key == iface_dev:
                return descr
        return None

    def strip_local(self, name):
        """ ("www.example.com.example.lan", True) when a local search domain was appended to a full name """
        for domain in self.domains:
            if name == domain:
                return name, False
            if name.endswith('.' + domain):
                rest = name[:-len(domain) - 1]
                return rest, True
        return name, False

    def describe(self):
        return {
            'internal': [str(n) for n in self.internal],
            'internal_ifaces': sorted(self.internal_ifaces),
            'uplinks': sorted(self.uplink_ifaces),
            'firewall': sorted(str(a) for a in self.firewall),
            'domains': sorted(self.domains),
            'dns_redirect': self.dns_redirect,
        }


def parse_ip(text):
    return _addr(text)
