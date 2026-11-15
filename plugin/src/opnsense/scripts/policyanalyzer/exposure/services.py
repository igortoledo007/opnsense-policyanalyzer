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

    Map listening processes and ports to human services, which packages make up each service
    (to link a vulnerable package to it) and the attack classes that apply to it.

    The map is data, not logic: a process that is not listed here becomes a "needs_review" finding.
"""

# attack classes (short, English, shown as text). Generic on purpose: they say what an attacker can try
# against the service when it is reachable, not that the firewall is vulnerable.
THREATS = {
    'webgui': ['credential brute force / password spraying', 'session hijacking and CSRF',
               'pre-auth or post-auth command injection in the web interface (see OPNsense advisories)',
               'PHP / lighttpd memory corruption (RCE)', 'TLS downgrade or weak ciphers'],
    'ssh': ['credential brute force', 'pre-auth memory corruption in sshd (RCE, e.g. CVE-2024-6387 class)',
            'user enumeration', 'weak kex/cipher negotiation'],
    'dns': ['DNS amplification / reflection DDoS (open resolver)', 'cache poisoning',
            'resource exhaustion (NXDOMAIN / random subdomain floods)', 'parser memory corruption'],
    'dns_control': ['remote control of the resolver if TLS keys leak'],
    'ntp': ['NTP amplification (monlist class)', 'time shifting'],
    'dhcp': ['rogue client starvation', 'packet parser memory corruption (LAN only)'],
    'vpn_wireguard': ['handshake flood (DoS); WireGuard does not answer unauthenticated packets'],
    'vpn_openvpn': ['TLS handshake flood (DoS)', 'credential brute force', 'pre-auth memory corruption'],
    'vpn_ipsec': ['IKE aggressive mode PSK cracking', 'IKE fragmentation DoS', 'pre-auth memory corruption'],
    'netflow': ['flow record injection / spoofing'],
    'web': ['web application attacks against the service'],
    'snmp': ['community string brute force', 'information disclosure', 'amplification'],
    'proxy': ['open proxy abuse', 'request smuggling'],
    'routing': ['route injection from unauthenticated peers'],
    'unknown': ['unknown service: review what it is and whether it must listen'],
}

# process name (as printed by sockstat, truncated to 10 characters) -> service definition.
#   service: stable id; label: human; kind: THREATS key; admin: management plane;
#   components: package name prefixes that belong to the service (direct link of a vulnerable package);
#   ports: optional {port: (service, label, kind, admin)} overrides for multi purpose daemons.
PROCESSES = {
    'lighttpd': {'service': 'web', 'label': 'lighttpd web server', 'kind': 'web', 'admin': False,
                 'components': ('lighttpd', 'php', 'opnsense', 'openssl')},
    'php-cgi': {'service': 'webgui', 'label': 'Web GUI (PHP)', 'kind': 'webgui', 'admin': True,
                'components': ('php', 'opnsense')},
    'php-fpm': {'service': 'php-fpm', 'label': 'PHP-FPM', 'kind': 'web', 'admin': False, 'components': ('php',)},
    'nginx': {'service': 'nginx', 'label': 'nginx', 'kind': 'web', 'admin': False,
              'components': ('nginx', 'openssl')},
    'haproxy': {'service': 'haproxy', 'label': 'HAProxy', 'kind': 'proxy', 'admin': False,
                'components': ('haproxy', 'openssl')},
    'squid': {'service': 'squid', 'label': 'Squid proxy', 'kind': 'proxy', 'admin': False, 'components': ('squid',)},
    'caddy': {'service': 'caddy', 'label': 'Caddy', 'kind': 'web', 'admin': False, 'components': ('caddy',)},
    'sshd': {'service': 'ssh', 'label': 'OpenSSH server', 'kind': 'ssh', 'admin': True,
             'components': ('openssh-portable', 'openssl')},
    'unbound': {'service': 'unbound', 'label': 'Unbound DNS resolver', 'kind': 'dns', 'admin': False,
                'components': ('unbound', 'openssl', 'libevent', 'expat'),
                'ports': {953: ('unbound-control', 'Unbound remote control', 'dns_control', True)}},
    'dnsmasq': {'service': 'dnsmasq', 'label': 'Dnsmasq DNS/DHCP', 'kind': 'dns', 'admin': False,
                'components': ('dnsmasq',)},
    'dnscrypt-p': {'service': 'dnscrypt-proxy', 'label': 'DNSCrypt proxy', 'kind': 'dns', 'admin': False,
                   'components': ('dnscrypt-proxy',)},
    'chronyd': {'service': 'ntp', 'label': 'chrony NTP', 'kind': 'ntp', 'admin': False,
                'components': ('chrony',),
                'ports': {323: ('chrony-control', 'chrony control (local)', 'ntp', True)}},
    'ntpd': {'service': 'ntp', 'label': 'NTP daemon', 'kind': 'ntp', 'admin': False, 'components': ('ntp',)},
    'kea-dhcp4': {'service': 'dhcp4', 'label': 'Kea DHCPv4', 'kind': 'dhcp', 'admin': False, 'components': ('kea',)},
    'kea-dhcp6': {'service': 'dhcp6', 'label': 'Kea DHCPv6', 'kind': 'dhcp', 'admin': False, 'components': ('kea',)},
    'kea-ctrl-a': {'service': 'kea-ctrl', 'label': 'Kea control agent', 'kind': 'web', 'admin': True,
                   'components': ('kea',)},
    'dhcpd': {'service': 'dhcp4', 'label': 'ISC DHCP', 'kind': 'dhcp', 'admin': False, 'components': ('isc-dhcp',)},
    'dhcpd6': {'service': 'dhcp6', 'label': 'ISC DHCPv6', 'kind': 'dhcp', 'admin': False,
               'components': ('isc-dhcp',)},
    'dhcp6c': {'service': 'dhcp6c', 'label': 'DHCPv6 client', 'kind': 'dhcp', 'admin': False,
               'components': ('dhcp6c',)},
    'dhclient': {'service': 'dhclient', 'label': 'DHCP client', 'kind': 'dhcp', 'admin': False, 'components': ()},
    'samplicate': {'service': 'netflow', 'label': 'NetFlow (samplicator)', 'kind': 'netflow', 'admin': False,
                   'components': ('samplicator',)},
    'flowd': {'service': 'netflow', 'label': 'NetFlow collector (flowd)', 'kind': 'netflow', 'admin': False,
              'components': ('flowd',)},
    'openvpn': {'service': 'openvpn', 'label': 'OpenVPN', 'kind': 'vpn_openvpn', 'admin': False,
                'components': ('openvpn', 'openssl')},
    'charon': {'service': 'ipsec', 'label': 'strongSwan IPsec', 'kind': 'vpn_ipsec', 'admin': False,
               'components': ('strongswan', 'openssl')},
    'bsnmpd': {'service': 'snmp', 'label': 'bsnmpd', 'kind': 'snmp', 'admin': False, 'components': ()},
    'snmpd': {'service': 'snmp', 'label': 'Net-SNMP', 'kind': 'snmp', 'admin': False, 'components': ('net-snmp',)},
    'bgpd': {'service': 'bgp', 'label': 'FRR bgpd', 'kind': 'routing', 'admin': False, 'components': ('frr',)},
    'ospfd': {'service': 'ospf', 'label': 'FRR ospfd', 'kind': 'routing', 'admin': False, 'components': ('frr',)},
    'zebra': {'service': 'zebra', 'label': 'FRR zebra', 'kind': 'routing', 'admin': True, 'components': ('frr',)},
    'syslog-ng': {'service': 'syslog', 'label': 'syslog-ng', 'kind': 'netflow', 'admin': False,
                  'components': ('syslog-ng',)},
    'suricata': {'service': 'suricata', 'label': 'Suricata IDS/IPS', 'kind': 'unknown', 'admin': False,
                 'components': ('suricata',)},
    'redis-serv': {'service': 'redis', 'label': 'Redis', 'kind': 'web', 'admin': True, 'components': ('redis',)},
    'mongod': {'service': 'mongodb', 'label': 'MongoDB', 'kind': 'web', 'admin': True, 'components': ('mongodb',)},
    'ollama': {'service': 'ollama', 'label': 'Ollama (local AI runtime)', 'kind': 'web', 'admin': True,
               'components': ('ollama',)},
}

# kernel sockets have no process ("?" in sockstat): identified by configuration
KERNEL_SERVICE = {'service': 'wireguard', 'label': 'WireGuard (kernel)', 'kind': 'vpn_wireguard', 'admin': False,
                  'components': ('wireguard',)}

# packages whose CVEs concern the whole system rather than one service
SYSTEM_COMPONENTS = ('opnsense', 'opnsense-update', 'FreeBSD-', 'pkg', 'openssl', 'ca_root_nss')


def lookup(process, port, admin_ports=None):
    """ :return: service definition dict (copy) for a listening socket, or None when unknown """
    definition = PROCESSES.get(process)
    if definition is None:
        return None
    result = dict(definition)
    result.pop('ports', None)
    override = definition.get('ports', {}).get(port)
    if override:
        result.update(service=override[0], label=override[1], kind=override[2], admin=override[3])
    # the web server on the GUI port is the web GUI (lighttpd spawns php-cgi)
    if process == 'lighttpd' and admin_ports and admin_ports.get(port) == 'webgui':
        result.update(service='webgui', label='Web GUI (lighttpd + PHP)', kind='webgui', admin=True)
    elif process == 'lighttpd' and port in (80, 443) and admin_ports is not None and \
            'webgui' in admin_ports.values() and port not in admin_ports:
        # the GUI redirect listener on 80 (or 443 when the GUI moved) is part of the GUI too
        result.update(service='webgui', label='Web GUI redirect (lighttpd)', kind='webgui', admin=True)
    result['threats'] = list(THREATS.get(result['kind'], THREATS['unknown']))
    return result


def kernel_service():
    result = dict(KERNEL_SERVICE)
    result['threats'] = list(THREATS[result['kind']])
    return result


def component_match(package, components):
    """ 'php' matches php85 and php85-sqlite3, 'pkg' does not match pkgconf; a trailing '-' is a plain prefix """
    for comp in components:
        if not comp:
            continue
        if package == comp:
            return True
        if comp.endswith('-'):
            if package.startswith(comp):
                return True
        elif package.startswith(comp) and len(package) > len(comp) and \
                (package[len(comp)].isdigit() or package[len(comp)] == '-'):
            return True
    return False
