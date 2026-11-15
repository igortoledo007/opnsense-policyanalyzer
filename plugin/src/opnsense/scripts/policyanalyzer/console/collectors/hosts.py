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

    Host names collector (read only): who an address is on the local networks.

    Sources, all local: Kea DHCPv4 leases (/var/db/kea/kea-leases4.csv), Kea reservations and Unbound host
    overrides from config.xml, and the core Host discovery database (/var/db/hostwatch/hosts.db, opened read
    only exactly like interfaces/list_hosts.py does): interface, MAC vendor, first and last seen.
"""

import csv
import ipaddress
import os
import sqlite3
import time

from ..common import clean_text, is_public
from . import fwinfo


def _leases(path):
    """ ip -> {hostname, mac, expires} (newest record of the CSV wins, as Kea appends) """
    result = {}
    for name in (path, path + '.2'):
        try:
            with open(name, newline='', errors='replace') as handle:
                for row in csv.DictReader(handle):
                    ip = (row.get('address') or '').strip()
                    if not ip:
                        continue
                    expire = int(row.get('expire') or 0) if str(row.get('expire') or '').isdigit() else 0
                    prev = result.get(ip)
                    if prev and prev['expire'] >= expire:
                        continue
                    result[ip] = {'hostname': clean_text(row.get('hostname'), 64).rstrip('.'),
                                  'mac': (row.get('hwaddr') or '').lower(), 'expire': expire}
        except OSError:
            continue
    return result


def _config_names(path):
    """ ip -> [{hostname, source}] from Kea reservations and Unbound overrides """
    root = fwinfo.load_root(path)
    result = {}
    if root is None:
        return result
    for node in root.findall('./OPNsense/Kea/dhcp4/reservations/reservation'):
        ip = (node.findtext('ip_address') or '').strip()
        name = (node.findtext('hostname') or '').strip()
        if ip and name:
            result.setdefault(ip, []).append({'hostname': clean_text(name, 64), 'source': 'kea reservation',
                                              'mac': (node.findtext('hw_address') or '').strip().lower()})
    for node in root.findall('./OPNsense/unboundplus/hosts/host'):
        ip = (node.findtext('server') or '').strip()
        host = (node.findtext('hostname') or '').strip()
        domain = (node.findtext('domain') or '').strip()
        if ip and (host or domain) and (node.findtext('enabled') or '1').strip() != '0':
            fqdn = '.'.join(p for p in (host, domain) if p and p != '*')
            result.setdefault(ip, []).append({'hostname': clean_text(fqdn, 96), 'source': 'unbound override'})
    for node in root.findall('./dhcpd/*/staticmap'):
        ip = (node.findtext('ipaddr') or '').strip()
        name = (node.findtext('hostname') or '').strip()
        if ip and name:
            result.setdefault(ip, []).append({'hostname': clean_text(name, 64), 'source': 'dhcp static map',
                                              'mac': (node.findtext('mac') or '').strip().lower()})
    return result


def _hostwatch_enabled(rc_file):
    try:
        with open(rc_file) as handle:
            return 'hostwatch_enable="YES"' in handle.read()
    except OSError:
        return False


def _discovery(paths, ips, timeout=3.0):
    """ ip -> {interface, mac, vendor, first_seen, last_seen} from the Host discovery database """
    if not ips or not os.path.exists(paths.hostwatch_db) or not _hostwatch_enabled(paths.hostwatch_rc):
        return {}
    result = {}
    try:
        con = sqlite3.connect('file:%s?mode=ro' % paths.hostwatch_db, uri=True, timeout=timeout)
        con.row_factory = sqlite3.Row
        marks = ','.join('?' for _ in ips)
        query = ('SELECT interface_name, ether_address, ip_address, organization_name, first_seen, last_seen '
                 'FROM v_hosts WHERE ip_address IN (%s) ORDER BY last_seen DESC' % marks)
        for row in con.execute(query, list(ips)):
            ip = row['ip_address']
            if ip in result:
                continue
            result[ip] = {'interface': row['interface_name'], 'mac': row['ether_address'],
                          'vendor': clean_text(row['organization_name'], 60),
                          'first_seen': row['first_seen'], 'last_seen': row['last_seen']}
        con.close()
    except sqlite3.Error:
        return {}
    return result


def lookup(paths, addresses):
    """ {available, hosts: [{address, names, interface, ...}]} for local addresses """
    ips = []
    for value in addresses:
        try:
            ip = ipaddress.ip_address(str(value).split('/')[0])
        except ValueError:
            continue
        if str(ip) not in ips:
            ips.append(str(ip))
    leases = _leases(paths.kea_leases)
    static = _config_names(paths.config)
    seen = _discovery(paths, ips)
    now = time.time()
    hosts = []
    for ip in ips[:10]:
        item = {'address': ip}
        names = []
        lease = leases.get(ip)
        if lease and lease['hostname']:
            names.append({'hostname': lease['hostname'], 'source': 'kea lease',
                          'lease_active': lease['expire'] > now})
        names += static.get(ip, [])
        if names:
            item['names'] = names
        if lease and lease['mac']:
            item['mac'] = lease['mac']
        if ip in seen:
            item.update({k: v for k, v in seen[ip].items() if v})
        iface = fwinfo.interface_of(paths.config, ip)
        if iface:
            item['subnet_of'] = '%s (%s)' % (iface['name'], iface['descr'])
        if ip in fwinfo.own_addresses(paths.config):
            item['firewall_address'] = True
        if is_public(ip) and len(item) == 1:
            item['note'] = 'internet address, not a local host'
        hosts.append(item)
    return {
        'available': True,
        'source': 'kea leases, kea reservations, unbound overrides, host discovery',
        'host_discovery': _hostwatch_enabled(paths.hostwatch_rc),
        'hosts': hosts,
    }


def known_names(paths):
    """ name -> [ip] of every local host name (for the router: "why can't the printer ...") """
    result = {}
    for ip, lease in _leases(paths.kea_leases).items():
        if lease['hostname']:
            result.setdefault(lease['hostname'], []).append(ip)
    for ip, items in _config_names(paths.config).items():
        for item in items:
            for name in {item['hostname'], item['hostname'].split('.')[0]}:
                if name and ip not in result.setdefault(name, []):
                    result[name].append(ip)
    # very short or generic names would match ordinary words of the question
    return {k: v for k, v in result.items() if len(k) >= 3 and not k.isdigit()}
