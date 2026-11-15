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

    Passive sources of the LAN inventory, all read only:
      hostwatch     /var/db/hostwatch/hosts.db (Interfaces > Host discovery; SQLite, opened read only)
      kea           Kea DHCPv4 memfile leases (kea-leases4.csv, .2, .1) and the reservations of config.xml
      dnsmasq       /var/db/dnsmasq.leases (when Dnsmasq serves DHCP)
      arp           "arp -an" (present now)
      dns           Unbound host overrides of config.xml and reverse lookups at the local resolver (127.0.0.1)
      port forwards destination NAT rules of config.xml (legacy nat/rule + MVC d_nat), 1:1 NAT
      interfaces    device -> interface key / description, WAN devices
    Nothing is sent to the devices: no probe, no scan.
"""

import calendar
import csv
import ipaddress
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET

from . import common

ARP_RE = re.compile(r'^\S+ \(([0-9.]+)\) at ([0-9a-fA-F:]+) on (\S+)(.*)$')
PTR_RE = re.compile(r'\sIN\s+PTR\s+(\S+)')


def _epoch(text):
    """ 'YYYY-MM-DD HH:MM:SS' (UTC, SQLite current_timestamp) -> epoch """
    try:
        return calendar.timegm(time.strptime(str(text)[:19], '%Y-%m-%d %H:%M:%S'))
    except (ValueError, TypeError):
        return None


def load_config(path=None):
    try:
        return ET.parse(path or common.paths()['config']).getroot()
    except (OSError, ET.ParseError):
        return None


def interfaces(root):
    """ {device: {key, descr, wan, networks[]}} """
    out = {}
    if root is None:
        return out
    for node in root.findall('./interfaces/*'):
        dev = (node.findtext('if') or '').strip()
        if not dev:
            continue
        ipaddr = (node.findtext('ipaddr') or '').strip()
        gateway = (node.findtext('gateway') or '').strip()
        nets = []
        try:
            if ipaddr and ipaddr[0].isdigit():
                nets.append(str(ipaddress.ip_interface('%s/%s' % (ipaddr, node.findtext('subnet') or '32')).network))
        except ValueError:
            pass
        out[dev] = {'key': node.tag, 'descr': (node.findtext('descr') or node.tag.upper()).strip(),
                    'wan': node.tag == 'wan' or bool(gateway) or ipaddr in ('dhcp', 'pppoe', 'pptp', 'l2tp'),
                    'networks': nets}
    return out


def hostwatch(path=None):
    """ [{mac, ip, family, dev, first_seen, last_seen, vendor}] ; dedupe by (mac, ip) keeping the newest """
    path = path or common.paths()['hostwatch']
    if not os.path.exists(path):
        return [], {'available': False, 'reason': 'Host discovery database not found'}
    try:
        db = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=3)
        try:
            has_oui = db.execute("SELECT 1 FROM sqlite_master WHERE name='oui'").fetchone() is not None
            sql = ('SELECT h.ether_address, h.ip_address, h.protocol, h.interface_name, h.first_seen, h.last_seen, %s '
                   'FROM hosts h %s' % (('o.organization_name', "LEFT JOIN oui o ON o.assignment = "
                                         "upper(replace(substr(h.ether_address,0,9),':',''))") if has_oui
                                        else ('NULL', '')))
            rows = db.execute(sql).fetchall()
        finally:
            db.close()
    except sqlite3.Error as exc:
        return [], {'available': False, 'reason': 'Host discovery database: %s' % exc}
    best = {}
    for mac, ip, proto, dev, first, last, vendor in rows:
        mac = common.norm_mac(mac)
        if not mac or not ip:
            continue
        rec = {'mac': mac, 'ip': ip, 'family': 6 if proto == 'inet6' or ':' in ip else 4, 'dev': dev,
               'first_seen': _epoch(first), 'last_seen': _epoch(last), 'vendor': vendor}
        key = (mac, ip)
        if key not in best or (rec['last_seen'] or 0) > (best[key]['last_seen'] or 0):
            best[key] = rec
    return list(best.values()), {'available': True, 'rows': len(rows)}


def kea_leases(paths=None):
    """ {mac: {ip, hostname, expire, state}} newest lease per MAC (memfile CSV, header line) """
    out = {}
    found = False
    for path in paths or common.paths()['kea4']:
        try:
            handle = open(path, newline='')
        except OSError:
            continue
        found = True
        with handle:
            for row in csv.DictReader(handle):
                mac = common.norm_mac(row.get('hwaddr'))
                if not mac:
                    continue
                try:
                    expire = int(row.get('expire') or 0)
                except ValueError:
                    expire = 0
                if row.get('state') not in (None, '', '0'):
                    continue                 # 1 declined, 2 expired-reclaimed
                host = (row.get('hostname') or '').strip().rstrip('.')
                if mac not in out or expire >= out[mac]['expire']:
                    out[mac] = {'ip': row.get('address'), 'hostname': host or None, 'expire': expire,
                                'source': 'kea'}
    return out, {'available': found}


def kea_reservations(root):
    out = {}
    if root is None:
        return out
    for node in root.findall('./OPNsense/Kea/dhcp4/reservations/reservation'):
        mac = common.norm_mac(node.findtext('hw_address'))
        if mac:
            out[mac] = {'ip': (node.findtext('ip_address') or '').strip() or None,
                        'hostname': (node.findtext('hostname') or '').strip() or None,
                        'description': (node.findtext('description') or '').strip() or None}
    for node in root.findall('./dhcpd/*/staticmap'):
        mac = common.norm_mac(node.findtext('mac'))
        if mac and mac not in out:
            out[mac] = {'ip': (node.findtext('ipaddr') or '').strip() or None,
                        'hostname': (node.findtext('hostname') or '').strip() or None,
                        'description': (node.findtext('descr') or '').strip() or None}
    return out


def dnsmasq_leases(path=None):
    """ 'expiry mac ip hostname client-id' per line """
    out = {}
    try:
        with open(path or common.paths()['dnsmasq']) as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 4:
                    continue
                mac = common.norm_mac(parts[1])
                if mac:
                    out[mac] = {'ip': parts[2], 'hostname': None if parts[3] == '*' else parts[3],
                                'source': 'dnsmasq'}
    except OSError:
        pass
    return out


def arp(run):
    """ {mac: {ip, dev}} from "arp -an" (present now) """
    rc, out, _err = run(['arp', '-an'], timeout=10)
    result = {}
    if rc is None:
        return result
    for line in out.splitlines():
        match = ARP_RE.match(line.strip())
        if not match or 'incomplete' in line:
            continue
        mac = common.norm_mac(match.group(2))
        if mac and 'permanent' not in match.group(4):          # permanent = the firewall's own addresses
            result[mac] = {'ip': match.group(1), 'dev': match.group(3)}
    return result


def host_overrides(root):
    """ {ip: fqdn} from Unbound host overrides (A / AAAA) """
    out = {}
    if root is None:
        return out
    for node in root.findall('./OPNsense/unboundplus/hosts/host'):
        if (node.findtext('enabled') or '1') != '1' or (node.findtext('rr') or 'A') not in ('A', 'AAAA'):
            continue
        ip = (node.findtext('server') or '').strip()
        name = '.'.join(x for x in ((node.findtext('hostname') or '').strip(), (node.findtext('domain') or '').strip())
                        if x and x != '*')
        if ip and name:
            out.setdefault(ip, name)
    return out


def reverse_dns(run, ip, timeout=2):
    """ PTR at the local resolver only (127.0.0.1); None when unknown """
    try:
        if not ipaddress.ip_address(ip).is_private:
            return None
    except ValueError:
        return None
    rc, out, _err = run(['drill', '-Q', '-x', ip, '@127.0.0.1'], timeout=timeout)
    if rc != 0 or not out.strip():
        return None
    for line in out.splitlines():
        line = line.strip()
        match = PTR_RE.search(' ' + line)
        name = (match.group(1) if match else line).rstrip('.')
        if name and ' ' not in name and not name.endswith('in-addr.arpa') and not name.endswith('ip6.arpa'):
            return name[:120]
    return None


def port_forwards(root):
    """ {internal ip: [{port, proto, descr, interface, kind}]} destination NAT that reaches LAN devices """
    out = {}
    if root is None:
        return out
    for node in root.findall('./nat/rule'):
        if node.find('disabled') is not None:
            continue
        ip = (node.findtext('target') or '').strip()
        if not ip:
            continue
        out.setdefault(ip, []).append({'port': (node.findtext('local-port') or
                                                node.findtext('destination/port') or '').strip() or 'any',
                                       'proto': (node.findtext('protocol') or 'any').strip(),
                                       'descr': (node.findtext('descr') or '').strip(),
                                       'interface': (node.findtext('interface') or '').strip(), 'kind': 'rdr'})
    for node in root.findall('./OPNsense/Firewall/DNat/rule') + root.findall('./OPNsense/Firewall/Filter/dnat/rule'):
        if (node.findtext('disabled') or '0') == '1' or (node.findtext('enabled') or '1') == '0':
            continue
        ip = (node.findtext('target') or '').strip()
        if ip:
            out.setdefault(ip, []).append({'port': (node.findtext('local_port') or
                                                    node.findtext('local-port') or 'any').strip() or 'any',
                                           'proto': (node.findtext('protocol') or 'any').strip(),
                                           'descr': (node.findtext('descr') or node.findtext('description') or
                                                     '').strip(),
                                           'interface': (node.findtext('interface') or '').strip(), 'kind': 'rdr'})
    for node in root.findall('./nat/onetoone'):
        if node.find('disabled') is not None:
            continue
        ip = (node.findtext('source/address') or '').strip()
        if ip:
            out.setdefault(ip, []).append({'port': 'all', 'proto': 'any', 'descr': (node.findtext('descr') or '').strip(),
                                           'interface': (node.findtext('interface') or '').strip(), 'kind': '1:1'})
    return out
