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

    Facts about this firewall taken from config.xml (read only, cached per process): interfaces with their
    device, description, subnets and WAN role.  Used to translate log devices (igc0, pppoe1) into the
    logical names of the rules (lan, wan, opt3) and to find the interface an address belongs to.
"""

import ipaddress
import os
import xml.etree.ElementTree as ET

DYNAMIC = ('dhcp', 'pppoe', 'pptp', 'l2tp')
_CACHE = {}


def _mtime(path):
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def load_root(path):
    """ parsed config.xml root (cached by path + mtime), None when unreadable """
    key = (path, _mtime(path))
    if key in _CACHE:
        return _CACHE[key]
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        root = None
    _CACHE.clear()
    _CACHE[key] = root
    return root


def interfaces(path):
    """ [{name, device, descr, enabled, wan, networks: [ip_network]}] in config order """
    root = load_root(path)
    result = []
    if root is None:
        return result
    for node in root.findall('./interfaces/*'):
        device = (node.findtext('if') or '').strip()
        ipaddr = (node.findtext('ipaddr') or '').strip()
        gateway = (node.findtext('gateway') or '').strip() or (node.findtext('gatewayv6') or '').strip()
        nets = []
        for addr_tag, bits_tag in (('ipaddr', 'subnet'), ('ipaddrv6', 'subnetv6')):
            addr = (node.findtext(addr_tag) or '').strip()
            bits = (node.findtext(bits_tag) or '').strip()
            if addr and bits.isdigit():
                try:
                    nets.append(ipaddress.ip_network('%s/%s' % (addr, bits), strict=False))
                except ValueError:
                    pass
        result.append({
            'name': node.tag,
            'device': device,
            'descr': (node.findtext('descr') or '').strip() or node.tag.upper(),
            'enabled': node.find('enable') is not None,
            'wan': node.tag == 'wan' or bool(gateway) or ipaddr in DYNAMIC,
            'networks': nets,
        })
    for vip in root.findall('./virtualip/vip'):
        subnet = (vip.findtext('subnet') or '').strip()
        bits = (vip.findtext('subnet_bits') or '').strip()
        ifname = (vip.findtext('interface') or '').strip()
        for item in result:
            if item['name'] == ifname and subnet and bits.isdigit():
                try:
                    item['networks'].append(ipaddress.ip_network('%s/%s' % (subnet, bits), strict=False))
                except ValueError:
                    pass
    return result


def device_map(path):
    """ device -> {name, descr, wan} """
    return {i['device']: i for i in interfaces(path) if i['device']}


def wan_devices(path):
    return {i['device'] for i in interfaces(path) if i['wan'] and i['device']}


def interface_of(path, address):
    """ the interface whose subnet holds address (most specific), or None """
    try:
        ip = ipaddress.ip_address(str(address).split('/')[0])
    except ValueError:
        return None
    best = None
    for item in interfaces(path):
        for net in item['networks']:
            if ip.version == net.version and ip in net:
                if best is None or net.prefixlen > best[1].prefixlen:
                    best = (item, net)
    return best[0] if best else None


def own_addresses(path):
    """ addresses configured on the firewall itself (static ones from the config) """
    result = set()
    root = load_root(path)
    if root is None:
        return result
    for node in root.findall('./interfaces/*'):
        for tag in ('ipaddr', 'ipaddrv6'):
            value = (node.findtext(tag) or '').strip()
            try:
                result.add(str(ipaddress.ip_address(value)))
            except ValueError:
                pass
    for vip in root.findall('./virtualip/vip'):
        try:
            result.add(str(ipaddress.ip_address((vip.findtext('subnet') or '').strip())))
        except ValueError:
            pass
    return result


def describe_device(path, device):
    item = device_map(path).get(device)
    if not item:
        return device
    return '%s (%s%s)' % (device, item['name'], ', wan' if item['wan'] else '')


def interface_names(path):
    """ names an operator may type: logical names, descriptions and devices """
    names = []
    for item in interfaces(path):
        for value in (item['name'], item['descr'], item['device']):
            if value and value not in names:
                names.append(value)
    return names
