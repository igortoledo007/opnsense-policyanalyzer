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

    Read only facts of /conf/config.xml used by the quarantine: WAN interfaces, the plugin objects
    (aliases, the "Max Cyber IA" rule, the cron job), the floating rules that decide the rule position and
    the sources of the guards (DNS, NTP, gateways, WireGuard, Tailscale, pa_never_block).
    Changes are never made here: they go through the core models (model.php).
"""

import xml.etree.ElementTree as ET

from . import common

DYNAMIC = ('dhcp', 'pppoe', 'pptp', 'l2tp')


def _text(node, path, default=''):
    value = node.findtext(path) if node is not None else None
    return value.strip() if isinstance(value, str) else default


class FirewallConfig:
    def __init__(self, path):
        self.path = path
        try:
            self.root = ET.parse(path).getroot()
        except (OSError, ET.ParseError) as exc:
            raise common.QuarantineError('can not read %s: %s' % (path, exc))

    # ---------------------------------------------------------- interfaces

    def interfaces(self):
        result = {}
        for node in self.root.findall('./interfaces/*'):
            result[node.tag] = {
                'key': node.tag, 'dev': _text(node, 'if'), 'descr': _text(node, 'descr') or node.tag.upper(),
                'ipaddr': _text(node, 'ipaddr'), 'subnet': _text(node, 'subnet'), 'ipaddrv6': _text(node, 'ipaddrv6'),
                'gateway': _text(node, 'gateway'), 'gatewayv6': _text(node, 'gatewayv6'),
                'enabled': node.find('enable') is not None, 'virtual': node.findtext('virtual') is not None,
                'type': _text(node, 'type'),
            }
        return result

    def wan_interfaces(self):
        """ [{"key", "dev", "descr"}]: "wan" and every interface with a gateway or a dynamic uplink """
        result = []
        for key, itf in self.interfaces().items():
            if not itf['dev'] or itf['type'] == 'group':
                continue
            if key == 'wan' or itf['gateway'] or itf['gatewayv6'] or itf['ipaddr'] in DYNAMIC or \
                    itf['ipaddrv6'] in ('dhcp6', 'slaac', 'pppoe'):
                result.append({'key': key, 'dev': itf['dev'], 'descr': itf['descr'], 'enabled': itf['enabled']})
        return result

    def device_to_key(self):
        return {itf['dev']: key for key, itf in self.interfaces().items() if itf['dev']}

    def static_addresses(self):
        """ own addresses written in the config (interfaces and virtual IPs) """
        result = []
        for itf in self.interfaces().values():
            for value in (itf['ipaddr'], itf['ipaddrv6']):
                if common.addr(value) is not None:
                    result.append(value)
        for vip in self.root.findall('./virtualip/vip'):
            value = _text(vip, 'subnet')
            if common.addr(value) is not None:
                result.append(value)
        return result

    # ---------------------------------------------------------- guard sources

    def gateways(self):
        result = []
        for gw in self.root.findall('.//gateways/gateway_item') + self.root.findall(
                './OPNsense/Gateways/gateway_item'):
            for field in ('gateway', 'monitor'):
                value = _text(gw, field)
                if common.addr(value) is not None:
                    result.append(value)
        return result

    def dns_servers(self):
        result = [n.text.strip() for n in self.root.findall('./system/dnsserver') if n.text and n.text.strip()]
        for dot in self.root.findall('./OPNsense/unboundplus/dots/dot'):
            value = _text(dot, 'server')
            if value:
                result.append(value)
        for node in self.root.findall('./OPNsense/unboundplus/forwarding/*'):
            if node.text and common.addr(node.text) is not None:
                result.append(node.text.strip())
        return result

    def ntp_servers(self):
        value = _text(self.root, './system/timeservers')
        return [v for v in value.split() if v]

    def webgui_port(self):
        port = _text(self.root, './system/webgui/port')
        if port.isdigit():
            return int(port)
        return 80 if _text(self.root, './system/webgui/protocol') == 'http' else 443

    def ssh_port(self):
        port = _text(self.root, './system/ssh/port')
        return int(port) if port.isdigit() else 22

    def wireguard(self):
        """ {"ports": [listen ports of enabled instances], "peers": [endpoint host or ip]} """
        wg = self.root.find('./OPNsense/wireguard')
        ports, peers = [], []
        if wg is None:
            return {'ports': ports, 'peers': peers}
        for srv in wg.findall('./server/servers/server'):
            port = _text(srv, 'port')
            if port.isdigit() and _text(srv, 'enabled', '1') != '0':
                ports.append(int(port))
        for peer in wg.findall('./client/clients/client'):
            value = _text(peer, 'serveraddress')
            if value:
                peers.append(value)
        return {'ports': sorted(set(ports)), 'peers': peers}

    def tailscale(self):
        node = self.root.find('./OPNsense/tailscale/settings')
        if node is None:
            return {'enabled': False, 'port': None}
        port = _text(node, 'listenPort')
        return {'enabled': _text(node, 'enabled') == '1', 'port': int(port) if port.isdigit() else 41641}

    # ---------------------------------------------------------- aliases / rules / cron

    def aliases(self):
        result = {}
        for node in self.root.findall('./OPNsense/Firewall/Alias/aliases/alias'):
            name = _text(node, 'name')
            if name:
                content = [c.strip() for c in _text(node, 'content').replace(',', '\n').split('\n') if c.strip()]
                result[name] = {'uuid': node.get('uuid'), 'name': name, 'type': _text(node, 'type'),
                                'enabled': _text(node, 'enabled', '1') != '0', 'content': content,
                                'description': _text(node, 'description')}
        return result

    def filter_version(self):
        node = self.root.find('./OPNsense/Firewall/Filter')
        return node.get('version') if node is not None else None

    def rules(self):
        """ MVC rules (Firewall: Rules / Automation), in config order """
        result = []
        for node in self.root.findall('./OPNsense/Firewall/Filter/rules/rule'):
            seq = _text(node, 'sequence')
            ifaces = [i for i in _text(node, 'interface').split(',') if i]
            result.append({
                'uuid': node.get('uuid'), 'sequence': int(seq) if seq.isdigit() else 1,
                'enabled': _text(node, 'enabled', '1') != '0', 'action': _text(node, 'action', 'pass'),
                'quick': _text(node, 'quick', '1') != '0', 'interfaces': ifaces,
                'interfacenot': _text(node, 'interfacenot', '0') == '1',
                'direction': _text(node, 'direction', 'in'), 'source_net': _text(node, 'source_net', 'any'),
                'destination_port': _text(node, 'destination_port'), 'protocol': _text(node, 'protocol', 'any'),
                'log': _text(node, 'log', '0') == '1', 'description': _text(node, 'description'),
                'floating': len(ifaces) != 1 or _text(node, 'interfacenot', '0') == '1',
            })
        return result

    def quarantine_rules(self):
        return [r for r in self.rules() if r['description'] == common.RULE_DESCR]

    def cron_jobs(self):
        result = []
        for node in self.root.findall('./OPNsense/cron/jobs/job'):
            result.append({'uuid': node.get('uuid'), 'command': _text(node, 'command'),
                           'parameters': _text(node, 'parameters'), 'minutes': _text(node, 'minutes'),
                           'hours': _text(node, 'hours'), 'enabled': _text(node, 'enabled', '1') != '0',
                           'description': _text(node, 'description'), 'origin': _text(node, 'origin')})
        return result

    def quarantine_cron(self):
        return [j for j in self.cron_jobs() if j['command'] == common.CRON_COMMAND]


def rule_position(cfg, wan_keys):
    """
    sequence for the new rule and what it precedes: a floating rule (more than one interface) is
    evaluated before every interface rule, and among the floating rules by sequence; MVC rules precede the
    legacy ones of the same group.  :return: {"sequence", "floating", "before": [rules], "warnings": []}
    """
    rules = [r for r in cfg.rules() if r['description'] != common.RULE_DESCR]
    floating = len(wan_keys) != 1
    warnings = []
    if floating:
        group = [r for r in rules if r['floating'] and r['enabled']]
    else:
        group = [r for r in rules if not r['floating'] and r['interfaces'] == wan_keys and r['enabled']]
        early = [r for r in rules if r['floating'] and r['enabled'] and r['action'] == 'pass' and r['quick'] and
                 r['direction'] in ('in', 'any') and (not r['interfaces'] or set(r['interfaces']) & set(wan_keys))]
        if early:
            warnings.append('only one WAN: the rule is an interface rule, %d floating pass rule(s) on it are '
                            'evaluated first: %s' % (len(early), ', '.join(r['description'] or r['uuid'] for r in early)))
    lowest = min([r['sequence'] for r in group] or [100])
    sequence = max(1, lowest - 1)
    ties = [r for r in group if r['sequence'] == sequence]
    if ties:
        warnings.append('sequence %d is shared with %s: open Firewall: Rules and move it below "%s"' % (
            sequence, ', '.join(r['description'] or r['uuid'] for r in ties), common.RULE_DESCR))
    group = sorted(group, key=lambda r: r['sequence'])
    wan_pass = [r for r in rules if r['enabled'] and r['action'] == 'pass' and r['direction'] in ('in', 'any') and
                (not r['interfaces'] or set(r['interfaces']) & set(wan_keys))]
    return {'sequence': sequence, 'floating': floating, 'before': group[:5], 'group_size': len(group),
            'wan_pass_rules': wan_pass, 'warnings': warnings}
