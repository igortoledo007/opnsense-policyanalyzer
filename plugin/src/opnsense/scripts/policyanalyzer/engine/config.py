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

    config.xml reader. Only reads; never writes. Values that are secrets (alias passwords, VIP passwords...)
    are never extracted.
"""

import base64
import json
import re
import xml.etree.ElementTree as ET

# rule fields (MVC names) that only narrow what a rule matches
MATCH_EXTRA_SET_FIELDS = ('icmptype', 'icmp6type')
MATCH_EXTRA_FIELDS = (
    'tagged', 'sched', 'tos', 'prio', 'received-on', 'received-on-not',
    'tcpflags1', 'tcpflags2', 'tcpflags_any', 'os'
)
# rule fields that change what happens to a matched packet (besides the action)
EFFECT_FIELDS = (
    'gateway', 'replyto', 'disablereplyto', 'tag', 'shaper1', 'shaper2', 'set-prio', 'set-prio-low',
    'divert-to', 'statetype', 'state-policy', 'max', 'max-src-nodes', 'max-src-conn', 'max-src-states',
    'max-src-conn-rate', 'max-src-conn-rates', 'overload', 'statetimeout', 'adaptivestart', 'adaptiveend',
    'udp-first', 'udp-multiple', 'udp-single', 'max-pkt-rate-number', 'max-pkt-rate-seconds', 'allowopts',
    'nopfsync',
    # 27.1 (Filter.xml 1.0.8+): normalization options on pass and match rules
    'scrub_no_df', 'scrub_random_id', 'scrub_max_mss', 'scrub_min_ttl', 'scrub_set_tos'
)
BOOL_FIELDS = ('disablereplyto', 'allowopts', 'nopfsync', 'tcpflags_any', 'received-on-not',
               'scrub_no_df', 'scrub_random_id')
# effect fields pf still applies on a "match" rule (FilterRule drops route-to/reply-to and state options on
# anything that is not "pass"); divert-to and allow-opts are kept to stay on the conservative side
MATCH_EFFECT_FIELDS = ('tag', 'shaper1', 'shaper2', 'set-prio', 'set-prio-low', 'divert-to', 'allowopts',
                       'scrub_no_df', 'scrub_random_id', 'scrub_max_mss', 'scrub_min_ttl', 'scrub_set_tos')
# //OPNsense/Firewall/Filter/settings/filter (27.1, MFP1_0_9 .. MFP1_1_7) -> legacy node used up to 26.7
FILTER_SETTINGS_LEGACY = {
    'keep_counters': ('system', 'keepcounters'),
    'skip_rules_gw_down': ('system', 'skip_rules_gw_down'),
    'disable_reply_to': ('system', 'disablereplyto'),
    'no_antilockout': ('system/webgui', 'noantilockout'),
    'disabled': ('system', 'disablefilter'),
    'state_policy': ('system', 'state-policy'),
}
# Filter.xml version that migrated legacy normalization (filter/scrub/rule) into "match" rules (MFP1_0_8)
SCRUB_MIGRATED_VERSION = (1, 0, 8)

DYNAMIC_V4 = ('dhcp', 'pppoe', 'pptp', 'l2tp', 'ppp')
DYNAMIC_V6 = ('dhcp6', 'slaac', '6rd', '6to4', 'track6', 'pppoe', 'ppp')


def _text(node, tag, default=''):
    if node is None:
        return default
    child = node.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _has(node, tag):
    return node is not None and node.find(tag) is not None


def _truthy(value):
    return str(value).strip().lower() in ('1', 'yes', 'true', 'on')


class Interface(object):
    def __init__(self, name, node):
        self.name = name
        self.descr = _text(node, 'descr') or name.upper()
        self.device = _text(node, 'if')
        self.enabled = _has(node, 'enable')
        self.ipaddr = _text(node, 'ipaddr')
        self.subnet = _text(node, 'subnet')
        self.ipaddrv6 = _text(node, 'ipaddrv6')
        self.subnetv6 = _text(node, 'subnetv6')
        self.gateway = _text(node, 'gateway')
        self.gatewayv6 = _text(node, 'gatewayv6')
        self.type = _text(node, 'type')
        self.virtual = _has(node, 'virtual')
        self.blockbogons = _has(node, 'blockbogons')
        self.blockpriv = _has(node, 'blockpriv')

    @property
    def is_group(self):
        return self.type == 'group'

    @property
    def is_wan(self):
        """ heuristic: an interface facing the internet """
        if self.name == 'wan':
            return True
        if self.gateway or self.gatewayv6:
            return True
        if self.ipaddr in DYNAMIC_V4 or self.ipaddrv6 in ('dhcp6', 'slaac', '6rd', '6to4', 'pppoe'):
            return True
        return self.blockbogons or self.blockpriv


class Alias(object):
    def __init__(self, node, uuid=None):
        self.uuid = uuid or node.get('uuid', '')
        self.name = _text(node, 'name')
        self.type = _text(node, 'type')
        self.enabled = _text(node, 'enabled', '1') != '0'
        self.description = _text(node, 'description') or _text(node, 'descr')
        self.proto = _text(node, 'proto')
        self.interface = _text(node, 'interface')
        raw = _text(node, 'content') or _text(node, 'address')
        self.content = [x.strip() for x in re.split(r'[\n,]', raw) if x.strip()] if raw else []
        if not self.content and _text(node, 'url'):
            # legacy url aliases
            self.content = [_text(node, 'url')]
        self.builtin = False

    @classmethod
    def builtin_alias(cls, name, atype, description):
        obj = cls.__new__(cls)
        obj.uuid = ''
        obj.name = name
        obj.type = atype
        obj.enabled = True
        obj.description = description
        obj.proto = ''
        obj.interface = ''
        obj.content = []
        obj.builtin = True
        return obj


class RawRule(object):
    """ rule as read from config.xml, converted to the MVC field names """

    def __init__(self):
        self.source = 'mvc'
        self.uuid = ''
        self.index = 0
        self.fields = {}
        self.audit = {}

    def get(self, key, default=''):
        return self.fields.get(key, default)


def _decode_audit(raw):
    if not raw:
        return {}
    for decoder in (lambda x: json.loads(x), lambda x: json.loads(base64.b64decode(x).decode('utf-8', 'replace'))):
        try:
            data = decoder(raw)
            if isinstance(data, dict):
                result = {}
                for key in ('created', 'updated'):
                    if isinstance(data.get(key), dict):
                        # only keep the timestamp, usernames are not needed for the analysis
                        result[key] = {'time': data[key].get('time', '')}
                return result
        except (ValueError, TypeError, UnicodeDecodeError, base64.binascii.Error):
            continue
    return {}


def _legacy_time(node):
    result = {}
    for key in ('created', 'updated'):
        child = node.find(key)
        if child is not None:
            result[key] = {'time': _text(child, 'time')}
    return result


class FirewallConfig(object):
    def __init__(self, path):
        self.path = path
        root = ET.parse(path).getroot()
        self.interfaces = {}
        self.groups = {}           # group name -> {'members': [...], 'sequence': int}
        self.vips = []             # (interface, address, bits, mode)
        self.aliases = {}          # name -> Alias
        self.rules = []            # RawRule, MVC first then legacy (config order)
        self.admin_ports = {}      # port -> service name
        self.keepcounters = False
        self.keepcounters_source = None   # 'mvc' | 'legacy' | None
        self.filter_settings = {}         # firewall settings, MVC names (keep_counters, skip_rules_gw_down, ...)
        self.filter_version = (0,)        # version attribute of //OPNsense/Firewall/Filter
        self.all_text_tokens = None
        self._root = root
        self._parse_interfaces(root)
        self._parse_groups(root)
        self._parse_vips(root)
        self._parse_aliases(root)
        self._parse_mvc_rules(root)
        self._parse_legacy_rules(root)
        self._parse_system(root)
        self._parse_filter_settings(root)

    # ------------------------------------------------------------------ parsers
    def _parse_interfaces(self, root):
        node = root.find('interfaces')
        if node is None:
            return
        for child in node:
            self.interfaces[child.tag] = Interface(child.tag, child)

    def _parse_groups(self, root):
        node = root.find('ifgroups')
        if node is None:
            return
        for entry in node.findall('ifgroupentry'):
            name = _text(entry, 'ifname')
            if not name:
                continue
            seq = _text(entry, 'sequence', '0')
            self.groups[name] = {
                'members': [x for x in re.split(r'[ |,]+', _text(entry, 'members')) if x],
                'sequence': int(seq) if seq.isdigit() else 0,
                'descr': _text(entry, 'descr'),
            }

    def _parse_vips(self, root):
        node = root.find('virtualip')
        if node is None:
            return
        for vip in node.findall('vip'):
            self.vips.append((
                _text(vip, 'interface'), _text(vip, 'subnet'), _text(vip, 'subnet_bits'), _text(vip, 'mode')
            ))

    def _parse_aliases(self, root):
        for node in root.findall('./OPNsense/Firewall/Alias/aliases/alias'):
            alias = Alias(node)
            if alias.name:
                self.aliases[alias.name] = alias
        # legacy aliases (pre MVC configurations)
        for node in root.findall('./aliases/alias'):
            alias = Alias(node)
            if alias.name and alias.name not in self.aliases:
                self.aliases[alias.name] = alias
        # static (core.json) aliases
        for name, descr in (('bogons', 'bogon networks (internal)'), ('bogonsv6', 'bogon networks IPv6 (internal)'),
                            ('virusprot', 'overload table for rate limiting (internal)'),
                            ('sshlockout', 'abuse lockout table (internal)')):
            if name not in self.aliases:
                self.aliases[name] = Alias.builtin_alias(name, 'external', descr)
        # interface network aliases (InterfaceNetworkAliases.php)
        for ifname in self.interfaces:
            name = '__%s_network' % ifname
            if name not in self.aliases:
                alias = Alias.builtin_alias(name, 'internal', '%s net' % self.interfaces[ifname].descr)
                alias.interface = ifname
                self.aliases[name] = alias

    def _parse_mvc_rules(self, root):
        for idx, node in enumerate(root.findall('./OPNsense/Firewall/Filter/rules/rule')):
            rule = RawRule()
            rule.source = 'mvc'
            rule.uuid = node.get('uuid', '')
            rule.index = idx
            for child in node:
                if child.tag == 'audit':
                    rule.audit = _decode_audit((child.text or '').strip())
                    continue
                rule.fields[child.tag] = (child.text or '').strip()
            # apply model defaults (Filter.xml) for missing values
            defaults = {
                'enabled': '1', 'action': 'pass', 'quick': '1', 'interfacenot': '0', 'direction': 'in',
                'ipprotocol': 'inet', 'protocol': 'any', 'source_net': 'any', 'source_not': '0',
                'destination_net': 'any', 'destination_not': '0', 'statetype': 'keep', 'log': '0',
                'sequence': '1', 'scrub_no_df': '0', 'scrub_random_id': '0'
            }
            for key, value in defaults.items():
                if rule.fields.get(key, '') == '':
                    rule.fields[key] = value
            self.rules.append(rule)

    def _parse_legacy_rules(self, root):
        for idx, node in enumerate(root.findall('./filter/rule')):
            rule = RawRule()
            rule.source = 'legacy'
            rule.uuid = node.get('uuid', '')
            rule.index = idx
            rule.audit = _legacy_time(node)
            f = rule.fields
            f['enabled'] = '0' if _has(node, 'disabled') else '1'
            f['action'] = _text(node, 'type') or 'pass'
            floating = _has(node, 'floating') and _text(node, 'floating') != 'no'
            f['floating'] = '1' if floating else '0'
            if _has(node, 'quick'):
                f['quick'] = '1' if (_text(node, 'quick') == '' or _truthy(_text(node, 'quick'))) else '0'
            else:
                # FilterRule::parseFilterRules(): all rules are quick by default except floating
                f['quick'] = '0' if floating else '1'
            f['interfacenot'] = '1' if _has(node, 'interfacenot') else '0'
            f['interface'] = _text(node, 'interface')
            f['direction'] = _text(node, 'direction') or 'in'
            f['ipprotocol'] = _text(node, 'ipprotocol') or 'inet'
            f['protocol'] = (_text(node, 'protocol') or 'any').upper() if _text(node, 'protocol') else 'any'
            if f['protocol'] == 'ANY':
                f['protocol'] = 'any'
            for tag, prefix in (('source', 'source'), ('destination', 'destination')):
                sub = node.find(tag)
                if sub is None:
                    f[prefix + '_net'] = 'any'
                    f[prefix + '_not'] = '0'
                    f[prefix + '_port'] = ''
                    continue
                if _text(sub, 'network'):
                    f[prefix + '_net'] = _text(sub, 'network')
                elif _text(sub, 'address'):
                    f[prefix + '_net'] = _text(sub, 'address')
                else:
                    f[prefix + '_net'] = 'any'
                f[prefix + '_not'] = '1' if _has(sub, 'not') else '0'
                port = _text(sub, 'port')
                if f['protocol'].lower() not in ('tcp', 'udp', 'tcp/udp'):
                    # Rule::legacyMoveAddressFields() only keeps ports for tcp/udp
                    port = ''
                f[prefix + '_port'] = port
            f['description'] = _text(node, 'descr')
            f['log'] = '1' if _has(node, 'log') else '0'
            f['statetype'] = (_text(node, 'statetype') or 'keep').split(' ')[0]
            for tag in ('gateway', 'reply-to', 'icmptype', 'icmp6-type', 'tag', 'tagged', 'sched', 'os', 'tos',
                        'prio', 'set-prio', 'set-prio-low', 'tcpflags1', 'tcpflags2', 'max', 'max-src-nodes',
                        'max-src-conn', 'max-src-states', 'max-src-conn-rate', 'max-src-conn-rates', 'overload',
                        'statetimeout', 'adaptivestart', 'adaptiveend', 'divert-to', 'state-policy', 'shaper1',
                        'shaper2', 'received-on'):
                if _text(node, tag):
                    target = {'reply-to': 'replyto', 'icmp6-type': 'icmp6type'}.get(tag, tag)
                    f[target] = _text(node, tag)
            for tag in ('tcpflags_any', 'allowopts', 'nopfsync', 'disablereplyto', 'received-on-not'):
                if _has(node, tag):
                    f[tag] = '1'
            self.rules.append(rule)

    def _parse_system(self, root):
        system = root.find('system')
        if system is None:
            self.admin_ports = {443: 'webgui', 22: 'ssh'}
            return
        webgui = system.find('webgui')
        port = _text(webgui, 'port')
        proto = _text(webgui, 'protocol') or 'https'
        if port.isdigit():
            self.admin_ports[int(port)] = 'webgui'
        else:
            self.admin_ports[443 if proto == 'https' else 80] = 'webgui'
        ssh = system.find('ssh')
        if ssh is not None and (_has(ssh, 'enabled') and _text(ssh, 'enabled') != '0'):
            sport = _text(ssh, 'port')
            self.admin_ports[int(sport) if sport.isdigit() else 22] = 'ssh'

    def _parse_filter_settings(self, root):
        """ firewall settings: 27.1 MVC model (//OPNsense/Firewall/Filter/settings/filter) first, the legacy
            nodes of 26.7 (system/keepcounters, ...) as fallback. A config in the middle of the migration can
            have both; a key present in the model always wins.
        """
        filter_node = root.find('./OPNsense/Firewall/Filter')
        version = (filter_node.get('version', '') if filter_node is not None else '').strip()
        self.filter_version = tuple(int(x) for x in version.split('.')) if re.match(r'^\d+(\.\d+)*$', version) \
            else (0,)
        result = {}
        node = root.find('./OPNsense/Firewall/Filter/settings/filter')
        if node is not None:
            for child in node:
                result[child.tag] = (child.text or '').strip()
        sources = {}
        for key, (path, tag) in FILTER_SETTINGS_LEGACY.items():
            if key in result:
                sources[key] = 'mvc'
                continue
            legacy = root.find(path)
            if _has(legacy, tag):
                result[key] = '1' if _text(legacy, tag) != '0' else '0'
                sources[key] = 'legacy'
            else:
                result[key] = '0'
        result['_model'] = 'mvc' if node is not None else 'legacy'
        self.filter_settings = result
        self.keepcounters = result.get('keep_counters') == '1'
        self.keepcounters_source = sources.get('keep_counters')

    @property
    def settings_page(self):
        """ where the firewall settings (keepcounters, ...) live in the GUI """
        if self.filter_settings.get('_model') == 'mvc':
            return 'ui/firewall/settings'
        return 'system_advanced_firewall.php'

    @property
    def scrub_migrated(self):
        """ True when legacy normalization rules were migrated to match rules and are ignored by pf """
        return self.filter_version >= SCRUB_MIGRATED_VERSION

    # ------------------------------------------------------------------ helpers
    def text_tokens(self):
        """ every token used as a value anywhere in the configuration, excluding alias definitions names.
            used to decide whether an alias is referenced by anything (rules, NAT, other aliases, plugins).
        """
        if self.all_text_tokens is not None:
            return self.all_text_tokens
        counts = {}
        skip = set()
        for path in ('./OPNsense/Firewall/Alias/aliases/alias/name', './aliases/alias/name'):
            for node in self._root.findall(path):
                skip.add(id(node))
        if self.scrub_migrated:
            # leftover legacy normalization (filter/scrub) is ignored by pf once migrated (MFP1_0_8), so an
            # alias only referenced there is not in use; before that version the scrub rules are still active
            for scrub in self._root.findall('./filter/scrub'):
                skip.update(id(x) for x in scrub.iter())
        for node in self._root.iter():
            # free text (descriptions) is not a reference
            if id(node) in skip or not node.text or node.tag in ('descr', 'description', 'audit'):
                continue
            for token in re.split(r'[\s,]+', node.text):
                token = token.strip('<>()!{}')
                if token:
                    counts[token] = counts.get(token, 0) + 1
        self.all_text_tokens = counts
        return counts

    def interface_display(self, name):
        if name in self.interfaces:
            return self.interfaces[name].descr
        return name
