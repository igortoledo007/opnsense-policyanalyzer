"""
Synthetic config.xml builder for the Policy Analyzer tests.

Only documentation addresses are used: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32.
Configurations are built in memory (io.BytesIO), nothing is written to disk.
"""

import base64
import hashlib
import io
import json
import os
import sys
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE_DIR = os.path.normpath(os.path.join(HERE, '..', 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer'))
FIXTURES = os.path.join(HERE, 'fixtures')
if ENGINE_DIR not in sys.path:
    sys.path.insert(0, ENGINE_DIR)

from engine.report import build_report  # noqa: E402

FIXED_NOW = 1793000000.0  # 2026-10-26, keeps relative dates deterministic

INTERFACES = """
  <interfaces>
    <wan><enable>1</enable><if>vtnet0</if><descr>WAN</descr><ipaddr>198.51.100.2</ipaddr><subnet>24</subnet>
         <gateway>WAN_GW</gateway><blockpriv>1</blockpriv></wan>
    <lan><enable>1</enable><if>vtnet1</if><descr>LAN</descr><ipaddr>192.0.2.1</ipaddr><subnet>25</subnet>
         <ipaddrv6>2001:db8:10::1</ipaddrv6><subnetv6>64</subnetv6></lan>
    <opt1><enable>1</enable><if>vtnet2</if><descr>DMZ</descr><ipaddr>192.0.2.129</ipaddr><subnet>26</subnet></opt1>
    <opt2><enable>1</enable><if>vtnet3</if><descr>GUEST</descr><ipaddr>192.0.2.193</ipaddr><subnet>26</subnet></opt2>
    <opt3><enable>1</enable><if>wg0</if><descr>VPN</descr></opt3>
    <wireguard><internal_dynamic>1</internal_dynamic><descr>WireGuard (Group)</descr><if>wireguard</if>
         <virtual>1</virtual><enable>1</enable><type>group</type></wireguard>
    <lo0><internal_dynamic>1</internal_dynamic><descr>Loopback</descr><enable>1</enable><if>lo0</if>
         <ipaddr>127.0.0.1</ipaddr><ipaddrv6>::1</ipaddrv6><subnet>8</subnet><subnetv6>128</subnetv6>
         <type>none</type><virtual>1</virtual></lo0>
  </interfaces>
  <ifgroups version="1.0.0">
    <ifgroupentry uuid="0f000000-0000-4000-8000-000000000001"><ifname>INTERNAL</ifname><members>lan,opt1</members>
      <nogroup>0</nogroup><sequence>10</sequence><descr>internal networks</descr></ifgroupentry>
  </ifgroups>
  <virtualip><vip><interface>opt1</interface><mode>ipalias</mode><subnet>192.0.2.130</subnet>
      <subnet_bits>26</subnet_bits><descr>dmz alias</descr></vip></virtualip>
"""

SYSTEM = """
  <system>
    <hostname>fw</hostname>
    <webgui><protocol>https</protocol><port>8443</port></webgui>
    <ssh><enabled>enabled</enabled><port>22</port></ssh>
    %s
  </system>
"""

_counter = [0]


def uuid_for(name):
    """ deterministic uuid derived from a readable name """
    raw = hashlib.md5(name.encode('utf-8')).hexdigest()[:12]
    return '00000000-0000-4000-8000-%s' % raw


def rule(name, **fields):
    """ MVC rule, field names as in Filter.xml (use underscores for dashes, e.g. received_on) """
    values = {
        'enabled': '1', 'action': 'pass', 'quick': '1', 'interface': 'lan', 'direction': 'in',
        'ipprotocol': 'inet', 'protocol': 'any', 'source_net': 'any', 'destination_net': 'any',
        'description': name,
    }
    _counter[0] += 1
    values['sequence'] = str(_counter[0] * 10)
    for key, value in fields.items():
        values[key.replace('received_on', 'received-on').replace('set_prio', 'set-prio')] = value
    audit = values.pop('audit', None)
    body = ''.join('<%s>%s</%s>' % (k, escape(str(v)), k) for k, v in values.items())
    if audit is not None:
        body += '<audit>%s</audit>' % base64.b64encode(json.dumps(audit).encode()).decode()
    return '<rule uuid="%s">%s</rule>' % (uuid_for(name), body)


def alias(name, atype, content='', enabled='1', uuid=None):
    content = '\n'.join(content) if isinstance(content, (list, tuple)) else content
    return ('<alias uuid="%s"><enabled>%s</enabled><name>%s</name><type>%s</type><proto/><interface/>'
            '<counters>0</counters><updatefreq/><content>%s</content><description>%s alias</description>'
            '</alias>' % (uuid or uuid_for('alias-' + name), enabled, name, atype, escape(content), name))


def legacy_rule(name, interface='lan', rtype='pass', source='<any/>', destination='<any/>', extra='',
                uuid=None):
    return ('<rule uuid="%s"><type>%s</type><interface>%s</interface><ipprotocol>inet</ipprotocol>'
            '<statetype>keep state</statetype><descr>%s</descr><source>%s</source>'
            '<destination>%s</destination>%s</rule>'
            % (uuid or uuid_for('legacy-' + name), rtype, interface, escape(name), source, destination, extra))


def build_config(rules=(), aliases=(), legacy=(), extra='', system_extra='', filter_settings=None,
                 filter_version='1.0.6'):
    """ filter_settings: dict for //OPNsense/Firewall/Filter/settings/filter (27.1 layout); filter_version:
        version attribute of the Filter model (1.0.6 = 26.7, 1.1.7 = 27.1 master) """
    settings = '' if filter_settings is None else '<settings><filter>%s</filter></settings>' % ''.join(
        '<%s>%s</%s>' % (k, escape(str(v)), k) for k, v in filter_settings.items())
    xml = ('<?xml version="1.0"?>\n<opnsense>%s%s<filter>%s</filter>%s<OPNsense><Firewall>'
           '<Alias version="1.0.1"><geoip><url/></geoip><aliases>%s</aliases></Alias>'
           '<Filter version="%s">%s<rules>%s</rules></Filter></Firewall></OPNsense></opnsense>'
           % (SYSTEM % system_extra, INTERFACES, ''.join(legacy), extra, ''.join(aliases), filter_version,
              settings, ''.join(rules)))
    return io.BytesIO(xml.encode('utf-8'))


def analyze(rules=(), aliases=(), legacy=(), extra='', stats=None, stats_meta=None, system_extra='',
            filter_settings=None, filter_version='1.0.6'):
    cfg = build_config(rules, aliases, legacy, extra, system_extra, filter_settings, filter_version)
    return build_report(cfg, stats, stats_meta or {}, now=FIXED_NOW)


def findings_of(result, ftype, description=None):
    out = []
    for item in result['findings']:
        if item['type'] != ftype:
            continue
        if description is not None and (not item['rules'] or item['rules'][0]['description'] != description):
            continue
        out.append(item)
    return out
