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

    Read-only inventory: installed packages, OPNsense and FreeBSD versions, listening sockets mapped to
    services and packages, interfaces (WAN or not) and the local addresses.

    Everything that can not be read (no root, command missing) is reported as null with a reason in
    "limitations"; nothing is guessed.
"""

import ipaddress
import json
import re

from . import common, services

CONFIGCTL = '/usr/local/sbin/configctl'
WHICH_RE = re.compile(r'^(?P<path>\S+) was installed by package (?P<pkg>\S+)\s*$')
WHICH_MISSING_RE = re.compile(r'^(?P<path>\S+) was not found in the database')
BASE_PREFIXES = ('/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/libexec/', '/libexec/', '/rescue/')
OPNSENSE_KEYS = ('CORE_ABI', 'CORE_ARCH', 'CORE_FLAVOUR', 'CORE_NAME', 'CORE_PACKAGE', 'CORE_PRODUCT',
                 'CORE_SERIES', 'CORE_VERSION', 'CORE_HASH')


# ------------------------------------------------------------------ packages and versions

def packages(run):
    rc, out, err = run(['pkg', 'query', '-e', '%a=0 || %a=1', '%n\t%v\t%o\t%a\t%c'])
    if rc != 0:
        return None, 'pkg query failed: %s' % (err.strip()[:200] or 'not available')
    items = []
    for line in out.splitlines():
        parts = line.split('\t', 4)
        if len(parts) < 4:
            continue
        items.append({'name': parts[0], 'version': parts[1], 'origin': parts[2],
                      'automatic': parts[3] == '1', 'comment': parts[4] if len(parts) > 4 else ''})
    items.sort(key=lambda p: p['name'])
    return items, None


def opnsense_version(run):
    rc, out, _err = run(['opnsense-version', '-v'])
    version = out.strip() if rc == 0 and out.strip() else None
    details = {}
    rc, out, _err = run(['opnsense-version', '-O'])
    if rc == 0:
        try:
            data = json.loads(out)
            details = {k: data[k] for k in OPNSENSE_KEYS if k in data}
        except ValueError:
            details = {}
    result = {'version': version, 'details': details}
    if version is None:
        result['reason'] = 'opnsense-version not available'
    return result


def freebsd_version(run):
    rc, out, _err = run(['freebsd-version', '-ku'])
    lines = [x.strip() for x in out.splitlines() if x.strip()] if rc == 0 else []
    if len(lines) >= 2:
        return {'kernel': lines[0], 'userland': lines[1]}
    return {'kernel': None, 'userland': None, 'reason': 'freebsd-version not available'}


# ------------------------------------------------------------------ sockets

def parse_endpoint(text):
    """ '*:22', '192.0.2.1:443', '[::1]:22', '[fe80::1%lo0]:80' -> (host, port) ; host '*' = wildcard """
    text = text.strip()
    if text.startswith('['):
        host, _sep, port = text[1:].partition(']:')
    else:
        host, _sep, port = text.rpartition(':')
    if not port.isdigit():
        return None, None
    return host, int(port)


def bind_scope(host):
    """ 'any' (wildcard), 'loopback' or 'address' """
    if host in ('*', '0.0.0.0', '::', ''):
        return 'any'
    if '%lo' in host:
        return 'loopback'
    try:
        ip = ipaddress.ip_address(host.split('%')[0])
    except ValueError:
        return 'address'
    return 'loopback' if ip.is_loopback else 'address'


def sockets(run):
    rc, out, err = run(['sockstat', '-46', '-l', '-P', 'tcp,udp'])
    if rc != 0:
        return None, 'sockstat failed: %s' % (err.strip()[:200] or 'not available')
    result = []
    seen = set()
    for line in out.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 6:
            continue
        user, cmd, pid, _fd, proto, local = fields[:6]
        host, port = parse_endpoint(local)
        if port is None:
            continue
        family = 6 if proto.endswith('6') else 4
        transport = 'udp' if proto.startswith('udp') else 'tcp'
        key = (cmd, pid, transport, family, host, port)
        if key in seen:
            continue
        seen.add(key)
        kernel = cmd == '?' * len(cmd)
        result.append({'user': None if kernel else user, 'process': None if kernel else cmd,
                       'pid': int(pid) if pid.isdigit() else None, 'proto': transport, 'family': family,
                       'address': host, 'port': port, 'scope': bind_scope(host), 'kernel': kernel})
    return result, None


def binaries(run, pids):
    """ pid -> executable path (procstat -b, root needed for other users' processes) """
    paths = {}
    pids = sorted(p for p in set(pids) if p)
    if not pids:
        return paths
    rc, out, _err = run(['procstat', '-b'] + [str(p) for p in pids])
    if rc is None:
        return paths
    for line in out.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[0].isdigit():
            paths[int(fields[0])] = fields[-1]
    return paths


def owners(run, paths):
    """ executable path -> 'name-version' of the package that installed it (None for base / unknown) """
    result = {}
    paths = sorted(set(p for p in paths if p and p.startswith('/')))
    if not paths:
        return result
    _rc, out, err = run(['pkg', 'which'] + paths)
    for line in (out + '\n' + err).splitlines():
        match = WHICH_RE.match(line.strip())
        if match:
            result[match.group('path')] = match.group('pkg')
            continue
        match = WHICH_MISSING_RE.match(line.strip())
        if match:
            result[match.group('path')] = None
    return result


# ------------------------------------------------------------------ interfaces

def live_addresses(run):
    """ device -> {'ipv4': [...], 'ipv6': [...], 'up': bool} from configd (same source as the GUI) """
    rc, out, err = run([CONFIGCTL, 'interface', 'list', 'ifconfig'])
    if rc != 0:
        return None, 'configctl interface list ifconfig failed: %s' % (err.strip()[:200] or 'not available')
    try:
        data = json.loads(out)
    except ValueError:
        return None, 'configctl interface list ifconfig returned no JSON'
    result = {}
    for device, info in data.items():
        if not isinstance(info, dict):
            continue
        v4 = [a.get('ipaddr') for a in info.get('ipv4') or [] if isinstance(a, dict) and a.get('ipaddr')]
        v6 = [a.get('ipaddr') for a in info.get('ipv6') or [] if isinstance(a, dict) and a.get('ipaddr')]
        result[device] = {'ipv4': v4, 'ipv6': v6, 'up': 'up' in (info.get('flags') or [])}
    return result, None


def interfaces(cfg, live):
    result = []
    gateway_ifs = set()
    root = getattr(cfg, '_root', None)
    if root is not None:
        for item in root.findall('./OPNsense/Gateways/gateway_item'):
            if (item.findtext('disabled') or '0') != '1' and item.findtext('interface'):
                gateway_ifs.add(item.findtext('interface'))
        for item in root.findall('./gateways/gateway_item'):
            if item.find('disabled') is None and item.findtext('interface'):
                gateway_ifs.add(item.findtext('interface'))
    for name, intf in sorted(cfg.interfaces.items()):
        if intf.is_group:
            continue
        entry = {'name': name, 'descr': intf.descr, 'device': intf.device, 'enabled': intf.enabled,
                 'wan': intf.is_wan, 'has_gateway': name in gateway_ifs or bool(intf.gateway or intf.gatewayv6),
                 'ipv4_mode': intf.ipaddr if intf.ipaddr in ('dhcp', 'pppoe', 'pptp', 'l2tp', 'ppp') else
                 ('static' if intf.ipaddr else None),
                 'ipv4': [], 'ipv6': []}
        static4 = intf.ipaddr if intf.ipaddr and common_is_ip(intf.ipaddr) else None
        static6 = intf.ipaddrv6 if intf.ipaddrv6 and common_is_ip(intf.ipaddrv6) else None
        if live is not None and intf.device in live:
            entry['ipv4'] = list(live[intf.device]['ipv4'])
            entry['ipv6'] = list(live[intf.device]['ipv6'])
            entry['up'] = live[intf.device]['up']
        else:
            entry['ipv4'] = [static4] if static4 else []
            entry['ipv6'] = [static6] if static6 else []
            entry['up'] = None
        result.append(entry)
    return result


def common_is_ip(value):
    try:
        ipaddress.ip_address(value.split('%')[0])
        return True
    except ValueError:
        return False


def wireguard_ports(cfg):
    root = getattr(cfg, '_root', None)
    ports = set()
    if root is None:
        return ports
    for node in root.findall('./OPNsense/wireguard/server/servers/server'):
        port = (node.findtext('port') or '').strip()
        if (node.findtext('enabled') or '0') == '1' and port.isdigit():
            ports.add(int(port))
    return ports


# ------------------------------------------------------------------ services

def build_services(socks, cfg, pid_paths, path_owner):
    """ group sockets into services: one entry per (service, proto, port) """
    wg_ports = wireguard_ports(cfg)
    grouped = {}
    for sock in socks:
        if sock['kernel']:
            definition = services.kernel_service() if sock['port'] in wg_ports else None
            process = None
        else:
            definition = services.lookup(sock['process'], sock['port'], cfg.admin_ports)
            process = sock['process']
        path = pid_paths.get(sock['pid']) if sock['pid'] else None
        package = path_owner.get(path) if path else None
        base = bool(path) and path.startswith(BASE_PREFIXES) and package is None
        review = None
        if definition is None:
            label = process or 'kernel socket'
            review = ('unknown process "%s"' % process) if process else \
                'kernel socket without a process that does not match a WireGuard instance'
            definition = {'service': 'unknown:%s' % (process or 'kernel'), 'label': label, 'kind': 'unknown',
                          'admin': False, 'components': (), 'threats': list(services.THREATS['unknown'])}
        key = (definition['service'], sock['proto'], sock['port'])
        entry = grouped.get(key)
        if entry is None:
            entry = grouped[key] = {
                'id': common.short_id('svc', *key),
                'service': definition['service'], 'label': definition['label'], 'kind': definition['kind'],
                'admin': bool(definition['admin']) or cfg.admin_ports.get(sock['port']) in ('webgui', 'ssh')
                and sock['proto'] == 'tcp' and definition['kind'] in ('webgui', 'ssh', 'web'),
                'proto': sock['proto'], 'port': sock['port'], 'process': process,
                'user': sock['user'], 'pids': [], 'binary': path, 'package': package,
                'base_system': base, 'components': list(definition.get('components', ())),
                'threats': definition['threats'], 'bind': [], 'families': [], 'scope': 'loopback',
                'needs_review': review,
            }
        if sock['pid'] and sock['pid'] not in entry['pids']:
            entry['pids'].append(sock['pid'])
        if path and not entry['binary']:
            entry['binary'], entry['package'], entry['base_system'] = path, package, base
        bind = {'address': sock['address'], 'family': sock['family'], 'scope': sock['scope']}
        if bind not in entry['bind']:
            entry['bind'].append(bind)
        if sock['family'] not in entry['families']:
            entry['families'].append(sock['family'])
        rank = {'loopback': 0, 'address': 1, 'any': 2}
        if rank[sock['scope']] > rank[entry['scope']]:
            entry['scope'] = sock['scope']
    for entry in grouped.values():
        name, version = common.split_pkg_version(entry['package']) if entry['package'] else (None, None)
        entry['package_name'], entry['package_version'] = name, version
        if name and name not in entry['components']:
            entry['components'].append(name)
        if entry['base_system']:
            entry['components'].append('FreeBSD-')
    return sorted(grouped.values(), key=lambda e: (e['proto'], e['port'], e['service']))


def collect(run, cfg, with_packages=True):
    """ :return: inventory dict (see README "Exposure & vulnerabilities") """
    limitations = []
    inv = {'opnsense': opnsense_version(run), 'freebsd': freebsd_version(run), 'root': common.is_root()}
    if with_packages:
        items, reason = packages(run)
        inv['packages'] = {'count': len(items) if items is not None else None, 'items': items}
        if reason:
            limitations.append(reason)
    socks, reason = sockets(run)
    if reason:
        limitations.append(reason)
        socks = []
    privileged = getattr(run, 'privileged', None)
    if privileged is None:
        privileged = common.is_root() or bool(getattr(run, 'sudo_read', False))
    complete = not reason and bool(privileged)
    if not reason and not complete:
        limitations.append('not running as root: sockstat only shows this user\'s sockets, the service list is '
                           'incomplete (run through configd)')
    pid_paths = binaries(run, [s['pid'] for s in socks])
    if socks and not pid_paths and any(s['pid'] for s in socks):
        limitations.append('procstat could not read the process binaries: packages of services are unknown')
    path_owner = owners(run, pid_paths.values())
    live, reason = live_addresses(run)
    if reason:
        limitations.append(reason + ' (using static addresses from config.xml)')
    inv['interfaces'] = interfaces(cfg, live)
    inv['local_addresses'] = sorted(set(a for i in inv['interfaces'] for a in i['ipv4'] + i['ipv6']))
    inv['sockets'] = socks
    inv['services_complete'] = complete
    inv['services'] = build_services(socks, cfg, pid_paths, path_owner)
    inv['admin_ports'] = {str(k): v for k, v in sorted(cfg.admin_ports.items())}
    inv['limitations'] = limitations
    return inv
