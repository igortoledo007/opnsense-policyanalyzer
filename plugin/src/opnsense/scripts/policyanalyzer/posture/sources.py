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

    Read-only data collection for the posture checks: config.xml accessors and runtime probes (sysctl,
    sockstat, pfctl, firmware status, SSH host keys, certificates, the last Policy Analyzer report).

    Probes run through a Runner (subprocess, fixed argument lists, short timeouts); the tests pass a fake
    one. A probe that fails returns None and the checks that need it report "n.a." instead of guessing.
"""

import base64
import datetime
import os
import re
import struct
import subprocess
import xml.etree.ElementTree as ET

from .common import load_json

WAN_DYNAMIC = ('dhcp', 'pppoe', 'pptp', 'l2tp', 'dhcp6', 'slaac')


class Runner:
    """ runs a fixed command line, returns stdout (str) or None """

    def __call__(self, argv, timeout=10):
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode != 0 and not out.stdout:
            return None
        return out.stdout


def _text(node):
    return (node.text or '').strip() if node is not None else ''


class Context:
    """ everything the checks look at, loaded lazily and only once """

    def __init__(self, paths, runner=None):
        self.paths = paths
        self.run = runner or Runner()
        self._cache = {}
        try:
            self.root = ET.parse(paths.config).getroot()
        except (OSError, ET.ParseError):
            self.root = None

    # ------------------------------------------------------------------ config.xml
    def node(self, path):
        return self.root.find(path) if self.root is not None else None

    def nodes(self, path):
        return self.root.findall(path) if self.root is not None else []

    def text(self, path, default=''):
        node = self.node(path)
        return _text(node) if node is not None else default

    def has(self, path):
        """ legacy booleans: present (any value) means set """
        return self.node(path) is not None

    def flag(self, path):
        """ MVC booleans: "1" means set """
        return self.text(path) == '1'

    def csv(self, path):
        return [x.strip() for x in self.text(path).split(',') if x.strip()]

    def _memo(self, key, factory):
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]

    @property
    def interfaces(self):
        """ {name: {descr, if, enabled, ipaddr, ipaddrv6, gateway, blockpriv, blockbogons}} """
        def build():
            result = {}
            node = self.node('interfaces')
            for item in (list(node) if node is not None else []):
                if item.findtext('type') == 'group' or item.tag == 'lo0':
                    continue
                result[item.tag] = {
                    'descr': _text(item.find('descr')) or item.tag.upper(),
                    'if': _text(item.find('if')),
                    'enabled': item.find('enable') is not None and _text(item.find('enable')) != '0',
                    'ipaddr': _text(item.find('ipaddr')),
                    'ipaddrv6': _text(item.find('ipaddrv6')),
                    'gateway': _text(item.find('gateway')),
                    'gatewayv6': _text(item.find('gatewayv6')),
                    'blockpriv': item.find('blockpriv') is not None,
                    'blockbogons': item.find('blockbogons') is not None,
                    'virtual': item.find('virtual') is not None or item.find('internal_dynamic') is not None,
                }
            return result
        return self._memo('interfaces', build)

    @property
    def wan_interfaces(self):
        """ wan + interfaces with a gateway or a dynamic uplink (same rule as the AI brief) """
        def build():
            result = []
            for name, info in self.interfaces.items():
                if not info['enabled'] and name != 'wan':
                    continue
                if name == 'wan' or info['gateway'] or info['gatewayv6'] or info['ipaddr'] in WAN_DYNAMIC \
                        or info['ipaddrv6'] in WAN_DYNAMIC:
                    result.append(name)
            return result
        return self._memo('wan', build)

    def interface_label(self, name):
        info = self.interfaces.get(name)
        return '%s (%s)' % (info['descr'], name) if info else name

    @property
    def users(self):
        def build():
            groups = {}
            for group in self.nodes('system/group'):
                members = [m.strip() for m in _text(group.find('member')).split(',') if m.strip()]
                for extra in group.findall('member')[1:]:
                    members += [m.strip() for m in _text(extra).split(',') if m.strip()]
                privs = [_text(p) for p in group.findall('priv')]
                groups[_text(group.find('name'))] = {'members': set(members), 'privs': set(privs),
                                                      'gid': _text(group.find('gid'))}
            users = []
            for user in self.nodes('system/user'):
                uid = _text(user.find('uid'))
                name = _text(user.find('name'))
                privs = set(_text(p) for p in user.findall('priv') if _text(p))
                member_of = sorted(g for g, info in groups.items() if uid in info['members'])
                admin = 'page-all' in privs or any('page-all' in groups[g]['privs'] for g in member_of) or \
                    'admins' in member_of
                keys_raw = _text(user.find('authorizedkeys'))
                try:
                    keys = base64.b64decode(keys_raw).decode('utf-8', 'replace') if keys_raw else ''
                except (ValueError, TypeError):
                    keys = keys_raw
                users.append({
                    'name': name, 'uid': uid,
                    'disabled': _text(user.find('disabled')) == '1',
                    'expires': _text(user.find('expires')),
                    'has_password': bool(_text(user.find('password'))),
                    'has_otp': bool(_text(user.find('otp_seed'))),
                    'has_apikeys': bool(_text(user.find('apikeys'))) or user.find('apikeys/item') is not None,
                    'shell': _text(user.find('shell')),
                    'authorized_keys': [k.strip() for k in keys.splitlines() if k.strip() and
                                        not k.strip().startswith('#')],
                    'groups': member_of,
                    'admin': admin,
                })
            return users
        return self._memo('users', build)

    @property
    def mvc_rules(self):
        def build():
            rules = []
            for rule in self.nodes('OPNsense/Firewall/Filter/rules/rule'):
                fields = {c.tag: _text(c) for c in rule}
                fields['uuid'] = rule.get('uuid', '')
                rules.append(fields)
            for idx, rule in enumerate(self.nodes('filter/rule')):
                fields = {'uuid': rule.get('uuid', '') or 'legacy-%d' % idx, 'legacy': '1',
                          'enabled': '0' if rule.find('disabled') is not None else '1',
                          'action': _text(rule.find('type')) or 'pass',
                          'interface': _text(rule.find('interface')),
                          'ipprotocol': _text(rule.find('ipprotocol')) or 'inet',
                          'log': '1' if rule.find('log') is not None else '0',
                          'description': _text(rule.find('descr')),
                          'direction': _text(rule.find('direction')) or 'in'}
                rules.append(fields)
            return rules
        return self._memo('rules', build)

    def certificate(self, refid):
        for cert in self.nodes('cert') + self.nodes('ca'):
            if _text(cert.find('refid')) == refid:
                return cert
        return None

    # ------------------------------------------------------------------ runtime probes
    def sysctl(self, names):
        """ {name: value} for the names the kernel knows (missing names are left out) """
        def build():
            out = self.run(['/sbin/sysctl', '-e'] + list(names), timeout=5)
            result = {}
            for line in (out or '').splitlines():
                if '=' in line:
                    key, value = line.split('=', 1)
                    result[key.strip()] = value.strip()
            return result if out is not None else None
        return self._memo('sysctl:' + ','.join(names), build)

    @property
    def listeners(self):
        """ [{command, proto, address, port}] of listening sockets (sockstat -46lq), None when unavailable """
        def build():
            out = self.run(['/usr/bin/sockstat', '-46lq'], timeout=10)
            if out is None:
                return None
            result = []
            seen = set()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue
                command, proto, local = parts[1], parts[4], parts[5]
                if proto.startswith('div'):
                    continue
                match = re.match(r'^(.*)[:.](\d+|\*)$', local)
                if not match:
                    continue
                address, port = match.group(1), match.group(2)
                key = (command, proto, address, port)
                if key in seen:
                    continue
                seen.add(key)
                result.append({'command': command, 'proto': proto, 'address': address.strip('[]'),
                               'port': int(port) if port.isdigit() else 0})
            return result
        return self._memo('listeners', build)

    @property
    def pf_limits(self):
        def build():
            limits = self.run(['/sbin/pfctl', '-sm'], timeout=5)
            info = self.run(['/sbin/pfctl', '-si'], timeout=5)
            if limits is None or info is None:
                return None
            hard = None
            for line in limits.splitlines():
                match = re.match(r'^states\s+hard limit\s+(\d+)', line.strip())
                if match:
                    hard = int(match.group(1))
            current = None
            for line in info.splitlines():
                match = re.match(r'^current entries\s+(\d+)', line.strip())
                if match:
                    current = int(match.group(1))
            return {'states_limit': hard, 'states_current': current}
        return self._memo('pf', build)

    @property
    def firmware(self):
        return self._memo('firmware', lambda: load_json(self.paths.firmware))

    @property
    def report(self):
        return self._memo('report', lambda: load_json(self.paths.report))

    @property
    def exposure(self):
        return self._memo('exposure', lambda: load_json(self.paths.exposure))

    def file_mtime(self, path):
        try:
            return os.path.getmtime(path)
        except OSError:
            return None

    @property
    def ssh_host_keys(self):
        """ [{file, type, bits}] from the public host keys """
        def build():
            result = []
            try:
                names = sorted(os.listdir(self.paths.sshd_dir))
            except OSError:
                return None
            for name in names:
                if not name.endswith('.pub'):
                    continue
                try:
                    with open(os.path.join(self.paths.sshd_dir, name)) as handle:
                        line = handle.readline().strip()
                except OSError:
                    continue
                info = ssh_key_info(line)
                if info:
                    info['file'] = name
                    result.append(info)
            return result
        return self._memo('hostkeys', build)

    def unbound_forwarders(self):
        """ forward-addr lines of the generated Unbound configuration (DoT / dnscrypt-proxy) """
        result = []
        try:
            names = os.listdir(self.paths.unbound_conf_dir)
        except OSError:
            return None
        for name in names:
            if not name.endswith('.conf'):
                continue
            try:
                with open(os.path.join(self.paths.unbound_conf_dir, name)) as handle:
                    for line in handle:
                        match = re.match(r'^\s*forward-addr:\s*(\S+)', line)
                        if match:
                            result.append(match.group(1))
            except OSError:
                continue
        return result


# ---------------------------------------------------------------------------------- key / certificate parsing

def ssh_key_info(line):
    """ type and size of an OpenSSH public key line ("ssh-rsa AAAA... comment") """
    parts = line.split()
    idx = 0
    # authorized_keys lines may start with options (from="...",no-pty ...)
    while idx < len(parts) and not re.match(r'^(ssh-|ecdsa-|sk-)', parts[idx]):
        idx += 1
    if idx + 1 >= len(parts):
        return None
    ktype, blob = parts[idx], parts[idx + 1]
    bits = None
    if ktype == 'ssh-rsa':
        try:
            raw = base64.b64decode(blob)
            pos = 0
            fields = []
            for _ in range(3):
                length = struct.unpack('>I', raw[pos:pos + 4])[0]
                fields.append(raw[pos + 4:pos + 4 + length])
                pos += 4 + length
            bits = int.from_bytes(fields[2], 'big').bit_length()
        except (ValueError, struct.error, IndexError):
            bits = None
    elif ktype == 'ssh-dss':
        bits = 1024
    elif ktype.startswith('ecdsa-sha2-nistp'):
        bits = int(ktype[len('ecdsa-sha2-nistp'):]) if ktype[len('ecdsa-sha2-nistp'):].isdigit() else None
    elif 'ed25519' in ktype:
        bits = 256
    return {'type': ktype, 'bits': bits}


def certificate_info(crt_b64):
    """
    {subject, issuer, not_after (epoch), self_signed, key_type, key_bits, staging} of a certificate stored in
    config.xml (base64 of the PEM text). None when it can not be parsed.
    """
    try:
        pem = base64.b64decode(crt_b64).decode('ascii', 'replace')
    except (ValueError, TypeError):
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    except ImportError:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode('ascii', 'replace'))
    except ValueError:
        return None
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = 'RSA', key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = 'EC', key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, bits = 'DSA', key.key_size
    else:
        key_type, bits = type(key).__name__.replace('PublicKey', ''), None
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    try:
        signature = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001 - unsupported algorithms raise library specific errors
        signature = None
    return {
        'subject': subject,
        'issuer': issuer,
        'not_after': int(not_after.timestamp()),
        'self_signed': subject == issuer,
        'key_type': key_type,
        'key_bits': bits,
        'signature_hash': signature,
        'staging': 'STAGING' in issuer.upper() or '(STAGING)' in issuer.upper() or 'FAKE LE' in issuer.upper(),
    }
