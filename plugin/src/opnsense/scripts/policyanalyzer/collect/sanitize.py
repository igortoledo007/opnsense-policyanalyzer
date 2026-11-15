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

    Sanitization and itemization of config.xml (port of opn.py, superset of its secret list).

    Every leaf whose tag names a secret (password, psk, privkey, token...) becomes "REDACTED:<hmac16>": an
    HMAC-SHA256 with a local random key (/var/db/policyanalyzer/collect/hmac.key, 0600, never leaves the
    firewall), so a diff still sees that a secret changed without storing it or allowing an offline brute
    force.  Flags (0/1/yes/no/...) are never secrets.  <property>name</property><value>..</value> pairs are
    masked by the property name.  Certificates (crt) and public keys stay: they are public.
"""

import copy
import hashlib
import hmac
import json
import os
import re
import secrets

SECRET_EXACT = {
    # opn.py
    'password', 'passwd', 'secret', 'prv', 'privkey', 'privatekey', 'psk',
    'pre-shared-key', 'shared_key', 'tls', 'tlsauth', 'key', 'bindpw', 'ldap_bindpw',
    'radius_secret', 'otp_seed', 'community', 'rocommunity', 'passphrase',
    'smtppassword', 'api_secret', 'token', 'authkey', 'md5password', 'ipsecpsk',
    # extra
    'authpass', 'privpass', 'sharedkey', 'apikey', 'rwcommunity', 'presharedkey', 'pin', 'md5sig',
    'hash', 'bcrypt-hash', 'otp', 'webhook', 'auth_pass',
}
SECRET_PATTERN = re.compile(r'(passw|secret|privkey|private_?key|psk|_key$|token|p12|passphrase|credential)', re.I)
# flags such as ssh/passwordauth=1 match the pattern but are not secrets
NOT_SECRET = {'0', '1', 'yes', 'no', 'on', 'off', 'true', 'false', 'enabled', 'disabled'}
REDACTED_RE = re.compile(r'^REDACTED:[0-9a-f]{16}$')

# (section, XPath, how the item is identified) -- same table as opn.py, so the history reads the same
SECTIONS = [
    ('interface', './interfaces/*', 'tag'),
    ('vlan', './vlans/vlan', 'field:vlanif'),
    ('gateway', './gateways/gateway_item', 'field:name'),
    ('gateway', './OPNsense/Gateways/gateway_item', 'uuid'),
    ('rota', './staticroutes/route', 'uuid'),
    ('alias', './OPNsense/Firewall/Alias/aliases/alias', 'uuid'),
    ('filter.rule', './filter/rule', 'uuid'),
    ('filter.rule_mvc', './OPNsense/Firewall/Filter/rules/rule', 'uuid'),
    ('nat.port_forward', './nat/rule', 'uuid'),
    ('nat.outbound', './nat/outbound/rule', 'uuid'),
    ('nat.outbound_modo', './nat/outbound/mode', 'tag'),
    ('nat.one_to_one', './nat/onetoone', 'uuid'),
    ('dhcp', './dhcpd/*', 'tag'),
    ('dns.unbound_host', './OPNsense/unboundplus/hosts/host', 'uuid'),
    ('usuario', './system/user', 'field:name'),
    ('grupo', './system/group', 'field:name'),
    ('sistema.webgui', './system/webgui', 'tag'),
    ('sistema.ssh', './system/ssh', 'tag'),
    ('sistema.dns', './system/dnsserver', 'index'),
    ('openvpn', './OPNsense/OpenVPN/Instances/Instance', 'uuid'),
    ('openvpn.legado', './openvpn/*', 'field:vpnid'),
    ('wireguard.server', './OPNsense/wireguard/server/servers/server', 'uuid'),
    ('wireguard.peer', './OPNsense/wireguard/client/clients/client', 'uuid'),
    ('ipsec.conexao', './OPNsense/Swanctl/Connections/Connection', 'uuid'),
    ('cron', './OPNsense/cron/jobs/job', 'uuid'),
]


def hmac_key(path):
    """ local random key, created on first use (0600) """
    try:
        with open(path, 'rb') as handle:
            key = handle.read()
        if len(key) >= 32:
            return key
    except OSError:
        pass
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(key)
    return key


def is_secret(tag, value):
    if value.lower() in NOT_SECRET:
        return False
    tag = tag.lower()
    return tag in SECRET_EXACT or bool(SECRET_PATTERN.search(tag))


def sanitize(root, key):
    """ mask secrets in place; :return: (root, number of masked values) """
    count = [0]

    def mask(el):
        text = el.text.strip()
        if REDACTED_RE.match(text):
            return
        el.text = 'REDACTED:%s' % hmac.new(key, text.encode(), hashlib.sha256).hexdigest()[:16]
        count[0] += 1

    for el in root.iter():
        if el.text and el.text.strip() and len(el) == 0 and is_secret(el.tag, el.text.strip()):
            mask(el)
        prop, value = el.find('property'), el.find('value')
        if prop is not None and value is not None and (value.text or '').strip() \
                and SECRET_PATTERN.search(prop.text or ''):
            mask(value)
        # attributes are kept (uuid, version, ...): none of the core models stores a secret in one
    return root, count[0]


def to_dict(el):
    if len(el) == 0:
        return (el.text or '').strip()
    out = {}
    for child in el:
        value = to_dict(child)
        if child.attrib.get('uuid'):
            value = {'@uuid': child.attrib['uuid'], **value} if isinstance(value, dict) else value
        if child.tag in out:
            if not isinstance(out[child.tag], list):
                out[child.tag] = [out[child.tag]]
            out[child.tag].append(value)
        else:
            out[child.tag] = value
    return out


def item(el):
    content = to_dict(el)
    if not isinstance(content, dict):
        content = {'valor': content}
    descr = el.findtext('descr') or el.findtext('description') or el.findtext('name') or ''
    text = json.dumps(content, ensure_ascii=False, sort_keys=True)
    return descr, text, hashlib.sha256(text.encode()).hexdigest()


def _generic(root, items):
    """ what SECTIONS does not map: elements with a uuid -> "mvc:<path>", the rest of each module ->
        ("modulo", <tag>) """
    root = copy.deepcopy(root)
    parents = {child: parent for parent in root.iter() for child in parent}
    for _, xpath, _ in SECTIONS:
        for el in root.findall(xpath):
            parents[el].remove(el)
    for el in root.findall('./revision'):
        root.remove(el)

    def path(el):
        parts = []
        while el in parents:
            el = parents[el]
            parts.append(el.tag)
        return '/'.join(reversed(parts[:-1]))

    for el in [e for e in root.iter() if e.attrib.get('uuid')]:
        if el not in parents or not any(el is c for c in parents[el]):
            continue
        items[('mvc:' + '/'.join(filter(None, [path(el), el.tag])), el.attrib['uuid'])] = item(el)
        parents[el].remove(el)
    modules = [m for m in root if m.tag != 'OPNsense'] + list(root.findall('./OPNsense/*'))
    for mod in modules:
        if len(mod) or (mod.text or '').strip():
            items[('modulo', mod.tag)] = item(mod)


def extract_items(root):
    """ {(section, key): (descr, json, sha256)} """
    items = {}
    for section, xpath, ident in SECTIONS:
        for i, el in enumerate(root.findall(xpath)):
            if ident == 'tag':
                key = el.tag
            elif ident == 'uuid':
                key = el.attrib.get('uuid') or '#%d' % i
            elif ident.startswith('field:'):
                key = el.findtext(ident[6:]) or '#%d' % i
            else:
                key = '#%d' % i
            items[(section, key)] = item(el)
    _generic(root, items)
    return items


def _flatten(value, prefix='', out=None):
    out = {} if out is None else out
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(v, '%s/%s' % (prefix, k) if prefix else k, out)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _flatten(v, '%s[%d]' % (prefix, i), out)
    else:
        out[prefix] = value
    return out


def field_diff(old_json, new_json, limit=40, width=160):
    """ changed leaves between two item JSONs: [{"field", "old", "new"}] (values already sanitized) """
    try:
        old = _flatten(json.loads(old_json)) if old_json else {}
        new = _flatten(json.loads(new_json)) if new_json else {}
    except ValueError:
        return []
    out = []
    for key in sorted(set(old) | set(new)):
        if old.get(key) != new.get(key):
            out.append({'field': key, 'old': None if key not in old else str(old[key])[:width],
                        'new': None if key not in new else str(new[key])[:width]})
            if len(out) >= limit:
                out.append({'field': '...', 'old': None, 'new': None})
                break
    return out
