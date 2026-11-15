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

    Reversible anonymizer.

    Replaces identifying values (IP addresses, hostnames, e-mail and MAC
    addresses, rule descriptions, alias names, ...) by stable placeholder
    tokens before data leaves the firewall, and restores them in the text
    that comes back.  The same value always maps to the same token within
    one Anonymizer instance, so the model can still reason about "the same
    host" without learning which host it is.

    Tokens look like IP4_PRIV_1, IP4_PUB_2, IP6_1, HOST_1, DESC_3, ALIAS_2,
    USER_1, MAC_1.  Prefix lengths are kept (10.0.0.0/8 -> IP4_PRIV_1/8),
    as are loopback/unspecified addresses, interface names, ports and
    protocol names, which carry meaning but no identity.
"""

import copy
import ipaddress
import re

# keys whose (string) values are always replaced as a whole, mapped to the token kind
DEFAULT_SENSITIVE_KEYS = {
    'description': 'DESC',
    'descr': 'DESC',
    'comment': 'DESC',
    'label': 'DESC',
    'hostname': 'HOST',
    'host': 'HOST',
    'fqdn': 'HOST',
    'domain': 'HOST',
    'user': 'USER',
    'username': 'USER',
    'alias': 'ALIAS',
    'aliases': 'ALIAS',
    'category': 'DESC',
    'categories': 'DESC',
}

# values that are never worth hiding (keywords used in rule summaries)
_NEVER = {
    'any', 'none', 'self', '(self)', 'lan', 'wan', 'lo0', 'all', 'true', 'false', 'yes', 'no',
    'in', 'out', 'pass', 'block', 'reject', 'inet', 'inet6', 'tcp', 'udp', 'icmp', 'tcp/udp',
}

# file extensions that look like a TLD but are not hostnames
_NOT_TLD = {
    'json', 'xml', 'conf', 'php', 'py', 'log', 'txt', 'sh', 'inc', 'volt', 'html', 'js', 'css',
    'db', 'csv', 'yaml', 'yml', 'md', 'pem', 'crt', 'key', 'gz', 'tar', 'tgz', 'pid', 'sock',
}

_TOKEN_RE = re.compile(r'\b(?:IP4_(?:PRIV|PUB)|IP6|HOST|DESC|ALIAS|USER|MAC|TERM)_\d+\b')
_IPV4_RE = re.compile(r'(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?(?![\w.]*\w)')
_IPV6_RE = re.compile(r'(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?)(/\d{1,3})?(?![\w:])')
_MAC_RE = re.compile(r'(?<![\w:])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![\w:])')
_EMAIL_RE = re.compile(r'(?<![\w.+-])([\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)')
_FQDN_RE = re.compile(
    r'(?<![\w.@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}))(?![\w-]|\.\w)'
)


def _is_ip(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


class Anonymizer:
    """ reversible, per-request anonymizer """

    def __init__(self, enabled=True, sensitive_keys=None, extra_terms=None):
        """
        :param enabled: when False all methods are the identity function
        :param sensitive_keys: dict key name -> token kind (defaults to DEFAULT_SENSITIVE_KEYS)
        :param extra_terms: iterable of literal strings that must always be hidden (kind TERM)
        """
        self.enabled = bool(enabled)
        self.sensitive_keys = dict(DEFAULT_SENSITIVE_KEYS if sensitive_keys is None else sensitive_keys)
        self._forward = {}      # original value -> token
        self._reverse = {}      # token -> original value
        self._counters = {}
        self._literal_re = None
        for term in (extra_terms or []):
            self._register('TERM', term)

    # ------------------------------------------------------------------ mapping
    @property
    def mapping(self):
        """ token -> original (read only copy, never send or log this) """
        return dict(self._reverse)

    def _register(self, kind, value):
        value = value if isinstance(value, str) else str(value)
        if value in self._forward:
            return self._forward[value]
        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = '%s_%d' % (kind, self._counters[kind])
        self._forward[value] = token
        self._reverse[token] = value
        self._literal_re = None
        return token

    @staticmethod
    def _worth_hiding(value):
        if not isinstance(value, str):
            return False
        stripped = value.strip()
        if len(stripped) < 2 or stripped.lower() in _NEVER:
            return False
        if stripped.isdigit() or _TOKEN_RE.fullmatch(stripped):
            return False
        return True

    # ------------------------------------------------------------------ anonymize
    def anonymize(self, data):
        """ return an anonymized deep copy of data (dict, list, str or scalar) """
        if not self.enabled:
            return copy.deepcopy(data)
        # first pass: register whole values of sensitive keys so they are found inside free text as well
        self._collect(data)
        return self._walk(data)

    def anonymize_text(self, text):
        if not self.enabled or not isinstance(text, str):
            return text
        return self._scrub(text)

    def _collect(self, data, kind=None):
        if isinstance(data, dict):
            for key, value in data.items():
                sub_kind = self.sensitive_keys.get(str(key).lower(), kind if isinstance(value, list) else None)
                self._collect(value, sub_kind)
        elif isinstance(data, list):
            for item in data:
                self._collect(item, kind)
        elif kind is not None and self._worth_hiding(data) and not _is_ip(data.strip()):
            # addresses are left to the regex pass, which keeps the private/public hint
            self._register(kind, data.strip())

    def _walk(self, data):
        if isinstance(data, dict):
            return {key: self._walk(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._walk(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(self._walk(item) for item in data)
        elif isinstance(data, str):
            return self._scrub(data)
        return data

    def _literal_pattern(self):
        if self._literal_re is None:
            kinds = ('DESC', 'ALIAS', 'HOST', 'USER', 'TERM')
            terms = [t for t in self._forward if self._forward[t].split('_')[0] in kinds]
            if terms:
                terms.sort(key=len, reverse=True)
                self._literal_re = re.compile(
                    r'(?<![\w.-])(' + '|'.join(re.escape(t) for t in terms) + r')(?![\w-]|\.\w)'
                )
            else:
                self._literal_re = False
        return self._literal_re

    def _scrub(self, text):
        literal = self._literal_pattern()
        if literal:
            text = literal.sub(lambda m: self._forward[m.group(1)], text)
        text = _EMAIL_RE.sub(lambda m: self._register('USER', m.group(1)), text)
        text = _MAC_RE.sub(lambda m: self._register('MAC', m.group(1).lower()), text)
        text = _IPV4_RE.sub(self._sub_ipv4, text)
        text = _IPV6_RE.sub(self._sub_ipv6, text)
        text = _FQDN_RE.sub(self._sub_fqdn, text)
        return text

    def _sub_ipv4(self, match):
        addr, prefix = match.group(1), match.group(2) or ''
        try:
            ip = ipaddress.IPv4Address(addr)
        except ValueError:
            return match.group(0)
        if ip.is_loopback or ip.is_unspecified or (ip.is_multicast and prefix) or str(ip) == '255.255.255.255':
            return match.group(0)
        kind = 'IP4_PRIV' if (ip.is_private or ip.is_link_local or ip.is_reserved) else 'IP4_PUB'
        return self._register(kind, str(ip)) + prefix

    def _sub_ipv6(self, match):
        addr, prefix = match.group(1), match.group(2) or ''
        if addr.count(':') < 2:
            return match.group(0)
        try:
            ip = ipaddress.IPv6Address(addr.split('%')[0])
        except ValueError:
            return match.group(0)
        if ip.is_loopback or ip.is_unspecified:
            return match.group(0)
        return self._register('IP6', addr.lower()) + prefix

    def _sub_fqdn(self, match):
        name, tld = match.group(1), match.group(2)
        if tld.lower() in _NOT_TLD or _TOKEN_RE.fullmatch(name):
            return match.group(0)
        return self._register('HOST', name.lower())

    # ------------------------------------------------------------------ restore
    def deanonymize(self, text):
        """ replace tokens in text by their original values """
        if not self.enabled or not isinstance(text, str) or not self._reverse:
            return text
        return _TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)


class StreamRestorer:
    """
    Deanonymize a token stream chunk by chunk without splitting a token in
    half: text after the last word boundary is held back until more data
    (or flush()) arrives.
    """

    def __init__(self, anonymizer):
        self._anonymizer = anonymizer
        self._pending = ''

    def feed(self, chunk):
        data = self._pending + (chunk or '')
        cut = max(data.rfind(c) for c in (' ', '\n', '\t', ',', '.', ';', ')', ']', '"', "'"))
        if cut < 0:
            self._pending = data
            return ''
        self._pending = data[cut + 1:]
        return self._anonymizer.deanonymize(data[:cut + 1])

    def flush(self):
        data, self._pending = self._pending, ''
        return self._anonymizer.deanonymize(data)
