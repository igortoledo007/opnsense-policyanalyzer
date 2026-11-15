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

    Aliases collector (read only): which aliases hold an address, and what a named alias contains.

    Host and network aliases are resolved from config.xml (nested aliases included); aliases whose content
    only exists at run time (URL tables, GeoIP, ASN, external, dynamic IPv6, FQDN hosts) are tested
    against their pf table with "pfctl -t <alias> -T test <address>", which only reads the table.
"""

import ipaddress
import re
import subprocess

from engine.config import FirewallConfig

from ..common import clean_text

STATIC_TYPES = ('host', 'network', 'networkgroup')
TABLE_TYPES = ('urltable', 'url', 'geoip', 'external', 'asn', 'dynipv6host', 'host', 'network', 'authgroup')
MAX_TABLE_TESTS = 40
NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,64}$')


def _config(paths):
    try:
        return FirewallConfig(paths.config)
    except (OSError, SyntaxError):
        return None


def _static_contains(cfg, alias, ip, depth=0):
    """ True/False when the config answers it, None when the alias needs its pf table """
    if depth > 4:
        return None
    unknown = False
    for item in alias.content:
        item = item.strip()
        if not item:
            continue
        if item in cfg.aliases and item != alias.name:
            sub = _static_contains(cfg, cfg.aliases[item], ip, depth + 1)
            if sub:
                return True
            if sub is None:
                unknown = True
            continue
        if '-' in item and not item.startswith('!'):
            lo, _, hi = item.partition('-')
            try:
                if ipaddress.ip_address(lo) <= ip <= ipaddress.ip_address(hi):
                    return True
                continue
            except (ValueError, TypeError):
                pass
        try:
            net = ipaddress.ip_network(item.lstrip('!'), strict=False)
        except ValueError:
            unknown = True          # FQDN or something only pf knows
            continue
        if net.version == ip.version and ip in net and not item.startswith('!'):
            return True
    return None if unknown else False


def _pf_test(paths, name, ip, timeout):
    try:
        proc = subprocess.run([paths.pfctl, '-t', name, '-T', 'test', str(ip)], capture_output=True, text=True,
                              timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if 'Table does not exist' in proc.stderr or 'does not exist' in proc.stderr:
        return None
    return proc.returncode == 0


def member_of(paths, address, budget):
    cfg = _config(paths)
    if cfg is None:
        return {'available': False, 'message': 'unable to read the configuration'}
    try:
        ip = ipaddress.ip_address(str(address).split('/')[0])
    except ValueError:
        return {'available': False, 'message': 'invalid address'}
    found = []
    tests = 0
    complete = True
    for name, alias in sorted(cfg.aliases.items()):
        if alias.builtin and name.startswith('__'):
            continue
        answer = None
        how = 'config'
        if alias.type in STATIC_TYPES:
            answer = _static_contains(cfg, alias, ip)
        if answer is None and (alias.type in TABLE_TYPES or alias.builtin):
            if tests >= MAX_TABLE_TESTS or budget.expired():
                complete = False
                continue
            tests += 1
            answer = _pf_test(paths, name, ip, timeout=min(2.0, max(0.2, budget.left())))
            how = 'pf table'
        if answer:
            found.append({'alias': name, 'type': alias.type, 'description': clean_text(alias.description, 80),
                          'how': how, 'enabled': alias.enabled})
    return {
        'available': True,
        'source': 'config.xml aliases + pf tables',
        'address': str(ip),
        'member_of': found,
        'pf_tables_tested': tests,
        'complete': complete,
    }


def describe(paths, names, entries=10):
    cfg = _config(paths)
    if cfg is None:
        return []
    out = []
    lowered = {n.lower(): n for n in cfg.aliases}
    for raw in names:
        name = lowered.get(str(raw).lower())
        if not name:
            continue
        alias = cfg.aliases[name]
        out.append({'alias': name, 'type': alias.type, 'description': clean_text(alias.description, 80),
                    'enabled': alias.enabled, 'entries': len(alias.content),
                    'content_sample': [clean_text(c, 80) for c in alias.content[:entries]]})
    return out


def alias_names(paths):
    cfg = _config(paths)
    if cfg is None:
        return []
    return [n for n, a in cfg.aliases.items() if not n.startswith('__')]
