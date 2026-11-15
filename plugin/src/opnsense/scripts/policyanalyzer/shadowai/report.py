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

    AI usage report: DNS queries and TLS connections to the catalogue's services, per internal host and
    service, per day; first/last use, "new" (first seen in the last NEW_DAYS days, after a baseline), and
    "known" (expected usage: the Claude Code bridge of the AI provider, the firewall's own local AI runtime, or
    entries of the catalogue's "known" list).

    History: SQLite <db_dir>/shadowai.db keeps the first/last use per host and service and the daily counts
    beyond the retention of the sources (the Unbound database keeps about a week, eve.json a few weeks).
    Each run replaces the days it can see and keeps older ones.
"""

import ipaddress
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from posture.common import day_of, iso_utc, now

from . import sources
from .catalog import Catalog

VERSION = 1
NEW_DAYS = 3
KEEP_DAYS = 400
LOOPBACK = ('127.0.0.1', '::1')
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10',
    '::1/128', 'fc00::/7', 'fe80::/10')]


def _ip_or_none(value):
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def internal(ip):
    """ hosts of the inside: private, loopback, link local, CGNAT (Tailscale), ULA """
    addr = _ip_or_none(ip)
    if addr is None:
        return False
    if os.environ.get('POLICYANALYZER_TEST_INTERNAL'):
        # tests use documentation prefixes for "internal" hosts
        if any(addr in ipaddress.ip_network(n) for n in os.environ['POLICYANALYZER_TEST_INTERNAL'].split(',')):
            return True
    return any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


# ------------------------------------------------------------------------------------------ expected usage

def _config_root(paths):
    try:
        return ET.parse(paths.config).getroot()
    except (OSError, ET.ParseError):
        return None


def firewall_addresses(root):
    result = set(LOOPBACK)
    if root is None:
        return result
    for iface in list(root.find('interfaces') if root.find('interfaces') is not None else []):
        addr = (iface.findtext('ipaddr') or '').strip()
        if _ip_or_none(addr):
            result.add(addr)
    for vip in root.findall('virtualip/vip'):
        addr = (vip.findtext('subnet') or '').strip()
        if _ip_or_none(addr):
            result.add(addr)
    return result


def expected_usage(root, names, catalog):
    """
    rules of expected usage: [{match {ip|net|hostname|mac}, services, reason, source}]
      - the computer that runs the Claude Code bridge of the AI provider (claude-bridge, //policyanalyzer/claudecode/url)
      - the firewall itself: Anthropic when the provider is the Claude API, Ollama/Hugging Face for the local runtime
      - the catalogue's "known" entries
    """
    rules = list(catalog.known)
    if root is None:
        return rules
    pa = root.find('OPNsense/policyanalyzer')
    provider = (pa.findtext('ai/provider') if pa is not None else '') or ''
    enabled = (pa.findtext('ai/enabled') if pa is not None else '') == '1'
    url = (pa.findtext('claudecode/url') if pa is not None else '') or ''
    host = (urlparse(url).hostname or '').lower() if url else ''
    fw = sorted(firewall_addresses(root))
    if host:
        match_ips = []
        if _ip_or_none(host):
            match_ips.append(str(_ip_or_none(host)))
        short = host.split('.')[0]
        for ip, info in names.items():
            name = (info.get('name') or '').lower()
            if name and (name == host or name.split('.')[0] == short):
                match_ips.append(ip)
        active = enabled and provider == 'claudecode'
        reason = 'Claude Code bridge of the Policy Analyzer AI (%s)%s' % (host, '' if active else
                                                                          ', configured but not the active provider')
        for ip in sorted(set(match_ips)):
            rules.append({'match': {'ip': ip}, 'services': ['anthropic'], 'reason': reason,
                          'source': 'policyanalyzer', 'bridge': True})
        if not match_ips:
            rules.append({'match': {'hostname': host}, 'services': ['anthropic'], 'reason': reason,
                          'source': 'policyanalyzer', 'bridge': True})
    for ip in fw:
        if provider == 'claude' and enabled:
            rules.append({'match': {'ip': ip}, 'services': ['anthropic'], 'source': 'policyanalyzer',
                          'reason': 'the firewall calls the Claude API for the Policy Analyzer explanations'})
        rules.append({'match': {'ip': ip}, 'services': ['ollama', 'huggingface'], 'source': 'policyanalyzer',
                      'reason': 'the firewall downloads models for its local AI runtime (Ollama)'})
    return rules


def known_reason(rules, ip, info, service):
    for rule in rules:
        if '*' not in rule['services'] and service not in rule['services']:
            continue
        m = rule['match']
        if m.get('ip') and m['ip'] == ip:
            return rule
        if m.get('net'):
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(m['net'], strict=False):
                    return rule
            except ValueError:
                pass
        name = (info.get('name') or '').lower()
        if m.get('hostname') and name and (name == m['hostname'] or name.split('.')[0] == m['hostname'].split('.')[0]):
            return rule
        if m.get('mac') and (info.get('mac') or '') == m['mac']:
            return rule
    return None


# ------------------------------------------------------------------------------------------ history store

class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or '.', mode=0o750, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS seen (host TEXT, service TEXT, first INTEGER, last INTEGER,
                                             PRIMARY KEY (host, service));
            CREATE TABLE IF NOT EXISTS daily (host TEXT, service TEXT, day TEXT, dns INTEGER, tls INTEGER,
                                              blocked INTEGER, PRIMARY KEY (host, service, day));
        ''')
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass

    def baseline(self, ts):
        row = self.db.execute("SELECT v FROM meta WHERE k = 'baseline'").fetchone()
        if row:
            return int(row[0])
        with self.db:
            self.db.execute("INSERT INTO meta (k, v) VALUES ('baseline', ?)", (str(int(ts)),))
        return None

    def first_seen(self):
        return {(h, s): (f, l) for h, s, f, l in self.db.execute('SELECT host, service, first, last FROM seen')}

    def update(self, pairs, daily, days_covered, ts):
        with self.db:
            for (host, service), (first, last) in pairs.items():
                self.db.execute('INSERT INTO seen (host, service, first, last) VALUES (?, ?, ?, ?) '
                                'ON CONFLICT (host, service) DO UPDATE SET first = min(first, excluded.first), '
                                'last = max(last, excluded.last)', (host, service, first, last))
            if days_covered:
                self.db.executemany('DELETE FROM daily WHERE day = ?', [(d,) for d in days_covered])
            self.db.executemany('INSERT OR REPLACE INTO daily (host, service, day, dns, tls, blocked) '
                                'VALUES (?, ?, ?, ?, ?, ?)',
                                [(h, s, d, v['dns'], v['tls'], v['blocked']) for (h, s, d), v in daily.items()])
            self.db.execute('DELETE FROM daily WHERE day < ?', (day_of(ts - KEEP_DAYS * 86400),))

    def daily_since(self, day):
        return self.db.execute('SELECT host, service, day, dns, tls, blocked FROM daily WHERE day >= ?',
                               (day,)).fetchall()

    def close(self):
        self.db.close()


# ------------------------------------------------------------------------------------------ report

def build(paths, days=7, write=True, catalog=None):
    started = time.monotonic()
    ts = now()
    since = ts - days * 86400
    catalog = catalog or Catalog(local=paths.local_catalog)
    root = _config_root(paths)
    dns, dns_meta = sources.dns_rows(paths, catalog, since, ts + 60)
    tls, tls_meta = sources.tls_events(paths, catalog, since, ts + 60)
    names = sources.host_names(paths, root, sources.unbound_clients(paths))
    rules = expected_usage(root, names, catalog)
    fw_addrs = firewall_addresses(root)

    pairs = {}      # (host, service) -> stats
    daily = {}      # (host, service, day) -> {dns, tls, blocked}
    per_day = {}    # day -> service -> count
    unattributed = 0
    for row in dns:
        hit = catalog.match(row['domain'])
        if hit is None:
            continue
        host = row['client'] or ''
        if not host or not internal(host):
            unattributed += row['queries']
            continue
        sid = hit[0]
        p = pairs.setdefault((host, sid), {'dns': 0, 'tls': 0, 'blocked': 0, 'first': row['first'], 'last': row['last'],
                                           'domains': {}, 'ja4': {}, 'sni': {}})
        p['dns'] += row['queries']
        p['blocked'] += row['blocked']
        p['first'] = min(p['first'], row['first'])
        p['last'] = max(p['last'], row['last'])
        p['domains'][row['domain']] = p['domains'].get(row['domain'], 0) + row['queries']
        day = day_of(row['hour'])
        d = daily.setdefault((host, sid, day), {'dns': 0, 'tls': 0, 'blocked': 0})
        d['dns'] += row['queries']
        d['blocked'] += row['blocked']
        per_day.setdefault(day, {}).setdefault(sid, 0)
        per_day[day][sid] += row['queries']
    for ev in tls:
        host = ev['src'] or ''
        if not internal(host):
            continue
        sid = ev['service']
        p = pairs.setdefault((host, sid), {'dns': 0, 'tls': 0, 'blocked': 0, 'first': ev['time'], 'last': ev['time'],
                                           'domains': {}, 'ja4': {}, 'sni': {}})
        p['tls'] += 1
        p['first'] = min(p['first'], ev['time'])
        p['last'] = max(p['last'], ev['time'])
        if ev.get('ja4'):
            p['ja4'][ev['ja4']] = p['ja4'].get(ev['ja4'], 0) + 1
        p['sni'][ev['sni']] = p['sni'].get(ev['sni'], 0) + 1
        day = day_of(ev['time'])
        d = daily.setdefault((host, sid, day), {'dns': 0, 'tls': 0, 'blocked': 0})
        d['tls'] += 1
        per_day.setdefault(day, {}).setdefault(sid, 0)
        per_day[day][sid] += 1

    history = {}
    baseline = None
    if write:
        store = Store(paths.db('shadowai.db'))
        try:
            baseline = store.baseline(ts)
            history = store.first_seen()
            covered = sorted({k[2] for k in daily})
            store.update({k: (v['first'], v['last']) for k, v in pairs.items()}, daily, covered, ts)
            for host, service, day, dns_n, tls_n, blocked in store.daily_since(day_of(since)):
                if (host, service, day) not in daily:
                    per_day.setdefault(day, {}).setdefault(service, 0)
                    per_day[day][service] += dns_n + tls_n
        finally:
            store.close()

    new_limit = ts - NEW_DAYS * 86400
    hosts = {}
    services = {}
    new_items = []
    for (host, sid), p in pairs.items():
        svc = catalog.services[sid]
        info = names.get(host, {})
        first = min(p['first'], history.get((host, sid), (p['first'], 0))[0])
        is_new = baseline is not None and first >= max(new_limit, baseline)
        rule = known_reason(rules, host, info, sid)
        item = {
            'service': sid, 'name': svc['name'], 'category': svc['category'], 'risk': svc['risk'],
            'dns': p['dns'], 'tls': p['tls'], 'blocked': p['blocked'], 'total': p['dns'] + p['tls'],
            'first': iso_utc(first), 'last': iso_utc(p['last']), 'new': is_new,
            'known': rule is not None, 'known_reason': rule['reason'] if rule else None,
            'bridge': bool(rule and rule.get('bridge')),
            'domains': [d for d, _ in sorted(p['domains'].items(), key=lambda x: -x[1])[:6]],
            'sni': [d for d, _ in sorted(p['sni'].items(), key=lambda x: -x[1])[:6]],
            'ja4': [{'ja4': j, 'count': n} for j, n in sorted(p['ja4'].items(), key=lambda x: -x[1])[:3]],
        }
        h = hosts.setdefault(host, {'ip': host, 'name': info.get('name'), 'mac': info.get('mac'),
                                    'vendor': info.get('vendor'), 'firewall': host in fw_addrs,
                                    'services': [], 'total': 0, 'unexpected': 0, 'new': 0})
        h['services'].append(item)
        h['total'] += item['total']
        h['unexpected'] += 0 if item['known'] else item['total']
        h['new'] += 1 if is_new else 0
        s = services.setdefault(sid, {'id': sid, 'name': svc['name'], 'vendor': svc['vendor'],
                                      'category': svc['category'], 'risk': svc['risk'], 'note': svc.get('note'),
                                      'hosts': 0, 'unexpected_hosts': 0, 'dns': 0, 'tls': 0, 'total': 0,
                                      'first': None, 'last': None, 'new_hosts': 0})
        s['hosts'] += 1
        s['unexpected_hosts'] += 0 if item['known'] else 1
        s['dns'] += p['dns']
        s['tls'] += p['tls']
        s['total'] += item['total']
        s['first'] = min(filter(None, [s['first'], item['first']]))
        s['last'] = max(filter(None, [s['last'], item['last']]))
        s['new_hosts'] += 1 if is_new else 0
        if is_new:
            new_items.append({'host': host, 'name': info.get('name'), 'service': sid, 'service_name': svc['name'],
                              'first': item['first'], 'known': item['known']})
    for h in hosts.values():
        h['services'].sort(key=lambda x: -x['total'])
    host_list = sorted(hosts.values(), key=lambda x: (-x['unexpected'], -x['total']))
    service_list = sorted(services.values(), key=lambda x: -x['total'])
    day_list = []
    for offset in range(days - 1, -1, -1):
        day = day_of(ts - offset * 86400)
        by = per_day.get(day, {})
        day_list.append({'day': day, 'total': sum(by.values()), 'by_service': by})
    return {
        'version': VERSION, 'kind': 'shadowai', 'status': 'ok',
        'generated': iso_utc(ts), 'duration_ms': int((time.monotonic() - started) * 1000),
        'window_days': days, 'new_days': NEW_DAYS, 'baseline': iso_utc(baseline) if baseline else None,
        'sources': {'dns': dns_meta, 'tls': tls_meta},
        'totals': {
            'hosts': len(hosts), 'services': len(services),
            'unexpected_hosts': sum(1 for h in hosts.values() if h['unexpected']),
            'dns': sum(p['dns'] for p in pairs.values()), 'tls': sum(p['tls'] for p in pairs.values()),
            'blocked': sum(p['blocked'] for p in pairs.values()), 'new': len(new_items),
            'unattributed_dns': unattributed,
        },
        'services': service_list,
        'hosts': host_list,
        'daily': day_list,
        'new_items': new_items,
        'expected_rules': [{'match': r['match'], 'services': r['services'], 'reason': r['reason'],
                            'source': r['source']} for r in rules],
        'catalog': {'version': catalog.version, 'local_version': catalog.local_version,
                    'services': len(catalog.services), 'errors': catalog.errors},
    }


def summary(report):
    if not isinstance(report, dict) or report.get('status') != 'ok':
        return {'status': (report or {}).get('status', 'none'), 'message': (report or {}).get('message')}
    return {
        'status': 'ok', 'kind': 'shadowai_summary', 'version': VERSION,
        'generated': report['generated'], 'age_seconds': report.get('age_seconds'),
        'window_days': report['window_days'], 'totals': report['totals'],
        'top_services': [{'id': s['id'], 'name': s['name'], 'hosts': s['hosts'], 'total': s['total'],
                          'unexpected_hosts': s['unexpected_hosts'], 'risk': s['risk']}
                         for s in report['services'][:5]],
        'new_items': report['new_items'][:5],
        'daily': [{'day': d['day'], 'total': d['total']} for d in report['daily']],
        'sources': {k: {'available': v.get('available'), 'complete': v.get('complete', True)}
                    for k, v in report['sources'].items()},
    }


# ------------------------------------------------------------------------------------------ policy proposal

SCOPE_RE = re.compile(r'^(all|host|net)$')


def propose(report, catalog, services, scope='all', value=None, method='unbound'):
    """
    Blocking proposal for the chosen services and scope, with a replay over the report window. Nothing is
    applied: the result is a read-only plan (contract of ai/changes.py) + a textual diff.
    """
    ids = [s for s in services if s in catalog.services]
    if not ids:
        return {'status': 'error', 'message': 'no known service selected'}
    if not SCOPE_RE.match(scope or ''):
        return {'status': 'error', 'message': 'invalid scope'}
    net = None
    if scope in ('host', 'net'):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except (ValueError, TypeError):
            return {'status': 'error', 'message': 'invalid address or network'}
        if scope == 'host' and net.num_addresses != 1:
            return {'status': 'error', 'message': 'a host scope needs one address'}
    if method not in ('unbound', 'alias'):
        return {'status': 'error', 'message': 'invalid method'}
    domains = sorted({d for sid in ids for d in catalog.services[sid]['domains']})
    affected = []
    conflicts = []
    hits = 0
    for host in report.get('hosts', []):
        try:
            in_scope = net is None or ipaddress.ip_address(host['ip']) in net
        except ValueError:
            in_scope = False
        if not in_scope:
            continue
        sel = [s for s in host['services'] if s['service'] in ids]
        if not sel:
            continue
        count = sum(s['total'] for s in sel)
        hits += count
        affected.append({'ip': host['ip'], 'name': host.get('name'), 'events': count,
                         'services': [s['service'] for s in sel]})
        for s in sel:
            if s['known']:
                conflicts.append({'ip': host['ip'], 'name': host.get('name'), 'service': s['name'],
                                  'reason': s['known_reason'], 'bridge': s.get('bridge')})
    scope_text = 'all clients' if net is None else str(net)
    alias_name = 'pa_ai_block_%s' % '_'.join(ids)[:20]
    if method == 'unbound':
        source_nets = '' if net is None else str(net)
        diff = '\n'.join(
            ['# Services › Unbound DNS › Blocklist › + (new policy)',
             '+ Enabled: checked',
             '+ Description: Block AI services (%s) for %s' % (', '.join(catalog.services[i]['name'] for i in ids),
                                                               scope_text),
             '+ Source net(s): %s' % (source_nets or '(empty = every client)'),
             '+ Wildcard domains: %s' % ', '.join(domains),
             '+ Return NXDOMAIN: checked'])
        steps = [
            {'description': 'Create an Unbound blocklist policy with the %d domains as wildcards' % len(domains),
             'command': 'GUI: Services › Unbound DNS › Blocklist (ui/unbound/dnsbl)',
             'effect': 'DNS answers NXDOMAIN for these names to %s' % scope_text},
            {'description': 'Apply the Unbound configuration', 'command': 'GUI: Apply',
             'effect': 'Unbound reloads the blocklists (a few seconds, the cache is kept)'},
        ]
        page = 'ui/unbound/dnsbl'
        warnings = ['DNS blocking is bypassed by clients with their own resolver (DoH in the browser, a VPN); '
                    'combine with a rule that blocks outbound DNS/DoT/DoH except to the firewall.']
        revert = ['Disable or delete the blocklist policy and apply.']
    else:
        diff = '\n'.join(
            ['# Firewall › Aliases › + (new alias)',
             '+ Name: %s' % alias_name,
             '+ Type: Host(s)',
             '+ Content: %s' % ', '.join(domains),
             '+ Description: AI services resolved by the firewall (refreshed every alias resolve interval)',
             '',
             '# Firewall › Rules › [interface of %s] › + (before the pass rules)' % scope_text,
             '+ Action: Block, Quick, Log',
             '+ Source: %s' % ('any' if net is None else scope_text),
             '+ Destination: %s' % alias_name,
             '+ Description: Block AI services (proposal from AI usage)'])
        steps = [
            {'description': 'Create the Host(s) alias %s with the %d domains' % (alias_name, len(domains)),
             'command': 'GUI: Firewall › Aliases (ui/firewall/alias)', 'effect': 'the firewall resolves the names '
             'periodically into a table'},
            {'description': 'Create a block rule from %s to the alias, above the pass rules' % scope_text,
             'command': 'GUI: Firewall › Rules', 'effect': 'connections to the resolved addresses are dropped'},
            {'description': 'Apply the firewall changes', 'command': 'GUI: Apply', 'effect': 'filter reload'},
        ]
        page = 'ui/firewall/alias'
        warnings = ['Address based blocking of services on shared CDNs can block unrelated sites using the same '
                    'addresses, and misses addresses that change between refreshes. Prefer the DNS method.']
        revert = ['Disable or delete the rule and the alias, then apply.']
    for c in conflicts:
        warnings.insert(0, 'Expected usage would break: %s on %s (%s).' % (c['service'], c['name'] or c['ip'],
                                                                           c['reason']))
    return {
        'status': 'ok', 'kind': 'shadowai_proposal', 'readonly': True,
        'services': ids, 'scope': scope_text, 'method': method, 'domains': domains,
        'simulation': {'window_days': report.get('window_days'), 'events_blocked': hits,
                       'hosts_affected': affected, 'expected_conflicts': conflicts},
        'diff': diff, 'page': page,
        'plan': {'status': 'ok', 'steps': steps, 'warnings': warnings, 'irreversible': [], 'revert': revert,
                 'risk': 'medium' if conflicts else 'low', 'requires_confirmation': True,
                 'message': 'Proposal only: nothing is applied from here. Replay over the last %s days: %d '
                            'DNS queries/TLS connections from %d host(s) would have been blocked.' %
                            (report.get('window_days'), hits, len(affected))},
    }
