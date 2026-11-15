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

    Exposure report: links vulnerable packages to listening services, produces findings in the Policy
    Analyzer contract format (CONTRACT.md, "Findings") and the summary consumed by the Max Cyber HUD.

    Finding types: exposed_vulnerable_service, known_exploited_vuln, outdated_component,
    admin_exposed_to_internet, service_listening_all_interfaces, needs_review.
    Every recommendation is a suggestion: nothing is applied.
"""

import json
import os
import tempfile
import time

from . import common, services as svcmap

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
STALE_VUXML_DAYS = 7
VPN_KINDS = ('vpn_wireguard', 'vpn_openvpn', 'vpn_ipsec')
OUTPUT_FILE = os.path.join(common.DB_DIR, 'exposure.json')
# reverse dependencies that do not mean "the service runs this code" (everything depends on them)
DEPENDENCY_IGNORE = ('opnsense', 'opnsense-update')
# interpreters: depending on them (helper scripts, bindings) does not put their CVEs in the network path of a daemon
INTERPRETERS = ('python3', 'perl5', 'ruby', 'tcl', 'lua')


class Builder(object):
    def __init__(self):
        self.findings = []
        self.seen = set()

    def add(self, ftype, severity, key, title, detail, recommendation, rules=(), evidence=None):
        """ same key twice (one service on several ports, e.g. the GUI on 80 and 443): merged into one finding
            with every port in evidence.ports and the highest severity """
        fid = common.short_id(ftype, key)
        evidence = evidence or {}
        if fid in self.seen:
            item = next(f for f in self.findings if f['id'] == fid)
            ports = item['evidence'].setdefault('ports', [item['evidence'].get('port')])
            if evidence.get('port') not in ports:
                ports.append(evidence.get('port'))
            if SEVERITY_ORDER[severity] < SEVERITY_ORDER[item['severity']]:
                item.update(severity=severity, detail=detail, recommendation=recommendation)
                item['evidence'].update({k: v for k, v in evidence.items() if k != 'port'})
            known = {r['uuid'] for r in item['rules']}
            item['rules'].extend(_rule_ref(r) for r in rules if r['uuid'] not in known)
            return
        self.seen.add(fid)
        self.findings.append({'id': fid, 'type': ftype, 'severity': severity, 'title': title, 'detail': detail,
                              'recommendation': recommendation, 'rules': [_rule_ref(r) for r in rules],
                              'aliases': [], 'evidence': evidence or {}})


def _rule_ref(rule):
    return {k: v for k, v in rule.items() if k not in ('level', 'notes')}


def _where(service):
    return '%s/%d' % (service['proto'], service['port'])


def _max_cvss(records):
    scores = [r['cvss'] for r in records if r.get('cvss') is not None]
    return max(scores) if scores else None


def link_packages(service, packages):
    """ [(package, link)] where link is 'direct' or 'dependency' """
    comps = service.get('components') or []
    dep_comps = [c for c in comps if c not in DEPENDENCY_IGNORE]
    out = []
    for pkg in packages:
        if not pkg['cves']:
            continue
        if svcmap.component_match(pkg['name'], comps):
            out.append((pkg, 'direct'))
        elif dep_comps and not pkg['name'].startswith(INTERPRETERS) and \
                any(svcmap.component_match(r, dep_comps) for r in pkg.get('reverse_deps') or []):
            out.append((pkg, 'dependency'))
    return out


def suggested_block(service, wan):
    return {'action': 'block', 'quick': True, 'interface': wan, 'direction': 'in',
            'ipprotocol': 'inet46' if len(service['families']) > 1 else
            ('inet6' if service['families'] == [6] else 'inet'),
            'protocol': service['proto'].upper(), 'source': 'any', 'destination': '(self)',
            'destination_port': str(service['port']),
            'description': 'Isolate %s from the internet (suggested by Policy Analyzer)' % service['label']}


def _isolate_text(service, wans):
    rules = service.get('rules') or []
    text = ('Isolate it from the internet: on %s add a quick block rule "in proto %s from any to (self) port %d" '
            'above the pass rule(s) %s, or restrict their source to a trusted alias / use the VPN.'
            % (', '.join(wans) or 'the WAN', service['proto'], service['port'],
               ', '.join(r['uuid'] for r in rules) or '(none found)'))
    if service['scope'] == 'any':
        text += ' Also bind the service only to the interfaces that need it.'
    return text


def _update_text(pkg, available=None):
    """ available: {package: newer version in the repository} or None when unknown """
    if available is not None and pkg['name'] in available:
        return 'Update %s to %s (System > Firmware > Updates).' % (pkg['name'], available[pkg['name']])
    if pkg.get('fixed_in') and available is not None:
        return ('%s is fixed upstream in %s, but the OPNsense repository does not offer it yet: keep it '
                'unexposed and update as soon as it is published.' % (pkg['name'], ' / '.join(pkg['fixed_in'])))
    if pkg.get('fixed_in'):
        return 'Update %s to %s or later (System > Firmware > Updates).' % (pkg['name'], ' / '.join(pkg['fixed_in']))
    if pkg.get('fix_available') is False:
        return 'No fixed version of %s is published yet: reduce exposure until the update arrives.' % pkg['name']
    return 'Check System > Firmware > Updates for a newer %s.' % pkg['name']


def _suricata_text(records, sids):
    parts = []
    for rec in records:
        for sid in sids.get(rec['id'], []):
            parts.append('sid %d (%s, %s)' % (sid['sid'], sid['file'], 'enabled' if sid['enabled'] else 'disabled'))
    if not parts:
        return ''
    return ' Suricata rules reference these CVEs: %s; enable them in IPS mode on the WAN (suggestion only).' \
        % ', '.join(parts[:5])


def build(inventory, vulns, outdated=None, outdated_reason=None, suricata=None, wan=(), started=None):
    suricata = suricata or {}
    services = inventory.get('services') or []
    packages = (vulns or {}).get('packages') or []
    b = Builder()
    linked = set()
    wans = list(wan)
    available = None if outdated is None else {o['name']: o['available'] for o in outdated}

    for svc in services:
        reach = svc.get('internet_reachable', 'no')
        reachable = reach in ('yes', 'maybe')
        svc_cves = set()
        svc_kev = set()
        for pkg, link in link_packages(svc, packages):
            linked.add(pkg['name'])
            records = pkg['cves']
            svc_cves.update(r['id'] for r in records)
            kev = [r['id'] for r in records if r.get('kev')]
            svc_kev.update(kev)
            top = _max_cvss(records)
            if reachable:
                severe = bool(kev) or (top is not None and top >= 9.0)
                severity = 'high' if severe and (reach == 'yes' or kev) else 'medium'
                if link == 'dependency' and not kev:
                    severity = 'medium'
            else:
                severity = 'low'
            rec = _update_text(pkg, available)
            if reachable:
                rec = rec + ' ' + _isolate_text(svc, wans)
            rec += _suricata_text(records, suricata)
            b.add('exposed_vulnerable_service', severity, '%s|%s|%s' % (svc['service'], pkg['name'], link),
                  'Vulnerable component in a %s service' % ('reachable' if reachable else 'listening'),
                  '%s (%s) %s %s %s with %d known vulnerabilit%s%s; internet reachable: %s.'
                  % (svc['label'], _where(svc), 'runs' if link == 'direct' else 'depends on', pkg['name'],
                     pkg['version'], len(records), 'y' if len(records) == 1 else 'ies',
                     (', highest CVSS %.1f' % top) if top is not None else '', reach),
                  rec, rules=svc.get('rules') or [],
                  evidence={'service': svc['service'], 'port': svc['port'], 'proto': svc['proto'],
                            'package': pkg['name'], 'version': pkg['version'], 'link': link,
                            'internet_reachable': reach, 'cves': [r['id'] for r in records], 'kev': kev,
                            'max_cvss': top, 'fixed_in': pkg.get('fixed_in'),
                            'suricata': {c: suricata[c] for c in (r['id'] for r in records) if c in suricata}})
        svc['cves'] = len(svc_cves)
        svc['kev'] = len(svc_kev)

        if svc['admin'] and reachable:
            severity = 'high' if reach == 'yes' else ('medium' if svc.get('source_restricted') else 'high')
            b.add('admin_exposed_to_internet', severity, svc['id'],
                  'Management service reachable from the internet',
                  '%s (%s) can be reached from the internet (%s) through the rule(s) %s. This complements the '
                  'wan_exposed finding of the rule analysis with what really listens.'
                  % (svc['label'], _where(svc), reach, ', '.join(r['uuid'] for r in svc.get('rules') or [])),
                  _isolate_text(svc, wans) + ' Restrict the listen interfaces (System > Settings > Administration) '
                  'and reach management through the VPN.',
                  rules=svc.get('rules') or [],
                  evidence={'service': svc['service'], 'port': svc['port'], 'proto': svc['proto'],
                            'internet_reachable': reach, 'source_restricted': svc.get('source_restricted'),
                            'suggested_rule': [suggested_block(svc, w) for w in wans[:3]],
                            'related_type': 'wan_exposed'})

        if svc['scope'] == 'any' and not svc['needs_review']:
            b.add('service_listening_all_interfaces', 'low', svc['id'],
                  'Service listens on all interfaces',
                  '%s (%s) is bound to the wildcard address, so it accepts connections on every interface '
                  'unless a rule blocks them; internet reachable: %s.' % (svc['label'], _where(svc), reach),
                  ('WireGuard binds every address by design; keep only the WAN rule for its port.'
                   if svc['kind'] == 'vpn_wireguard' else
                   'Bind %s only to the interfaces that need it (its listen interfaces setting).' % svc['label']),
                  rules=svc.get('rules') or [],
                  evidence={'service': svc['service'], 'port': svc['port'], 'proto': svc['proto'],
                            'families': svc['families'], 'internet_reachable': reach})

        if svc['needs_review']:
            b.add('needs_review', 'info', 'svc|%s' % svc['id'], 'Unknown listening service',
                  'A socket on %s is not mapped to a known service: %s; internet reachable: %s.'
                  % (_where(svc), svc['needs_review'], reach),
                  'Identify the process (sockstat -l, procstat -b <pid>) and either stop it, restrict its '
                  'listen address, or add it to exposure/services.py.',
                  rules=svc.get('rules') or [],
                  evidence={'reason': svc['needs_review'], 'process': svc['process'], 'binary': svc['binary'],
                            'port': svc['port'], 'proto': svc['proto'], 'internet_reachable': reach})
        elif svc['process'] and not svc['package'] and not svc['base_system'] and inventory.get('services_complete'):
            b.add('needs_review', 'info', 'pkg|%s' % svc['id'], 'Service binary not owned by a package',
                  '%s (%s) runs %s, which no installed package owns, so its vulnerabilities can not be '
                  'matched.' % (svc['label'], _where(svc), svc['binary'] or 'an unknown binary'),
                  'Check where the binary comes from (pkg which, freebsd-version) before trusting the result.',
                  evidence={'reason': 'binary without package', 'binary': svc['binary'], 'service': svc['service']})

    # vulnerable packages that no listening service runs: real but not exposed
    for pkg in packages:
        if not pkg['cves'] or pkg['name'] in linked:
            continue
        top = _max_cvss(pkg['cves'])
        b.add('exposed_vulnerable_service', 'low', 'nosvc|%s' % pkg['name'],
              'Vulnerable package not exposed by a listening service',
              '%s %s has %d known vulnerabilit%s%s; no listening service runs it directly, so it is not '
              'reachable from the network as far as this analysis can tell.'
              % (pkg['name'], pkg['version'], len(pkg['cves']), 'y' if len(pkg['cves']) == 1 else 'ies',
                 (', highest CVSS %.1f' % top) if top is not None else ''),
              _update_text(pkg, available) + _suricata_text(pkg['cves'], suricata),
              evidence={'package': pkg['name'], 'version': pkg['version'], 'link': 'none',
                        'internet_reachable': 'no', 'cves': [r['id'] for r in pkg['cves']], 'max_cvss': top,
                        'fixed_in': pkg.get('fixed_in'), 'reverse_deps': len(pkg.get('reverse_deps') or [])})
        for rec in pkg['cves']:
            if rec.get('affected') is None and rec.get('ghsa'):
                b.add('needs_review', 'info', 'ghsa|%s' % rec['ghsa'], 'OPNsense advisory needs a manual check',
                      'Advisory %s (%s) could not be compared with the installed version %s.'
                      % (rec['ghsa'], rec.get('summary') or '', pkg['version']),
                      'Read the advisory and compare the affected versions by hand.',
                      evidence={'reason': 'version range not understood', 'advisory': rec['ghsa']})

    # known exploited vulnerabilities (any package, reachable or not)
    for pkg in packages:
        for rec in pkg['cves']:
            if not rec.get('kev'):
                continue
            exposed = [s for s in services if s.get('internet_reachable') in ('yes', 'maybe') and
                       any(p['name'] == pkg['name'] for p, _l in link_packages(s, [pkg]))]
            b.add('known_exploited_vuln', 'high', '%s|%s' % (pkg['name'], rec['id']),
                  'Known exploited vulnerability installed',
                  '%s (%s %s) is in the CISA KEV catalogue (added %s%s).%s'
                  % (rec['id'], pkg['name'], pkg['version'], rec.get('kev_date_added') or '?',
                     ', used in ransomware campaigns' if rec.get('kev_ransomware') else '',
                     (' Reachable through: %s.' % ', '.join('%s %s' % (s['label'], _where(s)) for s in exposed))
                     if exposed else ''),
                  _update_text(pkg, available) + (' ' + rec['kev_action'] if rec.get('kev_action') else '') +
                  _suricata_text([rec], suricata),
                  evidence={'cve': rec['id'], 'package': pkg['name'], 'version': pkg['version'],
                            'kev_date_added': rec.get('kev_date_added'), 'epss': rec.get('epss'),
                            'reachable_services': [s['id'] for s in exposed], 'provenance': rec.get('provenance')})

    # outdated components
    vulnerable = {p['name'] for p in packages if p['cves']}
    components = set()
    for svc in services:
        components.update(svc.get('components') or [])
    for item in outdated or []:
        relevant = item['name'] in vulnerable or svcmap.component_match(item['name'], list(components))
        b.add('outdated_component', 'low' if relevant else 'info', item['name'], 'Newer version available',
              '%s %s can be updated to %s%s.' % (item['name'], item['version'], item['available'],
                                                  ' (it has known vulnerabilities)' if item['name'] in vulnerable
                                                  else (' (used by a listening service)' if relevant else '')),
              'Update through System > Firmware > Updates (read the release notes first).',
              evidence={'package': item['name'], 'version': item['version'], 'available': item['available'],
                        'vulnerable': item['name'] in vulnerable})

    meta = (vulns or {}).get('meta') or {}
    age = meta.get('database_age_days')
    if meta.get('error'):
        b.add('needs_review', 'info', 'vuxml-error', 'Vulnerability database could not be read',
              'pkg audit failed: %s.' % meta['error'],
              'Download the database (System > Firmware > Run an audit, or "pkg audit -F" as root).',
              evidence={'reason': 'pkg audit failed'})
    elif age is not None and age > STALE_VUXML_DAYS:
        b.add('needs_review', 'info', 'vuxml-stale', 'Vulnerability database is old',
              'The VuXML database is %.0f days old; newer advisories are not considered.' % age,
              'Refresh it (run the report with "refresh" or System > Firmware > Run an audit).',
              evidence={'reason': 'stale database', 'age_days': age})
    if not inventory.get('services_complete'):
        b.add('needs_review', 'info', 'inventory-partial', 'Listening services list is partial',
              'The probe did not run as root, so sockets of other users are missing: %s.'
              % ('; '.join(inventory.get('limitations') or []) or 'unknown reason'),
              'Run it through configd (configctl policyanalyzer exposure_report).',
              evidence={'reason': 'not root'})
    if outdated_reason:
        inventory.setdefault('limitations', []).append('pkg version: %s' % outdated_reason)

    findings = sorted(b.findings, key=lambda f: (SEVERITY_ORDER[f['severity']], f['type'], f['id']))
    by_severity = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for item in findings:
        by_severity[item['severity']] += 1
    reachable = [s for s in services if s.get('internet_reachable') == 'yes']
    maybe = [s for s in services if s.get('internet_reachable') == 'maybe']
    if by_severity['high']:
        posture = 'critical'
    elif by_severity['medium'] or any(s['kind'] not in VPN_KINDS for s in reachable):
        posture = 'exposed'
    else:
        posture = 'hardened'
    summary = {
        'services': len(services), 'reachable': len(reachable), 'maybe_reachable': len(maybe),
        'admin_reachable': sum(1 for s in reachable + maybe if s['admin']),
        'listening_all_interfaces': sum(1 for s in services if s['scope'] == 'any'),
        'packages': (inventory.get('packages') or {}).get('count'),
        'vulnerable_packages': sum(1 for p in packages if p['cves']),
        'cves_total': (vulns or {}).get('cves_total', 0), 'kev': (vulns or {}).get('kev_total', 0),
        'findings': len(findings), 'by_severity': by_severity, 'posture': posture,
        # "partial": the service list is incomplete (not root / sockstat failed), a "hardened" may be optimistic
        'posture_confidence': 'full' if inventory.get('services_complete') else 'partial',
        'services_complete': bool(inventory.get('services_complete')),
        'online': bool((vulns or {}).get('online')),
        'attack_surface': [{'id': s['id'], 'service': s['service'], 'label': s['label'], 'proto': s['proto'],
                            'port': s['port'], 'internet_reachable': s['internet_reachable'], 'admin': s['admin'],
                            'cves': s.get('cves', 0), 'kev': s.get('kev', 0)} for s in reachable + maybe],
    }
    return {
        'version': 1, 'kind': 'exposure', 'generated': common.now_iso(),
        'duration_ms': int((time.monotonic() - started) * 1000) if started else None,
        'summary': summary, 'findings': findings,
        'services': services,
        'vulns': vulns,
        'outdated': outdated,
        'inventory': {k: v for k, v in inventory.items() if k not in ('services', 'sockets')},
        # LAN devices are a separate front; the slot is reserved so the HUD can rely on the shape
        'devices': {'status': 'not_collected', 'items': [], 'source': None},
    }


def write(document, path=None):
    path = path or OUTPUT_FILE
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.exposure.', dir=directory)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(json.dumps(document))
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
