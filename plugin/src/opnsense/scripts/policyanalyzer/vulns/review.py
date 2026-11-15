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

    Queue "Under review": what the inventory can not map with confidence.

    Kinds:
      package_unmapped   vulnerable package that no listening service runs, but listening services depend on it
                         (e.g. python313 <- kea): is the vulnerable code in the network path?
      dependency_link    linked to a service only through a reverse dependency (the daemon may not load it)
      service_unknown    listening socket not mapped to a known service (exposure finding needs_review)
      binary_unowned     service binary that no package owns: its CVEs can not be matched
      advisory_unclear   OPNsense advisory whose version range could not be compared
      cve_unscored       CVE of an exposed component without CVSS, KEV or EPSS data

    The owner decides (change action vulns_review_decide, journaled and revertible):
      map:<service id>   the package runs inside that service (priority follows its exposure)
      none               confirmed: not in a network path (library only)
      ignore[=days]      hide until the validity ends (default 90 days)
      finding            confirmed as a real finding (kept and flagged in the lists and reports)
    The AI may only suggest (vulns/explain.py suggest); its suggestion is shown next to the evidence.

    State: <db>/vulns-review.json {"version": 1, "decisions": {id: {...}}, "suggestions": {id: {...}}}
"""

from . import common

DECISIONS = ('map', 'none', 'ignore', 'finding')


def _exposure_report():
    from exposure import report as exposure_report     # read only import (link_packages)
    return exposure_report


def load_state():
    data = common.load_json(common.paths()['review'], {}) or {}
    return {'version': 1, 'decisions': dict(data.get('decisions') or {}),
            'suggestions': dict(data.get('suggestions') or {})}


def save_state(state):
    common.write_json(common.paths()['review'], state)


def _svc_ref(svc):
    return {'id': svc.get('id'), 'service': svc.get('service'), 'name': svc.get('label'),
            'proto': svc.get('proto'), 'port': svc.get('port'),
            'internet_reachable': svc.get('internet_reachable', 'no'), 'package': svc.get('package_name')}


def build_items(doc):
    """ queue items computed from an exposure report (exposure.json) """
    doc = doc or {}
    services = doc.get('services') or []
    packages = ((doc.get('vulns') or {}).get('packages')) or []
    rep = _exposure_report()
    items = []
    for pkg in packages:
        if not pkg.get('cves'):
            continue
        links = []
        for svc in services:
            for _p, link in rep.link_packages(svc, [pkg]):
                links.append((svc, link))
        if any(link == 'direct' for _s, link in links):
            continue
        cves = [c['id'] for c in pkg['cves']]
        dep = [s for s, link in links if link == 'dependency']
        if dep:
            items.append({'kind': 'dependency_link', 'subject': pkg['name'], 'package': pkg['name'],
                          'version': pkg.get('version'), 'cves': cves,
                          'reason': '%s is linked to %s only through a reverse dependency: the daemon may not '
                                    'load it.' % (pkg['name'], ', '.join(s.get('label') or s['service'] for s in dep)),
                          'candidates': [_svc_ref(s) for s in dep]})
            continue
        rdeps = set(pkg.get('reverse_deps') or [])
        cands = [s for s in services if s.get('package_name') in rdeps or
                 any(c in rdeps for c in s.get('components') or [])]
        if cands:
            items.append({'kind': 'package_unmapped', 'subject': pkg['name'], 'package': pkg['name'],
                          'version': pkg.get('version'), 'cves': cves,
                          'reason': 'no listening service runs %s directly, but %d listening service(s) depend on '
                                    'it: is the vulnerable code in their network path?' % (pkg['name'], len(cands)),
                          'candidates': [_svc_ref(s) for s in cands[:8]]})
    for finding in doc.get('findings') or []:
        if finding.get('type') != 'needs_review':
            continue
        ev = finding.get('evidence') or {}
        reason = ev.get('reason') or ''
        if reason in ('stale database', 'pkg audit failed', 'not root'):
            continue                          # state of the probe, not something to map
        kind = {'binary without package': 'binary_unowned',
                'version range not understood': 'advisory_unclear'}.get(reason, 'service_unknown')
        subject = ev.get('advisory') or ev.get('binary') or ev.get('process') or \
            ('%s/%s' % (ev.get('proto'), ev.get('port')) if ev.get('port') else finding.get('id'))
        items.append({'kind': kind, 'subject': str(subject), 'package': None, 'version': None, 'cves': [],
                      'reason': finding.get('detail') or reason, 'candidates': [],
                      'finding_id': finding.get('id')})
    for item in items:
        item['id'] = common.short_id(item['kind'], item['subject'])
    return items


def add_unscored(items, prioritized):
    """ exposed CVEs without any score data (called by prioritize) """
    seen = {i['id'] for i in items}
    for rec in prioritized:
        if rec['exposure']['class'] == 'none' or rec['cvss'] is not None or rec['kev'] or rec['epss'] is not None:
            continue
        iid = common.short_id('cve_unscored', rec['cve'])
        if iid in seen:
            continue
        seen.add(iid)
        items.append({'id': iid, 'kind': 'cve_unscored', 'subject': rec['cve'], 'package': rec['package'],
                      'version': rec['version'], 'cves': [rec['cve']],
                      'reason': '%s affects an exposed component but has no CVSS, KEV or EPSS data yet; update '
                                'KEV/EPSS or check the advisory.' % rec['cve'],
                      'candidates': rec['exposure']['services']})
    return items


def decision_state(decision, now=None):
    """ 'active' | 'expired' | None """
    if not decision:
        return None
    now = common.now() if now is None else now
    until = common.parse_iso(decision.get('until'))
    if decision.get('decision') == 'ignore' and until is not None and until <= now:
        return 'expired'
    return 'active'


def merge(items, state=None, now=None):
    """ attach decisions and AI suggestions; status pending | decided """
    state = state or load_state()
    out = []
    for item in items:
        item = dict(item)
        dec = state['decisions'].get(item['id'])
        st = decision_state(dec, now)
        item['decision'] = dec if st == 'active' else None
        item['decision_expired'] = dec if st == 'expired' else None
        item['status'] = 'decided' if st == 'active' else 'pending'
        item['ai_suggestion'] = state['suggestions'].get(item['id'])
        out.append(item)
    out.sort(key=lambda i: (i['status'] != 'pending', i['kind'], i['subject']))
    return out


def mappings(state=None, now=None):
    """ package -> {'map': service id} / {'none': True} / {'finding': True}, from active decisions """
    state = state or load_state()
    out = {}
    for _iid, dec in state['decisions'].items():
        if decision_state(dec, now) != 'active' or not dec.get('package'):
            continue
        out.setdefault(dec['package'], {})[dec['decision']] = dec.get('target') or True
    return out


def parse_decision(token):
    """ 'map:<service id>' | 'none' | 'ignore' | 'ignore=30' | 'finding' -> (decision, target, days) """
    token = (token or '').strip()
    if token.startswith('map:'):
        target = token[4:]
        if not common.SERVICE_ID_RE.match(target):
            raise ValueError('invalid service id')
        return 'map', target, None
    if token.startswith('ignore'):
        days = common.IGNORE_DAYS_DEFAULT
        if token.startswith('ignore='):
            try:
                days = int(token[7:])
            except ValueError:
                raise ValueError('invalid validity')
            if not 1 <= days <= common.IGNORE_DAYS_MAX:
                raise ValueError('the validity must be 1 to %d days' % common.IGNORE_DAYS_MAX)
        elif token != 'ignore':
            raise ValueError('invalid decision')
        return 'ignore', None, days
    if token in ('none', 'finding'):
        return token, None, None
    raise ValueError('invalid decision (map:<service id>, none, ignore[=days], finding)')
