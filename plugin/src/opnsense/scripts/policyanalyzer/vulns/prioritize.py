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

    P1..P4 priority of every CVE of the inventory (exposure.json), explainable, without a black box:

      P1  critical  reachable from the internet AND (in CISA KEV OR EPSS >= epss_high)
      P2  high      reachable from the internet AND CVSS >= cvss_high, OR in KEV while not exposed
      P3  medium    listening only on LAN/VPN AND CVSS >= cvss_high, OR EPSS >= epss_medium,
                    OR reachable from the internet without enough data to say more
      P4  low       everything else (typically a library without a listening socket)

    "maybe" reachability (exposure/reach.py could not decide) counts as reachable and says so in the factors.
    The owner's mapping decisions of the review queue (review.py) override the automatic link. Read only:
    nothing here changes the firewall or calls the network.
"""

from . import common, intel, review

PRIORITY_ORDER = {'P1': 0, 'P2': 1, 'P3': 2, 'P4': 3}
LABELS = {'P1': 'critical', 'P2': 'high', 'P3': 'medium', 'P4': 'low'}
EXPOSURE_TEXT = {'internet': 'reachable from the internet', 'internet_maybe': 'possibly reachable from the internet',
                 'lan': 'listening only on internal networks (LAN/VPN)', 'none': 'no listening service runs it'}


def load_exposure():
    return common.load_json(common.paths()['exposure'])


def _link_packages():
    from exposure import report as exposure_report     # read only import
    return exposure_report.link_packages


def _svc(svc, link):
    return {'id': svc.get('id'), 'service': svc.get('service'), 'name': svc.get('label'), 'proto': svc.get('proto'),
            'port': svc.get('port'), 'internet_reachable': svc.get('internet_reachable', 'no'),
            'admin': bool(svc.get('admin')), 'link': link}


def exposure_class(linked):
    reach = [s['internet_reachable'] for s in linked]
    if 'yes' in reach:
        return 'internet'
    if 'maybe' in reach:
        return 'internet_maybe'
    return 'lan' if linked else 'none'


def score(exposure, kev, epss, cvss, t=None):
    """ :return: (priority, rule, factors[{factor, met, text}]) """
    t = t or common.DEFAULT_THRESHOLDS
    exposed = exposure in ('internet', 'internet_maybe')
    epss_high = epss is not None and epss >= t['epss_high']
    epss_medium = epss is not None and epss >= t['epss_medium']
    cvss_high = cvss is not None and cvss >= t['cvss_high']
    factors = [
        {'factor': 'exposure', 'met': exposed, 'value': exposure, 'text': EXPOSURE_TEXT[exposure] +
         (' (the reachability analysis was not conclusive)' if exposure == 'internet_maybe' else '')},
        {'factor': 'kev', 'met': bool(kev), 'value': bool(kev),
         'text': 'listed in CISA KEV (exploited in the wild)' if kev else 'not in CISA KEV'},
        {'factor': 'epss', 'met': epss_high or epss_medium, 'value': epss,
         'text': ('EPSS %.3f (>= %.2f: high probability of exploitation)' % (epss, t['epss_high']) if epss_high else
                  'EPSS %.3f (>= %.2f)' % (epss, t['epss_medium']) if epss_medium else
                  'EPSS %.3f' % epss if epss is not None else 'no EPSS score cached')},
        {'factor': 'cvss', 'met': cvss_high, 'value': cvss,
         'text': ('CVSS %.1f (>= %.1f)' % (cvss, t['cvss_high']) if cvss_high else
                  'CVSS %.1f' % cvss if cvss is not None else 'no CVSS score')},
    ]
    if exposed and (kev or epss_high):
        return 'P1', 'exposed and %s' % ('in KEV' if kev else 'EPSS high'), factors
    if exposed and cvss_high:
        return 'P2', 'exposed and CVSS high', factors
    if kev:
        return 'P2', 'in KEV but not exposed', factors
    if exposure == 'lan' and cvss_high:
        return 'P3', 'internal only and CVSS high', factors
    if epss_medium:
        return 'P3', 'EPSS above the medium threshold', factors
    if exposed:
        return 'P3', 'exposed, no high score', factors
    return 'P4', 'not exposed, no exploitation signal' if exposure == 'none' else 'internal, no high score', factors


def explanation(priority, rule, exposure, services):
    where = ', '.join('%s %s/%s' % (s['name'] or s['service'], s['proto'], s['port']) for s in services[:3])
    return '%s (%s): %s%s.' % (priority, LABELS[priority], rule, (' - via ' + where) if where and
                                                                    exposure != 'none' else '')


def _suricata(doc):
    out = {}
    for finding in doc.get('findings') or []:
        for cve, sids in ((finding.get('evidence') or {}).get('suricata') or {}).items():
            known = {s.get('sid') for s in out.setdefault(cve, [])}
            out[cve].extend(s for s in sids if s.get('sid') not in known)
    return out


def build(doc=None, now=None, state=None):
    """ :return: {status, items[], review[], intel, counts, ...} """
    doc = load_exposure() if doc is None else doc
    if not isinstance(doc, dict) or not doc.get('services') and not doc.get('vulns'):
        return {'status': 'none', 'message': 'no exposure report yet (run the exposure report first)',
                'items': [], 'review': [], 'counts': {p: 0 for p in PRIORITY_ORDER}}
    t = common.thresholds()
    services = doc.get('services') or []
    by_id = {s.get('id'): s for s in services}
    packages = (doc.get('vulns') or {}).get('packages') or []
    all_cves = sorted({c['id'] for p in packages for c in p.get('cves') or [] if common.CVE_RE.match(c['id'])})
    kev_items, _ = intel.load_kev()
    epss_items, _ = intel.load_epss(all_cves)
    state = state if state is not None else review.load_state()
    maps = review.mappings(state, now)
    sids = _suricata(doc)
    link_packages = _link_packages()
    items = []
    for pkg in packages:
        decided = maps.get(pkg['name'], {})
        if 'map' in decided and decided['map'] in by_id:
            linked = [_svc(by_id[decided['map']], 'owner')]
        elif 'none' in decided:
            linked = []
        else:
            linked = [_svc(s, link) for s in services for _p, link in link_packages(s, [pkg])]
        exp = exposure_class(linked)
        for rec in pkg.get('cves') or []:
            cve = rec['id']
            kev_info = kev_items.get(cve)
            if rec.get('kev') and not kev_info:
                kev_info = {'date_added': rec.get('kev_date_added'), 'due': rec.get('kev_due'),
                            'name': rec.get('kev_name'), 'action': rec.get('kev_action'),
                            'ransomware': bool(rec.get('kev_ransomware')), 'vendor': None, 'product': None}
            epss = rec.get('epss')
            pct = rec.get('epss_percentile')
            epss_date = None
            if epss is None and cve in epss_items:
                epss, pct = epss_items[cve].get('epss'), epss_items[cve].get('percentile')
                epss_date = epss_items[cve].get('date')
            priority, rule, factors = score(exp, bool(kev_info), epss, rec.get('cvss'), t)
            items.append({
                'id': common.short_id(pkg['name'], cve), 'cve': cve, 'package': pkg['name'],
                'version': pkg.get('version'), 'fixed_in': pkg.get('fixed_in') or [],
                'fix_available': pkg.get('fix_available'), 'summary': rec.get('summary'),
                'refs': (rec.get('refs') or [])[:5], 'cvss': rec.get('cvss'), 'cvss_vector': rec.get('cvss_vector'),
                'severity': rec.get('severity'), 'kev': kev_info, 'epss': epss, 'epss_percentile': pct,
                'epss_date': epss_date, 'priority': priority, 'priority_label': LABELS[priority], 'rule': rule,
                'factors': factors, 'explanation': explanation(priority, rule, exp, linked),
                'exposure': {'class': exp, 'services': linked, 'mapped_by_owner': 'map' in decided or
                             'none' in decided},
                'confirmed': 'finding' in decided, 'suricata': sids.get(cve, [])[:5],
                'sources': rec.get('sources') or [], 'ghsa': rec.get('ghsa')})
    items.sort(key=lambda i: (PRIORITY_ORDER[i['priority']], not i['kev'], -(i['epss'] or 0), -(i['cvss'] or 0),
                              i['cve']))
    queue = review.merge(review.add_unscored(review.build_items(doc), items), state, now)
    counts = {p: sum(1 for i in items if i['priority'] == p) for p in PRIORITY_ORDER}
    gen = common.parse_iso(doc.get('generated'))
    return {'status': 'ok', 'generated': common.iso(now), 'exposure_generated': doc.get('generated'),
            'exposure_age_minutes': None if gen is None else int(((now or common.now()) - gen) // 60),
            'posture': (doc.get('summary') or {}).get('posture'), 'thresholds': t,
            'counts': counts, 'total': len(items), 'kev': sum(1 for i in items if i['kev']),
            'items': items, 'review': queue, 'review_pending': sum(1 for q in queue if q['status'] == 'pending'),
            'intel': intel.status(all_cves)}


def summary(result=None):
    """ light view for the Max Cyber and the reports """
    result = result or build()
    if result.get('status') != 'ok':
        return {'status': result.get('status'), 'message': result.get('message'),
                'counts': result.get('counts'), 'total': 0}
    top = [{'cve': i['cve'], 'package': i['package'], 'priority': i['priority'], 'kev': bool(i['kev']),
            'epss': i['epss'], 'cvss': i['cvss'], 'exposure': i['exposure']['class'], 'rule': i['rule']}
           for i in result['items'][:5]]
    intel_state = result.get('intel') or {}
    return {'status': 'ok', 'generated': result['generated'], 'exposure_generated': result['exposure_generated'],
            'exposure_age_minutes': result['exposure_age_minutes'], 'posture': result.get('posture'),
            'counts': result['counts'], 'total': result['total'], 'kev': result['kev'],
            'review_pending': result['review_pending'], 'top': top,
            'intel': {'kev_fetched': (intel_state.get('kev') or {}).get('fetched'),
                      'kev_age_days': (intel_state.get('kev') or {}).get('age_days'),
                      'epss_covered': (intel_state.get('epss') or {}).get('covered'),
                      'epss_missing': len((intel_state.get('epss') or {}).get('missing') or [])}}
