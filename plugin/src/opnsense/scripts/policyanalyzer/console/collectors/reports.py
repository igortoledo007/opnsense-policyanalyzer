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

    Policy Analyzer findings and exposure report collectors (read only): both only read the JSON reports the
    plugin already wrote (/var/db/policyanalyzer/last.json and exposure.json); nothing is re-analyzed here.
"""

import datetime
import time

from ..common import clean_text, load_json

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
RULE_FIELDS = ('interface', 'direction', 'action', 'sequence', 'description', 'summary', 'enabled')


def _age_minutes(generated):
    try:
        stamp = datetime.datetime.fromisoformat(str(generated).replace('Z', '+00:00'))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.astimezone()
    return max(0, int((time.time() - stamp.timestamp()) // 60))


def findings(paths, rule_uuids=None, types=None, limit=12):
    report = load_json(paths.report)
    if not report:
        return {'available': False, 'message': 'no Policy Analyzer report yet (run an analysis first)'}
    items = [f for f in report.get('findings') or [] if isinstance(f, dict)]
    if rule_uuids:
        items = [f for f in items if any(r.get('uuid') in rule_uuids for r in f.get('rules') or [])]
    if types:
        items = [f for f in items if f.get('type') in types] or items
    items.sort(key=lambda f: SEVERITY_ORDER.get(f.get('severity'), 9))
    out = []
    for f in items[:limit]:
        out.append({
            'type': f.get('type'), 'severity': f.get('severity'), 'title': clean_text(f.get('title'), 160),
            'detail': clean_text(f.get('detail'), 400), 'recommendation': clean_text(f.get('recommendation'), 300),
            'rules': [{k: r.get(k) for k in RULE_FIELDS if k in r} for r in (f.get('rules') or [])[:2]],
        })
    return {
        'available': True,
        'source': 'Policy Analyzer report (last.json)',
        'generated': report.get('generated'),
        'report_age_minutes': _age_minutes(report.get('generated')),
        'summary': report.get('summary'),
        'stats_available': report.get('stats_available'),
        'counters_since': (report.get('stats') or {}).get('counters_since'),
        'findings_matching': len(items),
        'findings': out,
    }


def exposure(paths):
    report = load_json(paths.exposure)
    if not report or not isinstance(report.get('summary'), dict):
        return {'available': False, 'message': 'no exposure report yet'}
    sm = report['summary']
    keep = ('posture', 'posture_confidence', 'services', 'reachable', 'maybe_reachable', 'admin_reachable',
            'vulnerable_packages', 'cves_total', 'kev', 'findings', 'by_severity')
    data = {'available': True, 'source': 'exposure report (exposure.json)', 'generated': report.get('generated'),
            'report_age_minutes': _age_minutes(report.get('generated'))}
    data.update({k: sm[k] for k in keep if k in sm})
    surface = []
    for sv in sm.get('attack_surface') or report.get('services') or []:
        if not isinstance(sv, dict):
            continue
        surface.append({'service': clean_text(sv.get('label') or sv.get('service') or '?', 60),
                        'port': sv.get('port'), 'proto': sv.get('proto'),
                        'internet_reachable': sv.get('internet_reachable'), 'admin': bool(sv.get('admin')),
                        'cves': sv.get('cves', 0), 'kev': sv.get('kev', 0)})
    surface.sort(key=lambda s: ({'yes': 0, 'maybe': 1}.get(s['internet_reachable'], 2), -int(s['cves'] or 0)))
    data['services_list'] = surface[:12]
    return data
