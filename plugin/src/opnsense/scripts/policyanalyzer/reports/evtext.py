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

    Event texts in the language of the report. The detectors keep the facts of each event in "data" (address,
    level, vendor...) next to an English title/detail; at send time the title and detail are rebuilt from those facts
    with the "events" section of the catalogs. Events without the facts (older ones, or events of other modules)
    keep their stored text.
"""

import i18n

QUARANTINE_DAYS = {4: 'days_10', 5: 'days_30', 6: 'permanent'}


def severity(value, language):
    """ "medium" -> "média" (pt_BR); unknown values are returned as they are """
    return i18n.section(language, 'chart').get('sev', {}).get(value or 'info', value or 'info')


def _quarantine(d, t):
    if not d.get('addr') or d.get('level') is None:
        return None
    level = int(d['level'])
    title = t['quarantine_title'] % (d['addr'], t[QUARANTINE_DAYS[min(max(level, 4), 6)]], level)
    parts = [('%s %s' % (t.get('kind_' + str(d.get('kind')), d.get('kind') or ''),
                         t.get('origin_' + str(d.get('origin')), d.get('origin') or ''))).strip()]
    if d.get('country'):
        parts.append(t['country'] % d['country'])
    if d.get('asn'):
        parts.append('AS%s' % d['asn'])
    return title, ', '.join(p for p in parts if p)


def _device(d, t, language):
    if 'label' not in d:
        return None
    title = t['device_title'] % (d['label'], d.get('vendor') or t['unknown_vendor'])
    detail = t['device_detail'] % (d.get('ips') or '-', d.get('iface') or '-', d.get('type') or '-',
                                   severity(d.get('risk'), language))
    return title, detail


def _vuln(d, t, ev):
    if not d.get('cve') or 'package' not in d:
        return None
    if d.get('priority') == 'P1' and d.get('became_p1'):
        return t['vuln_p1_title'] % (d['cve'], d['package'], d.get('version') or ''), ev.get('detail') or ''
    if d.get('kev'):
        return (t['vuln_kev_title'] % (d['cve'], d['package']),
                t['vuln_kev_detail'] % (d.get('kev_date') or '?', d.get('priority') or '?'))
    return None


def _ai(d, t, ev):
    if not d.get('provider') or not d.get('failures'):
        return None
    name = d.get('provider_label') or d['provider']
    return t['ai_down_title'] % (name, int(d['failures'])), ev.get('detail') or ''


def _posture(d, t, ev):
    if d.get('before') is None or d.get('after') is None:
        return None
    return t['posture_title'] % (float(d['before']), float(d['after'])), ev.get('detail') or ''


def text(ev, language):
    """ :return: (title, detail) of one event in the language, or the stored ones """
    d, t = ev.get('data') or {}, i18n.section(language, 'events')
    kind = ev.get('type')
    try:
        if kind == 'quarantine_long':
            out = _quarantine(d, t)
        elif kind == 'device_new':
            out = _device(d, t, language)
        elif kind == 'vuln_kev_p1':
            out = _vuln(d, t, ev)
        elif kind == 'ai_down':
            out = _ai(d, t, ev)
        elif kind == 'posture_drop':
            out = _posture(d, t, ev)
        else:
            out = None
    except (KeyError, TypeError, ValueError):
        out = None
    return out or (ev.get('title') or '', ev.get('detail') or '')


def localize(events, language):
    """ copies of the events with title/detail in the language and the severity label in "severity_label" """
    out = []
    for ev in events:
        title, detail = text(ev, language)
        out.append(dict(ev, title=title, detail=detail, severity_label=severity(ev.get('severity'), language)))
    return out
