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

    Templates of the e-mails: responsive HTML (tables + inline styles, readable in webmail, mobile clients and the
    browser preview) and the plain text alternative. Every value is escaped. The texts are the section "report"
    of the catalogs i18n/<language>.json (en_US by default; a missing translation falls back to English), the
    dates follow format.datetime of the catalog.
"""

import html

import i18n

from . import common

SEV_COLOR = {'critical': '#b91c1c', 'high': '#dc2626', 'medium': '#d97706', 'low': '#2563eb', 'info': '#64748b'}
PRIO_COLOR = {'P1': '#b91c1c', 'P2': '#ea580c', 'P3': '#ca8a04', 'P4': '#64748b'}
POSTURE_COLOR = {'hardened': '#15803d', 'exposed': '#d97706', 'critical': '#b91c1c'}
LINKS = {'posture': '/ui/policyanalyzer/#exposure', 'quarantine': '/ui/policyanalyzer/#quarantine',
         'findings': '/ui/policyanalyzer/', 'traffic': '/ui/diagnostics/firewall/log',
         'cves': '/ui/policyanalyzer/vulns', 'devices': '/ui/policyanalyzer/devices',
         'notifications': '/ui/policyanalyzer/reports#notifications', 'reports': '/ui/policyanalyzer/reports'}

CSS = """
body{margin:0;padding:0;background:#eef2f7;-webkit-text-size-adjust:100%}
.pa-wrap{width:100%;background:#eef2f7;padding:16px 0}
.pa-card{max-width:680px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;
 font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;font-size:14px;line-height:1.45}
.pa-tile{display:inline-block;width:25%;vertical-align:top;box-sizing:border-box;padding:6px}
.pa-tile div.in{border:1px solid #e2e8f0;border-radius:10px;padding:10px 8px;text-align:center}
.pa-num{font-size:22px;font-weight:700;line-height:1.2}
.pa-lbl{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.04em}
table.pa-t{width:100%;border-collapse:collapse;font-size:13px}
table.pa-t th{text-align:left;color:#64748b;font-weight:600;font-size:11px;text-transform:uppercase;
 border-bottom:1px solid #e2e8f0;padding:6px 6px}
table.pa-t td{border-bottom:1px solid #f1f5f9;padding:6px 6px;vertical-align:top;word-break:normal;overflow-wrap:break-word}
.pa-chip{display:inline-block;border-radius:999px;padding:1px 8px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}
.pa-sec{padding:14px 20px 4px}
.pa-h2{font-size:15px;font-weight:700;margin:0 0 8px;color:#0f172a}
.pa-muted{color:#64748b;font-size:12px}
.pa-btn{display:inline-block;background:#2563eb;color:#ffffff !important;text-decoration:none;border-radius:8px;
 padding:10px 16px;font-weight:600}
@media only screen and (max-width:600px){
 .pa-wrap{padding:0}
 .pa-card{border-radius:0}
 .pa-tile{width:50%}
 .pa-sec{padding:12px 14px 4px}
 table.pa-t .pa-hide{display:none}
}
@media (prefers-color-scheme:dark){
 body,.pa-wrap{background:#0b1220 !important}
 .pa-card{background:#111827 !important;color:#e5e7eb !important}
 .pa-h2,.pa-num{color:#f1f5f9}
 .pa-tile div.in{border-color:#1f2937 !important}
 table.pa-t td{border-color:#1f2937 !important}
 table.pa-t th{border-color:#374151 !important}
 .pa-sum{background:#0f1a2e !important}
}
"""


def s(language):
    """ the texts of the e-mails; '_lang' = the normalized language """
    lang = i18n.normalize(language)
    return dict(i18n.section(lang, 'report'), _lang=lang)


def when(ts, t):
    return i18n.fmt_date(ts, t.get('_lang', i18n.DEFAULT))


def e(value):
    return html.escape('' if value is None else str(value), quote=True)


def chip(text, color):
    return '<span class="pa-chip" style="background:%s">%s</span>' % (color, e(text))


def _table(headers, rows, hide=()):
    head = ''.join('<th%s>%s</th>' % (' class="pa-hide"' if i in hide else '', e(h)) for i, h in enumerate(headers))
    body = ''.join('<tr>%s</tr>' % ''.join('<td%s>%s</td>' % (' class="pa-hide"' if i in hide else '', c)
                                          for i, c in enumerate(r)) for r in rows)
    return '<table class="pa-t" role="presentation" cellpadding="0" cellspacing="0"><tr>%s</tr>%s</table>' % (head,
                                                                                                             body)


def _section(key, title, inner, base):
    link = ('<a href="%s%s" style="font-size:12px;color:#2563eb;text-decoration:none;float:right">&rarr;</a>'
            % (e(base), e(LINKS.get(key, '')))) if base else ''
    return '<div class="pa-sec">%s<div class="pa-h2">%s</div>%s</div>' % (link, e(title), inner)


def _p(text, muted=False):
    return '<p style="margin:4px 0 8px"%s>%s</p>' % (' class="pa-muted"' if muted else '', text)


def _posture_html(p, t):
    if not p.get('available'):
        return _p(e(t['unavailable']), True)
    pv = t['posture_values'].get(p['posture'], p['posture'])
    head = chip(pv, POSTURE_COLOR.get(p['posture'], '#64748b'))
    facts = ' &middot; '.join(e(x) for x in ('%s %s' % (p.get('reachable', 0), t['reachable']),
                                              '%s %s' % (p.get('maybe_reachable', 0), t['maybe']),
                                              '%s %s' % (p.get('admin_reachable', 0), t['admin']),
                                              '%s %s, %s %s' % (p.get('cves_total', 0), t['cves_total'],
                                                                p.get('kev', 0), t['kev'])))
    out = _p('%s &nbsp; %s' % (head, facts))
    if p.get('changed') and p.get('previous'):
        out += _p(e(t['changed'] % t['posture_values'].get(p['previous']['posture'], p['previous']['posture'])), True)
    if p.get('attack_surface'):
        out += _table([t['service'], t['port'], 'Internet', 'CVE'],
                      [[e(a['service']), e('%s/%s' % (a['proto'], a['port'])), e(a['reachable']),
                        e('%s%s' % (a['cves'], (' (%s KEV)' % a['kev']) if a['kev'] else ''))]
                       for a in p['attack_surface']])
    return out


def _quarantine_html(q, t):
    if not q.get('installed'):
        return _p(e(t['not_installed']), True)
    if not q.get('available'):
        return _p(e(t['unavailable']), True)
    levels = ' '.join(chip('N%s: %s' % (k, v), ['#64748b', '#2563eb', '#0891b2', '#d97706', '#ea580c', '#dc2626',
                                                 '#7f1d1d'][min(int(k), 6)])
                      for k, v in sorted(q['by_level'].items()))
    out = _p('<b>%s</b> %s &middot; <b>%s</b> %s &middot; <b>%s</b> %s &middot; %s %s' % (
        e(q['active']), e(t['active']), e(q['new']), e(t['new']), e(q['expired']), e(t['expired']),
        e(q['offenses']), e(t['offenses'].lower())))
    if levels:
        out += _p('%s: %s' % (e(t['by_level']), levels))
    if q.get('top_repeat'):
        out += '<div class="pa-muted" style="margin-top:6px">%s</div>' % e(t['top_repeat'])
        out += _table([t['address'], t['level'], t['country'], t['offenses']],
                      [[e(r['addr']), e(r['level']), e(r['country'] or '-'), e(r['offenses'])] for r in q['top_repeat']])
    return out


def _findings_html(f, t):
    if not f.get('available'):
        return _p(e(t['unavailable']), True)
    sev = f.get('by_severity') or {}
    out = _p('%s %s &middot; %s' % (e(f.get('rules')), e(t['rules']), ' '.join(
        chip('%s %s' % (k, sev.get(k, 0)), SEV_COLOR[k]) for k in ('high', 'medium', 'low', 'info'))))
    if f.get('top'):
        out += _table([t['severity'], t['finding']],
                      [[chip(x['severity'], SEV_COLOR.get(x['severity'], '#64748b')),
                        '%s<div class="pa-muted">%s</div>' % (e(x['title']), e(x.get('rule') or ''))] for x in f['top']])
    return out


def _traffic_html(tr, t):
    if not tr.get('available'):
        return _p(e(t['unavailable']), True)
    out = _p('<b>%s</b> %s &middot; %s %s%s' % (e(tr['blocked_in']), e(t['blocked'].lower()),
                                                e(tr['distinct_sources']), e(t['sources']),
                                                ('' if tr.get('complete') else ' &middot; <i>%s</i>' % e(t['partial']))))
    cells = []
    if tr.get('top_ports'):
        cells.append(_table([t['top_ports'], t['blocked']], [[e(x['port']), e(x['blocked'])] for x in tr['top_ports']]))
    if tr.get('top_countries'):
        cells.append(_table([t['top_countries'], t['blocked']],
                            [[e(x['country']), e(x['blocked'])] for x in tr['top_countries']]))
    if cells:
        out += ''.join('<div class="pa-tile" style="width:50%%;padding:0 6px 0 0">%s</div>' % c for c in cells)
    if tr.get('top_sources'):
        out += _table([t['top_sources'], t['blocked']], [[e(x['addr']), e(x['blocked'])] for x in tr['top_sources']])
    return out


def _cves_html(c, t):
    if not c.get('available'):
        return _p(e(t['unavailable']), True)
    counts = c.get('counts') or {}
    out = _p('%s &middot; %s %s &middot; %s %s' % (
        ' '.join(chip('%s %s' % (p, counts.get(p, 0)), PRIO_COLOR[p]) for p in ('P1', 'P2', 'P3', 'P4')),
        e(c.get('kev', 0)), e(t['kev']), e(c.get('review_pending', 0)), e(t['review'])))
    if c.get('top'):
        out += _table([t['priority'], 'CVE', t['package'], t['why']],
                      [[chip(i['priority'], PRIO_COLOR[i['priority']]),
                        e(i['cve']) + (' ' + chip('KEV', '#7f1d1d') if i['kev'] else ''),
                        e('%s %s' % (i['package'], i['version'] or '')), '<span class="pa-muted">%s</span>' % e(i['why'])]
                       for i in c['top']], hide=(3,))
    return out


def _devices_html(d, t):
    if not d.get('available'):
        return _p(e(t['unavailable']), True)
    out = _p('<b>%s</b> %s &middot; %s %s &middot; %s %s' % (e(d['total']), e(t['device_total']), e(d['present']),
                                                             e(t['present']), e(d['unknown']), e(t['unknown'])))
    if d.get('new'):
        out += '<div class="pa-muted">%s (%s)</div>' % (e(t['device_new']), e(d['new_count']))
        out += _table([t['type'], t['vendor'], 'IP', t['risk']],
                      [[e(x['type']), e(x['vendor']), e(x['ip']).replace(', ', ',<br>'),
                        chip(x['risk'] or 'info', SEV_COLOR.get(x['risk'] or 'info', '#64748b'))] for x in d['new']],
                      hide=(1,))          # phones: no vendor column, the type/IP/risk columns keep their words whole
    return out


def _notifications_html(n, t):
    if not n.get('available') or not n.get('sent'):
        return _p(e(t['none']), True)
    return _p(' '.join(chip('%s %s' % (x['type'], x['count']), SEV_COLOR.get(x['severity'], '#64748b'))
                       for x in n['by_type']))


SECTION_RENDER = {'posture': _posture_html, 'quarantine': _quarantine_html, 'findings': _findings_html,
                  'traffic': _traffic_html, 'cves': _cves_html, 'devices': _devices_html,
                  'notifications': _notifications_html}


def _shell(inner, title, base):
    return ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,'
            'initial-scale=1"><meta name="color-scheme" content="light dark"><title>%s</title><style>%s</style>'
            '</head><body><div class="pa-wrap"><div class="pa-card">%s</div></div></body></html>') % (e(title), CSS,
                                                                                                    inner)


def _header(title, subtitle, color='#0f172a', badge=None):
    return ('<div style="background:%s;color:#ffffff;padding:18px 20px">'
            '<div style="font-size:12px;opacity:.8;letter-spacing:.06em;text-transform:uppercase">Policy Analyzer'
            '%s</div><div style="font-size:20px;font-weight:700;margin-top:2px">%s</div>'
            '<div style="font-size:13px;opacity:.85;margin-top:2px">%s</div></div>') % (
        color, (' &middot; ' + e(badge)) if badge else '', e(title), e(subtitle))


def _footer(t, base, target='reports'):
    button = ('<p style="margin:14px 0"><a class="pa-btn" href="%s%s">%s</a></p>' % (e(base), e(LINKS[target]),
                                                                                    e(t['open']))) if base else ''
    return '<div class="pa-sec" style="padding-bottom:18px">%s<p class="pa-muted">%s</p></div>' % (button,
                                                                                                    e(t['footer']))


def kpis(data, t):
    p = data.get('posture') or {}
    tr = data.get('traffic') or {}
    q = data.get('quarantine') or {}
    c = (data.get('cves') or {}).get('counts') or {}
    tiles = [(t['posture_values'].get(p.get('posture'), p.get('posture') or '-'), t['kpi_posture'],
              POSTURE_COLOR.get(p.get('posture'), '')),
             (tr.get('blocked_in', '-') if tr.get('available') else '-', t['kpi_blocked'], ''),
             (q.get('active', '-') if q.get('available') else '-', t['kpi_quarantine'], ''),
             ('%s / %s' % (c.get('P1', 0), c.get('P2', 0)) if c else '-', t['kpi_cves'],
              '#b91c1c' if c.get('P1') else '')]
    return '<div style="padding:12px 14px 0">%s</div>' % ''.join(
        '<div class="pa-tile"><div class="in"><div class="pa-num"%s>%s</div><div class="pa-lbl">%s'
        '</div></div></div>' % ((' style="color:%s"' % color) if color else '', e(v), e(label))
        for v, label, color in tiles)


def report(data, summary, language, base, hostname='', sections=None):
    """ :return: (subject, html, text) """
    t = s(language)
    kind = t.get('kind_' + data['kind'], data['kind'])
    period = '%s %s %s' % (when(data['since'], t), t['to'], when(data['until'], t))
    subject = '[%s] %s (%s) %s' % (hostname or 'OPNsense', t['title'], kind, when(data['until'], t))
    parts = [_header('%s%s' % (t['title'], (' - ' + hostname) if hostname else ''), '%s: %s' % (t['period'], period),
                     badge=kind), kpis(data, t)]
    sections = sections or list(SECTION_RENDER) + ['ai_summary']
    if 'ai_summary' in sections and summary:
        label = t['exec'] if summary.get('ai') else t['exec_fallback']
        parts.append('<div class="pa-sec"><div class="pa-sum" style="background:#f1f5ff;border-left:4px solid #2563eb;'
                     'border-radius:8px;padding:12px 14px"><div class="pa-lbl" style="margin-bottom:4px">%s</div>'
                     '<div>%s</div>%s</div></div>' % (e(label), e(summary['text']),
                                                      ('<div class="pa-muted" style="margin-top:4px">%s</div>'
                                                       % e(summary['note'])) if summary.get('note') else ''))
    for key in SECTION_RENDER:
        if key in sections and key in data:
            parts.append(_section(key, t[key], SECTION_RENDER[key](data[key], t), base))
    parts.append(_footer(t, base))
    return subject, _shell(''.join(parts), subject, base), report_text(data, summary, t, period, kind, base, hostname,
                                                                       sections)


def report_text(data, summary, t, period, kind, base, hostname, sections):
    lines = ['%s%s (%s)' % (t['title'], (' - ' + hostname) if hostname else '', kind), '%s: %s' % (t['period'], period),
             '']
    if summary and 'ai_summary' in sections:
        lines += [(t['exec'] if summary.get('ai') else t['exec_fallback']).upper(), summary['text'], '']
    p = data.get('posture')
    if p is not None:
        lines.append(t['posture'].upper())
        lines.append(('%s: %s, %s %s, %s %s, %s %s' % (t['kpi_posture'], t['posture_values'].get(p['posture'],
                                                                                              p['posture']),
                                                       p.get('reachable'), t['reachable'], p.get('cves_total'),
                                                       t['cves_total'], p.get('kev'), t['kev']))
                     if p.get('available') else t['unavailable'])
        lines.append('')
    q = data.get('quarantine')
    if q is not None:
        lines.append(t['quarantine'].upper())
        if not q.get('installed'):
            lines.append(t['not_installed'])
        elif q.get('available'):
            lines.append('%s %s, %s %s, %s %s' % (q['active'], t['active'], q['new'], t['new'], q['expired'],
                                                  t['expired']))
            lines.append('%s: %s' % (t['by_level'], ', '.join('N%s=%s' % kv for kv in sorted(q['by_level'].items()))))
            for r in q.get('top_repeat') or []:
                lines.append('  %s  N%s  %s  %s' % (r['addr'], r['level'], r['country'] or '-', r['offenses']))
        lines.append('')
    f = data.get('findings')
    if f is not None:
        lines.append(t['findings'].upper())
        if f.get('available'):
            lines.append('%s %s; %s' % (f.get('rules'), t['rules'], ', '.join(
                '%s %s' % (k, (f.get('by_severity') or {}).get(k, 0)) for k in ('high', 'medium', 'low', 'info'))))
            lines += ['  [%s] %s' % (x['severity'], x['title']) for x in f.get('top') or []]
        else:
            lines.append(t['unavailable'])
        lines.append('')
    tr = data.get('traffic')
    if tr is not None:
        lines.append(t['traffic'].upper())
        if tr.get('available'):
            lines.append('%s: %s, %s %s' % (t['blocked'], tr['blocked_in'], tr['distinct_sources'], t['sources']))
            lines.append('%s: %s' % (t['top_ports'], ', '.join('%s (%s)' % (x['port'], x['blocked'])
                                                               for x in tr['top_ports']) or '-'))
            lines.append('%s: %s' % (t['top_countries'], ', '.join('%s (%s)' % (x['country'], x['blocked'])
                                                                   for x in tr['top_countries']) or '-'))
        else:
            lines.append(t['unavailable'])
        lines.append('')
    c = data.get('cves')
    if c is not None:
        lines.append(t['cves'].upper())
        if c.get('available'):
            lines.append(' '.join('%s=%s' % (k, (c.get('counts') or {}).get(k, 0)) for k in ('P1', 'P2', 'P3', 'P4')) +
                         ', KEV=%s' % c.get('kev', 0))
            lines += ['  %s %s %s %s - %s' % (i['priority'], i['cve'], i['package'], '(KEV)' if i['kev'] else '',
                                              i['why']) for i in c.get('top') or []]
        else:
            lines.append(t['unavailable'])
        lines.append('')
    d = data.get('devices')
    if d is not None:
        lines.append(t['devices'].upper())
        if d.get('available'):
            lines.append('%s %s, %s %s, %s %s' % (d['total'], t['device_total'], d['present'], t['present'],
                                                  d['unknown'], t['unknown']))
            lines += ['  %s: %s %s %s [%s]' % (t['new'], x['type'], x['vendor'], x['ip'], x['risk']) for x in d['new']]
        else:
            lines.append(t['unavailable'])
        lines.append('')
    if base:
        lines.append('%s: %s%s' % (t['open'], base, LINKS['reports']))
    lines.append(t['footer'])
    return '\n'.join(lines) + '\n'


def notification(events, summary, language, base, hostname=''):
    """ one alert (or a digest of several events of the same type) """
    t = s(language)
    top = max(events, key=lambda ev: common.severity_rank(ev['severity']))
    title = top['title'] if len(events) == 1 else t['digest'] % len(events)
    subject = '[%s] %s: %s' % (hostname or 'OPNsense', t['alert'] if len(events) == 1 else t['events'], title)
    link = top.get('link') or LINKS['reports']
    rows = [[chip(ev.get('severity_label') or ev['severity'], SEV_COLOR.get(ev['severity'], '#64748b')),
             '<b>%s</b><div class="pa-muted">%s</div>' % (e(ev['title']), e(ev.get('detail') or '')),
             e(when(ev['ts'], t))] for ev in events[:30]]
    inner = [_header(title, '%s%s' % (hostname + ' - ' if hostname else '', when(top['ts'], t)),
                     SEV_COLOR.get(top['severity'], '#0f172a'), badge=top.get('severity_label') or top['severity']),
             '<div class="pa-sec"><div class="pa-sum" style="background:#f8fafc;border-radius:8px;padding:12px 14px">'
             '%s</div></div>' % e(summary['text']),
             _section('notifications', t['events'], _table([t['severity'], t['events'], t['when']], rows, hide=(2,)),
                      None),
             '<div class="pa-sec">%s%s</div>' % (
                 ('<p><a class="pa-btn" href="%s%s">%s</a></p>' % (e(base), e(link), e(t['open']))) if base else '',
                 '<p class="pa-muted">%s %s</p>' % (e(t['throttle']) if len(events) > 1 else '', e(t['footer'])))]
    text = [title, '', summary['text'], '']
    text += ['[%s] %s - %s (%s)' % (ev.get('severity_label') or ev['severity'], ev['title'], ev.get('detail') or '',
                                     when(ev['ts'], t))
             for ev in events[:30]]
    if base:
        text += ['', '%s: %s%s' % (t['open'], base, link)]
    text += ['', t['footer']]
    return subject, _shell(''.join(inner), subject, base), '\n'.join(text) + '\n'


def test_message(language, base, channel, hostname=''):
    t = s(language)
    subject = '[%s] Policy Analyzer: %s' % (hostname or 'OPNsense', t['test_title'])
    inner = (_header(t['test_title'], hostname or 'OPNsense', '#15803d') +
             '<div class="pa-sec">%s%s</div>' % (_p(e(t['test_body'])), _p('%s: %s' % (e(t['channel']), e(channel)),
                                                                           True)) + _footer(t, base))
    text = '%s\n\n%s\n%s: %s\n' % (t['test_title'], t['test_body'], t['channel'], channel)
    return subject, _shell(inner, subject, base), text
