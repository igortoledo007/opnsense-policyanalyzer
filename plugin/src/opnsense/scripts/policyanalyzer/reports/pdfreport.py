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

    The report as a PDF attachment, built from the SAME data as the HTML / text bodies (collect.build + the
    executive summary of aisum), never from the HTML. Same sections and strings as render.py (catalog section
    "report") plus the sections "pdf" and "chart" of i18n/<language>.json; a language whose script pdf.py cannot
    draw (see i18n.pdf_language) gets an English PDF while the e-mail body keeps the language. Laid out with
    pdf.Document: KPI cards, executive summary box, posture, quarantine (per level, new, most active, top repeat
    offenders), findings, blocks / ports / countries (bars), CVEs P1..P4, new devices, notifications.

    Attachment name: opnsense-relatorio-YYYY-MM-DD-HHMM.pdf (local time of the end of the period).
"""

import time

import i18n

from . import charts, common, pdf, render

MAX_BYTES = 300 * 1024          # target size of the attachment

LEVEL_COLORS = ['#64748b', '#2563eb', '#0891b2', '#d97706', '#ea580c', '#dc2626', '#7f1d1d']
SECTIONS = ('posture', 'quarantine', 'findings', 'traffic', 'cves', 'devices', 'notifications')


def strings(language):
    """ report + chart + pdf sections of the catalog (later ones win); '_lang' = the language of the PDF """
    lang = i18n.pdf_language(language, pdf.can_render)
    return dict(render.s(lang), _lang=lang, **dict(i18n.section(lang, 'chart'), **i18n.section(lang, 'pdf')))


def when(ts, t, key='datetime'):
    return i18n.fmt_date(ts, t['_lang'], key)


def filename(data):
    return 'opnsense-relatorio-%s.pdf' % time.strftime('%Y-%m-%d-%H%M', time.localtime(data.get('until') or
                                                                                       common.now()))


def num(value, language='en_US'):
    """ 31877 -> 31.877 (pt) / 31,877 (en); anything that is not an int is returned as is """
    return i18n.fmt_int(value, language)


def _join(value):
    return ', '.join(str(v) for v in value) if isinstance(value, (list, tuple)) else str(value)


def _v(value, default='-'):
    return default if value is None or value == '' else value


def _cards(doc, t, items, **kwargs):
    doc.kpis([(num(v, t['_lang']), label, color) for v, label, color in items], **kwargs)


def _bars(doc, t, items, **kwargs):
    doc.bars(items, value_format=lambda v: str(num(v, t['_lang'])), **kwargs)


def _sev_cell(value):
    value = value or 'info'
    return {'text': value, 'chip': render.SEV_COLOR.get(value, '#64748b')}


def _muted(doc, text):
    doc.paragraph(text, 9, color=pdf.MUTED)


def _posture(doc, p, t):
    if not p.get('available'):
        return _muted(doc, t['unavailable'])
    name = t['posture_values'].get(p.get('posture'), p.get('posture') or '-')
    _cards(doc, t, [(name, t['kpi_posture'], render.POSTURE_COLOR.get(p.get('posture'))),
              (p.get('reachable', 0), t['reachable'], None),
              (p.get('admin_reachable', 0), t['admin'], '#b91c1c' if p.get('admin_reachable') else None),
              ('%s / %s' % (p.get('cves_total', 0), p.get('kev', 0)), '%s / %s' % (t['cves_total'], t['kev']),
               '#7f1d1d' if p.get('kev') else None)], height=42, value_size=13)
    facts = '%s %s · %s %s' % (p.get('maybe_reachable', 0), t['maybe'], p.get('services', 0), t['service'].lower())
    if p.get('generated'):
        ts = common.parse_iso(p['generated'])
        facts += ' · ' + t['generated_age'] % (when(ts, t) if ts else p['generated'],
                                               _v(p.get('age_hours')))
    _muted(doc, facts)
    if p.get('changed') and p.get('previous'):
        prev = p['previous'].get('posture')
        doc.paragraph(t['changed'] % t['posture_values'].get(prev, prev), 9, color='#b45309')
    if p.get('attack_surface'):
        doc.subheading(t['attack_surface'])
        doc.table([t['service'], t['port'], 'Internet', 'CVE', 'KEV'],
                  [[a.get('service') or '-', '%s/%s' % (a.get('proto') or '-', a.get('port') or '-'),
                    _v(a.get('reachable')), a.get('cves', 0),
                    {'text': a.get('kev', 0), 'color': '#7f1d1d', 'bold': True} if a.get('kev') else 0]
                   for a in p['attack_surface']], widths=[0.36, 0.16, 0.2, 0.14, 0.14], align='lllrr')


def _quarantine(doc, q, t):
    if not q.get('installed', True) and not q.get('available'):
        return _muted(doc, t['not_installed'])
    if not q.get('available'):
        return _muted(doc, t['unavailable'])
    _cards(doc, t, [(q.get('active', 0), t['active'], '#d94f00'), (q.get('new', 0), t['new'], '#2563eb'),
              (q.get('expired', 0), t['expired'], '#15803d'), (q.get('offenses', 0), t['offenses'], None)],
             height=40, value_size=14)
    if q.get('paused'):
        doc.paragraph(t['quarantine_paused'], 9, color='#b45309')
    levels = sorted((q.get('by_level') or {}).items(), key=lambda kv: int(kv[0]))
    if levels:
        _bars(doc, t, [(t['level_n'] % k, v, LEVEL_COLORS[min(int(k), 6)]) for k, v in levels], title=t['by_level'])
    if q.get('by_reason'):
        _bars(doc, t, sorted(q['by_reason'].items(), key=lambda kv: -kv[1]), color='#475569', title=t['by_reason'])
    if q.get('top_period'):
        doc.subheading(t['top_period'])
        doc.table([t['address'], t['level'], t['country'], t['asn'], t['period_col'], t['total']],
                  [[{'text': r.get('addr'), 'mono': True}, 'N%s' % _v(r.get('level')), _v(r.get('country')),
                    _v(r.get('asn')), r.get('offenses', 0), _v(r.get('total'))] for r in q['top_period']],
                  widths=[0.32, 0.1, 0.1, 0.16, 0.16, 0.16], align='llllrr')
    if q.get('top_repeat'):
        doc.subheading(t['top_repeat'])
        doc.table([t['address'], t['level'], t['country'], t['offenses']],
                  [[{'text': r.get('addr'), 'mono': True}, 'N%s' % _v(r.get('level')), _v(r.get('country')),
                    r.get('offenses', 0)] for r in q['top_repeat']], widths=[0.46, 0.16, 0.16, 0.22], align='lllr')


def _findings(doc, f, t):
    if not f.get('available'):
        return _muted(doc, t['unavailable'])
    sev = f.get('by_severity') or {}
    _muted(doc, '%s %s · %s' % (_v(f.get('rules'), 0), t['rules'], _v(f.get('findings'), 0)))
    _bars(doc, t, [(k, sev.get(k, 0), render.SEV_COLOR[k]) for k in ('high', 'medium', 'low', 'info')],
             title=t['by_severity'], label_width=70)
    if f.get('top'):
        doc.table([t['severity'], t['finding']],
                  [[_sev_cell(x.get('severity')), {'text': x.get('title') or x.get('type') or '-',
                                                   'sub': x.get('rule') or ''}] for x in f['top']],
                  widths=[0.15, 0.85])
    else:
        _muted(doc, t['none_findings'])


def _traffic(doc, tr, t):
    if not tr.get('available'):
        return _muted(doc, t['unavailable'])
    _cards(doc, t, [(tr.get('blocked_in', 0), t['kpi_blocked'], '#d94f00'),
              (tr.get('distinct_sources', 0), t['sources'], None), (tr.get('events', 0), t['events'], None)],
             height=40, value_size=14)
    if not tr.get('complete', True):
        doc.paragraph(t['partial'], 8.5, color='#b45309')
    lang = t['_lang']
    if tr.get('top_ports'):
        charts.hbar(doc, [x['port'] for x in tr['top_ports']], [('', [x['blocked'] for x in tr['top_ports']])],
                    t['top_ports'], lang)
    if tr.get('top_countries'):
        charts.hbar(doc, [x['country'] or '??' for x in tr['top_countries']],
                    [('', [x['blocked'] for x in tr['top_countries']])], t['top_countries'], lang,
                    styles=[charts.PALETTE[3]],
                    note=t['country_source'] % tr['country_source'] if tr.get('country_source') else None)
    if tr.get('top_sources'):
        charts.hbar(doc, [x['addr'] for x in tr['top_sources']], [('', [x['blocked'] for x in tr['top_sources']])],
                    t['top_sources'], lang, styles=[charts.PALETTE[2]], mono=True)


def _cves(doc, c, t):
    if not c.get('available'):
        return _muted(doc, t['unavailable'])
    counts = c.get('counts') or {}
    _bars(doc, t, [(p, counts.get(p, 0), render.PRIO_COLOR[p]) for p in ('P1', 'P2', 'P3', 'P4')],
             title=t['by_priority'], label_width=40)
    _muted(doc, '%s %s · %s %s · %s %s' % (_v(c.get('total'), 0), 'CVE', c.get('kev', 0), t['kev'],
                                          c.get('review_pending', 0), t['review']))
    if not c.get('top'):
        return _muted(doc, t['none_cves'])
    rows = []
    for i in c['top']:
        scores = '%s / %s' % ('-' if i.get('epss') is None else ('%.2f' % i['epss'] if isinstance(i['epss'], float)
                                                                 else i['epss']), _v(i.get('cvss')))
        rows.append([{'text': i.get('priority'), 'chip': render.PRIO_COLOR.get(i.get('priority'), '#64748b')},
                     {'text': i.get('cve'), 'tag': ('KEV', '#7f1d1d') if i.get('kev') else None, 'bold': True},
                     {'text': '%s %s' % (i.get('package') or '-', i.get('version') or ''),
                      'sub': t['fixed'] % _join(i['fixed_in']) if i.get('fixed_in') else ''},
                     scores, _v(i.get('exposure')), i.get('why') or ''])
    doc.table([t['priority'], 'CVE', t['package'], t['epss'], t['exposure'], t['why']], rows,
              widths=[0.08, 0.19, 0.18, 0.13, 0.11, 0.31])


def _devices(doc, d, t):
    if not d.get('available'):
        return _muted(doc, t['unavailable'])
    _cards(doc, t, [(d.get('total', 0), t['device_total'], None), (d.get('present', 0), t['present'], None),
              (d.get('unknown', 0), t['unknown'], '#d97706' if d.get('unknown') else None),
              (d.get('new_count', 0), t['device_new'], '#2563eb' if d.get('new_count') else None)],
             height=40, value_size=14)
    if not d.get('new'):
        return _muted(doc, t['none_new'])
    doc.subheading('%s (%s)' % (t['device_new'], d.get('new_count', len(d['new']))))
    doc.table([t['name'], t['type'], t['vendor'], 'IP', t['interface'], t['risk']],
              [[x.get('name') or '-', x.get('type') or '-', x.get('vendor') or '-', {'text': x.get('ip') or '-',
                                                                                    'mono': True},
                x.get('interface') or '-', _sev_cell(x.get('risk'))] for x in d['new']],
              widths=[0.2, 0.13, 0.2, 0.2, 0.15, 0.12])


def _notifications(doc, n, t):
    if not n.get('available') or not n.get('sent'):
        return _muted(doc, t['none'])
    doc.table([t['kind'], t['severity'], t['count']],
              [[x.get('type'), _sev_cell(x.get('severity')), x.get('count', 0)] for x in n.get('by_type') or []],
              widths=[0.5, 0.25, 0.25], align='llr')


# ------------------------------------------------------------------ charts (data['metrics'], see collect.metrics)

SEV_ORDER = ('critical', 'high', 'medium', 'low', 'info')
CHART_SECTIONS = ('incidents', 'anomalies', 'ai_usage', 'collectors')


def _unit(m, t):
    return t['hour'] if (m.get('buckets') or {}).get('step', 3600) < 86400 else t['day']


def _labels(m, t):
    b = m.get('buckets') or {}
    return charts.bucket_labels(b.get('starts') or [], b.get('step', 3600), t['_lang'])


def _has(values):
    return bool(values) and any(v for v in values if v)


def _sev_series(t, cells, keys):
    """ cells: {key: {severity: n}} -> stacked series in severity order (only severities that occur) """
    present = [sv for sv in SEV_ORDER if any((cells.get(k) or {}).get(sv) for k in keys)]
    series = [(t['sev'].get(sv, sv), [(cells.get(k) or {}).get(sv, 0) for k in keys]) for sv in present]
    return series, [charts.SEVERITY[sv] for sv in present]


def _delta(t, current, previous):
    if previous is None:
        return None
    if not previous:
        return t['vs_prev'] % charts.fmt(previous, t['_lang']) if current else t['vs_prev'] % t['same']
    pct = 100.0 * (current - previous) / previous
    if abs(pct) < 0.5:
        return t['vs_prev'] % t['same']
    return t['vs_prev'] % ('%s%s%%' % ('+' if pct > 0 else '', charts.fmt(pct, t['_lang'], 0)))


def overview_cards(m, t, data=None):
    """ the 4 sparkline cards of the first page (only sources with a series) """
    data = data or {}
    unit = t['per'] % _unit(m, t)
    lang = t['_lang']
    cards = []
    tr = m.get('traffic') or {}
    if tr.get('blocked'):
        total = (data.get('traffic') or {}).get('blocked_in') if tr.get('source') == 'filter_log' else None
        total = sum(tr['blocked']) if total is None else total
        cards.append({'label': t['ov_blocks'], 'value': charts.fmt(total, lang), 'values': tr['blocked'],
                      'delta': _delta(t, sum(tr['blocked']), tr.get('previous')), 'hint': unit})
    q = m.get('quarantine') or {}
    if 'new' in q:
        cards.append({'label': t['ov_quarantine'], 'value': charts.fmt(sum(q['new']) + sum(q.get('repeat') or []), lang),
                      'values': [a + b for a, b in zip(q['new'], q.get('repeat') or [0] * len(q['new']))],
                      'delta': _delta(t, sum(q['new']) + sum(q.get('repeat') or []), q.get('previous_new')),
                      'hint': unit})
    inc = m.get('incidents') or {}
    if 'opened_series' in inc:
        cards.append({'label': t['ov_incidents'], 'value': charts.fmt(sum(inc['opened_series']), lang),
                      'values': inc['opened_series'], 'delta': _delta(t, sum(inc['opened_series']), inc.get('previous')),
                      'hint': unit})
    ai = m.get('ai') or {}
    if ai.get('requests'):
        cards.append({'label': t['ov_ai'], 'value': charts.fmt(sum(ai['requests']), lang), 'values': ai['requests'],
                      'delta': _delta(t, sum(ai['requests']), ai.get('previous')), 'hint': unit})
    an = m.get('anomalies') or {}
    if len(cards) < 4 and an.get('occurrences') is not None:
        cards.append({'label': t['ov_anomalies'], 'value': charts.fmt(sum(an['occurrences']), lang),
                      'values': an['occurrences'], 'hint': unit})
    dv = m.get('devices') or {}
    if len(cards) < 4 and dv.get('new_by_type') is not None:
        per = [sum(v) for v in zip(*dv['new_by_type'].values())] if dv['new_by_type'] else []
        cards.append({'label': t['ov_devices'], 'value': charts.fmt(sum(per), lang), 'values': per, 'hint': unit})
    return cards[:4]


def chart_traffic(doc, m, t, show_empty=False):
    tr = m.get('traffic') or {}
    labels = _labels(m, t)
    if not tr.get('blocked') or (not _has(tr['blocked']) and not show_empty):
        return False
    charts.line(doc, labels, [('', tr['blocked'])], t['ch_blocks'] % _unit(m, t), t['_lang'], area=True, integer=True,
                note=t.get('src_' + str(tr.get('source')), None))
    return True


def chart_asn(doc, m, t, show_empty=False):
    asn = (m.get('quarantine') or {}).get('top_asn') or []
    if not asn:
        return False
    charts.hbar(doc, ['AS%s' % a['asn'] for a in asn], [('', [a['offenses'] for a in asn])], t['ch_asn'], t['_lang'],
                styles=[charts.PALETTE[5]],
                note=t['asn_note'] % charts.fmt(sum(a['sources'] for a in asn), t['_lang']))
    return True


def chart_quarantine(doc, m, t, show_empty=False):
    q = m.get('quarantine') or {}
    drawn = False
    if 'new' in q:
        series = [(t['q_new'], q['new']), (t['q_released'], q.get('released') or []), (t['q_repeat'], q.get('repeat') or [])]
        if show_empty or not charts.is_empty(series):
            charts.vbar(doc, _labels(m, t), series, t['ch_q_flow'] % _unit(m, t), t['_lang'],
                        styles=[charts.PALETTE[0], charts.PALETTE[2], charts.PALETTE[1]])
            drawn = True
    dur = q.get('by_duration') or {}
    if dur:
        keys = [k for k in collect_levels() if dur.get(k)]
        charts.vbar(doc, [t['durations'].get(k, k) for k in keys], [('', [dur[k] for k in keys])], t['ch_q_duration'],
                    t['_lang'], height=104, styles=[charts.PALETTE[3]])
        drawn = True
    return drawn


def collect_levels():
    return ('1', '2', '3', '4', '5', '6')


def chart_incidents(doc, m, t, show_empty=False):
    inc = m.get('incidents') or {}
    if 'opened' not in inc:
        return False
    cells = {'opened': inc.get('opened') or {}, 'closed': inc.get('closed') or {}}
    series, styles = _sev_series(t, cells, ('opened', 'closed'))
    if not series and not show_empty:
        return False
    if series:
        charts.hbar(doc, [t['inc_opened'], t['inc_closed']], series, t['ch_inc'], t['_lang'], stacked=True,
                    styles=styles, row=16)
    else:
        charts.empty(doc, t['ch_inc'], t['_lang'])
    now = inc.get('open_now') or {}
    if now:
        _muted(doc, t['inc_open_now'] % ', '.join('%s %s' % (charts.fmt(now[sv], t['_lang']), t['sev'].get(sv, sv))
                                                    for sv in SEV_ORDER if now.get(sv)))
    return True


def chart_anomalies(doc, m, t, show_empty=False):
    an = m.get('anomalies') or {}
    labels = _labels(m, t)
    lang = t['_lang']
    drawn = False
    if an.get('volume') and any(v for v in an['volume'] if v):
        peak = max(v for v in an['volume'] if v is not None)
        power = 0
        while peak >= 1024 ** (power + 1) and power < 4:
            power += 1
        unit = ('B', 'KB', 'MB', 'GB', 'TB')[power]
        scaled = [None if v is None else v / 1024.0 ** power for v in an['volume']]
        # modern look (same as the Anomalies page): smooth line over a fading area, the last point marked
        charts.line(doc, labels, [('', scaled)], '%s (%s)' % (t['ch_anom_volume'] % _unit(m, t), unit), lang,
                    area=True, highlight=an.get('flagged'), smooth=True, markers=False,
                    color='#0284c7', gradient=('#7dd3fc', '#ffffff'))
        drawn = True
    elif an.get('occurrences') is not None and (show_empty or _has(an['occurrences'])):
        charts.vbar(doc, labels, [('', an['occurrences'])], t['ch_anom_occ'] % _unit(m, t), lang,
                    styles=[charts.SEVERITY['high']])
        drawn = True
    sev = an.get('by_severity') or {}
    if sev and drawn:
        _muted(doc, t['anom_sev'] % ', '.join('%s %s' % (charts.fmt(sev[sv], lang), t['sev'].get(sv, sv))
                                              for sv in SEV_ORDER if sev.get(sv)))
    return drawn


def chart_cves(doc, c, t, show_empty=False):
    matrix = (c or {}).get('by_age_severity') or {}
    keys = [k for k in ('y0', 'y1_2', 'y3_5', 'y6p', 'unknown') if matrix.get(k)]
    if not keys:
        return False
    series, styles = _sev_series(t, matrix, keys)
    charts.vbar(doc, [t['ages'][k] for k in keys], series, t['ch_cve_age'], t['_lang'], stacked=True, styles=styles,
                height=112, note=t['age_note'])
    return True


def chart_devices(doc, m, t, show_empty=False):
    dv = m.get('devices') or {}
    drawn = False
    new = dv.get('new_by_type') or {}
    if new:
        order = sorted(new, key=lambda k: -sum(new[k]))
        series = [(t['dev_types'].get(k, k), new[k]) for k in order[:5]]
        if len(order) > 5:
            rest = [sum(v) for v in zip(*[new[k] for k in order[5:]])]
            series.append((charts.tr(t['_lang'], 'other'), rest))
        charts.vbar(doc, _labels(m, t), series, t['ch_dev_new'] % _unit(m, t), t['_lang'], stacked=True, height=104)
        drawn = True
    if dv.get('by_type'):
        charts.donut(doc, sorted(((t['dev_types'].get(k, k), v) for k, v in dv['by_type'].items()),
                                 key=lambda kv: -kv[1]), t['ch_dev_types'], t['_lang'])
        drawn = True
    return drawn


def chart_posture(doc, m, t, show_empty=False):
    ps = m.get('posture') or {}
    points = ps.get('points') or []
    if not points:
        return False
    labels = [when(p[0], t, 'day_month') for p in points]
    charts.line(doc, labels, [('', [p[1] for p in points])], t['ch_posture'] % ps.get('window_days', 14), t['_lang'],
                low=0, high=100, height=104)
    last = ps.get('last') or {}
    if last.get('grade') is not None:
        _muted(doc, t['posture_last'] % (charts.fmt(last.get('score'), t['_lang'], 1), last.get('grade'),
                                         _v(last.get('pass')), _v(last.get('warn')), _v(last.get('fail'))))
    return True


def chart_ai(doc, m, t, show_empty=False):
    ai = m.get('ai') or {}
    lang = t['_lang']
    drawn = False
    routes = ai.get('by_route') or {}
    if routes:
        order = sorted(routes, key=lambda k: -(routes[k]['ok'] + routes[k]['error']))
        charts.hbar(doc, order, [(t['ok'], [routes[k]['ok'] for k in order]),
                                 (t['error'], [routes[k]['error'] for k in order])], t['ch_ai_routes'], lang,
                    stacked=True, styles=[charts.STATUS['ok'], charts.STATUS['error']], max_items=8,
                    note=t.get('ai_source_' + str(ai.get('source'))))
        drawn = True
    lat = ai.get('latency') or {}
    if lat:
        order = sorted(lat, key=lambda k: -(lat[k]['p90'] or 0))[:10]
        charts.hbar(doc, ['%s (%s)' % (k, lat[k]['n']) for k in order],
                    [('p50', [lat[k]['p50'] for k in order]), ('p90', [lat[k]['p90'] for k in order])],
                    t['ch_ai_latency'], lang, styles=[charts.PALETTE[0], charts.PALETTE[4]],
                    value_format=lambda v: charts.fmt_seconds(v, lang))
        drawn = True
    fmt_ok = ai.get('format') or {}
    if fmt_ok:
        order = sorted(fmt_ok, key=lambda k: fmt_ok[k]['ok'] / float(fmt_ok[k]['total'] or 1))[:10]
        charts.hbar(doc, ['%s (%s)' % (k, fmt_ok[k]['total']) for k in order],
                    [('', [100.0 * fmt_ok[k]['ok'] / (fmt_ok[k]['total'] or 1) for k in order])], t['ch_ai_format'],
                    lang, styles=[charts.PALETTE[5]], value_format=lambda v: charts.fmt(v, lang, 0) + '%')
        drawn = True
    queue = ai.get('queue') or {}
    if queue:
        counts = queue.get('counts') or {}
        _muted(doc, t['ai_queue'] % (charts.fmt(queue.get('jobs'), lang), charts.fmt(counts.get('done', 0), lang),
                                     charts.fmt(counts.get('error', 0), lang),
                                     charts.fmt_seconds(queue['wait_p50'], lang) if queue.get('wait_p50') is not None
                                     else '-'))
        drawn = True
    shadow = ai.get('shadow') or []
    if shadow:
        charts.hbar(doc, [x['service'] for x in shadow], [('', [x['hits'] for x in shadow])], t['ch_shadow'], lang,
                    styles=[charts.PALETTE[6]])
        drawn = True
    return drawn


def chart_collectors(doc, m, t, show_empty=False):
    drawn = False
    for base in m.get('collectors') or []:
        series = list(base['series'].items())[:4]
        if series and any(_has(v) for _k, v in series):
            charts.line(doc, _labels(m, t), series, '%s: %s' % (t['collectors'], base['base']), t['_lang'], height=104)
            drawn = True
    return drawn


SECTION_CHARTS = {'traffic': (chart_traffic,), 'quarantine': (chart_quarantine, chart_asn),
                  'devices': (chart_devices,), 'posture': (chart_posture,)}
EXTRA_CHARTS = {'incidents': chart_incidents, 'anomalies': chart_anomalies, 'ai_usage': chart_ai,
                'collectors': chart_collectors}
EXTRA_DATA = {'incidents': 'incidents', 'anomalies': 'anomalies', 'ai_usage': 'ai', 'collectors': 'collectors'}


def _section_charts(doc, key, data, t):
    m = data.get('metrics') or {}
    funcs = list(SECTION_CHARTS.get(key, ()))
    for func in funcs:
        if _probe(func, m, t):
            func(doc, m, t)
    if key == 'cves' and _probe(lambda d, _m, tt: chart_cves(d, data.get('cves'), tt), m, t):
        chart_cves(doc, data.get('cves'), t)


def _extra_sections(doc, data, t, sections=None):
    m = data.get('metrics') or {}
    for key in CHART_SECTIONS:
        if sections is not None and key not in sections:
            continue
        part = m.get(EXTRA_DATA[key])
        if not part or (isinstance(part, dict) and set(part) <= {'error', 'previous', 'previous_new'}):
            continue
        if _probe(EXTRA_CHARTS[key], m, t):          # draw only when the section has something
            doc.heading(t[key], keep=110)
            EXTRA_CHARTS[key](doc, m, t)


def _probe(func, m, t):
    scratch = pdf.Document('probe', compress=False)
    try:
        return func(scratch, m, t)
    except Exception:                       # noqa: BLE001 - a chart that can not be drawn is left out
        return False


RENDER = {'posture': _posture, 'quarantine': _quarantine, 'findings': _findings, 'traffic': _traffic,
          'cves': _cves, 'devices': _devices, 'notifications': _notifications}


def report(data, summary, language, hostname='', sections=None, base='', compress=True, charts_on=True):
    """ :return: (filename, PDF bytes) """
    t = strings(language)
    kind = t.get('kind_' + str(data.get('kind')), data.get('kind'))
    since, until = data.get('since') or 0, data.get('until') or common.now()
    period = '%s %s %s' % (when(since, t), t['to'], when(until, t))
    host = hostname or 'OPNsense'
    doc = pdf.Document('%s - %s' % (t['title'], host), header_right=when(until, t),
                       footer_left='OPNsense Policy Analyzer · %s · %s' % (host, t['generated'] %
                                                                           when(common.now(), t)),
                       page_label=t['page'], compress=compress, created=common.now())
    doc.title_block(t['title'], '%s · %s: %s' % (host, t['period'], period), badge=str(kind).upper())
    _cards(doc, t, _kpis(data, t))
    charts_on = charts_on and bool(data.get('metrics'))
    if charts_on:
        cards = overview_cards(data['metrics'], t, data)
        if cards:
            charts.overview(doc, cards, t['_lang'], t['overview'])
    sections = sections or list(SECTIONS) + ['ai_summary'] + list(CHART_SECTIONS)
    if 'ai_summary' in sections and summary and summary.get('text'):
        doc.note(summary['text'], t['exec'] if summary.get('ai') else t['exec_fallback'], summary.get('note'))
    for key in SECTIONS:
        if key in sections and key in data:
            doc.heading(t[key])
            RENDER[key](doc, data[key] or {}, t)
            if charts_on and (data[key] or {}).get('available', True):
                _section_charts(doc, key, data, t)
    if charts_on:
        _extra_sections(doc, data, t, sections)
    doc.spacer(6)
    if base:
        _muted(doc, t['link'] % (base + render.LINKS['reports']))
    _muted(doc, t['footer'])
    return filename(data), doc.finish()


def _kpis(data, t):
    p = data.get('posture') or {}
    tr = data.get('traffic') or {}
    q = data.get('quarantine') or {}
    c = (data.get('cves') or {}).get('counts') or {}
    return [(t['posture_values'].get(p.get('posture'), p.get('posture') or '-'), t['kpi_posture'],
             render.POSTURE_COLOR.get(p.get('posture'))),
            (tr.get('blocked_in', '-') if tr.get('available') else '-', t['kpi_blocked'], '#d94f00'),
            (q.get('active', '-') if q.get('available') else '-', t['kpi_quarantine'], '#475569'),
            ('%s / %s' % (c.get('P1', 0), c.get('P2', 0)) if c else '-', t['kpi_cves'],
             '#b91c1c' if c.get('P1') else '#475569')]


# ------------------------------------------------------------------ attachment of a notification e-mail

TYPE_CHARTS = {'quarantine_long': (chart_quarantine, chart_asn), 'incident': (chart_incidents, chart_traffic),
               'anomaly': (chart_anomalies,), 'vuln_kev_p1': (), 'posture_drop': (chart_posture,),
               'ai_down': (chart_ai,), 'device_new': (chart_devices,), 'report': ()}


def notification_filename(events, now=None):
    kind = (events[0].get('type') if events else None) or 'alerta'
    return 'opnsense-alerta-%s-%s.pdf' % (str(kind).replace('_', '-'),
                                          time.strftime('%Y-%m-%d-%H%M', time.localtime(now or common.now())))


def notification(events, summary, language, hostname='', base='', metrics=None, cves=None, hours=24,
                 compress=True, now=None):
    """
    PDF attached to a notification (or digest) e-mail: the events, the summary and the charts of the context of
    that event type over the last <hours> (metrics = collect.metrics(now - hours h, now)). :return: (name, bytes)
    """
    t = strings(language)
    now = now or common.now()
    host = hostname or 'OPNsense'
    etype = events[0].get('type') if events else 'report'
    label = t['event_types'].get(etype, etype)
    doc = pdf.Document('%s - %s' % (t['notify_title'], host), header_right=when(now, t),
                       footer_left='OPNsense Policy Analyzer · %s · %s' % (host, t['generated'] %
                                                                           when(now, t)),
                       page_label=t['page'], compress=compress, created=now)
    worst = max((e.get('severity') for e in events), key=common.severity_rank, default='info')
    doc.title_block('%s: %s' % (t['notify_title'], label),
                    '%s · %d %s' % (host, len(events), t['events'].lower()), badge=str(worst).upper())
    if summary and summary.get('text'):
        doc.note(summary['text'], t['exec'] if summary.get('ai') else t['exec_fallback'], summary.get('note'))
    rows = []
    for ev in events[:40]:
        rows.append([when(ev.get('ts') or now, t), _sev_cell(ev.get('severity')),
                     {'text': ev.get('title') or '-', 'sub': ev.get('detail') or ''}])
    doc.table([t['when'], t['severity'], t['events_col']], rows, widths=[0.17, 0.13, 0.7])
    m = metrics or {}
    if m:
        doc.heading(t['notify_context'] % hours, keep=110)
        cards = overview_cards(m, t)
        if cards:
            charts.overview(doc, cards, t['_lang'])
        for func in TYPE_CHARTS.get(etype, ()):
            if _probe(lambda d, mm, tt: func(d, mm, tt, True), m, t):
                func(doc, m, t, True)
        if etype == 'vuln_kev_p1' and cves:
            chart_cves(doc, cves, t, True)
    if base:
        _muted(doc, t['link'] % (base + (events[0].get('link') or render.LINKS['reports'] if events else '')))
    _muted(doc, t['footer'])
    return notification_filename(events, now), doc.finish()
