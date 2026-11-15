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

    The PDFs of the per scenario evaluation (ai/evaluate.py), first person, didactic: every number comes with why
    it matters.  model_pdf(db, eval_id): setup of the model, hardware, results per scenario, components,
    comparison with the whole history (firewall measurements only) and conclusions, with charts
    (reports/charts.py: scatter effectiveness x performance, bars of the score per scenario, time ranges against the
    budget, RAM and load).  final_pdf(db, plan_id): ranking per scenario and the recommended route (recommendation
    only).

    Language: the texts come from the catalogs i18n/<language>.json (sections "eval" and "eval_pdf"), in the
    language of the AI settings (evaluate.report_language: ai.language, "auto" = the GUI language, en_US by
    default).  The models themselves are always tested in Brazilian Portuguese (evaluate.LANG): that is
    evaluation data, not the language of the report.
"""

import statistics
import time

import i18n
from ai import bench, compute, eval_fixtures, evaluate
from reports import charts, pdf

# keyed by the stored indication values (see the catalog section "eval.indication" for what the reader sees)
IND_COLORS = {'indicado': '#15803d', 'promissor': '#b45309', 'não indicado': '#991b1b'}


def strings(language=None):
    """ the texts of the PDF: section eval_pdf + eval of the catalog, '_lang' = the language actually used """
    lang = i18n.pdf_language(evaluate.report_language(language), pdf.can_render, i18n.EVAL_PDF_SECTIONS)
    return dict(i18n.section(lang, 'eval_pdf'), _lang=lang, _eval=i18n.section(lang, 'eval'))


def _doc(title, t):
    return pdf.Document(title, header_right=i18n.fmt_date(time.time(), t['_lang']), footer_left=t['footer'],
                        page_label=t['page'])


def _f(value, nd=0, t=None):
    return charts.fmt(value, (t or {}).get('_lang', i18n.DEFAULT), nd) if value is not None else '—'


def _v(value):
    return '—' if value in (None, '') else value


def _y_range(values):
    """ the effectiveness axis starts 10 points below the lowest value (multiple of 10) to separate the points """
    vals = [v for v in values if v is not None]
    low = max(0.0, (int(min(vals) // 10) * 10 - 10)) if vals else 0.0
    return (low, 100.0)


def _scenario_short(sid):
    return sid.replace('console_explain_', 'console_').replace('_summary', '_sum').replace('notification', 'notif')


def _ind(indication, t):
    return t['_eval']['indication'].get(indication, indication)


def _chip(indication, t):
    return {'text': _ind(indication, t), 'chip': IND_COLORS.get(indication, '#4b5563')}


def method_box(doc, weights, t):
    doc.note(t['method'] % (_f(weights['effectiveness'], 1, t), _f(weights['performance'], 1, t)),
             label=t['method_label'])


def glossary(doc, t):
    doc.heading(t['glossary'])
    w = dict(evaluate.EFFECT_WEIGHTS)
    p = dict(evaluate.PERF_WEIGHTS)
    g = t['glossary_items']
    doc.bullets([
        g['validacao'] % w['validacao'], g['idioma'] % w['idioma'], g['raciocinio'] % w['raciocinio'],
        g['ancoragem'] % w['ancoragem'], g['cobertura'] % w['cobertura'], g['formato'] % w['formato'],
        g['estabilidade'] % w['estabilidade'], g['time'] % (p['p50'], p['p95']),
        g['tps'] % (p['tps'], evaluate.TPS_FULL), g['ttft'] % p['ttft'],
        g['ram'] % (p['ram'], evaluate.RAM_GOOD, evaluate.RAM_BAD),
        g['carga'] % (p['carga'], _f(bench.LOAD_HEADROOM, 1, t)),
        g['indication'] % (evaluate.INDICATED_EFF, evaluate.PROMISING_EFF),
    ], size=8.6)


def hardware_table(doc, hw, t):
    hw = hw or {}
    h = t['hw']
    lang = t['_lang']
    doc.table([t['item'], t['value']], [
        [h['host'], hw.get('hostname') or '—'],
        [h['system'], '%s %s' % (hw.get('os') or '—', hw.get('os_release') or '')],
        ['CPU', '%s%s' % (hw.get('cpu') or '—', ' (%s)' % hw['simd'] if hw.get('simd') else '')],
        [h['cores'], '%s / %s' % (hw.get('cores') or '—', hw.get('jail_threads') or '—')],
        [h['share'], '%s; num_ctx %s' % (evaluate.share_text(dict(hw, num_ctx=None), lang) or '—',
                                         hw.get('num_ctx') or '—')],
        [h['memory'], compute.memory_text(hw, lang)],
        ['Ollama', h['ollama'] % (hw.get('ollama_version') or '—', hw.get('ollama_url') or '—')],
        [h['where'], h['where_fw'] if evaluate.from_firewall(hw) else h['where_out']],
    ], widths=[0.32, 0.68], size=8.2)


def setup_table(doc, setup, ev, t):
    setup = setup or {}
    s = t['setup']
    routes = setup.get('routes') or {}
    short, long_ = routes.get('short') or {}, routes.get('long') or {}
    think = setup.get('think_mode') or '—'
    think_text = t['think'].get(think, think)
    opts = bench.loads(ev['options'], {}) or {}
    weights = bench.loads(ev['weights'], {}) or {}
    rows = [
        [s['model'], setup.get('model') or ev['model']],
        ['Digest', str(ev['digest'] or setup.get('digest') or '—')[:24]],
        [s['family'], '%s / %s / %s' % (
            _v(setup.get('family')), _v(setup.get('quantization')), _v(setup.get('parameter_size')))],
        [s['params'], '%s B / %s B%s' % (
            _f(setup.get('params_b'), 1, t), _f(setup.get('active_b'), 1, t),
            s['moe'] % (setup.get('experts_used'), setup.get('experts')) if setup.get('experts') else '')],
        [s['size'], '%s GiB / %s GiB' % (_f(setup.get('size_gib'), 2, t), _f(setup.get('ram_gib'), 1, t))],
        [s['context'], '%s / %s' % (_f(setup.get('context_native'), 0, t), _f(short.get('num_ctx'), 0, t))],
        [s['reasoning'], think_text],
        [s['short_route'], s['short_route_value'] % (
            _v(short.get('num_predict')), _v(short.get('timeout')), _v(short.get('retries')), _v(short.get('budget')),
            _v(short.get('keep_alive')))],
        [s['long_route'], s['long_route_value'] % (
            _v(long_.get('num_predict')), _v(long_.get('timeout')), _v(routes.get('brief_timeout')),
            _v(long_.get('retries')), _v(long_.get('budget')))],
        [s['temperature'], '%s / %s' % (_f(setup.get('temperature', 0.2), 1, t), ev['reps'])],
        [s['fixtures'], s['fixtures_value'] % (ev['fixtures_version'], len(eval_fixtures.FIXTURES))],
        [s['weights'], s['weights_value'] % (weights.get('effectiveness'), weights.get('performance'),
                                             s['reeval'] if opts.get('reeval') else '')],
    ]
    doc.table([t['item'], t['value']], rows, widths=[0.32, 0.68], size=8.2)


def _component_lowest(rows):
    sums = {}
    for r in rows:
        for k, v in (r.get('components') or {}).items():
            if v is not None:
                sums.setdefault(k, []).append(v)
    avg = {k: statistics.mean(v) for k, v in sums.items() if v}
    return sorted(avg.items(), key=lambda kv: kv[1])


def conclusions(model, rows, hist_rows, setup, t=None):
    """ didactic conclusions in the first person; :return: list of paragraphs """
    t = t or strings()
    c = t['conclusions']
    out = []
    if not rows:
        return [c['none']]
    ind = [r['scenario'] for r in rows if r['indication'] == 'indicado']
    prom = [r['scenario'] for r in rows if r['indication'] == 'promissor']
    out.append(c['indicated'] % (model, len(ind), (' (%s)' % ', '.join(ind)) if ind else '', len(prom),
                                 (' (%s)' % ', '.join(prom)) if prom else ''))
    low = _component_lowest(rows)
    if low:
        k, v = low[0]
        out.append(c['weakest'] % (t['_eval']['components'].get(k, k), _f(v, 2, t), c['weak_why'].get(k, k)))
    tps = [r['gen_tps'] for r in rows if r.get('gen_tps')]
    others = [r['gen_tps'] for r in hist_rows if r.get('gen_tps') and r['model'] != model]
    if tps:
        txt = c['tps'] % _f(statistics.median(tps), 1, t)
        if others:
            txt += c['tps_others'] % _f(statistics.median(others), 1, t)
        out.append(txt + c['tps_why'])
    ram = (setup or {}).get('ram_gib')
    if ram:
        free = evaluate.RAM_TOTAL_GIB - ram
        out.append(c['ram'] % (_f(ram, 1, t), _f(free, 1, t), c['ram_ok'] if free >= 8 else c['ram_tight']))
    slow = [r['scenario'] for r in rows if r.get('p95') and r['p95'] > r['budget']]
    if slow:
        out.append(c['slow'] % ', '.join(slow))
    tm = (setup or {}).get('think_mode')
    if tm in ('forced', 'harmony'):
        out.append(c['thinks'])
    best = evaluate.best_by_scenario(hist_rows)
    leads = [sid for sid, items in best.items() if items and items[0]['model'] == model]
    if leads:
        out.append(c['leads'] % ', '.join(leads))
    small = [r['scenario'] for r in rows if r['indication'] != 'não indicado' and r.get('confidence') == 'baixa']
    if small:
        out.append(c['low_confidence'] % (', '.join(small), model))
    return out


def _by_model(rows, extra=False):
    out = []
    for m in sorted({x['model'] for x in rows}):
        mr = [x for x in rows if x['model'] == m]
        item = (m, statistics.mean(x['effectiveness'] for x in mr), statistics.mean(x['performance'] for x in mr),
                statistics.mean(x['composite'] for x in mr))
        if extra:
            item += (max([x.get('ram_gib') or 0 for x in mr]), max([x.get('load_p95') or 0 for x in mr]))
        out.append(item)
    out.sort(key=lambda x: -x[3])
    return out


def model_pdf(db, eval_id, language=None):
    """ :return: (filename, bytes) of the PDF of one model evaluation """
    t = strings(language)
    lang = t['_lang']
    evaluate.ensure(db)
    ev = db.execute('SELECT * FROM eval_models WHERE id = ?', (eval_id,)).fetchone()
    setup = bench.loads(ev['setup'], {}) or {}
    hw = bench.loads(ev['hardware'], {}) or {}
    weights = bench.loads(ev['weights'], evaluate.WEIGHTS) or evaluate.WEIGHTS
    rows = [dict(bench.loads(r['data'], {}) or {}, model=r['model']) for r in
            db.execute('SELECT * FROM eval_results WHERE eval_id = ? ORDER BY scenario', (eval_id,))]
    from ai import scenarios as routing_mod
    order = list(routing_mod.CATALOG)
    rows.sort(key=lambda r: order.index(r['scenario']) if r['scenario'] in order else 99)
    hist_rows, discarded = evaluate.history(db, language=lang)
    m = t['model']
    doc = _doc(m['doc_title'] % ev['model'], t)
    doc.title_block(m['title'] % ev['model'], m['subtitle'] % (
        eval_id, bench.iso(ev['started']) if ev['started'] else '—',
        bench.iso(ev['finished']) if ev['finished'] else '—'),
        badge=m['badge_fw'] if evaluate.from_firewall(hw) else m['badge_out'])
    if rows:
        counts = {k: sum(1 for r in rows if r['indication'] == k) for k in evaluate.INDICATIONS}
        doc.kpis([(_f(statistics.mean(r['composite'] for r in rows), 0, t), m['kpi_score'], '#1f4e79'),
                  (_f(statistics.mean(r['effectiveness'] for r in rows), 0, t), m['kpi_eff'], '#15803d'),
                  (_f(statistics.mean(r['performance'] for r in rows), 0, t), m['kpi_perf'], '#b45309'),
                  ('%d/%d/%d' % (counts['indicado'], counts['promissor'], counts['não indicado']), m['kpi_counts'],
                   '#4b5563')])
    paras = conclusions(ev['model'], rows, hist_rows, setup, t)
    doc.note(' '.join(paras[:3]), label=m['summary'])
    method_box(doc, weights, t)

    doc.heading(m['setup'])
    setup_table(doc, setup, ev, t)
    doc.subheading(m['hardware'])
    hardware_table(doc, hw, t)

    doc.heading(m['results'])
    doc.paragraph(m['results_note'], 8.6, color=pdf.MUTED)
    col = t['col']
    table = []
    for r in rows:
        table.append([r['scenario'], '%d/%d' % (r['n_ok'], r['n']), _f(r['effectiveness'], 0, t),
                      _f(r['performance'], 0, t), {'text': _f(r['composite'], 0, t), 'bold': True},
                      '%s / %s' % (_f(r.get('p50'), 0, t), _f(r.get('p95'), 0, t)), _f(r['budget'], 0, t),
                      _chip(r['indication'], t),
                      '%s%s' % (t['_eval']['confidence'].get(r['confidence'], r['confidence']),
                                (' ±%s' % _f(r['ci95'], 0, t)) if r.get('ci95') is not None else '')])
    doc.table([col['scenario'], 'ok/n', col['eff'], col['perf'], col['score'], 'p50 / p95 (s)', col['budget'],
               col['indication'], col['confidence']],
              table, widths=[0.22, 0.07, 0.07, 0.07, 0.07, 0.13, 0.09, 0.14, 0.14], align=['l', 'r', 'r', 'r', 'r', 'r',
                                                                                         'r', 'l', 'l'], size=7.6)
    ch = t['charts']
    doc.heading(ch['heading'])
    labels = [_scenario_short(r['scenario']) for r in rows]
    charts.hbar(doc, labels, [(ch['eff'], [r['effectiveness'] for r in rows]),
                              (ch['perf'], [r['performance'] for r in rows]),
                              (ch['score'], [r['composite'] for r in rows])],
                title=ch['per_scenario'], language=lang, max_items=30, note=ch['per_scenario_note'])
    pts = [{'x': r['performance'], 'y': r['effectiveness'], 'series': 0, 'label': str(i + 1),
            'ring': r['indication'] == 'indicado'} for i, r in enumerate(rows)]
    charts.scatter(doc, pts, title=ch['scatter'], language=lang, x_label=ch['perf'], y_label=ch['eff'],
                   guides={'y': evaluate.INDICATED_EFF}, series=[ev['model']],
                   y_range=_y_range([r['effectiveness'] for r in rows]),
                   note=ch['scatter_note'] % evaluate.INDICATED_EFF)
    charts.ranges(doc, labels, [(r.get('min'), r.get('p50'), r.get('p95'), r.get('max')) for r in rows],
                  title=ch['ranges'], language=lang, limits=[r['budget'] for r in rows], note=ch['ranges_note'])
    doc.heading(m['components'])
    keys = [k for k, _w in evaluate.EFFECT_WEIGHTS]
    comp_rows = []
    for r in rows:
        c = r.get('components') or {}
        comp_rows.append([r['scenario']] + [_f(c.get(k), 2, t) if c.get(k) is not None else '—' for k in keys])
    doc.table([col['scenario']] + [t['_eval']['components_short'].get(k, k) for k in keys], comp_rows,
              widths=[0.23] + [0.11] * len(keys), align=['l'] + ['r'] * len(keys), size=7.4)
    doc.paragraph(m['components_note'], 8.4, color=pdf.MUTED)
    ex = t['examples']
    examples = []
    for r in db.execute('SELECT scenario, metrics FROM eval_runs WHERE eval_id = ? AND effectiveness < 70 ORDER BY '
                        'effectiveness LIMIT 6', (eval_id,)):
        met = bench.loads(r['metrics'], {}) or {}
        det = met.get('details') or {}
        bits = []
        if met.get('error'):
            bits.append(ex['error'] % bench.mask(met['error'], 90))
        if (det.get('anchoring') or {}).get('invented'):
            bits.append(ex['invented'] % ', '.join(det['anchoring']['invented'][:3]))
        if (det.get('coverage') or {}).get('missing'):
            bits.append(ex['missing'] % ', '.join(p.split('|')[0].replace('\\b', '')
                                                  for p in det['coverage']['missing'][:3]))
        if det.get('problems'):
            bits.append(ex['validation'] % bench.mask('; '.join(det['problems']), 90))
        examples.append('%s: %s' % (r['scenario'], '; '.join(bits) or ex['low']))
    doc.bullets(examples or [ex['none']], size=8.2)

    doc.heading(m['history'])
    best = evaluate.best_by_scenario(hist_rows)
    comp = []
    for r in rows:
        items = best.get(r['scenario']) or []
        pos = next((i + 1 for i, x in enumerate(items) if x['model'] == ev['model']), None)
        top = items[0] if items else None
        comp.append([r['scenario'], m['position'] % (pos or '—', len(items)),
                     top['model'] if top else '—', _f(top['composite'], 0, t) if top else '—',
                     _f(r['composite'], 0, t)])
    doc.table([col['scenario'], col['position'], col['best'], col['its_score'], col['this_score']], comp,
              widths=[0.24, 0.12, 0.38, 0.13, 0.13], align=['l', 'r', 'l', 'r', 'r'], size=7.8)
    by_model = _by_model(hist_rows, extra=True)
    if by_model:
        charts.hbar(doc, [x[0] for x in by_model], [(ch['avg_score'], [x[3] for x in by_model])],
                    title=ch['ranking'], language=lang, max_items=30, value_format=lambda v: _f(v, 0, t))
        charts.scatter(doc, [{'x': x[2], 'y': x[1], 'series': 0 if x[0] == ev['model'] else 1, 'label': str(i + 1),
                              'ring': x[0] == ev['model']} for i, x in enumerate(by_model)],
                       title=ch['map'], language=lang, x_label=ch['avg_perf'], y_label=ch['avg_eff'],
                       guides={'y': evaluate.INDICATED_EFF}, series=[ev['model'], ch['other_models']],
                       y_range=_y_range([x[1] for x in by_model]), note=ch['map_note'])
        charts.hbar(doc, [x[0] for x in by_model], [(ch['ram'], [x[4] for x in by_model]),
                                                    (ch['load'], [x[5] for x in by_model])],
                    title=ch['cost'], language=lang, max_items=30, value_format=lambda v: _f(v, 1, t),
                    note=ch['cost_note'] % _f(evaluate.load_bounds(hw)[1], 1, t))
    if discarded:
        doc.paragraph(m['discarded'] % len(discarded), 8.4, color=pdf.MUTED)

    doc.heading(m['conclusions'])
    doc.bullets(paras, size=9)
    glossary(doc, t)
    name = 'avaliacao-ia-%s-%s.pdf' % (ev['model'].replace(':', '_').replace('/', '_'),
                                      time.strftime('%Y%m%d-%H%M', time.localtime(ev['finished'] or time.time())))
    return name, doc.finish()


def final_pdf(db, plan_id, language=None):
    """ :return: (filename, bytes): ranking per scenario, the indication matrix and the recommended route """
    from ai import scenarios as routing_mod
    t = strings(language)
    lang = t['_lang']
    evaluate.ensure(db)
    rows, discarded = evaluate.history(db, language=lang)
    rec = evaluate.recommend(rows, language=lang)
    best = evaluate.best_by_scenario(rows)
    hw = evaluate.reference_hardware(db)
    f = t['final']
    col = t['col']
    ch = t['charts']
    doc = _doc(f['doc_title'], t)
    doc.title_block(f['title'], f['subtitle'] % (plan_id if plan_id is not None else '—',
                                                 evaluate.hardware_line(hw, lang) if hw else f['no_measurement']))
    method_box(doc, evaluate.WEIGHTS, t)
    doc.heading(f['route'])
    table = []
    for sid, r in rec['per_scenario'].items():
        table.append([sid, r.get('model') or f['keep'], _chip(r['indication'], t) if r.get('model') else '—',
                      r.get('mode') or '—', _f(r.get('timeout'), 0, t), r.get('why') or ''])
    doc.table([col['scenario'], col['model'], col['indication'], col['mode'], 'timeout', col['reason']], table,
              widths=[0.2, 0.26, 0.13, 0.08, 0.08, 0.25], size=7.4)
    if rec['pair']:
        doc.note(f['pair'] % (' + '.join(rec['pair']), '; '.join('%s -> %s' % (k, v or f['current']) for k, v in
                                                                rec['consolidated'].items())),
                 label=f['pair_label'])
    doc.heading(f['ranking'])
    for sid in routing_mod.CATALOG:
        items = best.get(sid) or []
        doc.subheading(sid, keep=40)
        if not items:
            doc.paragraph(f['not_measured'], 8.4, color=pdf.MUTED)
            continue
        doc.table(['#', col['model'], col['eff'], col['perf'], col['score'], 'p95 (s)', col['indication']],
                  [[str(i + 1), x['model'], _f(x['effectiveness'], 0, t), _f(x['performance'], 0, t),
                    _f(x['composite'], 0, t), _f(x.get('p95'), 0, t), _chip(x['indication'], t)]
                   for i, x in enumerate(items[:6])],
                  widths=[0.05, 0.4, 0.1, 0.1, 0.1, 0.1, 0.15], size=7.6)
    by_model = _by_model(rows)
    if by_model:
        doc.heading(f['map'])
        charts.hbar(doc, [x[0] for x in by_model], [(ch['avg_score'], [x[3] for x in by_model])],
                    title=f['avg_per_model'], language=lang, max_items=30, value_format=lambda v: _f(v, 0, t))
        charts.scatter(doc, [{'x': x[2], 'y': x[1], 'series': 0, 'label': str(i + 1)} for i, x in enumerate(by_model)],
                       title=f['scatter'], language=lang, x_label=ch['avg_perf'], y_label=ch['avg_eff'],
                       guides={'y': evaluate.INDICATED_EFF}, series=[f['models']],
                       y_range=_y_range([x[1] for x in by_model]))
    if discarded:
        doc.paragraph(f['discarded'] % '; '.join('%s/%s (%s)' % (d['model'], d['scenario'], d['discarded'])
                                                 for d in discarded[:12]), 8, color=pdf.MUTED)
    glossary(doc, t)
    return 'avaliacao-ia-final-%s.pdf' % time.strftime('%Y%m%d-%H%M'), doc.finish()
