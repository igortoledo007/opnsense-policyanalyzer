"""
Vector charts of the PDFs (reports/charts.py), the metrics read from the local SQLite bases (collect.metrics),
their integration in the periodic report and in the notification attachment, and the weekly report.
Fictitious data only (chart_fixtures.py); no network.

Sample PDFs for a visual check: PA_CHART_SAMPLE=<dir> python3 -m unittest test_charts
(writes <dir>/relatorio-diario.pdf)
"""

import email
import email.policy
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest

import rhelpers  # noqa: F401  (sys.path of the plugin scripts)
from rhelpers import ReportsCase

import chart_fixtures  # noqa: E402
import i18n  # noqa: E402
from reports import charts, collect, deliver, notify, pdf, pdfreport, settings  # noqa: E402
from test_pdf import parse, sample_data, SAMPLE_SUMMARY  # noqa: E402
from test_reports import own_settings  # noqa: E402


def text_of(doc):
    return b'\n'.join(op for page in doc.pages for op in page)


def lit(text):
    """ text as it appears inside a PDF string literal (parentheses escaped) """
    return pdf._literal(pdf.winansi(text))[1:-1]


def poppler(blob, tool):
    """ pdfinfo / pdftotext output when poppler is installed locally, else None """
    exe = shutil.which(tool)
    if not exe:
        return None
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as handle:
        handle.write(blob)
        name = handle.name
    try:
        args = [exe, name] + (['-'] if tool == 'pdftotext' else [])
        res = subprocess.run(args, capture_output=True, timeout=30)
        return res.returncode, res.stdout.decode('utf-8', 'replace')
    finally:
        os.unlink(name)


class NumbersTest(unittest.TestCase):
    def test_pt_br_and_en(self):
        self.assertEqual(charts.fmt(31877, 'pt_BR'), '31.877')
        self.assertEqual(charts.fmt(31877), '31,877')                          # en_US is the default
        self.assertEqual(charts.fmt(1234567.891, 'pt_BR', 2), '1.234.567,89')
        self.assertEqual(charts.fmt(2.5, 'pt_BR', 1), '2,5')
        self.assertEqual(charts.fmt(31877, 'en_US'), '31,877')
        self.assertEqual(charts.fmt(2.5, 'en_US', 1), '2.5')
        self.assertEqual(charts.fmt(-0.2), '0')
        # a missing or unknown language falls back to en_US (reports, PDF and the saved settings)
        self.assertEqual(settings.validate({})['language'], 'en_US')
        self.assertEqual(pdfreport.strings(None)['_lang'], 'en_US')
        self.assertEqual(pdfreport.strings('xx_YY')['ch_q_flow'], i18n.section('en_US', 'chart')['ch_q_flow'])
        self.assertEqual(pdfreport.strings('xx_YY')['_lang'], 'en_US')
        self.assertEqual(pdfreport.num(31877), '31,877')
        self.assertEqual(charts.fmt(None), '-')
        self.assertEqual(charts.compact(12000, 'pt_BR'), '12 mil')
        self.assertEqual(charts.compact(1500000, 'pt_BR'), '1,5 mi')
        self.assertEqual(charts.compact(1500000), '1.5M')
        self.assertEqual(charts.compact(950), '950')
        self.assertEqual(charts.compact(0.5, 'pt_BR', 1), '0,5')
        self.assertEqual(charts.fmt_bytes(1536, 'pt_BR'), '1,5 KB')
        self.assertEqual(charts.fmt_seconds(5.26, 'pt_BR'), '5,3 s')
        self.assertEqual(charts.fmt_seconds(600), '10.0 min')

    def test_nice_scale(self):
        self.assertEqual(charts.nice_scale(87), (0, 100, 20))
        low, high, step = charts.nice_scale(9120, 0, 4)
        self.assertIn(step / 10 ** int(len(str(int(step))) - 1), (1, 2, 5))
        self.assertGreaterEqual(high, 9120)
        self.assertEqual(charts.nice_scale(3, 0, 4, integer=True), (0, 3, 1))
        self.assertEqual(charts.nice_scale(0), (0, 1, 0.2))
        self.assertEqual(charts.nice_scale(0.37, 0, 4)[2], 0.1)
        self.assertEqual(charts.nice_scale(80, 40, 4), (40, 80, 10))
        for raw in (0.013, 0.3, 7, 13, 45, 260, 7300):
            step = charts.nice_step(raw)
            mantissa = step / 10 ** __import__('math').floor(__import__('math').log10(step))
            self.assertIn(round(mantissa, 6), (1, 2, 5, 10))
            self.assertGreaterEqual(step, raw)
        self.assertEqual(charts.ticks_of(0, 100, 25), [0, 25, 50, 75, 100])
        self.assertEqual(charts.decimals_for(0.25), 1)
        self.assertEqual(charts.decimals_for(5), 0)

    def test_percentile_and_buckets(self):
        self.assertEqual(collect.percentile([5, 1, 3, 2, 4], 50), 3)
        self.assertEqual(collect.percentile(list(range(1, 11)), 90), 9)
        self.assertIsNone(collect.percentile([], 50))
        now = int(time.mktime((2026, 11, 9, 7, 0, 0, 0, 0, -1)))
        self.assertEqual(len(collect.Buckets(now - 6 * 3600, now).starts), 6)
        self.assertEqual(len(collect.Buckets(now - 86400, now).starts), 24)
        since, until = deliver.period('weekly', now)
        week = collect.Buckets(since, until)
        self.assertEqual(len(week.starts), 7)
        self.assertEqual(week.step, 86400)
        self.assertEqual(time.localtime(since).tm_wday, 0)                     # Monday 00:00 ... Sunday 24:00
        self.assertEqual(time.localtime(until)[3:6], (0, 0, 0))
        self.assertEqual(charts.bucket_labels(week.starts, 86400, 'pt_BR')[:2], ['seg 02', 'ter 03'])
        self.assertEqual(charts.bucket_labels(week.starts, 86400)[6], 'Sun 08')
        self.assertEqual(week.series([(since + 10, 2), (until - 1, 3), (until, 9), (since - 1, 9)]),
                         [2, 0, 0, 0, 0, 0, 3])


class ChartDrawTest(unittest.TestCase):
    def doc(self):
        return pdf.Document('Teste', compress=False)

    def test_vbar_grouped_and_stacked(self):
        doc = self.doc()
        self.assertEqual(charts.vbar(doc, ['07h', '08h', '09h'], [('novos', [3, 0, 12]), ('liberados', [1, 2, 0])],
                                     'Quarentena', 'pt_BR'), 'chart')
        self.assertEqual(charts.vbar(doc, ['a', 'b'], [('alta', [1, 2]), ('baixa', [3, 4])], 'Pilha', stacked=True,
                                     styles=[charts.SEVERITY['high'], charts.SEVERITY['low']]), 'chart')
        ops = text_of(doc)
        self.assertIn(b'(Quarentena) Tj', ops)
        self.assertIn(b'(novos) Tj', ops)                      # legend
        self.assertIn(b'(12) Tj', ops)                         # value label
        self.assertIn(b'(6) Tj', ops)                          # stacked total
        self.assertIn(b're W n', ops)                          # hatch clipped to the bar (black and white)
        self.assertRegex(ops, rb'\d re f')

    def test_hbar_line_donut(self):
        doc = self.doc()
        charts.hbar(doc, ['203.0.113.10', '203.0.113.11'], [('', [9120, 600])], 'Top IPs', 'pt_BR', mono=True)
        charts.hbar(doc, ['p'], [('p50', [1.5]), ('p90', [4.0])], 'Latência', 'pt_BR',
                    value_format=lambda v: charts.fmt_seconds(v, 'pt_BR'))
        charts.line(doc, ['01h', '02h', '03h', '04h'], [('a', [1, 5, None, 2]), ('b', [2, 2, 2, 2])], 'Série',
                    'pt_BR', area=True, highlight=[1])
        charts.donut(doc, [('telefone', 12), ('pc', 4), ('tv', 3)], 'Tipos', 'pt_BR')
        ops = text_of(doc)
        self.assertIn(b'(9.120) Tj', ops)
        self.assertIn(b'/F3', ops)                             # addresses in Courier
        self.assertIn(b'(1,5 s) Tj', ops)
        self.assertIn(b'[4 2] 0 d', ops)                       # dashed second series
        self.assertIn(pdf.winansi('(ponto anômalo) Tj'), ops)
        self.assertIn(b' c ', ops)                             # Bezier arcs (ring, markers)
        self.assertIn(b'(19) Tj', ops)                         # donut centre = total
        self.assertIn(b'(12  \\(63,2%\\)) Tj', ops)

    def test_empty_series(self):
        doc = self.doc()
        self.assertEqual(charts.vbar(doc, ['a', 'b'], [('', [0, 0])], 'Vazio', 'pt_BR'), 'empty')
        self.assertEqual(charts.hbar(doc, [], [('', [])], 'Vazio', 'pt_BR'), 'empty')
        self.assertEqual(charts.line(doc, ['a'], [('', [None])], 'Vazio', 'pt_BR'), 'empty')
        self.assertEqual(charts.donut(doc, [('a', 0)], 'Empty'), 'empty')                  # en_US by default
        self.assertFalse(charts.sparkline(doc, 0, 0, 50, 10, []))
        ops = text_of(doc)
        self.assertEqual(ops.count(pdf.winansi('(sem dados no período) Tj')), 3)
        self.assertIn(b'(no data in the period) Tj', ops)
        self.assertEqual(charts.line(doc, ['a', 'b'], [('', [0, 0])], 'Postura', low=0, high=100), 'chart')

    def test_overview_and_valid_pdf(self):
        doc = pdf.Document('Teste')
        charts.overview(doc, [{'label': 'Bloqueios', 'value': '31.877', 'values': [1, 4, 2, 8], 'delta': '+5%',
                               'hint': 'por hora'},
                              {'label': 'IA', 'value': '0', 'values': []}], 'pt_BR', 'Visão geral')
        for i in range(12):            # forces page breaks: a chart never splits between pages
            charts.vbar(doc, ['%02dh' % h for h in range(24)], [('', [(h * 7 + i) % 11 for h in range(24)])],
                        'Gráfico %d' % i)
        blob = doc.finish()
        info = parse(blob, self)
        self.assertGreater(info['pages'], 2)
        out = poppler(blob, 'pdfinfo')
        if out is not None:
            self.assertEqual(out[0], 0)
            self.assertIn('PDF version:     1.4', out[1])
        out = poppler(blob, 'pdftotext')
        if out is not None:
            self.assertIn('Visão geral', out[1])
            self.assertIn('31.877', out[1])
            self.assertIn('Gráfico 11', out[1])


class MetricsTest(ReportsCase):
    def setUp(self):
        super().setUp()
        self.now = int(time.time()) // 3600 * 3600 + 120
        chart_fixtures.build_all(self.tmp, self.now, 86400)

    def test_metrics_from_the_bases(self):
        m = collect.metrics(self.now - 86400, self.now)
        n = len(m['buckets']['starts'])
        self.assertEqual(m['buckets']['step'], 3600)
        db = sqlite3.connect(self.path('quarantine.db'))
        enters = db.execute("SELECT count(*) FROM events WHERE kind IN ('enter', 'upgrade') AND ts >= ? AND ts < ?",
                            (self.now - 86400, self.now)).fetchone()[0]
        db.close()
        q = m['quarantine']
        self.assertEqual(len(q['new']), n)
        self.assertEqual(sum(q['new']) + sum(q['repeat']), enters)
        self.assertTrue(q['top_asn'])
        self.assertTrue(set(q['by_duration']) <= set('123456'))
        self.assertIn('blocked', m['traffic'])
        self.assertEqual(m['traffic']['source'], 'incidents')
        self.assertIn('previous', m['traffic'])
        self.assertTrue(set(m['incidents']['opened']) <= {'critical', 'high', 'medium', 'low'})
        self.assertTrue(m['anomalies']['flagged'])
        self.assertEqual(len(m['anomalies']['volume']), n)
        self.assertTrue(m['devices']['by_type'])
        self.assertGreaterEqual(len(m['posture']['points']), 14)
        ai = m['ai']
        self.assertEqual(ai['source'], 'audit')
        self.assertTrue(ai['by_route'])
        for value in ai['latency'].values():
            self.assertLessEqual(value['p50'], value['p90'])
        self.assertTrue(ai['shadow'])
        self.assertEqual(m['collectors'][0]['base'], 'dns')
        flat = repr(m)
        self.assertNotIn('203.0.113', flat)                     # aggregates only: no address in the metrics
        self.assertNotIn('192.0.2', flat)
        self.assertNotIn('FICTITIOUS', flat)                      # never the prompt of the audit log

    def test_missing_and_old_bases(self):
        for name in ('incidents.db', 'anomalies.db', 'posture.db', 'ai-queue.db', 'shadowai.db', 'ai.log',
                     'ai.log.1'):
            os.unlink(self.path(name))
        shutil.rmtree(self.path('collect'))
        os.unlink(self.path('devices.db'))
        db = sqlite3.connect(self.path('devices.db'))           # old schema: no user_type
        db.execute('CREATE TABLE devices (id INTEGER PRIMARY KEY, first_seen INTEGER, auto_type TEXT)')
        db.execute("INSERT INTO devices VALUES (1, ?, 'tv')", (self.now - 60,))
        db.commit()
        db.close()
        with open(self.path('quarantine.db'), 'r+b') as handle:  # damaged base
            handle.write(b'not a sqlite file at all' * 4)
        m = collect.metrics(self.now - 86400, self.now)
        self.assertEqual(set(m) - {'buckets'}, {'devices'})
        self.assertEqual(m['devices']['by_type'], {'tv': 1})
        self.assertEqual(collect.metrics(self.now - 3600, self.now, sections=['findings']).keys(), {'buckets'})

    def test_daily_report_with_charts(self):
        cfg = settings.load()
        rep = deliver.build_report('daily', cfg, self.now, ai=False)
        self.assertIn('metrics', rep['data'])
        name, blob, error = deliver.build_pdf(rep, cfg)
        self.assertIsNone(error)
        self.assertLess(len(blob), pdfreport.MAX_BYTES)
        info = parse(blob, self)
        for text in ('Visão geral do período', 'Quarentena por hora: novos, liberados e reincidentes',
                     'Top ASN (ofensas na quarentena)', 'Incidentes abertos e fechados no período, por severidade',
                     'Volume de saída da LAN por hora, anomalias destacadas', 'Uso da IA',
                     'Latência por cenário (p50 / p90)',
                     'Pontuação de postura (0-100, últimos 14 dias)', 'Coletores locais: dns'):
            self.assertIn(lit(text), info['text'], text)
        self.assertNotIn('metrics', __import__('json').dumps(
            __import__('reports.aisum', fromlist=['x']).report_inputs(rep['data']), default=str))
        cfg['report']['charts'] = False
        rep = deliver.build_report('daily', cfg, self.now, ai=False)
        self.assertNotIn('metrics', rep['data'])
        _n, plain, _e = deliver.build_pdf(rep, cfg)
        self.assertNotIn(lit('Visão geral do período'), parse(plain, self)['text'])
        if os.environ.get('PA_CHART_SAMPLE'):
            self._samples(os.environ['PA_CHART_SAMPLE'])

    def test_weekly_report(self):
        cfg = settings.load()
        self.assertTrue(cfg['report']['weekly'])
        rep = deliver.build_report('weekly', cfg, self.now, ai=False)
        data = rep['data']
        self.assertEqual(data['until'] - data['since'], 7 * 86400)
        self.assertEqual(len(data['metrics']['buckets']['starts']), 7)
        self.assertIn('(semanal)', rep['subject'])
        _n, blob, error = deliver.build_pdf(rep, cfg)
        self.assertIsNone(error)
        self.assertIn(b'SEMANAL', parse(blob, self)['text'])

    def test_notification_attachment(self):
        cfg = own_settings(self.smtp.port)
        cfg['notify']['enabled'] = True
        cfg['notify']['ai_summary'] = False
        settings.save(cfg)
        notify.run(now=self.now, smtp_factory=self.smtp.factory())               # baseline
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 10, 1, 'upgrade', 5)
        notify.run(now=self.now + 60, smtp_factory=self.smtp.factory())
        self.assertEqual(len(self.smtp.messages), 1)
        msg = email.message_from_string(self.smtp.messages[0]['data'], policy=email.policy.default)
        parts = list(msg.iter_parts())
        self.assertEqual([p.get_content_type() for p in parts], ['multipart/alternative', 'application/pdf'])
        self.assertRegex(parts[1].get_filename(), r'^opnsense-alerta-quarantine-long-\d{4}-\d{2}-\d{2}-\d{4}\.pdf$')
        info = parse(parts[1].get_content(), self)
        self.assertIn(lit('Alerta do firewall: Quarentena longa'), info['text'])
        self.assertIn(lit('Contexto (últimas 24 h)'), info['text'])
        self.assertIn(lit('Quarentenas aplicadas no período, por duração'), info['text'])
        cfg['notify']['attach_pdf'] = False
        settings.save(cfg)
        self.smtp.messages.clear()
        rhelpers.add_quarantine_event(self.path('quarantine.db'), self.now + 7200, 1, 'extend', 5)
        notify.run(now=self.now + 7300, smtp_factory=self.smtp.factory())
        self.assertEqual(len(self.smtp.messages), 1)
        self.assertNotIn('application/pdf', self.smtp.messages[0]['data'])

    def _samples(self, out):
        os.makedirs(out, exist_ok=True)
        data = sample_data(self.now)
        data['metrics'] = collect.metrics(self.now - 86400, self.now)
        _name, blob = pdfreport.report(data, {'ai': True, 'text': SAMPLE_SUMMARY}, 'pt_BR', 'fw.exemplo.test',
                                       base='https://fw.exemplo.test:8443')
        with open(os.path.join(out, 'relatorio-diario.pdf'), 'wb') as handle:
            handle.write(blob)


class CronWeeklyTest(unittest.TestCase):
    def test_desired_and_steps(self):
        from reports import actions
        cfg = settings.validate({'report': {'enabled': True, 'daily': True, 'every_6h': False}})
        want = actions.desired_crons(cfg)
        self.assertEqual(want['report_weekly'], {'minutes': '30', 'hours': '7', 'weekdays': '1'})
        steps = actions.cron_steps(want, {'report_weekly': {'minutes': '30', 'hours': '7', 'weekdays': '*',
                                                            'enabled': True}})
        self.assertIn('model.php cron_set report_weekly 30 7 1', [s['command'] for s in steps])
        steps = actions.cron_steps({'report_weekly': want['report_weekly']},
                                   {'report_weekly': {'minutes': '30', 'hours': '7', 'weekdays': '1', 'enabled': True}})
        self.assertEqual(steps, [])
        cfg = settings.validate({'report': {'enabled': True, 'weekly': False}})
        self.assertNotIn('report_weekly', actions.desired_crons(cfg))
        with self.assertRaises(ValueError):
            settings.validate({'report': {'weekly_day': 7}})

    def test_sections_upgrade(self):
        old = list(settings.SECTIONS_V1)
        self.assertEqual(settings.validate({'report': {'sections': old}})['report']['sections'],
                         old + list(settings.CHART_SECTIONS))
        self.assertEqual(settings.validate({'report': {'sections': ['quarantine']}})['report']['sections'],
                         ['quarantine'])
        self.assertEqual(settings.validate({'report': {'sections': old, 'sections_version': 2}})['report']['sections'],
                         old)


if __name__ == '__main__':
    unittest.main()
