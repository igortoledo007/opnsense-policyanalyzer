"""
Reports of the per scenario evaluation: the PDF of a model and the final one (valid PDF, several pages, pt-BR
texts, hardware recorded), the markdown comparison for docs/ia-local-catalogo.md, the e-mail text of a finished
model and the new charts (scatter, ranges).  Unit tests with fakes: nothing here is a measurement.
"""

import re
import zlib

from eval_fakes import WORKSTATION, FIREWALL, EvalCase, doc

from ai import bench, eval_fixtures, eval_pdf, evaluate
from reports import charts, pdf


def pdf_text(data):
    """ the text operators of every content stream (Flate) """
    out = []
    for m in re.finditer(rb'stream\n(.*?)\nendstream', data, re.S):
        try:
            body = zlib.decompress(m.group(1))
        except zlib.error:
            body = m.group(1)
        out += [t.decode('latin-1') for t in re.findall(rb'\((.*?)\) Tj', body)]
    return ' '.join(out)


def all_docs(text_ok=True):
    out = []
    for fx in eval_fixtures.FIXTURES:
        text = 'Resposta em português com %s.' % fx['subject'] if text_ok else ''
        out.append(doc(fx['id'], text=text, wall=60.0))
    return out


class TestPdf(EvalCase):
    def test_model_pdf_opens_and_has_pages(self):
        self.evaluation('outro:7b', all_docs(), FIREWALL)
        eid = self.evaluation('m:1b', all_docs() + [doc('notify-quarantine'), doc('notify-quarantine')], FIREWALL)
        name, data = eval_pdf.model_pdf(self.db, eid)
        self.assertTrue(name.startswith('avaliacao-ia-m_1b-') and name.endswith('.pdf'))
        self.assertTrue(data.startswith(b'%PDF-1.4'))
        self.assertTrue(data.rstrip().endswith(b'%%EOF'))
        pages = int(re.search(rb'/Count (\d+)', data).group(1))
        self.assertGreaterEqual(pages, 4)
        text = pdf_text(data)
        for needle in ('Setup of the tested model', 'Hardware I measured on', 'Results per scenario',
                       'Comparison with the history', 'Conclusions', 'Why each metric matters', 'N100'):
            self.assertIn(pdf.winansi(needle).decode('latin-1'), text, needle)

    def test_pdf_flags_a_measurement_outside_the_firewall(self):
        eid = self.evaluation('workstation:1b', all_docs(), WORKSTATION)
        _name, data = eval_pdf.model_pdf(self.db, eid)
        self.assertIn('OUTSIDE THE FIREWALL', pdf_text(data))

    def test_final_pdf_and_markdown(self):
        self.evaluation('a:3b', all_docs(), FIREWALL)
        self.evaluation('b:8b', all_docs(text_ok=False), FIREWALL)
        self.evaluation('workstation:1b', all_docs(), WORKSTATION)
        _name, data = eval_pdf.final_pdf(self.db, None)
        self.assertTrue(data.startswith(b'%PDF-'))
        self.assertIn('Recommended route', pdf_text(data))
        md = evaluate.report_md(self.db)
        self.assertIn('## Per scenario evaluation', md)
        self.assertIn('| notification_summary |', md)
        self.assertIn('a:3b', md)
        self.assertIn('left out', md)
        self.assertIn('N100', md)

    def test_round_summary_saves_the_pdf_and_lists_the_comparison(self):
        plan = self.plan()
        rnd = self.db.execute('SELECT * FROM rounds WHERE plan_id = ?', (plan['id'],)).fetchone()
        bench.add_steps(self.db, rnd['id'], bench.expand(self.db, plan, rnd))
        eid = self.db.execute('SELECT id FROM eval_models').fetchone()[0]
        evaluate.on_step_done(self.db, {'kind': 'eval_setup', 'params': '{"eval_id": %d}' % eid, 'round_id': rnd['id'],
                                        'model': 'm:1b'}, {'hardware': FIREWALL, 'digest': 'sha256:z', 'ram_gib': 2})
        for d in all_docs():
            evaluate.record_run(self.db, {'id': 1, 'round_id': rnd['id'], 'model': 'm:1b', 'scenario': d['scenario'],
                                          'params': {'fixture': d['fixture'], 'rep': 1}}, d, eid)
        status, title, text, attachments = evaluate.round_summary(self.db, plan, rnd)
        self.assertEqual(title, 'Model evaluated: m:1b')
        self.assertIn('Hardware: Intel(R) N100', text)
        self.assertIn('Best so far', text)
        self.assertEqual(len(attachments), 1)
        with open(attachments[0], 'rb') as fh:
            self.assertTrue(fh.read(5) == b'%PDF-')


class TestCharts(EvalCase):
    def test_scatter_and_ranges_draw(self):
        d = pdf.Document('t')
        self.assertEqual(charts.scatter(d, [{'x': 50, 'y': 90, 'label': '1', 'ring': True},
                                            {'x': 20, 'y': 40, 'label': '2', 'series': 1}],
                                        title='s', guides={'y': 80}, series=['a', 'b']), 'chart')
        self.assertEqual(charts.ranges(d, ['x', 'y'], [(10, 20, 30, 40), (5, 6, 7, 8)], title='r',
                                       limits=[600, 600]), 'chart')
        self.assertEqual(charts.scatter(d, [], title='vazio'), 'empty')
        self.assertTrue(d.finish().startswith(b'%PDF-'))
