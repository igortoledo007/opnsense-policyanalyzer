"""
Language of the reports of the per scenario evaluation (PDFs, e-mails, markdown of ai/evaluate.py, ai/bench.py and
ai/compute.py): ai.language of the settings, "auto" = the GUI language (system/language of config.xml), en_US by
default; the texts come from the catalogs i18n/<language>.json.  The models are still tested in Brazilian
Portuguese (evaluate.LANG): that never changes with the report language.  Unit tests with fakes.
"""

import os
import re
import shutil
import tempfile
import zlib

from eval_fakes import FIREWALL, EvalCase, doc

import i18n
from ai import bench, compute, eval_fixtures, eval_pdf, evaluate


def pdf_text(data):
    out = []
    for m in re.finditer(rb'stream\n(.*?)\nendstream', data, re.S):
        try:
            body = zlib.decompress(m.group(1))
        except zlib.error:
            body = m.group(1)
        out += [t.decode('cp1252', 'replace') for t in re.findall(rb'\((.*?)\) Tj', body)]
    return ' '.join(out)


def all_docs():
    return [doc(fx['id'], text='Resposta em português com %s.' % fx['subject'], wall=60.0)
            for fx in eval_fixtures.FIXTURES]


CONFIG = """<?xml version="1.0"?>
<opnsense><system><language>%s</language></system>
<OPNsense><policyanalyzer><ai><language>%s</language></ai></policyanalyzer></OPNsense></opnsense>
"""


class ConfigCase(EvalCase):
    def setUp(self):
        super(ConfigCase, self).setUp()
        self.cfg_dir = tempfile.mkdtemp(prefix='pa-eval-i18n-')
        self.saved_cfg = os.environ.get('POLICYANALYZER_CONFIG')
        evaluate._LANG_CACHE.clear()

    def tearDown(self):
        if self.saved_cfg is None:
            os.environ.pop('POLICYANALYZER_CONFIG', None)
        else:
            os.environ['POLICYANALYZER_CONFIG'] = self.saved_cfg
        evaluate._LANG_CACHE.clear()
        shutil.rmtree(self.cfg_dir, ignore_errors=True)
        super(ConfigCase, self).tearDown()

    def config(self, gui, ai):
        path = os.path.join(self.cfg_dir, 'config-%s-%s.xml' % (gui, ai))
        with open(path, 'w') as handle:
            handle.write(CONFIG % (gui, ai))
        os.environ['POLICYANALYZER_CONFIG'] = path
        return path


class TestReportLanguage(ConfigCase):
    def test_choice_of_the_language(self):
        os.environ['POLICYANALYZER_CONFIG'] = os.path.join(self.cfg_dir, 'missing.xml')
        self.assertEqual(evaluate.report_language(), 'en_US')
        self.config('de_DE', 'pt_BR')
        self.assertEqual(evaluate.report_language(), 'pt_BR')            # ai.language wins
        self.config('de_DE', 'auto')
        self.assertEqual(evaluate.report_language(), 'de_DE')            # auto: the GUI language
        self.config('xx_YY', 'auto')
        self.assertEqual(evaluate.report_language(), 'en_US')            # unknown: English
        self.assertEqual(evaluate.report_language('pt'), 'pt_BR')        # explicit argument
        self.assertEqual(evaluate.LANG, 'pt_BR')                         # the models are tested in pt-BR

    def test_reports_follow_the_settings(self):
        eid = self.evaluation('m:1b', all_docs(), FIREWALL)
        self.config('en_US', 'pt_BR')
        text = pdf_text(eval_pdf.model_pdf(self.db, eid)[1])
        for needle in ('Setup do modelo testado', 'Hardware onde medi', 'Resultados por cenário', 'Conclusões',
                       'Por que cada métrica importa', 'página 1 de'):
            self.assertIn(needle, text)
        self.assertIn('Rota recomendada por cenário', pdf_text(eval_pdf.final_pdf(self.db, 1)[1]))
        md = evaluate.report_md(self.db)
        self.assertIn('## Avaliação por cenário (efetividade × performance)', md)
        self.assertIn('| Cenário | 1º | 2º | 3º |', md)
        self.assertIn('Cenário', evaluate.scoreboard_text(self.db))
        self.assertIn('Intel(R) N100, 4 núcleos, 31,8 GiB', evaluate.hardware_line(FIREWALL))
        self.assertIn('## 2. Resultado por cenário e modelo', bench.report_md(self.db))
        self.config('pt_BR', 'en_US')
        self.assertIn('Setup of the tested model', pdf_text(eval_pdf.model_pdf(self.db, eid)[1]))
        self.assertIn('## Per scenario evaluation', evaluate.report_md(self.db))

    def test_explicit_language_and_mails(self):
        self.evaluation('outro:7b', all_docs(), FIREWALL)
        plan = self.plan()
        status, title, text = evaluate.start_mail(self.db, plan, 'pt_BR')
        self.assertEqual(title, 'Avaliação por cenário iniciada')
        self.assertIn('Comecei o plano de avaliação por cenário', text)
        lines, _attachments = evaluate.final_mail(self.db, plan, 'pt_BR')
        self.assertIn('Rota recomendada (somente recomendação; nada foi alterado):', lines)
        self.assertIn('indício: vale mais amostras', evaluate.scoreboard_text(self.db, language='pt_BR'))
        rec = evaluate.recommend(evaluate.history(self.db)[0], language='pt_BR')
        self.assertTrue(any(r['why'].startswith('nota ') for r in rec['per_scenario'].values() if r.get('model')))
        rec_en = evaluate.recommend(evaluate.history(self.db)[0], language='en_US')
        self.assertTrue(any(r['why'].startswith('score ') for r in rec_en['per_scenario'].values() if r.get('model')))
        mem = {'ram_gib': 31.7, 'mem_modules': [{}], 'mem_type': 'DDR5', 'mem_speed': 4800, 'mem_channels': 1,
               'mem_bandwidth_gbs': 38.4}
        self.assertEqual(compute.memory_text(mem, 'pt_BR'), '31,7 GiB, 1 × DDR5-4800 em canal único (38,4 GB/s teóricos)')
        self.assertEqual(compute.memory_text(mem, 'en_US'),
                         '31.7 GiB, 1 × DDR5-4800 in a single channel (38.4 GB/s theoretical)')
        self.assertEqual(compute.short({'jail_threads': 2, 'jail_cores': 2, 'jail_cpus': '2-3'}, 'pt_BR'),
                         '2 threads em 2 núcleos (cpus 2-3)')
        self.assertEqual(len(bench.executive_summary(self.db, plan['id'], 'pt_BR')), 10)
        self.assertTrue(bench.executive_summary(self.db, plan['id'], 'pt_BR')[0].startswith('1. Preset recomendado'))

    def test_language_without_glyphs_writes_an_english_pdf(self):
        """ a catalog the PDF fonts cannot draw (no TrueType here) gives an English PDF, never a page of "?" """
        eid = self.evaluation('m:1b', all_docs(), FIREWALL)
        tmp = tempfile.mkdtemp(prefix='pa-eval-i18n-')
        saved_dir, saved_fonts = i18n.HERE, os.environ.get('POLICYANALYZER_PDF_FONTS')
        try:
            for code in ('en_US', 'pt_BR'):
                shutil.copy(i18n.path(code), tmp)
            with open(os.path.join(tmp, 'ru_RU.json'), 'w', encoding='utf-8') as handle:
                handle.write('{"_meta": {"language": "ru_RU"}, "eval_pdf": {"model": {"setup": "Настройка модели"}}}')
            i18n.HERE = tmp
            i18n.reset()
            os.environ['POLICYANALYZER_PDF_FONTS'] = 'none'
            from reports import pdf
            pdf.reset_fonts()
            self.assertEqual(eval_pdf.strings('ru_RU')['_lang'], 'en_US')
            self.assertIn('Setup of the tested model', pdf_text(eval_pdf.model_pdf(self.db, eid, 'ru_RU')[1]))
            self.assertEqual(evaluate.texts('ru_RU', 'eval_pdf')['model']['setup'], 'Настройка модели')
        finally:
            i18n.HERE = saved_dir
            i18n.reset()
            if saved_fonts is None:
                os.environ.pop('POLICYANALYZER_PDF_FONTS', None)
            else:
                os.environ['POLICYANALYZER_PDF_FONTS'] = saved_fonts
            from reports import pdf
            pdf.reset_fonts()
            shutil.rmtree(tmp, ignore_errors=True)
