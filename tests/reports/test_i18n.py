"""
Catalogs of the report texts (i18n/<language>.json) and the PDF writer with other alphabets:

  - every catalog has the keys of en_US (a missing translation is allowed only because the loader falls back,
    key by key, to the "fallback" language and then to English; the test lists what is missing per language)
  - the placeholders (%s, %d, %.1f, %%) of a translation are the ones of en_US, in the same order
  - en_US and pt_BR are complete; normalize / fallback / number formats / resolve ('auto' = GUI language)
  - PDFs generated in en_US and pt_BR (base-14 fonts only), and with an embedded TrueType for Cyrillic / Greek
    when a font is available here (the copy of the OPNsense theme in tema/referencia, else DejaVu); CJK and
    Persian fall back to an English PDF

Fictitious data only.
"""

import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest

import rhelpers  # noqa: F401  (sys.path of the plugin scripts)

import i18n  # noqa: E402
from reports import charts, pdf, pdfreport, render, ttf  # noqa: E402
from test_pdf import parse, sample_data, SAMPLE_SUMMARY  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
THEME_FONTS = os.path.join(REPO, 'tema', 'referencia', 'www', 'themes', 'opnsense', 'build', 'fonts')
FONT_CANDIDATES = (
    (os.path.join(THEME_FONTS, 'SourceSansPro-Regular', 'SourceSansPro-Regular.ttf'),
     os.path.join(THEME_FONTS, 'SourceSansPro-Bold', 'SourceSansPro-Bold.ttf')),
    ('/usr/share/fonts/dejavu/DejaVuSans.ttf', '/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf'),
    ('/usr/local/share/fonts/dejavu/DejaVuSans.ttf', '/usr/local/share/fonts/dejavu/DejaVuSans-Bold.ttf'),
)


def font_pair():
    for regular, bold in FONT_CANDIDATES:
        if ttf.load(regular):
            return regular, bold if ttf.load(bold) else regular
    return None


def own(language):
    return i18n.flatten({k: v for k, v in i18n.raw(language).items() if k != '_meta'})


REFERENCE = i18n.flatten({k: v for k, v in i18n.raw('en_US').items() if k not in ('_meta', 'format')})


class FontEnv(object):
    """ POLICYANALYZER_PDF_FONTS for one block, the font cache of pdf.py reset before and after """

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self.saved = os.environ.get('POLICYANALYZER_PDF_FONTS')
        os.environ['POLICYANALYZER_PDF_FONTS'] = self.value
        pdf.reset_fonts()
        i18n.reset()
        return self

    def __exit__(self, *_exc):
        if self.saved is None:
            os.environ.pop('POLICYANALYZER_PDF_FONTS', None)
        else:
            os.environ['POLICYANALYZER_PDF_FONTS'] = self.saved
        pdf.reset_fonts()
        i18n.reset()


class CatalogTest(unittest.TestCase):
    def test_every_language_has_a_valid_catalog(self):
        self.assertEqual(len(i18n.LANGUAGES), 20)
        for code in i18n.LANGUAGES:
            with open(i18n.path(code), encoding='utf-8') as handle:
                data = json.load(handle)
            self.assertEqual(data['_meta']['language'], code)
            self.assertTrue(data['_meta']['name'])
            fmt = data['format']
            for key in ('decimal', 'thousands', 'datetime', 'hour', 'day_month'):
                self.assertTrue(fmt.get(key), '%s format.%s' % (code, key))
            self.assertNotEqual(fmt['decimal'], fmt['thousands'], code)

    def test_no_key_outside_the_reference(self):
        """ a key en_US does not have is a typo of the translator: it would never be read """
        for code in i18n.LANGUAGES:
            extra = sorted(k for k in set(own(code)) - set(REFERENCE) if not k.startswith('format.'))
            self.assertEqual(extra, [], '%s: keys that en_US does not have: %s' % (code, extra))

    def test_missing_keys_fall_back_and_are_listed(self):
        """ missing translations are allowed: the loader falls back key by key; the list goes to stderr """
        lines = []
        for code in i18n.LANGUAGES:
            missing = i18n.missing(code)
            merged = i18n.flatten(i18n.catalog(code))
            for key in REFERENCE:
                self.assertFalse(i18n.empty(merged.get(key)), '%s: %s has no text even after the fallback' % (code,
                                                                                                           key))
            if missing:
                sections = {}
                for key in missing:
                    sections[key.split('.')[0]] = sections.get(key.split('.')[0], 0) + 1
                lines.append('  %s: %d of %d keys missing -> %s (%s)' % (
                    code, len(missing), len(REFERENCE), ' -> '.join(i18n.chain(code)[1:]),
                    ', '.join('%s %d' % kv for kv in sorted(sections.items()))))
        if lines:
            sys.stderr.write('\ni18n: untranslated keys (they read the fallback language):\n%s\n' % '\n'.join(lines))

    def test_en_us_and_pt_br_are_complete(self):
        self.assertEqual(i18n.missing('en_US'), [])
        self.assertEqual(i18n.missing('pt_BR'), [])
        self.assertEqual({k for k in own('pt_BR') if not k.startswith('format.')}, set(REFERENCE))

    def test_placeholders_match_the_reference(self):
        for code in i18n.LANGUAGES:
            for key, value in own(code).items():
                if key.startswith('format.') or i18n.empty(value) or key not in REFERENCE:
                    continue
                self.assertEqual(i18n.placeholders(value), i18n.placeholders(REFERENCE[key]),
                                 '%s: %s has other placeholders than en_US' % (code, key))
                if isinstance(REFERENCE[key], list):
                    self.assertEqual(len(value), len(REFERENCE[key]), '%s: %s' % (code, key))

    def test_reference_strings_format(self):
        """ every reference string with placeholders formats with dummy values of the right type """
        for key, value in REFERENCE.items():
            if key.startswith('format.') or not isinstance(value, str):
                continue
            args = []
            for ph in i18n.placeholders(value):
                if ph == '%%':
                    continue
                args.append(1 if ph[-1] in 'di' else 1.5 if ph[-1] in 'feEgG' else 'x')
            if args or '%%' in value:
                value % tuple(args)

    def test_normalize(self):
        cases = {'pt': 'pt_BR', 'pt_BR': 'pt_BR', 'pt-pt': 'pt_PT', 'PT_br': 'pt_BR', 'pt_BR.UTF-8': 'pt_BR',
                 'auto': 'en_US', '': 'en_US', None: 'en_US', 'xx_YY': 'en_US', 'en': 'en_US', 'en_GB': 'en_US',
                 'de': 'de_DE', 'de_AT': 'de_DE', 'zh': 'zh_CN', 'zh_HK': 'zh_TW', 'nb': 'no_NO', 'ru_RU': 'ru_RU',
                 'es_MX': 'es_ES', 'fr_CA': 'fr_FR'}
        for given, expected in cases.items():
            self.assertEqual(i18n.normalize(given), expected, given)

    def test_fallback_chain_and_key_by_key(self):
        self.assertEqual(i18n.chain('pt_PT'), ['pt_PT', 'pt_BR', 'en_US'])
        self.assertEqual(i18n.chain('ru_RU'), ['ru_RU', 'en_US'])
        self.assertEqual(i18n.section('pt_PT', 'report')['title'], 'Relatório de segurança')
        tmp = tempfile.mkdtemp(prefix='pa-i18n-')
        saved = i18n.HERE
        try:
            for code in ('en_US', 'pt_BR'):
                shutil.copy(i18n.path(code), tmp)
            with open(os.path.join(tmp, 'de_DE.json'), 'w', encoding='utf-8') as handle:
                json.dump({'_meta': {'language': 'de_DE', 'name': 'Deutsch', 'fallback': 'en_US'},
                           'report': {'title': 'Sicherheitsbericht', 'period': '', 'posture_values': {'exposed': 'offen'}},
                           'weekdays': ['', '', '', '', '', '', '']}, handle)
            i18n.HERE = tmp
            i18n.reset()
            t = i18n.section('de_DE', 'report')
            self.assertEqual(t['title'], 'Sicherheitsbericht')
            self.assertEqual(t['period'], 'Period')                          # empty string: English
            self.assertEqual(t['posture_values'], {'hardened': 'hardened', 'exposed': 'offen', 'critical': 'critical'})
            self.assertEqual(i18n.section('de_DE', 'weekdays')[0], 'Mon')     # list of empty strings: English
            self.assertIn('report.period', i18n.missing('de_DE'))
            self.assertNotIn('report.title', i18n.missing('de_DE'))
            self.assertEqual(i18n.number_format('de_DE')['decimal'], '.')     # no format section: English
            subject = render.report(sample_data(int(time.time())), None, 'de_DE', '', 'fw')[0]
            self.assertIn('Sicherheitsbericht', subject)
        finally:
            i18n.HERE = saved
            i18n.reset()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_number_and_date_formats(self):
        self.assertEqual(i18n.fmt_number(31877.5, 'pt_BR', 1), '31.877,5')
        self.assertEqual(i18n.fmt_number(31877.5, 'en_US', 1), '31,877.5')
        self.assertEqual(i18n.fmt_number(31877.5, 'de_DE', 1), '31.877,5')
        self.assertEqual(i18n.fmt_number(31877.5, 'fr_FR', 1), '31 877,5')
        self.assertEqual(i18n.fmt_number(31877.5, 'zh_CN', 1), '31,877.5')
        self.assertEqual(i18n.fmt_number(None), '-')
        self.assertEqual(i18n.fmt_int(31877, 'pt_BR'), '31.877')
        self.assertEqual(i18n.fmt_int(True, 'pt_BR'), True)
        self.assertEqual(charts.fmt(2.5, 'ru_RU', 1), '2,5')
        ts = time.mktime((2026, 11, 14, 7, 5, 0, 0, 0, -1))
        self.assertEqual(i18n.fmt_date(ts, 'pt_BR'), '14/11/2026 07:05')
        self.assertEqual(i18n.fmt_date(ts, 'de_DE'), '14.11.2026 07:05')
        self.assertEqual(i18n.fmt_date(ts, 'zh_CN'), '2026-11-14 07:05')
        self.assertEqual(charts.bucket_labels([ts], 3600, 'pt_BR'), ['07h'])
        self.assertEqual(charts.bucket_labels([ts], 3600, 'en_US'), ['07:00'])

    def test_resolve_auto_follows_the_gui_language(self):
        tmp = tempfile.mkdtemp(prefix='pa-i18n-')
        try:
            path = os.path.join(tmp, 'config.xml')
            with open(path, 'w') as handle:
                handle.write('<opnsense><system><language>pt_BR</language></system></opnsense>')
            self.assertEqual(i18n.resolve('auto', path), 'pt_BR')
            self.assertEqual(i18n.resolve('', path), 'pt_BR')
            self.assertEqual(i18n.resolve('de', path), 'de_DE')
            self.assertEqual(i18n.resolve('auto', os.path.join(tmp, 'missing.xml')), 'en_US')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ReportPdfTest(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())

    def build(self, language):
        data = sample_data(self.now)
        return pdfreport.report(data, {'ai': True, 'text': SAMPLE_SUMMARY}, language, 'fw.exemplo.test',
                                base='https://fw.exemplo.test:8443')

    def test_pdf_in_en_us_and_pt_br(self):
        with FontEnv('none'):
            for language, needles in (('en_US', ('Security report', 'Posture \\(exposure\\)', 'Quarantine',
                                                 'page 1 of', 'Generated by the Policy Analyzer')),
                                      ('pt_BR', ('Relatório de segurança', 'Postura \\(exposição\\)', 'Quarentena',
                                                 'página 1 de', 'Gerado pelo Policy Analyzer'))):
                name, blob = self.build(language)
                self.assertTrue(name.startswith('opnsense-relatorio-'))
                info = parse(blob, self)
                self.assertGreaterEqual(info['pages'], 2)
                for needle in needles:
                    self.assertIn(pdf.winansi(needle), info['text'], (language, needle))
                self.assertNotIn(b'/Type0', blob)                  # Latin-1 languages: base-14 fonts only
                self.assertLess(len(blob), pdfreport.MAX_BYTES)

    def test_pdf_languages_without_a_font(self):
        """ no TrueType: a Cyrillic catalog cannot be drawn, the PDF is English (never a page of "?") """
        tmp = tempfile.mkdtemp(prefix='pa-i18n-')
        saved = i18n.HERE
        try:
            for code in ('en_US', 'pt_BR', 'fa_IR'):
                shutil.copy(i18n.path(code), tmp)
            with open(os.path.join(tmp, 'ru_RU.json'), 'w', encoding='utf-8') as handle:
                json.dump({'_meta': {'language': 'ru_RU', 'name': 'Русский'},
                           'format': {'decimal': ',', 'thousands': '\u00a0'},
                           'report': {'title': 'Отчёт о безопасности'}}, handle)
            i18n.HERE = tmp
            with FontEnv('none'):
                self.assertEqual(i18n.pdf_language('ru_RU', pdf.can_render), 'en_US')
                self.assertEqual(i18n.pdf_language('fa_IR', pdf.can_render), 'en_US')     # right to left
                self.assertEqual(i18n.pdf_language('pt_BR', pdf.can_render), 'pt_BR')
                _name, blob = self.build('ru_RU')
                self.assertIn(b'Security report', parse(blob, self)['text'])
                self.assertEqual(render.s('ru_RU')['title'], 'Отчёт о безопасности')      # the e-mail keeps it
                d = pdf.Document('t')
                d.paragraph('Отчёт ok')
                self.assertIn(b'(????? ok) Tj', parse(d.finish(), self)['text'])
        finally:
            i18n.HERE = saved
            i18n.reset()
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(font_pair(), 'no TrueType font with Cyrillic here (tema/referencia or DejaVu)')
class UnicodeFontTest(unittest.TestCase):
    def setUp(self):
        self.fonts = '%s%s%s' % (font_pair()[0], os.pathsep, font_pair()[1])

    @staticmethod
    def unicode_text(info):
        """ the text drawn with the embedded font, decoded through its ToUnicode CMap """
        cmap = {}
        for m in re.finditer(rb'<([0-9A-F]{4})> <([0-9A-F]+)>', info['text']):
            cmap[m.group(1).decode()] = bytes.fromhex(m.group(2).decode()).decode('utf-16-be')
        out = []
        for m in re.finditer(rb'<([0-9A-F]+)> Tj', info['text']):
            hexs = m.group(1).decode()
            out.append(''.join(cmap.get(hexs[i:i + 4], '�') for i in range(0, len(hexs), 4)))
        return ' '.join(out)

    def test_subset_is_a_valid_truetype(self):
        regular = ttf.load(font_pair()[0])
        gids = [regular.gid(c) for c in 'Отчёт Ελληνικά ž']
        sub = regular.subset(gids)
        self.assertTrue({b'glyf', b'head', b'hhea', b'hmtx', b'loca', b'maxp'} <= set(ttf.table_tags(sub)))
        self.assertNotIn(b'GSUB', ttf.table_tags(sub))
        self.assertLess(len(sub), len(regular.data) / 2)
        self.assertTrue(regular.has('Ж') and regular.has('λ') and regular.has('ř'))

    def test_cyrillic_greek_and_latin_extended_are_embedded(self):
        with FontEnv(self.fonts):
            self.assertTrue(pdf.can_render('Отчёт Ελληνικά Příliš žluťoučký tiếng Việt'))
            self.assertFalse(pdf.can_render('日本語'))
            d = pdf.Document('Отчёт о безопасности', page_label='стр. %d из %d')
            d.heading('Ελληνικά')
            d.paragraph('Zażółć gęślą jaźń · ação')
            d.table(['Сервис', 'Port'], [['日本', '22']])
            blob = d.finish()
            info = parse(blob, self)
            self.assertIn(b'/Subtype /CIDFontType2', blob)
            self.assertIn(b'/Encoding /Identity-H', blob)
            self.assertIn(b'/FontFile2', blob)
            text = self.unicode_text(info)
            for needle in ('Отчёт о безопасности', 'стр. 1 из 1', 'Ελληνικά', 'Zażółć gęślą jaźń · ação', 'Сервис'):
                self.assertIn(needle, text)
            self.assertIn('??', text)                               # CJK is not in the font: "?"
            self.assertIn(b'(Port) Tj', info['text'])               # WinAnsi text keeps the base-14 font

    def test_pdf_language_with_the_font(self):
        tmp = tempfile.mkdtemp(prefix='pa-i18n-')
        saved = i18n.HERE
        try:
            for code in ('en_US', 'pt_BR'):
                shutil.copy(i18n.path(code), tmp)
            with open(os.path.join(tmp, 'ru_RU.json'), 'w', encoding='utf-8') as handle:
                json.dump({'_meta': {'language': 'ru_RU', 'name': 'Русский'},
                           'format': {'decimal': ',', 'thousands': '\u00a0'},
                           'report': {'title': 'Отчёт о безопасности', 'quarantine': 'Карантин'},
                           'pdf': {'page': 'стр. %d из %d'}}, handle)
            with open(os.path.join(tmp, 'ja_JP.json'), 'w', encoding='utf-8') as handle:
                json.dump({'_meta': {'language': 'ja_JP', 'name': '日本語'},
                           'report': {'title': 'セキュリティレポート'}}, handle)
            i18n.HERE = tmp
            with FontEnv(self.fonts):
                self.assertEqual(i18n.pdf_language('ru_RU', pdf.can_render), 'ru_RU')
                self.assertEqual(i18n.pdf_language('ja_JP', pdf.can_render), 'en_US')   # no CJK glyphs
                self.assertEqual(pdfreport.strings('ja_JP')['title'], 'Security report')
                self.assertEqual(render.s('ja_JP')['title'], 'セキュリティレポート')     # the e-mail keeps it
        finally:
            i18n.HERE = saved
            shutil.rmtree(tmp, ignore_errors=True)

    def test_report_pdf_ru(self):
        self.now = int(time.time())
        tmp = tempfile.mkdtemp(prefix='pa-i18n-')
        saved = i18n.HERE
        try:
            for code in ('en_US', 'pt_BR'):
                shutil.copy(i18n.path(code), tmp)
            with open(os.path.join(tmp, 'ru_RU.json'), 'w', encoding='utf-8') as handle:
                json.dump({'_meta': {'language': 'ru_RU', 'name': 'Русский'},
                           'format': {'decimal': ',', 'thousands': '\u00a0'},
                           'report': {'title': 'Отчёт о безопасности', 'quarantine': 'Карантин'},
                           'pdf': {'page': 'стр. %d из %d'}}, handle)
            i18n.HERE = tmp
            with FontEnv(self.fonts):
                _name, blob = ReportPdfTest.build(self, 'ru_RU')
                info = parse(blob, self)
                text = self.unicode_text(info)
                for needle in ('Отчёт о безопасности', 'Карантин', 'стр. 1 из'):
                    self.assertIn(needle, text)
                self.assertIn(b'(Posture \\(exposure\\)) Tj', info['text'])   # untranslated: English
                self.assertLess(len(blob), pdfreport.MAX_BYTES)
        finally:
            i18n.HERE = saved
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
