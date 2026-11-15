"""
The report as a PDF attachment: the pure Python PDF writer (structure: header, objects, xref offsets, trailer,
startxref, %%EOF, page count, WinAnsi text with Portuguese accents inside the inflated content streams, page
breaks with a long table), the report PDF built from the report data, the e-mail as multipart/mixed
(alternative text + HTML, then application/pdf base64) through the FAKE local SMTP server, the "Attach PDF"
setting, the download (preview ... pdf) and "Send report now". No real e-mail.
Run: cd tests/reports && TMPDIR=<scratch> /usr/bin/python3 -m unittest discover -s . -v
Sample PDF for a visual check: PA_PDF_SAMPLE=<dir> /usr/bin/python3 -m unittest test_pdf  (writes <dir>/exemplo.pdf)
"""

import base64
import email
import email.policy
import os
import re
import unittest
import zlib

import rhelpers  # noqa: F401  (sys.path of the plugin scripts)
from rhelpers import ReportsCase

from reports import cli, deliver, pdf, pdfreport, settings, store  # noqa: E402
from ai import changes  # noqa: E402

from test_reports import own_settings  # noqa: E402

ACCENTS = 'á é í ó ú ã õ ç â ê ô à Á É Ç'


def parse(blob, testcase):
    """ structural check of a PDF written by pdf.Document; returns {objects, pages, text (inflated streams)} """
    testcase.assertTrue(blob.startswith(b'%PDF-1.4\n'))
    testcase.assertTrue(blob.endswith(b'%%EOF\n'))
    start = int(re.search(rb'startxref\n(\d+)\n%%EOF\n$', blob).group(1))
    testcase.assertEqual(blob[start:start + 5], b'xref\n')
    head = re.match(rb'xref\n0 (\d+)\n', blob[start:])
    size = int(head.group(1))
    table = blob[start + head.end():]
    entries = [table[i * 20:(i + 1) * 20] for i in range(size)]
    testcase.assertEqual(entries[0], b'0000000000 65535 f \n')
    objects = {}
    for num in range(1, size):
        entry = entries[num]
        testcase.assertTrue(re.match(rb'^\d{10} 00000 n \n$', entry), entry)
        offset = int(entry[:10])
        testcase.assertTrue(blob[offset:].startswith(b'%d 0 obj\n' % num), 'bad offset of object %d' % num)
        end = blob.index(b'\nendobj\n', offset)
        objects[num] = blob[offset:end]
    trailer = blob[start + head.end() + size * 20:]
    testcase.assertTrue(trailer.startswith(b'trailer\n<< /Size %d /Root 1 0 R' % size))
    pages = [n for n, o in objects.items() if b'/Type /Page ' in o]
    count = int(re.search(rb'/Type /Pages /Kids \[[^\]]*\] /Count (\d+)', objects[2]).group(1))
    testcase.assertEqual(count, len(pages))
    text = b''
    for num, obj in objects.items():
        if b'stream\n' not in obj:
            continue
        length = int(re.search(rb'/Length (\d+)', obj).group(1))
        data = obj[obj.index(b'stream\n') + 7:]
        testcase.assertEqual(data[length:], b'\nendstream')
        data = data[:length]
        text += zlib.decompress(data) if b'/FlateDecode' in obj else data
    return {'objects': objects, 'pages': count, 'text': text}


class WriterTest(unittest.TestCase):
    def test_winansi_and_metrics(self):
        self.assertEqual(pdf.winansi('ação'), b'a\xe7\xe3o')
        self.assertEqual(pdf.winansi('€ “x” – •'), b'\x80 \x93x\x94 \x96 \x95')
        self.assertEqual(pdf.winansi('✓ 日本\tx'), b'? ?? x')
        self.assertEqual(pdf.text_width('a', pdf.REGULAR, 1000), 556)
        self.assertEqual(pdf.text_width('i', pdf.REGULAR, 1000), 222)
        self.assertEqual(pdf.text_width('W', pdf.BOLD, 1000), 944)
        self.assertEqual(pdf.text_width('b', pdf.BOLD, 1000), 611)
        self.assertEqual(pdf.text_width('ç', pdf.REGULAR, 1000), 500)
        self.assertEqual(pdf.text_width('iW', pdf.MONO, 10), 12)
        self.assertEqual(len(pdf.HELVETICA), 224)
        self.assertEqual(len(pdf.HELVETICA_BOLD), 224)

    def test_wrap_by_width(self):
        text = 'Período com pontos de atenção na rede ' * 12
        lines = pdf.wrap(text, pdf.REGULAR, 10, 200)
        self.assertGreater(len(lines), 5)
        for line in lines:
            self.assertLessEqual(pdf.text_width(line, pdf.REGULAR, 10), 200)
        self.assertEqual(' '.join(lines).split(), text.split())
        long_word = pdf.wrap('x' * 200, pdf.REGULAR, 10, 100)
        self.assertTrue(all(pdf.text_width(w, pdf.REGULAR, 10) <= 100 for w in long_word))
        self.assertEqual(''.join(long_word), 'x' * 200)

    def test_structure_and_accents(self):
        for compress in (True, False):
            doc = pdf.Document('Relatório de segurança', header_right='08/11/2026 07:00', footer_left='fw',
                               page_label='página %d de %d', compress=compress)
            doc.title_block('Relatório de segurança', 'Período: ontem até hoje', badge='DIÁRIO')
            doc.kpis([('exposta', 'Postura', '#d97706'), (12, 'Em quarentena', None)])
            doc.note('Resumo com acentuação: ' + ACCENTS, 'Resumo executivo pela IA')
            doc.heading('Quarentena')
            doc.paragraph('Parágrafo (com parênteses) e barra \\ invertida.')
            doc.bullets(['primeiro item', 'segundo item'])
            doc.bars([('Nível 1', 10), ('Nível 2', 3, '#2563eb')], title='Por nível')
            doc.table(['Origem', 'Ofensas'], [['203.0.113.5', '12'], [{'text': 'high', 'chip': '#dc2626'}, '1']])
            info = parse(doc.finish(), self)
            self.assertEqual(info['pages'], 1)
            self.assertIn(pdf.winansi(ACCENTS), info['text'])
            self.assertIn(b'(p\xe1gina 1 de 1)', info['text'])
            self.assertIn(b'(Par\xe1grafo \\(com par\xeanteses\\) e barra \\\\ invertida.)', info['text'])
            self.assertEqual(b'/FlateDecode' in b''.join(info['objects'].values()), compress)
            fonts = b''.join(info['objects'][n] for n in (3, 4, 5))
            for name in (b'/Helvetica ', b'/Helvetica-Bold ', b'/Courier '):
                self.assertIn(name, fonts)
            self.assertEqual(fonts.count(b'/Encoding /WinAnsiEncoding'), 3)

    def test_long_table_breaks_pages(self):
        doc = pdf.Document('Tabela longa', page_label='página %d de %d')
        doc.heading('Origens')
        rows = [['198.51.100.%d' % (i % 250), 'Linha número %d com um texto razoavelmente comprido para quebrar '
                 'em mais de uma linha dentro da coluna' % i, str(i)] for i in range(220)]
        doc.table(['Origem', 'Descrição', 'Ofensas'], rows, widths=[0.25, 0.6, 0.15], align='llr')
        info = parse(doc.finish(), self)
        self.assertGreaterEqual(info['pages'], 5)
        total = info['pages']
        for n in range(1, total + 1):
            self.assertIn(b'(p\xe1gina %d de %d)' % (n, total), info['text'])
        self.assertEqual(info['text'].count(b'(Descri\xe7\xe3o)'), total)         # header repeated on every page
        self.assertIn(b'(219)', info['text'])
        # every drawn row stays between the footer and the header
        for match in re.finditer(rb'([\d.]+) ([\d.]+) Td \((\d+)\) Tj', info['text']):
            self.assertGreater(float(match.group(2)), pdf.MARGIN + pdf.FOOTER_H - 1)


class ReportPdfTest(ReportsCase):
    def build(self, **cfg_extra):
        cfg = settings.load()
        for key, value in cfg_extra.items():
            cfg[key].update(value)
        return deliver.build_report('daily', cfg, self.now, ai=False), cfg

    def test_report_pdf_from_data(self):
        rep, cfg = self.build()
        name, blob, error = deliver.build_pdf(rep, cfg)
        self.assertIsNone(error)
        self.assertRegex(name, r'^opnsense-relatorio-\d{4}-\d{2}-\d{2}-\d{4}\.pdf$')
        self.assertLess(len(blob), pdfreport.MAX_BYTES)
        info = parse(blob, self)
        for text in ('Relatório de segurança', 'Quarentena', 'RESUMO AUTOMÁTICO', 'CVEs relevantes', '203.0.113.5',
                     'CVE-2099-1000', 'Rule is shadowed', 'Top reincidentes', 'Dispositivos da rede', 'Top portas'):
            self.assertTrue(pdf.winansi(text) in info['text'], text)
        self.assertIn(b'corrigido em 2.6.1', info['text'])
        if sample_dir():
            name, big = pdfreport.report(sample_data(self.now), {'ai': True, 'text': SAMPLE_SUMMARY}, 'pt_BR',
                                         'fw.exemplo.test', base='https://fw.exemplo.test:8443')
            with open(os.path.join(sample_dir(), 'exemplo.pdf'), 'wb') as handle:
                handle.write(big)

    def test_sections_and_english(self):
        cfg = settings.load()
        cfg['language'] = 'en_US'
        cfg['report']['sections'] = ['quarantine']
        rep = deliver.build_report('6h', cfg, self.now, ai=False)
        _name, blob, _err = deliver.build_pdf(rep, cfg)
        info = parse(blob, self)
        self.assertIn(b'(Quarantine)', info['text'])
        self.assertNotIn(b'(Relevant CVEs)', info['text'])
        self.assertRegex(info['text'], rb'\(page 1 of \d\)')
        self.assertNotIn(b'(AI usage)', info['text'])          # chart sections follow the selected sections

    def test_preview_pdf_download(self):
        res = cli.run(['preview', 'manual', 'pdf'])
        self.assertEqual(res['status'], 'ok')
        blob = base64.b64decode(res['pdf'])
        self.assertEqual(res['size'], len(blob))
        parse(blob, self)
        self.assertNotIn('html', res)
        plain = cli.run(['preview', 'manual', '-'])
        self.assertNotIn('pdf', plain)
        self.assertTrue(plain['attach_pdf'])
        self.assertEqual(plain['pdf_name'], res['name'])
        self.assertFalse(os.path.exists(self.path('reports.db')))          # preview stores nothing

    def test_setting_default_and_validation(self):
        self.assertTrue(settings.load()['report']['attach_pdf'])
        cfg = settings.load()
        cfg['report']['attach_pdf'] = 'false'
        self.assertFalse(settings.validate(cfg)['report']['attach_pdf'])
        plan = changes.run('plan', 'reports_settings', [self.payload(cfg)])
        self.assertIn('report.attach_pdf: True -> False', plan['info'][0]['items'])


class MailPdfTest(ReportsCase):
    def sent(self):
        self.assertEqual(len(self.smtp.messages), 1)
        return email.message_from_string(self.smtp.messages[0]['data'], policy=email.policy.default)

    def test_report_mail_with_pdf(self):
        settings.save(own_settings(self.smtp.port, report={'enabled': True}))
        res = deliver.send_report('daily', scheduled=True, smtp_factory=self.smtp.factory())
        self.assertEqual(res['status'], 'sent', res)
        msg = self.sent()
        self.assertEqual(msg.get_content_type(), 'multipart/mixed')
        parts = list(msg.iter_parts())
        self.assertEqual([p.get_content_type() for p in parts], ['multipart/alternative', 'application/pdf'])
        self.assertEqual([p.get_content_type() for p in parts[0].iter_parts()], ['text/plain', 'text/html'])
        att = parts[1]
        self.assertEqual(att.get_content_disposition(), 'attachment')
        self.assertEqual(att['Content-Transfer-Encoding'], 'base64')
        self.assertRegex(att.get_filename(), r'^opnsense-relatorio-\d{4}-\d{2}-\d{2}-\d{4}\.pdf$')
        blob = att.get_content()
        parse(blob, self)
        self.assertLess(len(blob), 300 * 1024)
        self.assertEqual(res['pdf'], {'name': att.get_filename(), 'size': len(blob)})
        db = store.connect(readonly=True)
        _total, rows = store.messages(db, kind='report')
        stored = store.message(db, rows[0]['id'])
        db.close()
        self.assertEqual(stored['summary']['pdf']['name'], att.get_filename())

    def test_attach_pdf_off(self):
        settings.save(own_settings(self.smtp.port, report={'enabled': True, 'attach_pdf': False}))
        res = deliver.send_report('daily', scheduled=True, smtp_factory=self.smtp.factory())
        self.assertEqual(res['status'], 'sent', res)
        msg = self.sent()
        self.assertEqual(msg.get_content_type(), 'multipart/alternative')
        self.assertNotIn('application/pdf', self.smtp.messages[0]['data'])

    def test_pdf_failure_does_not_block_the_mail(self):
        settings.save(own_settings(self.smtp.port, report={'enabled': True}))
        original = pdfreport.report

        def broken(*_a, **_k):
            raise RuntimeError('font table exploded')
        pdfreport.report = broken
        try:
            res = deliver.send_report('daily', scheduled=True, smtp_factory=self.smtp.factory())
        finally:
            pdfreport.report = original
        self.assertEqual(res['status'], 'sent', res)
        self.assertIn('font table exploded', res['pdf']['error'])
        self.assertEqual(self.sent().get_content_type(), 'multipart/alternative')

    def test_send_report_now_attaches_pdf(self):
        settings.save(own_settings(self.smtp.port))
        plan = changes.run('plan', 'reports_send_test', ['report'])
        self.assertIn('PDF attached', plan['steps'][0]['effect'])
        deliver.SMTP_FACTORY = self.smtp.factory()
        try:
            res = changes.run('apply', 'reports_send_test', ['report'])
        finally:
            deliver.SMTP_FACTORY = None
        self.assertTrue(res['done'], res)
        msg = self.sent()
        self.assertEqual(msg.get_content_type(), 'multipart/mixed')
        pdfs = [p for p in msg.iter_attachments() if p.get_content_type() == 'application/pdf']
        self.assertEqual(len(pdfs), 1)
        parse(pdfs[0].get_content(), self)

    def test_test_message_has_no_attachment(self):
        settings.save(own_settings(self.smtp.port))
        deliver.SMTP_FACTORY = self.smtp.factory()
        try:
            changes.run('apply', 'reports_send_test', ['test'])
        finally:
            deliver.SMTP_FACTORY = None
        self.assertEqual(self.sent().get_content_type(), 'multipart/alternative')


# ---------------------------------------------------------------------- fictitious sample for a visual check

SAMPLE_SUMMARY = ('Período com pontos de atenção. Foram bloqueadas 31.877 conexões de entrada na WAN, com 8 origens '
                  'novas em quarentena, principalmente varreduras de SSH e Telnet. Há 2 vulnerabilidades P1, uma '
                  'delas no catálogo KEV da CISA (OpenSSL), e a postura passou de protegida para exposta. Sugestão: '
                  'atualizar o OpenSSL para 3.0.16 e revisar a exposição da interface web na porta 8443.')


def sample_dir():
    return os.environ.get('PA_PDF_SAMPLE')


def sample_data(now):
    countries = ['NL', 'CN', 'RU', 'US', 'BR']
    return {
        'kind': 'daily', 'since': now - 86400, 'until': now,
        'posture': {'available': True, 'posture': 'exposed', 'services': 6, 'reachable': 2, 'maybe_reachable': 1,
                    'admin_reachable': 1, 'cves_total': 14, 'kev': 1, 'generated': None, 'changed': True,
                    'previous': {'posture': 'hardened', 'kev': 0},
                    'attack_surface': [{'service': 'OpenVPN', 'proto': 'udp', 'port': 1194, 'reachable': 'sim',
                                        'cves': 2, 'kev': 0},
                                       {'service': 'Interface web (lighttpd)', 'proto': 'tcp', 'port': 8443,
                                        'reachable': 'talvez', 'cves': 5, 'kev': 1}]},
        'quarantine': {'available': True, 'installed': True, 'paused': False, 'active': 37,
                       'by_level': {'1': 12, '2': 9, '3': 7, '4': 5, '5': 3, '6': 1}, 'new': 8, 'expired': 4,
                       'offenses': 152, 'by_reason': {'base': 70, 'scan': 51, 'bait': 22, 'suricata': 9},
                       'top_period': [{'addr': '203.0.113.%d' % (i + 1), 'level': 6 - i, 'country': c,
                                       'asn': 64500 + i, 'offenses': 40 - 6 * i, 'total': 90 - 7 * i}
                                      for i, c in enumerate(countries)],
                       'top_repeat': [{'addr': '198.51.100.%d' % (i + 1), 'level': 5 - i, 'country': c,
                                       'offenses': 30 - 4 * i} for i, c in enumerate(countries)]},
        'findings': {'available': True, 'rules': 42, 'findings': 7,
                     'by_severity': {'high': 1, 'medium': 3, 'low': 2, 'info': 1},
                     'top': [{'severity': 'high', 'type': 'shadowed',
                              'title': 'Regra de liberação sombreada por regra anterior mais genérica',
                              'rule': 'pass in on lan from any to 192.0.2.10 port 22'},
                             {'severity': 'medium', 'type': 'permissive',
                              'title': 'Regra permissiva: qualquer origem para qualquer destino na DMZ',
                              'rule': 'pass in on opt1'}]},
        'traffic': {'available': True, 'events': 48211, 'blocked_in': 31877, 'passed': 15000,
                    'distinct_sources': 2214, 'complete': True,
                    'top_ports': [{'port': p, 'blocked': v} for p, v in
                                  [('22/tcp', 9120), ('23/tcp', 6011), ('3389/tcp', 4120), ('445/tcp', 2210),
                                   ('5060/udp', 980)]],
                    'top_sources': [{'addr': '203.0.113.%d' % (10 + i), 'blocked': 900 - 120 * i} for i in range(5)],
                    'top_countries': [{'country': c, 'blocked': v} for c, v in
                                      [('CN', 8800), ('US', 6100), ('NL', 4300), ('RU', 3900), ('BR', 1200)]],
                    'country_source': 'índice GeoIP da quarentena'},
        'cves': {'available': True, 'counts': {'P1': 2, 'P2': 3, 'P3': 6, 'P4': 3}, 'total': 14, 'kev': 1,
                 'review_pending': 2,
                 'top': [{'cve': 'CVE-2099-1000', 'package': 'openssl', 'version': '3.0.15', 'priority': 'P1',
                          'kev': True, 'epss': 0.91, 'cvss': 9.8, 'exposure': 'internet', 'fixed_in': '3.0.16',
                          'why': 'Explorada ativamente (KEV), serviço alcançável da internet, correção disponível.'},
                         {'cve': 'CVE-2099-1001', 'package': 'lighttpd', 'version': '1.4.76', 'priority': 'P1',
                          'kev': False, 'epss': 0.42, 'cvss': 8.1, 'exposure': 'talvez', 'fixed_in': None,
                          'why': 'Interface de gerência possivelmente exposta; EPSS alto.'},
                         {'cve': 'CVE-2099-1002', 'package': 'unbound', 'version': '1.22.0', 'priority': 'P2',
                          'kev': False, 'epss': 0.05, 'cvss': 7.5, 'exposure': 'lan', 'fixed_in': '1.22.1',
                          'why': 'Negação de serviço no resolvedor, só a partir da LAN.'}]},
        'devices': {'available': True, 'total': 41, 'present': 33, 'unknown': 5, 'new_count': 2, 'by_risk': {},
                    'new': [{'name': 'câmera-portão', 'vendor': 'Hikvision', 'type': 'câmera', 'ip': '192.168.1.77',
                             'interface': 'IoT', 'risk': 'high'},
                            {'name': '-', 'vendor': 'Apple', 'type': 'telefone', 'ip': '192.168.1.80',
                             'interface': 'LAN', 'risk': 'low'}]},
        'notifications': {'available': True, 'sent': 5,
                          'by_type': [{'type': 'incident', 'severity': 'high', 'count': 2},
                                      {'type': 'device_new', 'severity': 'medium', 'count': 3}]},
    }


if __name__ == '__main__':
    unittest.main()
