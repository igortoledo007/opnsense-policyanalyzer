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

    Minimal PDF writer in pure Python (stdlib only: the firewall has no PDF library and none is installed).

      - PDF 1.4, A4 portrait, the base-14 fonts Helvetica, Helvetica-Bold and Courier (never embedded) with
        /WinAnsiEncoding for every text that fits in WinAnsi (English, Portuguese, Spanish, French, German,
        Italian, Norwegian accents: á é í ó ú ã õ ç â ê ô à ü ø ...)
      - any other text (Greek, Cyrillic, Czech / Polish / Turkish / Vietnamese letters, ...) is drawn, line by
        line, with an embedded subset of a TrueType font found on the system (ttf.find: Source Sans Pro of the
        OPNsense theme), Type0 / Identity-H with a ToUnicode map (copy and search work). Characters that font does
        not have (CJK, Arabic / Persian with Source Sans Pro), or every non-WinAnsi character when no font is
        found, become "?"; can_render(text) tells beforehand (i18n.pdf_language uses it to write the PDF in
        English instead). No shaping and no right to left: Persian is never drawn even with a font
      - line breaking by width with the real Helvetica / Helvetica-Bold metrics (AFM widths 32..255 in WinAnsi
        order below; Courier is 600 for every glyph)
      - flow layout with automatic page breaks: title block, section headings, paragraphs, bullet lists,
        tables with a header row (repeated after a page break) and zebra rows, KPI cards, horizontal bars,
        a highlighted note box
      - header (title + date) and footer ("page N of M") drawn on every page once the page count is known
      - optional Flate compression of the content streams (zlib)

    Usage:
        doc = Document('Title', header_right='08/11/2026 07:00', footer_left='fw.example', page_label='page %d of %d')
        doc.heading('Section'); doc.paragraph('text'); doc.table(['A', 'B'], [['1', '2']])
        data = doc.finish()          # bytes of the PDF
"""

import hashlib
import time
import zlib

from . import ttf

PAGE_W = 595.28
PAGE_H = 841.89
MARGIN = 42.0
HEADER_H = 34.0                 # space above the content used by the running header
FOOTER_H = 30.0

REGULAR, BOLD, MONO = 'F1', 'F2', 'F3'
BASE_FONTS = {REGULAR: 'Helvetica', BOLD: 'Helvetica-Bold', MONO: 'Courier'}
# embedded Unicode font used for the texts outside WinAnsi: U1 regular (also for MONO), U2 bold
UNICODE_KEY = {REGULAR: 'U1', BOLD: 'U2', MONO: 'U1'}

# Adobe AFM widths (1/1000 em) of the WinAnsi codes 32..255; 0 = code not defined in WinAnsi (never emitted)
HELVETICA = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,   # 32-47
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,   # 48-63
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,  # 64-79
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,   # 80-95
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,   # 96-111
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 0,     # 112-127
    556, 0, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0,      # 128-143
    0, 222, 222, 333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 0, 500, 667,     # 144-159
    278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333,   # 160-175
    400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611,   # 176-191
    667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,  # 192-207
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,   # 208-223
    556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278,   # 224-239
    556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500,   # 240-255
)
HELVETICA_BOLD = (
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,   # 32-47
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,   # 48-63
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,   # 64-79
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,   # 80-95
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,   # 96-111
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584, 0,     # 112-127
    556, 0, 278, 556, 500, 1000, 556, 556, 333, 1000, 667, 333, 1000, 0, 611, 0,      # 128-143
    0, 278, 278, 500, 500, 350, 556, 1000, 333, 1000, 556, 333, 944, 0, 500, 667,     # 144-159
    278, 333, 556, 556, 556, 556, 280, 556, 333, 737, 370, 556, 584, 333, 737, 333,   # 160-175
    400, 584, 333, 333, 333, 611, 556, 278, 333, 333, 365, 556, 834, 834, 834, 611,   # 176-191
    722, 722, 722, 722, 722, 722, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,  # 192-207
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,   # 208-223
    556, 556, 556, 556, 556, 556, 889, 556, 556, 556, 556, 556, 278, 278, 278, 278,   # 224-239
    611, 611, 611, 611, 611, 611, 611, 584, 611, 611, 611, 611, 611, 556, 611, 556,   # 240-255
)
WIDTHS = {REGULAR: HELVETICA, BOLD: HELVETICA_BOLD}

# WinAnsiEncoding (cp1252) 0x80..0x9F; 0x20..0x7E and 0xA0..0xFF are the same code points as Latin-1
WINANSI_HIGH = {0x20AC: 0x80, 0x201A: 0x82, 0x0192: 0x83, 0x201E: 0x84, 0x2026: 0x85, 0x2020: 0x86, 0x2021: 0x87,
                0x02C6: 0x88, 0x2030: 0x89, 0x0160: 0x8A, 0x2039: 0x8B, 0x0152: 0x8C, 0x017D: 0x8E, 0x2018: 0x91,
                0x2019: 0x92, 0x201C: 0x93, 0x201D: 0x94, 0x2022: 0x95, 0x2013: 0x96, 0x2014: 0x97, 0x02DC: 0x98,
                0x2122: 0x99, 0x0161: 0x9A, 0x203A: 0x9B, 0x0153: 0x9C, 0x017E: 0x9E, 0x0178: 0x9F}

# sober palette; orange of OPNsense for the titles
ORANGE = '#d94f00'
TEXT = '#1f2937'
MUTED = '#6b7280'
RULE = '#d1d5db'
ZEBRA = '#f5f7fa'
HEAD_BG = '#eceff3'
CARD_BG = '#f8fafc'
NOTE_BG = '#fff5ee'
BAR = '#d94f00'


_FONTS = []                     # [] = not searched yet; [None] = none; [(regular, bold)]


def unicode_fonts():
    """ :return: (regular, bold) ttf.TrueType of the system (cached) or None """
    if not _FONTS:
        _FONTS.append(ttf.find())
    return _FONTS[0]


def reset_fonts():
    """ search the fonts again (tests change POLICYANALYZER_PDF_FONTS) """
    del _FONTS[:]


def encodable(text):
    """ True when the text fits in WinAnsi (drawn with the base-14 fonts) """
    text = '' if text is None else str(text)
    if text.isascii():
        return True
    for ch in text:
        code = ord(ch)
        if not (0x20 <= code <= 0x7E or 0xA0 <= code <= 0xFF or code in WINANSI_HIGH or ch in '\t\r\n'):
            return False
    return True


def _ufont(font):
    fonts = unicode_fonts()
    if not fonts:
        return None
    return fonts[1] if font == BOLD else fonts[0]


def can_render(text):
    """ True when every character of the text can be drawn (WinAnsi, or the embedded Unicode font) """
    text = '' if text is None else str(text)
    if encodable(text):
        return True
    font = _ufont(REGULAR)
    bold = _ufont(BOLD)
    return bool(font) and all(encodable(ch) or (font.has(ch) and bold.has(ch)) for ch in text)


def _plain(text):
    return ''.join(' ' if ch in '\t\r\n' else ch for ch in text)


def winansi(text):
    """ unicode -> WinAnsi bytes; tabs / line breaks become spaces, other characters outside WinAnsi "?" """
    out = bytearray()
    for ch in '' if text is None else str(text):
        code = ord(ch)
        if 0x20 <= code <= 0x7E or 0xA0 <= code <= 0xFF:
            out.append(code)
        elif code in WINANSI_HIGH:
            out.append(WINANSI_HIGH[code])
        elif ch in '\t\r\n':
            out.append(0x20)
        else:
            out.append(0x3F)
    return bytes(out)


def text_width(text, font=REGULAR, size=10.0):
    if not isinstance(text, bytes) and not encodable(text):
        uni = _ufont(font)
        if uni:
            return uni.width(_plain(str(text))) * size / 1000.0
    raw = text if isinstance(text, bytes) else winansi(text)
    if font == MONO:
        return len(raw) * 600 * size / 1000.0
    table = WIDTHS.get(font, HELVETICA)
    return sum(table[b - 32] if b >= 32 else 0 for b in raw) * size / 1000.0


def wrap(text, font=REGULAR, size=10.0, width=100.0):
    """ greedy line breaking on spaces; words wider than the line are cut by characters """
    lines = []
    for para in ('' if text is None else str(text)).split('\n'):
        words = para.split()
        if not words:
            lines.append('')
            continue
        line = ''
        for word in words:
            cand = word if not line else line + ' ' + word
            if text_width(cand, font, size) <= width:
                line = cand
                continue
            if line:
                lines.append(line)
            while text_width(word, font, size) > width and len(word) > 1:
                cut = len(word) - 1
                while cut > 1 and text_width(word[:cut], font, size) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            line = word
        lines.append(line)
    return lines


def fit(text, font=REGULAR, size=10.0, width=100.0):
    """ one line, cut with "..." when wider than width """
    text = '' if text is None else str(text)
    if text_width(text, font, size) <= width:
        return text
    while text and text_width(text + '...', font, size) > width:
        text = text[:-1]
    return text + '...'


def _num(value):
    text = ('%.2f' % value).rstrip('0').rstrip('.')
    return '0' if text in ('-0', '') else text


def _rgb(color):
    color = (color or '#000000').lstrip('#')
    if len(color) == 3:
        color = ''.join(c * 2 for c in color)
    return ' '.join(_num(int(color[i:i + 2], 16) / 255.0) for i in (0, 2, 4))


def _literal(raw):
    return b'(' + raw.replace(b'\\', b'\\\\').replace(b'(', b'\\(').replace(b')', b'\\)') + b')'


def _utf16(text):
    """ text string of the document information dictionary (any Unicode) """
    return b'<FEFF' + str(text).encode('utf-16-be').hex().upper().encode() + b'>'


def _cell(value):
    cell = dict(value) if isinstance(value, dict) else {'text': value}
    cell['text'] = '' if cell.get('text') is None else str(cell['text'])
    return cell


class Document(object):
    def __init__(self, title, header_right='', footer_left='', page_label='%d / %d', compress=True,
                 author='OPNsense Policy Analyzer', created=None):
        self.title = title
        self.header_right = header_right
        self.footer_left = footer_left
        self.page_label = page_label
        self.compress = compress
        self.author = author
        self.created = time.time() if created is None else created
        self.width = PAGE_W - 2 * MARGIN
        self.left = MARGIN
        self.top = PAGE_H - MARGIN - HEADER_H
        self.bottom = MARGIN + FOOTER_H
        self.pages = []
        self.unicode_used = {}          # 'U1' / 'U2' -> {gid: character}
        self.new_page()

    # ------------------------------------------------------------------ primitives

    def new_page(self):
        self.pages.append([])
        self.y = self.top

    def ensure(self, height):
        """ start a new page when <height> does not fit below the cursor; True when a page was added """
        if self.y - height < self.bottom and self.y < self.top:
            self.new_page()
            return True
        return False

    def _op(self, data):
        self.pages[-1].append(data if isinstance(data, bytes) else data.encode('latin-1'))

    def text(self, x, y, value, font=REGULAR, size=10.0, color=TEXT):
        if value is not None and not encodable(value) and _ufont(font):
            return self._unicode_text(x, y, _plain(str(value)), font, size, color)
        raw = winansi(value)
        if raw:
            self._op(b'BT /' + font.encode() + b' ' + _num(size).encode() + b' Tf ' + _rgb(color).encode() +
                     b' rg ' + _num(x).encode() + b' ' + _num(y).encode() + b' Td ' + _literal(raw) + b' Tj ET')

    def _unicode_text(self, x, y, value, font, size, color):
        key = UNICODE_KEY.get(font, 'U1')
        uni = _ufont(font)
        used = self.unicode_used.setdefault(key, {})
        gids = []
        for ch in value:
            gid = uni.gid(ch)
            gids.append(gid)
            used.setdefault(gid, ch if uni.has(ch) else '?')
        if gids:
            self._op(b'BT /' + key.encode() + b' ' + _num(size).encode() + b' Tf ' + _rgb(color).encode() + b' rg ' +
                     _num(x).encode() + b' ' + _num(y).encode() + b' Td <' +
                     ''.join('%04X' % g for g in gids).encode() + b'> Tj ET')

    def text_right(self, x_right, y, value, font=REGULAR, size=10.0, color=TEXT):
        self.text(x_right - text_width(value, font, size), y, value, font, size, color)

    def rect(self, x, y, w, h, fill=None, stroke=None, line_width=0.5):
        """ (x, y) is the lower left corner """
        ops = []
        if fill:
            ops.append('%s rg' % _rgb(fill))
        if stroke:
            ops.append('%s RG %s w' % (_rgb(stroke), _num(line_width)))
        ops.append('%s %s %s %s re %s' % (_num(x), _num(y), _num(w), _num(h),
                                          'B' if fill and stroke else ('f' if fill else 'S')))
        self._op(' '.join(ops))

    def line(self, x1, y1, x2, y2, color=RULE, line_width=0.5):
        self._op('%s RG %s w %s %s m %s %s l S' % (_rgb(color), _num(line_width), _num(x1), _num(y1), _num(x2),
                                                    _num(y2)))

    def chip(self, x, y_top, value, color, size=7.0):
        """ small filled label (severity, priority); returns its width """
        w = text_width(value, BOLD, size) + 6
        h = size + 4
        self.rect(x, y_top - h, w, h, fill=color)
        self.text(x + 3, y_top - h + 2.6, value, BOLD, size, '#ffffff')
        return w

    # ------------------------------------------------------------------ flow elements

    def spacer(self, height=6.0):
        self.y -= height

    def title_block(self, title, subtitle='', badge=None):
        self.ensure(60)
        self.text(self.left, self.y - 18, fit(title, BOLD, 18, self.width), BOLD, 18, ORANGE)
        self.y -= 26
        if subtitle:
            for line in wrap(subtitle, REGULAR, 9.5, self.width):
                self.text(self.left, self.y - 10, line, REGULAR, 9.5, MUTED)
                self.y -= 13
        if badge:
            self.chip(self.left, self.y - 2, badge, '#374151', 7.5)
            self.y -= 15
        self.y -= 6

    def heading(self, value, keep=48.0):
        """ section title; <keep> points of the following content stay with it on the same page """
        self.ensure(26 + keep)
        if self.y < self.top:
            self.y -= 10
        self.text(self.left, self.y - 12, fit(value, BOLD, 12.5, self.width), BOLD, 12.5, ORANGE)
        self.y -= 17
        self.line(self.left, self.y, self.left + self.width, self.y, ORANGE, 0.8)
        self.y -= 7

    def subheading(self, value, keep=30.0):
        self.ensure(16 + keep)
        self.text(self.left, self.y - 9.5, fit(value, BOLD, 9.5, self.width), BOLD, 9.5, TEXT)
        self.y -= 15

    def paragraph(self, value, size=9.5, font=REGULAR, color=TEXT, indent=0.0, space_after=4.0):
        lead = size * 1.38
        for line in wrap(value, font, size, self.width - indent):
            self.ensure(lead)
            self.text(self.left + indent, self.y - size, line, font, size, color)
            self.y -= lead
        self.y -= space_after

    def bullets(self, items, size=9.5, color=TEXT):
        lead = size * 1.38
        for item in items:
            lines = wrap(item, REGULAR, size, self.width - 12)
            for i, line in enumerate(lines):
                self.ensure(lead)
                if i == 0:
                    self.text(self.left + 2, self.y - size, '•', BOLD, size, ORANGE)
                self.text(self.left + 12, self.y - size, line, REGULAR, size, color)
                self.y -= lead
        self.y -= 4

    def note(self, value, label=None, extra=None, color=ORANGE, background=NOTE_BG, size=9.5):
        """ highlighted box (executive summary); falls back to plain paragraphs when taller than a page """
        lead = size * 1.42
        inner = self.width - 22
        lines = wrap(value, REGULAR, size, inner)
        extra_lines = wrap(extra, REGULAR, 8, inner) if extra else []
        height = 12 + (12 if label else 0) + len(lines) * lead + len(extra_lines) * 11 + 6
        if height > self.top - self.bottom:
            if label:
                self.subheading(label)
            self.paragraph(value, size)
            if extra:
                self.paragraph(extra, 8, color=MUTED)
            return
        self.ensure(height)
        y0 = self.y
        self.rect(self.left, y0 - height, self.width, height, fill=background)
        self.rect(self.left, y0 - height, 3.5, height, fill=color)
        y = y0 - 8
        if label:
            self.text(self.left + 12, y - 8, label.upper(), BOLD, 7.5, color)
            y -= 13
        for line in lines:
            self.text(self.left + 12, y - size, line, REGULAR, size, TEXT)
            y -= lead
        for line in extra_lines:
            self.text(self.left + 12, y - 8, line, REGULAR, 8, MUTED)
            y -= 11
        self.y = y0 - height - 8

    def kpis(self, items, height=50.0, value_size=17.0, columns=None):
        """ number cards: items = [(value, label, color or None)] """
        if not items:
            return
        cols = columns or len(items)
        gap = 8.0
        w = (self.width - gap * (cols - 1)) / cols
        def labels_of(label):
            lines = wrap(str(label).upper(), BOLD, 6.8, w - 8)
            return lines if len(lines) <= 2 else [lines[0], fit(' '.join(lines[1:]), BOLD, 6.8, w - 8)]

        for start in range(0, len(items), cols):
            row = items[start:start + cols]
            labels = [labels_of(label) for _v, label, _c in row]
            h = height + 8 * (max(len(lab) for lab in labels) - 1)
            self.ensure(h + 6)
            y0 = self.y
            for i, (value, _label, color) in enumerate(row):
                x = self.left + i * (w + gap)
                self.rect(x, y0 - h, w, h, fill=CARD_BG, stroke=RULE, line_width=0.6)
                self.rect(x, y0 - 2.5, w, 2.5, fill=color or '#9ca3af')
                val = fit(value, BOLD, value_size, w - 10)
                self.text(x + (w - text_width(val, BOLD, value_size)) / 2, y0 - 8 - value_size, val, BOLD,
                          value_size, color or TEXT)
                for j, lab in enumerate(labels[i]):
                    self.text(x + (w - text_width(lab, BOLD, 6.8)) / 2, y0 - h + 7 + 8 * (len(labels[i]) - 1 - j),
                              lab, BOLD, 6.8, MUTED)
            self.y = y0 - h - 8

    def bars(self, items, color=BAR, value_format=None, label_width=None, size=8.5, title=None):
        """ horizontal bars: items = [(label, value)] or [(label, value, color)] """
        items = [i for i in items if i is not None]
        if not items:
            return
        row = size + 7
        if title:
            self.subheading(title, keep=row * min(len(items), 3))
        label_w = label_width or min(150.0, max(text_width(str(i[0]), REGULAR, size) for i in items) + 8)
        value_w = max(text_width(value_format(i[1]) if value_format else str(i[1]), BOLD, size) for i in items) + 6
        area = max(40.0, self.width - label_w - value_w)
        top = max([float(i[1] or 0) for i in items] + [1.0])
        for item in items:
            label, value = item[0], float(item[1] or 0)
            self.ensure(row)
            y0 = self.y
            self.text(self.left, y0 - size - 1, fit(label, REGULAR, size, label_w - 6), REGULAR, size, TEXT)
            self.rect(self.left + label_w, y0 - row + 3, area, row - 6, fill='#f1f3f6')
            w = area * value / top
            if w > 0:
                self.rect(self.left + label_w, y0 - row + 3, max(w, 1.5), row - 6,
                          fill=item[2] if len(item) > 2 and item[2] else color)
            shown = value_format(item[1]) if value_format else str(item[1])
            self.text_right(self.left + self.width, y0 - size - 1, shown, BOLD, size, TEXT)
            self.y -= row
        self.y -= 6

    def table(self, headers, rows, widths=None, size=8.2, align=None, max_lines=30):
        """
        :param headers: column titles (the header row is repeated after a page break)
        :param rows: list of rows; a cell is a string or a dict {text, bold, mono, color, chip (background color
                     of a label), tag: (text, color) label after the text, sub: second smaller muted line}
        :param widths: fractions of the width (default: equal)
        :param align: per column 'l' or 'r'
        """
        n = len(headers)
        widths = widths or [1.0 / n] * n
        total = float(sum(widths))
        cols = [self.width * w / total for w in widths]
        align = align or ['l'] * n
        pad = 4.0
        lead = size * 1.3
        sub_size = size - 1.3

        def layout(cell, width):
            cell = _cell(cell)
            font = MONO if cell.get('mono') else (BOLD if cell.get('bold') else REGULAR)
            if cell.get('chip'):
                lines = [fit(cell['text'], BOLD, size - 1, width - 8)]
            else:
                lines = wrap(cell['text'], font, size, width)[:max_lines]
            subs = wrap(cell['sub'], REGULAR, sub_size, width)[:max_lines] if cell.get('sub') else []
            height = len(lines) * lead + len(subs) * (sub_size * 1.3)
            return cell, font, lines, subs, height

        def draw_header():
            hh = lead + 2 * pad
            y0 = self.y
            self.rect(self.left, y0 - hh, self.width, hh, fill=HEAD_BG)
            x = self.left
            for i, head in enumerate(headers):
                label = fit(head, BOLD, size - 0.4, cols[i] - 2 * pad)
                if align[i] == 'r':
                    self.text_right(x + cols[i] - pad, y0 - pad - size + 0.5, label, BOLD, size - 0.4, '#374151')
                else:
                    self.text(x + pad, y0 - pad - size + 0.5, label, BOLD, size - 0.4, '#374151')
                x += cols[i]
            self.y -= hh

        self.ensure(lead * 2 + 4 * pad)
        draw_header()
        for index, row in enumerate(rows):
            cells = [layout(row[i] if i < len(row) else '', cols[i] - 2 * pad) for i in range(n)]
            rh = max(c[4] for c in cells) + 2 * pad
            if self.y - rh < self.bottom:
                self.new_page()
                draw_header()
            y0 = self.y
            if index % 2 == 1:
                self.rect(self.left, y0 - rh, self.width, rh, fill=ZEBRA)
            x = self.left
            for i, (cell, font, lines, subs, _h) in enumerate(cells):
                y = y0 - pad
                for line in lines:
                    if cell.get('chip'):
                        self.chip(x + pad, y + 0.5, line, cell['chip'], size - 1)
                    elif align[i] == 'r':
                        self.text_right(x + cols[i] - pad, y - size + 1, line, font, size, cell.get('color') or TEXT)
                    else:
                        self.text(x + pad, y - size + 1, line, font, size, cell.get('color') or TEXT)
                    y -= lead
                tag = cell.get('tag')
                if tag and lines and not cell.get('chip'):
                    tw = text_width(lines[-1], font, size)
                    if tw + text_width(tag[0], BOLD, size - 1.5) + 10 < cols[i] - 2 * pad:
                        self.chip(x + pad + tw + 4, y + lead + 0.5, tag[0], tag[1], size - 1.5)
                for line in subs:
                    self.text(x + pad, y - sub_size + 1, line, REGULAR, sub_size, MUTED)
                    y -= sub_size * 1.3
                x += cols[i]
            self.line(self.left, y0 - rh, self.left + self.width, y0 - rh, '#e5e7eb', 0.4)
            self.y -= rh
        self.y -= 8

    # ------------------------------------------------------------------ output

    def _decorate(self, number, total):
        ops = []
        saved, self.pages = self.pages, [ops]           # draw into a scratch list
        y = PAGE_H - MARGIN
        self.text(self.left, y - 10, fit(self.title, BOLD, 10, self.width * 0.68), BOLD, 10, TEXT)
        if self.header_right:
            self.text_right(self.left + self.width, y - 10, self.header_right, REGULAR, 8.5, MUTED)
        self.line(self.left, y - 17, self.left + self.width, y - 17, ORANGE, 1.1)
        fy = MARGIN + 12
        self.line(self.left, fy + 9, self.left + self.width, fy + 9, RULE, 0.5)
        if self.footer_left:
            self.text(self.left, fy, fit(self.footer_left, REGULAR, 7.5, self.width * 0.7), REGULAR, 7.5, MUTED)
        self.text_right(self.left + self.width, fy, self.page_label % (number, total), REGULAR, 7.5, MUTED)
        self.pages = saved
        return ops

    def finish(self):
        """ :return: the PDF as bytes """
        total = len(self.pages)
        objects = {}
        objects[1] = b'<< /Type /Catalog /Pages 2 0 R >>'
        for num, key in ((3, REGULAR), (4, BOLD), (5, MONO)):
            objects[num] = ('<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>'
                            % BASE_FONTS[key]).encode()
        stamp = time.strftime('D:%Y%m%d%H%M%SZ', time.gmtime(self.created))
        objects[6] = (b'<< /Title ' + _utf16(self.title) + b' /Producer ' + _utf16(self.author) + b' /Creator ' +
                      _utf16(self.author) + b' /CreationDate (' + stamp.encode() + b') >>')
        kids = []
        bodies = [b'\n'.join(self._decorate(index + 1, total) + ops) + b'\n' for index, ops in enumerate(self.pages)]
        fonts = b'/F1 3 0 R /F2 4 0 R /F3 5 0 R'
        next_num = 7 + 2 * total
        for key in sorted(self.unicode_used):
            objects.update(self._unicode_objects(key, next_num))
            fonts += b' /%s %d 0 R' % (key.encode(), next_num)
            next_num += 5
        resources = b'<< /Font << ' + fonts + b' >> /ProcSet [/PDF /Text] >>'
        for index, body in enumerate(bodies):
            page_num, content_num = 7 + index * 2, 8 + index * 2
            kids.append(page_num)
            if self.compress:
                body = zlib.compress(body, 9)
                head = b'<< /Length %d /Filter /FlateDecode >>' % len(body)
            else:
                head = b'<< /Length %d >>' % len(body)
            objects[content_num] = head + b'\nstream\n' + body + b'\nendstream'
            objects[page_num] = (b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources ' %
                                 (_num(PAGE_W).encode(), _num(PAGE_H).encode()) + resources +
                                 b' /Contents %d 0 R >>' % content_num)
        objects[2] = b'<< /Type /Pages /Kids [' + b' '.join(b'%d 0 R' % k for k in kids) + b'] /Count %d >>' % total
        out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        size = max(objects) + 1
        offsets = [0] * size
        for num in range(1, size):
            offsets[num] = len(out)
            out += b'%d 0 obj\n' % num + objects[num] + b'\nendobj\n'
        xref = len(out)
        out += b'xref\n0 %d\n0000000000 65535 f \n' % size
        for num in range(1, size):
            out += b'%010d 00000 n \n' % offsets[num]
        doc_id = hashlib.sha256(bytes(out)).hexdigest()[:32].encode()
        out += (b'trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R /ID [<' % size + doc_id + b'> <' + doc_id +
                b'>] >>\nstartxref\n%d\n%%%%EOF\n' % xref)
        return bytes(out)

    def _stream(self, data, extra=b''):
        if self.compress:
            data = zlib.compress(data, 9)
            extra += b' /Filter /FlateDecode'
        return b'<< /Length %d' % len(data) + extra + b' >>\nstream\n' + data + b'\nendstream'

    def _unicode_objects(self, key, num):
        """ Type0 font <num>, CIDFontType2 num+1, descriptor num+2, FontFile2 num+3, ToUnicode num+4 """
        font = _ufont(BOLD if key == 'U2' else REGULAR)
        used = self.unicode_used[key]
        gids = sorted(used)
        tag = ''.join(chr(65 + int(c, 16) % 26) for c in hashlib.sha256(
            (font.name + ','.join(map(str, gids))).encode()).hexdigest()[:6])
        name = ('%s+%s' % (tag, font.name)).encode()
        program = font.subset(gids)
        widths = b' '.join(b'%d [%d]' % (g, font.widths[g]) for g in gids)
        cmap = ['/CIDInit /ProcSet findresource begin', '12 dict begin', 'begincmap',
                '/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def',
                '/CMapName /Adobe-Identity-UCS def', '/CMapType 2 def', '1 begincodespacerange', '<0000> <FFFF>',
                'endcodespacerange']
        for i in range(0, len(gids), 100):
            chunk = gids[i:i + 100]
            cmap.append('%d beginbfchar' % len(chunk))
            cmap += ['<%04X> <%s>' % (g, used[g].encode('utf-16-be').hex().upper()) for g in chunk]
            cmap.append('endbfchar')
        cmap += ['endcmap', 'CMapName currentdict /CMap defineresource pop', 'end', 'end']
        return {
            num: b'<< /Type /Font /Subtype /Type0 /BaseFont /' + name + b' /Encoding /Identity-H /DescendantFonts [' +
                 b'%d 0 R] /ToUnicode %d 0 R >>' % (num + 1, num + 4),
            num + 1: b'<< /Type /Font /Subtype /CIDFontType2 /BaseFont /' + name + b' /CIDSystemInfo << /Registry ' +
                     b'(Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor %d 0 R /DW 500 /W [' % (num + 2) +
                     widths + b'] /CIDToGIDMap /Identity >>',
            num + 2: b'<< /Type /FontDescriptor /FontName /' + name + b' /Flags 32 /FontBBox [%d %d %d %d]' %
                     tuple(font.bbox) + b' /ItalicAngle 0 /Ascent %d /Descent %d /CapHeight %d /StemV %d' % (
                         font.ascent, font.descent, font.cap_height, 120 if key == 'U2' else 80) +
                     b' /FontFile2 %d 0 R >>' % (num + 3),
            num + 3: self._stream(program, b' /Length1 %d' % len(program)),
            num + 4: self._stream('\n'.join(cmap).encode('ascii')),
        }
