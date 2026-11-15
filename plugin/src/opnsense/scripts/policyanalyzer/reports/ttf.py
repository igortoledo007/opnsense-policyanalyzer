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

    TrueType (glyf) fonts for pdf.py, stdlib only: reads the tables a PDF needs (head, hhea, maxp, hmtx, cmap,
    loca, glyf, OS/2, name, post) and writes a SUBSET that keeps every glyph id (unused glyphs are emptied, so
    the PDF can use Identity-H + CIDToGIDMap /Identity without remapping).  Composite glyphs pull their
    components.  CFF / OpenType-PS (.otf) and collections (.ttc) are not supported: load() returns None.

    Which fonts exist on the firewall (nothing is downloaded, nothing is installed by the plugin):
      - the OPNsense core theme ships Source Sans Pro 2.020 (SIL OFL 1.1, embeddable: OS/2 fsType 0) as TTF in
        /usr/local/opnsense/www/themes/opnsense/build/fonts/: Latin + Latin Extended (cs, pl, tr, vi, ...), Greek
        and Cyrillic (ru, uk); no Arabic / Persian, no CJK.  Assumption: the path of OPNsense 24.x-26.x (checked
        against a copy of /usr/local/opnsense/www of the firewall, tema/referencia); the code also tries
        assets/fonts and DejaVu / Noto when a package installed them.
      - POLICYANALYZER_PDF_FONTS="<regular.ttf>[:<bold.ttf>]" overrides the search (tests, or a CJK TTF copied
        by the administrator); "none" turns the embedded font off (everything outside WinAnsi becomes "?").
"""

import os
import struct

THEME = '/usr/local/opnsense/www/themes/opnsense'
CANDIDATES = tuple(
    [('%s/%s/fonts/SourceSansPro-Regular/SourceSansPro-Regular.ttf' % (THEME, d),
      '%s/%s/fonts/SourceSansPro-Bold/SourceSansPro-Bold.ttf' % (THEME, d)) for d in ('build', 'assets')] +
    [('/usr/local/share/fonts/dejavu/DejaVuSans.ttf', '/usr/local/share/fonts/dejavu/DejaVuSans-Bold.ttf'),
     ('/usr/local/share/fonts/noto/NotoSans-Regular.ttf', '/usr/local/share/fonts/noto/NotoSans-Bold.ttf'),
     ('/usr/local/share/fonts/Droid/DroidSansFallback.ttf', None)])
KEEP_TABLES = (b'head', b'hhea', b'maxp', b'hmtx', b'loca', b'glyf', b'cvt ', b'fpgm', b'prep')


class FontError(ValueError):
    pass


def _u16(data, off):
    return struct.unpack_from('>H', data, off)[0]


def _i16(data, off):
    return struct.unpack_from('>h', data, off)[0]


def _u32(data, off):
    return struct.unpack_from('>I', data, off)[0]


class TrueType(object):
    def __init__(self, data, name='Font'):
        self.data = data
        if data[:4] not in (b'\x00\x01\x00\x00', b'true'):
            raise FontError('not a TrueType (glyf) font')
        self.tables = {}
        for i in range(_u16(data, 4)):
            tag, _sum, off, length = struct.unpack_from('>4sIII', data, 12 + 16 * i)
            self.tables[tag] = data[off:off + length]
        for tag in (b'head', b'hhea', b'maxp', b'hmtx', b'cmap', b'loca', b'glyf'):
            if tag not in self.tables:
                raise FontError('table %s missing' % tag.decode())
        os2 = self.tables.get(b'OS/2', b'')
        if len(os2) >= 10 and _u16(os2, 8) & 0x0002:
            raise FontError('the license of the font forbids embedding (fsType 2)')
        head = self.tables[b'head']
        self.upem = float(_u16(head, 18)) or 1000.0
        self.bbox = [int(_i16(head, 36 + 2 * i) * 1000 / self.upem) for i in range(4)]
        self.long_loca = _i16(head, 50) == 1
        hhea = self.tables[b'hhea']
        self.ascent = int(_i16(hhea, 4) * 1000 / self.upem)
        self.descent = int(_i16(hhea, 6) * 1000 / self.upem)
        n_metrics = _u16(hhea, 34)
        self.num_glyphs = _u16(self.tables[b'maxp'], 4)
        hmtx = self.tables[b'hmtx']
        adv = [_u16(hmtx, 4 * i) for i in range(n_metrics)]
        adv += [adv[-1]] * max(0, self.num_glyphs - n_metrics)
        self.widths = [int(round(a * 1000 / self.upem)) for a in adv]
        self.cap_height = int(_i16(os2, 88) * 1000 / self.upem) if len(os2) >= 90 and _u16(os2, 0) >= 2 \
            else self.ascent
        loca = self.tables[b'loca']
        if self.long_loca:
            self.loca = [_u32(loca, 4 * i) for i in range(self.num_glyphs + 1)]
        else:
            self.loca = [_u16(loca, 2 * i) * 2 for i in range(self.num_glyphs + 1)]
        self.cmap = self._cmap(self.tables[b'cmap'])
        self.name = self._ps_name() or name
        self.missing = self.cmap.get(ord('?'), 0)

    # ------------------------------------------------------------------ reading

    @staticmethod
    def _cmap(table):
        records = []
        for i in range(_u16(table, 2)):
            pid, eid, off = struct.unpack_from('>HHI', table, 4 + 8 * i)
            fmt = _u16(table, off)
            rank = {(3, 10, 12): 0, (0, 4, 12): 1, (3, 1, 4): 2, (0, 3, 4): 3}.get((pid, eid, fmt), 9 if fmt in (4, 12)
                                                                                    else None)
            if rank is not None:
                records.append((rank, fmt, off))
        if not records:
            raise FontError('no Unicode cmap')
        _rank, fmt, off = sorted(records)[0]
        out = {}
        if fmt == 12:
            for g in range(_u32(table, off + 12)):
                start, end, gid = struct.unpack_from('>III', table, off + 16 + 12 * g)
                for code in range(start, min(end, 0x10FFFF) + 1):
                    out[code] = gid + code - start
            return out
        seg = _u16(table, off + 6) // 2
        ends = off + 14
        starts = ends + 2 * seg + 2
        deltas = starts + 2 * seg
        ranges = deltas + 2 * seg
        for i in range(seg):
            end, start = _u16(table, ends + 2 * i), _u16(table, starts + 2 * i)
            delta, roff = _u16(table, deltas + 2 * i), _u16(table, ranges + 2 * i)
            if start == 0xFFFF:
                continue
            for code in range(start, end + 1):
                if roff == 0:
                    gid = (code + delta) & 0xFFFF
                else:
                    pos = ranges + 2 * i + roff + 2 * (code - start)
                    gid = _u16(table, pos) if pos + 2 <= len(table) else 0
                    gid = (gid + delta) & 0xFFFF if gid else 0
                if gid:
                    out[code] = gid
        return out

    def _ps_name(self):
        table = self.tables.get(b'name')
        if not table or len(table) < 6:
            return None
        count, strings = _u16(table, 2), _u16(table, 4)
        for i in range(count):
            pid, eid, _lid, nid, length, off = struct.unpack_from('>HHHHHH', table, 6 + 12 * i)
            if nid != 6:
                continue
            raw = table[strings + off:strings + off + length]
            text = raw.decode('utf-16-be', 'replace') if pid in (0, 3) else raw.decode('latin-1')
            text = ''.join(c for c in text if c.isalnum() or c in '-_')
            if text:
                return text
        return None

    def gid(self, char):
        return self.cmap.get(ord(char), self.missing)

    def has(self, char):
        return ord(char) in self.cmap

    def width(self, text):
        """ width in 1/1000 em """
        return sum(self.widths[self.gid(c)] for c in text)

    def _glyph(self, gid):
        return self.tables[b'glyf'][self.loca[gid]:self.loca[gid + 1]]

    def _components(self, gid):
        data = self._glyph(gid)
        if len(data) < 10 or _i16(data, 0) >= 0:
            return []
        out, pos = [], 10
        while pos + 4 <= len(data):
            flags, comp = _u16(data, pos), _u16(data, pos + 2)
            out.append(comp)
            pos += 4 + (4 if flags & 0x0001 else 2)
            pos += 2 if flags & 0x0008 else 4 if flags & 0x0040 else 8 if flags & 0x0080 else 0
            if not flags & 0x0020:
                break
        return out

    # ------------------------------------------------------------------ writing

    def subset(self, gids):
        """ :return: bytes of a TrueType font where only <gids> (and their components) keep their outlines """
        keep, todo = set(), [0] + sorted(set(gids))
        while todo:
            g = todo.pop()
            if g in keep or g >= self.num_glyphs:
                continue
            keep.add(g)
            todo.extend(self._components(g))
        glyf, loca = bytearray(), []
        for g in range(self.num_glyphs):
            loca.append(len(glyf))
            if g in keep:
                glyf += self._glyph(g)
                glyf += b'\0' * (-len(glyf) % 4)
        loca.append(len(glyf))
        head = bytearray(self.tables[b'head'])
        struct.pack_into('>I', head, 8, 0)              # checkSumAdjustment (not checked by PDF readers)
        struct.pack_into('>h', head, 50, 1)             # long loca
        tables = {tag: self.tables[tag] for tag in KEEP_TABLES if tag in self.tables}
        tables.update({b'head': bytes(head), b'glyf': bytes(glyf),
                       b'loca': struct.pack('>%dI' % len(loca), *loca)})
        return _sfnt(tables)


def _checksum(data):
    data += b'\0' * (-len(data) % 4)
    return sum(struct.unpack('>%dI' % (len(data) // 4), data)) & 0xFFFFFFFF


def _sfnt(tables):
    tags = sorted(tables)
    n = len(tags)
    power = 1
    while power * 2 <= n:
        power *= 2
    out = bytearray(struct.pack('>IHHHH', 0x00010000, n, power * 16, (power.bit_length() - 1), n * 16 - power * 16))
    offset = 12 + 16 * n
    body = bytearray()
    for tag in tags:
        data = tables[tag]
        out += struct.pack('>4sIII', tag, _checksum(data), offset + len(body), len(data))
        body += data + b'\0' * (-len(data) % 4)
    return bytes(out + body)


def table_tags(data):
    """ the table tags of an sfnt (checks of the subset) """
    return sorted(struct.unpack_from('>4s', data, 12 + 16 * i)[0] for i in range(_u16(data, 4)))


def load(path):
    """ :return: TrueType or None (missing, unreadable, CFF, not embeddable) """
    if not path:
        return None
    try:
        with open(path, 'rb') as handle:
            return TrueType(handle.read(), os.path.splitext(os.path.basename(path))[0])
    except (OSError, FontError, struct.error, IndexError):
        return None


def find():
    """ :return: (regular, bold) TrueType objects (bold may be the regular one) or None """
    env = os.environ.get('POLICYANALYZER_PDF_FONTS')
    if env is not None:
        if env.strip().lower() in ('', 'none', 'off'):
            return None
        parts = env.split(os.pathsep)
        candidates = [(parts[0], parts[1] if len(parts) > 1 else None)]
    else:
        candidates = CANDIDATES
    for regular, bold in candidates:
        font = load(regular)
        if font:
            return font, (load(bold) or font)
    return None
