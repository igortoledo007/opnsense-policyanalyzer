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

    Vector charts drawn straight into the content stream of a pdf.Document (stdlib only, no matplotlib /
    reportlab: the firewall has none). Path operators m / l / c / re / h, fill f, stroke S, clipping W n inside
    q ... Q, RGB colours, axis texts with the fonts of pdf.py (Helvetica / WinAnsi, or its embedded TrueType).

      vbar       vertical bars (one series, grouped or stacked)
      hbar       horizontal bars (one series, grouped or stacked), long labels cut with "..."
      line       time series as line or area, with markers, light grid and highlighted points (anomalies)
      donut      ring chart (arcs as cubic Bezier curves) with a legend of values and percentages
      sparkline  tiny line for the overview cards; overview() draws the 4-card panel
      scatter    points on two axes (x and y), numbered markers per series, optional guide lines (thresholds)
      ranges     one row per category: min..max line, a p50 marker, a p95 tick and an optional limit per row
      empty      a framed box "no data in the period" (every chart falls back to it)

    Accessibility / black and white printing: every series has a fill tone of a distinct lightness AND a hatch
    pattern (diagonal, cross, horizontal, back diagonal) or, for lines, a dash pattern and a marker shape;
    highlighted points use a ring. Values are written next to the bars and in the legends, so no meaning depends
    on colour alone.

    Texts, weekdays and number formats come from the catalogs i18n/<language>.json (sections "axis", "weekdays"
    and "format"): pt_BR uses "." for thousands and "," for decimals (31.877 / 2,5), en_US "," and ".". Axis
    scales are "nice" (steps 1, 2, 5 x 10^k).
"""

import math

import i18n

from . import pdf

# (fill, hatch): lightness alternates dark / mid / light and the hatch alternates too (readable in grey scale)
PALETTE = (('#1f4e79', None), ('#e07b39', 'diag'), ('#9ec5e8', None), ('#4b5563', 'cross'),
           ('#f2c14e', 'horiz'), ('#5f9e6e', 'back'), ('#c4b5fd', 'diag'), ('#7c2d12', None))
# line series: colour, dash pattern, marker
LINES = (('#1f4e79', '', 'circle'), ('#d94f00', '[4 2] 0', 'square'), ('#4b5563', '[1 1.6] 0', 'triangle'),
         ('#2e7d4f', '[5 2 1 2] 0', 'diamond'))
# ordinal ramps: darker = more severe, hatch on the two most severe levels
SEVERITY = {'critical': ('#7f1d1d', 'cross'), 'high': ('#c2410c', 'diag'), 'medium': ('#f59e0b', None),
            'low': ('#93c5fd', None), 'info': ('#d1d5db', 'horiz')}
STATUS = {'ok': ('#1f4e79', None), 'error': ('#e07b39', 'diag')}
HIGHLIGHT = '#b91c1c'
GRID = '#e5e7eb'
AXIS = '#9ca3af'
LABEL = '#4b5563'
FRAME = '#f8fafc'

AXIS_SIZE = 6.6
VALUE_SIZE = 6.4
LEGEND_SIZE = 7.2
TITLE_SIZE = 9.0
KAPPA = 0.5522847498


def tr(language, key):
    return i18n.section(language, 'axis')[key]


# ------------------------------------------------------------------ numbers

def fmt(value, language='en_US', decimals=0):
    """ 31877 -> "31.877" (pt) / "31,877" (en); 2.5 with decimals=1 -> "2,5" / "2.5" """
    return i18n.fmt_number(value, language, decimals)


def decimals_for(step):
    """ how many decimals the ticks of a scale with this step need """
    if step <= 0 or step >= 1:
        return 0
    return min(4, int(math.ceil(-math.log10(step) - 1e-9)))


def compact(value, language='en_US', decimals=None):
    """ axis text: 12.000 -> "12 mil", 1.500.000 -> "1,5 mi" (pt) / "12k", "1.5M" (en) """
    t = i18n.section(language, 'axis')
    sep = i18n.number_format(language).get('compact_space', '')
    av = abs(float(value))
    for limit, divisor, suffix in ((1e9, 1e9, t['billion']), (1e6, 1e6, t['million']), (1e4, 1e3, t['thousand'])):
        if av >= limit:
            scaled = value / divisor
            dec = 0 if abs(scaled - round(scaled)) < 1e-9 else 1
            return fmt(scaled, language, dec) + sep + suffix
    return fmt(value, language, decimals if decimals is not None else (0 if float(value).is_integer() else 1))


def fmt_bytes(value, language='en_US'):
    value = float(value or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(value) < 1024 or unit == 'TB':
            return fmt(value, language, 0 if unit == 'B' or value >= 100 else 1) + ' ' + unit
        value /= 1024.0


def fmt_seconds(value, language='en_US'):
    value = float(value or 0)
    if value < 10:
        return fmt(value, language, 1) + ' s'
    if value < 120:
        return fmt(value, language, 0) + ' s'
    return fmt(value / 60.0, language, 1) + ' min'


def nice_step(raw):
    """ the smallest 1 / 2 / 5 x 10^k >= raw """
    if raw <= 0:
        return 1.0
    exp = math.floor(math.log10(raw))
    base = 10 ** exp
    for mult in (1, 2, 5, 10):
        if mult * base >= raw * (1 - 1e-9):
            return mult * base
    return 10 * base


def nice_scale(high, low=0.0, ticks=5, integer=False):
    """ (low, high, step) covering [low, high] with steps 1-2-5; integer=True never goes below a step of 1 """
    high = float(high or 0)
    low = float(low or 0)
    if high < low:
        low, high = high, low
    if high == low:
        high = low + (1.0 if low == 0 else abs(low) * 0.5)
    step = nice_step((high - low) / max(1, ticks))
    if integer:
        step = max(1.0, step)
    top = math.ceil(high / step - 1e-9) * step
    bottom = math.floor(low / step + 1e-9) * step
    return bottom, top, step


def ticks_of(low, high, step):
    out = []
    value = low
    while value <= high + step * 1e-6:
        out.append(round(value, 10))
        value += step
    return out


# ------------------------------------------------------------------ drawing primitives

def _n(value):
    return pdf._num(value)


def _rgb(color):
    return pdf._rgb(color)


def luminance(color):
    color = color.lstrip('#')
    r, g, b = (int(color[i:i + 2], 16) / 255.0 for i in (0, 2, 4))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def style(index, styles=None):
    """ (fill, hatch) of series <index>; styles may give explicit (fill, hatch) per series """
    if styles and index < len(styles) and styles[index]:
        return styles[index]
    return PALETTE[index % len(PALETTE)]


def _hatch_lines(x, y, w, h, kind, spacing=3.2):
    ops = []
    if kind in ('diag', 'cross'):
        k = 0.0
        while k < w + h:
            ops.append('%s %s m %s %s l' % (_n(x + k - h), _n(y), _n(x + k), _n(y + h)))
            k += spacing
    if kind in ('back', 'cross'):
        k = 0.0
        while k < w + h:
            ops.append('%s %s m %s %s l' % (_n(x + k), _n(y), _n(x + k - h), _n(y + h)))
            k += spacing
    if kind == 'horiz':
        k = spacing / 2
        while k < h:
            ops.append('%s %s m %s %s l' % (_n(x), _n(y + k), _n(x + w), _n(y + k)))
            k += spacing
    return ops


def _hatch_color(fill):
    return '#ffffff' if luminance(fill) < 0.45 else '#1f2937'


def fill_rect(doc, x, y, w, h, fill, hatch=None):
    """ filled rectangle, hatched (clipped to the rectangle) when <hatch> is given """
    if w <= 0 or h <= 0:
        return
    doc._op('%s rg %s %s %s %s re f' % (_rgb(fill), _n(x), _n(y), _n(w), _n(h)))
    if hatch:
        lines = _hatch_lines(x, y, w, h, hatch)
        if lines:
            doc._op('q %s %s %s %s re W n %s RG 0.45 w %s S Q' % (_n(x), _n(y), _n(w), _n(h),
                                                                 _rgb(_hatch_color(fill)), ' '.join(lines)))


def swatch(doc, x, y, fill, hatch=None, size=7.0):
    fill_rect(doc, x, y, size, size, fill, hatch)
    doc._op('%s RG 0.4 w %s %s %s %s re S' % (_rgb('#6b7280'), _n(x), _n(y), _n(size), _n(size)))


def stroke_line(doc, points, color, width=1.0, dash=''):
    if len(points) < 2:
        return
    path = ' '.join(('%s %s %s' % (_n(px), _n(py), 'm' if i == 0 else 'l')) for i, (px, py) in enumerate(points))
    doc._op('%s RG %s w 1 J 1 j %s d %s S [] 0 d 0 J 0 j' % (_rgb(color), _n(width), dash or '[] 0', path))


def _circle_path(cx, cy, r):
    k = KAPPA * r
    return ('%s %s m %s %s %s %s %s %s c %s %s %s %s %s %s c %s %s %s %s %s %s c %s %s %s %s %s %s c h' % tuple(
        _n(v) for v in (cx + r, cy, cx + r, cy + k, cx + k, cy + r, cx, cy + r, cx - k, cy + r, cx - r, cy + k,
                        cx - r, cy, cx - r, cy - k, cx - k, cy - r, cx, cy - r, cx + k, cy - r, cx + r, cy - k,
                        cx + r, cy)))


def marker(doc, x, y, shape, color, size=2.2, outline='#ffffff'):
    if shape == 'square':
        path = '%s %s %s %s re' % (_n(x - size), _n(y - size), _n(2 * size), _n(2 * size))
    elif shape == 'triangle':
        path = '%s %s m %s %s l %s %s l h' % (_n(x), _n(y + size * 1.25), _n(x - size * 1.15), _n(y - size * 0.85),
                                              _n(x + size * 1.15), _n(y - size * 0.85))
    elif shape == 'diamond':
        path = '%s %s m %s %s l %s %s l %s %s l h' % (_n(x), _n(y + size * 1.3), _n(x + size * 1.1), _n(y),
                                                      _n(x), _n(y - size * 1.3), _n(x - size * 1.1), _n(y))
    else:
        path = _circle_path(x, y, size)
    doc._op('%s rg %s RG 0.6 w %s B' % (_rgb(color), _rgb(outline), path))


def ring(doc, x, y, color=HIGHLIGHT, radius=4.4):
    """ highlighted point: a thick ring around the marker (shape, not only colour) """
    doc._op('%s RG 1.3 w %s S' % (_rgb(color), _circle_path(x, y, radius)))


def _arc(cx, cy, r, a0, a1, move=True):
    """ path of an arc from angle a0 to a1 (radians, counter clockwise when a1 > a0) in Bezier segments <= 90 deg """
    segments = max(1, int(math.ceil(abs(a1 - a0) / (math.pi / 2) - 1e-9)))
    delta = (a1 - a0) / segments
    k = 4.0 / 3.0 * math.tan(delta / 4.0)
    ops = []
    x0, y0 = cx + r * math.cos(a0), cy + r * math.sin(a0)
    ops.append('%s %s %s' % (_n(x0), _n(y0), 'm' if move else 'l'))
    for i in range(segments):
        t0 = a0 + i * delta
        t1 = t0 + delta
        p0 = (cx + r * math.cos(t0), cy + r * math.sin(t0))
        p3 = (cx + r * math.cos(t1), cy + r * math.sin(t1))
        p1 = (p0[0] - k * r * math.sin(t0), p0[1] + k * r * math.cos(t0))
        p2 = (p3[0] + k * r * math.sin(t1), p3[1] - k * r * math.cos(t1))
        ops.append('%s %s %s %s %s %s c' % tuple(_n(v) for v in (p1[0], p1[1], p2[0], p2[1], p3[0], p3[1])))
    return ' '.join(ops)


def ring_slice_path(cx, cy, r_out, r_in, a0, a1):
    return '%s %s h' % (_arc(cx, cy, r_out, a0, a1, True), _arc(cx, cy, r_in, a1, a0, False))


def text_center(doc, x, y, value, font=pdf.REGULAR, size=AXIS_SIZE, color=LABEL):
    doc.text(x - pdf.text_width(value, font, size) / 2.0, y, value, font, size, color)


# ------------------------------------------------------------------ layout helpers

def _values(series):
    return [float(v or 0) for _name, vals in series for v in vals]


def is_empty(series):
    vals = _values(series)
    return not vals or not any(vals)


def _title(doc, title, height):
    """ keep title + chart on the same page; returns the top y of the drawing area """
    need = height + (TITLE_SIZE + 9 if title else 0) + 6
    doc.ensure(need)
    if title:
        doc.text(doc.left, doc.y - TITLE_SIZE, pdf.fit(title, pdf.BOLD, TITLE_SIZE, doc.width), pdf.BOLD,
                 TITLE_SIZE, pdf.TEXT)
        doc.y -= TITLE_SIZE + 7
    return doc.y


def empty(doc, title=None, language='en_US', height=46.0, message=None):
    """ framed box with "no data in the period" """
    top = _title(doc, title, height)
    doc.rect(doc.left, top - height, doc.width, height, fill=FRAME, stroke=pdf.RULE, line_width=0.5)
    msg = message or tr(language, 'no_data')
    text_center(doc, doc.left + doc.width / 2.0, top - height / 2.0 - 3, msg, pdf.REGULAR, 8.5, pdf.MUTED)
    doc.y = top - height - 10
    return 'empty'


def _legend_height(doc, entries, width):
    if not entries:
        return 0.0
    rows, x = 1, 0.0
    for entry in entries:
        w = 11 + pdf.text_width(entry[0], pdf.REGULAR, LEGEND_SIZE) + 12
        if x + w > width and x > 0:
            rows += 1
            x = 0.0
        x += w
    return rows * 11.0 + 2


def legend(doc, x, y_top, width, entries):
    """ entries: (label, kind, a, b): kind 'box' (a=fill, b=hatch), 'line' (a=index of LINES), 'ring' """
    cx, cy = x, y_top
    for label, kind, a, b in entries:
        w = 11 + pdf.text_width(label, pdf.REGULAR, LEGEND_SIZE) + 12
        if cx + w > x + width and cx > x:
            cx = x
            cy -= 11
        if kind == 'line':
            color, dash, shape = LINES[a % len(LINES)]
            stroke_line(doc, [(cx, cy - 4), (cx + 9, cy - 4)], color, 1.2, dash)
            marker(doc, cx + 4.5, cy - 4, shape, color, 1.8)
        elif kind == 'ring':
            marker(doc, cx + 4.5, cy - 4, 'circle', LINES[0][0], 1.8)
            ring(doc, cx + 4.5, cy - 4, HIGHLIGHT, 3.6)
        else:
            swatch(doc, cx, cy - 7.5, a, b)
        doc.text(cx + 11, cy - 6.6, label, pdf.REGULAR, LEGEND_SIZE, pdf.TEXT)
        cx += w
    return y_top - cy + 11


def _thin(n, label_w, available):
    """ every how many categories a label is written so they do not overlap """
    if n <= 0:
        return 1
    per = available / float(n)
    return max(1, int(math.ceil((label_w + 4) / max(per, 0.1))))


def _y_axis(doc, x_plot, y0, w_plot, h_plot, low, high, step, language, value_format=None):
    """ grid lines and tick labels; returns nothing (labels are right aligned at x_plot - 3) """
    for value in ticks_of(low, high, step):
        y = y0 + (value - low) / (high - low) * h_plot
        doc.line(x_plot, y, x_plot + w_plot, y, AXIS if value == low else GRID, 0.6 if value == low else 0.4)
        label = value_format(value) if value_format else compact(value, language, decimals_for(step))
        doc.text_right(x_plot - 3, y - AXIS_SIZE / 2 + 1, label, pdf.REGULAR, AXIS_SIZE, LABEL)


def _y_label_width(low, high, step, language, value_format=None):
    labels = [value_format(v) if value_format else compact(v, language, decimals_for(step))
              for v in ticks_of(low, high, step)]
    return max(pdf.text_width(lab, pdf.REGULAR, AXIS_SIZE) for lab in labels) + 6


# ------------------------------------------------------------------ charts

def vbar(doc, labels, series, title=None, language='en_US', stacked=False, height=128.0, styles=None,
         value_labels=True, value_format=None, note=None, integer=True):
    """
    :param labels: categories (x axis)
    :param series: [(name, [value per category])]; one series = simple bars, several = grouped (or stacked)
    :return: 'chart' or 'empty'
    """
    series = [(name, list(vals) + [0] * (len(labels) - len(vals))) for name, vals in series]
    if not labels or is_empty(series):
        return empty(doc, title, language)
    show_legend = len(series) > 1 or bool(series[0][0])
    entries = [(name, 'box') + tuple(style(i, styles)) for i, (name, _v) in enumerate(series)] if show_legend else []
    leg_h = _legend_height(doc, entries, doc.width)
    top = _title(doc, title, height + leg_h)
    legend(doc, doc.left, top, doc.width, entries)
    n = len(labels)
    if stacked:
        peak = max(sum(float(s[1][i] or 0) for s in series) for i in range(n))
    else:
        peak = max(_values(series))
    low, high, step = nice_scale(peak, 0, 4, integer)
    y_label_w = _y_label_width(low, high, step, language, value_format)
    x_plot = doc.left + y_label_w
    w_plot = doc.width - y_label_w - 4
    y0 = top - leg_h - height + 14
    h_plot = height - 14 - 10
    _y_axis(doc, x_plot, y0, w_plot, h_plot, low, high, step, language, value_format)
    slot = w_plot / float(n)
    group = min(slot * (0.72 if n > 3 else 0.5), 30.0 if stacked else 22.0 * len(series))
    bar_w = group if stacked else group / len(series)
    label_w = max(pdf.text_width(str(lab), pdf.REGULAR, AXIS_SIZE) for lab in labels)
    every = _thin(n, label_w, w_plot)
    for i, lab in enumerate(labels):
        gx = x_plot + i * slot + (slot - group) / 2.0
        base = y0
        for j, (_name, vals) in enumerate(series):
            value = float(vals[i] or 0)
            h = value / (high - low) * h_plot if high > low else 0
            fill, hatch = style(j, styles)
            if stacked:
                fill_rect(doc, gx, base, bar_w, h, fill, hatch)
                base += h
            else:
                bx = gx + j * bar_w
                fill_rect(doc, bx + 0.4, y0, bar_w - 0.8, h, fill, hatch)
                if value_labels and value and bar_w >= 9:
                    shown = value_format(value) if value_format else compact(value, language)
                    if pdf.text_width(shown, pdf.REGULAR, VALUE_SIZE) <= bar_w + 6:
                        text_center(doc, bx + bar_w / 2.0, y0 + h + 2, shown, pdf.REGULAR, VALUE_SIZE, pdf.TEXT)
        if stacked and value_labels and bar_w >= 9:
            total = sum(float(s[1][i] or 0) for s in series)
            if total:
                shown = value_format(total) if value_format else compact(total, language)
                if pdf.text_width(shown, pdf.REGULAR, VALUE_SIZE) <= bar_w + 8:
                    text_center(doc, gx + bar_w / 2.0, base + 2, shown, pdf.BOLD, VALUE_SIZE, pdf.TEXT)
        if i % every == 0:
            text_center(doc, x_plot + i * slot + slot / 2.0, y0 - AXIS_SIZE - 3,
                        pdf.fit(str(lab), pdf.REGULAR, AXIS_SIZE, slot * every - 2), pdf.REGULAR, AXIS_SIZE, LABEL)
    doc.y = top - leg_h - height - 4
    if note:
        doc.paragraph(note, 7.5, color=pdf.MUTED, space_after=2)
    doc.y -= 6
    return 'chart'


def hbar(doc, labels, series, title=None, language='en_US', stacked=False, styles=None, value_format=None,
         label_width=None, row=13.0, mono=False, note=None, max_items=12):
    """ horizontal bars; series as in vbar. The value (or the stacked total) is written after each bar """
    labels = list(labels)[:max_items]
    series = [(name, (list(vals) + [0] * len(labels))[:len(labels)]) for name, vals in series]
    if not labels or is_empty(series):
        return empty(doc, title, language)
    show_legend = len(series) > 1 or bool(series[0][0])
    entries = [(name, 'box') + tuple(style(i, styles)) for i, (name, _v) in enumerate(series)] if show_legend else []
    leg_h = _legend_height(doc, entries, doc.width)
    group_h = row if stacked or len(series) == 1 else row * 0.62 * len(series) + 3
    height = group_h * len(labels) + 4
    top = _title(doc, title, height + leg_h)
    legend(doc, doc.left, top, doc.width, entries)
    font = pdf.MONO if mono else pdf.REGULAR
    size = 7.4
    lab_w = label_width or min(doc.width * 0.34, max(pdf.text_width(str(lab), font, size) for lab in labels) + 8)
    fmt_v = value_format or (lambda v: fmt(v, language))
    if stacked:
        totals = [sum(float(s[1][i] or 0) for s in series) for i in range(len(labels))]
    else:
        totals = [max(float(s[1][i] or 0) for s in series) for i in range(len(labels))]
    val_w = max(pdf.text_width(fmt_v(v), pdf.BOLD, VALUE_SIZE) for v in totals + _values(series)) + 6
    area = doc.width - lab_w - val_w
    peak = max(totals) or 1.0
    y = top - leg_h
    for i, lab in enumerate(labels):
        doc.text(doc.left, y - group_h / 2.0 - size / 2.0 + 1.5, pdf.fit(str(lab), font, size, lab_w - 6), font, size,
                 pdf.TEXT)
        doc.rect(doc.left + lab_w, y - group_h + 2, area, group_h - 4, fill='#f3f4f6')
        if stacked:
            x = doc.left + lab_w
            for j, (_name, vals) in enumerate(series):
                w = area * float(vals[i] or 0) / peak
                fill, hatch = style(j, styles)
                fill_rect(doc, x, y - group_h + 2, w, group_h - 4, fill, hatch)
                x += w
            doc.text(x + 3, y - group_h / 2.0 - VALUE_SIZE / 2.0 + 1.5, fmt_v(totals[i]), pdf.BOLD, VALUE_SIZE,
                     pdf.TEXT)
        else:
            bar_h = (group_h - 4) / len(series)
            for j, (_name, vals) in enumerate(series):
                value = float(vals[i] or 0)
                w = area * value / peak
                fill, hatch = style(j, styles)
                by = y - 2 - (j + 1) * bar_h
                fill_rect(doc, doc.left + lab_w, by + 0.4, max(w, 1.2 if value else 0), bar_h - 0.8, fill, hatch)
                doc.text(doc.left + lab_w + w + 3, by + bar_h / 2.0 - VALUE_SIZE / 2.0 + 1, fmt_v(value), pdf.BOLD,
                         VALUE_SIZE, pdf.TEXT)
        y -= group_h
    doc.y = y - 4
    if note:
        doc.paragraph(note, 7.5, color=pdf.MUTED, space_after=2)
    doc.y -= 6
    return 'chart'


def _mix(c1, c2, f):
    """ colour between c1 (f = 0) and c2 (f = 1), as #rrggbb """
    a = [int(c1.lstrip('#')[i:i + 2], 16) for i in (0, 2, 4)]
    b = [int(c2.lstrip('#')[i:i + 2], 16) for i in (0, 2, 4)]
    return '#%02x%02x%02x' % tuple(int(round(a[k] + (b[k] - a[k]) * f)) for k in range(3))


def _monotone_tangents(pts):
    """ Fritsch-Carlson tangents: the curve passes through every point and never overshoots (no dip before a jump,
    no bump above a peak) """
    n = len(pts)
    d = [(pts[k + 1][1] - pts[k][1]) / ((pts[k + 1][0] - pts[k][0]) or 1e-9) for k in range(n - 1)]
    m = [d[0]] + [0.0 if d[k - 1] * d[k] <= 0 else (d[k - 1] + d[k]) / 2.0 for k in range(1, n - 1)] + [d[-1]]
    for k in range(n - 1):
        if d[k] == 0:
            m[k] = m[k + 1] = 0.0
            continue
        a, b = m[k] / d[k], m[k + 1] / d[k]
        if a * a + b * b > 9:
            t = 3.0 / (a * a + b * b) ** 0.5
            m[k], m[k + 1] = t * a * d[k], t * b * d[k]
    return m


def _smooth_ops(pts, y_low=None, y_high=None):
    """ PDF path through the points as monotone cubic Béziers """
    m = _monotone_tangents(pts)
    ops = ['%s %s m' % (_n(pts[0][0]), _n(pts[0][1]))]
    for k in range(len(pts) - 1):
        (x1, y1), (x2, y2) = pts[k], pts[k + 1]
        h = (x2 - x1) / 3.0
        ops.append('%s %s %s %s %s %s c' % (_n(x1 + h), _n(y1 + m[k] * h), _n(x2 - h), _n(y2 - m[k + 1] * h),
                                            _n(x2), _n(y2)))
    return ' '.join(ops)


def line(doc, labels, series, title=None, language='en_US', area=False, height=128.0, highlight=None,
         markers=True, value_format=None, low=None, high=None, integer=False, note=None, highlight_label=None,
         smooth=False, gradient=None, color=None):
    """
    :param series: [(name, [value or None per label])]; None = gap
    :param highlight: indices of series 0 drawn with a ring (anomalous points); legend entry "anomalous point"
    :param low / high: fixed scale (e.g. 0..100 for a score)
    :param smooth: draw the lines as smooth curves; the last point of series 0 gets a dot with a soft halo
    :param gradient: (top colour, bottom colour) of the area of series 0, painted as a vertical fade
    :param color: colour of series 0 (default: the first of LINES)
    """
    series = [(name, list(vals) + [None] * (len(labels) - len(vals))) for name, vals in series]
    present = [float(v) for _n, vals in series for v in vals if v is not None]
    if not labels or not present or (not any(present) and low is None):
        return empty(doc, title, language)
    entries = []
    if len(series) > 1 or series[0][0]:
        entries = [(name, 'line', i, None) for i, (name, _v) in enumerate(series)]
    highlight = sorted(set(i for i in (highlight or []) if 0 <= i < len(labels) and series[0][1][i] is not None))
    if highlight:
        entries.append((highlight_label or tr(language, 'highlight'), 'ring', None, None))
    leg_h = _legend_height(doc, entries, doc.width)
    top = _title(doc, title, height + leg_h)
    legend(doc, doc.left, top, doc.width, entries)
    lo = min(present) if low is None else low
    hi = max(present) if high is None else high
    if low is None:
        lo = min(0.0, lo)
    s_low, s_high, step = nice_scale(hi, lo, 4, integer)
    if low is not None:
        s_low = low
    if high is not None:
        s_high = high
        step = nice_step((s_high - s_low) / 4.0)
    y_label_w = _y_label_width(s_low, s_high, step, language, value_format)
    x_plot = doc.left + y_label_w
    w_plot = doc.width - y_label_w - 8
    y0 = top - leg_h - height + 14
    h_plot = height - 14 - 10
    _y_axis(doc, x_plot, y0, w_plot, h_plot, s_low, s_high, step, language, value_format)
    n = len(labels)
    dx = w_plot / float(max(1, n - 1)) if n > 1 else 0
    def px(i):
        return x_plot + (i * dx if n > 1 else w_plot / 2.0)

    def py(v):
        return y0 + (float(v) - s_low) / (s_high - s_low) * h_plot
    color0 = color
    for j, (_name, vals) in enumerate(series):
        color, dash, shape = LINES[j % len(LINES)]
        if j == 0 and color0:
            color = color0
        runs, cur = [], []
        for i, v in enumerate(vals):
            if v is None:
                if cur:
                    runs.append(cur)
                cur = []
            else:
                cur.append((px(i), py(v)))
        if cur:
            runs.append(cur)
        for pts in runs:
            if area and j == 0 and len(pts) > 1:
                if smooth:
                    curve = _smooth_ops(pts, y0, y0 + h_plot)
                    path = '%s %s m %s %s l ' % (_n(pts[0][0]), _n(y0), _n(pts[0][0]), _n(pts[0][1])) + \
                        curve.split(' m', 1)[1].strip() + ' %s %s l h' % (_n(pts[-1][0]), _n(y0))
                else:
                    path = '%s %s m ' % (_n(pts[0][0]), _n(y0)) + ' '.join('%s %s l' % (_n(a), _n(b)) for a, b in pts) + \
                           ' %s %s l h' % (_n(pts[-1][0]), _n(y0))
                if gradient:
                    # vertical fade: the area is the clip, horizontal bands from the top colour to the bottom one
                    bands, band_h = 28, h_plot / 28.0
                    ops = ['q', path, 'W n']
                    for b in range(bands):
                        ops.append('%s rg %s %s %s %s re f' % (_rgb(_mix(gradient[0], gradient[1], b / float(bands - 1))),
                                                             _n(x_plot), _n(y0 + h_plot - (b + 1) * band_h),
                                                             _n(w_plot), _n(band_h + 0.4)))
                    ops.append('Q')
                    doc._op(' '.join(ops))
                else:
                    doc._op('%s rg %s f' % (_rgb('#dbe7f3'), path))
            if smooth and len(pts) > 2:
                doc._op('%s RG 1.6 w 1 J 1 j %s d %s S [] 0 d 0 J 0 j' % (_rgb(color), dash or '[] 0',
                                                                       _smooth_ops(pts, y0, y0 + h_plot)))
            else:
                stroke_line(doc, pts, color, 1.3, dash)
        if markers and n <= 60:
            for i, v in enumerate(vals):
                if v is not None:
                    marker(doc, px(i), py(v), shape, color, 1.9 if n > 24 else 2.2)
    for i in highlight:
        ring(doc, px(i), py(series[0][1][i]))
    if smooth:
        last = max((i for i, v in enumerate(series[0][1]) if v is not None), default=None)
        if last is not None:
            c0 = color0 or LINES[0][0]
            lx, ly = px(last), py(series[0][1][last])
            doc._op('%s rg %s f' % (_rgb(_mix(c0, '#ffffff', 0.7)), _circle_path(lx, ly, 4.6)))
            doc._op('%s rg %s RG 0.8 w %s B' % (_rgb(c0), _rgb('#ffffff'), _circle_path(lx, ly, 2.4)))
    label_w = max(pdf.text_width(str(lab), pdf.REGULAR, AXIS_SIZE) for lab in labels)
    every = _thin(n, label_w, w_plot + dx)
    for i, lab in enumerate(labels):
        if i % every == 0:
            text_center(doc, px(i), y0 - AXIS_SIZE - 3, str(lab), pdf.REGULAR, AXIS_SIZE, LABEL)
    doc.y = top - leg_h - height - 4
    if note:
        doc.paragraph(note, 7.5, color=pdf.MUTED, space_after=2)
    doc.y -= 6
    return 'chart'


def donut(doc, items, title=None, language='en_US', styles=None, center=None, size=96.0, max_items=6, note=None):
    """ items: [(label, value)]; the smallest beyond max_items are grouped as "other" """
    items = [(str(k), float(v or 0)) for k, v in items if v]
    if not items:
        return empty(doc, title, language)
    items.sort(key=lambda kv: -kv[1])
    if len(items) > max_items:
        rest = sum(v for _k, v in items[max_items - 1:])
        items = items[:max_items - 1] + [(tr(language, 'other'), rest)]
    total = sum(v for _k, v in items)
    rows_h = len(items) * 12.5
    height = max(size, rows_h) + 4
    top = _title(doc, title, height)
    r_out = size / 2.0
    r_in = r_out * 0.58
    cx, cy = doc.left + r_out + 4, top - height / 2.0
    angle = math.pi / 2
    for i, (_label, value) in enumerate(items):
        sweep = 2 * math.pi * value / total
        a1 = angle - sweep
        fill, hatch = style(i, styles)
        path = ring_slice_path(cx, cy, r_out, r_in, angle, a1) if sweep < 2 * math.pi - 1e-6 else \
            '%s %s' % (_circle_path(cx, cy, r_out), _circle_path(cx, cy, r_in))
        rule = 'f*' if sweep >= 2 * math.pi - 1e-6 else 'f'
        doc._op('%s rg %s %s' % (_rgb(fill), path, rule))
        if hatch:
            lines = _hatch_lines(cx - r_out, cy - r_out, 2 * r_out, 2 * r_out, hatch, 3.4)
            doc._op('q %s W%s n %s RG 0.45 w %s S Q' % (path, '*' if rule == 'f*' else '', _rgb(_hatch_color(fill)),
                                                        ' '.join(lines)))
        if len(items) > 1:
            doc._op('1 1 1 RG 1 w %s %s m %s %s l S' % (_n(cx + r_in * math.cos(angle)), _n(cy + r_in * math.sin(angle)),
                                                       _n(cx + r_out * math.cos(angle)),
                                                       _n(cy + r_out * math.sin(angle))))
        angle = a1
    center = fmt(total, language) if center is None else center
    text_center(doc, cx, cy - 2, center, pdf.BOLD, 11, pdf.TEXT)
    lx = doc.left + size + 22
    ly = top - (height - rows_h) / 2.0
    val_x = doc.left + doc.width
    for i, (label, value) in enumerate(items):
        fill, hatch = style(i, styles)
        swatch(doc, lx, ly - 8.5, fill, hatch, 7.5)
        doc.text(lx + 12, ly - 7.6, pdf.fit(label, pdf.REGULAR, 7.8, val_x - lx - 110), pdf.REGULAR, 7.8, pdf.TEXT)
        pct = fmt(100.0 * value / total, language, 1) + '%'
        doc.text_right(val_x, ly - 7.6, '%s  (%s)' % (fmt(value, language), pct), pdf.BOLD, 7.8, pdf.TEXT)
        ly -= 12.5
    doc.y = top - height - 4
    if note:
        doc.paragraph(note, 7.5, color=pdf.MUTED, space_after=2)
    doc.y -= 6
    return 'chart'


def sparkline(doc, x, y, w, h, values, color=LINES[0][0], fill='#dbe7f3', last_marker=True):
    """ tiny line in the box (x, y lower left, w, h); None values are skipped; returns False when empty """
    vals = [float(v) for v in values if v is not None]
    if len(vals) < 2 or not any(vals):
        doc.line(x, y + 1, x + w, y + 1, GRID, 0.8)
        return False
    lo, hi = min(vals + [0.0]), max(vals)
    span = (hi - lo) or 1.0
    n = len(vals)
    pts = [(x + i * w / float(n - 1), y + (v - lo) / span * h) for i, v in enumerate(vals)]
    path = '%s %s m ' % (_n(x), _n(y)) + ' '.join('%s %s l' % (_n(a), _n(b)) for a, b in pts) + \
           ' %s %s l h' % (_n(x + w), _n(y))
    doc._op('%s rg %s f' % (_rgb(fill), path))
    stroke_line(doc, pts, color, 1.0)
    if last_marker:
        marker(doc, pts[-1][0], pts[-1][1], 'circle', color, 1.6)
        peak = max(range(n), key=lambda i: vals[i])
        if peak != n - 1:
            marker(doc, pts[peak][0], pts[peak][1], 'triangle', '#4b5563', 1.6)
    return True


def overview(doc, cards, language='en_US', title=None, height=66.0):
    """
    panel of up to 4 cards: {label, value (text), values (series for the sparkline), delta (text or None),
    hint (small text, e.g. "per hour")}
    """
    cards = [c for c in cards if c][:4]
    if not cards:
        return 'empty'
    top = _title(doc, title, height)
    gap = 8.0
    w = (doc.width - gap * 3) / 4.0               # always 4 columns: the cards keep their size
    for i, card in enumerate(cards):
        x = doc.left + i * (w + gap)
        doc.rect(x, top - height, w, height, fill=pdf.CARD_BG, stroke=pdf.RULE, line_width=0.6)
        doc.text(x + 6, top - 11, pdf.fit(str(card.get('label', '')).upper(), pdf.BOLD, 6.6, w - 12), pdf.BOLD, 6.6,
                 pdf.MUTED)
        doc.text(x + 6, top - 27, pdf.fit(str(card.get('value', '-')), pdf.BOLD, 13, w - 12), pdf.BOLD, 13, pdf.TEXT)
        if card.get('delta'):
            doc.text_right(x + w - 6, top - 26, pdf.fit(card['delta'], pdf.REGULAR, 6.6, w * 0.5), pdf.REGULAR, 6.6,
                           pdf.MUTED)
        ok = sparkline(doc, x + 6, top - height + 13, w - 12, 18, card.get('values') or [])
        hint = card.get('hint') if ok else tr(language, 'no_data')
        if hint:
            doc.text(x + 6, top - height + 4, pdf.fit(hint, pdf.REGULAR, 6.0, w - 12), pdf.REGULAR, 6.0, pdf.MUTED)
    doc.y = top - height - 10
    return 'chart'


# ------------------------------------------------------------------ time buckets (labels)

def bucket_labels(starts, step, language='en_US'):
    """ x labels of the time buckets: "07h" (hours), "seg 03" (weekly, days), "03/11" (longer, days) """
    import time as _time
    fmt = i18n.number_format(language)
    days = i18n.section(language, 'weekdays')
    out = []
    for ts in starts:
        tm = _time.localtime(ts)
        if step < 86400:
            out.append(_time.strftime(fmt.get('hour') or '%H:00', tm))
        elif len(starts) <= 8:
            out.append('%s %s' % (days[tm.tm_wday], _time.strftime('%d', tm)))
        else:
            out.append(_time.strftime(fmt.get('day_month') or '%d/%m', tm))
    return out


# ------------------------------------------------------------------ scatter and ranges (AI evaluation)

def scatter(doc, points, title=None, language='en_US', x_label='', y_label='', x_range=(0.0, 100.0),
            y_range=(0.0, 100.0), guides=None, series=None, height=190.0, note=None, numbered=True):
    """
    :param points: [{"x", "y", "series": index, "label": short text (a number), "ring": bool}]
    :param guides: {"x": value, "y": value} dashed threshold lines (e.g. 80 on the effectiveness axis)
    :param series: names of the series (legend); each series has a marker shape and a colour (LINES)
    Each point is drawn with the marker of its series and its label next to it, so the reader can match it
    with a table (no meaning depends on colour alone).
    """
    pts = [p for p in points or [] if p.get('x') is not None and p.get('y') is not None]
    if not pts:
        return empty(doc, title, language)
    entries = [(name, 'line', i, None) for i, name in enumerate(series or []) if name]
    leg_h = _legend_height(doc, entries, doc.width)
    top = _title(doc, title, height + leg_h)
    legend(doc, doc.left, top, doc.width, entries)
    x0v, x1v = x_range
    y0v, y1v = y_range
    y_step = nice_step((y1v - y0v) / 4.0)
    y_label_w = _y_label_width(y0v, y1v, y_step, language) + (10 if y_label else 0)
    x_plot = doc.left + y_label_w
    w_plot = doc.width - y_label_w - 10
    y0 = top - leg_h - height + 26
    h_plot = height - 26 - 10
    _y_axis(doc, x_plot, y0, w_plot, h_plot, y0v, y1v, y_step, language)
    x_step = nice_step((x1v - x0v) / 5.0)
    for value in ticks_of(x0v, x1v, x_step):
        x = x_plot + (value - x0v) / (x1v - x0v) * w_plot
        doc.line(x, y0, x, y0 + h_plot, GRID, 0.4)
        text_center(doc, x, y0 - AXIS_SIZE - 3, compact(value, language, decimals_for(x_step)))
    doc.rect(x_plot, y0, w_plot, h_plot, stroke=AXIS, line_width=0.6)
    if x_label:
        text_center(doc, x_plot + w_plot / 2.0, y0 - 2 * AXIS_SIZE - 7, x_label, pdf.BOLD, AXIS_SIZE, LABEL)
    if y_label:
        doc.text(doc.left, y0 + h_plot + 3, pdf.fit(y_label, pdf.BOLD, AXIS_SIZE, doc.width / 2), pdf.BOLD, AXIS_SIZE,
                 LABEL)

    def px(v):
        return x_plot + (min(max(float(v), x0v), x1v) - x0v) / (x1v - x0v) * w_plot

    def py(v):
        return y0 + (min(max(float(v), y0v), y1v) - y0v) / (y1v - y0v) * h_plot
    for axis, value in sorted((guides or {}).items()):
        if axis == 'x' and x0v < value < x1v:
            stroke_line(doc, [(px(value), y0), (px(value), y0 + h_plot)], HIGHLIGHT, 0.8, '[3 2] 0')
        if axis == 'y' and y0v < value < y1v:
            stroke_line(doc, [(x_plot, py(value)), (x_plot + w_plot, py(value))], HIGHLIGHT, 0.8, '[3 2] 0')
    placed = []
    for p in pts:
        color, _dash, shape = LINES[int(p.get('series') or 0) % len(LINES)]
        x, y = px(p['x']), py(p['y'])
        marker(doc, x, y, shape, color, 2.6)
        if p.get('ring'):
            ring(doc, x, y)
        label = str(p.get('label') or '')
        if numbered and label:
            lx, ly = x + 4, y + 2
            for (ox, oy) in placed:                # move a label that would sit on another one
                if abs(ox - lx) < 9 and abs(oy - ly) < 7:
                    ly -= 7
            placed.append((lx, ly))
            doc.text(lx, ly, label, pdf.BOLD, 6.2, pdf.TEXT)
    doc.y = top - leg_h - height - 4
    if note:
        doc.paragraph(note, 7.5, color=pdf.MUTED, space_after=2)
    doc.y -= 6
    return 'chart'


def ranges(doc, labels, rows, title=None, language='en_US', limits=None, value_format=None, row=13.0, note=None,
           max_items=24):
    """
    :param rows: [(minimum, p50, p95, maximum)] per label (None = not measured)
    :param limits: per label the limit drawn as a red tick (e.g. the time budget of the scenario)
    The line goes from minimum to maximum, a thick bar from p50 to p95, a circle at p50; the scale is shared.
    """
    labels = list(labels)[:max_items]
    rows = list(rows)[:len(labels)]
    limits = list(limits or [])[:len(labels)]
    vals = [v for r in rows for v in r if v is not None] + [v for v in limits if v]
    if not labels or not vals or not any(vals):
        return empty(doc, title, language)
    fmt_v = value_format or (lambda v: compact(v, language))
    entries = [(tr(language, 'range'), 'box', '#9ca3af', None), ('p50–p95', 'box', PALETTE[0][0], None),
               (tr(language, 'limit'), 'box', HIGHLIGHT, None)]
    leg_h = _legend_height(doc, entries, doc.width)
    height = row * len(labels) + 18
    top = _title(doc, title, height + leg_h)
    legend(doc, doc.left, top, doc.width, entries)
    size = 7.4
    lab_w = min(doc.width * 0.3, max(pdf.text_width(str(lab), pdf.REGULAR, size) for lab in labels) + 8)
    val_w = 34.0
    area = doc.width - lab_w - val_w
    low, high, step = nice_scale(max(vals), 0, 4)
    x_of = lambda v: doc.left + lab_w + (float(v) - low) / (high - low) * area   # noqa: E731
    y = top - leg_h
    for value in ticks_of(low, high, step):
        doc.line(x_of(value), y - height + 14, x_of(value), y, GRID, 0.4)
        text_center(doc, x_of(value), y - height + 6, fmt_v(value))
    for i, lab in enumerate(labels):
        mn, p50, p95, mx = (list(rows[i]) + [None] * 4)[:4]
        cy = y - row / 2.0 - 1
        doc.text(doc.left, cy - size / 2.0 + 1.5, pdf.fit(str(lab), pdf.REGULAR, size, lab_w - 6), pdf.REGULAR, size,
                 pdf.TEXT)
        if mn is not None and mx is not None:
            stroke_line(doc, [(x_of(mn), cy), (x_of(mx), cy)], '#9ca3af', 1.0)
        if p50 is not None and p95 is not None:
            fill_rect(doc, x_of(p50), cy - 2.6, max(1.5, x_of(p95) - x_of(p50)), 5.2, PALETTE[0][0])
        if p50 is not None:
            marker(doc, x_of(p50), cy, 'circle', '#ffffff', 2.2, PALETTE[0][0])
            doc.text(doc.left + lab_w + area + 4, cy - VALUE_SIZE / 2.0 + 1, fmt_v(p50), pdf.BOLD, VALUE_SIZE,
                     pdf.TEXT)
        if i < len(limits) and limits[i]:
            lx = x_of(limits[i])
            doc.line(lx, cy - 4.5, lx, cy + 4.5, HIGHLIGHT, 1.4)
        y -= row
    doc.y = top - leg_h - height - 4
    if note:
        doc.paragraph(note, 7.5, color=pdf.MUTED, space_after=2)
    doc.y -= 6
    return 'chart'
