/*
 * Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.

/**
 * Shared helpers of the Posture, AI usage and Minimal rule screens (posture.js, aiusage.js, minrule.js).
 *
 *   PAInsights.esc(v)                     HTML escape
 *   PAInsights.answer(data, S)            HTML of an AI answer (PAMarkdown when loaded, else plain text)
 *   PAInsights.dialog({title, message, buttons, wide})   BootstrapDialog (PASimulation.dialog when loaded)
 *   PAInsights.diff(text)                 <pre> of a textual diff with +/- lines coloured
 *   PAInsights.gauge(score, grade)        SVG ring 0-100
 *   PAInsights.spark(values, opts)        SVG sparkline with hover titles
 *   PAInsights.hbars(items, opts)         horizontal bars [{label, value, color, title}]
 *   PAInsights.stacked(days, series, opts)  stacked day columns [{day, by_service}] x [{id, name, color}]
 *   PAInsights.PALETTE                    categorical order (validated reference palette), fixed per entity
 *
 * Charts are plain SVG strings: text uses currentColor so light and dark themes keep their ink; every mark has
 * a <title> (hover tooltip) and every chart has a table/list view next to it on the page.
 */
const PAInsights = (function () {
    'use strict';

    const PALETTE = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948'];
    const OTHER = '#8a8984';
    const STATUS = {pass: '#0ca30c', warn: '#fab219', fail: '#d03b3b', na: '#8a8984'};

    function esc(value) {
        return String(value === undefined || value === null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function answer(data, S) {
        S = S || {};
        if (!data) {
            return '<div class="alert alert-danger">' + esc(S.error || 'No answer.') + '</div>';
        }
        if (data.status === 'disabled') {
            return '<div class="alert alert-info">' + esc(data.message || S.aiDisabled) + '</div>';
        }
        if (data.status === 'refusal') {
            return '<div class="alert alert-warning">' + esc(data.message) + '</div>';
        }
        if (data.status !== 'ok') {
            return '<div class="alert alert-danger">' + esc(data.message || S.error || 'Error') + '</div>';
        }
        if (data.messages) {
            /* preview: exactly what would be sent */
            return '<p class="text-muted">' + esc((data.anonymized ? S.anonymized : S.notAnonymized) || '') + ', ' +
                esc(data.bytes) + ' bytes</p>' + data.messages.map(function (m) {
                    return '<h5>' + esc(m.role) + '</h5><pre class="pa-ins-pre">' + esc(m.content) + '</pre>';
                }).join('');
        }
        let body;
        if (typeof PAMarkdown !== 'undefined' && PAMarkdown.render) {
            body = '<div class="pa-ins-answer">' + PAMarkdown.render(data.text || '') + '</div>';
        } else {
            body = '<div class="pa-ins-answer pa-ins-plain">' + esc(data.text || '') + '</div>';
        }
        const meta = [data.provider, data.model].filter(Boolean).join(' / ');
        return body + '<p class="text-muted pa-ins-meta"><small>' + esc(meta) +
            (data.duration_ms ? ', ' + esc(Math.round(data.duration_ms / 100) / 10) + ' s' : '') +
            (data.cached ? ', ' + esc(S.cached || 'cached') : '') +
            ', ' + esc((data.anonymized ? S.anonymized : S.notAnonymized) || '') + '<br/>' +
            esc(S.aiDisclaimer || '') + '</small></p>';
    }

    function dialog(opts) {
        const options = {
            title: opts.title, message: opts.message, buttons: opts.buttons || [],
            size: opts.wide === false ? BootstrapDialog.SIZE_NORMAL : BootstrapDialog.SIZE_WIDE,
            onshown: opts.onshown
        };
        if (typeof PASimulation !== 'undefined' && PASimulation.dialog) {
            return PASimulation.dialog(options);
        }
        options.cssClass = 'pa-dialog';
        return BootstrapDialog.show(options);
    }

    function diff(text) {
        return '<pre class="pa-ins-diff">' + String(text || '').split('\n').map(function (line) {
            const cls = line.charAt(0) === '+' ? 'pa-add' : (line.charAt(0) === '-' ? 'pa-del' :
                (line.charAt(0) === '#' ? 'pa-hdr' : ''));
            return '<span class="' + cls + '">' + esc(line) + '</span>';
        }).join('\n') + '</pre>';
    }

    function gradeColor(score) {
        if (score === null || score === undefined) {
            return STATUS.na;
        }
        return score >= 80 ? STATUS.pass : (score >= 60 ? STATUS.warn : STATUS.fail);
    }

    function gauge(score, grade, size) {
        size = size || 96;
        const r = size / 2 - 7;
        const c = 2 * Math.PI * r;
        const value = Math.max(0, Math.min(100, score || 0));
        const color = gradeColor(score);
        return '<svg class="pa-ins-gauge" width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' +
            size + '" role="img" aria-label="score ' + esc(score) + '"><title>' + esc(score) + ' / 100</title>' +
            '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="currentColor" ' +
            'stroke-opacity="0.12" stroke-width="8"/>' +
            '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + color +
            '" stroke-width="8" stroke-linecap="round" stroke-dasharray="' + (c * value / 100).toFixed(1) + ' ' +
            c.toFixed(1) + '" transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')"/>' +
            '<text x="50%" y="47%" text-anchor="middle" dominant-baseline="middle" fill="currentColor" ' +
            'font-size="' + Math.round(size * 0.27) + '" font-weight="700">' + esc(score === null ? '–' :
                Math.round(score)) + '</text>' +
            '<text x="50%" y="72%" text-anchor="middle" fill="currentColor" fill-opacity="0.7" font-size="' +
            Math.round(size * 0.14) + '">' + esc(grade || '') + '</text></svg>';
    }

    function spark(points, opts) {
        opts = opts || {};
        const w = opts.width || 220;
        const h = opts.height || 44;
        const vals = points.map(function (p) { return p.value; });
        if (!vals.length) {
            return '<span class="text-muted small">' + esc(opts.empty || '') + '</span>';
        }
        const min = opts.min !== undefined ? opts.min : Math.min.apply(null, vals);
        const max = opts.max !== undefined ? opts.max : Math.max.apply(null, vals);
        const span = (max - min) || 1;
        const step = vals.length > 1 ? (w - 8) / (vals.length - 1) : 0;
        const xy = vals.map(function (v, i) {
            return [4 + i * step, h - 5 - (h - 10) * (v - min) / span];
        });
        let svg = '<svg class="pa-ins-spark" width="100%" height="' + h + '" viewBox="0 0 ' + w + ' ' + h +
            '" preserveAspectRatio="none" role="img">';
        svg += '<polyline fill="none" stroke="' + (opts.color || PALETTE[0]) + '" stroke-width="2" ' +
            'vector-effect="non-scaling-stroke" points="' + xy.map(function (p) {
                return p[0].toFixed(1) + ',' + p[1].toFixed(1);
            }).join(' ') + '"/>';
        xy.forEach(function (p, i) {
            svg += '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="' +
                (i === xy.length - 1 ? 3.5 : 6) + '" fill="' + (i === xy.length - 1 ? (opts.color || PALETTE[0]) :
                'transparent') + '"><title>' + esc(points[i].label) + '</title></circle>';
        });
        return svg + '</svg>';
    }

    function hbars(items, opts) {
        opts = opts || {};
        const max = Math.max.apply(null, items.map(function (i) { return i.value; }).concat([1]));
        return '<div class="pa-ins-hbars">' + items.map(function (i) {
            const pct = Math.max(1, Math.round(100 * i.value / max));
            return '<div class="pa-ins-hbar" title="' + esc(i.title || (i.label + ': ' + i.value)) + '">' +
                '<span class="pa-ins-hbar-label">' + (i.swatch !== false ? '<i style="background:' +
                esc(i.color || PALETTE[0]) + '"></i>' : '') + esc(i.label) + '</span>' +
                '<span class="pa-ins-hbar-track"><span style="width:' + pct + '%;background:' +
                esc(i.color || PALETTE[0]) + '"></span></span>' +
                '<span class="pa-ins-hbar-value">' + esc(i.text !== undefined ? i.text : i.value) + '</span></div>';
        }).join('') + '</div>';
    }

    function stacked(days, series, opts) {
        opts = opts || {};
        const w = opts.width || 560;
        const h = opts.height || 150;
        const pad = {l: 34, r: 6, t: 8, b: 20};
        const totals = days.map(function (d) {
            return series.reduce(function (sum, s) { return sum + (s.value(d) || 0); }, 0);
        });
        const max = Math.max.apply(null, totals.concat([1]));
        const nice = Math.pow(10, Math.floor(Math.log10(max)));
        const top = Math.ceil(max / nice) * nice;
        const slot = (w - pad.l - pad.r) / Math.max(days.length, 1);
        const bw = Math.max(4, Math.min(42, slot * 0.62));
        let svg = '<svg class="pa-ins-stacked" width="100%" viewBox="0 0 ' + w + ' ' + h + '" role="img">';
        [0, 0.5, 1].forEach(function (f) {
            const y = pad.t + (h - pad.t - pad.b) * (1 - f);
            svg += '<line x1="' + pad.l + '" x2="' + (w - pad.r) + '" y1="' + y + '" y2="' + y +
                '" stroke="currentColor" stroke-opacity="' + (f === 0 ? 0.35 : 0.1) + '"/>' +
                '<text x="' + (pad.l - 4) + '" y="' + (y + 3) + '" text-anchor="end" font-size="9" ' +
                'fill="currentColor" fill-opacity="0.65">' + esc(Math.round(top * f)) + '</text>';
        });
        days.forEach(function (d, i) {
            const x = pad.l + slot * i + (slot - bw) / 2;
            let y = h - pad.b;
            const parts = [];
            series.forEach(function (s) {
                const v = s.value(d) || 0;
                if (!v) {
                    return;
                }
                const bh = (h - pad.t - pad.b) * v / top;
                y -= bh;
                parts.push({y: y, h: bh, color: s.color, title: s.name + ': ' + v});
            });
            parts.forEach(function (p, idx) {
                /* 2px surface gap between segments; rounded top on the last one */
                const gap = idx < parts.length - 1 ? 1 : 0;
                svg += '<rect x="' + x.toFixed(1) + '" y="' + (p.y + gap).toFixed(1) + '" width="' + bw.toFixed(1) +
                    '" height="' + Math.max(0.5, p.h - gap).toFixed(1) + '" rx="' + (idx === parts.length - 1 ? 3 : 0) +
                    '" fill="' + p.color + '"><title>' + esc(d.day + ' — ' + p.title) + '</title></rect>';
            });
            svg += '<rect x="' + (pad.l + slot * i).toFixed(1) + '" y="' + pad.t + '" width="' + slot.toFixed(1) +
                '" height="' + (h - pad.t - pad.b) + '" fill="transparent"><title>' + esc(d.day + ': ' + totals[i]) +
                '</title></rect>';
            if (days.length <= 16 || i % Math.ceil(days.length / 10) === 0) {
                svg += '<text x="' + (pad.l + slot * i + slot / 2).toFixed(1) + '" y="' + (h - 6) +
                    '" text-anchor="middle" font-size="9" fill="currentColor" fill-opacity="0.7">' +
                    esc(String(d.day).slice(5)) + '</text>';
            }
        });
        return svg + '</svg>';
    }

    function legend(series) {
        return '<div class="pa-ins-legend">' + series.map(function (s) {
            return '<span><i style="background:' + esc(s.color) + '"></i>' + esc(s.name) + '</span>';
        }).join('') + '</div>';
    }

    function when(iso) {
        if (!iso) {
            return '';
        }
        const d = new Date(iso);
        return isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
    }

    function ago(seconds, S) {
        if (seconds === null || seconds === undefined) {
            return '';
        }
        if (seconds < 90) {
            return (S && S.justNow) || 'just now';
        }
        const m = Math.round(seconds / 60);
        return m < 90 ? m + ' min' : Math.round(m / 60) + ' h';
    }

    function wait(text) {
        return '<p class="pa-ins-wait"><i class="fa fa-spinner fa-pulse"></i> ' + esc(text) + '</p>';
    }

    return {
        PALETTE: PALETTE, OTHER: OTHER, STATUS: STATUS, esc: esc, answer: answer, dialog: dialog, diff: diff,
        gauge: gauge, spark: spark, hbars: hbars, stacked: stacked, legend: legend, when: when, ago: ago, wait: wait,
        gradeColor: gradeColor
    };
})();
