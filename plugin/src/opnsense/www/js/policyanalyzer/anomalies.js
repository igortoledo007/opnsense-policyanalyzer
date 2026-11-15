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
 * Policy Analyzer: Anomalies page (/ui/policyanalyzer/anomalies).
 *
 *   PAAnomalies.init({strings: {...}})
 *
 * Reads /api/policyanalyzer/anomalies/{summary,status,search,finding,host}; explanations through
 * POST .../explain (text only); every change (install, expected, close, exceptions, parameters, quarantine of an
 * external address) opens the PASimulation dialog: plan first, apply after confirmation, journaled.
 * The sparklines are inline SVG (no chart library).
 */
const PAAnomalies = (function () {
    'use strict';

    const API = '/api/policyanalyzer/anomalies';
    const SEV = ['high', 'medium', 'low', 'info'];
    const TYPES = ['beaconing', 'dga', 'dns_tunnel', 'volume', 'rare_destination', 'new_device', 'internal_scan',
                   'dns_bypass', 'new_domain', 'tls'];
    const ICONS = {beaconing: 'fa-heartbeat', dga: 'fa-random', dns_tunnel: 'fa-exchange', volume: 'fa-upload',
                   rare_destination: 'fa-globe', new_device: 'fa-plug', internal_scan: 'fa-crosshairs',
                   dns_bypass: 'fa-share', new_domain: 'fa-asterisk', tls: 'fa-lock'};
    let T = {};
    const state = {severity: '', type: '', status: 'open', days: '7', search: '', host: '', selected: null,
                   rows: [], status_data: null, ai: {enabled: false}, finding: null};

    function esc(value) {
        return $('<div/>').text(value === undefined || value === null ? '' : String(value)).html();
    }

    function mobile() {
        return window.matchMedia('(max-width: 767px)').matches;
    }

    function ago(seconds) {
        seconds = Math.max(0, Math.round(seconds));
        if (seconds < 90) {
            return seconds + ' s';
        }
        if (seconds < 5400) {
            return Math.round(seconds / 60) + ' min';
        }
        if (seconds < 172800) {
            return Math.round(seconds / 3600) + ' h';
        }
        return Math.round(seconds / 86400) + ' d';
    }

    function when(iso) {
        if (!iso) {
            return '-';
        }
        const d = new Date(iso);
        return isNaN(d) ? iso : d.toLocaleString();
    }

    function fmtBytes(v) {
        return PASimulation.fmtBytes ? PASimulation.fmtBytes(v) : v + ' B';
    }

    function typeName(t) {
        return T['t_' + t] || t;
    }

    function sevLabel(s) {
        return '<span class="pa-an-sev sev-' + esc(s) + '">' + esc(T[s] || s) + '</span>';
    }

    function b64(text) {
        try {
            return text ? btoa(unescape(encodeURIComponent(text))) : '-';
        } catch (e) {
            return '-';
        }
    }

    /******************************************************************************************************
     * sparkline: values (solid) against the baseline (dashed), the last point marked
     ******************************************************************************************************/
    let sparkSeq = 0;
    // smooth path through the points: monotone cubic (Fritsch-Carlson), so the curve passes through every point
    // and never overshoots (no dip before a jump, no bump above a peak)
    function smoothPath(pts) {
        const n = pts.length;
        const d = [], m = [];
        for (let k = 0; k < n - 1; k++) { d.push((pts[k + 1][1] - pts[k][1]) / ((pts[k + 1][0] - pts[k][0]) || 1e-9)); }
        m.push(d[0]);
        for (let k = 1; k < n - 1; k++) { m.push(d[k - 1] * d[k] <= 0 ? 0 : (d[k - 1] + d[k]) / 2); }
        m.push(d[n - 2]);
        for (let k = 0; k < n - 1; k++) {
            if (d[k] === 0) { m[k] = 0; m[k + 1] = 0; continue; }
            const a = m[k] / d[k], b = m[k + 1] / d[k];
            if (a * a + b * b > 9) { const t = 3 / Math.sqrt(a * a + b * b); m[k] = t * a * d[k]; m[k + 1] = t * b * d[k]; }
        }
        let path = 'M' + pts[0][0].toFixed(1) + ' ' + pts[0][1].toFixed(1);
        for (let k = 0; k < n - 1; k++) {
            const h = (pts[k + 1][0] - pts[k][0]) / 3;
            path += ' C' + (pts[k][0] + h).toFixed(1) + ' ' + (pts[k][1] + m[k] * h).toFixed(1) + ' ' +
                (pts[k + 1][0] - h).toFixed(1) + ' ' + (pts[k + 1][1] - m[k + 1] * h).toFixed(1) + ' ' +
                pts[k + 1][0].toFixed(1) + ' ' + pts[k + 1][1].toFixed(1);
        }
        return path;
    }

    /******************************************************************************************************
     * sparkline: values (smooth line over a gradient area) against the baseline (dashed); the stretch above the
     * baseline is tinted, faint grid lines, the peak and the last point marked
     ******************************************************************************************************/
    function sparkline(series, opts) {
        opts = Object.assign({w: 300, h: 60, pad: 4}, opts || {});
        const pts = (series && series.points) || [];
        if (pts.length < 2) {
            return '<div class="pa-an-spark-empty text-muted"><small>' + esc(T.noData) + '</small></div>';
        }
        const vals = pts.map(function (p) { return Number(p.v) || 0; });
        const base = pts.map(function (p) { return p.b === null || p.b === undefined ? null : Number(p.b); });
        const max = (Math.max.apply(null, vals.concat(base.filter(function (b) { return b !== null; }))) || 1) * 1.08;
        const w = opts.w, h = opts.h, pad = opts.pad;
        const x = function (i) { return pad + i * (w - 2 * pad) / (pts.length - 1); };
        const y = function (v) { return h - pad - (v / max) * (h - 2 * pad); };
        const top = pad, bottom = h - pad;
        const vp = vals.map(function (v, i) { return [x(i), y(v)]; });
        const line = smoothPath(vp);
        const area = line + ' L' + x(pts.length - 1).toFixed(1) + ' ' + bottom + ' L' + x(0).toFixed(1) + ' ' + bottom + ' Z';
        let bline = '';
        const bp = [];
        base.forEach(function (b, i) {
            if (b !== null) {
                bline += (bline ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(b).toFixed(1) + ' ';
                bp.push([x(i), y(b)]);
            }
        });
        const id = 'paSpark' + (++sparkSeq);
        // above-baseline tint: the value area clipped to the region over the baseline line
        let over = '';
        if (bp.length > 1) {
            const above = 'M' + bp[0][0].toFixed(1) + ' ' + top + ' ' + bp.map(function (p) {
                return 'L' + p[0].toFixed(1) + ' ' + p[1].toFixed(1);
            }).join(' ') + ' L' + bp[bp.length - 1][0].toFixed(1) + ' ' + top + ' Z';
            over = '<clipPath id="' + id + 'c"><path d="' + above + '"/></clipPath>' +
                '<path class="over" clip-path="url(#' + id + 'c)" d="' + area + '"/>';
        }
        const grid = [0.25, 0.5, 0.75].map(function (f) {
            const gy = (top + (bottom - top) * f).toFixed(1);
            return '<path class="grid" d="M' + pad + ' ' + gy + ' L' + (w - pad) + ' ' + gy + '"/>';
        }).join('');
        const last = vals.length - 1;
        let peak = 0;
        vals.forEach(function (v, i) { if (v > vals[peak]) { peak = i; } });
        // dots as zero-length round-capped strokes: they stay round although the SVG stretches to the box
        const dot = function (cls, i) {
            return '<path class="' + cls + '" d="M' + x(i).toFixed(1) + ' ' + y(vals[i]).toFixed(1) + ' h0.01"/>';
        };
        const unit = series.unit === 'B' ? fmtBytes : function (v) { return Math.round(v * 10) / 10 + (series.unit || ''); };
        const title = esc(series.label || '') + ': ' + esc(T.current) + ' ' + esc(unit(vals[last])) +
            (base[last] !== null ? ', ' + esc(T.baseline) + ' ' + esc(unit(base[last])) : '');
        return '<svg class="pa-an-spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" role="img" ' +
            'aria-label="' + title + '"><title>' + title + '</title>' +
            '<defs><linearGradient id="' + id + 'g" x1="0" y1="0" x2="0" y2="1">' +
            '<stop offset="0" class="g0"/><stop offset="1" class="g1"/></linearGradient></defs>' + grid +
            '<path class="area" fill="url(#' + id + 'g)" d="' + area + '"/>' + over +
            (bline ? '<path class="base" d="' + bline + '"/>' : '') +
            '<path class="value" d="' + line + '"/>' +
            (peak !== last ? dot('peak', peak) : '') + dot('halo', last) + dot('last', last) + '</svg>' +
            '<div class="pa-an-spark-legend"><span class="lv"></span>' + esc(series.label || '') +
            ' <span class="lb"></span>' + esc(T.baseline) + ' <b>' + esc(unit(vals[last])) + '</b>' +
            (base[last] !== null ? ' / ' + esc(unit(base[last])) : '') +
            ' <span class="pk">▲ ' + esc(unit(vals[peak])) + '</span></div>';
    }

    /******************************************************************************************************
     * header, cards, filters
     ******************************************************************************************************/
    function loadStatus() {
        ajaxGet(API + '/status', {}, function (data) {
            state.status_data = data || {};
            renderState();
        });
        ajaxGet('/api/policyanalyzer/ai/status', {}, function (data) {
            state.ai = data || {enabled: false};
        });
    }

    function renderState() {
        const d = state.status_data || {};
        const last = d.last_run || null;
        let html;
        if (!d.installed) {
            html = '<span class="pa-an-dot off"></span> ' + esc(T.notInstalled) +
                ' <button type="button" class="btn btn-primary btn-xs" id="pa_an_install">' +
                '<i class="fa fa-calendar-plus-o fa-fw"></i> ' + esc(T.install) + '</button>';
        } else {
            html = '<span class="pa-an-dot on"></span> ' + esc(T.installed);
        }
        if (last && last.ts) {
            const age = Date.now() / 1000 - last.ts;
            html += ' <span class="text-muted">&middot; ' + esc(T.lastRun) + ' ' + esc(ago(age)) + ' ' + esc(T.ago) +
                (last.duration_ms !== undefined ? ' (' + esc((last.duration_ms / 1000).toFixed(1)) + ' s)' : '') +
                '</span>';
            const srcs = last.sources || {};
            const bad = Object.keys(srcs).filter(function (k) { return srcs[k] !== 'ok'; });
            if (bad.length) {
                html += ' <span class="pa-an-src-warn" title="' + esc(bad.map(function (k) {
                    return k + ': ' + (T[srcs[k]] || srcs[k]);
                }).join(', ')) + '"><i class="fa fa-exclamation-triangle"></i> ' +
                    esc(bad.map(function (k) { return k + ' ' + (T[srcs[k]] || srcs[k]); }).join(', ')) + '</span>';
            }
        } else {
            html += ' <span class="text-muted">&middot; ' + esc(T.lastRun) + ' ' + esc(T.never) + '</span>';
        }
        $('#pa_an_state').html(html);
        $('#pa_an_uninstall').toggle(!!d.installed);
    }

    function loadSummary() {
        ajaxGet(API + '/summary', {}, function (data) {
            data = data || {};
            const bySev = data.by_severity || {};
            SEV.forEach(function (s) { $('#pa_an_c_' + s).text(bySev[s] || 0); });
            const byType = data.by_type || {};
            const chips = TYPES.filter(function (t) { return byType[t]; }).map(function (t) {
                return '<button type="button" class="pa-an-chip' + (state.type === t ? ' active' : '') +
                    '" data-type="' + esc(t) + '"><i class="fa ' + ICONS[t] + ' fa-fw"></i>' + esc(typeName(t)) +
                    ' <b>' + esc(byType[t]) + '</b></button>';
            });
            if (data.new_24h) {
                chips.push('<span class="pa-an-new">' + esc(data.new_24h) + ' ' + esc(T.new24) + '</span>');
            }
            $('#pa_an_types').html(chips.join(''));
        });
    }

    function fillTypeSelect() {
        const sel = $('#pa_an_f_type').empty().append($('<option/>').val('').text(T.allTypes));
        TYPES.forEach(function (t) { sel.append($('<option/>').val(t).text(typeName(t))); });
    }

    /******************************************************************************************************
     * list
     ******************************************************************************************************/
    function query() {
        const q = {current: 1, rowCount: 200};
        ['severity', 'type', 'status', 'days', 'host'].forEach(function (k) {
            if (state[k]) {
                q[k] = state[k];
            }
        });
        if (state.search) {
            q.searchPhrase = state.search;
        }
        return q;
    }

    function loadList() {
        ajaxGet(API + '/search', query(), function (data) {
            state.rows = (data && data.rows) || [];
            renderList();
            if (state.selected && !mobile()) {
                if (state.rows.some(function (r) { return r.id === state.selected; })) {
                    select(state.selected, true);
                } else {
                    state.selected = null;
                    if (state.rows.length) {
                        select(state.rows[0].id, true);
                    } else {
                        renderEmptyDetail();
                    }
                }
            } else if (!state.selected && state.rows.length && !mobile()) {
                select(state.rows[0].id, true);
            } else if (!state.rows.length) {
                renderEmptyDetail();
            }
        });
    }

    function renderList() {
        const list = $('#pa_an_list');
        if (!state.rows.length) {
            list.html('<div class="pa-an-empty">' + esc(state.status_data && state.status_data.last_run ?
                T.noFindings : T.noData) + '</div>');
            return;
        }
        const now = Date.now() / 1000;
        list.html(state.rows.map(function (r) {
            return '<button type="button" class="pa-an-row sev-' + esc(r.severity) +
                (r.id === state.selected ? ' active' : '') + '" data-id="' + esc(r.id) + '">' +
                '<span class="pa-an-row-icon"><i class="fa ' + (ICONS[r.type] || 'fa-circle') + ' fa-fw"></i></span>' +
                '<span class="pa-an-row-main"><span class="pa-an-row-top">' + sevLabel(r.severity) +
                ' <b>' + esc(typeName(r.type)) + '</b> <span class="pa-an-row-host">' + esc(r.host) +
                (r.hostname ? ' <small>' + esc(r.hostname) + '</small>' : '') + '</span>' +
                (r.status !== 'open' ? ' <span class="pa-an-status">' + esc(T[r.status] || r.status) + '</span>' : '') +
                '</span><span class="pa-an-row-detail">' + esc(r.detail) + '</span></span>' +
                '<span class="pa-an-row-side"><span class="pa-an-score" title="' + esc(T.score) + ' ' + esc(r.score) +
                '"><span style="width:' + Math.max(4, Math.min(100, r.score)) + '%"></span></span>' +
                '<small>' + esc(ago(now - r.last_seen)) + '</small>' +
                (r.occurrences > 1 ? '<small class="pa-an-occ">&times;' + esc(r.occurrences) + '</small>' : '') +
                '</span></button>';
        }).join(''));
    }

    function renderEmptyDetail() {
        $('#pa_an_detail').html('<div class="pa-an-empty">' + esc(T.selectOne) + '</div>');
    }

    /******************************************************************************************************
     * detail
     ******************************************************************************************************/
    function factorRows(factors) {
        return (factors || []).map(function (f) {
            const met = f.met === true ? '<i class="fa fa-check-circle text-danger" title="' + esc(T.counted) + '"></i>' :
                (f.met === false ? '<i class="fa fa-circle-o text-muted"></i>' : '');
            return '<tr class="' + (f.met ? 'met' : '') + '"><td data-label="' + esc(T.factor) + '">' + met + ' ' +
                esc(f.name) + '<div class="pa-an-ftext">' + esc(f.text || '') + '</div></td>' +
                '<td data-label="' + esc(T.value) + '"><b>' + esc(f.value) + '</b>' + (f.unit ? ' ' + esc(f.unit) : '') +
                '</td><td data-label="' + esc(T.threshold) + '">' + (f.threshold !== undefined ? esc(f.threshold) +
                (f.unit ? ' ' + esc(f.unit) : '') : '-') + '</td></tr>';
        }).join('');
    }

    function evidenceHtml(f) {
        const ev = f.evidence || {};
        const items = [];
        const add = function (label, value) {
            if (value !== undefined && value !== null && value !== '' && !(Array.isArray(value) && !value.length)) {
                items.push('<dt>' + esc(label) + '</dt><dd>' + value + '</dd>');
            }
        };
        if (Array.isArray(ev.destinations)) {
            add('destinations', ev.destinations.slice(0, 8).map(function (d) {
                return esc(d.destination + ':' + d.port) + ' <small>(' + esc(d.connections) + ' &times; ' +
                    esc(Math.round(d.median_interval_s)) + ' s' +
                    (d.dst_info && d.dst_info.country ? ', ' + esc(d.dst_info.country) : '') + ')</small>';
            }).join('<br/>'));
        }
        if (Array.isArray(ev.samples)) {
            add('samples', ev.samples.slice(0, 8).map(function (s) {
                return esc(typeof s === 'string' ? s : s.name + ' (' + s.score + '%)');
            }).join('<br/>'));
        }
        if (Array.isArray(ev.domains) && f.type !== 'dga') {
            add('domains', ev.domains.slice(0, 10).map(function (d) {
                return esc(typeof d === 'string' ? d : d.domain);
            }).join(', '));
        }
        if (Array.isArray(ev.items)) {
            add('new', ev.items.map(function (i) {
                return esc((i.kind === 'asn' ? 'AS' : '') + i.value) + ' <small>' + esc(fmtBytes(i.bytes)) + ', ' +
                    esc(i.sample) + '</small>';
            }).join('<br/>'));
        }
        if (Array.isArray(ev.top)) {
            add('top', ev.top.map(function (t) { return esc(t[0]) + ' <small>' + esc(fmtBytes(t[1])) + '</small>'; })
                .join('<br/>'));
        }
        if (Array.isArray(ev.flows)) {
            add('flows', ev.flows.slice(0, 8).map(function (x) {
                return esc(x.dst + ':' + x.port + '/' + x.proto + ' ' + x.kind) + ' <small>&times;' + esc(x.flows) +
                    '</small>';
            }).join('<br/>'));
        }
        if (Array.isArray(ev.doh_lookups) && ev.doh_lookups.length) {
            add('DoH', esc(ev.doh_lookups.join(', ')));
        }
        if (Array.isArray(ev.targets)) {
            add('targets', esc(ev.targets.slice(0, 20).join(', ')));
        }
        ['subject', 'issuer', 'sni', 'ja4', 'mac', 'vendor', 'hostname', 'redirect'].forEach(function (k) {
            if (ev[k]) {
                add(k, esc(ev[k]));
            }
        });
        return items.length ? '<dl class="pa-an-ev">' + items.join('') + '</dl>' : '';
    }

    function actionButtons(f) {
        return (f.actions || []).map(function (a) {
            const cls = a.id === 'quarantine' ? 'btn-warning' : (a.id === 'expect' ? 'btn-default' : 'btn-default');
            const icon = {live_view: 'fa-list', live_view_dst: 'fa-list', console: 'fa-comments', quarantine: 'fa-ban',
                          expect: 'fa-check', host: 'fa-desktop'}[a.id] || 'fa-arrow-right';
            if (a.url && /^\/ui\/[A-Za-z0-9_\/#=.:&-]*$/.test(a.url)) {
                return '<a class="btn btn-sm ' + cls + '" href="' + esc(a.url) + '" target="_blank" rel="noopener">' +
                    '<i class="fa ' + icon + ' fa-fw"></i> ' + esc(a.label) + '</a>';
            }
            return '<button type="button" class="btn btn-sm ' + cls + ' pa-an-act" data-act="' + esc(a.id) + '"' +
                (a.target ? ' data-target="' + esc(a.target) + '"' : '') + (a.host ? ' data-host="' + esc(a.host) + '"' : '') +
                '><i class="fa ' + icon + ' fa-fw"></i> ' + esc(a.label) + '</button>';
        }).join(' ');
    }

    function detailHtml(f) {
        const params = Object.keys(f.params || {}).map(function (k) { return esc(k) + '=' + esc(f.params[k]); })
            .join(', ');
        return '<div class="pa-an-d sev-' + esc(f.severity) + '">' +
            '<div class="pa-an-d-head"><span class="pa-an-d-icon"><i class="fa ' + (ICONS[f.type] || 'fa-circle') +
            ' fa-fw"></i></span><div><h4>' + esc(f.title) + '</h4><div class="pa-an-d-meta">' + sevLabel(f.severity) +
            ' <span>' + esc(T.score) + ' <b>' + esc(f.score) + '</b></span> <span>' + esc(T.host) + ' <b>' +
            esc(f.host) + '</b>' + (f.hostname ? ' (' + esc(f.hostname) + ')' : '') + '</span>' +
            (f.status !== 'open' ? ' <span class="pa-an-status">' + esc(T[f.status] || f.status) + '</span>' : '') +
            '</div></div></div>' +
            '<p class="pa-an-d-text">' + esc(f.detail) + '</p>' +
            '<div class="pa-an-d-grid"><div class="pa-an-d-spark">' + sparkline(f.series) + '</div>' +
            '<div class="pa-an-d-times"><div><small>' + esc(T.firstSeen) + '</small> ' + esc(when(f.first_seen_iso)) +
            '</div><div><small>' + esc(T.lastSeen) + '</small> ' + esc(when(f.last_seen_iso)) + '</div><div><small>' +
            esc(T.occurrences) + '</small> ' + esc(f.occurrences) + '</div></div></div>' +
            '<h5>' + esc(T.factors) + '</h5><table class="table table-condensed pa-an-factors"><thead><tr><th>' +
            esc(T.factor) + '</th><th>' + esc(T.value) + '</th><th>' + esc(T.threshold) + '</th></tr></thead><tbody>' +
            factorRows(f.factors) + '</tbody></table>' +
            evidenceHtml(f) +
            (params ? '<p class="pa-an-params text-muted"><small>' + esc(T.parameters) + ': ' + params + '</small></p>' : '') +
            '<div class="pa-an-d-actions"><button type="button" class="btn btn-primary btn-sm pa-an-explain"' +
            (state.ai.enabled ? '' : ' disabled title="' + esc(T.aiDisabled) + '"') + '><i class="fa fa-magic fa-fw"></i> ' +
            esc(T.explain) + '</button> <button type="button" class="btn btn-default btn-sm pa-an-preview">' +
            '<i class="fa fa-eye fa-fw"></i> ' + esc(T.preview) + '</button> ' + actionButtons(f) +
            (f.status !== 'resolved' ? ' <button type="button" class="btn btn-default btn-sm pa-an-act" data-act="resolve">' +
                '<i class="fa fa-archive fa-fw"></i> ' + esc(T.resolve) + '</button>' : '') +
            '</div><p class="text-muted pa-an-suggest-note"><small>' + esc(T.suggestedNote) + '</small></p>' +
            '<div class="pa-an-ai" id="pa_an_ai"></div></div>';
    }

    function select(id, quiet) {
        state.selected = id;
        $('.pa-an-row').removeClass('active').filter('[data-id="' + id + '"]').addClass('active');
        ajaxGet(API + '/finding', {id: id}, function (data) {
            if (!data || data.status !== 'ok') {
                $('#pa_an_detail').html('<div class="alert alert-danger">' + esc((data && data.message) || T.error) +
                    '</div>');
                return;
            }
            state.finding = data.finding;
            if (mobile() && !quiet) {
                const dlg = PASimulation.dialog({title: typeName(data.finding.type), message: detailHtml(data.finding),
                    cssClass: 'pa-an-dialog', buttons: [{label: T.close, action: function (d) { d.close(); }}]});
                bindDetail(dlg.getModalBody());
            } else if (!mobile()) {
                $('#pa_an_detail').html(detailHtml(data.finding));
                bindDetail($('#pa_an_detail'));
            }
        });
    }

    /******************************************************************************************************
     * AI
     ******************************************************************************************************/
    function mdLite(text) {
        /* escaped first; then **bold**, headings and "- " lists only */
        const lines = esc(text || '').split(/\n/);
        let html = '', inList = false;
        lines.forEach(function (line) {
            const m = line.match(/^\s*[-*]\s+(.*)$/);
            if (m) {
                if (!inList) {
                    html += '<ul>';
                    inList = true;
                }
                html += '<li>' + m[1] + '</li>';
                return;
            }
            if (inList) {
                html += '</ul>';
                inList = false;
            }
            const h = line.match(/^\s*#{1,4}\s+(.*)$/);
            if (h) {
                html += '<h5>' + h[1] + '</h5>';
            } else if (line.trim()) {
                html += '<p>' + line + '</p>';
            }
        });
        if (inList) {
            html += '</ul>';
        }
        return html.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
    }

    function renderAnswer(data, actions) {
        if (!data || data.status === 'disabled') {
            return '<div class="alert alert-warning">' + esc((data && data.message) || T.aiDisabled) + '</div>';
        }
        if (data.status !== 'ok') {
            return '<div class="alert alert-danger">' + esc(data.message || T.error) + '</div>';
        }
        return '<div class="pa-an-answer">' + mdLite(data.text) + '</div>' +
            (actions && actions.length ? '<h5>' + esc(T.suggested) + '</h5><div class="pa-an-d-actions">' +
                actionButtons({actions: actions}) + '</div>' : '') +
            '<p class="text-muted"><small>' + esc(data.provider || '') + ' / ' + esc(data.model || '') + ', ' +
            esc(Math.round((data.duration_ms || 0) / 100) / 10) + ' s, ' +
            esc(data.anonymized ? T.anonymized : T.notAnonymized) + '<br/>' + esc(T.aiDisclaimer) + '</small></p>';
    }

    function explain(kind, id, target) {
        target.html('<p><i class="fa fa-spinner fa-pulse"></i> ' + esc(T.asking) + '</p>');
        ajaxCall(API + '/explain', {kind: kind, id: id}, function (data) {
            target.html(renderAnswer(data, data && data.actions));
            bindActions(target);
        });
    }

    function preview(kind, id) {
        ajaxCall(API + '/explain', {kind: kind, id: id, preview: 1}, function (data) {
            let html;
            if (!data || data.status !== 'ok') {
                html = '<div class="alert alert-danger">' + esc((data && data.message) || T.error) + '</div>';
            } else {
                html = '<p>' + esc(data.anonymized ? T.anonymized : T.notAnonymized) + ', ' + esc(data.bytes) +
                    ' bytes</p>' + (data.messages || []).map(function (m) {
                        return '<h5>' + esc(m.role) + '</h5><pre style="white-space:pre-wrap">' + esc(m.content) + '</pre>';
                    }).join('');
            }
            PASimulation.dialog({title: T.preview, message: html, size: BootstrapDialog.SIZE_WIDE, cssClass: 'pa-an-dialog',
                buttons: [{label: T.close, action: function (d) { d.close(); }}]});
        });
    }

    /******************************************************************************************************
     * actions (all through the simulation)
     ******************************************************************************************************/
    function refreshAll() {
        loadStatus();
        loadSummary();
        loadList();
    }

    function runChange(action, args, title, endpoint) {
        PASimulation.run({action: action, args: args || [], endpoint: endpoint || API, title: title,
            onDone: function () { refreshAll(); }});
    }

    function expectDialog(f) {
        const html = '<p>' + esc(f.detail) + '</p><label>' + esc(T.expectScope) + '</label>' +
            ['finding', 'host', 'all'].map(function (s, i) {
                return '<div class="radio"><label><input type="radio" name="pa_an_scope" value="' + s + '"' +
                    (i ? '' : ' checked') + '> ' + esc(T['scope' + s.charAt(0).toUpperCase() + s.slice(1)]) +
                    '</label></div>';
            }).join('') + '<label for="pa_an_comment">' + esc(T.comment) + '</label>' +
            '<input id="pa_an_comment" class="form-control" maxlength="200" type="text">';
        PASimulation.dialog({title: T.expect, message: html, cssClass: 'pa-an-dialog', buttons: [
            {label: T.close, action: function (d) { d.close(); }},
            {label: T.simulate, cssClass: 'btn-primary', action: function (d) {
                const scope = d.getModalBody().find('input[name=pa_an_scope]:checked').val();
                const comment = d.getModalBody().find('#pa_an_comment').val().trim();
                d.close();
                runChange('anomaly_expect', [f.id, scope, b64(comment)], T.expect);
            }}]});
    }

    function quarantine(target, f) {
        const note = 'anomaly ' + f.type + ' of ' + f.host;
        runChange('quarantine_add', [target, 'auto', b64(note)], 'Quarantine ' + target, '/api/policyanalyzer/change');
    }

    function bindActions(scope) {
        scope.find('.pa-an-act').off('click').on('click', function () {
            const act = $(this).data('act');
            const f = state.finding;
            if (act === 'expect') {
                expectDialog(f);
            } else if (act === 'resolve') {
                runChange('anomaly_resolve', [f.id], T.resolve);
            } else if (act === 'quarantine') {
                quarantine(String($(this).data('target')), f);
            } else if (act === 'host') {
                hostProfile(String($(this).data('host') || f.host));
            }
        });
    }

    function bindDetail(scope) {
        bindActions(scope);
        scope.find('.pa-an-explain').off('click').on('click', function () {
            explain('finding', state.finding.id, scope.find('.pa-an-ai'));
        });
        scope.find('.pa-an-preview').off('click').on('click', function () {
            preview('finding', state.finding.id);
        });
    }

    /******************************************************************************************************
     * host profile
     ******************************************************************************************************/
    function kv(label, value) {
        return '<tr><th>' + esc(label) + '</th><td>' + value + '</td></tr>';
    }

    function hostProfile(ip) {
        ajaxGet(API + '/host', {ip: ip}, function (p) {
            if (!p || p.status !== 'ok') {
                PASimulation.dialog({title: T.hostProfile, message: '<div class="alert alert-danger">' +
                    esc((p && p.message) || T.error) + '</div>'});
                return;
            }
            const n = p.normal || {}, now = p.now || {}, dev = p.device || {};
            const slot = n.bytes_out_this_hour_of_day || n.bytes_out_any_hour;
            const html = '<div class="pa-an-host">' +
                '<div class="pa-an-host-cols"><table class="table table-condensed"><caption>' + esc(T.device) +
                '</caption>' + kv(T.host, esc(p.host)) + kv(T.mac, esc(dev.mac || '-')) + kv(T.vendor, esc(dev.vendor || '-')) +
                kv('DHCP', esc(dev.hostname || '-')) + kv(T.firstSeen, esc(when(p.first_seen))) + '</table>' +
                '<table class="table table-condensed"><caption>' + esc(T.normal) + ' / ' + esc(T.now) + '</caption>' +
                kv(T.outHour, '<b>' + esc(fmtBytes(now.bytes_out || 0)) + '</b> / ' +
                    esc(slot ? fmtBytes(slot.mean) + ' ± ' + fmtBytes(slot.std) : '-')) +
                kv(T.dnsHour, esc(now.dns_last_hour ? now.dns_last_hour.queries : '-') + ' / ' + esc(n.dns_queries_per_hour)) +
                kv(T.nxHour, esc(now.dns_last_hour ? now.dns_last_hour.nx : '-') + ' / ' + esc(n.nxdomain_per_hour)) +
                kv(T.countries, esc((n.countries || []).map(function (c) { return c.country; }).join(', ') || '-')) +
                kv(T.learned, esc(n.domains || 0) + ' ' + esc(T.domains) + ', ' + esc(n.ja4 || 0) + ' ' +
                    esc(T.fingerprints)) + '</table></div>' +
                '<div class="pa-an-host-spark">' + sparkline(p.series, {w: 600, h: 70}) + '</div>' +
                '<h5>' + esc(T.topDst) + '</h5><p class="pa-an-host-dst">' + ((now.top_destinations_24h || []).map(function (d) {
                    return esc(d.address) + ' <small>' + esc(fmtBytes(d.bytes)) + '</small>';
                }).join(' &middot; ') || '-') + '</p>' +
                '<h5>' + esc(T.findings) + '</h5><ul class="pa-an-host-f">' + ((p.findings || []).map(function (f) {
                    return '<li>' + sevLabel(f.severity) + ' <b>' + esc(typeName(f.type)) + '</b> ' + esc(f.detail) + '</li>';
                }).join('') || '<li>-</li>') + '</ul>' +
                '<div class="pa-an-d-actions">' + actionButtons({actions: p.actions}) + ' <button type="button" ' +
                'class="btn btn-primary btn-sm pa-an-explain-host"' + (state.ai.enabled ? '' : ' disabled') +
                '><i class="fa fa-magic fa-fw"></i> ' + esc(T.explainHost) + '</button> <button type="button" ' +
                'class="btn btn-default btn-sm pa-an-preview-host"><i class="fa fa-eye fa-fw"></i> ' + esc(T.preview) +
                '</button> <button type="button" class="btn btn-default btn-sm pa-an-filter-host"><i class="fa fa-filter ' +
                'fa-fw"></i> ' + esc(T.findings) + '</button></div><div class="pa-an-ai"></div></div>';
            const dlg = PASimulation.dialog({title: T.hostProfile + ': ' + p.host, message: html,
                size: BootstrapDialog.SIZE_WIDE, cssClass: 'pa-an-dialog', buttons: [{label: T.close, action: function (d) { d.close(); }}]});
            const body = dlg.getModalBody();
            body.find('.pa-an-explain-host').on('click', function () { explain('host', p.host, body.find('.pa-an-ai')); });
            body.find('.pa-an-preview-host').on('click', function () { preview('host', p.host); });
            body.find('.pa-an-filter-host').on('click', function () {
                dlg.close();
                setHost(p.host);
            });
        });
    }

    function setHost(ip) {
        state.host = ip || '';
        state.selected = null;
        const el = $('#pa_an_f_host');
        if (state.host) {
            el.html(esc(T.host) + ' <b>' + esc(state.host) + '</b> <a href="#" class="pa-an-host-clear">&times;</a>').show();
        } else {
            el.hide().empty();
        }
        loadList();
    }

    /******************************************************************************************************
     * exceptions / parameters
     ******************************************************************************************************/
    function exceptionsDialog() {
        const ex = (state.status_data && state.status_data.exceptions) || [];
        const html = ex.length ? '<table class="table table-condensed pa-an-extable"><thead><tr><th>' + esc(T.type) +
            '</th><th>' + esc(T.host) + '</th><th>key</th><th>' + esc(T.comment) + '</th><th></th></tr></thead><tbody>' +
            ex.map(function (e) {
                return '<tr><td data-label="' + esc(T.type) + '">' + esc(e.type === '*' ? T.all : typeName(e.type)) +
                    '</td><td data-label="' + esc(T.host) + '">' + esc(e.host) + '</td><td data-label="key">' + esc(e.key) +
                    '</td><td data-label="' + esc(T.comment) + '">' + esc(e.comment || '') + '</td><td>' +
                    '<button type="button" class="btn btn-xs btn-default pa-an-exdel" data-id="' + esc(e.id) + '">' +
                    '<i class="fa fa-trash fa-fw"></i> ' + esc(T.remove) + '</button></td></tr>';
            }).join('') + '</tbody></table>' : '<p>' + esc(T.noExceptions) + '</p>';
        const dlg = PASimulation.dialog({title: T.exceptions, message: html, size: BootstrapDialog.SIZE_WIDE,
            cssClass: 'pa-an-dialog',
            buttons: [{label: T.close, action: function (d) { d.close(); }}]});
        dlg.getModalBody().on('click', '.pa-an-exdel', function () {
            dlg.close();
            runChange('anomaly_exception_del', [String($(this).data('id'))], T.exceptions);
        });
    }

    function settingsDialog() {
        const d = state.status_data || {};
        const rows = (d.settings || []).map(function (s) {
            return '<tr><td data-label="' + esc(T.settings) + '"><code>' + esc(s.key) + '</code><div class="pa-an-ftext">' +
                esc(s.description) + '</div></td><td><input type="number" class="form-control input-sm pa-an-set" ' +
                'data-key="' + esc(s.key) + '" data-value="' + esc(s.value) + '" value="' + esc(s.value) + '" min="' +
                esc(s.min) + '" max="' + esc(s.max) + '"></td></tr>';
        }).join('');
        const runs = (d.runs || []).slice(0, 6).map(function (r) {
            return esc(when(r.ts)) + ': ' + esc(((r.duration_ms || 0) / 1000).toFixed(1)) + ' s, CPU ' +
                esc(((r.cpu_ms || 0) / 1000).toFixed(1)) + ' s';
        }).join('<br/>');
        const srcs = d.sources || {};
        const html = '<p class="text-muted"><small>' + esc(T.settingsNote) + '</small></p>' +
            '<p><b>' + esc(T.sources) + ':</b> ' + Object.keys(srcs).map(function (k) {
                return esc(k) + ' ' + (srcs[k] ? '<i class="fa fa-check text-success"></i>' :
                    '<i class="fa fa-times text-danger"></i>');
            }).join(' &middot; ') + '</p>' + (runs ? '<p><b>' + esc(T.cost) + ':</b><br/>' + runs + '</p>' : '') +
            '<div class="pa-an-settings"><table class="table table-condensed"><tbody>' + rows + '</tbody></table></div>';
        PASimulation.dialog({title: T.settings, message: html, size: BootstrapDialog.SIZE_WIDE, cssClass: 'pa-an-dialog',
            buttons: [
            {label: T.close, action: function (dl) { dl.close(); }},
            {label: T.simulate, cssClass: 'btn-primary', action: function (dl) {
                const changed = [];
                dl.getModalBody().find('.pa-an-set').each(function () {
                    const v = String($(this).val()).trim();
                    if (v !== String($(this).data('value')) && /^\d{1,8}$/.test(v)) {
                        changed.push($(this).data('key') + '=' + v);
                    }
                });
                dl.close();
                if (changed.length) {
                    runChange('anomaly_settings', [changed.slice(0, 16).join(':')], T.settings);
                }
            }}]});
    }

    /******************************************************************************************************
     * init
     ******************************************************************************************************/
    function init(opts) {
        T = Object.assign({}, (opts && opts.strings) || {});
        fillTypeSelect();
        renderEmptyDetail();
        $('#pa_an_cards').on('click', '.pa-an-card', function () {
            const sev = $(this).data('severity');
            state.severity = state.severity === sev ? '' : sev;
            $('.pa-an-card').removeClass('active');
            if (state.severity) {
                $(this).addClass('active');
            }
            state.selected = null;
            loadList();
        });
        $('#pa_an_types').on('click', '.pa-an-chip', function () {
            const t = $(this).data('type');
            state.type = state.type === t ? '' : t;
            $('#pa_an_f_type').val(state.type);
            state.selected = null;
            loadSummary();
            loadList();
        });
        $('#pa_an_f_type').on('change', function () { state.type = $(this).val(); state.selected = null; loadList(); });
        $('#pa_an_f_status').on('change', function () { state.status = $(this).val(); state.selected = null; loadList(); });
        $('#pa_an_f_days').on('change', function () { state.days = $(this).val(); state.selected = null; loadList(); });
        let timer = null;
        $('#pa_an_f_search').on('input', function () {
            clearTimeout(timer);
            const v = $(this).val().trim();
            timer = setTimeout(function () {
                state.search = /^[0-9A-Za-z:.\/_-]{0,64}$/.test(v) ? v : '';
                state.selected = null;
                loadList();
            }, 300);
        });
        $('#pa_an_f_host').on('click', '.pa-an-host-clear', function (e) {
            e.preventDefault();
            setHost('');
        });
        $('#pa_an_list').on('click', '.pa-an-row', function () { select($(this).data('id')); });
        $('#pa_an_state').on('click', '#pa_an_install', function () { runChange('install_anomalies', [], T.install); });
        $('#pa_an_run').on('click', function () {
            const btn = $(this).prop('disabled', true);
            const label = btn.html();
            btn.html('<i class="fa fa-spinner fa-pulse fa-fw"></i> ' + esc(T.running));
            ajaxCall(API + '/run', {}, function () {
                btn.prop('disabled', false).html(label);
                refreshAll();
            });
        });
        $('#pa_an_exceptions').on('click', exceptionsDialog);
        $('#pa_an_settings').on('click', settingsDialog);
        const m = (window.location.hash || '').match(/host=([0-9A-Fa-f:.]{2,45})/);
        if (m) {
            setHost(m[1]);
        }
        refreshAll();
        setInterval(function () {
            if (!document.hidden) {
                loadSummary();
                loadStatus();
            }
        }, 60000);
    }

    return {init: init, sparkline: sparkline, refresh: refreshAll};
})();
