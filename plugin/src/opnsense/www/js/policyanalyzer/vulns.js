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
 */

/**
 * Vulnerabilities page (vulns.volt): CVEs of the inventory prioritised P1..P4 with CISA KEV and FIRST EPSS,
 * the review queue ("Under review") with the AI suggestion and the owner's decision, Explain CVE by the AI.
 * API: /api/policyanalyzer/vulns/*. Network only through "Update KEV/EPSS" (simulation first).
 */
const PAVulns = (function () {
    'use strict';

    const API = '/api/policyanalyzer/vulns/';
    const DEFAULTS = {
        title: 'Vulnerabilities',
        subtitle: 'CVEs of the inventory ranked by exposure and real exploitation (KEV, EPSS). Read only.',
        refresh: 'Refresh',
        updateIntel: 'Update KEV/EPSS',
        updateIntelTitle: 'Update CISA KEV and FIRST EPSS',
        openExposure: 'Exposure report',
        kpiTotal: 'CVEs',
        kpiKev: 'In KEV',
        kpiReview: 'Under review',
        p1: 'P1 critical', p2: 'P2 high', p3: 'P3 medium', p4: 'P4 low',
        tabList: 'Prioritised',
        tabReview: 'Under review',
        tabRules: 'How the priority works',
        colPrio: 'Priority', colCve: 'CVE', colPkg: 'Package', colExposure: 'Exposure', colKev: 'KEV',
        colEpss: 'EPSS', colCvss: 'CVSS', colWhy: 'Why', colActions: 'Actions',
        colKind: 'Kind', colSubject: 'Component', colReason: 'Why it is here', colCandidates: 'Candidates',
        colAi: 'AI suggestion', colDecision: 'Decision',
        details: 'Details', explain: 'Explain', explainTitle: 'Explain %s', suggest: 'AI suggestion',
        suggestTitle: 'Mapping suggestion for %s', decide: 'Decide', decideTitle: 'Decision on %s',
        internet: 'internet', internet_maybe: 'internet (maybe)', lan: 'internal only', none: 'no listener',
        kevNone: 'no KEV cache: the KEV signal is missing',
        kevStale: 'the KEV cache is %s days old',
        kevAt: 'KEV collected %s (%s entries, %s)',
        epssAt: 'EPSS cached for %s of %s CVEs',
        noNetwork: 'No network is used unless you click Update (simulation first).',
        exposureAge: 'Exposure report from %s',
        noReport: 'No exposure report yet: run it in the Exposure tab of the Policy Analyzer.',
        factors: 'Factors', services: 'Services', fixed: 'Fixed in', refs: 'References', suricata: 'Suricata rules',
        mapped: 'mapped by you', confirmed: 'confirmed finding',
        kind_package_unmapped: 'package without service', kind_dependency_link: 'dependency only',
        kind_service_unknown: 'unknown service', kind_binary_unowned: 'binary without package',
        kind_advisory_unclear: 'advisory unclear', kind_cve_unscored: 'CVE without score',
        pending: 'pending', decided: 'decided', expired: 'decision expired',
        decMap: 'It runs inside this service (priority follows its exposure)',
        decNone: 'No network path (library only)',
        decIgnore: 'Ignore for', days: 'days',
        decFinding: 'Confirm as a real finding',
        decClear: 'Remove my decision (back to pending)',
        comment: 'Comment (optional)',
        simulate: 'Simulate',
        aiSays: 'AI suggests'
    };
    let S = Object.assign({}, DEFAULTS);
    let data = null;
    let filter = null;
    const E = function (v) { return PAMod.esc(v); };

    function fmt(text) {
        const args = Array.prototype.slice.call(arguments, 1);
        return String(text).replace(/%s/g, function () { return args.length ? args.shift() : ''; });
    }

    function load() {
        $('#pav_list').html('<i class="fa fa-spinner fa-spin"></i>');
        PAMod.get(API + 'list', {}, function (res) {
            data = res;
            render();
        });
    }

    function kpis() {
        const c = data.counts || {};
        let html = '';
        ['P1', 'P2', 'P3', 'P4'].forEach(function (p) {
            html += '<button type="button" class="pa-kpi' + (filter === p ? ' pa-on' : '') + '" data-prio="' + p +
                '"><span class="pa-kpi-n">' + E(c[p] || 0) + '</span><span class="pa-kpi-l">' + E(S[p.toLowerCase()]) +
                '</span></button>';
        });
        html += '<div class="pa-kpi"><span class="pa-kpi-n">' + E(data.kev || 0) + '</span><span class="pa-kpi-l">' +
            E(S.kpiKev) + '</span></div>';
        html += '<button type="button" class="pa-kpi" data-tab="review"><span class="pa-kpi-n">' +
            E(data.review_pending || 0) + '</span><span class="pa-kpi-l">' + E(S.kpiReview) + '</span></button>';
        $('#pav_kpis').html(html);
    }

    function intelNote() {
        const intel = data.intel || {};
        const kev = intel.kev || {};
        const epss = intel.epss || {};
        const parts = [];
        let cls = '';
        if (!kev.available) {
            parts.push(E(S.kevNone));
            cls = ' pa-warn';
        } else {
            parts.push(E(fmt(S.kevAt, PAMod.when(kev.fetched), kev.count, kev.source)));
            if (kev.stale) {
                parts.push(E(fmt(S.kevStale, kev.age_days)));
                cls = ' pa-warn';
            }
        }
        parts.push(E(fmt(S.epssAt, epss.covered || 0, data.total || 0)));
        if (data.exposure_generated) {
            parts.push(E(fmt(S.exposureAge, PAMod.when(data.exposure_generated))));
        }
        $('#pav_intel').attr('class', 'pa-mod-note' + cls).html('<span>' + parts.join(' &middot; ') +
            '<br><span class="pa-small">' + E(S.noNetwork) + '</span></span>' +
            '<button type="button" class="btn btn-xs btn-default pa-intel-update"><i class="fa fa-cloud-download"></i> ' +
            E(S.updateIntel) + '</button>');
    }

    function exposureHtml(item) {
        const cls = item.exposure['class'];
        const icon = {internet: 'fa-globe', internet_maybe: 'fa-globe', lan: 'fa-home', none: 'fa-book'}[cls];
        const svc = (item.exposure.services || []).slice(0, 2).map(function (s) {
            return E((s.name || s.service) + ' ' + s.proto + '/' + s.port);
        }).join('<br>');
        return '<i class="fa ' + icon + '"></i> ' + E(S[cls]) + (item.exposure.mapped_by_owner ? ' <span class="pa-small">(' +
            E(S.mapped) + ')</span>' : '') + (svc ? '<div class="pa-small">' + svc + '</div>' : '');
    }

    function detailHtml(item) {
        let html = '<b>' + E(S.factors) + '</b><ul>' + item.factors.map(function (f) {
            return '<li>' + (f.met ? '<i class="fa fa-check-circle text-danger"></i> ' : '<i class="fa fa-circle-o"></i> ') +
                E(f.text) + '</li>';
        }).join('') + '</ul>';
        if (item.summary) {
            html += '<div>' + E(item.summary) + '</div>';
        }
        if (item.kev) {
            html += '<div><b>KEV</b>: ' + E(item.kev.name || '') + ' - ' + E(item.kev.date_added || '') +
                (item.kev.action ? ' - ' + E(item.kev.action) : '') + '</div>';
        }
        if (item.fixed_in && item.fixed_in.length) {
            html += '<div><b>' + E(S.fixed) + '</b>: ' + E(item.fixed_in.join(', ')) + '</div>';
        }
        if (item.suricata && item.suricata.length) {
            html += '<div><b>' + E(S.suricata) + '</b>: ' + item.suricata.map(function (s) {
                return E('sid ' + s.sid + ' (' + (s.enabled ? 'enabled' : 'disabled') + ') ' + (s.msg || ''));
            }).join('; ') + '</div>';
        }
        if (item.refs && item.refs.length) {
            html += '<div><b>' + E(S.refs) + '</b>: ' + item.refs.map(function (r) {
                return /^https:\/\//.test(r) ? '<a href="' + E(r) + '" target="_blank" rel="noopener noreferrer">' +
                    E(r.replace(/^https:\/\//, '').slice(0, 60)) + '</a>' : E(r);
            }).join(' &middot; ') + '</div>';
        }
        return html;
    }

    function listTable() {
        const items = (data.items || []).filter(function (i) { return !filter || i.priority === filter; });
        const cols = [
            {key: 'prio', label: S.colPrio, width: '74px'}, {key: 'cve', label: S.colCve, width: '150px'},
            {key: 'pkg', label: S.colPkg, width: '14%'}, {key: 'exp', label: S.colExposure, width: '17%'},
            {key: 'kev', label: S.colKev, width: '52px'}, {key: 'epss', label: S.colEpss, width: '62px'},
            {key: 'cvss', label: S.colCvss, width: '56px'}, {key: 'why', label: S.colWhy, cls: 'pa-col-opt'},
            {key: 'actions', label: S.colActions, width: '150px'}];
        const rows = items.map(function (i) {
            return {attrs: ' id="cve-' + E(i.cve) + '"', detail: detailHtml(i), cells: {
                prio: PAMod.chip(i.priority, 'pa-' + i.priority.toLowerCase()) + (i.confirmed ? ' <i class="fa fa-flag" title="' +
                    E(S.confirmed) + '"></i>' : ''),
                cve: '<b>' + E(i.cve) + '</b>',
                pkg: E(i.package) + '<div class="pa-small">' + E(i.version || '') + '</div>',
                exp: exposureHtml(i),
                kev: i.kev ? PAMod.chip('KEV', 'pa-kev') : '<span class="pa-small">-</span>',
                epss: i.epss === null || i.epss === undefined ? '<span class="pa-small">-</span>' : E(Number(i.epss).toFixed(3)),
                cvss: i.cvss === null || i.cvss === undefined ? '<span class="pa-small">-</span>' : E(i.cvss),
                why: '<span class="pa-small">' + E(i.rule) + '</span>',
                actions: '<button type="button" class="btn btn-xs btn-default pa-detail-toggle" title="' + E(S.details) +
                    '"><i class="fa fa-list"></i></button><button type="button" class="btn btn-xs btn-primary pa-explain" ' +
                    'data-cve="' + E(i.cve) + '"><i class="fa fa-magic"></i> ' + E(S.explain) + '</button>'}};
        });
        $('#pav_list').html(PAMod.table(cols, rows, {empty: data.status === 'none' ? S.noReport : undefined}));
    }

    function reviewTable() {
        const cols = [
            {key: 'kind', label: S.colKind, width: '14%'}, {key: 'subject', label: S.colSubject, width: '14%'},
            {key: 'reason', label: S.colReason}, {key: 'cand', label: S.colCandidates, width: '16%', cls: 'pa-col-opt'},
            {key: 'ai', label: S.colAi, width: '16%'}, {key: 'dec', label: S.colDecision, width: '11%'},
            {key: 'actions', label: S.colActions, width: '150px'}];
        const rows = (data.review || []).map(function (q) {
            const ai = q.ai_suggestion;
            const dec = q.decision;
            return {cells: {
                kind: E(S['kind_' + q.kind] || q.kind),
                subject: '<b>' + E(q.subject) + '</b>' + (q.cves && q.cves.length ? '<div class="pa-small">' +
                    E(q.cves.slice(0, 3).join(', ')) + (q.cves.length > 3 ? '...' : '') + '</div>' : ''),
                reason: '<span class="pa-small">' + E(q.reason) + '</span>',
                cand: (q.candidates || []).map(function (c) {
                    return E((c.name || c.service) + ' ' + c.proto + '/' + c.port);
                }).join('<br>') || '-',
                ai: ai ? '<b>' + E(ai.mapping) + '</b><div class="pa-small">' + E((ai.text || '').slice(0, 140)) + '</div>' : '-',
                dec: dec ? PAMod.chip(dec.decision + (dec.target ? ':' + dec.target.slice(0, 6) : ''), 'pa-ok') +
                    (dec.until ? '<div class="pa-small">' + PAMod.when(dec.until) + '</div>' : '') :
                    PAMod.chip(q.decision_expired ? S.expired : S.pending, 'pa-muted-chip'),
                actions: '<button type="button" class="btn btn-xs btn-default pa-suggest" data-id="' + E(q.id) + '">' +
                    '<i class="fa fa-magic"></i> ' + E(S.suggest) + '</button><button type="button" ' +
                    'class="btn btn-xs btn-primary pa-decide" data-id="' + E(q.id) + '">' + E(S.decide) + '</button>'}};
        });
        $('#pav_review').html(PAMod.table(cols, rows));
    }

    function render() {
        if (!data || (data.status !== 'ok' && data.status !== 'none')) {
            $('#pav_list').html('<div class="alert alert-danger">' + E((data && data.message) || S.noReport) + '</div>');
            return;
        }
        if (data.status === 'none') {
            data.counts = data.counts || {};
            data.intel = data.intel || {};
        }
        kpis();
        intelNote();
        listTable();
        reviewTable();
        $('#pav_review_count').text(data.review_pending || 0);
        if (location.hash.indexOf('#CVE-') === 0) {
            const $row = $('#cve-' + location.hash.slice(1));
            $row.addClass('pa-row-sel').next('.pa-detail-row').show();
        }
    }

    function item(id) {
        return (data.review || []).find(function (q) { return q.id === id; });
    }

    function decide(id) {
        const q = item(id);
        if (!q) {
            return;
        }
        const $f = $('<form class="pa-mod-dialog"/>');
        const opt = function (value, label, extra) {
            return $('<div class="radio"/>').append($('<label/>').append($('<input type="radio" name="pav_dec"/>')
                .val(value)).append(' ').append(label).append(extra || ''));
        };
        $f.append($('<p/>').text(q.reason));
        if (q.ai_suggestion) {
            $f.append($('<div class="pa-ai-box"/>').append($('<b/>').text(S.aiSays + ': ' + q.ai_suggestion.mapping))
                .append($('<pre class="pa-text"/>').text(q.ai_suggestion.text || '')));
        }
        (q.candidates || []).forEach(function (c) {
            if (q.package) {
                $f.append(opt('map:' + c.id, S.decMap + ': ' + (c.name || c.service) + ' ' + c.proto + '/' + c.port +
                    ' (' + c.internet_reachable + ')'));
            }
        });
        if (q.package) {
            $f.append(opt('none', S.decNone));
        }
        $f.append(opt('ignore', S.decIgnore + ' ', $('<input type="number" class="form-control pa-days" min="1" max="365" ' +
            'value="90" style="display:inline-block;width:80px;height:26px"/>')).append(' ' + S.days));
        $f.append(opt('finding', S.decFinding));
        if (q.decision) {
            $f.append(opt('clear', S.decClear));
        }
        $f.append($('<label/>').text(S.comment)).append($('<input type="text" class="form-control pa-comment" maxlength="300"/>'));
        $f.find('input[name=pav_dec]').first().prop('checked', true);
        PASimulation.dialog({title: fmt(S.decideTitle, q.subject), message: $f, buttons: [
            {label: S.simulate, cssClass: 'btn-primary', action: function (d) {
                let token = $f.find('input[name=pav_dec]:checked').val();
                if (token === 'ignore') {
                    token = 'ignore=' + Math.max(1, Math.min(365, parseInt($f.find('.pa-days').val(), 10) || 90));
                }
                const text = $f.find('.pa-comment').val().trim();
                const comment = text ? PAMod.b64text(text).slice(0, 1000) : '-';
                d.close();
                PAMod.simulate(API, 'vulns_review_decide', [id, token, comment], fmt(S.decideTitle, q.subject), load);
            }},
            {label: PAMod.S().close, action: function (d) { d.close(); }}]});
    }

    function bind() {
        const $root = $('#pa_vulns');
        $root.on('click', '.pa-kpi[data-prio]', function () {
            const p = $(this).data('prio');
            filter = filter === p ? null : p;
            $('a[href="#pav_tab_list"]').tab('show');
            kpis();
            listTable();
        });
        $root.on('click', '.pa-kpi[data-tab=review]', function () { $('a[href="#pav_tab_review"]').tab('show'); });
        $root.on('click', '.pa-detail-toggle', function () { $(this).closest('tr').next('.pa-detail-row').toggle(); });
        $root.on('click', '.pa-intel-update', function () {
            PAMod.simulate(API, 'vulns_intel_update', ['all'], S.updateIntelTitle, load);
        });
        $root.on('click', '#pav_refresh', load);
        $root.on('click', '.pa-explain', function () {
            const cve = $(this).data('cve');
            const it = (data.items || []).find(function (i) { return i.cve === cve; }) || {};
            PAMod.aiDialog({title: fmt(S.explainTitle, cve),
                intro: PAMod.chip(it.priority || '', 'pa-' + String(it.priority || '').toLowerCase()) + ' ' +
                    E(it.explanation || ''),
                cached: function (cb) { PAMod.get(API + 'explain', {cve: cve}, cb); },
                preview: function (cb) { PAMod.post(API + 'explain', {cve: cve, mode: 'preview'}, cb); },
                ask: function (cb) { PAMod.post(API + 'explain', {cve: cve, mode: 'refresh'}, cb); }});
        });
        $root.on('click', '.pa-suggest', function () {
            const id = $(this).data('id');
            const q = item(id) || {};
            PAMod.aiDialog({title: fmt(S.suggestTitle, q.subject), intro: E(q.reason),
                preview: function (cb) { PAMod.post(API + 'suggest', {id: id, mode: 'preview'}, cb); },
                ask: function (cb) { PAMod.post(API + 'suggest', {id: id, mode: 'refresh'}, cb); },
                onAnswer: function (res) { if (res && res.status === 'ok') { load(); } }});
        });
        $root.on('click', '.pa-decide', function () { decide($(this).data('id')); });
    }

    return {
        DEFAULTS: DEFAULTS,
        setStrings: function (s) { S = Object.assign({}, DEFAULTS, s || {}); },
        init: function () {
            PAMod.accent(document.getElementById('pa_vulns'));
            bind();
            load();
        }
    };
})();
