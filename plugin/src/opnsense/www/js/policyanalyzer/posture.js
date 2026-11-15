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
 * Posture page (/ui/policyanalyzer/posture, posture.volt): health check score, categories, trend and the list
 * of checks (table on desktop, cards below 768 px). Details show evidence, recommendation, references and the
 * "Fix" proposal: a textual diff + "Open page"; "Simulate" only where an existing change action is safe
 * (PASimulation.simulate, plan only); "Minimal rule" opens PAMinRule for rule findings.
 *
 *   PAPosture.init({strings: {...}, aiEnabled: bool})
 */
const PAPosture = (function () {
    'use strict';

    const API = '/api/policyanalyzer/posture/';
    const I = PAInsights;
    const esc = I.esc;
    let S = {
        run: 'Run now', running: 'Running the checks...', summaryAi: 'Executive summary (AI)', explain: 'Explain (AI)',
        preview: 'Show data sent', details: 'Details', fix: 'Fix (proposal)', openPage: 'Open page',
        simulate: 'Simulate', minrule: 'Minimal rule', close: 'Close', evidence: 'Evidence',
        recommendation: 'Recommendation', references: 'References', all: 'All', search: 'Search checks',
        pass: 'Pass', warn: 'Warn', fail: 'Fail', na: 'N/A', high: 'high', medium: 'medium', low: 'low', info: 'info',
        score: 'Posture score', generated: 'Generated', previous: 'since the previous run', trend: 'Score trend',
        newFailures: 'New problems', fixed: 'Fixed', noChecks: 'No check matches the filter.', asking: 'Asking the AI...',
        error: 'Error', aiDisabled: 'AI assistance is disabled in the settings.', anonymized: 'anonymized',
        notAnonymized: 'not anonymized', cached: 'cached', aiDisclaimer: 'AI text: verify before acting.',
        fixNote: 'Proposal only: nothing is changed from here. Change it on the page, then run the checks again.',
        category: 'Category', check: 'Check', result: 'Result', severity: 'Severity', actions: 'Actions',
        noHistory: 'run the checks on different days to see the trend', policyReport: 'Rule analysis from',
        empty: 'No posture report yet.'
    };
    let report = null;
    let filter = {result: '', category: '', text: ''};
    let aiEnabled = false;

    function badge(result) {
        const icon = {pass: 'fa-check', warn: 'fa-exclamation', fail: 'fa-times', na: 'fa-minus'}[result] || 'fa-minus';
        return '<span class="pa-ins-res pa-res-' + esc(result) + '"><i class="fa ' + icon + '"></i> ' +
            esc(S[result] || result) + '</span>';
    }

    function sev(s) {
        return '<span class="pa-ins-sev pa-sev-' + esc(s) + '">' + esc(S[s] || s) + '</span>';
    }

    function header() {
        const r = report;
        const ch = r.changes || {};
        let delta = '';
        if (ch.delta !== null && ch.delta !== undefined) {
            const cls = ch.delta > 0 ? 'pa-up' : (ch.delta < 0 ? 'pa-down' : '');
            delta = '<span class="pa-ins-delta ' + cls + '">' + (ch.delta > 0 ? '+' : '') + esc(ch.delta) + ' ' +
                esc(S.previous) + '</span>';
        }
        const counts = ['fail', 'warn', 'pass', 'na'].map(function (k) {
            return '<button type="button" class="pa-ins-chip pa-res-' + k + (filter.result === k ? ' active' : '') +
                '" data-result="' + k + '">' + esc(S[k]) + ' <b>' + esc((r.counts || {})[k] || 0) + '</b></button>';
        }).join('');
        const hist = (r.trendPoints || []);
        let html = '<div class="pa-ins-head">' +
            '<div class="pa-ins-score">' + I.gauge(r.score, r.grade) + '</div>' +
            '<div class="pa-ins-headinfo"><div class="pa-ins-title">' + esc(S.score) + ' ' + delta + '</div>' +
            '<div class="pa-ins-chips">' + counts + '</div>' +
            '<div class="text-muted small">' + esc(S.generated) + ': ' + esc(I.when(r.generated)) +
            (r.system && r.system.version ? ' · OPNsense ' + esc(r.system.version) : '') +
            (r.policy_report ? ' · ' + esc(S.policyReport) + ' ' + esc(I.when(r.policy_report)) : '') + '</div></div>' +
            '<div class="pa-ins-trend"><div class="small text-muted">' + esc(S.trend) + '</div>' +
            (hist.length > 1 ? I.spark(hist, {min: 0, max: 100, color: I.gradeColor(r.score)}) :
                '<div class="small text-muted">' + esc(S.noHistory) + '</div>') + '</div>' +
            '<div class="pa-ins-actions">' +
            '<button class="btn btn-primary" id="pa_post_run"><i class="fa fa-refresh"></i> ' + esc(S.run) + '</button>' +
            (aiEnabled ? '<button class="btn btn-default" id="pa_post_summary"><i class="fa fa-magic"></i> ' +
                esc(S.summaryAi) + '</button>' : '') + '</div></div>';
        if ((ch.new_failures || []).length || (ch.fixed || []).length) {
            html += '<div class="pa-ins-changes">' +
                (ch.new_failures || []).map(function (c) {
                    return '<span class="pa-ins-tag pa-res-fail" data-id="' + esc(c.id) + '">' + esc(S.newFailures) +
                        ': ' + esc(c.id) + '</span>';
                }).join('') + (ch.fixed || []).map(function (c) {
                    return '<span class="pa-ins-tag pa-res-pass" data-id="' + esc(c.id) + '">' + esc(S.fixed) + ': ' +
                        esc(c.id) + '</span>';
                }).join('') + '</div>';
        }
        html += '<div class="pa-ins-cats">' + Object.keys(r.by_category || {}).map(function (k) {
            const c = r.by_category[k];
            const score = c.score === null ? '–' : Math.round(c.score);
            return '<button type="button" class="pa-ins-cat' + (filter.category === k ? ' active' : '') +
                '" data-cat="' + esc(k) + '" title="' + esc(c.label + ': ' + c.fail + ' ' + S.fail + ', ' + c.warn + ' ' +
                S.warn + ', ' + c.pass + ' ' + S.pass) + '"><span class="pa-ins-cat-label">' + esc(c.label) + '</span>' +
                '<span class="pa-ins-cat-bar"><span style="width:' + (c.score || 0) + '%;background:' +
                I.gradeColor(c.score) + '"></span></span><span class="pa-ins-cat-score">' + esc(score) +
                (c.fail ? ' · <b class="pa-ins-failn"><i class="fa fa-times"></i> ' + esc(c.fail) + '</b>' : '') +
                (c.warn ? ' · <span class="pa-res-warn"><i class="fa fa-exclamation"></i> ' + esc(c.warn) + '</span>' : '') + '</span></button>';
        }).join('') + '</div>';
        html += '<div class="pa-ins-filter"><input type="search" class="form-control" id="pa_post_search" ' +
            'placeholder="' + esc(S.search) + '" value="' + esc(filter.text) + '"/>' +
            (filter.result || filter.category ? '<button class="btn btn-default btn-sm" id="pa_post_clear">' +
                esc(S.all) + '</button>' : '') + '</div>';
        return html;
    }

    function visible() {
        const text = filter.text.toLowerCase();
        return (report.checks || []).filter(function (c) {
            if (filter.result && c.result !== filter.result) {
                return false;
            }
            if (filter.category && c.category !== filter.category) {
                return false;
            }
            if (text && (c.id + ' ' + c.title + ' ' + c.summary + ' ' + c.category_label).toLowerCase()
                .indexOf(text) < 0) {
                return false;
            }
            return true;
        });
    }

    function actionButtons(c, block) {
        const cls = block ? 'btn btn-default' : 'btn btn-xs btn-default';
        let html = '<button type="button" class="' + cls + ' pa-post-details" data-id="' + esc(c.id) + '" title="' +
            esc(S.details) + '"><i class="fa fa-search-plus"></i>' + (block ? ' ' + esc(S.details) : '') + '</button>';
        if (c.fix) {
            html += '<button type="button" class="' + cls + ' pa-post-fix" data-id="' + esc(c.id) + '" title="' +
                esc(S.fix) + '"><i class="fa fa-wrench"></i>' + (block ? ' ' + esc(S.fix) : '') + '</button>';
        }
        if (aiEnabled) {
            html += '<button type="button" class="' + cls + ' pa-post-explain" data-id="' + esc(c.id) + '" title="' +
                esc(S.explain) + '"><i class="fa fa-magic"></i>' + (block ? ' ' + esc(S.explain) : '') + '</button>';
        }
        return html;
    }

    function list() {
        const items = visible();
        if (!items.length) {
            return '<div class="pa-ins-empty text-muted">' + esc(S.noChecks) + '</div>';
        }
        let html = '<table class="table table-condensed table-hover pa-ins-table hidden-xs"><colgroup>' +
            '<col style="width:86px"/><col style="width:78px"/><col style="width:92px"/><col/>' +
            '<col style="width:190px"/><col style="width:96px"/></colgroup><thead><tr><th>' + esc(S.result) +
            '</th><th>' + esc(S.severity) + '</th><th>ID</th><th>' + esc(S.check) + '</th><th>' + esc(S.category) +
            '</th><th>' + esc(S.actions) + '</th></tr></thead><tbody>';
        items.forEach(function (c) {
            html += '<tr class="pa-post-row" data-id="' + esc(c.id) + '"><td>' + badge(c.result) + '</td><td>' +
                sev(c.severity) + '</td><td><code>' + esc(c.id) + '</code></td><td><div class="pa-ins-ctitle">' +
                esc(c.title) + '</div><div class="pa-ins-csum text-muted">' + esc(c.summary) + '</div></td><td>' +
                esc(c.category_label) + '</td><td class="pa-ins-btns">' + actionButtons(c, false) + '</td></tr>';
        });
        html += '</tbody></table><div class="pa-ins-cards visible-xs">';
        items.forEach(function (c) {
            html += '<div class="pa-ins-card pa-card-' + esc(c.result) + '"><div class="pa-ins-card-head">' +
                badge(c.result) + ' ' + sev(c.severity) + ' <code>' + esc(c.id) + '</code></div>' +
                '<div class="pa-ins-ctitle">' + esc(c.title) + '</div><div class="pa-ins-csum text-muted">' +
                esc(c.summary) + '</div><div class="pa-ins-card-btns">' + actionButtons(c, true) + '</div></div>';
        });
        return html + '</div>';
    }

    function render() {
        const root = $('#pa_posture');
        if (!report || report.status !== 'ok') {
            root.html('<div class="alert alert-warning">' + esc((report && report.message) || S.empty) + '</div>' +
                '<button class="btn btn-primary" id="pa_post_run"><i class="fa fa-refresh"></i> ' + esc(S.run) +
                '</button>');
            bind();
            return;
        }
        root.html(header() + '<div id="pa_post_list">' + list() + '</div>');
        bind();
    }

    function renderList() {
        $('#pa_post_list').html(list());
        bindList();
    }

    function bindList() {
        $('.pa-post-details').off('click').on('click', function (e) {
            e.stopPropagation();
            details($(this).data('id'));
        });
        $('.pa-post-row').off('click').on('click', function () { details($(this).data('id')); });
        $('.pa-post-fix').off('click').on('click', function (e) {
            e.stopPropagation();
            details($(this).data('id'), true);
        });
        $('.pa-post-explain').off('click').on('click', function (e) {
            e.stopPropagation();
            explain($(this).data('id'));
        });
    }

    function bind() {
        $('#pa_post_run').off('click').on('click', run);
        $('#pa_post_summary').off('click').on('click', function () { explain('summary'); });
        $('.pa-ins-chip').off('click').on('click', function () {
            const v = $(this).data('result');
            filter.result = filter.result === v ? '' : v;
            render();
        });
        $('.pa-ins-cat').off('click').on('click', function () {
            const v = $(this).data('cat');
            filter.category = filter.category === v ? '' : v;
            render();
        });
        $('.pa-ins-tag').off('click').on('click', function () { details($(this).data('id')); });
        $('#pa_post_clear').off('click').on('click', function () {
            filter = {result: '', category: '', text: filter.text};
            render();
        });
        $('#pa_post_search').off('input').on('input', function () {
            filter.text = $(this).val();
            renderList();
        });
        bindList();
    }

    function evidenceHtml(ev) {
        const keys = Object.keys(ev || {});
        if (!keys.length) {
            return '<p class="text-muted">–</p>';
        }
        return '<table class="table table-condensed pa-ins-kv"><tbody>' + keys.map(function (k) {
            const v = ev[k];
            const text = (v !== null && typeof v === 'object') ? JSON.stringify(v, null, 1) : String(v);
            return '<tr><th>' + esc(k.replace(/_/g, ' ')) + '</th><td><pre class="pa-ins-pre">' + esc(text) +
                '</pre></td></tr>';
        }).join('') + '</tbody></table>';
    }

    function fixHtml(c) {
        if (!c.fix) {
            return '';
        }
        return '<h4><i class="fa fa-wrench"></i> ' + esc(S.fix) + '</h4><p class="small text-muted">' + esc(S.fixNote) +
            '</p>' + I.diff(c.fix.diff) + (c.fix.note ? '<div class="alert alert-info small">' + esc(c.fix.note) +
            '</div>' : '');
    }

    function details(id, focusFix) {
        const c = (report.checks || []).find(function (x) { return x.id === id; });
        if (!c) {
            return;
        }
        let html = '<div class="pa-ins-dlg">' + '<p>' + badge(c.result) + ' ' + sev(c.severity) + ' <code>' +
            esc(c.id) + '</code> · ' + esc(c.category_label) + '</p><p><b>' + esc(c.summary) + '</b></p>';
        if (focusFix) {
            html += fixHtml(c);
        }
        html += '<h4>' + esc(S.recommendation) + '</h4><p>' + esc(c.recommendation) + '</p>';
        if (!focusFix) {
            html += fixHtml(c);
        }
        html += '<h4>' + esc(S.evidence) + '</h4>' + evidenceHtml(c.evidence);
        html += '<h4>' + esc(S.references) + '</h4><ul class="pa-ins-refs">' + (c.references || []).map(function (r) {
            return '<li><a href="' + esc(r.url) + '" target="_blank" rel="noopener noreferrer">' + esc(r.label) +
                '</a>' + (r.title ? ' — ' + esc(r.title) : '') + '</li>';
        }).join('') + '</ul><div id="pa_post_answer"></div></div>';
        const buttons = [];
        const fix = c.fix || {};
        const page = fix.page || c.page;
        if (page) {
            buttons.push({label: S.openPage, icon: 'fa fa-external-link', action: function () {
                window.open('/' + String(page).replace(/^\//, ''), '_blank', 'noopener');
            }});
        }
        if (fix.action && typeof PASimulation !== 'undefined') {
            buttons.push({label: S.simulate, icon: 'fa fa-flask', cssClass: 'btn-primary', action: function () {
                PASimulation.simulate({action: fix.action.name, args: fix.action.args || [], title: c.title});
            }});
        }
        if (fix.minrule && typeof PAMinRule !== 'undefined') {
            buttons.push({label: S.minrule, icon: 'fa fa-compress', cssClass: 'btn-primary', action: function () {
                PAMinRule.open(fix.minrule);
            }});
        }
        if (aiEnabled) {
            buttons.push({label: S.explain, icon: 'fa fa-magic', action: function () {
                explain(c.id, '#pa_post_answer');
            }});
        }
        buttons.push({label: S.preview, action: function () { preview(c.id); }});
        buttons.push({label: S.close, action: function (d) { d.close(); }});
        I.dialog({title: c.id + ' — ' + c.title, message: html, buttons: buttons});
    }

    function explain(id, target) {
        let dlg = null;
        if (target) {
            $(target).html(I.wait(S.asking));
        } else {
            dlg = I.dialog({title: id === 'summary' ? S.summaryAi : S.explain + ' — ' + id, message: I.wait(S.asking),
                buttons: [{label: S.close, action: function (d) { d.close(); }}]});
        }
        ajaxCall(API + 'explain', {id: id}, function (data) {
            const html = I.answer(data, S);
            if (target) {
                $(target).html('<h4><i class="fa fa-magic"></i> ' + esc(S.explain) + '</h4>' + html);
            } else {
                dlg.getModalBody().html(html);
            }
        });
    }

    function preview(id) {
        ajaxCall(API + 'explain', {id: id, preview: 1}, function (data) {
            I.dialog({title: S.preview, message: I.answer(data, S),
                buttons: [{label: S.close, action: function (d) { d.close(); }}]});
        });
    }

    function attachHistory(cb) {
        ajaxGet(API + 'history', {days: 90}, function (h) {
            report.trendPoints = ((h && h.history) || []).map(function (p) {
                return {value: p.score, label: I.when(p.generated) + ': ' + p.score + ' (' + p.grade + ')'};
            });
            cb();
        });
    }

    function load() {
        $('#pa_posture').html(I.wait(S.running));
        ajaxGet(API + 'report', {}, function (data) {
            report = data;
            if (report && report.status === 'ok') {
                attachHistory(render);
            } else {
                render();
            }
        });
    }

    function run() {
        $('#pa_post_run').prop('disabled', true).html('<i class="fa fa-spinner fa-pulse"></i> ' + esc(S.running));
        ajaxCall(API + 'run', {}, function (data) {
            report = data;
            if (report && report.status === 'ok') {
                attachHistory(render);
            } else {
                render();
            }
        });
    }

    function init(opts) {
        opts = opts || {};
        S = Object.assign(S, opts.strings || {});
        aiEnabled = !!opts.aiEnabled;
        if (opts.aiStatusUrl) {
            ajaxGet(opts.aiStatusUrl, {}, function (st) {
                aiEnabled = !!(st && st.enabled);
                if (report) {
                    render();
                }
            });
        }
        load();
    }

    return {init: init, reload: load};
})();
