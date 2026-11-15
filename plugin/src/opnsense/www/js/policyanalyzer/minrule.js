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
 * "Minimal rule from the observed traffic" dialog (read only).
 *
 *   PAMinRule.setStrings({...})
 *   PAMinRule.open(uuid, {days: 7})     analyse one pass rule: observed traffic, proposal, coverage, what would be
 *                                       blocked, diff; "Open rule" leads to the rule editor, "Simulate" shows the
 *                                       read-only plan (PASimulation.show(plan, {readOnly: true}))
 *   PAMinRule.pick()                    list of candidate rules (permissive / wan_exposed findings first)
 *
 * Nothing is applied from here: the administrator edits the rule.
 */
const PAMinRule = (function () {
    'use strict';

    const API = '/api/policyanalyzer/minrule/';
    const I = PAInsights;
    const esc = I.esc;
    let S = {
        title: 'Minimal rule from the observed traffic', pick: 'Choose a rule to narrow', analyze: 'Analyse',
        window: 'Window', days: 'days', analyzing: 'Reading the filter log / NetFlow of the rule...',
        rule: 'Rule', observed: 'Observed', coverage: 'Coverage of the observed traffic', changes: 'Proposed changes',
        field: 'Field', from: 'Now', to: 'Proposed', aliases: 'New aliases', extra: 'Additional rules',
        wouldBlock: 'Observed traffic the proposal would block', nothingBlocked: 'Nothing observed would be blocked.',
        warnings: 'Notes', diff: 'Diff (for the rule editor)', openRule: 'Open rule', simulate: 'Simulate',
        explain: 'Explain risk (AI)', close: 'Close', confidence: 'Confidence', exact: 'filter log (exact)',
        approx: 'NetFlow (approximate)', noTraffic: 'No traffic attributed to this rule in the window.',
        candidates: 'Rules', reasons: 'Why', noCandidates: 'No permissive pass rule found.', error: 'Error',
        asking: 'Asking the AI...', nothingToNarrow: 'The rule already matches only what was observed.',
        high: 'high', medium: 'medium', low: 'low', none: 'none', proposalOnly:
            'Proposal only: open the rule and change it yourself; nothing is applied from here.',
        aiDisabled: 'AI assistance is disabled in the settings.', anonymized: 'anonymized',
        notAnonymized: 'not anonymized', cached: 'cached', aiDisclaimer: 'AI text: verify before acting.',
        logs: 'logs', nolog: 'no log'
    };
    let aiEnabled = null;

    function setStrings(strings) {
        S = Object.assign(S, strings || {});
    }

    function ai(cb) {
        if (aiEnabled !== null) {
            return cb(aiEnabled);
        }
        ajaxGet('/api/policyanalyzer/ai/status', {}, function (st) {
            aiEnabled = !!(st && st.enabled);
            cb(aiEnabled);
        });
    }

    function coverageBar(pct) {
        const color = pct >= 99 ? I.STATUS.pass : (pct >= 90 ? I.STATUS.warn : I.STATUS.fail);
        return '<div class="pa-ins-cov"><span class="pa-ins-cov-track"><span style="width:' + Math.max(1, pct) +
            '%;background:' + color + '"></span></span><b>' + esc(pct) + '%</b></div>';
    }

    function render(r) {
        if (!r || r.status !== 'ok') {
            return '<div class="alert alert-danger">' + esc((r && r.message) || S.error) + '</div>';
        }
        const rule = r.rule;
        let html = '<div class="pa-ins-dlg"><p><b>' + esc(S.rule) + ':</b> ' + esc(rule.description || rule.uuid) +
            ' <span class="text-muted">(' + esc(rule.interface) + ', ' + (rule.log ? esc(S.logs) : esc(S.nolog)) +
            ')</span></p><pre class="pa-ins-pre">' + esc(rule.summary) + '</pre>';
        const o = r.observed || {};
        if (!r.proposal) {
            return html + '<div class="alert alert-info">' + esc(r.message || S.noTraffic) + '</div></div>';
        }
        const unit = o.unit === 'flows' ? S.approx : S.exact;
        html += '<p><b>' + esc(S.observed) + ':</b> ' + esc(o.total) + ' ' + esc(o.unit) + ' · ' + esc(unit) + ' · ' +
            esc(o.destinations) + ' dst, ' + esc(o.ports) + ' ports, ' + Object.keys(o.protocols || {}).map(function (p) {
                return esc(p) + ' ' + esc(o.protocols[p]);
            }).join(', ') + ' · ' + esc(o.days_with_data) + '/' + esc(r.window_days) + ' ' + esc(S.days) + ' · ' +
            esc(S.confidence) + ': <span class="pa-ins-conf pa-conf-' + esc(r.confidence) + '">' +
            esc(S[r.confidence] || r.confidence) + '</span></p>';
        html += '<h4>' + esc(S.coverage) + '</h4>' + coverageBar(r.coverage.percent);
        const p = r.proposal;
        html += '<h4>' + esc(S.changes) + '</h4>';
        if (p.changes.length) {
            html += '<table class="table table-condensed pa-ins-kv"><thead><tr><th>' + esc(S.field) + '</th><th>' +
                esc(S.from) + '</th><th>' + esc(S.to) + '</th></tr></thead><tbody>' + p.changes.map(function (c) {
                    return '<tr><td>' + esc(c.field) + '</td><td class="pa-del">' + esc(c.from) + '</td><td class="pa-add">' +
                        esc(c.to) + '</td></tr>';
                }).join('') + '</tbody></table>';
        } else {
            html += '<p class="text-muted">' + esc(S.nothingToNarrow) + '</p>';
        }
        if (p.aliases.length) {
            html += '<h4>' + esc(S.aliases) + '</h4>' + p.aliases.map(function (a) {
                return '<p><code>' + esc(a.name) + '</code> (' + esc(a.type) + ', ' + esc(a.content.length) + ')<br/>' +
                    '<span class="small pa-ins-wrap">' + a.content.map(esc).join(', ') + '</span></p>';
            }).join('');
        }
        if (p.extra_rules.length) {
            html += '<h4>' + esc(S.extra) + '</h4><ul>' + p.extra_rules.map(function (e) {
                return '<li>' + esc(e.protocol) + ' → ' + esc(e.destination) + ' (' + esc(e.connections) + '): ' +
                    esc(e.why) + '</li>';
            }).join('') + '</ul>';
        }
        html += '<h4>' + esc(S.wouldBlock) + '</h4>';
        if (r.would_block.length) {
            html += '<table class="table table-condensed pa-ins-kv"><tbody>' + r.would_block.map(function (b) {
                return '<tr><td>' + esc(b.proto) + '</td><td>' + esc(b.src) + '</td><td>→ ' + esc(b.dst) +
                    (b.dport ? ':' + esc(b.dport) : '') + '</td><td>' + esc(b.count) + '</td></tr>';
            }).join('') + '</tbody></table>';
        } else {
            html += '<p class="text-muted">' + esc(S.nothingBlocked) + '</p>';
        }
        html += '<h4>' + esc(S.warnings) + '</h4><ul class="small">' + (r.plan.warnings || []).map(function (w) {
            return '<li>' + esc(w) + '</li>';
        }).join('') + '</ul><h4>' + esc(S.diff) + '</h4>' + I.diff(r.diff) +
            '<p class="small text-muted">' + esc(S.proposalOnly) + '</p><div id="pa_min_answer"></div></div>';
        return html;
    }

    function open(uuid, opts) {
        opts = opts || {};
        let days = opts.days || 7;
        let last = null;
        const controls = '<div class="pa-ins-toolbar"><label>' + esc(S.window) + ' <select id="pa_min_days" ' +
            'class="form-control">' + [1, 3, 7, 14, 30].map(function (d) {
                return '<option value="' + d + '"' + (d === days ? ' selected' : '') + '>' + d + ' ' + esc(S.days) +
                    '</option>';
            }).join('') + '</select></label></div><div id="pa_min_body"></div>';
        ai(function (enabled) {
            const buttons = [
                {label: S.openRule, icon: 'fa fa-external-link', action: function () {
                    if (last && last.rule) {
                        window.open('/' + last.rule.ref, '_blank', 'noopener');
                    }
                }},
                {label: S.simulate, icon: 'fa fa-flask', cssClass: 'btn-primary', action: function () {
                    if (last && last.plan && typeof PASimulation !== 'undefined') {
                        PASimulation.show(last.plan, {readOnly: true, title: S.title});
                    }
                }}
            ];
            if (enabled) {
                buttons.push({label: S.explain, icon: 'fa fa-magic', action: function () {
                    $('#pa_min_answer').html(I.wait(S.asking));
                    ajaxCall(API + 'explain', {uuid: uuid, days: days}, function (data) {
                        $('#pa_min_answer').html('<h4><i class="fa fa-magic"></i> ' + esc(S.explain) + '</h4>' +
                            I.answer(data, S));
                    });
                }});
            }
            buttons.push({label: S.close, action: function (d) { d.close(); }});
            I.dialog({title: S.title, message: controls, buttons: buttons, onshown: function () {
                const run = function () {
                    $('#pa_min_body').html(I.wait(S.analyzing));
                    ajaxCall(API + 'analyze', {uuid: uuid, days: days}, function (data) {
                        last = data;
                        $('#pa_min_body').html(render(data));
                    });
                };
                $('#pa_min_days').on('change', function () {
                    days = parseInt($(this).val(), 10) || 7;
                    run();
                });
                run();
            }});
        });
    }

    function pick() {
        const dlg = I.dialog({title: S.pick, message: I.wait(S.analyzing),
            buttons: [{label: S.close, action: function (d) { d.close(); }}]});
        ajaxGet(API + 'candidates', {}, function (data) {
            const list = (data && data.candidates) || [];
            if (!list.length) {
                dlg.getModalBody().html('<p class="text-muted">' + esc((data && data.message) || S.noCandidates) +
                    '</p>');
                return;
            }
            dlg.getModalBody().html('<div class="pa-ins-picklist">' + list.map(function (c) {
                return '<button type="button" class="pa-ins-pick" data-uuid="' + esc(c.uuid) + '"><b>' +
                    esc(c.description || c.uuid) + '</b> <span class="text-muted">(' + esc(c.interface) + ', ' +
                    (c.exact ? esc(S.exact) : esc(S.approx)) + ')</span>' +
                    c.findings.map(function (f) {
                        return ' <span class="pa-ins-badge pa-b-risk">' + esc(f.type) + '</span>';
                    }).join('') + '<br/><span class="small pa-ins-wrap">' + esc(c.summary) + '</span><br/>' +
                    '<span class="small text-muted">' + esc(S.reasons) + ': ' + c.reasons.map(esc).join(', ') +
                    '</span></button>';
            }).join('') + '</div>');
            dlg.getModalBody().find('.pa-ins-pick').on('click', function () {
                const uuid = $(this).data('uuid');
                dlg.close();
                open(uuid);
            });
        });
    }

    return {setStrings: setStrings, open: open, pick: pick};
})();

window.PAMinRule = PAMinRule;
