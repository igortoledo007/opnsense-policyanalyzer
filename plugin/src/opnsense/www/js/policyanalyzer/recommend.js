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
 * "Recommended for this hardware" block (Settings tab and the AI setup wizard, step 5).
 *
 *   PARecommend.setStrings({...});
 *   PARecommend.load($target, {onUse: function (modelName) {...}, url: '/api/policyanalyzer/ai/recommend',
 *                              params: {budget: 40}});              budget: % of RAM for the model
 *   PARecommend.render($target, data, opts)        when the caller already has the data
 *   opts.visible: alternatives shown before "Show all" (default 4)
 *
 * Data: GET /api/policyanalyzer/ai/recommend (manage.py status recommend):
 *   {recommended, alternatives[], candidates[{model, verdict, reasons[], est_seconds_per_finding, ram_gb,
 *    size_gb, pt_br, note}], backend, settings{num_thread, num_ctx, reason}, notes[], estimates}
 * "Use this model" always passes the concrete model name (never the word "recommended").
 */
const PARecommend = (function () {
    'use strict';

    let S = {
        title: 'Recommended for this hardware',
        none: 'No model fits this hardware as a local runtime: use a model server in your network.',
        perFinding: 's per finding',
        ram: 'RAM',
        disk: 'download',
        backend: 'backend',
        use: 'Use this model',
        alternatives: 'Alternatives',
        showAll: 'Show all {n} alternatives',
        settings: 'Suggested settings',
        notes: 'Notes',
        estimates: 'Estimates are rough; run the benchmark in the AI setup for real numbers.',
        unavailable: 'Recommendations are not available (the AI setup component is not installed).',
        recommended: 'recommended',
        possible: 'possible',
        not_recommended: 'not recommended'
    };
    const VERDICT_CLASS = {recommended: 'success', possible: 'warning', not_recommended: 'default'};

    function esc(value) {
        return $('<div/>').text(value === undefined || value === null ? '' : String(value)).html();
    }

    function facts(c, backend) {
        const out = [];
        if (c.est_seconds_per_finding) {
            out.push('~' + c.est_seconds_per_finding + ' ' + S.perFinding);
        }
        if (c.ram_gb) {
            out.push(S.ram + ' ' + c.ram_gb + ' GB');
        }
        if (c.size_gb) {
            out.push(S.disk + ' ' + c.size_gb + ' GB');
        }
        if (backend) {
            out.push(S.backend + ' ' + backend);
        }
        return out.join(' · ');
    }

    function useButton(name, opts, primary) {
        return $('<button type="button" class="btn ' + (primary ? 'btn-primary' : 'btn-default btn-xs') + '"/>')
            .text(S.use).click(function () {
                if (opts.onUse && name && name !== 'recommended') {
                    opts.onUse(name);
                }
            });
    }

    function render(target, data, opts) {
        opts = opts || {};
        target.empty().addClass('pa-recommend');
        if (!data || data.status === 'error') {
            target.append($('<div class="text-muted"/>').text((data && data.message) || S.unavailable));
            return;
        }
        const cands = data.candidates || [];
        const best = cands.find(function (c) { return c.model === data.recommended; });
        if (!best) {
            target.append($('<div class="alert alert-warning"/>').text(S.none));
        } else {
            const box = $('<div class="panel panel-primary pa-rec-best"/>');
            const body = $('<div class="panel-body"/>');
            body.append($('<div class="pa-rec-name"/>').text(best.model)
                .append(' <span class="label label-success">' + esc(S.recommended) + '</span>'));
            body.append($('<div class="pa-rec-facts text-muted"/>').text(facts(best, data.backend)));
            if ((best.reasons || []).length) {
                body.append($('<div class="pa-rec-reasons"/>').text(best.reasons.join('; ')));
            }
            body.append(useButton(best.model, opts, true));
            target.append(box.append(body));
        }
        const others = cands.filter(function (c) { return !best || c.model !== best.model; });
        const visible = opts.visible || 4;
        if (others.length) {
            target.append($('<h5/>').text(S.alternatives));
            const list = $('<ul class="list-unstyled pa-rec-list"/>');
            others.forEach(function (c, idx) {
                const li = $('<li class="pa-rec-item"/>');
                if (idx >= visible) {
                    li.addClass('pa-rec-extra').hide();
                }
                li.append($('<b/>').text(c.model)).append(' <span class="label label-' +
                    (VERDICT_CLASS[c.verdict] || 'default') + '">' + esc(S[c.verdict] || c.verdict) + '</span> ');
                li.append($('<span class="text-muted"/>').text(facts(c)));
                if ((c.reasons || []).length) {
                    li.append($('<div class="pa-rec-reasons text-muted"/>').text(c.reasons.join('; ')));
                }
                if (c.verdict !== 'not_recommended') {
                    li.append(useButton(c.model, opts, false));
                }
                list.append(li);
            });
            target.append(list);
            if (others.length > visible) {
                $('<button type="button" class="btn btn-default btn-xs pa-rec-more"/>')
                    .text(S.showAll.replace('{n}', others.length)).click(function () {
                        list.find('.pa-rec-extra').slideDown(150);
                        $(this).remove();
                    }).appendTo(target);
            }
        }
        if (data.settings) {
            target.append($('<p class="pa-rec-settings"/>').text(S.settings + ': num_thread ' +
                data.settings.num_thread + ', num_ctx ' + data.settings.num_ctx +
                (data.settings.reason ? ' (' + data.settings.reason + ')' : '')));
        }
        if ((data.notes || []).length) {
            target.append($('<h5/>').text(S.notes));
            target.append('<ul class="pa-rec-notes text-muted">' + data.notes.map(function (n) {
                return '<li>' + esc(n) + '</li>';
            }).join('') + '</ul>');
        }
        target.append($('<p class="text-muted"/>').append($('<small/>').text(S.estimates)));
    }

    function load(target, opts) {
        opts = opts || {};
        target.html('<i class="fa fa-spinner fa-pulse"></i>');
        ajaxGet(opts.url || '/api/policyanalyzer/ai/recommend', opts.params || {}, function (data) {
            render(target, data, opts);
        });
    }

    return {
        setStrings: function (strings) { S = Object.assign({}, S, strings || {}); },
        render: render,
        load: load
    };
})();
