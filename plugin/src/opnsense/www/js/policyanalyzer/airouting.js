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
 * Settings > "AI per scenario": one row per AI scenario of the plugin (provider, model, sync or queue, timeout,
 * num_ctx, num_predict, keep_alive, context budget), the presets "Local only" / "Hybrid" / "Follow the global
 * provider", the fallback provider, the cron job of the queue and the queue itself (latest jobs and statistics per
 * scenario and model: what docs/ia-local-catalogo.md is filled with).
 *
 * Every change is simulated first and journaled (PASimulation.run with the change actions ai_routing and
 * ai_queue_schedule); this page never writes anything itself.  Table on desktop, cards below 768 px.
 *
 *   PAAIRouting.init({strings: {...}})
 */
const PAAIRouting = (function () {
    'use strict';

    const API = '/api/policyanalyzer/ai/';
    let S = {
        title: 'AI per scenario',
        help: 'Each AI feature of the plugin is a scenario with its own provider, model and limits. Empty fields ' +
            'follow the global provider above. Long scenarios on the local runtime go to a background queue: the page ' +
            'shows the position and the estimate and receives the answer when it is ready.',
        presets: 'Presets', fallback: 'Fallback provider', fallbackHelp: 'Used when the provider of a scenario ' +
            'fails (bridge down, timeout). "auto": the Ollama of this firewall, when the AI setup installed it.',
        setFallback: 'Simulate', scenario: 'Scenario', kind: 'Kind', provider: 'Provider', model: 'Model',
        mode: 'Mode', timeout: 'Timeout (s)', ctx: 'num_ctx', predict: 'num_predict', keepAlive: 'keep_alive',
        budget: 'Context budget (tokens)', retries: 'Correction attempts', think: 'Reasoning (think)',
        thinkOff: 'off', thinkOn: 'on', thinkLow: 'low (gpt-oss)', thinkMedium: 'medium (gpt-oss)',
        thinkHigh: 'high (gpt-oss)', thinkBudget: 'Reasoning tokens (think_budget)',
        thinkBudgetHelp: 'Extra num_predict for the reasoning when it is on (default 3072). Small models may need ' +
            'more; num_ctx must hold the prompt + this + num_predict.', thinkHelp: 'Thinking models reason before answering: better analysis, but ' +
            'more time (the reasoning takes think_budget more tokens of num_predict). Raise the timeout with it. Models ' +
            'without the thinking capability ignore it.', source: 'Source', edit: 'Edit',
        reset: 'Follow the global provider', simulate: 'Simulate', global: 'global', scenarioSet: 'scenario',
        short: 'short', long: 'long', background: 'already in the background', structured: 'JSON Schema on Ollama',
        mapreduce: 'map/reduce above the budget', defaultProvider: 'global provider', sync: 'synchronous',
        queue: 'background queue', auto: 'auto (queue when local and long)', queueTitle: 'AI queue',
        cron: 'Cron job of the queue', cronOn: 'installed (every 5 minutes)', cronOff: 'not installed',
        cronCreate: 'Install the cron job', cronRemove: 'Remove the cron job', worker: 'Worker',
        workerOn: 'running', workerOff: 'idle', kick: 'Run the queue now', refresh: 'Refresh', jobs: 'Latest jobs',
        stats: 'Statistics per scenario and model (90 days)', none: 'nothing yet', status: 'Status',
        queueS: 'Queue (s)', runS: 'Run (s)', tokens: 'Tokens in/out', format: 'Format ok', lang: 'Language ok',
        fb: 'Fallback', cancel: 'Cancel', count: 'Jobs', ok: 'ok', cached: 'from cache', when: 'Created',
        fallbackActive: 'fallback', editTitle: 'AI per scenario: %s', presetApply: 'Simulate preset',
        runtimeMissing: 'The local runtime is not installed: the local presets need the AI setup first.'
    };
    let data = null;

    function esc(v) { return PASimulation.escape(v); }

    function fmt(t, a) { return String(t).replace('%s', a); }

    function load() {
        ajaxGet(API + 'routing', {}, function (res) {
            data = res && res.status === 'ok' ? res : null;
            render();
        });
        loadQueue();
    }

    function routeText(r) {
        if (!r) {
            return '';
        }
        return [r.provider, r.model].filter(Boolean).join(' · ');
    }

    function modeText(m) {
        return S[m] || m || S.sync;
    }

    function badge(text, cls) {
        return '<span class="label label-' + (cls || 'default') + '">' + esc(text) + '</span>';
    }

    function render() {
        const $root = $('#pa_airouting_body').empty();
        if (!data) {
            $root.append($('<div class="alert alert-warning"/>').text('AI routing unavailable'));
            return;
        }
        /* presets */
        const $pre = $('<div class="pa-air-presets"/>').append($('<b/>').text(S.presets + ': '));
        (data.presets || []).forEach(function (p) {
            $pre.append($('<button type="button" class="btn btn-default btn-sm"/>')
                .toggleClass('active', data.preset === p.id || (!data.preset && p.id === 'global'))
                .attr('title', p.help).text(p.label).on('click', function () {
                    PASimulation.run({action: 'ai_routing', args: ['preset', p.id], title: S.presetApply + ': ' + p.label,
                        plainRevert: p.help, onDone: load});
                })).append(' ');
        });
        $root.append($pre);
        if (!data.runtime_installed) {
            $root.append($('<p class="text-muted"/>').append($('<small/>').text(S.runtimeMissing)));
        }
        /* fallback */
        const fb = data.fallback || {provider: 'auto', model: ''};
        const $fb = $('<form class="form-inline pa-air-fallback"/>');
        const $fp = $('<select class="form-control input-sm" aria-label="' + esc(S.fallback) + '"/>');
        ((data.fields || {}).fallback || ['auto', 'none']).forEach(function (v) {
            $fp.append($('<option/>').val(v).text(v).prop('selected', v === fb.provider));
        });
        const $fm = $('<input type="text" class="form-control input-sm" maxlength="128"/>').val(fb.model || '')
            .attr('placeholder', S.model).attr('aria-label', S.model);
        $fb.append($('<b/>').text(S.fallback + ': ')).append($fp).append(' ').append($fm).append(' ')
            .append($('<button type="submit" class="btn btn-default btn-sm"/>').text(S.setFallback));
        $fb.on('submit', function (e) {
            e.preventDefault();
            const p = $fp.val();
            const spec = (p === 'auto' || p === 'none') && !$fm.val().trim() ? p :
                'provider=' + p + ($fm.val().trim() ? '+model=' + $fm.val().trim() : '');
            PASimulation.run({action: 'ai_routing', args: ['fallback', spec], title: S.fallback, onDone: load});
        });
        $root.append($fb).append($('<p class="text-muted"/>').append($('<small/>').text(S.fallbackHelp)));

        /* desktop table */
        const $table = $('<table class="table table-condensed table-striped pa-air-table"/>');
        $table.append('<thead><tr><th>' + [S.scenario, S.provider, S.mode, S.timeout, S.ctx, S.predict, S.keepAlive,
            S.budget, S.think, S.fb, ''].map(esc).join('</th><th>') + '</th></tr></thead>');
        const $tb = $('<tbody/>');
        const $cards = $('<div class="pa-air-cards"/>');
        (data.scenarios || []).forEach(function (sc) {
            const r = sc.route || {};
            const tags = [badge(S[sc.kind] || sc.kind, sc.kind === 'long' ? 'warning' : 'info')];
            if (sc.background) {
                tags.push(badge(S.background));
            }
            if (sc.structured) {
                tags.push(badge(S.structured));
            }
            if (sc.mapreduce) {
                tags.push(badge(S.mapreduce));
            }
            const src = r.source === 'scenario' ? badge(S.scenarioSet, 'primary') : badge(S.global);
            const fbText = r.fallback ? routeText(r.fallback) + ' (' + modeText(r.fallback.mode) + ')' : '—';
            const editBtn = $('<button type="button" class="btn btn-default btn-xs pa-air-edit"/>')
                .attr('aria-label', S.edit + ' ' + sc.label).html('<i class="fa fa-pencil"></i> ' + esc(S.edit))
                .on('click', function () { edit(sc); });
            const $tr = $('<tr/>');
            $tr.append($('<td/>').html('<b>' + esc(sc.label) + '</b><br/><code>' + esc(sc.id) + '</code> ' + tags.join(' ')));
            $tr.append($('<td/>').html(esc(routeText(r)) + '<br/>' + src));
            $tr.append($('<td/>').text(modeText(r.mode)));
            $tr.append($('<td/>').text(r.timeout || '—'));
            $tr.append($('<td/>').text(r.num_ctx || '—'));
            $tr.append($('<td/>').text(r.num_predict || '—'));
            $tr.append($('<td/>').text(r.keep_alive || '—'));
            $tr.append($('<td/>').text(r.budget || '—'));
            $tr.append($('<td/>').text(thinkCell(r)));
            $tr.append($('<td/>').text(fbText));
            $tr.append($('<td/>').append(editBtn.clone(true)));
            $tb.append($tr);
            /* mobile card */
            const rows = [[S.provider, routeText(r)], [S.mode, modeText(r.mode)], [S.timeout, r.timeout || '—'],
                [S.ctx + ' / ' + S.predict, (r.num_ctx || '—') + ' / ' + (r.num_predict || '—')],
                [S.keepAlive, r.keep_alive || '—'], [S.budget, r.budget || '—'], [S.think, thinkCell(r)],
                [S.fb, fbText]];
            const $card = $('<div class="pa-air-card"/>').append($('<div class="pa-air-card-title"/>')
                .html('<b>' + esc(sc.label) + '</b> ' + src + '<br/>' + tags.join(' ')));
            const $dl = $('<dl class="pa-air-dl"/>');
            rows.forEach(function (row) {
                $dl.append($('<dt/>').text(row[0])).append($('<dd/>').text(row[1]));
            });
            $card.append($dl).append(editBtn);
            $cards.append($card);
        });
        $table.append($tb);
        $root.append($('<div class="pa-air-table-wrap"/>').append($table)).append($cards);
        renderCron();
    }

    function field(id, label, $input, help) {
        const $g = $('<div class="form-group"/>').append($('<label/>').attr('for', id).text(label))
            .append($input.attr('id', id).addClass('form-control'));
        if (help) {
            $g.append($('<small class="help-block"/>').text(help));
        }
        return $g;
    }

    function thinkText(v) {
        const key = 'think' + String(v || 'off').charAt(0).toUpperCase() + String(v || 'off').slice(1);
        return S[key] || String(v || 'off');
    }

    function thinkCell(r) {
        return thinkText(r.think) + (r.think && r.think !== 'off' && r.think_budget ? ' (' + r.think_budget + ')' : '');
    }

    function edit(sc) {
        const e = sc.entry || {};
        const lim = (data.fields || {}).limits || {};
        const num = function (key, value) {
            const range = lim[key] || [];
            return $('<input type="number"/>').attr({min: range[0], max: range[1]}).val(value || '');
        };
        const $f = $('<form class="pa-air-form" autocomplete="off"/>');
        const $prov = $('<select/>');
        ((data.fields || {}).providers || ['default', 'ollama', 'claudecode', 'claude']).forEach(function (p) {
            $prov.append($('<option/>').val(p).text(p === 'default' ? S.defaultProvider : p)
                .prop('selected', (e.provider || 'default') === p));
        });
        const $mode = $('<select/>');
        ((data.fields || {}).modes || ['sync', 'queue', 'auto']).forEach(function (m) {
            $mode.append($('<option/>').val(m).text(modeText(m)).prop('selected', (e.mode || 'sync') === m));
        });
        const $think = $('<select/>');
        ((data.fields || {}).think || ['off', 'on', 'low', 'medium', 'high']).forEach(function (v) {
            $think.append($('<option/>').val(v).text(thinkText(v)).prop('selected', (e.think || 'off') === v));
        });
        const inputs = {
            provider: $prov,
            model: $('<input type="text" maxlength="128"/>').val(e.model || '').attr('placeholder', 'qwen2.5:3b, fable, ...'),
            mode: $mode,
            timeout: num('timeout', e.timeout),
            num_ctx: num('num_ctx', e.num_ctx),
            num_predict: num('num_predict', e.num_predict),
            keep_alive: $('<input type="text" maxlength="6"/>').val(e.keep_alive || '').attr('placeholder', '30m'),
            budget: num('budget', e.budget),
            retries: num('retries', e.retries),
            think: $think,
            think_budget: num('think_budget', e.think_budget).attr('placeholder', '3072')
        };
        const labels = {provider: S.provider, model: S.model, mode: S.mode, timeout: S.timeout, num_ctx: S.ctx,
            num_predict: S.predict, keep_alive: S.keepAlive, budget: S.budget, retries: S.retries, think: S.think,
            think_budget: S.thinkBudget};
        Object.keys(inputs).forEach(function (k) {
            $f.append(field('pa_air_' + k, labels[k], inputs[k], k === 'think' ? S.thinkHelp : (k === 'think_budget' ? S.thinkBudgetHelp : undefined)));
        });
        const spec = function () {
            return Object.keys(inputs).map(function (k) {
                const v = String(inputs[k].val() || '').trim();
                return v && !(k === 'provider' && v === 'default') && !(k === 'think' && v === 'off') ?
                    k + '=' + v : null;
            }).filter(Boolean).join('+');
        };
        PASimulation.dialog({
            title: fmt(S.editTitle, sc.label), message: $f, size: BootstrapDialog.SIZE_WIDE,
            buttons: [{label: S.reset, action: function (dlg) {
                dlg.close();
                PASimulation.run({action: 'ai_routing', args: [sc.id, 'reset'], title: fmt(S.editTitle, sc.label),
                    onDone: load});
            }}, {label: S.simulate, cssClass: 'btn-primary', action: function (dlg) {
                const value = spec();
                dlg.close();
                PASimulation.run({action: 'ai_routing', args: [sc.id, value || 'reset'], title: fmt(S.editTitle, sc.label),
                    onDone: load});
            }}]
        });
    }

    function renderCron() {
        const $c = $('#pa_airouting_cron').empty();
        const on = data && (data.queue_cron || []).length > 0;
        $c.append($('<b/>').text(S.cron + ': ')).append(document.createTextNode((on ? S.cronOn : S.cronOff) + ' '));
        $c.append($('<button type="button" class="btn btn-default btn-xs"/>').text(on ? S.cronRemove : S.cronCreate)
            .on('click', function () {
                PASimulation.run({action: 'ai_queue_schedule', args: [on ? 'remove' : 'create'], title: S.cron,
                    onDone: load});
            }));
    }

    function secs(v) {
        return v === null || v === undefined ? '—' : String(v);
    }

    function pct(v) {
        return v === null || v === undefined ? '—' : Math.round(v * 100) + ' %';
    }

    function loadQueue() {
        ajaxGet(API + 'queue', {limit: 30}, function (q) {
            const $q = $('#pa_airouting_queue').empty();
            if (!q || q.status !== 'ok') {
                return;
            }
            const head = $('<p/>').append($('<b/>').text(S.worker + ': '))
                .append(document.createTextNode((q.worker && q.worker.running ? S.workerOn : S.workerOff) + ' · ' +
                    Object.keys(q.counts || {}).map(function (k) { return k + ' ' + q.counts[k]; }).join(', ') +
                    (q.cache ? ' · cache ' + q.cache.entries + ' (' + q.cache.hits + ' hits)' : '') + ' '));
            head.append($('<button type="button" class="btn btn-default btn-xs"/>').text(S.kick).on('click', function () {
                ajaxCall(API + 'queue_kick', {}, function () { setTimeout(loadQueue, 1500); });
            })).append(' ').append($('<button type="button" class="btn btn-default btn-xs"/>').text(S.refresh)
                .on('click', load));
            $q.append(head);
            $q.append($('<h5/>').text(S.jobs));
            const jobs = q.jobs || [];
            if (!jobs.length) {
                $q.append($('<p class="text-muted"/>').text(S.none));
            } else {
                const $t = $('<table class="table table-condensed table-striped pa-air-jobs"/>');
                $t.append('<thead><tr><th>#</th><th>' + [S.scenario, S.status, S.model, S.queueS, S.runS, S.tokens,
                    S.format, S.lang, ''].map(esc).join('</th><th>') + '</th></tr></thead>');
                const $b = $('<tbody/>');
                jobs.forEach(function (j) {
                    const st = j.status + (j.status === 'queued' && j.position ? ' (' + j.position + ')' : '') +
                        (j.fallback ? ' · ' + S.fallbackActive : '') + (j.cached_calls ? ' · ' + S.cached : '');
                    const $tr = $('<tr/>').append($('<td/>').text(j.id)).append($('<td/>').text(j.scenario))
                        .append($('<td/>').text(st).attr('title', j.error || ''))
                        .append($('<td/>').text((j.model_used || j.model || '') + (j.provider_used ? ' (' + j.provider_used + ')' : '')))
                        .append($('<td/>').text(secs(j.queue_seconds))).append($('<td/>').text(secs(j.run_seconds)))
                        .append($('<td/>').text((j.prompt_tokens || '—') + ' / ' + (j.completion_tokens || '—')))
                        .append($('<td/>').text(j.format_ok === null || j.format_ok === undefined ? '—' : (j.format_ok ? S.ok : '✗')))
                        .append($('<td/>').text(j.lang_ok === null || j.lang_ok === undefined ? '—' : (j.lang_ok ? S.ok : '✗')));
                    const $act = $('<td/>');
                    if (j.status === 'queued' || j.status === 'running') {
                        $act.append($('<button type="button" class="btn btn-default btn-xs"/>').text(S.cancel)
                            .on('click', function () {
                                ajaxCall(API + 'queue_cancel', {id: j.id}, function () { loadQueue(); });
                            }));
                    }
                    $tr.append($act);
                    $b.append($tr);
                });
                $q.append($('<div class="pa-air-table-wrap"/>').append($t.append($b)));
            }
            $q.append($('<h5/>').text(S.stats));
            const stats = q.stats || [];
            if (!stats.length) {
                $q.append($('<p class="text-muted"/>').text(S.none));
                return;
            }
            const $s = $('<table class="table table-condensed table-striped pa-air-stats"/>');
            $s.append('<thead><tr><th>' + [S.scenario, S.model, S.count, S.ok, S.queueS, S.runS, S.tokens, S.format,
                S.lang, S.fb].map(esc).join('</th><th>') + '</th></tr></thead>');
            const $sb = $('<tbody/>');
            stats.forEach(function (r) {
                $sb.append($('<tr/>').append($('<td/>').text(r.scenario))
                    .append($('<td/>').text((r.model || '') + (r.provider ? ' (' + r.provider + ')' : '')))
                    .append($('<td/>').text(r.jobs)).append($('<td/>').text(r.ok))
                    .append($('<td/>').text(secs(r.queue_s))).append($('<td/>').text(secs(r.run_s) +
                        (r.run_max ? ' (max ' + r.run_max + ')' : '')))
                    .append($('<td/>').text((r.prompt_tokens || '—') + ' / ' + (r.completion_tokens || '—')))
                    .append($('<td/>').text(pct(r.format_ok))).append($('<td/>').text(pct(r.lang_ok)))
                    .append($('<td/>').text(r.fallback || 0)));
            });
            $q.append($('<div class="pa-air-table-wrap"/>').append($s.append($sb)));
        });
    }

    return {
        init: function (opts) {
            S = Object.assign({}, S, (opts && opts.strings) || {});
            load();
        },
        refresh: load
    };
})();
