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
 * AI setup assistant: a modal over Firewall: Policy Analyzer (/ui/policyanalyzer/#setup; the route
 * /ui/policyanalyzer/setup renders the same page with it open), see WIZARD.md.
 *
 *   PASetup.setStrings({...});           translated labels (setup.volt)
 *   PASetup.bind({onClose});             [data-pa-setup] buttons, the Settings link and #setup / #setup-N open it
 *   PASetup.open({step, onClose});       modal over the Policy Analyzer page (full screen on phones)
 *
 * Eight steps; every one shows the state detected right now (probes, never cookies), what would change and the
 * buttons Back / Skip / Undo / Simulate / Apply / Next. Simulate shows the plan without an Apply button;
 * Apply shows the same plan with the confirmation box(es) and applies through change/apply, so nothing is ever
 * applied without its simulation. Undo opens the action history filtered on the actions of the step.
 *
 *   step      probes (GET)                          change (POST change/plan|apply)
 *   check     setup/hwprofile, ai/runtime           -
 *   provider  ai/providers, settings/get            -
 *   storage   ai/storage                            prepare_storage (path from the saved settings)
 *   runtime   ai/runtime                            install_runtime <branch> [cpus] [+no_start] [+no_boot],
 *                                                   start|stop|enable|disable_runtime, uninstall_runtime
 *   model     ai/runtime, ai/recommend, ai/models   pull_model <name> [+custom] [+large], remove_model <name>
 *   limits    ai/runtime                            set_limits <cpus/threads/ctx/nice>
 *   test      ai/runtime, ai/status, analysis/search  benchmark <model>; ai/explain (preview / send)
 *   finish    settings/get, ai/status, ai/runtime   settings/set (journaled, simulated locally first)
 *
 * Long actions answer "started" + job: PASimulation follows ai/job with a Cancel button; a job that is already
 * running when the page opens is shown in a banner above the step.
 */
const PASetup = (function () {
    'use strict';

    const API = '/api/policyanalyzer/';
    const GIB = 1073741824;
    const GB = 1000000000;
    const esc = PASimulation.escape;
    const fmtBytes = PASimulation.fmtBytes;
    const CTX_VALUES = [2048, 4096, 8192, 16384, 32768];
    const DEFAULT_LIMITS = {cpus: '2-3', threads: 2, ctx: 8192, nice: 20};
    const CPUSET_RE = /^[0-9]{1,3}(-[0-9]{1,3})?([,_][0-9]{1,3}(-[0-9]{1,3})?)*$/;
    const MODEL_RE = /^[A-Za-z0-9][A-Za-z0-9._:\/@+-]{0,127}$/;

    let S = {};                     // strings, see setup.volt

    const STEPS = [
        {id: 'check', actions: []},
        {id: 'provider', actions: ['settings']},
        {id: 'storage', actions: ['prepare_storage']},
        {id: 'runtime', actions: ['install_runtime', 'uninstall_runtime', 'start_runtime', 'stop_runtime',
                                  'enable_runtime', 'disable_runtime']},
        {id: 'model', actions: ['pull_model', 'remove_model']},
        {id: 'limits', actions: ['set_limits']},
        {id: 'test', actions: ['benchmark']},
        {id: 'finish', actions: ['settings']}
    ];
    const LOCAL_STEPS = ['storage', 'runtime', 'model', 'limits', 'test'];

    const state = {
        current: 0,
        root: null,
        hw: null,
        runtime: null,
        storage: null,
        settings: null,
        saved: {},
        providers: null,
        aiStatus: null,
        recommend: null,
        choice: {provider: null, location: 'local'},      // provider id and, for Ollama, local|lan
        model: null,                                      // model chosen for the local runtime
        bench: null,                                      // last benchmark report of this page
        done: {},
        jobTimer: null,
        fields: {},                                       // values typed in the finish step (LAN / Claude)
        dialog: null,                                     // the BootstrapDialog of the assistant while open
        onClose: null,
        prevHash: ''
    };

    /******************************************************************************************************
     * helpers
     ******************************************************************************************************/
    function get(url, data, cb) {
        ajaxGet(API + url, data || {}, function (resp) { cb(resp || {status: 'error'}); });
    }

    function post(url, data, cb) {
        ajaxCall(API + url, data || {}, function (resp) { cb(resp || {status: 'error'}); });
    }

    function gib(bytes) {
        return bytes === null || bytes === undefined ? '?' : (bytes / GIB).toFixed(1) + ' GiB';
    }

    function optionValue(node) {
        if (node !== null && typeof node === 'object') {
            for (const key in node) {
                if (node[key] && node[key].selected) {
                    return key;
                }
            }
            return '';
        }
        return node === undefined || node === null ? '' : String(node);
    }

    function flatten(obj, prefix, out) {
        out = out || {};
        $.each(obj || {}, function (key, value) {
            const path = prefix ? prefix + '.' + key : key;
            const isOptions = value && typeof value === 'object' &&
                Object.values(value).some(function (v) { return v && typeof v === 'object' && 'selected' in v; });
            if (value && typeof value === 'object' && !isOptions) {
                flatten(value, path, out);
            } else {
                out[path] = optionValue(value);
            }
        });
        return out;
    }

    function label(cls, text) {
        return '<span class="label label-' + cls + '">' + esc(text) + '</span>';
    }

    function alert(cls, html) {
        return $('<div class="alert alert-' + cls + '"/>').html(html);
    }

    function facts(rows) {
        const dl = $('<dl class="pa-facts"/>');
        rows.forEach(function (row) {
            if (row[1] === undefined || row[1] === null || row[1] === '') {
                return;
            }
            dl.append($('<dt/>').text(row[0]));
            const dd = $('<dd/>');
            if (row[2] === 'html') {
                dd.html(row[1]);
            } else {
                dd.text(row[1]);
            }
            dl.append(dd);
        });
        return dl;
    }

    function stateBox(title, content) {
        const box = $('<div class="pa-state"/>');
        box.append($('<div class="pa-state-title"/>').text(title || S.currentState));
        box.append(content);
        return box;
    }

    function spinner(text) {
        return $('<p/>').html('<i class="fa fa-spinner fa-pulse"></i> ' + esc(text || S.loading));
    }

    function btn(text, cls, onClick, icon) {
        const b = $('<button type="button" class="btn ' + (cls || 'btn-default') + '"/>');
        b.html((icon ? '<span class="fa ' + icon + ' fa-fw"></span> ' : '') + esc(text));
        if (onClick) {
            b.click(onClick);
        }
        return b;
    }

    function formGroup(id, text, input, help) {
        const g = $('<div class="form-group"/>');
        g.append($('<label/>').attr('for', id).text(text));
        g.append(input.attr('id', id));
        if (help) {
            g.append($('<p class="help-block"/>').append($('<small/>').text(help).attr('title', help)));
        }
        return g;
    }

    function checkbox(id, text, checked, help) {
        const g = $('<div class="checkbox"/>');
        const l = $('<label/>');
        const i = $('<input type="checkbox"/>').attr('id', id).prop('checked', !!checked);
        l.append(i).append($('<span/>').text(text));
        g.append(l);
        if (help) {
            l.attr('title', help);
        }
        return g;
    }

    /* every notice that asks for something brings the button that does it */
    function goBtn(stepId) {
        return btn(S.goTo.replace('%s', stepTitle(stepId)), 'btn-default btn-xs', function () { go(stepIndex(stepId)); },
            'fa-arrow-right');
    }

    function openSettingsTab() {
        if (state.dialog) {
            state.dialog.close();
        }
        $('a[href="#settings"]').tab('show');
    }

    function isLocal() {
        return state.choice.provider === 'ollama' && state.choice.location === 'local';
    }

    /* API providers, and LAN providers that pass the data on (privacy_warn, e.g. Claude Code): privacy as a warning */
    function leavesNetwork(p) {
        return !!p && (p.group === 'api' || !!p.privacy_warn);
    }

    function stepIndex(id) {
        return STEPS.findIndex(function (s) { return s.id === id; });
    }

    /******************************************************************************************************
     * probes
     ******************************************************************************************************/
    function loadRuntime(cb) {
        get('ai/runtime', {}, function (data) {
            state.runtime = data.status === 'ok' ? data : null;
            cb(state.runtime);
        });
    }

    function loadSettings(cb) {
        get('settings/get', {}, function (data) {
            if (data && data.policyanalyzer) {
                state.settings = data;
                state.saved = flatten({policyanalyzer: data.policyanalyzer});
                if (state.choice.provider === null) {
                    const provider = state.saved['policyanalyzer.ai.provider'] || 'none';
                    state.choice.provider = provider === 'none' ? null : provider;
                    state.choice.location = state.saved['policyanalyzer.ollama.location'] || 'local';
                }
                if (state.model === null && state.saved['policyanalyzer.ollama.model']) {
                    state.model = state.saved['policyanalyzer.ollama.model'];
                }
            }
            cb(state.settings);
        });
    }

    function loadProviders(cb) {
        if (state.providers) {
            return cb(state.providers);
        }
        get('ai/providers', {}, function (data) {
            state.providers = data && data.providers ? data : {providers: [], groups: {}};
            cb(state.providers);
        });
    }

    function loadAiStatus(cb) {
        get('ai/status', {}, function (data) {
            state.aiStatus = data.status === 'ok' ? data : {enabled: false};
            cb(state.aiStatus);
        });
    }

    function provider(id) {
        return ((state.providers || {}).providers || []).find(function (p) { return p.id === id; }) || null;
    }

    /******************************************************************************************************
     * stepper, footer, navigation
     ******************************************************************************************************/
    function stepTitle(id) {
        return S['step_' + id] || id;
    }

    function renderStepper() {
        if (!state.root) {
            return;
        }
        const ol = $('#pa_steps').empty();
        const local = isLocal() || state.choice.provider === null;
        STEPS.forEach(function (step, idx) {
            const li = $('<li/>').attr('tabindex', 0).attr('role', 'button');
            li.toggleClass('active', idx === state.current);
            li.toggleClass('done', !!state.done[step.id] && idx !== state.current);
            li.toggleClass('skipped', !local && LOCAL_STEPS.includes(step.id));
            li.append($('<span class="pa-step-num"/>').html(state.done[step.id] && idx !== state.current ?
                '<span class="fa fa-check"></span>' : String(idx + 1)));
            li.append($('<span class="pa-step-label"/>').text(stepTitle(step.id)));
            li.attr('title', stepTitle(step.id));
            li.on('click keypress', function (e) {
                if (e.type === 'click' || e.key === 'Enter' || e.key === ' ') {
                    go(idx);
                }
            });
            ol.append(li);
        });
        $('#pa_steps_current').text(S.stepOf.replace('%n', state.current + 1)
            .replace('%t', STEPS.length) + ': ' + stepTitle(STEPS[state.current].id));
    }

    /**
     * @param opts {back, skip, next, simulate, apply, undo: [actions], nextLabel, applyLabel, nextDisabled}
     */
    function footer(opts) {
        opts = opts || {};
        if (!state.root) {
            return;
        }
        const box = $('#pa_footer').empty();
        const secondary = $('<div class="pa-footer-secondary"/>');
        const primary = $('<div class="pa-footer-primary"/>');
        if (opts.back !== false && state.current > 0) {
            secondary.append(btn(S.back, 'btn-default', function () { back(); }, 'fa-chevron-left'));
        }
        if (opts.skip) {
            secondary.append(btn(S.skip, 'btn-default', function () { next(true); }));
        }
        if (opts.undo && opts.undo.length) {
            secondary.append(btn(S.undo, 'btn-default', function () { showHistory(opts.undo); }, 'fa-undo'));
        }
        if (opts.simulate) {
            primary.append(btn(opts.simulateLabel || S.simulate, 'btn-default', opts.simulate, 'fa-eye'));
        }
        if (opts.apply) {
            primary.append(btn(opts.applyLabel || S.apply, 'btn-primary', opts.apply, 'fa-play'));
        }
        if (opts.next !== false && state.current < STEPS.length - 1) {
            const n = btn(opts.nextLabel || (S.next + ': ' + stepTitle(STEPS[nextTarget()].id)), opts.apply ? 'btn-default' : 'btn-primary', function () { next(false); });
            n.append(' <span class="fa fa-chevron-right"></span>');
            n.prop('disabled', !!opts.nextDisabled);
            if (opts.nextDisabled && opts.nextReason) {
                /* a disabled button shows no tooltip: the reason is on a wrapper */
                primary.append($('<span class="pa-next-wrap"/>').attr('title', opts.nextReason).append(n));
            } else {
                primary.append(n);
            }
        }
        box.append(secondary).append('<span class="pa-footer-spacer"></span>').append(primary);
        columns();
    }

    /**
     * two columns on wide screens (CSS): the description and the detected state on the left, the action of the step
     * on the right, so a step fits the dialog without scrolling. Runs once per step, when its renderer has built it
     * (every renderer ends with footer()); elements with .pa-left also go to the left column.
     */
    function columns() {
        const box = state.root && state.root.find('#pa_step');
        if (!box || !box.length || box.children('.pa-cols').length || !box.children('.pa-state').length) {
            return;
        }
        const left = $('<div class="pa-col-left"/>');
        const right = $('<div class="pa-col-right"/>');
        box.children().not('h2').each(function () {
            ($(this).is('.pa-step-help, .pa-state, .pa-left') ? left : right).append(this);
        });
        box.append($('<div class="pa-cols"/>').append(left, right));
    }

    function nextTarget() {
        const id = STEPS[state.current].id;
        if (id === 'provider' && !isLocal()) {
            return stepIndex('finish');
        }
        return Math.min(state.current + 1, STEPS.length - 1);
    }

    function go(idx) {
        if (!state.root) {
            return;
        }
        idx = Math.max(0, Math.min(STEPS.length - 1, idx));
        state.current = idx;
        if (history.replaceState) {
            history.replaceState(null, null, '#setup-' + (idx + 1));
        }
        renderStepper();
        const box = state.root.find('#pa_step').empty();
        box.append($('<h2/>').text((idx + 1) + '. ' + stepTitle(STEPS[idx].id)));
        box.append(spinner());
        footer({});
        RENDER[STEPS[idx].id](box);
        const modal = state.root.closest('.modal');
        if (modal.length) {
            modal.scrollTop(0);
        }
    }

    function next(skipped) {
        const id = STEPS[state.current].id;
        if (id === 'provider' && !isLocal()) {
            return go(stepIndex('finish'));             // LAN server or API: nothing to install here
        }
        if (skipped) {
            state.done[id] = state.done[id] || false;
        }
        go(state.current + 1);
    }

    function back() {
        const id = STEPS[state.current].id;
        if (id === 'finish' && !isLocal()) {
            return go(stepIndex('provider'));
        }
        go(state.current - 1);
    }

    function refresh() {
        go(state.current);
    }

    /******************************************************************************************************
     * background job banner (a job started here or elsewhere, e.g. the Settings tab)
     ******************************************************************************************************/
    function watchJobBanner() {
        clearTimeout(state.jobTimer);
        get('ai/job', {}, function (data) {
            const job = data && data.job;
            if (!state.root) {
                return;
            }
            const box = state.root.find('#pa_job').empty().hide();
            if (PASimulation.isActive(job)) {
                box.show().append(label('info', S.jobRunning)).append(PASimulation.renderJob(job))
                    .append(btn(S.cancel, 'btn-warning', function () { PASimulation.cancelJob(watchJobBanner); }));
                state.jobTimer = setTimeout(watchJobBanner, 3000);
                state.jobWasActive = true;
            } else if (state.jobWasActive) {
                // a job followed by this banner just ended (e.g. a model download started on another page or before
                // a reload): render the step again so lists such as the installed models show the result
                state.jobWasActive = false;
                refresh();
            }
        });
    }

    function afterChange() {
        watchJobBanner();
        refresh();
    }

    /******************************************************************************************************
     * action history filtered on the actions of a step (Undo)
     ******************************************************************************************************/
    function showHistory(actions) {
        get('change/history', {}, function (data) {
            const items = ((data && data.items) || []).filter(function (item) {
                return actions.includes(item.action);
            });
            const body = $('<div/>');
            body.append($('<p class="text-muted"/>').append($('<small/>').text(S.undoHelp)));
            if (!items.length) {
                body.append(alert('info', esc(S.undoEmpty)));
            }
            const list = $('<div class="pa-cards"/>');
            items.forEach(function (item) {
                const card = $('<div class="pa-card-item"/>');
                card.append($('<div class="pa-card-title"/>').text(item.description || item.action));
                card.append($('<div class="pa-card-meta text-muted"/>').html(esc(item.ts || item.id) + ' — ' +
                    esc(item.status) + (item.reverted ? ' ' + label('default', S.reverted + ' ' + (item.reverted.ts || '')) : '')));
                if ((item.summary || []).length) {
                    card.append($('<div class="pa-card-meta"/>').html(item.summary.map(esc).join('<br/>')));
                }
                if (item.revertible) {
                    card.append($('<div class="pa-card-actions"/>').append(btn(S.revert, 'btn-default', function () {
                        revertEntry(item, afterChange);
                    }, 'fa-undo')));
                }
                list.append(card);
            });
            body.append(list);
            body.append($('<p/>').append($('<a/>').attr('href', '/ui/policyanalyzer/#history').text(S.undoFull)));
            PASimulation.dialog({title: S.undo, message: body, size: BootstrapDialog.SIZE_WIDE,
                buttons: [{label: S.close, action: function (d) { d.close(); }}]});
        });
    }

    /******************************************************************************************************
     * step 1: check (read only)
     ******************************************************************************************************/
    function classify(hw, rt) {
        const blockers = [], warnings = [], notes = [];
        const cpu = hw.cpu || {}, mem = hw.memory || {}, flags = cpu.flags || {}, services = hw.services || {};
        if (rt && rt.arch && rt.arch !== 'amd64') {
            blockers.push(S.chkArch + ': ' + rt.arch);
        }
        if (rt && rt.release && !/^15\./.test(rt.release)) {
            blockers.push(S.chkRelease + ': ' + rt.release);
        }
        const total = mem.total_bytes || 0;
        if (total && total < 8 * GB) {
            blockers.push(S.chkRamTooSmall + ' (' + gib(total) + ')');
        } else if (total && total < 12 * GB) {
            warnings.push(S.chkRamSmall + ' (' + gib(total) + ')');
        }
        const free = hw.models_free_bytes;
        if (free !== null && free !== undefined) {
            if (free < 4 * GIB) {
                blockers.push(S.chkDiskTooSmall + ' (' + gib(free) + ')');
            } else if (free < 10 * GIB) {
                warnings.push(S.chkDiskSmall + ' (' + gib(free) + ')');
            }
        }
        if (!flags.avx2) {
            warnings.push(S.chkNoAvx2);
        }
        if ((cpu.threads || 0) < 4) {
            warnings.push(S.chkFewCores + ' (' + (cpu.threads || '?') + ')');
        }
        const load1 = (hw.load || [0])[0];
        if (load1 > 1.5) {
            warnings.push(S.chkLoad + ' (' + load1 + ')');
        }
        const sur = services.suricata || {};
        if (sur.ips && sur.running !== false && sur.enabled !== false) {
            warnings.push(S.chkIps);
        }
        Object.keys(services).forEach(function (name) {
            const svc = services[name];
            if (svc.running === true && !(name === 'suricata' && sur.ips)) {
                warnings.push(S.chkHeavy + ': ' + name);
            }
        });
        (hw.gpus || []).forEach(function (g) {
            if (g.integrated) {
                notes.push(S.chkIgpu + (g.name ? ' (' + g.name + ')' : ''));
            }
        });
        return {verdict: blockers.length ? 'no' : (warnings.length ? 'reservations' : 'fit'),
                blockers: blockers, warnings: warnings, notes: notes};
    }

    function renderCheck(box) {
        let pending = 2;
        let hw = null;
        const done = function () {
            if (--pending > 0) {
                return;
            }
            box.find('p:has(.fa-spinner)').remove();
            const rt = state.runtime;
            if (!hw) {
                box.append(alert('danger', esc(S.probeFailed)));
                footer({next: true, skip: false});
                return;
            }
            const cpu = hw.cpu || {}, mem = hw.memory || {}, flags = cpu.flags || {}, services = hw.services || {};
            const product = hw.product || {};
            const flagList = ['avx2', 'avx512', 'avx_vnni', 'amx', 'fma', 'f16c'].map(function (f) {
                return label(flags[f] ? 'success' : 'default', f.toUpperCase().replace('_', '-'));
            }).join(' ');
            const svcList = Object.keys(services).map(function (name) {
                const svc = services[name];
                let txt = name;
                if (name === 'suricata' && svc.running !== false && svc.installed) {
                    txt += ' (' + (svc.ips ? 'IPS' : 'IDS') + ')';
                }
                const cls = svc.running === true ? 'warning' : (svc.running === 'unknown' ? 'default' : 'default');
                return label(cls, txt + ': ' + (svc.running === true ? S.running : (svc.running === 'unknown' ?
                    S.unknown : S.notRunning)));
            }).join(' ');
            const rows = [
                [S.chkProduct, (product.name || 'OPNsense') + ' ' + (product.version || '?') +
                    (rt && rt.release ? ' — FreeBSD ' + rt.release + ' ' + (rt.arch || '') : '')],
                [S.chkCpu, (cpu.model || '?') + ' — ' + (cpu.cores || '?') + ' ' + S.cores + ', ' + (cpu.threads || '?') + ' ' + S.threads],
                [S.chkFlags, flagList, 'html'],
                [S.chkRam, gib(mem.total_bytes) + ' ' + S.total + ', ' + gib(mem.available_bytes) + ' ' + S.available +
                    (mem.arc_bytes ? ' (ARC ' + gib(mem.arc_bytes) + ')' : '')],
                [S.chkDisk, gib(hw.models_free_bytes) + ' ' + S.freeFor + ' ' + (state.saved['policyanalyzer.ollama.models_dir'] || '/var/db/ai/models') +
                    (rt && rt.ai_dataset ? ' (' + rt.ai_dataset + ')' : '')],
                [S.chkLoadAvg, (hw.load || []).join(' / ') || '?'],
                [S.chkServices, svcList || esc(S.none), 'html'],
                [S.chkRacct, rt ? (racctState(rt).on ? S.enabled : (racctState(rt).pending ? S.racctPendingShort : S.disabled)) : S.unknown]
            ];
            box.append(stateBox(S.currentState, facts(rows)));
            const c = classify(hw, rt);
            const cls = {fit: 'success', reservations: 'warning', no: 'danger'}[c.verdict];
            const v = $('<div class="alert alert-' + cls + ' pa-verdict"/>');
            v.append($('<b/>').text(S['verdict_' + c.verdict]));
            const items = c.blockers.concat(c.warnings);
            if (items.length) {
                v.append('<ul>' + items.map(function (i) { return '<li>' + esc(i) + '</li>'; }).join('') + '</ul>');
            }
            if (c.verdict === 'fit') {
                v.append($('<div/>').text(S.verdictFitHelp));
            } else if (c.verdict === 'no') {
                v.append($('<div/>').text(S.verdictNoHelp));
            } else {
                v.append($('<div/>').text(S.verdictResHelp));
            }
            box.append(v);
            if (c.notes.length) {
                box.append($('<ul class="text-muted"/>').html(c.notes.map(function (n) {
                    return '<li>' + esc(n) + '</li>';
                }).join('')));
            }
            /* RAM limit off: the notice brings its button (enable_racct) or the reboot link */
            const racctSlot = $('<div/>');
            box.append(racctSlot);
            racctNotice(rt, function (notice) {
                if (notice) {
                    racctSlot.append(notice);
                }
            });
            box.append($('<p class="text-muted"/>').append($('<small/>').text(S.readOnlyStep)));
            state.done.check = true;
            renderStepper();
            footer({next: true});
        };
        get('setup/hwprofile', {}, function (data) {
            hw = data && data.status === 'ok' ? data : null;
            state.hw = hw;
            done();
        });
        loadRuntime(done);
    }

    /******************************************************************************************************
     * step 2: provider (cards as in Settings)
     ******************************************************************************************************/
    function choiceCard(value, icon, text, help, groupLabel, badge) {
        /* a choice may carry its own badge (e.g. "LAN" for Claude Code), shown instead of the group label */
        return $('<label class="panel panel-default pa-choice"/>').attr('data-value', value).html(
            '<input type="radio" name="pa_choice" value="' + esc(value) + '">' +
            '<span class="pa-choice-icon fa fa-fw ' + esc(icon) + '" aria-hidden="true"></span>' +
            '<span class="pa-choice-text"><span class="pa-choice-name">' + esc(text) + '</span>' +
            (badge ? ' <span class="label label-info pa-choice-group">' + esc(badge) + '</span>' :
                (groupLabel ? ' <span class="label label-default pa-choice-group">' + esc(groupLabel) + '</span>' : '')) +
            (help ? '<span class="pa-choice-desc text-muted">' + esc(help) + '</span>' : '') + '</span>');
    }

    function renderProvider(box) {
        loadSettings(function () {
            loadProviders(function (reg) {
                box.find('p:has(.fa-spinner)').remove();
                box.append($('<p class="pa-step-help"/>').text(S.providerHelp));
                const current = state.saved['policyanalyzer.ai.provider'] || 'none';
                const enabled = state.saved['policyanalyzer.ai.enabled'] === '1';
                box.append(stateBox(S.currentState, facts([
                    [S.aiState, enabled && current !== 'none' ? S.enabledWith + ' ' + current : S.disabled],
                    [S.savedProvider, current === 'none' ? S.none : current +
                        (current === 'ollama' ? ' (' + (state.saved['policyanalyzer.ollama.location'] || 'local') + ')' : '')]
                ])));
                const chooser = $('<div class="pa-choices" role="radiogroup"/>').attr('aria-label', S.step_provider);
                const groups = reg.groups || {local: S.local, api: S.api};
                Object.keys(groups).forEach(function (group) {
                    const items = [];
                    (reg.providers || []).forEach(function (p) {
                        (p.choices || []).forEach(function (c) {
                            if ((c.group || p.group) === group) {
                                items.push({provider: p, choice: c});
                            }
                        });
                    });
                    if (!items.length) {
                        return;
                    }
                    const title = group === 'local' ? S.local : (group === 'api' ? S.api : groups[group]);
                    chooser.append($('<h5 class="pa-choice-header"/>').text(title));
                    items.forEach(function (it) {
                        chooser.append(choiceCard(it.provider.id, it.choice.icon || (group === 'api' ? 'fa-cloud' : 'fa-server'),
                            it.choice.label, it.choice.help, title, it.choice.badge));
                    });
                });
                box.append(chooser);
                const sub = $('<div id="pa_provider_sub"/>');
                box.append(sub);
                const privacy = $('<div class="alert" style="display:none"/>');
                box.append(privacy);

                const mark = function () {
                    chooser.find('.pa-choice').each(function () {
                        const on = $(this).data('value') === state.choice.provider;
                        $(this).toggleClass('panel-primary pa-choice-selected', on).toggleClass('panel-default', !on);
                        $(this).find('input').prop('checked', on);
                    });
                    sub.empty();
                    privacy.hide();
                    const p = provider(state.choice.provider);
                    if (!p) {
                        footer({nextDisabled: true});
                        return;
                    }
                    privacy.show().toggleClass('alert-warning', leavesNetwork(p)).toggleClass('alert-info', !leavesNetwork(p))
                        .text(p.privacy || '');
                    (p.fields || []).forEach(function (field) {
                        if (field.type !== 'choice') {
                            return;
                        }
                        sub.append($('<h5/>').text(field.label));
                        const seg = $('<div class="pa-segment" role="radiogroup"/>').attr('aria-label', field.label);
                        $.each(field.options || {}, function (k, text) {
                            const opt = $('<label class="pa-segment-option panel"/>');
                            const radio = $('<input type="radio"/>').attr('name', 'pa_seg_' + field.id).val(k)
                                .prop('checked', k === state.choice[field.id]);
                            opt.append(radio).append($('<span class="pa-segment-label"/>').text(text));
                            if (field.option_help && field.option_help[k]) {
                                opt.append($('<span class="pa-segment-desc text-muted"/>').text(field.option_help[k]));
                            }
                            opt.toggleClass('active panel-primary', k === state.choice[field.id])
                                .toggleClass('panel-default', k !== state.choice[field.id]);
                            radio.on('change', function () {
                                state.choice[field.id] = k;
                                mark();
                            });
                            seg.append(opt);
                        });
                        sub.append(seg);
                    });
                    const local = isLocal();
                    sub.append($('<p class="text-muted"/>').append($('<small/>').text(local ? S.providerLocalNext : S.providerRemoteNext)));
                    renderStepper();
                    footer({next: true, nextLabel: local ? null : S.goToFinish, undo: ['settings']});
                };
                chooser.find('input[name=pa_choice]').change(function () {
                    state.choice.provider = $(this).val();
                    if (state.choice.provider === 'ollama' && !state.choice.location) {
                        state.choice.location = 'local';
                    }
                    mark();
                });
                mark();
                state.done.provider = !!state.choice.provider;
            });
        });
    }

    /******************************************************************************************************
     * step 3: storage
     ******************************************************************************************************/
    function renderStorage(box) {
        loadSettings(function () {
            const path = state.saved['policyanalyzer.ollama.models_dir'] || '/var/db/ai/models';
            get('ai/storage', {}, function (data) {
                box.find('p:has(.fa-spinner)').remove();
                box.append($('<p class="pa-step-help"/>').text(S.storageHelp));
                if (data.status !== 'ok') {
                    box.append(alert('danger', esc(data.message || S.probeFailed)));
                    footer({skip: true, undo: ['prepare_storage']});
                    return;
                }
                state.storage = data;
                const ready = data.exists && data.writable !== false;
                const rows = [
                    [S.modelsDir, path],
                    [S.storageState, data.exists ? (data.writable === false ? S.notWritable : S.exists) : S.missing],
                    [S.dataset, data.dataset || (data.mountpoint ? data.mountpoint + ' (' + (data.fstype || '?') + ')' : null)],
                    [S.freeSpace, gib(data.free_bytes) + (data.local === false ? ' — ' + S.notLocal : '')]
                ];
                box.append(stateBox(S.currentState, facts(rows)));
                if (ready) {
                    box.append(alert('success', esc(S.storageReady)));
                    state.done.storage = true;
                } else {
                    box.append(alert('info', esc(S.storagePlanHelp)));
                    state.done.storage = false;
                }
                box.append($('<p class="text-muted"/>').append($('<small/>').text(S.storageDirHint + ' '))
                    .append(btn(S.openSettings, 'btn-default btn-xs', openSettingsTab, 'fa-cog')));
                renderStepper();
                const run = function (readOnly) {
                    const opts = {action: 'prepare_storage', args: [], title: S.prepareStorage, plainRevert: S.plainRevertStorage,
                                  onDone: afterChange};
                    readOnly ? PASimulation.simulate(opts) : PASimulation.run(opts);
                };
                footer({
                    skip: !ready,
                    undo: ['prepare_storage'],
                    simulate: function () { run(true); },
                    simulateLabel: S.simulatePrepare,
                    apply: ready ? null : function () { run(false); },
                    applyLabel: S.prepareStorage,
                    nextDisabled: !ready, nextReason: S.reasonStorageFirst
                });
            });
        });
    }

    /******************************************************************************************************
     * step 4: runtime (jail)
     ******************************************************************************************************/
    function runtimeRows(rt) {
        const limits = rt.limits || {};
        const rows = [
            [S.runtimeState, rt.installed ? (rt.running ? S.runtimeRunning : S.runtimeStopped) : S.runtimeMissing],
            [S.ollamaVersion, rt.version ? rt.version + (rt.version_ok === false ? ' — ' + S.versionOld : '') : null],
            [S.bootState, rt.installed ? (rt.boot_enabled ? S.enabled : S.disabled) : null],
            [S.jailDataset, rt.jail_dataset ? rt.jail_dataset + (rt.jail_dataset_exists ? '' : ' (' + S.missing + ')') : null],
            [S.freeSpace, gib(rt.free_bytes)],
            [S.modelsInstalled, (rt.models || []).length ? rt.models.map(function (m) { return m.name; }).join(', ') : S.none],
            [S.limits, limits.threads ? 'cpuset ' + (limits.cpus || '?') + ', ' + limits.threads + ' ' + S.threads + ', ctx ' +
                (limits.ctx || '?') + ', nice ' + (limits.nice === undefined ? '?' : limits.nice) : S.notSet]
        ];
        return rows;
    }

    /**
     * what the probes say about an unfinished runtime: a job running now, an install that stopped half way (files of
     * the jail without ollama), a jail that is installed but stopped
     * @return {kind: 'running'|'partial'|'failed'|'stopped'|null, job}
     */
    function runtimeCondition(rt) {
        const job = (rt && rt.job) || null;
        if (job && PASimulation.isActive(job)) {
            return {kind: 'running', job: job};
        }
        if (rt && !rt.installed && (rt.base_extracted || rt.jail_dataset_exists || rt.jail_conf)) {
            return {kind: 'partial', job: job};
        }
        if (rt && !rt.installed && job && job.action === 'install_runtime' && ['failed', 'cancelled', 'error'].includes(job.status)) {
            return {kind: 'failed', job: job};
        }
        if (rt && rt.installed && !rt.running) {
            return {kind: 'stopped', job: job};
        }
        return {kind: null, job: job};
    }

    function jobMessage(job) {
        const r = (job && job.result) || {};
        return r.message || (job && job.message) || '';
    }

    function renderRuntime(box) {
        loadRuntime(function (rt) {
            box.find('p:has(.fa-spinner)').remove();
            box.append($('<p class="pa-step-help"/>').text(S.runtimeHelp));
            if (!rt) {
                box.append(alert('danger', esc(S.runtimeUnknown)));
                footer({skip: true, undo: STEPS[stepIndex('runtime')].actions});
                return;
            }
            box.append(stateBox(S.currentState, facts(runtimeRows(rt))));
            if (rt.warning) {
                box.append(alert('danger', esc(rt.warning)).addClass('pa-left'));
            }
            if (rt.api === 'not answering') {
                box.append(alert('warning', esc(S.apiNotAnswering)).addClass('pa-left'));
            }
            /* warnings of the probe that something resolves: each one with its button or link */
            (rt.warning_actions || []).forEach(function (wa) {
                if (wa && typeof wa === 'object' && wa.warning) {
                    box.append(alert('warning', esc(wa.warning) + PASimulation.actionButton(wa)).addClass('pa-left pa-wa'));
                }
            });
            const undo = STEPS[stepIndex('runtime')].actions;
            const cond = runtimeCondition(rt);
            state.done.runtime = !!rt.installed;
            renderStepper();
            const plain = {install_runtime: S.plainRevertInstall, uninstall_runtime: S.plainRevertUninstall,
                           start_runtime: S.plainRevertService, stop_runtime: S.plainRevertService,
                           enable_runtime: S.plainRevertService, disable_runtime: S.plainRevertService};
            const simple = function (action, title, args) {
                return function () {
                    PASimulation.run({action: action, args: args || [], title: title, plainRevert: plain[action], onDone: afterChange});
                };
            };

            /* an unfinished state always comes with the action that resolves it */
            if (cond.kind === 'running') {
                box.append(alert('info', esc(S.condRunning)));
            } else if (cond.kind === 'partial' || cond.kind === 'failed') {
                const a = alert('warning', '<b>' + esc(cond.kind === 'partial' ? S.condPartial : S.condFailed) + '</b>' +
                    (jobMessage(cond.job) ? '<br/><small>' + esc(jobMessage(cond.job)) + '</small>' : ''));
                const acts = $('<div class="pa-actions"/>');
                acts.append(btn(S.resumeInstall, 'btn-primary', simple('install_runtime', S.resumeInstall,
                    [(rt.limits && rt.limits.branch) || 'quarterly']), 'fa-play'));
                if (cond.kind === 'partial') {
                    acts.append(btn(S.cleanupPartial, 'btn-default', simple('uninstall_runtime', S.cleanupPartial), 'fa-eraser'));
                }
                box.append(a.append(acts));
            } else if (cond.kind === 'stopped') {
                box.append(alert('warning', esc(S.condStopped)).append($('<div class="pa-actions"/>')
                    .append(btn(S.startRuntime, 'btn-primary', simple('start_runtime', S.startRuntime), 'fa-play'))));
            }

            if (!rt.installed) {
                const form = $('<div class="pa-form"/>');
                const defaults = Object.assign({}, DEFAULT_LIMITS, rt.limits || {});
                form.append($('<h4/>').text(S.installOptions));
                const branch = $('<select class="form-control"/>');
                branch.append($('<option value="quarterly"/>').text(S.branchQuarterly));
                branch.append($('<option value="latest"/>').text(S.branchLatest));
                const cpus = $('<input type="text" class="form-control" autocomplete="off"/>').val(defaults.cpus);
                form.append($('<div class="pa-inline"/>')
                    .append(formGroup('pa_branch', S.branch, branch, S.branchHelp))
                    .append(formGroup('pa_cpus', S.cpuset, cpus, S.cpusetHelp.replace('%n', (state.hw && state.hw.cpu && state.hw.cpu.threads) || '?'))));
                form.append($('<div class="pa-inline pa-checks"/>')
                    .append(checkbox('pa_start', S.startNow, true))
                    .append(checkbox('pa_boot', S.startAtBoot, true)));
                box.append(form);
                box.append($('<p class="text-muted"/>').append($('<small/>').text(S.installWhat)));
                const args = function () {
                    const list = [branch.val()];
                    const cs = cpus.val().trim();
                    if (!CPUSET_RE.test(cs)) {
                        PASimulation.dialog({type: BootstrapDialog.TYPE_WARNING, title: S.cpuset, message: esc(S.cpusetInvalid)});
                        return null;
                    }
                    if (cs !== defaults.cpus) {
                        list.push(cs.replace(/,/g, '_'));
                    }
                    if (!form.find('#pa_start').prop('checked')) {
                        list.push('+no_start');
                    }
                    if (!form.find('#pa_boot').prop('checked')) {
                        list.push('+no_boot');
                    }
                    if (list.length > 3) {
                        /* configd takes 3 arguments: the cpuset is then applied in the Limits step */
                        list.splice(1, 1);
                        PASimulation.dialog({type: BootstrapDialog.TYPE_INFO, title: S.cpuset, message: esc(S.cpusetLater)});
                    }
                    return list;
                };
                const run = function (readOnly) {
                    const a = args();
                    if (a === null) {
                        return;
                    }
                    const opts = {action: 'install_runtime', args: a, title: S.installRuntime, plainRevert: S.plainRevertInstall,
                                  onDone: afterChange};
                    readOnly ? PASimulation.simulate(opts) : PASimulation.run(opts);
                };
                footer({skip: true, undo: undo, simulate: function () { run(true); }, simulateLabel: S.simulateInstall,
                        apply: cond.kind === 'running' ? null : function () { run(false); }, applyLabel: S.applyInstall,
                        nextDisabled: true, nextReason: S.reasonInstallFirst});
                return;
            }

            /* installed: service controls and "Remove local AI", each one simulated before Apply */
            const actions = $('<div class="pa-actions"/>');
            if (rt.running) {
                actions.append(btn(S.stopRuntime, 'btn-default', simple('stop_runtime', S.stopRuntime), 'fa-stop'));
            } else if (cond.kind !== 'stopped') {
                actions.append(btn(S.startRuntime, 'btn-primary', simple('start_runtime', S.startRuntime), 'fa-play'));
            }
            if (rt.boot_enabled) {
                actions.append(btn(S.disableBoot, 'btn-default', simple('disable_runtime', S.disableBoot), 'fa-power-off'));
            } else {
                actions.append(btn(S.enableBoot, 'btn-default', simple('enable_runtime', S.enableBoot), 'fa-power-off'));
            }
            actions.append(btn(S.removeLocalAi, 'btn-default', function () { removeLocalAi({onDone: afterChange}); }, 'fa-trash'));
            box.append($('<h4/>').text(S.runtimeControls)).append(actions);
            box.append($('<p class="text-muted"/>').append($('<small/>').text(S.removeLocalAiHelp)));
            footer({undo: undo, next: true});
        });
    }

    /**
     * Revert of an action history entry; the install of the runtime goes through "Remove local AI" (one choice:
     * delete the downloaded models too), everything else through the plain revert simulation
     */
    function revertEntry(item, onDone) {
        if (item.action === 'install_runtime') {
            return removeLocalAi({entry: item, onDone: onDone});
        }
        PASimulation.run({action: 'revert', args: [item.id], title: S.revert + ': ' + (item.description || item.action),
            plainRevert: S.plainRevertRevert, onDone: onDone});
    }

    /******************************************************************************************************
     * shared: actions offered by the backend, RAM limit (racct), removal of the local AI
     ******************************************************************************************************/
    function loadActions(cb) {
        if (state.actions) {
            return cb(state.actions);
        }
        get('change/actions', {}, function (data) {
            state.actions = ((data && data.actions) || []).map(function (a) { return a.name; });
            cb(state.actions);
        });
    }

    function hasAction(name) {
        return (state.actions || []).includes(name);
    }

    /**
     * RAM limit of the jail needs kern.racct.enable=1 (tunable, effective after a reboot): the warning comes with the
     * button that sets it (enable_racct, when the backend offers it) and, once set, with the link to reboot
     * @param cb function ($element or null)
     */
    /**
     * status_runtime.racct: {enabled_now, pending_reboot, configured, in_loader_conf, tunables_url, reboot_url}
     * (older setup components: a boolean)
     */
    function racctState(rt) {
        const r = rt ? rt.racct : null;
        if (r !== null && typeof r === 'object') {
            return {on: !!r.enabled_now, pending: !!r.pending_reboot && !r.enabled_now, known: true,
                    reboot: /^\/ui\/[A-Za-z0-9_\/#.-]*$/.test(r.reboot_url || '') ? r.reboot_url : '/ui/core/reboot'};
        }
        return {on: r === true, pending: false, known: r === true || r === false, reboot: '/ui/core/reboot'};
    }

    function racctNotice(rt, cb) {
        const rs = racctState(rt);
        if (!rt || !rs.known || rs.on) {
            return cb(null);
        }
        loadActions(function () {
            get('change/history', {}, function (h) {
                /* pending reboot: from the probe, or (older probe) from an applied enable_racct in the journal */
                const pending = rs.pending || ((h && h.items) || []).some(function (i) {
                    return i.action === 'enable_racct' && !i.reverted && i.status !== 'error';
                });
                const box = $('<div class="alert alert-warning pa-racct"/>');
                if (pending) {
                    box.append($('<span/>').text(S.racctPending + ' '))
                        .append($('<a class="btn btn-default btn-xs"/>').attr('href', rs.reboot).text(S.rebootLink));
                } else {
                    box.append($('<span/>').text(S.racctOff + ' '));
                    if (hasAction('enable_racct')) {
                        box.append(btn(S.enableRamLimit, 'btn-default btn-xs', function () {
                            PASimulation.run({action: 'enable_racct', args: [], title: S.enableRamLimit,
                                plainRevert: S.plainRevertRacct, onDone: afterChange});
                        }, 'fa-memory'));
                    } else {
                        box.append($('<small class="text-muted"/>').text(S.racctManual));
                    }
                }
                cb(box, pending);
            });
        });
    }

    function modelOf(item) {
        const a = item && item.args;
        if (a && typeof a === 'object' && !Array.isArray(a)) {
            return a.model || (a.args && a.args.model) || null;
        }
        return Array.isArray(a) ? a[0] : null;
    }

    /**
     * "Remove local AI": the revert of the install (one click, back to how the firewall was), with one choice:
     * also delete the models downloaded since (keep_models=no). Without an install entry in the journal (installed
     * before the journal existed) it falls back to uninstall_runtime, where the choice destroys the models dataset.
     * @param opts {entry: history item of install_runtime (optional), onDone}
     */
    function removeLocalAi(opts) {
        opts = opts || {};
        get('change/history', {}, function (h) {
            const items = (h && h.items) || [];
            const entry = opts.entry || items.find(function (i) {
                return i.action === 'install_runtime' && i.revertible && !i.reverted;
            });
            get('ai/runtime', {}, function (rt) {
                const models = (rt && rt.models) || [];
                let names, flags, action, args, plain;
                if (entry) {
                    names = items.filter(function (i) {
                        return i.action === 'pull_model' && !i.reverted && i.id > entry.id;
                    }).map(modelOf).filter(function (n) { return n; });
                    action = 'revert';
                    args = [entry.id];
                    flags = ['keep_models=no'];
                    plain = S.plainRevertRemove;
                } else {
                    names = models.map(function (m) { return m.name; });
                    action = 'uninstall_runtime';
                    args = [];
                    flags = rt && rt.ai_dataset ? ['+remove_dataset', rt.ai_dataset] : [];
                    plain = S.plainRevertUninstall;
                }
                const bytes = models.filter(function (m) { return names.includes(m.name); })
                    .reduce(function (t, m) { return t + (m.size || 0); }, 0);
                const choice = names.length && flags.length ? {
                    label: S.deleteModels.replace('%s', gib(bytes)) + ': ' + names.join(', '),
                    flags: flags, checked: false} : null;
                PASimulation.run({action: action, args: args, title: S.removeLocalAi, plainRevert: plain, choice: choice,
                    onDone: function () {
                        if (opts.onDone) {
                            opts.onDone();
                        }
                    }});
            });
        });
    }

    /******************************************************************************************************
     * step 5: model
     ******************************************************************************************************/
    /* flags of pull_model for a recommended model: the candidate brings its action (pull_model [model, +large]);
     * older probes: from the size */
    function modelFlags(name) {
        const cand = (((state.recommend || {}).candidates) || []).find(function (c) { return c.model === name; }) || {};
        if (cand.action && cand.action.id === 'pull_model' && Array.isArray(cand.action.args)) {
            return cand.action.args.filter(function (a) { return a !== name && /^\+[a-z_]+$/.test(a); });
        }
        return cand.size_gb && cand.size_gb * GB > 6 * GIB ? ['+large'] : [];
    }

    function pullModel(name, flags, readOnly) {
        const args = [name].concat(flags || []);
        const opts = {action: 'pull_model', args: args, title: S.pullModel + ' ' + name, plainRevert: S.plainRevertModel,
            onDone: function () {
            state.model = name;
            afterChange();
        }};
        readOnly ? PASimulation.simulate(opts) : PASimulation.run(opts);
    }

    /**
     * "Import a GGUF model": a .gguf copied with scp to /var/db/ai/models/import/ (SHA-256 required) or downloaded
     * from Hugging Face (hf:owner/repo/file.gguf[@revision], SHA-256 of the LFS object read from the API); the
     * Modelfile gets the chat template chosen here. Simulated first like every change (action import_gguf).
     */
    function importBox(onDone) {
        const t = function (key, fallback) { return S[key] || fallback; };
        const box = $('<details class="pa-left pa-import-gguf"/>');
        box.append($('<summary/>').append($('<b/>').text(t('importTitle', 'Import a GGUF model'))));
        box.append($('<p class="pa-step-help"/>').text(t('importHelp', 'Copy the .gguf file to ' +
            '/var/db/ai/models/import/ with scp (or give hf:owner/repo/file.gguf to download it from Hugging Face), ' +
            'then simulate the import. Ollama keeps its own copy of the weights.')));
        const form = $('<form class="pa-import-form" autocomplete="off"/>');
        const field = function (id, label, input) {
            return $('<div class="form-group"/>').append($('<label/>').attr('for', id).text(label)).append(input.attr('id', id));
        };
        const src = $('<input type="text" class="form-control" maxlength="250"/>')
            .attr('placeholder', 'foundation-sec-8b-instruct-q4_k_m.gguf');
        const name = $('<input type="text" class="form-control" maxlength="120"/>').attr('placeholder', 'foundation-sec:8b');
        const sha = $('<input type="text" class="form-control" maxlength="64" spellcheck="false"/>')
            .attr('placeholder', 'sha256 (64 hex)');
        const tpl = $('<select class="form-control"/>');
        [['foundation-sec', 'Foundation-Sec-8B (Cisco)'], ['llama3', 'Llama 3.x'], ['chatml', 'ChatML / Qwen'], ['gguf', t('importTplGguf', 'embedded in the file')]]
            .forEach(function (o) { tpl.append($('<option/>').val(o[0]).text(o[1])); });
        const cleanup = $('<input type="checkbox"/>');
        form.append(field('pa_gguf_src', t('importSource', 'File in the import directory or hf:owner/repo/file.gguf'), src));
        form.append(field('pa_gguf_name', t('importName', 'Model name (name:tag)'), name));
        form.append(field('pa_gguf_sha', t('importSha', 'SHA-256 (required for a local file)'), sha));
        form.append(field('pa_gguf_tpl', t('importTemplate', 'Chat template'), tpl));
        form.append($('<div class="checkbox"/>').append($('<label/>').append(cleanup)
            .append(' ' + esc(t('importCleanup', 'Delete the source file after the import (irreversible)')))));
        const go = $('<button type="submit" class="btn btn-primary"/>').html('<i class="fa fa-upload"></i> ' +
            esc(t('importSimulate', 'Simulate the import')));
        form.append(go);
        form.on('submit', function (e) {
            e.preventDefault();
            const args = [src.val().trim(), name.val().trim()];
            if (sha.val().trim()) {
                args.push('sha256=' + sha.val().trim().toLowerCase());
            }
            args.push('template=' + tpl.val());
            if (cleanup.prop('checked')) {
                args.push('+cleanup');
            }
            PASimulation.run({action: 'import_gguf', args: args, title: t('importTitle', 'Import a GGUF model'),
                onDone: function () {
                    state.model = name.val().trim() || state.model;
                    onDone();
                }});
        });
        box.append(form);
        return box;
    }

    function renderModel(box) {
        loadRuntime(function (rt) {
            box.find('p:has(.fa-spinner)').remove();
            box.append($('<p class="pa-step-help"/>').text(S.modelHelp));
            const installed = (rt && rt.models) || [];
            const names = installed.map(function (m) { return m.name; });
            if (state.model === null && names.length) {
                state.model = names[0];
            }
            const rows = [
                [S.runtimeState, rt ? (rt.installed ? (rt.running ? S.runtimeRunning : S.runtimeStopped) : S.runtimeMissing) : S.unknown],
                [S.modelsInstalled, names.length ? names.join(', ') : S.none],
                [S.freeSpace, rt ? gib(rt.free_bytes) : '?'],
                [S.chosenModel, state.model || S.none]
            ];
            box.append(stateBox(S.currentState, facts(rows)));
            if (rt && !rt.installed) {
                box.append(alert('warning', esc(S.modelNoRuntime) + ' ').append(goBtn('runtime')).addClass('pa-left'));
            }
            /* a download that stopped half way (cancelled, failed, firewall restarted): resume it, blobs already
             * verified are not downloaded again */
            const job = (rt && rt.job) || null;
            const jobArgs = (job && job.args) || {};
            const halfModel = job && job.action === 'pull_model' && ['failed', 'cancelled', 'error'].includes(job.status) &&
                jobArgs.model && !names.includes(jobArgs.model) ? jobArgs.model : null;
            if (halfModel) {
                const flags = [];
                if (jobArgs.custom === true || jobArgs.custom === 'yes') {
                    flags.push('+custom');
                }
                if (jobArgs.large === true || jobArgs.large === 'yes') {
                    flags.push('+large');
                }
                box.append(alert('warning', '<b>' + esc(S.condPull.replace('%s', halfModel)) + '</b>' +
                    (jobMessage(job) ? '<br/><small>' + esc(jobMessage(job)) + '</small>' : '') + ' ')
                    .append(btn(S.resumeDownload, 'btn-primary btn-xs', function () { pullModel(halfModel, flags, false); }, 'fa-download'))
                    .addClass('pa-left'));
            } else if (job && job.action === 'pull_model' && PASimulation.isActive(job)) {
                box.append(alert('info', esc(S.condRunning)));
            }

            /* installed models (manifests on disk; details from Ollama when it answers) */
            const list = $('<div class="pa-cards pa-left"/>');
            const renderInstalled = function (details) {
                list.empty();
                installed.forEach(function (m) {
                    const d = (details || []).find(function (x) { return x.name === m.name; }) || {};
                    const card = $('<div class="pa-card-item"/>').toggleClass('pa-selected', m.name === state.model);
                    card.append($('<div class="pa-card-title"/>').text(m.name)
                        .append(m.name === state.model ? ' ' + label('primary', S.chosen) : ''));
                    const meta = [];
                    if (m.size || d.size) {
                        meta.push(gib(m.size || d.size));
                    }
                    if (d.parameters) {
                        meta.push(d.parameters);
                    }
                    if (d.quantization) {
                        meta.push(d.quantization);
                    }
                    if ((rt.loaded || []).some(function (l) { return l.name === m.name; })) {
                        meta.push(S.loadedInRam);
                    }
                    card.append($('<div class="pa-card-meta text-muted"/>').text(meta.join(' · ')));
                    const acts = $('<div class="pa-card-actions"/>');
                    acts.append(btn(S.useModel, m.name === state.model ? 'btn-primary' : 'btn-default', function () {
                        state.model = m.name;
                        refresh();
                    }, 'fa-check'));
                    acts.append(btn(S.removeModel, 'btn-default', function () {
                        PASimulation.run({action: 'remove_model', args: [m.name], title: S.removeModel + ' ' + m.name,
                            onDone: function () {
                                if (state.model === m.name) {
                                    state.model = null;
                                }
                                afterChange();
                            }});
                    }, 'fa-trash'));
                    card.append(acts);
                    list.append(card);
                });
            };
            box.append($('<h4 class="pa-left"/>').text(S.modelsInstalled));
            if (!installed.length) {
                box.append($('<p class="text-muted pa-left"/>').text(S.noModelsYet));
            }
            box.append(list);
            renderInstalled([]);
            box.append(importBox(afterChange));
            const savedLocal = state.saved['policyanalyzer.ai.provider'] === 'ollama' &&
                (state.saved['policyanalyzer.ollama.location'] || 'local') === 'local';
            if (rt && rt.running && installed.length && savedLocal) {
                get('ai/models', {}, function (data) {
                    if (data.status === 'ok') {
                        renderInstalled(data.models || []);
                    }
                });
            }

            /* recommendation (shared block): the recommended model and three alternatives; everything else, the
             * notes and any other library model are behind "See all models" */
            const onUse = function (name) {
                if (allDialog) {
                    allDialog.close();
                }
                state.model = name;
                if (names.includes(name)) {
                    refresh();
                } else {
                    pullModel(name, modelFlags(name), false);
                }
            };
            let allDialog = null;
            const recHead = $('<h4 class="pa-h-actions"/>').text(S.recommendTitle);
            const seeAll = $('<button type="button" class="btn btn-link btn-xs"/>').text(S.seeAllModels).hide();
            recHead.append(seeAll);
            box.append(recHead);
            const rec = $('<div/>');
            box.append(rec);
            rec.html('<i class="fa fa-spinner fa-pulse"></i>');
            get('ai/recommend', {}, function (data) {
                state.recommend = data.status === 'ok' ? data : null;
                const short = data.status === 'ok' ? Object.assign({}, data, {
                    candidates: (data.candidates || []).filter(function (c) {
                        return c.model === data.recommended || (data.alternatives || []).includes(c.model);
                    }),
                    notes: [], settings: null}) : data;
                PARecommend.render(rec, short, {onUse: onUse});
                seeAll.show().off('click').click(function () {
                    const full = $('<div/>');
                    PARecommend.render(full, data, {onUse: onUse});
                    allDialog = PASimulation.dialog({title: S.recommendTitle, message: full, size: BootstrapDialog.SIZE_WIDE,
                        buttons: [{label: S.close, action: function (d) { d.close(); }}]});
                });
            });

            /* any other library model (shown in the "See all models" dialog) */
            const form = $('<div class="pa-form"/>');
            form.append($('<h4/>').text(S.customModel));
            const custom = $('<input type="text" class="form-control" autocomplete="off" placeholder="qwen2.5:3b"/>');
            form.append(formGroup('pa_custom_model', S.customModelName, custom.attr('title', S.customModelHelp), S.customModelHelp));
            form.append(checkbox('pa_large', S.allowLarge, false, S.allowLargeHelp));
            const customArgs = function () {
                const name = custom.val().trim();
                if (!MODEL_RE.test(name)) {
                    PASimulation.dialog({type: BootstrapDialog.TYPE_WARNING, title: S.customModel, message: esc(S.modelInvalid)});
                    return null;
                }
                const flags = ['+custom'];
                if (form.find('#pa_large').prop('checked')) {
                    flags.push('+large');
                }
                return {name: name, flags: flags};
            };
            form.addClass('pa-custom');
            form.append($('<div class="pa-actions"/>')
                .append(btn(S.simulate, 'btn-default', function () {
                    const a = customArgs();
                    if (a) {
                        pullModel(a.name, a.flags, true);
                    }
                }, 'fa-eye'))
                .append(btn(S.pullModel, 'btn-default', function () {
                    const a = customArgs();
                    if (a) {
                        pullModel(a.name, a.flags, false);
                    }
                }, 'fa-download')));
            box.append(form);

            state.done.model = names.length > 0;
            renderStepper();
            const chosenInstalled = state.model && names.includes(state.model);
            footer({
                skip: true,
                undo: ['pull_model', 'remove_model'],
                simulate: state.model && !chosenInstalled ? function () { pullModel(state.model, modelFlags(state.model), true); } : null,
                simulateLabel: S.simulateDownload,
                apply: state.model && !chosenInstalled ? function () { pullModel(state.model, modelFlags(state.model), false); } : null,
                nextDisabled: !chosenInstalled, nextReason: S.reasonModelFirst,
                applyLabel: S.pullModel + (state.model ? ' ' + state.model : '')
            });
        });
    }

    /******************************************************************************************************
     * step 6: limits
     ******************************************************************************************************/
    function renderLimits(box) {
        loadRuntime(function (rt) {
            box.find('p:has(.fa-spinner)').remove();
            box.append($('<p class="pa-step-help"/>').text(S.limitsHelp));
            const current = Object.assign({}, DEFAULT_LIMITS, (rt && rt.limits) || {});
            const suggested = (state.recommend && state.recommend.settings) || {};
            const ncpu = (state.hw && state.hw.cpu && state.hw.cpu.threads) || 0;
            box.append(stateBox(S.currentState, facts([
                [S.limits, rt && rt.limits && rt.limits.threads ? 'cpuset ' + current.cpus + ', ' + current.threads + ' ' + S.threads +
                    ', ctx ' + current.ctx + ', nice ' + current.nice : S.notSet + ' (' + S.defaults + ': cpuset ' + DEFAULT_LIMITS.cpus +
                    ', ' + DEFAULT_LIMITS.threads + ' ' + S.threads + ', ctx ' + DEFAULT_LIMITS.ctx + ', nice ' + DEFAULT_LIMITS.nice + ')'],
                [S.runtimeState, rt ? (rt.installed ? (rt.running ? S.runtimeRunning : S.runtimeStopped) : S.runtimeMissing) : S.unknown],
                [S.suggested, suggested.num_thread ? 'num_thread ' + suggested.num_thread + ', num_ctx ' + suggested.num_ctx +
                    (suggested.reason ? ' (' + suggested.reason + ')' : '') : null]
            ])));
            /* RAM limit: needs kern.racct.enable=1; the notice brings the button (filled asynchronously) */
            const racctSlot = $('<div class="pa-left"/>');
            box.append(racctSlot);
            if (rt && !rt.installed) {
                box.append(alert('warning', esc(S.limitsNoRuntime) + ' ').append(goBtn('runtime')).addClass('pa-left'));
            }
            const form = $('<div class="pa-form"/>');
            const cpus = $('<input type="text" class="form-control" autocomplete="off"/>').val(current.cpus);
            form.append(formGroup('pa_l_cpus', S.cpuset, cpus, S.cpusetHelp.replace('%n', ncpu || '?')));
            const inline = $('<div class="pa-inline"/>');
            const threads = $('<input type="number" class="form-control" min="1" step="1"/>').val(current.threads);
            if (ncpu) {
                threads.attr('max', ncpu);
            }
            inline.append(formGroup('pa_l_threads', S.threadsLabel, threads, S.threadsHelp));
            const ctx = $('<select class="form-control"/>');
            CTX_VALUES.forEach(function (v) { ctx.append($('<option/>').val(v).text(v)); });
            ctx.val(String(current.ctx));
            inline.append(formGroup('pa_l_ctx', S.ctxLabel, ctx, S.ctxHelp));
            const nice = $('<input type="number" class="form-control" min="0" max="20" step="1"/>').val(current.nice);
            inline.append(formGroup('pa_l_nice', S.niceLabel, nice, S.niceHelp));
            const racctOn = racctState(rt).on;
            const memCurrent = parseInt((rt && rt.limits && rt.limits.mem_gb) || 12, 10);
            const mem = $('<input type="number" class="form-control" min="2" max="64" step="1"/>').val(memCurrent)
                .prop('disabled', !racctOn);
            const memGroup = formGroup('pa_l_mem', S.memLabel, mem, racctOn ? S.memHelp : S.memDisabledHelp);
            inline.append(memGroup);
            form.append(inline);
            if (!racctOn && rt) {
                racctNotice(rt, function (notice, pending) {
                    if (notice) {
                        racctSlot.append(notice);
                    }
                    if (!pending && hasAction('enable_racct')) {
                        memGroup.append(btn(S.enableRamLimit, 'btn-default btn-xs', function () {
                            PASimulation.run({action: 'enable_racct', args: [], title: S.enableRamLimit,
                                plainRevert: S.plainRevertRacct, onDone: afterChange});
                        }));
                    }
                });
            }
            form.append($('<p class="text-muted"/>').append($('<small/>').text(S.fixedLimits)));
            const future = $('<div class="form-group pa-future"/>');
            future.append($('<label/>').text(S.allowedHours).append(' ' + label('default', S.future)));
            future.append($('<input type="text" class="form-control" disabled/>').attr('placeholder', S.allowedHoursHelp));
            form.append(future);
            box.append(form);
            const token = function () {
                const cs = cpus.val().trim();
                const th = parseInt(threads.val(), 10);
                const ni = parseInt(nice.val(), 10);
                if (!CPUSET_RE.test(cs) || !(th >= 1) || !(ni >= 0 && ni <= 20)) {
                    PASimulation.dialog({type: BootstrapDialog.TYPE_WARNING, title: S.step_limits, message: esc(S.limitsInvalid)});
                    return null;
                }
                let t = cs.replace(/,/g, '_') + '/' + th + '/' + ctx.val() + '/' + ni;
                const mg = parseInt(mem.val(), 10);
                if (racctOn && mg >= 2 && mg <= 64 && mg !== memCurrent) {
                    t += '/' + mg;          /* cpus/threads/ctx/nice/mem_gb (needs the 5 part form in setup/) */
                }
                return t;
            };
            const run = function (readOnly) {
                const t = token();
                if (t === null) {
                    return;
                }
                const opts = {action: 'set_limits', args: [t], title: S.setLimits, plainRevert: S.plainRevertLimits,
                              onDone: afterChange};
                readOnly ? PASimulation.simulate(opts) : PASimulation.run(opts);
            };
            state.done.limits = !!(rt && rt.limits && rt.limits.threads);
            renderStepper();
            footer({skip: true, undo: ['set_limits', 'enable_racct'], simulate: function () { run(true); },
                    simulateLabel: S.simulateLimits, apply: function () { run(false); }, applyLabel: S.setLimits});
        });
    }

    /******************************************************************************************************
     * step 7: test (benchmark + sample explanation)
     ******************************************************************************************************/
    function renderBench(report) {
        const box = $('<div/>');
        const items = [
            [report.prompt_tps !== null && report.prompt_tps !== undefined ? report.prompt_tps : '?', S.promptTps],
            [report.gen_tps !== null && report.gen_tps !== undefined ? report.gen_tps : '?', S.genTps],
            [report.model_ram_bytes ? gib(report.model_ram_bytes) : (report.jail_rss_bytes ? gib(report.jail_rss_bytes) : '?'), S.ramUsed],
            [report.estimate_finding_seconds ? Math.round(report.estimate_finding_seconds) + ' s' : '?', S.perFindingEst]
        ];
        const grid = $('<div class="pa-bench"/>');
        items.forEach(function (it) {
            grid.append($('<div class="pa-bench-item"/>').append($('<div class="pa-bench-value"/>').text(it[0]))
                .append($('<div class="pa-bench-label"/>').text(it[1])));
        });
        box.append(grid);
        box.append($('<p class="text-muted"/>').append($('<small/>').text(
            (report.model || '') + ' — ' + (report.threads || '?') + ' ' + S.threads + ', ' + S.wall + ' ' + (report.wall_seconds || '?') +
            ' s, ' + S.load + ' ' + (report.load_seconds || '?') + ' s' + (report.jail_rss_bytes ? ', ' + S.jailRss + ' ' + gib(report.jail_rss_bytes) : ''))));
        return box;
    }

    function readBenchResult(cb) {
        get('ai/job', {}, function (data) {
            const job = (data && data.job) || {};
            let report = job.result || null;
            if (report && report.result && typeof report.result === 'object') {
                report = report.result;
            }
            cb(job.action === 'benchmark' && job.status !== 'running' && report && report.gen_tps !== undefined ? report : null, job);
        });
    }

    function renderAnswer(data) {
        if (!data) {
            return alert('danger', esc(S.error));
        }
        if (data.status === 'refusal') {
            return alert('warning', '<b>' + esc(S.refusal) + '</b><br/>' + esc(data.message));
        }
        if (data.status !== 'ok') {
            return alert('danger', esc(data.message || S.error));
        }
        const out = $('<div/>');
        out.append($('<div class="well pa-answer"/>').text(data.text));
        if (data.truncated) {
            out.append(alert('warning', esc(S.truncated)));
        }
        out.append($('<p class="text-muted"/>').append($('<small/>').html(esc(data.provider || '') + ' / ' + esc(data.model || '') + ', ' +
            esc(Math.round((data.duration_ms || 0) / 100) / 10) + ' s, ' + esc(data.anonymized ? S.anonymized : S.notAnonymized) +
            '<br/>' + esc(S.aiDisclaimer))));
        return out;
    }

    function renderTest(box) {
        loadRuntime(function (rt) {
            loadAiStatus(function (ai) {
                box.find('p:has(.fa-spinner)').remove();
                box.append($('<p class="pa-step-help"/>').text(S.testHelp));
                const names = ((rt && rt.models) || []).map(function (m) { return m.name; });
                box.append(stateBox(S.currentState, facts([
                    [S.runtimeState, rt ? (rt.installed ? (rt.running ? S.runtimeRunning : S.runtimeStopped) : S.runtimeMissing) : S.unknown],
                    [S.modelsInstalled, names.length ? names.join(', ') : S.none],
                    [S.aiState, ai.enabled ? S.enabledWith + ' ' + ai.provider + (ai.model ? ' / ' + ai.model : '') : S.disabled]
                ])));

                /* benchmark */
                box.append($('<h4/>').text(S.benchmark));
                const form = $('<div class="pa-form"/>');
                const sel = $('<select class="form-control"/>');
                names.forEach(function (n) { sel.append($('<option/>').val(n).text(n)); });
                if (state.model && names.includes(state.model)) {
                    sel.val(state.model);
                }
                form.append(formGroup('pa_bench_model', S.benchModel, sel, S.benchHelp));
                box.append(form);
                const result = $('<div/>');
                box.append(result);
                if (state.bench) {
                    result.append(renderBench(state.bench));
                }
                const canBench = rt && rt.running && names.length > 0;
                if (!canBench) {
                    box.append(alert('warning', esc(S.benchUnavailable)));
                }
                const runBench = function (readOnly) {
                    const opts = {action: 'benchmark', args: [sel.val()], title: S.benchmark, onDone: function () {
                        readBenchResult(function (report) {
                            if (report) {
                                state.bench = report;
                                state.done.test = true;
                            }
                            refresh();
                        });
                    }};
                    readOnly ? PASimulation.simulate(opts) : PASimulation.run(opts);
                };
                if (!state.bench) {
                    readBenchResult(function (report) {
                        if (report) {
                            state.bench = report;
                            result.empty().append(renderBench(report));
                        }
                    });
                }

                /* quick test: one real question with today's date and a random topic, answer in its own dialog */
                const quick = $('<div class="pa-actions pa-quicktest"/>');
                const quickBtn = btn(S.quickTest, 'btn-default', function () {
                    const out = $('<div/>').append(spinner(S.asking));
                    PASimulation.dialog({title: S.quickTest + ' — ' + sel.val(), message: out, size: BootstrapDialog.SIZE_WIDE,
                        buttons: [{label: S.quickAgain, icon: 'fa fa-refresh', action: function () { ask(); }},
                                  {label: S.close, action: function (d) { d.close(); }}]});
                    const ask = function () {
                        out.empty().append(spinner(S.asking));
                        post('setup/quicktest', {model: sel.val()}, function (resp) {
                            out.empty();
                            if (resp.status !== 'ok') {
                                out.append(alert('danger', esc(resp.message || S.error)));
                                return;
                            }
                            out.append($('<p class="text-muted"/>').append($('<small/>').text(S.quickQuestion + ': ' + resp.prompt)));
                            out.append($('<blockquote class="pa-quick-answer"/>').text(resp.answer || '—'));
                            out.append($('<p/>').append($('<small/>').text(
                                resp.model + ' · ' + resp.wall_seconds + ' s' +
                                (resp.load_seconds ? ' (' + S.quickLoad + ' ' + resp.load_seconds + ' s)' : '') +
                                (resp.tokens_per_second ? ' · ' + resp.tokens_per_second + ' ' + S.genTps : ''))));
                            state.done.test = true;
                        });
                    };
                    ask();
                }, 'fa-commenting-o');
                quickBtn.prop('disabled', !canBench);
                quick.append(quickBtn).append($('<small class="text-muted"/>').text(' ' + S.quickHelp));
                box.append($('<h4/>').text(S.quickTest)).append(quick);

                /* sample explanation */
                box.append($('<h4/>').text(S.sampleTitle));
                const sample = $('<div/>');
                box.append(sample);
                sample.append(spinner());
                post('analysis/search', {current: 1, rowCount: 1}, function (data) {
                    sample.empty();
                    const row = ((data && data.rows) || [])[0];
                    if (!row) {
                        sample.append(alert('info', esc(S.noFinding) + ' ').append(btn(S.runAnalysis, 'btn-default btn-xs', function () {
                            $(this).prop('disabled', true).append(' <i class="fa fa-spinner fa-pulse"></i>');
                            post('analysis/analyze', {}, function () { refresh(); });
                        }, 'fa-play')));
                        return;
                    }
                    sample.append($('<p/>').html(label({high: 'danger', medium: 'warning', low: 'info', info: 'default'}[row.severity] || 'default', row.severity) +
                        ' <code>' + esc(row.type) + '</code> ' + esc(row.title)));
                    /* the payload and the answer open in their own dialog, the step keeps its size */
                    const openAnswer = function (title, waitText) {
                        const out = $('<div/>').append(spinner(waitText));
                        PASimulation.dialog({title: title, message: out, size: BootstrapDialog.SIZE_WIDE,
                            buttons: [{label: S.close, action: function (d) { d.close(); }}]});
                        return out;
                    };
                    const acts = $('<div class="pa-actions"/>');
                    acts.append(btn(S.previewSend, 'btn-default', function () {
                        const answer = openAnswer(S.previewSend);
                        post('ai/explain', {id: row.id, preview: 1}, function (resp) {
                            answer.empty();
                            if (resp.status !== 'ok') {
                                answer.append(alert('danger', esc(resp.message || S.error)));
                                return;
                            }
                            answer.append($('<p/>').text((resp.anonymized ? S.anonymized : S.notAnonymized) + ', ' + resp.bytes + ' bytes'));
                            (resp.messages || []).forEach(function (m) {
                                answer.append($('<h5/>').text(m.role)).append($('<pre/>').text(m.content));
                            });
                        });
                    }, 'fa-eye'));
                    const send = btn(S.explainSample, 'btn-primary', function () {
                        const answer = openAnswer(S.explainSample, S.asking);
                        post('ai/explain', {id: row.id}, function (resp) {
                            answer.empty().append(renderAnswer(resp));
                        });
                    }, 'fa-magic');
                    if (!ai.enabled) {
                        send.prop('disabled', true);
                    }
                    acts.append(send);
                    sample.append(acts);
                    if (!ai.enabled) {
                        sample.append($('<p class="text-muted"/>').append($('<small/>').text(S.explainNeedsEnable + ' '))
                            .append(goBtn('finish')));
                    }
                });

                renderStepper();
                footer({skip: true, undo: [], simulate: canBench ? function () { runBench(true); } : null,
                        apply: canBench ? function () { runBench(false); } : null, applyLabel: S.runBenchmark});
            });
        });
    }

    /******************************************************************************************************
     * step 8: finish (enable the AI with the chosen provider / model)
     ******************************************************************************************************/
    function providerFieldInputs(p, box) {
        /* fields of a provider for LAN / API choices (text, url, password, dropdown); choice/status/recommend/storage are skipped */
        const inputs = {};
        (p.fields || []).forEach(function (field) {
            if (['choice', 'status', 'recommend'].includes(field.type) || field.storage) {
                return;
            }
            const show = Object.keys(field.show_if || {}).every(function (k) { return state.choice[k] === String(field.show_if[k]); });
            if (!show) {
                return;
            }
            const id = p.id + '.' + field.id;
            const saved = state.saved['policyanalyzer.' + id];
            const value = state.fields[id] !== undefined ? state.fields[id] : (saved || field.default || '');
            let input;
            if (field.type === 'dropdown') {
                input = $('<select class="form-control"/>');
                $.each(field.options || {}, function (k, text) { input.append($('<option/>').val(k).text(text)); });
                input.val(value);
            } else if (field.type === 'password') {
                input = $('<input type="password" class="form-control" autocomplete="new-password"/>');
            } else {
                input = $('<input type="text" class="form-control" autocomplete="off"/>').val(value);
            }
            input.on('change keyup', function () { state.fields[id] = $(this).val(); });
            let help = field.help || '';
            if (field.secret) {
                const hint = ((state.settings || {}).secret_hints || {})[id] || '';
                help = (hint ? S.configured + ' ' + hint + '. ' : S.notConfigured + '. ') + help;
            }
            box.append(formGroup('pa_f_' + id.replace('.', '_'), field.label, input, help));
            inputs[id] = {field: field, input: input};
        });
        return inputs;
    }

    function renderFinish(box) {
        loadSettings(function () {
            loadProviders(function () {
                loadRuntime(function (rt) {
                    loadAiStatus(function (ai) {
                        box.find('p:has(.fa-spinner)').remove();
                        box.append($('<p class="pa-step-help"/>').text(S.finishHelp));
                        // the choice of step 2 lives only in this page: after a reload, a local runtime that is
                        // installed and running is the obvious choice (shown, still confirmed with Simulate/Apply)
                        if (!state.choice.provider && rt && rt.installed && rt.running && provider('ollama')) {
                            state.choice.provider = 'ollama';
                            state.choice.location = 'local';
                            state.done.provider = true;
                        }
                        const installedModels = ((rt && rt.models) || []).map(function (m) { return m.name; });
                        if (!state.model && installedModels.length) {
                            state.model = installedModels[0];
                        }
                        const p = provider(state.choice.provider);
                        const local = isLocal();
                        const rows = [
                            [S.aiState, ai.enabled ? S.enabledWith + ' ' + ai.provider + (ai.model ? ' / ' + ai.model : '') : S.disabled],
                            [S.chosenProvider, p ? p.label + (p.id === 'ollama' ? ' (' + (state.choice.location === 'lan' ? S.lan : S.localFw) + ')' : '') : S.none]
                        ];
                        if (local) {
                            rows.push([S.chosenModel, state.model || S.none]);
                            rows.push([S.runtimeState, rt ? (rt.installed ? (rt.running ? S.runtimeRunning : S.runtimeStopped) : S.runtimeMissing) : S.unknown]);
                            const l = (rt && rt.limits) || {};
                            rows.push([S.limits, l.threads ? 'cpuset ' + l.cpus + ', ' + l.threads + ' ' + S.threads + ', ctx ' + l.ctx + ', nice ' + l.nice : S.notSet]);
                            if (state.bench) {
                                rows.push([S.benchmark, state.bench.gen_tps + ' ' + S.genTps + ', ~' + Math.round(state.bench.estimate_finding_seconds || 0) + ' s ' + S.perFinding]);
                            }
                        }
                        box.append(stateBox(S.summary, facts(rows)));
                        if (!p) {
                            box.append(alert('warning', esc(S.noProviderChosen) + ' ').append(goBtn('provider')));
                            footer({next: false, undo: ['settings']});
                            return;
                        }
                        if (leavesNetwork(p)) {
                            box.append(alert('warning', esc(p.privacy || '')).addClass('pa-left'));
                        }
                        const form = $('<div class="pa-form"/>');
                        let inputs = {};
                        if (!local) {
                            form.append($('<h4/>').text(S.providerSettings));
                            const grid = $('<div class="pa-grid2"/>');
                            form.append(grid);
                            inputs = providerFieldInputs(p, grid);
                        } else {
                            const model = $('<input type="text" class="form-control" autocomplete="off"/>').val(state.model || '');
                            model.on('change keyup', function () { state.model = $(this).val().trim() || null; });
                            form.append(formGroup('pa_f_model', S.chosenModel, model, S.finishModelHelp));
                            if (rt && !rt.installed) {
                                form.append(alert('warning', esc(S.finishNoRuntime) + ' ').append(goBtn('runtime')));
                            }
                        }
                        const anon = checkbox('pa_f_anon', S.anonymize, state.saved['policyanalyzer.ai.anonymize'] !== '0', S.anonymizeHelp);
                        form.append(anon);
                        box.append(form);
                        box.append($('<p class="text-muted pa-left"/>').append($('<small/>').text(S.finishJournal)));

                        /* local plan: a settings diff, applied through settings/set (journaled) */
                        const changes = function () {
                            const values = {ai: {enabled: '1', provider: p.id, anonymize: form.find('#pa_f_anon').prop('checked') ? '1' : '0'}};
                            values[p.id] = {};
                            if (p.id === 'ollama') {
                                values.ollama.location = state.choice.location;
                                if (local) {
                                    values.ollama.model = state.model || '';
                                }
                            }
                            Object.keys(inputs).forEach(function (id) {
                                const short = id.split('.')[1];
                                const v = inputs[id].input.val();
                                if (inputs[id].field.secret && v === '') {
                                    return;                 // keep the stored secret
                                }
                                values[p.id][short] = v;
                            });
                            const steps = [];
                            const flat = flatten(values);
                            Object.keys(flat).sort().forEach(function (k) {
                                const old = state.saved['policyanalyzer.' + k] === undefined ? '' : state.saved['policyanalyzer.' + k];
                                const secret = (p.fields || []).some(function (f) { return f.secret && p.id + '.' + f.id === k; });
                                if (secret) {
                                    steps.push({description: k, command: 'settings: ' + k,
                                                effect: S.configured + ' ****' + flat[k].slice(-4)});
                                } else if (flat[k] !== old) {
                                    steps.push({description: k, command: 'settings: ' + k + ' = ' + flat[k],
                                                effect: (old === '' ? '(empty)' : old) + ' → ' + (flat[k] === '' ? '(empty)' : flat[k])});
                                }
                            });
                            return {values: values, steps: steps};
                        };
                        const run = function (readOnly) {
                            if (local && !state.model) {
                                PASimulation.dialog({type: BootstrapDialog.TYPE_WARNING, title: S.enableAi, message: esc(S.modelRequired)});
                                return;
                            }
                            const c = changes();
                            if (!c.steps.length) {
                                PASimulation.dialog({title: S.enableAi, message: esc(S.noChanges)});
                                return;
                            }
                            const plan = {status: 'ok', risk: 'low', steps: c.steps, warnings: leavesNetwork(p) ? [p.privacy || ''] : [],
                                          revert: [S.settingsRevert]};
                            if (readOnly) {
                                return PASimulation.show(plan, {title: S.enableAi, readOnly: true});
                            }
                            PASimulation.show(plan, {
                                title: S.enableAi,
                                apply: function (dialog, done) {
                                    post('settings/set', {policyanalyzer: c.values}, function (data) {
                                        if (data && data.result === 'saved') {
                                            done({status: 'ok', done: true, journal_id: data.journal_id,
                                                  completed: c.steps.map(function (s) { return s.description; })});
                                        } else {
                                            const v = (data && data.validations) || {};
                                            done({status: 'error', done: false, message: Object.keys(v).map(function (k) {
                                                return k + ': ' + v[k];
                                            }).join('; ') || (data && data.message) || S.error});
                                        }
                                    });
                                },
                                onDone: function () {
                                    state.fields = {};
                                    afterChange();
                                }
                            });
                        };
                        const after = $('<div class="pa-actions"/>');
                        if (ai.enabled) {
                            after.append(btn(S.testConnection, 'btn-default', function () {
                                const b = $(this).prop('disabled', true);
                                post('ai/test', {}, function (data) {
                                    b.prop('disabled', false);
                                    let html;
                                    if (!data || data.status !== 'ok') {
                                        html = '<div class="alert alert-danger">' + esc((data && data.message) || S.error) + '</div>';
                                    } else {
                                        html = '<div class="alert ' + (data.model_available ? 'alert-success' : 'alert-warning') + '">' +
                                            esc(S.reachable) + ': ' + esc(data.endpoint) + ' (' + esc(data.version) + ', ' + esc(data.duration_ms) +
                                            ' ms)' + (data.model_available ? '' : '<br/>' + esc(data.model) + ': ' + esc(S.modelMissing)) + '</div>';
                                    }
                                    PASimulation.dialog({title: S.testConnection, message: html,
                                        buttons: [{label: S.close, action: function (d) { d.close(); }}]});
                                });
                            }, 'fa-plug'));
                            after.append($('<a class="btn btn-default" href="/ui/policyanalyzer/#findings"/>')
                                .html('<span class="fa fa-stethoscope fa-fw"></span> ' + esc(S.openFindings)));
                            after.append(btn(S.disableAi, 'btn-default', function () {
                                const plan = {status: 'ok', risk: 'low', revert: [S.settingsRevert],
                                              steps: [{description: 'ai.enabled', command: 'settings: ai.enabled = 0', effect: '1 → 0'}]};
                                PASimulation.show(plan, {title: S.disableAi, apply: function (dialog, done) {
                                    post('settings/set', {policyanalyzer: {ai: {enabled: '0'}}}, function (data) {
                                        done(data && data.result === 'saved' ? {status: 'ok', done: true, journal_id: data.journal_id} :
                                            {status: 'error', done: false, message: (data && data.message) || S.error});
                                    });
                                }, onDone: afterChange});
                            }, 'fa-ban'));
                            box.append($('<h4/>').text(S.afterEnable)).append(after);
                        }
                        state.done.finish = !!ai.enabled;
                        renderStepper();
                        footer({undo: ['settings'], simulate: function () { run(true); }, apply: function () { run(false); },
                                applyLabel: S.enableAi, next: false});
                    });
                });
            });
        });
    }

    const RENDER = {
        check: renderCheck,
        provider: renderProvider,
        storage: renderStorage,
        runtime: renderRuntime,
        model: renderModel,
        limits: renderLimits,
        test: renderTest,
        finish: renderFinish
    };

    /******************************************************************************************************
     * modal: opened over the Policy Analyzer page (full screen on phones, see policyanalyzer.css .pa-dialog)
     ******************************************************************************************************/
    function accent() {
        /* accent colour of the active theme (no fixed colours in the plugin CSS) */
        const probe = $('<button type="button" class="btn btn-primary" style="position:absolute;left:-9999px"/>').appendTo('body');
        const colour = getComputedStyle(probe[0]).backgroundColor;
        probe.remove();
        if (colour) {
            state.root.closest('.modal')[0].style.setProperty('--pa-accent', colour);
        }
        const content = state.root.closest('.modal-content')[0] || document.body;
        let bg = getComputedStyle(content).backgroundColor;
        if (!bg || bg === 'rgba(0, 0, 0, 0)' || bg === 'transparent') {
            bg = getComputedStyle(document.body).backgroundColor;
        }
        if (bg && bg !== 'rgba(0, 0, 0, 0)') {
            state.root.closest('.modal')[0].style.setProperty('--pa-footer-bg', bg);
        }
    }

    /* body of the dialog: only this part scrolls, and only when the screen is really too small (phones) */
    function markup() {
        return $('<div class="pa-setup"/>').html(
            '<div id="pa_steps_current" class="pa-steps-current"></div>' +
            '<div id="pa_job" class="pa-job" style="display:none"></div>' +
            '<div id="pa_step" class="pa-step"></div>');
    }

    /* header: title, the step bar and "?" (what the assistant does) in one row */
    function headerMarkup() {
        const head = $('<div class="pa-setup-head"/>');
        head.append($('<span class="pa-setup-title"/>').text(S.title));
        head.append($('<ol id="pa_steps" class="pa-steps"/>').attr('aria-label', S.stepsLabel));
        head.append($('<button type="button" class="btn btn-default btn-xs pa-setup-help"/>')
            .attr('title', S.helpTitle).attr('aria-label', S.helpTitle).text('?')
            .click(function () {
                PASimulation.dialog({title: S.title, message: $('<p/>').text(S.intro),
                    buttons: [{label: S.close, action: function (d) { d.close(); }}]});
            }));
        return head;
    }

    function stepFromHash() {
        const m = (window.location.hash || '').match(/^#setup(?:-([1-8]))?$/);
        return m ? (m[1] ? parseInt(m[1], 10) - 1 : 0) : null;
    }

    /* the stacked dialogs (simulation, undo, results) remove "modal-open" from the body when they close;
     * while the assistant is open the page behind it must not scroll, so it is put back */
    $(document).on('hidden.bs.modal', function () {
        if (state.dialog && state.dialog.isOpened && state.dialog.isOpened()) {
            $(document.body).addClass('modal-open');
        }
    });

    /**
     * open the assistant (once); the state always comes from the probes, so it can be reopened at any step
     * @param opts {step: 0-7, onClose: function () {}}
     */
    function open(opts) {
        opts = opts || {};
        if (state.dialog && state.dialog.isOpened && state.dialog.isOpened()) {
            return;
        }
        state.onClose = opts.onClose || null;
        state.prevHash = /^#setup/.test(window.location.hash || '') ? '#findings' : (window.location.hash || '');
        const first = opts.step !== undefined && opts.step !== null ? opts.step : (stepFromHash() || 0);
        const body = markup();
        state.root = body;
        state.done = {};
        state.dialog = PASimulation.dialog({
            title: headerMarkup(),
            message: body,
            size: BootstrapDialog.SIZE_WIDE,
            cssClass: 'pa-setup-dialog',
            closable: true,
            closeByBackdrop: false,
            buttons: [],
            onshown: function () {
                if (state.root) {
                    accent();
                }
            },
            onhidden: function () {
                clearTimeout(state.jobTimer);
                if (history.replaceState) {
                    history.replaceState(null, null, state.prevHash || window.location.pathname);
                }
                state.root = null;
                state.dialog = null;
                /* closing never cancels a background job: it keeps running, its progress is in the action history */
                get('ai/job', {}, function (data) {
                    if (PASimulation.isActive(data && data.job)) {
                        PASimulation.dialog({type: BootstrapDialog.TYPE_INFO, title: S.title,
                            message: $('<div/>').append($('<p/>').text(S.closedWithJob)).append(PASimulation.renderJob(data.job)),
                            buttons: [{label: S.openHistory, cssClass: 'btn-primary', action: function (d) {
                                d.close();
                                $('a[href="#history"]').tab('show');
                            }}, {label: S.close, action: function (d) { d.close(); }}]});
                    }
                });
                if (state.onClose) {
                    state.onClose();
                }
            }
        });
        state.dialog.getModalFooter().show().empty()
            .append($('<div id="pa_footer" class="pa-setup-footer"/>'));
        state.root.append(spinner());
        /* hardware profile for the cpuset hints and the check step (refreshed by the check step itself) */
        get('setup/hwprofile', {}, function (data) {
            if (data && data.status === 'ok') {
                state.hw = data;
            }
        });
        /* detected state marks the steps as done before the first render */
        loadSettings(function () {
            loadRuntime(function (rt) {
                loadAiStatus(function (ai) {
                    state.done.provider = !!state.choice.provider;
                    state.done.runtime = !!(rt && rt.installed);
                    state.done.model = !!(rt && (rt.models || []).length);
                    state.done.limits = !!(rt && rt.limits && rt.limits.threads);
                    state.done.finish = !!ai.enabled;
                    get('ai/storage', {}, function (st) {
                        state.done.storage = !!(st && st.status === 'ok' && st.exists);
                        if (!state.root) {
                            return;
                        }
                        state.root.children('p:has(.fa-spinner)').remove();
                        watchJobBanner();
                        go(first);
                    });
                });
            });
        });
    }

    /**
     * wire the page: #setup / #setup-N in the URL (also /ui/policyanalyzer/setup, which renders the page with it)
     * and every element with data-pa-setup opens the assistant
     */
    function bind(opts) {
        opts = opts || {};
        $(document).on('click', '[data-pa-setup], a[href="/ui/policyanalyzer/setup"]', function (e) {
            e.preventDefault();
            open(opts);
        });
        $(window).on('hashchange', function () {
            const step = stepFromHash();
            if (step === null) {
                return;
            }
            if (state.dialog) {
                if (step !== state.current) {
                    go(step);
                }
            } else {
                open(Object.assign({}, opts, {step: step}));
            }
        });
        if (opts.autoOpen || stepFromHash() !== null) {
            open(opts);
        }
    }

    return {
        setStrings: function (strings) { S = Object.assign({}, S, strings || {}); },
        open: open,
        bind: bind,
        revertEntry: revertEntry,
        removeLocalAi: removeLocalAi,
        state: state
    };
})();
