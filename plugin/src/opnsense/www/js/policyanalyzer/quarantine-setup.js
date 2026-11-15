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
 * Quarantine setup assistant (Max Cyber IA): a modal over the Quarantine tab, same look and behaviour as the AI
 * setup (setup.js, untouched: the few helpers needed here are copied, not shared). See WIZARD.md, "Quarantine
 * wizard" and scripts/policyanalyzer/quarantine/steps.py.
 *
 *   PAQSetup.setStrings({...});      translated labels (quarantine_setup.volt)
 *   PAQSetup.open({step, onClose});  opens at the given step (0-7) or at the first step not done yet
 *   PAQSetup.removeAll();            the inverse steps one by one (each simulated, confirmed and undoable)
 *   PAQSetup.bind({onClose});        [data-pa-qsetup] buttons and #qsetup / #qsetup-N open it
 *
 * Every step is its own change action with Simulate -> Apply (confirmation) -> Undo (revert of the journal entry
 * of that step, from the history filtered on its actions); the state on the left is detected again by
 * GET /api/policyanalyzer/quarantine/wizard every time a step is shown.
 *
 *   step       change actions (POST change/plan|apply)
 *   check      qsetup_rule_log <uuid> on|off              (button of the "WireGuard rule does not log" notice)
 *   ledger     qsetup_ledger create|attach <name>|detach|purge
 *   aliases    qsetup_aliases create|remove, qsetup_never_block add|del <address>
 *   rule       qsetup_rule create on|off, qsetup_rule remove
 *   scenarios  qsetup_scenarios <key=value:...|defaults>   (live preview: GET quarantine/preview)
 *   schedule   qsetup_schedule create|remove
 *   activate   qsetup_activate (Undo = pause), quarantine_pause / quarantine_resume
 *   finish     summary, shortcuts, Remove all
 */
const PAQSetup = (function () {
    'use strict';

    const API = '/api/policyanalyzer/';
    const esc = PASimulation.escape;
    const V4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(\/([0-9]|[12]\d|3[0-2]))?$/;
    const V6 = /^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(\/([0-9]|[1-9]\d|1[01]\d|12[0-8]))?$/;
    const FIELDS = [
        {key: 'reset_days', type: 'number'}, {key: 'scan_ports', type: 'number'},
        {key: 'scan_window', type: 'number'}, {key: 'bait_ports', type: 'text'},
        {key: 'suricata', type: 'bool'}, {key: 'suricata_severity', type: 'select', options: [1, 2, 3]},
        {key: 'max_active', type: 'number'}, {key: 'syn_only', type: 'bool'}
    ];

    let S = {
        title: 'Quarantine setup', stepsLabel: 'Steps', helpTitle: 'What does the quarantine setup do?',
        intro: 'Installs the automatic quarantine (rule "Max Cyber IA") step by step. Every step shows the state detected now; Simulate shows exactly what would change, Apply asks for confirmation, and Undo reverts that step alone (its entry in the action history).',
        currentState: 'Current state (detected now)', loading: 'Reading the current state...',
        back: 'Back', skip: 'Skip', undo: 'Undo', simulate: 'Simulate', apply: 'Apply', next: 'Next', close: 'Close',
        cancel: 'Cancel', error: 'Error', stepOf: 'Step %n of %t', goTo: 'Go to %s',
        step_check: 'Check', step_ledger: 'Ledger', step_aliases: 'Aliases', step_rule: 'Rule',
        step_scenarios: 'Scenarios', step_schedule: 'Schedule', step_activate: 'Activate', step_finish: 'Finish',
        yes: 'yes', no: 'no', none: 'none', present: 'present', missing: 'missing', enabled: 'enabled',
        disabled: 'disabled', running: 'running', notRunning: 'not running', readOnlyStep: 'This step only reads the system; nothing is changed.',
        probeFailed: 'The state could not be read (see the system log).',
        undoHelp: 'Changes made by this step, newest first. Revert first shows a simulation of what will be undone.',
        undoEmpty: 'This step has not changed anything yet.', reverted: 'reverted', revert: 'Revert',
        undoFull: 'Open the full action history', plainRevert: 'Undo of this step: the button Undo of the assistant, or Revert in the action history.',
        /* check */
        checkHelp: 'What the quarantine would see on this firewall right now: the WAN interfaces, how many external sources the filter blocks there, the sources of events and the addresses that are never quarantined.',
        wanNone: 'No WAN interface found.', blocked5: '%b blocked from %s sources in 5 min', blocked60: '1 h: %b / %s',
        estimate: 'Would enter (estimate)', estimateText: '≈ %a per 5 min · %b per hour', filterLog: 'Filter log',
        logCovers: 'the last %m min were read', logMissing: 'missing', suricata: 'Suricata', eve: 'eve.json',
        suricataOff: 'scenario disabled in the settings', limit: 'Limit', limitText: '%m active entries (now %n)',
        guards: 'Guards: never quarantined', seeAll: 'See all', alwaysProtected: 'always',
        g_firewall: 'this firewall', g_gateway: 'gateways', g_dns: 'DNS servers', g_ntp: 'NTP servers',
        g_wireguard_peer: 'WireGuard peers', g_tailscale_peer: 'Tailscale peers',
        g_wireguard_allowed: 'WireGuard clients (24 h)', g_never_block: 'pa_never_block', g_admin_session: 'admin sessions',
        /* ledger */
        ledgerHelp: 'The ledger is the SQLite database of the quarantine: every offense, entry and exit, kept forever, plus the settings of the scenarios. Reading starts at the current end of the logs.',
        ledger: 'Ledger', ledgerSize: 'Size', ledgerHistory: 'History', historyText: '%e entries, %o offenses',
        since: 'since', createdAt: 'Created', detachedTitle: 'Disconnected ledgers (kept)',
        ledgerReady: 'The ledger exists; nothing to create.', connectAgain: 'Connect again',
        disconnect: 'Disconnect (keep everything)', deleteLedger: 'Delete the ledger...',
        ledgerUndoHelp: 'Undo removes an empty ledger. A ledger with history is only disconnected (renamed and kept); deleting it is a separate, explicit option with a double confirmation.',
        ledgerCreate: 'Create the ledger',
        ledgerApply: 'Apply creates %p (SQLite, WAL) and remembers the current end of the filter log and of eve.json: what happened before is not counted.',
        /* aliases */
        aliasesHelp: 'pa_quarantine (External) holds the quarantined addresses as a pf table filled at run time; pa_never_block (Network) lists what you never want quarantined.',
        neverBlockTitle: 'pa_never_block', neverEmpty: 'empty', neverAdd: 'Add', neverRemove: 'Remove %s',
        neverPlaceholder: '203.0.113.7 or 203.0.113.0/28', neverInvalid: 'Enter an address or a network (CIDR).',
        neverNeedsAlias: 'The list can be edited once the aliases exist (Apply).', entries: 'entries',
        createAliases: 'Create aliases', removeAliases: 'Remove the aliases',
        /* rule */
        ruleHelp: 'The rule "Max Cyber IA" blocks (quick, logged, IPv4+IPv6) inbound traffic from pa_quarantine on the WAN interfaces, before every other rule of its group.',
        ruleState: 'Rule', sequence: 'Sequence', interfaces: 'Interfaces', floating: 'floating',
        createAs: 'Create the rule', createOn: 'enabled now', createOff: 'disabled (turned on in step 7, recommended)',
        position: 'Position', positionText: 'sequence %s, %t, among %n enabled rules', precedes: 'Evaluated before',
        wanPass: 'WAN pass rules after it', removeRule: 'Remove the rule', createRule: 'Create the rule',
        /* scenarios */
        scenariosHelp: 'When an external address enters the quarantine. Fixed by design: the base trigger (1 or more blocked inbound connections in the 5-minute window) and the ladder of durations; the rest is adjustable.',
        fixedBase: 'Base: ≥ 1 blocked connection in the window', ladder: 'Ladder', custom: 'custom', dflt: 'default',
        set_reset_days: 'Reset after (days without offenses)', set_scan_ports: 'Port scan: distinct ports',
        set_scan_window: 'Port scan: window (s)', set_bait_ports: 'Bait ports (separated by +)',
        set_suricata: 'Use Suricata alerts', set_suricata_severity: 'Suricata severity up to',
        set_max_active: 'Limit of active entries', set_syn_only: 'TCP: only connection attempts (SYN)',
        preview: 'Preview: with the logs of the last 5 min, %n address(es) would enter', previewNone: 'nobody',
        previewPartial: 'the log covers only %s s', previewRefresh: 'Refresh preview', previewOld: 'already in quarantine',
        level: 'level', defaults: 'Defaults', invalid: 'Check the highlighted values.',
        needsLedger: 'The scenarios are stored in the ledger: create it first (step 2).',
        noChange: 'No value changed yet: edit a field to simulate.',
        /* schedule */
        scheduleHelp: 'Runs the quarantine every 5 minutes (System: Settings: Cron) and rebuilds the pf table from the ledger after a reboot (boot hook).',
        cron: 'Cron job', every: 'every', nextRun: 'Next run', bootHook: 'Boot hook', removeSchedule: 'Remove schedule',
        /* activate */
        activateHelp: 'Turns the rule on (if it was created disabled), marks the quarantine as running and runs it once now. Undo pauses it: the rule is disabled and the ledger keeps recording.',
        paused: 'Paused', lastRun: 'Last run', never: 'never', runText: '%o entered, %s sources, %g protected, %d ms',
        firstRun: 'Result of the first run',
        actEnable: 'Enable the rule Max Cyber IA and reload the rules (it is disabled now).',
        actResume: 'Mark the quarantine as running (it is paused now).',
        actRun: 'Run the quarantine once now; Simulate shows who would enter (read from the logs since the ledger was created).', entered: 'Entered', byReason: 'by reason', pause: 'Pause', resume: 'Resume',
        /* finish */
        finishHelp: 'The quarantine is ready when every step is done. Each step can be undone alone; Remove all goes through the inverse steps one by one and keeps the ledger unless you choose otherwise.',
        summary: 'Summary', done: 'done', notDone: 'not done', openTab: 'Open the Quarantine tab',
        removeAll: 'Remove all (step by step)', removeAllTitle: 'Remove all',
        removeAllHelp: 'The inverse steps run one by one, each with its own simulation and confirmation and its own entry in the action history (each can be undone).',
        rmSchedule: 'Schedule (6): remove the cron job and the boot hook', rmRule: 'Rule (4): end the active quarantines, remove the rule',
        rmAliases: 'Aliases (3): remove pa_quarantine and pa_never_block (its entries are saved for Undo)',
        rmLedger: 'Ledger (2)', keepLedger: 'keep it (default)', detachLedger: 'disconnect it (renamed, kept)',
        purgeLedger: 'delete it with its history (double confirmation, irreversible)', start: 'Start',
        nothingToRemove: 'Nothing to remove.', installed: 'Installed', notInstalled: 'Not installed'
    };

    const STEPS = [
        {id: 'check', actions: ['qsetup_rule_log']},
        {id: 'ledger', actions: ['qsetup_ledger']},
        {id: 'aliases', actions: ['qsetup_aliases', 'qsetup_never_block']},
        {id: 'rule', actions: ['qsetup_rule']},
        {id: 'scenarios', actions: ['qsetup_scenarios', 'quarantine_settings']},
        {id: 'schedule', actions: ['qsetup_schedule']},
        {id: 'activate', actions: ['qsetup_activate', 'quarantine_pause', 'quarantine_resume']},
        {id: 'finish', actions: ['install_quarantine', 'remove_quarantine', 'qsetup_rule_log', 'qsetup_ledger',
                                 'qsetup_aliases', 'qsetup_never_block', 'qsetup_rule', 'qsetup_scenarios',
                                 'qsetup_schedule', 'qsetup_activate', 'quarantine_pause', 'quarantine_resume']}
    ];

    const state = {current: 0, root: null, data: null, dialog: null, onClose: null, prevHash: '', createOn: false,
                   lastRun: null, previewTimer: null, previewSeq: 0};

    /******************************************************************************************************
     * helpers (copied from setup.js, kept local so the AI assistant stays untouched)
     ******************************************************************************************************/
    function get(url, data, cb) {
        ajaxGet(API + url, data || {}, function (resp) { cb(resp || {status: 'error'}); });
    }

    function fmt(text, map) {
        let out = String(text);
        Object.keys(map || {}).forEach(function (k) { out = out.split('%' + k).join(String(map[k])); });
        return out;
    }

    function label(cls, text) {
        return '<span class="label label-' + cls + '">' + esc(text) + '</span>';
    }

    function alertBox(cls, html) {
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

    function stateBox(content) {
        const box = $('<div class="pa-state"/>');
        box.append($('<div class="pa-state-title"/>').text(S.currentState));
        box.append(content);
        return box;
    }

    function spinner(text) {
        return $('<p class="paq-spin"/>').html('<i class="fa fa-spinner fa-pulse"></i> ' + esc(text || S.loading));
    }

    function btn(text, cls, onClick, icon) {
        const b = $('<button type="button" class="btn ' + (cls || 'btn-default') + '"/>');
        b.html((icon ? '<span class="fa ' + icon + ' fa-fw"></span> ' : '') + esc(text));
        if (onClick) {
            b.click(onClick);
        }
        return b;
    }

    function help(text) {
        return $('<p class="pa-step-help text-muted"/>').append($('<small/>').text(text));
    }

    function yesNo(v, yes, no, clsYes, clsNo) {
        return label(v ? (clsYes || 'success') : (clsNo || 'default'), v ? (yes || S.yes) : (no || S.no));
    }

    function stepTitle(id) {
        return S['step_' + id] || id;
    }

    function stepIndex(id) {
        return STEPS.findIndex(function (s) { return s.id === id; });
    }

    function goBtn(stepId) {
        return btn(fmt(S.goTo, {s: stepTitle(stepId)}), 'btn-default btn-xs', function () { go(stepIndex(stepId)); },
            'fa-arrow-right');
    }

    function fmtTime(iso) {
        if (!iso) {
            return '-';
        }
        const d = new Date(iso);
        const p = function (n) { return String(n).padStart(2, '0'); };
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' +
            p(d.getMinutes());
    }

    function reasonsText(map) {
        const keys = Object.keys(map || {});
        return keys.length ? keys.sort().map(function (k) { return k + ' ' + map[k]; }).join(', ') : '';
    }

    /* change actions: Simulate = plan only; Apply = plan with confirmation, then apply; both refresh the step */
    function simulate(action, args, title) {
        PASimulation.simulate({action: action, args: args || [], title: title, plainRevert: S.plainRevert});
    }

    function run(action, args, title, onDone) {
        PASimulation.run({action: action, args: args || [], title: title, plainRevert: S.plainRevert,
                          onDone: function (result) {
                              if (onDone) {
                                  onDone(result);
                              }
                              refresh();
                          }});
    }

    /* a notice that asks for something always brings the button that does it */
    function notice(w, cls) {
        const box = alertBox(cls || 'warning', '').addClass('paq-notice');
        box.append($('<span/>').text(w.warning || w.text || String(w)));
        const act = w.action;
        if (act && /^[a-z][a-z0-9_]{0,63}$/.test(act.id || '')) {
            box.append(' ').append(btn(act.label || act.id, 'btn-default btn-xs', function () {
                run(act.id, (act.args || []).map(String), act.label);
            }, 'fa-flask'));
        } else if (w.link && /^\/ui\/[A-Za-z0-9_\/#=.?&-]*$/.test(w.link.url || '')) {
            box.append(' ').append($('<a class="btn btn-default btn-xs"/>').attr('href', w.link.url)
                .text(w.link.label || w.link.url));
        } else if (w.step) {
            box.append(' ').append(goBtn(w.step));
        }
        return box;
    }

    /******************************************************************************************************
     * stepper, footer, navigation
     ******************************************************************************************************/
    function done(id) {
        return !!(state.data && state.data.done && state.data.done[id]);
    }

    function renderStepper() {
        if (!state.root) {
            return;
        }
        const ol = $('#paq_steps').empty();
        STEPS.forEach(function (step, idx) {
            const li = $('<li/>').attr('tabindex', 0).attr('role', 'button');
            const isDone = (step.id === 'finish' ? !!(state.data && state.data.installed) : done(step.id)) &&
                idx !== state.current;
            li.toggleClass('active', idx === state.current).toggleClass('done', isDone);
            li.append($('<span class="pa-step-num"/>').html(isDone ? '<span class="fa fa-check"></span>' : String(idx + 1)));
            li.append($('<span class="pa-step-label"/>').text(stepTitle(step.id)));
            li.attr('title', stepTitle(step.id));
            li.on('click keypress', function (e) {
                if (e.type === 'click' || e.key === 'Enter' || e.key === ' ') {
                    go(idx);
                }
            });
            ol.append(li);
        });
        $('#paq_steps_current').text(fmt(S.stepOf, {n: state.current + 1, t: STEPS.length}) + ': ' +
            stepTitle(STEPS[state.current].id));
    }

    /**
     * @param opts {back, skip, next, simulate, apply, undo, applyLabel, simulateLabel, nextDisabled}
     */
    function footer(opts) {
        opts = opts || {};
        if (!state.root) {
            return;
        }
        const box = $('#paq_footer').empty();
        const secondary = $('<div class="pa-footer-secondary"/>');
        const primary = $('<div class="pa-footer-primary"/>');
        if (opts.back !== false && state.current > 0) {
            secondary.append(btn(S.back, 'btn-default', back, 'fa-chevron-left'));
        }
        if (opts.skip) {
            secondary.append(btn(S.skip, 'btn-default', function () { go(state.current + 1); }));
        }
        if (opts.undo !== false) {
            secondary.append(btn(S.undo, 'btn-default', function () { showHistory(STEPS[state.current].actions); },
                'fa-undo'));
        }
        if (opts.simulate) {
            primary.append(btn(opts.simulateLabel || S.simulate, 'btn-default', opts.simulate, 'fa-eye'));
        }
        if (opts.apply) {
            primary.append(btn(opts.applyLabel || S.apply, 'btn-primary', opts.apply, 'fa-play'));
        }
        if (opts.next !== false && state.current < STEPS.length - 1) {
            const n = btn(S.next + ': ' + stepTitle(STEPS[state.current + 1].id), opts.apply ? 'btn-default' : 'btn-primary',
                function () { go(state.current + 1); });
            n.append(' <span class="fa fa-chevron-right"></span>');
            primary.append(n);
        }
        if (state.current === STEPS.length - 1) {
            primary.append(btn(S.close, 'btn-primary', function () { if (state.dialog) { state.dialog.close(); } }));
        }
        box.append(secondary).append('<span class="pa-footer-spacer"></span>').append(primary);
        columns();
    }

    /* two columns on wide screens: help and detected state on the left, the options of the step on the right */
    function columns() {
        const box = state.root && state.root.find('#paq_step');
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

    function go(idx) {
        if (!state.root) {
            return;
        }
        idx = Math.max(0, Math.min(STEPS.length - 1, idx));
        state.current = idx;
        clearTimeout(state.previewTimer);
        if (history.replaceState) {
            history.replaceState(null, null, '#qsetup-' + (idx + 1));
        }
        renderStepper();
        const box = state.root.find('#paq_step').empty();
        box.append($('<h2/>').text((idx + 1) + '. ' + stepTitle(STEPS[idx].id)));
        box.append(spinner());
        footer({undo: false, next: false});
        /* the state is detected again for every step shown */
        get('quarantine/wizard', {}, function (data) {
            if (!state.root || state.current !== idx) {
                return;
            }
            box.children('.paq-spin').remove();
            if (!data || data.status !== 'ok') {
                box.append(alertBox('danger', esc((data && data.message) || S.probeFailed)));
                footer({});
                return;
            }
            state.data = data;
            renderStepper();
            RENDER[STEPS[idx].id](box, data);
            const modal = state.root.closest('.modal');
            if (modal.length) {
                modal.find('.modal-body').scrollTop(0);
            }
        });
    }

    function back() {
        go(state.current - 1);
    }

    function refresh() {
        go(state.current);
    }

    /* action history filtered on the actions of the step (Undo) */
    function showHistory(actions) {
        get('change/history', {}, function (data) {
            const items = ((data && data.items) || []).filter(function (item) { return actions.includes(item.action); });
            const body = $('<div/>');
            body.append($('<p class="text-muted"/>').append($('<small/>').text(S.undoHelp)));
            if (!items.length) {
                body.append(alertBox('info', esc(S.undoEmpty)));
            }
            const list = $('<div class="pa-cards"/>');
            items.forEach(function (item) {
                const card = $('<div class="pa-card-item"/>');
                const args = item.args && typeof item.args === 'object' ? Object.keys(item.args).filter(function (k) {
                    return k !== 'via' && typeof item.args[k] !== 'object';
                }).map(function (k) { return item.args[k]; }).join(' ') : '';
                card.append($('<div class="pa-card-title"/>').text((item.description || item.action) + (args ? ' — ' + args : '')));
                card.append($('<div class="pa-card-meta text-muted"/>').html(esc(item.ts || item.id) + ' — ' +
                    esc(item.status) + (item.reverted ? ' ' + label('default', S.reverted + ' ' + (item.reverted.ts || '')) : '')));
                if ((item.summary || []).length) {
                    card.append($('<div class="pa-card-meta"/>').html(item.summary.slice(0, 6).map(esc).join('<br/>')));
                }
                if (item.revertible) {
                    card.append($('<div class="pa-card-actions"/>').append(btn(S.revert, 'btn-default', function () {
                        dlg.close();
                        PASimulation.run({action: 'revert', args: [item.id], title: S.revert + ': ' + (item.description || item.action),
                                          onDone: refresh});
                    }, 'fa-undo')));
                }
                list.append(card);
            });
            body.append(list);
            body.append($('<p/>').append($('<a/>').attr('href', '/ui/policyanalyzer/#history').text(S.undoFull)));
            const dlg = PASimulation.dialog({title: S.undo + ': ' + stepTitle(STEPS[state.current].id), message: body,
                size: BootstrapDialog.SIZE_WIDE, buttons: [{label: S.close, action: function (d) { d.close(); }}]});
        });
    }

    /******************************************************************************************************
     * 1 check (read only)
     ******************************************************************************************************/
    function renderCheck(box, d) {
        const c = d.check;
        box.append(help(S.checkHelp));
        const rows = [];
        (c.wan || []).forEach(function (w) {
            rows.push([w.descr + ' (' + w.key + ', ' + w.dev + ')', fmt(S.blocked5, {b: w.blocks_5m, s: w.sources_5m}) +
                ' · ' + fmt(S.blocked60, {b: w.blocks_1h, s: w.sources_1h})]);
        });
        if (!(c.wan || []).length) {
            rows.push(['WAN', S.wanNone]);
        }
        const reasons = reasonsText(c.by_reason_1h);
        rows.push([S.estimate, '<b>' + esc(fmt(S.estimateText, {a: c.entering_5m, b: c.entering_1h})) + '</b>' +
            (reasons ? ' <small class="text-muted">(' + esc(reasons) + ')</small>' : ''), 'html']);
        rows.push([S.filterLog, c.filter_log.exists ? yesNo(true, S.present) + ' <small class="text-muted">' +
            esc(fmt(S.logCovers, {m: Math.round((c.log.covers_seconds || 0) / 60)})) + '</small>' :
            label('danger', S.logMissing), 'html']);
        rows.push([S.suricata, (c.suricata.enabled ? yesNo(c.suricata.running, S.running, S.notRunning, 'success', 'warning') +
            ' ' + S.eve + ': ' + yesNo(c.suricata.eve, S.present, S.missing) : label('default', S.suricataOff)), 'html']);
        rows.push([S.limit, fmt(S.limitText, {m: c.limit.max_active, n: c.limit.pf_entries})]);
        box.append(stateBox(facts(rows)));

        const g = $('<div class="paq-guards"/>');
        g.append($('<h4/>').text(S.guards + ' (' + c.guards.total + ')').append(' ').append(
            btn(S.seeAll, 'btn-default btn-xs', function () {
                if (window.PAQuarantine && PAQuarantine.showGuards) {
                    PAQuarantine.showGuards();
                }
            }, 'fa-list')));
        const chips = $('<div class="paq-chips"/>');
        Object.keys(c.guards.counts || {}).forEach(function (k) {
            const n = c.guards.counts[k];
            const sample = (c.guards.sample || {})[k] || [];
            chips.append($('<span class="paq-chip"/>').toggleClass('paq-chip-zero', !n)
                .attr('title', sample.join(', ')).html(esc(S['g_' + k] || k) + ' <b>' + esc(n) + '</b>'));
        });
        g.append(chips);
        g.append($('<p class="text-muted paq-small"/>').text(S.alwaysProtected + ': ' + (c.guards.implicit || []).join(', ')));
        box.append(g);
        (c.warning_actions || []).forEach(function (w) { box.append(notice(w)); });
        (c.guards.notes || []).forEach(function (n) { box.append(notice({warning: n}, 'info')); });
        box.append($('<p class="text-muted paq-small"/>').text(S.readOnlyStep));
        footer({});
    }

    /******************************************************************************************************
     * 2 ledger
     ******************************************************************************************************/
    function renderLedger(box, d) {
        const l = d.ledger;
        box.append(help(S.ledgerHelp));
        box.append(stateBox(facts([
            [S.ledger, (l.exists ? yesNo(true, S.present) : label('default', S.missing)) + ' <code>' + esc(l.path) + '</code>', 'html'],
            [S.ledgerSize, l.exists ? PASimulation.fmtBytes(l.bytes) : null],
            [S.ledgerHistory, l.exists ? fmt(S.historyText, {e: l.entries, o: l.offenses}) +
                (l.history_since ? ' (' + S.since + ' ' + fmtTime(l.history_since) + ')' : '') : null],
            [S.createdAt, l.exists ? fmtTime(l.installed) : null],
            [S.detachedTitle, (l.detached || []).length ? String(l.detached.length) : null]
        ])));
        if (!l.exists) {
            (l.detached || []).slice(-3).reverse().forEach(function (a) {
                const card = $('<div class="pa-card-item paq-row"/>');
                card.append($('<span/>').html('<code>' + esc(a.name) + '</code> <small class="text-muted">' +
                    esc(PASimulation.fmtBytes(a.bytes) + ' · ' + fmtTime(a.mtime)) + '</small>'));
                card.append(btn(S.connectAgain, 'btn-default btn-xs', function () {
                    run('qsetup_ledger', ['attach', a.name], S.connectAgain + ': ' + a.name);
                }, 'fa-plug'));
                box.append(card);
            });
            box.append($('<p/>').text(fmt(S.ledgerApply, {p: l.path})));
            box.append($('<p class="paq-small text-muted"/>').text(S.ledgerUndoHelp));
            footer({simulate: function () { simulate('qsetup_ledger', ['create'], S.ledgerCreate); },
                    apply: function () { run('qsetup_ledger', ['create'], S.ledgerCreate); }});
            return;
        }
        box.append(alertBox('success', esc(S.ledgerReady)));
        box.append($('<div class="pa-actions"/>')
            .append(btn(S.disconnect, 'btn-default', function () { run('qsetup_ledger', ['detach'], S.disconnect); }, 'fa-chain-broken'))
            .append(btn(S.deleteLedger, 'btn-danger', function () { run('qsetup_ledger', ['purge'], S.deleteLedger); }, 'fa-trash')));
        box.append($('<p class="paq-small text-muted"/>').text(S.ledgerUndoHelp));
        footer({});
    }

    /******************************************************************************************************
     * 3 aliases (+ pa_never_block editor)
     ******************************************************************************************************/
    function validNever(value) {
        return V4.test(value) || (value.indexOf(':') >= 0 && V6.test(value));
    }

    function renderAliases(box, d) {
        const a = d.aliases;
        const both = a.quarantine.present && a.never_block.present;
        box.append(help(S.aliasesHelp));
        box.append(stateBox(facts([
            ['pa_quarantine', (a.quarantine.present ? yesNo(true, S.present) : label('default', S.missing)) +
                (a.quarantine.type ? ' <small class="text-muted">' + esc(a.quarantine.type) + '</small>' : ''), 'html'],
            ['pa_never_block', (a.never_block.present ? yesNo(true, S.present) : label('default', S.missing)) +
                (a.never_block.present ? ' <small class="text-muted">' + esc(a.never_block.content.length) + ' ' +
                    esc(S.entries) + '</small>' : ''), 'html']
        ])));
        const ed = $('<div class="paq-never"/>');
        ed.append($('<h4/>').text(S.neverBlockTitle));
        const list = $('<div class="paq-chips"/>');
        (a.never_block.content || []).forEach(function (v) {
            list.append($('<span class="paq-chip"/>').append($('<code/>').text(v)).append(
                $('<button type="button" class="btn btn-link btn-xs paq-chip-x"/>').attr('title', fmt(S.neverRemove, {s: v}))
                    .attr('aria-label', fmt(S.neverRemove, {s: v})).html('<span class="fa fa-times"></span>').click(function () {
                        run('qsetup_never_block', ['del', v], fmt(S.neverRemove, {s: v}));
                    })));
        });
        if (!(a.never_block.content || []).length) {
            list.append($('<span class="text-muted"/>').text(S.neverEmpty));
        }
        ed.append(list);
        const input = $('<input type="text" class="form-control" maxlength="64" autocomplete="off"/>')
            .attr('placeholder', S.neverPlaceholder).attr('aria-label', S.neverPlaceholder);
        const err = $('<small class="text-danger paq-err"/>');
        const add = btn(S.neverAdd, 'btn-default', function () {
            const v = (input.val() || '').trim();
            if (!validNever(v)) {
                err.text(S.neverInvalid);
                input.focus();
                return;
            }
            err.text('');
            run('qsetup_never_block', ['add', v], S.neverAdd + ': ' + v);
        }, 'fa-plus');
        input.on('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); add.click(); } });
        const row = $('<div class="paq-inline"/>').append(input).append(add);
        if (!a.never_block.present) {
            input.prop('disabled', true);
            add.prop('disabled', true);
        }
        ed.append(row).append(err);
        if (!a.never_block.present) {
            ed.append($('<p class="paq-small text-muted"/>').text(S.neverNeedsAlias));
        }
        box.append(ed);
        if (a.quarantine.present || a.never_block.present) {
            box.append($('<div class="pa-actions"/>').append(btn(S.removeAliases, 'btn-default', function () {
                run('qsetup_aliases', ['remove'], S.removeAliases);
            }, 'fa-trash')));
        }
        footer(both ? {} : {simulate: function () { simulate('qsetup_aliases', ['create'], S.createAliases); },
                            apply: function () { run('qsetup_aliases', ['create'], S.createAliases); }});
    }

    /******************************************************************************************************
     * 4 rule
     ******************************************************************************************************/
    function positionBlock(pos) {
        const wrap = $('<div class="paq-position"/>');
        if (!pos) {
            return wrap;
        }
        wrap.append($('<h4/>').text(S.position));
        wrap.append($('<p/>').text(fmt(S.positionText, {s: pos.sequence, t: pos.floating ? S.floating : 'interface rule',
                                                         n: pos.group_size})));
        if ((pos.before || []).length) {
            const t = $('<table class="table table-condensed paq-table"/>');
            t.append($('<caption/>').text(S.precedes));
            pos.before.forEach(function (r) {
                t.append($('<tr/>').append($('<td/>').text(r.sequence)).append($('<td/>').text(r.description || r.uuid))
                    .append($('<td/>').append(label(r.action === 'pass' ? 'success' : 'danger', r.action))));
            });
            wrap.append(t);
        }
        if (pos.wan_pass_total) {
            wrap.append($('<p class="paq-small"/>').text(S.wanPass + ' (' + pos.wan_pass_total + '): ' +
                pos.wan_pass_rules.map(function (r) { return '"' + (r.description || r.uuid) + '" (' + r.sequence + ')'; })
                    .join(', ')));
        }
        (pos.warnings || []).forEach(function (w) { wrap.append(notice({warning: w})); });
        return wrap;
    }

    function renderRule(box, d) {
        const r = d.rule;
        box.append(help(S.ruleHelp));
        box.append(stateBox(facts([
            [S.ruleState, (r.present ? yesNo(r.enabled, S.enabled, S.disabled, 'success', 'warning') : label('default', S.missing)) +
                ' <b>' + esc(r.description) + '</b>', 'html'],
            [S.sequence, r.present ? String(r.sequence) : null],
            [S.interfaces, (r.interfaces || []).join(', ')]
        ])));
        if (!d.aliases.quarantine.present && !r.present) {
            box.append(notice({warning: 'pa_quarantine: ' + S.missing, step: 'aliases'}));
        }
        if (!r.present) {
            const form = $('<div class="pa-form paq-radio"/>');
            form.append($('<label/>').text(S.createAs));
            [[false, S.createOff], [true, S.createOn]].forEach(function (o) {
                const id = 'paq_rule_' + (o[0] ? 'on' : 'off');
                const radio = $('<input type="radio" name="paq_rule_on"/>').attr('id', id).prop('checked', state.createOn === o[0])
                    .change(function () { state.createOn = o[0]; });
                form.append($('<div class="radio"/>').append($('<label/>').attr('for', id).append(radio).append(' ').append(
                    document.createTextNode(o[1]))));
            });
            box.append(form);
        }
        box.append(positionBlock(r.position));
        if (r.present) {
            box.append($('<div class="pa-actions"/>').append(btn(S.removeRule, 'btn-default', function () {
                run('qsetup_rule', ['remove'], S.removeRule);
            }, 'fa-trash')));
            footer({});
            return;
        }
        const args = function () { return ['create', state.createOn ? 'on' : 'off']; };
        footer({simulate: function () { simulate('qsetup_rule', args(), S.createRule); },
                apply: function () { run('qsetup_rule', args(), S.createRule); }});
    }

    /******************************************************************************************************
     * 5 scenarios (values before/after, live preview from the logs of the last 5 minutes)
     ******************************************************************************************************/
    function scenarioValues(form, current) {
        const values = {};
        let ok = true;
        FIELDS.forEach(function (f) {
            const el = form.find('[data-key="' + f.key + '"]');
            let v = f.type === 'bool' ? (el.prop('checked') ? '1' : '0') : String(el.val() || '').trim();
            if (f.key === 'bait_ports') {
                v = v.replace(/[ ,]+/g, '+').replace(/^\++|\++$/g, '');
            }
            const rule = (state.data.scenarios.rules || {})[f.key];
            let valid = true;
            if (f.key === 'bait_ports') {
                valid = /^[0-9]{1,5}(\+[0-9]{1,5}){0,63}$/.test(v) && v.split('+').every(function (p) {
                    return +p > 0 && +p < 65536;
                });
            } else if (rule) {
                valid = /^[0-9]{1,7}$/.test(v) && +v >= rule[0] && +v <= rule[1];
            }
            el.closest('.form-group').toggleClass('has-error', !valid);
            ok = ok && valid;
            const norm = f.key === 'bait_ports' ? v.split('+').map(Number).sort(function (a, b) { return a - b; }).join('+') : v;
            const cur = f.key === 'bait_ports' ? String(current[f.key]).split('+').map(Number).sort(function (a, b) {
                return a - b; }).join('+') : String(current[f.key]);
            if (valid && norm !== cur) {
                values[f.key] = v;
            }
        });
        return {ok: ok, values: values, token: Object.keys(values).map(function (k) { return k + '=' + values[k]; }).join(':')};
    }

    function renderPreview(target, data) {
        target.empty();
        if (!data || data.status !== 'ok') {
            target.append(alertBox('danger', esc((data && data.message) || S.error)));
            return;
        }
        const head = $('<div class="paq-preview-head"/>').append($('<b/>').text(fmt(S.preview, {n: data.entering})));
        const reasons = reasonsText(data.by_reason);
        if (reasons) {
            head.append(' <small class="text-muted">(' + esc(reasons) + ')</small>');
        }
        if (!data.complete) {
            head.append(' <small class="text-warning">' + esc(fmt(S.previewPartial, {s: (data.log || {}).covers_seconds})) + '</small>');
        }
        target.append(head);
        const list = $('<div class="paq-preview-list"/>');
        (data.candidates || []).slice(0, 6).forEach(function (c) {
            list.append($('<span class="paq-chip"/>').toggleClass('paq-chip-zero', !!c.already)
                .attr('title', (c.reasons || []).join(', ') + (c.ports ? ' · ' + c.ports : '') + (c.already ? ' · ' + S.previewOld : ''))
                .html('<code>' + esc(c.addr) + '</code> ' + esc(c.reason) + ' · ' + esc(c.level_label)));
        });
        if (!(data.candidates || []).length) {
            list.append($('<span class="text-muted"/>').text(S.previewNone));
        }
        target.append(list);
    }

    function renderScenarios(box, d) {
        const sc = d.scenarios;
        const cur = sc.settings;
        box.append(help(S.scenariosHelp));
        box.append(stateBox(facts([
            [S.fixedBase.split(':')[0], S.fixedBase.split(':').slice(1).join(':').trim()],
            [S.ladder, (sc.fixed.ladder || []).join(' → ')]
        ].concat(FIELDS.map(function (f) {
            const custom = Object.prototype.hasOwnProperty.call(sc.stored || {}, f.key);
            let v = cur[f.key];
            if (f.type === 'bool') {
                v = +v ? S.yes : S.no;
            }
            return [S['set_' + f.key], esc(String(v)).replace(/\+/g, ' ') + ' <small class="text-muted">' +
                esc(custom ? S.custom : S.dflt) + '</small>', 'html'];
        })))));
        if (!d.ledger.exists) {
            box.append(notice({warning: S.needsLedger, step: 'ledger'}));
            footer({});
            return;
        }
        const form = $('<form class="pa-form paq-scen" autocomplete="off"/>');
        FIELDS.forEach(function (f) {
            const id = 'paq_set_' + f.key;
            const g = $('<div class="form-group"/>');
            let input;
            if (f.type === 'bool') {
                input = $('<input type="checkbox"/>').prop('checked', !!+cur[f.key]);
                g.addClass('paq-check').append($('<label/>').attr('for', id).append(input.attr('id', id).attr('data-key', f.key))
                    .append(' ').append(document.createTextNode(S['set_' + f.key])));
            } else {
                if (f.type === 'select') {
                    input = $('<select class="form-control"/>');
                    f.options.forEach(function (o) { input.append($('<option/>').val(o).text(o)); });
                    input.val(String(cur[f.key]));
                } else {
                    input = $('<input class="form-control"/>').attr('type', f.type === 'number' ? 'number' : 'text')
                        .val(String(cur[f.key]));
                    const rule = (sc.rules || {})[f.key];
                    if (rule) {
                        input.attr('min', rule[0]).attr('max', rule[1]).attr('title', rule[0] + '-' + rule[1]);
                    }
                }
                g.append($('<label/>').attr('for', id).text(S['set_' + f.key]))
                    .append(input.attr('id', id).attr('data-key', f.key));
            }
            form.append(g);
        });
        form.on('submit', function (e) { e.preventDefault(); });
        box.append(form);
        const prev = $('<div class="paq-preview" aria-live="polite"/>');
        box.append(prev);
        const msg = $('<small class="text-muted paq-small"/>');
        const update = function () {
            const v = scenarioValues(form, cur);
            msg.text(v.ok ? (v.token ? '' : S.noChange) : S.invalid);
            if (!v.ok) {
                return;
            }
            const seq = ++state.previewSeq;
            prev.addClass('paq-busy');
            get('quarantine/preview', {settings: v.token || '-'}, function (data) {
                if (seq !== state.previewSeq || !state.root) {
                    return;
                }
                prev.removeClass('paq-busy');
                renderPreview(prev, data);
            });
        };
        form.on('input change', 'input, select', function () {
            clearTimeout(state.previewTimer);
            state.previewTimer = setTimeout(update, 600);
        });
        box.append($('<div class="paq-inline paq-scen-actions"/>').append(msg).append(
            btn(S.defaults, 'btn-default btn-xs', function () { run('qsetup_scenarios', ['defaults'], S.defaults); },
                'fa-refresh')));
        update();
        const act = function (apply) {
            return function () {
                const v = scenarioValues(form, cur);
                if (!v.ok || !v.token) {
                    msg.text(v.ok ? S.noChange : S.invalid);
                    return;
                }
                (apply ? run : simulate)('qsetup_scenarios', [v.token], stepTitle('scenarios'));
            };
        };
        footer({simulate: act(false), apply: act(true)});
    }

    /******************************************************************************************************
     * 6 schedule
     ******************************************************************************************************/
    function renderSchedule(box, d) {
        const s = d.schedule;
        box.append(help(S.scheduleHelp));
        box.append(stateBox(facts([
            [S.cron, (s.cron.present ? yesNo(s.cron.enabled, S.enabled, S.disabled) : label('default', S.missing)) +
                (s.cron.present ? ' ' + esc(S.every) + ' <code>' + esc(s.cron.minutes) + '</code>' : ''), 'html'],
            [S.nextRun, s.next_run ? fmtTime(s.next_run) : null],
            [S.bootHook, (s.syshook ? yesNo(true, S.present) : label('default', S.missing)) + ' <code>' +
                esc(s.syshook_path) + '</code>', 'html']
        ])));
        box.append($('<ul class="paq-list"/>').html('<li><code>*/5 * * * * policyanalyzer quarantine_run</code></li>' +
            '<li><code>configctl cron restart</code></li><li><code>' + esc(s.syshook_path) + '</code> → ' +
            '<code>configctl policyanalyzer quarantine_sync</code></li>'));
        const present = s.cron.present && s.syshook;
        if (s.cron.present || s.syshook) {
            box.append($('<div class="pa-actions"/>').append(btn(S.removeSchedule, 'btn-default', function () {
                run('qsetup_schedule', ['remove'], S.removeSchedule);
            }, 'fa-trash')));
        }
        footer(present ? {} : {simulate: function () { simulate('qsetup_schedule', ['create'], stepTitle('schedule')); },
                               apply: function () { run('qsetup_schedule', ['create'], stepTitle('schedule')); }});
    }

    /******************************************************************************************************
     * 7 activate (first run now; Undo = pause)
     ******************************************************************************************************/
    function runRows(r) {
        if (!r) {
            return S.never;
        }
        return fmtTime(r.ts) + ' — ' + fmt(S.runText, {o: r.offenses || 0, s: r.sources || 0,
            g: Object.values(r.guarded || {}).reduce(function (a, b) { return a + b; }, 0), d: r.duration_ms || 0});
    }

    function renderActivate(box, d) {
        const a = d.activate;
        const r = d.rule;
        box.append(help(S.activateHelp));
        box.append(stateBox(facts([
            [S.ruleState, r.present ? yesNo(r.enabled, S.enabled, S.disabled, 'success', 'warning') : label('default', S.missing), 'html'],
            [S.paused, a.paused === null ? null : yesNo(a.paused, S.yes, S.no, 'warning', 'success'), 'html'],
            [S.lastRun, runRows(a.last_run)]
        ])));
        const need = [];
        if (!d.ledger.exists) { need.push('ledger'); }
        if (!d.aliases.quarantine.present) { need.push('aliases'); }
        if (!r.present) { need.push('rule'); }
        need.forEach(function (id) { box.append(notice({warning: stepTitle(id) + ': ' + S.notDone, step: id})); });
        if (!d.schedule.cron.present) {
            box.append(notice({warning: stepTitle('schedule') + ': ' + S.notDone, step: 'schedule'}, 'info'));
        }
        if (!need.length) {
            box.append($('<ul class="paq-list"/>').html(
                (r.enabled ? '' : '<li>' + esc(S.actEnable) + '</li>') +
                (a.paused ? '<li>' + esc(S.actResume) + '</li>' : '') +
                '<li>' + esc(S.actRun) + '</li>'));
        }
        const result = state.lastRun || a.last_run;
        if (result && result.status === 'ok') {
            const res = $('<div class="paq-result"/>');
            res.append($('<h4/>').text(state.lastRun ? S.firstRun : S.lastRun));
            const cards = $('<div class="pa-bench"/>');
            cards.append($('<div class="pa-bench-item"/>').html('<div class="pa-bench-value">' + esc(result.offenses || 0) +
                '</div><div class="pa-bench-label">' + esc(S.entered) + '</div>'));
            Object.keys(result.by_reason || {}).sort().forEach(function (k) {
                cards.append($('<div class="pa-bench-item"/>').html('<div class="pa-bench-value">' + esc(result.by_reason[k]) +
                    '</div><div class="pa-bench-label">' + esc(k) + '</div>'));
            });
            res.append(cards);
            box.append(res);
        }
        const ctl = $('<div class="pa-actions"/>');
        if (r.present && d.ledger.exists) {
            if (r.enabled && !a.paused) {
                ctl.append(btn(S.pause, 'btn-default', function () { run('quarantine_pause', [], S.pause); }, 'fa-pause'));
            } else if (a.last_run) {
                ctl.append(btn(S.resume, 'btn-default', function () { run('quarantine_resume', [], S.resume); }, 'fa-play'));
            }
        }
        box.append(ctl);
        if (need.length) {
            footer({});
            return;
        }
        footer({simulate: function () { simulate('qsetup_activate', [], stepTitle('activate')); },
                apply: function () {
                    run('qsetup_activate', [], stepTitle('activate'), function (res) { state.lastRun = res && res.run; });
                }});
    }

    /******************************************************************************************************
     * 8 finish (summary, shortcuts, Remove all)
     ******************************************************************************************************/
    function renderFinish(box, d) {
        box.append(help(S.finishHelp));
        box.append(stateBox(facts(STEPS.slice(1, 7).map(function (s, i) {
            return [(i + 2) + '. ' + stepTitle(s.id), yesNo(done(s.id), S.done, S.notDone, 'success', 'default'), 'html'];
        }).concat([[S.installed, yesNo(d.installed, S.installed, S.notInstalled), 'html']]))));
        const actions = $('<div class="pa-actions paq-finish"/>');
        actions.append(btn(S.openTab, 'btn-primary', function () {
            if (state.dialog) { state.dialog.close(); }
            $('a[href="#quarantine"]').tab('show');
        }, 'fa-shield'));
        if (d.rule.present && d.ledger.exists) {
            if (d.rule.enabled && !d.activate.paused) {
                actions.append(btn(S.pause, 'btn-default', function () { run('quarantine_pause', [], S.pause); }, 'fa-pause'));
            } else {
                actions.append(btn(S.resume, 'btn-default', function () { run('quarantine_resume', [], S.resume); }, 'fa-play'));
            }
        }
        actions.append(btn(S.removeAll, 'btn-default', removeAll, 'fa-trash'));
        box.append(actions);
        STEPS.slice(1, 7).forEach(function (s, i) {
            if (!done(s.id)) {
                box.append(notice({warning: (i + 2) + '. ' + stepTitle(s.id) + ': ' + S.notDone, step: s.id}, 'info'));
            }
        });
        footer({next: false});
    }

    /* the inverse steps one by one, each with its own simulation, confirmation and journal entry */
    function removeAll() {
        get('quarantine/wizard', {}, function (d) {
            if (!d || d.status !== 'ok') {
                return;
            }
            const items = [];
            if (d.schedule.cron.present || d.schedule.syshook) {
                items.push({id: 'schedule', text: S.rmSchedule, action: 'qsetup_schedule', args: ['remove']});
            }
            if (d.rule.present) {
                items.push({id: 'rule', text: S.rmRule, action: 'qsetup_rule', args: ['remove']});
            }
            if (d.aliases.quarantine.present || d.aliases.never_block.present) {
                items.push({id: 'aliases', text: S.rmAliases, action: 'qsetup_aliases', args: ['remove']});
            }
            const body = $('<div class="pa-setup paq-remove"/>');
            body.append($('<p/>').text(S.removeAllHelp));
            items.forEach(function (it) {
                body.append($('<div class="checkbox"/>').append($('<label/>').append(
                    $('<input type="checkbox" checked/>').attr('data-id', it.id)).append(' ').append(document.createTextNode(it.text))));
            });
            if (d.ledger.exists) {
                const g = $('<div class="form-group"/>').append($('<label/>').text(S.rmLedger));
                [['keep', S.keepLedger], ['detach', S.detachLedger], ['purge', S.purgeLedger]].forEach(function (o, i) {
                    g.append($('<div class="radio"/>').append($('<label/>').append(
                        $('<input type="radio" name="paq_rm_ledger"/>').val(o[0]).prop('checked', i === 0))
                        .append(' ').append(document.createTextNode(o[1]))));
                });
                body.append(g);
            }
            if (!items.length && !d.ledger.exists) {
                body.append(alertBox('info', esc(S.nothingToRemove)));
            }
            PASimulation.dialog({title: S.removeAllTitle, message: body, size: BootstrapDialog.SIZE_WIDE, buttons: [
                {label: S.cancel, action: function (dlg) { dlg.close(); }},
                {label: S.start, cssClass: 'btn-primary', action: function (dlg) {
                    const chosen = items.filter(function (it) {
                        return body.find('input[data-id="' + it.id + '"]').prop('checked');
                    });
                    const ledger = body.find('input[name=paq_rm_ledger]:checked').val();
                    if (ledger && ledger !== 'keep') {
                        chosen.push({id: 'ledger', action: 'qsetup_ledger', args: [ledger]});
                    }
                    dlg.close();
                    const stepN = function (i) {
                        if (i >= chosen.length) {
                            if (state.root) { refresh(); }
                            return;
                        }
                        const it = chosen[i];
                        PASimulation.run({action: it.action, args: it.args, plainRevert: S.plainRevert,
                            title: S.removeAllTitle + ' ' + (i + 1) + '/' + chosen.length + ': ' + stepTitle(it.id),
                            onDone: function () { stepN(i + 1); }});
                    };
                    stepN(0);
                }}]});
        });
    }

    const RENDER = {
        check: renderCheck, ledger: renderLedger, aliases: renderAliases, rule: renderRule,
        scenarios: renderScenarios, schedule: renderSchedule, activate: renderActivate, finish: renderFinish
    };

    /******************************************************************************************************
     * modal (same frame as the AI setup: .pa-setup-dialog, full screen on phones)
     ******************************************************************************************************/
    function accent() {
        const probe = $('<button type="button" class="btn btn-primary" style="position:absolute;left:-9999px"/>').appendTo('body');
        const colour = getComputedStyle(probe[0]).backgroundColor;
        probe.remove();
        const modal = state.root.closest('.modal')[0];
        if (colour && modal) {
            modal.style.setProperty('--pa-accent', colour);
        }
        const content = state.root.closest('.modal-content')[0] || document.body;
        let bg = getComputedStyle(content).backgroundColor;
        if (!bg || bg === 'rgba(0, 0, 0, 0)' || bg === 'transparent') {
            bg = getComputedStyle(document.body).backgroundColor;
        }
        if (bg && bg !== 'rgba(0, 0, 0, 0)' && modal) {
            modal.style.setProperty('--pa-footer-bg', bg);
        }
    }

    function headerMarkup() {
        const head = $('<div class="pa-setup-head"/>');
        head.append($('<span class="pa-setup-title"/>').text(S.title));
        head.append($('<ol id="paq_steps" class="pa-steps"/>').attr('aria-label', S.stepsLabel));
        head.append($('<button type="button" class="btn btn-default btn-xs pa-setup-help"/>')
            .attr('title', S.helpTitle).attr('aria-label', S.helpTitle).text('?')
            .click(function () {
                PASimulation.dialog({title: S.title, message: $('<p/>').text(S.intro),
                    buttons: [{label: S.close, action: function (d) { d.close(); }}]});
            }));
        return head;
    }

    function stepFromHash() {
        const m = (window.location.hash || '').match(/^#qsetup(?:-([1-8]))?$/);
        return m ? (m[1] ? parseInt(m[1], 10) - 1 : -1) : null;
    }

    /* the first step not done yet ("the point where the setup is") */
    function currentPoint(d) {
        if (!d || !d.done) {
            return 0;
        }
        if (!d.done.ledger && !d.done.aliases && !d.done.rule) {
            return 0;
        }
        for (let i = 1; i < 7; i++) {
            if (!d.done[STEPS[i].id] && STEPS[i].id !== 'scenarios') {
                return i;
            }
        }
        return STEPS.length - 1;
    }

    $(document).on('hidden.bs.modal', function () {
        if (state.dialog && state.dialog.isOpened && state.dialog.isOpened()) {
            $(document.body).addClass('modal-open');
        }
    });

    /**
     * @param opts {step: 0-7 (default: the first step not done), onClose}
     */
    function open(opts) {
        opts = opts || {};
        if (state.dialog && state.dialog.isOpened && state.dialog.isOpened()) {
            return;
        }
        state.onClose = opts.onClose || state.onClose;
        state.prevHash = /^#qsetup/.test(window.location.hash || '') ? '#quarantine' : (window.location.hash || '');
        state.lastRun = null;
        const body = $('<div class="pa-setup paq-setup"/>').html(
            '<div id="paq_steps_current" class="pa-steps-current"></div><div id="paq_step" class="pa-step"></div>');
        state.root = body;
        state.dialog = PASimulation.dialog({
            title: headerMarkup(), message: body, size: BootstrapDialog.SIZE_WIDE,
            cssClass: 'pa-setup-dialog paq-setup-dialog', closable: true, closeByBackdrop: false, buttons: [],
            onshown: function () { if (state.root) { accent(); } },
            onhidden: function () {
                clearTimeout(state.previewTimer);
                if (history.replaceState) {
                    history.replaceState(null, null, state.prevHash || window.location.pathname);
                }
                state.root = null;
                state.dialog = null;
                if (state.onClose) {
                    state.onClose();
                }
            }
        });
        state.dialog.getModalFooter().show().empty().append($('<div id="paq_footer" class="pa-setup-footer"/>'));
        body.append(spinner());
        get('quarantine/wizard', {}, function (d) {
            if (!state.root) {
                return;
            }
            body.children('.paq-spin').remove();
            state.data = d && d.status === 'ok' ? d : null;
            const first = opts.step !== undefined && opts.step !== null && opts.step >= 0 ? opts.step : currentPoint(state.data);
            go(first);
        });
    }

    function bind(opts) {
        opts = opts || {};
        state.onClose = opts.onClose || null;
        $(document).on('click', '[data-pa-qsetup]', function (e) {
            e.preventDefault();
            open(opts);
        });
        $(window).on('hashchange', function () {
            const step = stepFromHash();
            if (step === null) {
                return;
            }
            if (state.dialog) {
                if (step >= 0 && step !== state.current) {
                    go(step);
                }
            } else {
                open(Object.assign({}, opts, {step: step}));
            }
        });
        if (stepFromHash() !== null) {
            open(Object.assign({}, opts, {step: stepFromHash()}));
        }
    }

    return {
        setStrings: function (strings) { S = Object.assign({}, S, strings || {}); },
        strings: function () { return S; },
        open: open,
        bind: bind,
        removeAll: removeAll,
        state: state
    };
})();

// quarantine.js looks for window.PAQSetup (a top-level const is not a window property)
window.PAQSetup = PAQSetup;
