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
 * Reusable "simulate, then apply" dialog (Policy Analyzer and the AI setup wizard).
 *
 *   PASimulation.setStrings({...});                       translated labels, see DEFAULT_STRINGS
 *   PASimulation.run({
 *       action: 'prepare_storage', args: [],               server plan: POST {endpoint}/plan then {endpoint}/apply
 *       endpoint: '/api/policyanalyzer/change',            optional
 *       title: 'Prepare storage',
 *       onDone: function(result) {}                        called after a successful apply
 *   });
 *   PASimulation.show(plan, {title, apply: function(dialog, done) {...}, onDone})
 *                                                          local plan (e.g. a settings diff), custom apply
 *   PASimulation.simulate({action, args, title})           plan only: the same dialog without Apply ("Simulate"
 *                                                          button of the AI setup); show(plan, {readOnly: true})
 *   run/simulate/show options:
 *     plainRevert: 'text'                                  how to undo, in plain words; the technical "revert"
 *                                                          list of the plan moves under "Technical details"
 *     choice: {label, flags: [...], checked}               one checkbox shown above the plan; toggling it plans
 *                                                          again with args + flags, Apply uses the current args
 *   PASimulation.dialog({...BootstrapDialog options})      any other dialog, full screen on phones
 *   PASimulation.watchJob($el, jobId, onFinish)            progress + Cancel of a background job; apply
 *                                                          results with "status": "started" use it automatically
 *
 * The plan follows the contract of scripts/policyanalyzer/ai/changes.py:
 *   {status, steps[{description, command, effect}], warnings[], irreversible[], revert[], risk, space,
 *    requires_confirmation, requires_double_confirmation, message}
 * Apply stays disabled until the operator ticks the confirmation box(es).
 */
const PASimulation = (function () {
    'use strict';

    let S = {
        simulate: 'Simulation',
        nothing: 'Nothing to do: the system is already in the requested state.',
        steps: 'Steps',
        command: 'Command',
        effect: 'Effect',
        warnings: 'Warnings',
        irreversible: 'Can not be reverted later',
        revert: 'How to revert',
        risk: 'Risk',
        space: 'Disk space',
        confirm: 'I reviewed the steps above and want to apply them.',
        confirm2: 'I understand that part of this can not be undone or that other changes depend on it.',
        apply: 'Apply',
        close: 'Close',
        applied: 'applied',
        running: 'running',
        cancel: 'Cancel',
        applying: 'Applying...',
        done: 'Done',
        failed: 'Failed',
        completed: 'Completed steps',
        journal: 'Recorded in the action history, it can be reverted from there.',
        error: 'Error',
        running: 'Running in the background',
        cancel_job: 'Cancel',
        cancel_confirm: 'Cancel the running job? It rolls back what it changed so far.',
        technical: 'Technical details',
        finished: 'Finished',
        step: 'Step'
    };
    const JOB_URL = '/api/policyanalyzer/ai/job';
    const ACTIVE = ['queued', 'running', 'started', 'cancelling'];

    /* full screen on phones, see css/policyanalyzer/policyanalyzer.css */
    const DIALOG_CLASS = 'pa-dialog';

    /**
     * BootstrapDialog.show() with the plugin dialog class, for every dialog of the plugin pages
     */
    function dialog(options) {
        options = Object.assign({}, options);
        options.cssClass = ((options.cssClass || '') + ' ' + DIALOG_CLASS).trim();
        return BootstrapDialog.show(options);
    }

    /*
     * The OPNsense core HTML-escapes every JSON API response (Response.php: htmlspecialchars(json, ENT_NOQUOTES)).
     * Undo exactly that for this plugin's own endpoints, once, before jQuery parses the JSON: every screen then gets
     * the original text and escapes it a single time when rendering (otherwise "System > Power" showed "&gt;").
     */
    if (!window.__paUnescapeInstalled) {
        window.__paUnescapeInstalled = true;
        $.ajaxPrefilter(function (options) {
            if (/^\/api\/policyanalyzer\//.test(options.url || '')) {
                options.dataFilter = function (data, type) {
                    return typeof data === 'string'
                        ? data.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&') : data;
                };
            }
        });
    }

    function esc(value) {
        return $('<div/>').text(value === undefined || value === null ? '' : String(value)).html();
    }

    /**
     * items are strings, or {warning|text|message, action: {id, label, args}} / {warning, link: {label, url}} when
     * something resolves the warning (backend "warning_actions"): shown with a button that opens the simulation of
     * that action, or with the link (e.g. System: Power: Reboot), never only as an instruction
     */
    function itemText(i) {
        return i !== null && typeof i === 'object' ? (i.warning || i.text || i.message || '') : i;
    }

    function actionButton(i, cls) {
        if (i === null || typeof i !== 'object') {
            return '';
        }
        const act = i.action;
        if (act && /^[a-z][a-z0-9_]{0,63}$/.test(act.id || '')) {
            return ' <button type="button" class="btn ' + (cls || 'btn-xs btn-default') + ' pa-sim-action" data-action="' +
                esc(act.id) + '" data-args="' + esc(JSON.stringify(Array.isArray(act.args) ? act.args : [])) +
                '" data-label="' + esc(act.label || act.id) + '">' + esc(act.label || act.id) + '</button>';
        }
        const link = i.link;
        if (link && /^\/ui\/[A-Za-z0-9_\/#=.?&-]*$/.test(link.url || '')) {
            return ' <a class="btn ' + (cls || 'btn-xs btn-default') + '" href="' + esc(link.url) + '">' +
                esc(link.label || link.url) + '</a>';
        }
        return '';
    }

    // plain "links" of a plan/result (e.g. System: Power: Reboot) as buttons, when no warning already carries them
    function linkButtons(obj) {
        const carried = (obj.warning_actions || []).some(function (wa) { return wa && wa.link; });
        if (carried || !Array.isArray(obj.links)) {
            return '';
        }
        return obj.links.map(function (l) { return actionButton({link: l}, 'btn-sm btn-default'); }).join('');
    }

    function list(items) {
        return '<ul>' + items.map(function (i) {
            return '<li>' + esc(itemText(i)) + actionButton(i) + '</li>';
        }).join('') + '</ul>';
    }

    /**
     * warnings of a plan with their actions: "warnings" stay text, "warning_actions" adds the button
     */
    function warningItems(plan) {
        const extra = (plan.warning_actions || []).filter(function (wa) { return wa && typeof wa === 'object'; });
        const items = (plan.warnings || []).map(function (w) {
            const text = itemText(w);
            return extra.find(function (wa) { return wa.warning === text; }) || w;
        });
        extra.forEach(function (wa) {
            if (!(plan.warnings || []).some(function (w) { return itemText(w) === wa.warning; })) {
                items.push(wa);
            }
        });
        return items;
    }

    /* buttons of warnings with an action, in any plugin dialog */
    $(document).on('click', '.pa-dialog .pa-sim-action, .pa-setup .pa-sim-action', function () {
        let args = [];
        try {
            args = JSON.parse($(this).attr('data-args') || '[]');
        } catch (e) {
            args = [];
        }
        run({action: $(this).data('action'), args: Array.isArray(args) ? args.map(String) : [],
             title: String($(this).data('label'))});
    });

    function render(plan, readOnly, opts) {
        opts = opts || {};
        let html = '';
        if (plan.status === 'error') {
            return '<div class="alert alert-danger">' + esc(plan.message || S.error) + '</div>';
        }
        if (!plan.steps || plan.steps.length === 0) {
            html += '<div class="alert alert-info">' + esc(S.nothing) + '</div>';
        } else {
            html += '<h4>' + esc(S.steps) + '</h4><table class="table table-condensed table-striped pa-sim-steps"><thead><tr>' +
                '<th>#</th><th>' + esc(S.steps) + '</th><th>' + esc(S.command) + '</th><th>' + esc(S.effect) +
                '</th></tr></thead><tbody>';
            plan.steps.forEach(function (step, idx) {
                html += '<tr><td data-label="#">' + (idx + 1) + '</td><td>' + esc(step.description) +
                    '</td><td data-label="' + esc(S.command) + '"><code>' + esc(step.command) + '</code></td>' +
                    '<td data-label="' + esc(S.effect) + '">' + esc(step.effect) + '</td></tr>';
            });
            html += '</tbody></table>';
        }
        if (plan.risk) {
            html += '<p><b>' + esc(S.risk) + ':</b> ' + esc(plan.risk) + '</p>';
        }
        if (plan.space) {
            html += '<p><b>' + esc(S.space) + ':</b> ' + esc(plan.space) + '</p>';
        }
        const warnings = warningItems(plan);
        if (warnings.length) {
            html += '<div class="alert alert-warning"><b>' + esc(S.warnings) + '</b>' + list(warnings) + '</div>';
        }
        /* informational blocks of the plan (e.g. rule position, scenarios, guards): [{title, items[]}] */
        (Array.isArray(plan.info) ? plan.info : []).forEach(function (block) {
            if (!block || !Array.isArray(block.items) || !block.items.length) {
                return;
            }
            html += '<details class="pa-sim-info"' + (block.items.length <= 6 ? ' open' : '') + '><summary><b>' +
                esc(block.title) + '</b> (' + block.items.length + ')</summary>' + list(block.items) + '</details>';
        });
        if (plan.irreversible && plan.irreversible.length) {
            html += '<div class="alert alert-danger"><b>' + esc(S.irreversible) + '</b>' + list(plan.irreversible) +
                '</div>';
        }
        if (opts.plainRevert) {
            html += '<p><b>' + esc(S.revert) + ':</b> ' + esc(opts.plainRevert) + '</p>';
            if (plan.revert && plan.revert.length) {
                html += '<details class="pa-sim-tech"><summary>' + esc(S.technical) + '</summary>' + list(plan.revert) +
                    '</details>';
            }
        } else if (plan.revert && plan.revert.length) {
            html += '<p><b>' + esc(S.revert) + ':</b></p>' + list(plan.revert);
        }
        if (plan.steps && plan.steps.length && !readOnly) {
            html += '<div class="checkbox"><label><input type="checkbox" class="pa-sim-confirm"> ' + esc(S.confirm) +
                '</label></div>';
            if (plan.requires_double_confirmation) {
                html += '<div class="checkbox"><label><input type="checkbox" class="pa-sim-confirm"> ' +
                    esc(S.confirm2) + '</label></div>';
            }
        }
        return html;
    }

    function renderResult(result) {
        const ok = result.status !== 'error' && result.done !== false;
        let html = '<div class="alert ' + (ok ? 'alert-success' : 'alert-danger') + '">' +
            esc(ok ? S.done : (S.failed + ': ' + (result.message || ''))) + '</div>';
        if (result.completed && result.completed.length) {
            html += '<p><b>' + esc(S.completed) + '</b></p>' + list(result.completed);
        }
        const warnings = warningItems(result);
        if (warnings.length) {
            html += '<div class="alert alert-warning">' + list(warnings) + linkButtons(result) + '</div>';
        }
        if (result.journal_id) {
            html += '<p class="text-muted">' + esc(S.journal) + ' (' + esc(result.journal_id) + ')</p>';
        }
        return html;
    }

    function fmtBytes(value) {
        if (!value) {
            return '0 B';
        }
        const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
        let idx = 0;
        while (value >= 1024 && idx < units.length - 1) {
            value /= 1024;
            idx++;
        }
        return value.toFixed(idx ? 1 : 0) + ' ' + units[idx];
    }

    /* download speed from consecutive polls of the same job (smoothed), shown as bytes/s and bits/s with ETA */
    let speedSample = null;

    function fmtRate(bytesPerSec) {
        const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
        const bits = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'];
        let v = bytesPerSec, i = 0;
        while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
        let w = bytesPerSec * 8, j = 0;
        while (w >= 1000 && j < bits.length - 1) { w /= 1000; j++; }
        return v.toFixed(i ? 1 : 0) + ' ' + units[i] + ' (' + w.toFixed(j ? 1 : 0) + ' ' + bits[j] + ')';
    }

    function fmtEta(seconds) {
        seconds = Math.max(0, Math.round(seconds));
        const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60), sec = seconds % 60;
        return (h ? h + 'h ' : '') + (h || m ? m + 'min ' : '') + sec + 's';
    }

    function jobSpeed(job) {
        const key = (job.job || job.action || '') + '|' + (job.step_index || '') + '|' + job.bytes_total;
        const now = Date.now() / 1000;
        if (job.status !== 'running' || !job.bytes_total) {
            speedSample = null;
            return null;
        }
        if (!speedSample || speedSample.key !== key || job.bytes_done < speedSample.bytes) {
            speedSample = {key: key, bytes: job.bytes_done || 0, t: now, rate: null};
            return null;
        }
        const dt = now - speedSample.t;
        if (dt >= 0.8) {
            const inst = ((job.bytes_done || 0) - speedSample.bytes) / dt;
            speedSample.rate = speedSample.rate === null ? inst : 0.6 * speedSample.rate + 0.4 * inst;
            speedSample.bytes = job.bytes_done || 0;
            speedSample.t = now;
        }
        return speedSample.rate;
    }

    function renderJob(job) {
        let pct = null;
        const finishedOk = job && (job.status === 'ok' || job.status === 'done');
        if (job.bytes_total) {
            pct = Math.min(100, Math.round(100 * (job.bytes_done || 0) / job.bytes_total));
        } else if (job.step_total) {
            pct = Math.min(100, Math.round(100 * Math.max(0, (job.step_index || 1) - 1) / job.step_total));
        }
        let html = '<p><b>' + esc(job.action || '') + '</b> — ' + esc(job.status || '') + '</p>';
        if (finishedOk) { pct = 100; }
        if (pct !== null) {
            html += '<div class="progress"><div class="progress-bar progress-bar-striped active" role="progressbar" ' +
                'aria-valuenow="' + pct + '" aria-valuemin="0" aria-valuemax="100" style="width:' + pct + '%">' +
                pct + '%</div></div>';
        }
        if (job.step) {
            html += '<p>' + esc(S.step) + ' ' + esc(job.step_index || '') + (job.step_total ? '/' + esc(job.step_total) : '') +
                ': ' + esc(job.step) + '</p>';
        }
        if (job.bytes_total) {
            const rate = jobSpeed(job);
            let speed = '';
            if (rate !== null && rate > 0) {
                speed = ' · ' + fmtRate(rate) + ' · ' + (S.eta || 'ETA') + ' ' + fmtEta((job.bytes_total - (job.bytes_done || 0)) / rate);
            }
            html += '<p class="text-muted">' + esc(fmtBytes(job.bytes_done)) + ' / ' + esc(fmtBytes(job.bytes_total)) + esc(speed) + '</p>';
        }
        if (job.message) {
            html += '<p class="text-muted">' + esc(job.message) + '</p>';
        }
        return html;
    }

    function cancelJob(after) {
        stdDialogConfirm(S.cancel_job, S.cancel_confirm, S.cancel_job, S.close, function () {
            ajaxCall('/api/policyanalyzer/change/apply', {action: 'setup_cancel', args: []}, function () {
                if (after) {
                    after();
                }
            });
        }, 'warning');
    }

    /**
     * follow a background job ("status": "started" + "job") in target until it ends
     * @param target jQuery element to render into
     * @param jobId id returned by apply (null: whatever job is current)
     * @param onFinish callback(job) when the job is no longer queued/running
     */
    function watchJob(target, jobId, onFinish) {
        const cancelBtn = $('<button type="button" class="btn btn-warning"/>').text(S.cancel_job)
            .click(function () { cancelJob(); });
        const body = $('<div/>');
        target.empty().append('<div class="alert alert-info">' + esc(S.running) + '</div>').append(body)
            .append(cancelBtn);
        const poll = function () {
            ajaxGet(JOB_URL, {}, function (data) {
                const job = (data && data.job) || {};
                if (jobId && job.id && job.id !== jobId) {
                    body.text(S.finished);
                    cancelBtn.hide();
                    return onFinish && onFinish(job);
                }
                body.html(renderJob(job));
                if (ACTIVE.includes(job.status)) {
                    setTimeout(poll, 2000);
                } else {
                    cancelBtn.hide();
                    target.find('.alert-info').removeClass('alert-info')
                        .addClass(job.status === 'ok' || job.status === 'done' ? 'alert-success' : 'alert-warning')
                        .text(S.finished + ': ' + (job.status || ''));
                    if (onFinish) {
                        onFinish(job);
                    }
                }
            });
        };
        poll();
    }

    function show(plan, opts) {
        opts = opts || {};
        const canApply = !opts.readOnly && plan.status !== 'error' && plan.steps && plan.steps.length > 0;
        const buttons = [{
            id: 'pa-sim-close',
            label: opts.readOnly ? S.close : S.cancel,
            action: function (dialog) { dialog.close(); }
        }];
        if (canApply) {
            buttons.push({
                id: 'pa-sim-apply',
                label: S.apply,
                cssClass: plan.risk === 'high' || plan.requires_double_confirmation ? 'btn-danger' : 'btn-primary',
                action: function (dialog) {
                    const btn = dialog.getButton('pa-sim-apply');
                    btn.disable();
                    btn.spin();
                    dialog.setClosable(false);
                    opts.apply(dialog, function (result) {
                        dialog.setClosable(true);
                        btn.stopSpin();
                        btn.hide();
                        if (result && result.status === 'started') {
                            // running in the background: closing this window does not cancel the job
                            const closeRun = dialog.getButton('pa-sim-close');
                            if (closeRun) { closeRun.text(S.close); }
                            dialog.setClosable(true);
                            dialog.setTitle((opts.title || S.apply) + ' — ' + S.running);
                            watchJob(dialog.getModalBody(), result.job || null, function (job) {
                                dialog.setTitle((opts.title || S.apply) + ' — ' + (job && (job.status === 'ok' || job.status === 'done') ? S.applied : S.error));
                                if (opts.onDone) {
                                    opts.onDone(result);
                                }
                            });
                            return;
                        }
                        dialog.getModalBody().html(renderResult(result || {}));
                        // after Apply nothing is pending any more: "Close" instead of "Cancel", title says applied
                        const closeBtn = dialog.getButton('pa-sim-close');
                        if (closeBtn) { closeBtn.text(S.close); }
                        dialog.setClosable(true);
                        dialog.setTitle((opts.title || S.apply) + ' — ' + (result && result.status === 'error' ? S.error : S.applied));
                        if (result && result.status !== 'error' && result.done !== false && opts.onDone) {
                            opts.onDone(result);
                        }
                    });
                }
            });
        }
        BootstrapDialog.show({
            cssClass: DIALOG_CLASS,
            type: plan.risk === 'high' ? BootstrapDialog.TYPE_DANGER : BootstrapDialog.TYPE_WARNING,
            title: (opts.title || S.simulate) + ' — ' + S.simulate,
            message: opts.choice ? $('<div/>').append(choiceBox(opts))
                .append($('<div class="pa-sim-plan"/>').html(render(plan, !!opts.readOnly, opts))) :
                render(plan, !!opts.readOnly, opts),
            size: BootstrapDialog.SIZE_WIDE,
            buttons: buttons,
            onshown: function (dialog) {
                const apply = dialog.getButton('pa-sim-apply');
                if (!apply) {
                    return;
                }
                apply.disable();
                if (opts.choice) {
                    dialog.getModalBody().on('change', '.pa-sim-choice', function () {
                        const checked = $(this).prop('checked');
                        apply.disable();
                        const area = dialog.getModalBody().find('.pa-sim-plan').html('<i class="fa fa-spinner fa-pulse"></i>');
                        opts.onChoice(checked, function (newPlan) {
                            area.html(render(newPlan, !!opts.readOnly, opts));
                            newPlan.status === 'error' || !(newPlan.steps || []).length ? apply.hide() : apply.show();
                        });
                    });
                }
                dialog.getModalBody().on('change', '.pa-sim-confirm', function () {
                    const boxes = dialog.getModalBody().find('.pa-sim-confirm');
                    const all = boxes.length > 0 && boxes.filter(':checked').length === boxes.length;
                    all ? apply.enable() : apply.disable();
                });
            }
        });
    }

    function choiceBox(opts) {
        return $('<div class="checkbox pa-sim-choice-box"/>').append($('<label/>')
            .append($('<input type="checkbox" class="pa-sim-choice"/>').prop('checked', !!opts.choice.checked))
            .append(' ').append($('<b/>').text(opts.choice.label)));
    }

    function run(opts) {
        const endpoint = opts.endpoint || '/api/policyanalyzer/change';
        const argsFor = function (checked) {
            return (opts.args || []).concat(checked && opts.choice ? (opts.choice.flags || []) : []);
        };
        const payload = {action: opts.action, args: argsFor(opts.choice && opts.choice.checked)};
        ajaxCall(endpoint + '/plan', payload, function (plan) {
            show(plan || {status: 'error'}, {
                title: opts.title,
                onDone: opts.onDone,
                plainRevert: opts.plainRevert,
                choice: opts.choice,
                onChoice: function (checked, cb) {
                    payload.args = argsFor(checked);
                    ajaxCall(endpoint + '/plan', payload, function (newPlan) { cb(newPlan || {status: 'error'}); });
                },
                apply: function (dialog, done) {
                    ajaxCall(endpoint + '/apply', payload, function (result) {
                        done(result || {status: 'error'});
                    });
                }
            });
        });
    }

    /**
     * plan only (nothing can be applied from this dialog): used by the "Simulate" buttons of the AI setup
     */
    function simulate(opts) {
        const endpoint = opts.endpoint || '/api/policyanalyzer/change';
        ajaxCall(endpoint + '/plan', {action: opts.action, args: opts.args || []}, function (plan) {
            show(plan || {status: 'error'}, {title: opts.title, readOnly: true, plainRevert: opts.plainRevert});
        });
    }

    return {
        setStrings: function (strings) { S = Object.assign({}, S, strings || {}); },
        show: show,
        run: run,
        simulate: simulate,
        render: render,
        warningItems: warningItems,
        actionButton: actionButton,
        renderResult: renderResult,
        fmtBytes: fmtBytes,
        dialog: dialog,
        watchJob: watchJob,
        renderJob: renderJob,
        cancelJob: cancelJob,
        isActive: function (job) { return !!job && ACTIVE.includes(job.status); },
        escape: esc
    };
})();
