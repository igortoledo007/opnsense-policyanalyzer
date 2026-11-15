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
 * Background AI queue in every page of the plugin.
 *
 * A request whose scenario is routed to the queue (Settings > AI per scenario) answers at once
 *   {"status": "queued", "job": {"id", "position", "eta_seconds", ...}, "label": "local AI", ...}
 * instead of the module result.  This file wraps the OPNsense ajaxCall/ajaxGet for /api/policyanalyzer/*: the
 * caller's callback is held back, the page shows "In analysis by the local AI (position N, ~X min)" (next to the
 * spinner of the request, and in a small panel in the corner), the job is polled every 10 s and, when it ends,
 * the original callback receives the module result exactly as if the request had waited.  No module needs to
 * know about the queue.  Pending jobs survive a reload in sessionStorage (then only the panel shows them; the
 * modules store their answers, so reopening the item shows it).
 *
 *   PAAIQueue.setStrings({...})          translated labels
 *   PAAIQueue.track(queuedAnswer, cb)    used by the wrapper; cb(result) when the job ends
 */
const PAAIQueue = (function () {
    'use strict';

    const JOB_URL = '/api/policyanalyzer/ai/queue_job';
    const CANCEL_URL = '/api/policyanalyzer/ai/queue_cancel';
    const STORE = 'pa-ai-queue';
    const POLL_MS = 10000;
    const pt = /^pt/i.test(document.documentElement.getAttribute('lang') || navigator.language || '');
    let S = pt ? {
        queuedLocal: 'Em análise pela IA local (posição %p, ~%m min)',
        queued: 'Na fila de %l (posição %p, ~%m min)',
        runningLocal: 'Em análise pela IA local agora (~%m min restantes)',
        running: 'Em análise por %l agora (~%m min restantes)',
        fallback: 'o provedor principal falhou; respondendo pela reserva',
        title: 'Fila da IA',
        cancel: 'Cancelar',
        done: 'Pronto: %s',
        failed: 'Falhou: %s',
        reopen: 'abra o item de novo para ver a resposta'
    } : {
        queuedLocal: 'In analysis by the local AI (position %p, ~%m min)',
        queued: 'Queued for %l (position %p, ~%m min)',
        runningLocal: 'In analysis by the local AI now (~%m min left)',
        running: 'In analysis by %l now (~%m min left)',
        fallback: 'the main provider failed; answering through the fallback',
        title: 'AI queue',
        cancel: 'Cancel',
        done: 'Done: %s',
        failed: 'Failed: %s',
        reopen: 'open the item again to see the answer'
    };
    const jobs = {};                 // id -> {job, label, cb, inline, scenario}

    function esc(value) {
        return String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
        });
    }

    function message(entry) {
        const job = entry.job || {};
        const minutes = Math.max(1, Math.round((job.eta_seconds || 60) / 60));
        const local = /local/i.test(entry.label || '');
        const tpl = job.status === 'running' || job.position === 0 ?
            (local ? S.runningLocal : S.running) : (local ? S.queuedLocal : S.queued);
        let text = tpl.replace('%p', job.position || 1).replace('%m', minutes).replace('%l', entry.label || 'AI');
        if (entry.fallback) {
            text += ' — ' + S.fallback;
        }
        return text;
    }

    function save() {
        try {
            const list = Object.keys(jobs).map(function (id) {
                return {id: id, label: jobs[id].label, scenario: jobs[id].scenario};
            });
            sessionStorage.setItem(STORE, JSON.stringify(list));
        } catch (e) { /* private mode: no persistence */ }
    }

    function panel() {
        let $p = $('#pa-aiq');
        if (!$p.length) {
            style();
            /* panel classes of the theme: colours follow the active OPNsense theme (light or dark) */
            $p = $('<div id="pa-aiq" class="pa-aiq panel panel-default" role="status" aria-live="polite"/>')
                .append($('<div class="pa-aiq-title panel-heading"/>').html('<i class="fa fa-hourglass-half"></i> ' +
                    esc(S.title)))
                .append('<ul class="pa-aiq-list panel-body"/>');
            $('body').append($p);
        }
        return $p;
    }

    function style() {
        if (document.getElementById('pa-aiq-style')) {
            return;
        }
        $('head').append($('<style id="pa-aiq-style"/>').text(
            '.pa-aiq{position:fixed;right:16px;bottom:16px;z-index:1060;max-width:420px;margin:0;' +
            'box-shadow:0 2px 10px rgba(0,0,0,.25)}' +
            '.pa-aiq-title{padding:6px 10px;font-weight:bold}' +
            '.pa-aiq-list{list-style:none;margin:0;padding:6px 10px}' +
            '.pa-aiq-list li{display:flex;align-items:center;gap:6px;padding:2px 0}' +
            '.pa-aiq-text{flex:1}.pa-aiq-cancel{min-width:32px;min-height:32px}' +
            '.pa-aiq-inline{margin:6px 0;font-style:italic}' +
            '.pa-aiq-toast{position:fixed;right:16px;bottom:16px;z-index:1061;max-width:420px;padding:8px 12px;' +
            'border-radius:4px;background:rgba(0,0,0,.8);color:#fff}' +
            '@media (max-width:767px){.pa-aiq,.pa-aiq-toast{left:16px;right:16px;max-width:none;bottom:8px}' +
            '.pa-aiq-cancel{min-width:44px;min-height:44px}}'));
    }

    function render() {
        const ids = Object.keys(jobs);
        const $p = panel();
        const $list = $p.find('.pa-aiq-list').empty();
        ids.forEach(function (id) {
            const entry = jobs[id];
            const $li = $('<li/>').append($('<span class="pa-aiq-text"/>').text(message(entry)));
            $li.append($('<button type="button" class="btn btn-link btn-xs pa-aiq-cancel"/>')
                .attr('title', S.cancel).attr('aria-label', S.cancel).html('<i class="fa fa-times"></i>')
                .on('click', function () { cancel(id); }));
            $list.append($li);
            if (entry.inline) {
                entry.inline.text(message(entry));
            }
        });
        $p.toggle(ids.length > 0);
    }

    function inlineSlot() {
        /* the spinner the module shows while it waits: put the queue message right after it */
        const $spin = $('.modal.in .fa-spinner:visible').last().length ? $('.modal.in .fa-spinner:visible').last()
            : $('.fa-spinner:visible').last();
        if (!$spin.length) {
            return null;
        }
        const $note = $('<div class="pa-aiq-inline text-muted"/>');
        $spin.parent().after($note);
        return $note;
    }

    function finish(id, result) {
        const entry = jobs[id];
        delete jobs[id];
        save();
        if (entry && entry.inline) {
            entry.inline.remove();
        }
        render();
        if (entry && typeof entry.cb === 'function') {
            entry.cb(result);
        } else if (entry && window.BootstrapDialog) {
            const ok = result && result.status === 'ok';
            const $n = $('<div class="pa-aiq-toast"/>').text((ok ? S.done : S.failed).replace('%s', entry.scenario || id) +
                (ok ? ' — ' + S.reopen : (result && result.message ? ' — ' + result.message : '')));
            panel().after($n);
            setTimeout(function () { $n.fadeOut(400, function () { $n.remove(); }); }, 12000);
        }
    }

    function poll(id) {
        $.ajax({url: JOB_URL, data: {id: id}, dataType: 'json', cache: false}).done(function (res) {
            if (!jobs[id]) {
                return;
            }
            const job = res && res.job;
            if (!job) {
                finish(id, {status: 'error', message: (res && res.message) || 'job not found'});
                return;
            }
            jobs[id].job = job;
            if (['queued', 'running'].indexOf(job.status) >= 0) {
                render();
                setTimeout(function () { poll(id); }, POLL_MS);
                return;
            }
            if (job.status === 'cancelled') {
                finish(id, {status: 'error', message: job.error || 'cancelled'});
                return;
            }
            finish(id, res.result || {status: 'error', message: job.error || 'the job ended without a result'});
        }).fail(function () {
            if (jobs[id]) {
                setTimeout(function () { poll(id); }, POLL_MS * 3);
            }
        });
    }

    function cancel(id) {
        /* the unwrapped ajaxCall: same CSRF handling as every POST of the GUI */
        (rawCall || window.ajaxCall)(CANCEL_URL, {id: id}, function () { poll(id); });
    }

    function track(answer, cb) {
        const job = answer.job || {};
        const id = String(job.id);
        const existing = jobs[id];
        jobs[id] = {job: job, label: answer.label || job.label, cb: cb, scenario: answer.scenario,
                    fallback: !!answer.fallback, inline: existing ? existing.inline : inlineSlot()};
        save();
        render();
        if (!existing) {
            setTimeout(function () { poll(id); }, 3000);
        }
    }

    function wrap(orig) {
        if (typeof orig !== 'function' || orig.__paQueue) {
            return orig;
        }
        const wrapped = function (url, data, callback) {
            if (typeof callback !== 'function' || !/^\/api\/policyanalyzer\//.test(url || '')) {
                return orig.apply(this, arguments);
            }
            const args = Array.prototype.slice.call(arguments);
            args[2] = function (res) {
                if (res && res.status === 'queued' && res.job && res.job.id) {
                    track(res, callback);
                    return undefined;
                }
                return callback.apply(this, arguments);
            };
            return orig.apply(this, args);
        };
        wrapped.__paQueue = true;
        return wrapped;
    }

    const rawCall = typeof window.ajaxCall === 'function' ? window.ajaxCall : null;
    if (typeof window.ajaxCall === 'function') {
        window.ajaxCall = wrap(window.ajaxCall);
    }
    if (typeof window.ajaxGet === 'function') {
        window.ajaxGet = wrap(window.ajaxGet);
    }

    $(function () {
        try {
            (JSON.parse(sessionStorage.getItem(STORE) || '[]') || []).forEach(function (item) {
                if (item && item.id && !jobs[item.id]) {
                    jobs[item.id] = {job: {id: item.id, status: 'queued'}, label: item.label, scenario: item.scenario,
                                     cb: null, inline: null};
                    poll(item.id);
                }
            });
            render();
        } catch (e) { /* nothing stored */ }
    });

    return {
        setStrings: function (strings) { S = Object.assign({}, S, strings || {}); render(); },
        track: track,
        pending: function () { return Object.keys(jobs).length; }
    };
})();
