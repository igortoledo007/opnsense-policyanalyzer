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
 * AI Console page (views/OPNsense/PolicyAnalyzer/console.volt), read only.
 *
 *   PAConsole.init({strings: {...}})
 *
 * "Ask the firewall": the question (plus the last turns, kept in sessionStorage of this browser tab) goes to
 * /api/policyanalyzer/console/ask; the backend routes it to read-only collectors, anonymizes the evidence and
 * asks the configured AI. "Show what was sent" shows the exact anonymized messages; "Preview" shows them
 * before anything is sent. "Explain" buttons on the log, rules and alerts viewers call .../console/explain.
 * Answers are rendered with PAMarkdown (escaped first, fixed tags only). Nothing here changes the firewall.
 * Needs: jQuery, BootstrapDialog, ajaxCall/ajaxGet (OPNsense), PASimulation (dialogs + JSON unescape),
 * PAMarkdown.
 */
const PAConsole = (function () {
    'use strict';

    const API = '/api/policyanalyzer/console/';
    const CHAT_KEY = 'pa_console_chat_v1';
    const LANG_KEY = 'pa_console_lang';
    const MAX_TURNS = 30;
    const HISTORY_TURNS = 3;

    let S = {};
    let status = null;
    let chat = [];
    let busy = false;
    const loaded = {};

    function t(key) {
        return S[key] !== undefined ? S[key] : key;
    }

    function esc(value) {
        return PAMarkdown.escape(value);
    }

    function storage(fn) {
        try {
            return fn(window.sessionStorage);
        } catch (e) {
            return null;
        }
    }

    function saveChat() {
        /* keep what was sent only for the newest turns, sessionStorage is small */
        const slim = chat.slice(-MAX_TURNS).map(function (entry, idx, all) {
            if (entry.sent && idx < all.length - 10) {
                return Object.assign({}, entry, {sent: null});
            }
            return entry;
        });
        storage(function (s) { s.setItem(CHAT_KEY, JSON.stringify(slim)); });
    }

    function loadChat() {
        const raw = storage(function (s) { return s.getItem(CHAT_KEY); });
        try {
            chat = (JSON.parse(raw || '[]') || []).filter(function (e) { return e && e.role && e.role !== 'pending'; });
        } catch (e) {
            chat = [];
        }
    }

    function fmtNum(value) {
        if (value === null || value === undefined || value === '') {
            return '';
        }
        return Number(value).toLocaleString();
    }

    function copyText(text, button) {
        const done = function () {
            const $b = $(button);
            const old = $b.html();
            $b.html('<i class="fa fa-check"></i> ' + esc(t('copied')));
            setTimeout(function () { $b.html(old); }, 1500);
        };
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(done, function () {});
            return;
        }
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try {
            document.execCommand('copy');
            done();
        } catch (e) { /* nothing to do */ }
        document.body.removeChild(area);
    }

    /* ---------------------------------------------------------------------------------------------- header */

    function renderStatus() {
        const ai = (status && status.ai) || {};
        let html = '';
        if (!status || status.status !== 'ok') {
            html = '<span class="text-danger">' + esc((status && status.message) || t('error')) + '</span>';
        } else if (!ai.enabled) {
            html = '<span class="pa-c-badge pa-c-warn" title="' + esc(t('aiOffHelp')) + '"><i class="fa fa-power-off"></i> ' +
                esc(t('aiOff')) + '</span>';
        } else {
            html = '<span class="pa-c-badge pa-c-ok"><i class="fa fa-magic"></i> ' + esc(ai.provider_label || ai.provider) +
                (ai.model ? ' · ' + esc(ai.model) : '') + '</span> ' +
                '<span class="pa-c-badge ' + (ai.anonymize ? 'pa-c-ok' : 'pa-c-warn') + '">' +
                '<i class="fa ' + (ai.anonymize ? 'fa-user-secret' : 'fa-exclamation-triangle') + '"></i> ' +
                esc(ai.anonymize ? t('anonymized') : t('notAnonymized')) + '</span>';
        }
        $('#pa_c_state').html(html);
        $('#pa_c_send').prop('disabled', busy || !(ai.enabled));
        $('#pa_c_foot').text(t('disclaimer'));
    }

    function loadStatus() {
        ajaxGet(API + 'status', {}, function (data) {
            status = data || {status: 'error'};
            if (status.ai) {
                const names = {claudecode: 'Claude Code (LAN)', claude: 'Claude', ollama: 'Ollama'};
                status.ai.provider_label = names[status.ai.provider] || status.ai.provider;
            }
            renderStatus();
        });
    }

    function loadSuggestions() {
        ajaxGet(API + 'suggest', {}, function (data) {
            const items = (data && data.suggestions) || [];
            $('#pa_c_suggest').html(items.map(function (q) {
                return '<button type="button" class="btn btn-default btn-xs pa-c-sugg">' + esc(q) + '</button>';
            }).join(''));
            $('.pa-c-sugg').on('click', function () {
                $('#pa_c_question').val($(this).text()).focus();
                if (status && status.ai && status.ai.enabled) {
                    ask(false);
                }
            });
            toggleSuggestions();
        });
    }

    function toggleSuggestions() {
        $('#pa_c_suggest').toggle(chat.length === 0);
    }

    /* ---------------------------------------------------------------------------------------------- answers */

    function sourcesHtml(sources) {
        return (sources || []).map(function (s) {
            let cls = 'pa-c-ok';
            let note = '';
            if (!s.available) {
                cls = 'pa-c-off';
                note = t('unavailable');
            } else if (s.complete === false) {
                cls = 'pa-c-warn';
                note = t('incomplete');
            }
            const title = [note, s.message].filter(Boolean).join(': ');
            return '<span class="pa-c-badge ' + cls + '"' + (title ? ' title="' + esc(title) + '"' : '') + '>' +
                esc(s.name) + (note ? ' · ' + esc(note) : '') + '</span>';
        }).join(' ');
    }

    /**
     * body of an AI answer (chat bubble or explain dialog); the caller adds buttons
     */
    function answerBody(data) {
        if (!data) {
            return '<div class="alert alert-danger">' + esc(t('error')) + '</div>';
        }
        if (data.status === 'refusal') {
            return '<div class="alert alert-warning"><b>' + esc(t('refusal')) + '</b><br>' + esc(data.message) + '</div>';
        }
        if (data.status === 'disabled') {
            return '<div class="alert alert-warning">' + esc(data.message || t('aiOffHelp')) + '</div>';
        }
        if (data.status !== 'ok') {
            return '<div class="alert alert-danger">' + esc(data.message || t('error')) + '</div>';
        }
        let html = PAMarkdown.render(data.text || '');
        if (data.truncated) {
            html += '<div class="alert alert-warning">' + esc(t('truncated')) + '</div>';
        }
        return html;
    }

    function metaLine(data) {
        const bits = [];
        if (data.provider || data.model) {
            bits.push(esc([data.provider, data.model].filter(Boolean).join(' / ')));
        }
        if (data.duration_ms) {
            bits.push(esc(Math.round(data.duration_ms / 100) / 10) + ' ' + esc(t('seconds')));
        }
        if (data.anonymized !== undefined) {
            bits.push(esc(data.anonymized ? t('anonymized') : t('notAnonymized')));
        }
        if (data.plan) {
            bits.push(esc(data.plan.intents.join(', ')) + ' · ' + esc(data.plan.window));
            if (data.plan.carried && data.plan.carried.length) {
                bits.push(esc(t('carried')));
            }
        }
        if (data.history_sent) {
            bits.push(esc(data.history_sent) + ' ' + esc(t('history')));
        }
        if (data.context && data.context.trimmed && data.context.trimmed.length) {
            bits.push('<span title="' + esc(data.context.trimmed.join('\n')) + '">' + esc(t('trimmed')) + '</span>');
        }
        return bits.join(' · ');
    }

    function showMessages(messages, info, title) {
        let html = '<div class="pa-c-sent">';
        if (info) {
            html += '<p>' + info + '</p>';
        }
        html += (messages || []).map(function (m) {
            return '<h5>' + esc(m.role) + '</h5><pre>' + esc(m.content) + '</pre>';
        }).join('') + '</div>';
        PASimulation.dialog({title: title, message: html, size: BootstrapDialog.SIZE_WIDE,
            buttons: [{label: t('close'), action: function (d) { d.close(); }}]});
    }

    function sentInfo(data) {
        const msgs = (data.sent && data.sent.messages) || data.messages || [];
        const bytes = (data.sent && data.sent.bytes) || data.bytes ||
            msgs.reduce(function (n, m) { return n + (m.content || '').length; }, 0);
        return esc(data.anonymized ? t('anonymized') : t('notAnonymized')) + ' · ' + esc(fmtNum(bytes)) + ' ' +
            esc(t('bytes')) + (data.placeholders !== undefined ? ' · ' + esc(data.placeholders) + ' ' +
            esc(t('placeholders')) : '') + (data.sources ? '<br>' + esc(t('sources')) + ': ' +
            sourcesHtml(data.sources) : '');
    }

    /* ---------------------------------------------------------------------------------------------- chat */

    function entryHtml(entry, idx) {
        if (entry.role === 'user') {
            return '<div class="pa-c-msg pa-c-user"><div class="pa-c-bubble">' + esc(entry.text) + '</div></div>';
        }
        if (entry.role === 'pending') {
            return '<div class="pa-c-msg pa-c-ai"><div class="pa-c-bubble"><i class="fa fa-spinner fa-pulse"></i> ' +
                esc(t('thinking')) + '</div></div>';
        }
        const data = entry.data || {};
        let html = '<div class="pa-c-msg pa-c-ai"><div class="pa-c-bubble">' + answerBody(data);
        html += '<div class="pa-c-meta">';
        if (data.status === 'ok') {
            html += '<span>' + metaLine(data) + '</span>';
        }
        html += '</div><div class="pa-c-meta">' + sourcesHtml(data.sources);
        if (entry.sent) {
            html += ' <button type="button" class="btn btn-default btn-xs pa-c-show-sent" data-idx="' + idx + '">' +
                '<i class="fa fa-eye"></i> ' + esc(t('showSent')) + '</button>';
        }
        if (data.status === 'ok') {
            html += ' <button type="button" class="btn btn-default btn-xs pa-c-copy" data-idx="' + idx + '">' +
                '<i class="fa fa-clipboard"></i> ' + esc(t('copy')) + '</button>';
        }
        return html + '</div></div></div>';
    }

    function renderChat() {
        const $chat = $('#pa_c_chat');
        if (!chat.length) {
            $chat.html('<div class="pa-c-empty"><i class="fa fa-info-circle"></i> ' + esc(t('emptyChat')) + '</div>');
        } else {
            $chat.html(chat.map(entryHtml).join(''));
        }
        $chat.find('.pa-c-show-sent').on('click', function () {
            const entry = chat[+$(this).data('idx')];
            showMessages(entry.sent, sentInfo(Object.assign({}, entry.data, {sent: {messages: entry.sent}})),
                t('sentTitle'));
        });
        $chat.find('.pa-c-copy').on('click', function () {
            copyText((chat[+$(this).data('idx')].data || {}).text || '', this);
        });
        $chat.scrollTop($chat[0].scrollHeight);
        toggleSuggestions();
    }

    function historyForRequest() {
        const pairs = [];
        for (let i = 0; i + 1 < chat.length; i++) {
            if (chat[i].role === 'user' && chat[i + 1].role === 'ai' && chat[i + 1].data &&
                chat[i + 1].data.status === 'ok') {
                pairs.push({q: chat[i].text, a: chat[i + 1].data.text});
            }
        }
        return pairs.slice(-HISTORY_TURNS);
    }

    function ask(preview) {
        const question = $('#pa_c_question').val().trim();
        if (question.length < 2 || busy) {
            return;
        }
        const request = {question: question, history: historyForRequest(), language: $('#pa_c_lang').val()};
        if (preview) {
            const $btn = $('#pa_c_preview').prop('disabled', true);
            ajaxCall(API + 'ask', Object.assign({preview: 1}, request), function (data) {
                $btn.prop('disabled', false);
                if (!data || data.status !== 'ok') {
                    PASimulation.dialog({type: BootstrapDialog.TYPE_DANGER, title: t('error'),
                        message: esc((data && data.message) || t('error'))});
                    return;
                }
                showMessages(data.messages, sentInfo(data), t('wouldSendTitle'));
            });
            return;
        }
        busy = true;
        renderStatus();
        chat.push({role: 'user', text: question});
        chat.push({role: 'pending'});
        $('#pa_c_question').val('');
        renderChat();
        ajaxCall(API + 'ask', request, function (data) {
            busy = false;
            chat.pop();
            data = data || {status: 'error', message: t('error')};
            const sent = data.sent ? data.sent.messages : null;
            if (data.sent) {
                delete data.sent.messages;
            }
            chat.push({role: 'ai', data: data, sent: sent});
            if (chat.length > MAX_TURNS * 2) {
                chat = chat.slice(-MAX_TURNS * 2);
            }
            saveChat();
            renderChat();
            renderStatus();
        });
    }

    /* ---------------------------------------------------------------------------------------------- explain */

    function explain(kind, item, title) {
        const enabled = status && status.ai && status.ai.enabled;
        const request = {kind: kind, item: item, language: $('#pa_c_lang').val()};
        const wait = '<p><i class="fa fa-spinner fa-pulse"></i> ' + esc(enabled ? t('thinking') : t('collecting')) + '</p>';
        let result = null;
        const previewButton = {label: t('preview'), action: function () {
            ajaxCall(API + 'explain', Object.assign({preview: 1}, request), function (data) {
                if (!data || data.status !== 'ok') {
                    PASimulation.dialog({type: BootstrapDialog.TYPE_DANGER, title: t('error'),
                        message: esc((data && data.message) || t('error'))});
                    return;
                }
                showMessages(data.messages, sentInfo(data), t('wouldSendTitle'));
            });
        }};
        const sentButton = {label: t('showSent'), id: 'pa_c_explain_sent', action: function () {
            if (result && result.sent) {
                showMessages(result.sent.messages, sentInfo(result), t('sentTitle'));
            }
        }};
        const dialog = PASimulation.dialog({title: title, message: enabled ? wait : '', size: BootstrapDialog.SIZE_WIDE,
            buttons: [enabled ? sentButton : previewButton, {label: t('close'), action: function (d) { d.close(); }}],
            onshown: function (d) {
                if (enabled) {
                    d.getButton('pa_c_explain_sent').disable();
                }
            }});
        if (!enabled) {
            dialog.getModalBody().html('<div class="alert alert-warning">' + esc(t('aiOffHelp')) + '</div>');
            return;
        }
        ajaxCall(API + 'explain', request, function (data) {
            result = data || {status: 'error'};
            let html = answerBody(result);
            if (result.status === 'ok') {
                html += '<p class="text-muted"><small>' + metaLine(result) + '<br>' + sourcesHtml(result.sources) +
                    '<br>' + esc(t('disclaimer')) + ' ' + esc(t('proposalNote')) + '</small></p>';
                const btn = dialog.getButton('pa_c_explain_sent');
                if (btn) {
                    btn.enable();
                }
            }
            dialog.getModalBody().html(html);
        });
    }

    /* ---------------------------------------------------------------------------------------------- viewers */

    function formData($form) {
        const out = {};
        $form.serializeArray().forEach(function (f) {
            if (f.value !== '') {
                out[f.name] = f.value;
            }
        });
        return out;
    }

    function fillInterfaces($select, list, valueKey) {
        if ($select.data('filled') || !list) {
            return;
        }
        list.forEach(function (i) {
            $select.append($('<option>').val(i[valueKey]).text(i.descr && i.descr !== i.name ? i.descr + ' (' + i.name +
                ')' : i.name));
        });
        $select.data('filled', true);
    }

    function explainButton(cls, idx) {
        return '<button type="button" class="btn btn-default btn-xs ' + cls + '" data-idx="' + idx + '">' +
            '<i class="fa fa-magic"></i> ' + esc(t('explain')) + '</button>';
    }

    function actionCell(action) {
        const cls = action === 'block' || action === 'reject' ? 'pa-c-act-block' : (action === 'pass' ? 'pa-c-act-pass' : '');
        const icon = action === 'block' || action === 'reject' ? 'fa-times' : (action === 'pass' ? 'fa-play' : 'fa-circle-o');
        return '<span class="' + cls + '"><i class="fa ' + icon + '"></i> ' + esc(action) + '</span>';
    }

    function loading($table, cols) {
        $table.find('tbody').html('<tr><td colspan="' + cols + '"><i class="fa fa-spinner fa-pulse"></i> ' +
            esc(t('loading')) + '</td></tr>');
    }

    function loadLog() {
        const $table = $('#pa_c_log_table');
        loading($table, 9);
        ajaxGet(API + 'log', formData($('#pa_c_log_form')), function (data) {
            if (!data || data.status !== 'ok') {
                $table.find('tbody').html('<tr><td colspan="9" class="text-danger">' + esc((data && data.message) ||
                    t('error')) + '</td></tr>');
                return;
            }
            fillInterfaces($('#pa_c_log_form select[name=iface]'), data.interfaces, 'name');
            const rows = data.rows || [];
            const meta = data.meta || {};
            $('#pa_c_log_info').text(fmtNum(rows.length) + ' · ' + fmtNum(meta.lines_read) + ' ' + t('linesRead') +
                (meta.complete === false ? ' · ' + t('partialRead') : ''));
            if (!rows.length) {
                $table.find('tbody').html('<tr><td colspan="9">' + esc(t('noRows')) + '</td></tr>');
                return;
            }
            $table.find('tbody').html(rows.map(function (r, idx) {
                return '<tr>' +
                    '<td data-label="' + esc(t('time')) + '" class="pa-c-nowrap">' + esc(r.time) + '</td>' +
                    '<td data-label="' + esc(t('iface')) + '">' + esc(r.interface_name || r.interface) +
                    '<span class="pa-c-sub">' + esc(r.interface) + '</span></td>' +
                    '<td data-label="' + esc(t('action')) + '">' + actionCell(r.action) + '</td>' +
                    '<td data-label="' + esc(t('dir')) + '" class="pa-c-hide-md">' + esc(r.dir) + '</td>' +
                    '<td data-label="' + esc(t('proto')) + '" class="pa-c-hide-md">' + esc(r.proto) + '</td>' +
                    '<td data-label="' + esc(t('src')) + '">' + esc(r.src) + '</td>' +
                    '<td data-label="' + esc(t('dst')) + '">' + esc(r.dst) + '</td>' +
                    '<td data-label="' + esc(t('rule')) + '">' + esc(r.rule) + '</td>' +
                    '<td class="pa-c-act">' + explainButton('pa-c-explain-log', idx) + '</td></tr>';
            }).join(''));
            $table.find('.pa-c-explain-log').on('click', function () {
                const r = rows[+$(this).data('idx')];
                explain('log', {ts: r.ts, iface: r.interface, action: r.action, dir: r.dir, proto: r.proto, src: r.src_ip,
                    sport: r.sport, dst: r.dst_ip, dport: r.dport, rid: r.rid}, t('explainTitleLog'));
            });
        });
    }

    function findingBadges(findings) {
        return (findings || []).map(function (f) {
            const cls = f.severity === 'high' ? 'pa-c-warn' : 'pa-c-ok';
            return '<span class="pa-c-badge ' + cls + '" title="' + esc(f.title) + '">' + esc(f.type) + '</span>';
        }).join(' ');
    }

    function loadRules() {
        const $table = $('#pa_c_rules_table');
        loading($table, 9);
        const req = formData($('#pa_c_rules_form'));
        ajaxGet(API + 'rules', req, function (data) {
            if (!data || data.status !== 'ok') {
                $table.find('tbody').html('<tr><td colspan="9" class="text-danger">' + esc((data && data.message) ||
                    t('error')) + '</td></tr>');
                return;
            }
            fillInterfaces($('#pa_c_rules_form select[name=iface]'), data.interfaces, 'name');
            const rows = data.rows || [];
            const since = data.stats && data.stats.counters_since;
            $('#pa_c_rules_info').text(fmtNum(rows.length) + ' / ' + fmtNum(data.total) + ' · ' +
                (data.stats_available ? t('countersSince') + ' ' + (since || '?') : t('noCounters')));
            if (!rows.length) {
                $table.find('tbody').html('<tr><td colspan="9">' + esc(t('noRows')) + '</td></tr>');
                return;
            }
            $table.find('tbody').html(rows.map(function (r, idx) {
                const c = r.counters || {};
                const where = r.priority_group === 'floating' ? t('floating') + (r.interface ? ': ' + r.interface : '') :
                    (r.interface || t('any'));
                const canExplain = /^[0-9a-f-]{36}$/.test(r.uuid || '');
                return '<tr' + (r.enabled ? '' : ' style="opacity: .6"') + '>' +
                    '<td data-label="#">' + esc(r.position) + '</td>' +
                    '<td data-label="' + esc(t('iface')) + '">' + esc(where) + '</td>' +
                    '<td data-label="' + esc(t('action')) + '">' + actionCell(r.action) +
                    (r.enabled ? '' : '<span class="pa-c-sub">' + esc(t('disabled')) + '</span>') + '</td>' +
                    '<td data-label="' + esc(t('description')) + '">' + esc(r.description || '—') +
                    '<span class="pa-c-sub">' + esc(r.summary) + '</span></td>' +
                    '<td data-label="' + esc(t('evaluations')) + '" class="pa-c-num pa-c-hide-md">' +
                    esc(fmtNum(c.evaluations)) + '</td>' +
                    '<td data-label="' + esc(t('packets')) + '" class="pa-c-num">' + esc(fmtNum(c.packets)) + '</td>' +
                    '<td data-label="' + esc(t('states')) + '" class="pa-c-num pa-c-hide-md">' + esc(fmtNum(c.states)) +
                    '</td>' +
                    '<td data-label="' + esc(t('findings')) + '">' + findingBadges(r.findings) + '</td>' +
                    '<td class="pa-c-act">' + (canExplain ? explainButton('pa-c-explain-rule', idx) : '') +
                    (r.ref ? ' <a class="btn btn-default btn-xs" target="_blank" rel="noopener" href="/' + esc(r.ref) +
                        '" title="' + esc(t('openRule')) + '"><i class="fa fa-external-link"></i></a>' : '') +
                    '</td></tr>';
            }).join(''));
            $table.find('.pa-c-explain-rule').on('click', function () {
                explain('rule', {uuid: rows[+$(this).data('idx')].uuid}, t('explainTitleRule'));
            });
        });
    }

    function loadAlerts() {
        const $table = $('#pa_c_alerts_table');
        loading($table, 7);
        ajaxGet(API + 'alerts', formData($('#pa_c_alerts_form')), function (data) {
            if (!data || data.status !== 'ok') {
                $table.find('tbody').html('<tr><td colspan="7" class="text-danger">' + esc((data && data.message) ||
                    t('error')) + '</td></tr>');
                return;
            }
            const rows = data.rows || [];
            const meta = data.meta || {};
            $('#pa_c_alerts_info').text(meta.available === false ? t('noEve') : fmtNum(rows.length) + ' · ' +
                fmtNum(meta.lines_read) + ' ' + t('linesRead') + (meta.complete === false ? ' · ' + t('partialRead') : ''));
            if (!rows.length) {
                $table.find('tbody').html('<tr><td colspan="7">' + esc(t('noRows')) + '</td></tr>');
                return;
            }
            $table.find('tbody').html(rows.map(function (r, idx) {
                return '<tr>' +
                    '<td data-label="' + esc(t('time')) + '" class="pa-c-nowrap">' + esc(r.time) + '</td>' +
                    '<td data-label="' + esc(t('severity')) + '"><span class="pa-c-sev pa-c-sev-' + esc(r.severity) + '">' +
                    esc(r.severity) + '</span></td>' +
                    '<td data-label="' + esc(t('signature')) + '">' + esc(r.signature) + '<span class="pa-c-sub">' +
                    esc(r.classification || '') + ' · sid ' + esc(r.sid) + '</span></td>' +
                    '<td data-label="' + esc(t('src')) + '">' + esc(r.src) + '</td>' +
                    '<td data-label="' + esc(t('dst')) + '">' + esc(r.dst) + '</td>' +
                    '<td data-label="' + esc(t('action')) + '" class="pa-c-hide-md">' + esc(r.action || '') + '</td>' +
                    '<td class="pa-c-act">' + explainButton('pa-c-explain-alert', idx) + '</td></tr>';
            }).join(''));
            $table.find('.pa-c-explain-alert').on('click', function () {
                const r = rows[+$(this).data('idx')];
                explain('alert', {timestamp: r.timestamp, flow_id: r.flow_id, sid: r.sid}, t('explainTitleAlert'));
            });
        });
    }

    /* ---------------------------------------------------------------------------------------------- init */

    function showTab(name) {
        if (loaded[name]) {
            return;
        }
        loaded[name] = true;
        if (name === 'log') {
            loadLog();
        } else if (name === 'rules') {
            loadRules();
        } else if (name === 'alerts') {
            loadAlerts();
        }
    }

    function init(opts) {
        S = Object.assign({}, (opts && opts.strings) || {});
        const activeTab = document.querySelector('#pa_console #maintabs > li.active > a');
        if (activeTab) {
            document.getElementById('pa_console').style.setProperty('--pa-accent', getComputedStyle(activeTab).color);
        }
        const lang = storage(function (s) { return window.localStorage.getItem(LANG_KEY); });
        if (lang && /^(auto|pt_BR|en_US)$/.test(lang)) {
            $('#pa_c_lang').val(lang);
        }
        $('#pa_c_lang').on('change', function () {
            const value = $(this).val();
            storage(function () { window.localStorage.setItem(LANG_KEY, value); });
        });
        $('#pa_c_question').attr('placeholder', t('placeholder')).on('keydown', function (e) {
            if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
                e.preventDefault();
                ask(false);
            }
        });
        $('#pa_c_form').on('submit', function (e) {
            e.preventDefault();
            ask(false);
        });
        $('#pa_c_preview').on('click', function () { ask(true); });
        $('#pa_c_clear').on('click', function () {
            chat = [];
            saveChat();
            renderChat();
        });
        $('#pa_c_log_form').on('submit', function (e) { e.preventDefault(); loadLog(); });
        $('#pa_c_rules_form').on('submit', function (e) { e.preventDefault(); loadRules(); });
        $('#pa_c_rules_form input[name=unused], #pa_c_rules_form select').on('change', loadRules);
        $('#pa_c_log_form select').on('change', loadLog);
        $('#pa_c_alerts_form').on('submit', function (e) { e.preventDefault(); loadAlerts(); });
        $('#pa_c_alerts_form select').on('change', loadAlerts);
        $('#pa_console #maintabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            const name = $(e.target).attr('href').substring(1);
            showTab(name);
            if (history.replaceState) {
                history.replaceState(null, '', '#' + name);
            }
        });
        const hash = (window.location.hash || '').substring(1);
        if (/^(log|rules|alerts)$/.test(hash)) {
            $('#pa_console #maintabs a[href="#' + hash + '"]').tab('show');
        }
        // links from other pages (Anomalies, Incidents): #host=<ip> prefills a question about that host
        const hostMatch = hash.match(/^host=([0-9a-fA-F:.]{2,45})$/);
        if (hostMatch) {
            const lang = ($('#pa_c_lang').val() || '').indexOf('pt') === 0 || (navigator.language || '').indexOf('pt') === 0;
            $('#pa_c_question').val(lang ? 'O que o host ' + hostMatch[1] + ' fez nas últimas 24 horas? Algo fora do normal?'
                : 'What did host ' + hostMatch[1] + ' do in the last 24 hours? Anything unusual?').focus();
        }
        loadChat();
        renderChat();
        renderStatus();
        loadStatus();
        loadSuggestions();
    }

    return {init: init, render: PAMarkdown.render};
})();
