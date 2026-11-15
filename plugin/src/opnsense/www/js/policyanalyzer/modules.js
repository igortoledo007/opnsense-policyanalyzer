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
 * Small helpers shared by the Reports, Vulnerabilities and Devices pages (reports.js, vulns.js, devices.js).
 * Changes always go through PASimulation (simulation.js): plan -> confirmation -> apply -> journal.
 *
 *   PAMod.setStrings({...})                 translated labels (see S)
 *   PAMod.get(url, data, cb) / post(...)     ajaxGet / ajaxCall with a status=error fallback
 *   PAMod.table(cols, rows)                  fixed layout table; each cell carries data-label (mobile cards)
 *   PAMod.simulate(endpoint, action, args, title, onDone)
 *   PAMod.aiDialog({title, intro, preview: fn(cb), ask: fn(cb), cached: fn(cb)})   "what is sent" + "ask the AI"
 *   PAMod.b64url(object)                     UTF-8 JSON -> base64url (payload of reports_settings)
 */
const PAMod = (function () {
    'use strict';

    let S = {
        loading: 'Loading...',
        error: 'Error',
        none: 'Nothing to show.',
        close: 'Close',
        preview: 'Show what is sent',
        ask: 'Ask the AI',
        asking: 'Asking the AI... (it may take a while)',
        aiOff: 'The AI is disabled in the Policy Analyzer settings.',
        aiNote: 'The AI only explains and suggests: nothing is changed. Apply any change yourself, with its simulation.',
        payloadTitle: 'Exactly what would be sent (anonymised when the option is on)',
        model: 'Model',
        cached: 'Stored answer from',
        never: 'never'
    };

    function esc(value) {
        return $('<div/>').text(value === undefined || value === null ? '' : String(value)).html();
    }

    function get(url, data, cb) {
        ajaxGet(url, data || {}, function (res) { cb(res && typeof res === 'object' ? res : {status: 'error'}); });
    }

    function post(url, data, cb) {
        ajaxCall(url, data || {}, function (res) { cb(res && typeof res === 'object' ? res : {status: 'error'}); });
    }

    function chip(text, cls) {
        return '<span class="pa-chip ' + (cls || '') + '">' + esc(text) + '</span>';
    }

    function when(iso) {
        if (!iso) {
            return S.never;
        }
        const d = new Date(typeof iso === 'number' ? iso * 1000 : iso);
        if (isNaN(d.getTime())) {
            return esc(iso);
        }
        return d.toLocaleString(undefined, {day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit',
            minute: '2-digit'});
    }

    /**
     * cols: [{key, label, width, cls}] ; rows: [{cells: {key: html}, cls, attrs}] ; cells are trusted HTML
     */
    function table(cols, rows, opts) {
        opts = opts || {};
        let html = '<table class="pa-tbl ' + (opts.cls || '') + '"><colgroup>';
        cols.forEach(function (c) {
            html += '<col' + (c.width ? ' style="width:' + c.width + '"' : '') + (c.cls ? ' class="' + c.cls + '"' : '') +
                '>';
        });
        html += '</colgroup><thead><tr>';
        cols.forEach(function (c) {
            html += '<th class="' + (c.cls || '') + '" title="' + esc(c.label) + '">' + esc(c.label) + '</th>';
        });
        html += '</tr></thead><tbody>';
        if (!rows.length) {
            html += '<tr><td colspan="' + cols.length + '" class="pa-small">' + esc(opts.empty || S.none) + '</td></tr>';
        }
        rows.forEach(function (r) {
            html += '<tr class="' + (r.cls || '') + '"' + (r.attrs || '') + '>';
            cols.forEach(function (c) {
                const cell = r.cells[c.key];
                html += '<td class="' + (c.cls || '') + (c.key === 'actions' ? ' pa-act' : '') + '" data-label="' +
                    esc(c.label) + '">' + (cell === undefined || cell === null ? '' : cell) + '</td>';
            });
            html += '</tr>';
            if (r.detail) {
                html += '<tr class="pa-detail-row" style="display:none"><td colspan="' + cols.length +
                    '" class="pa-detail-cell">' + r.detail + '</td></tr>';
            }
        });
        return html + '</tbody></table>';
    }

    function b64url(obj) {
        const bytes = new TextEncoder().encode(JSON.stringify(obj));
        let bin = '';
        bytes.forEach(function (b) { bin += String.fromCharCode(b); });
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    /** plain UTF-8 text -> base64url (comments, names) */
    function b64text(text) {
        const bytes = new TextEncoder().encode(String(text));
        let bin = '';
        bytes.forEach(function (b) { bin += String.fromCharCode(b); });
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function simulate(endpoint, action, args, title, onDone, extra) {
        PASimulation.run(Object.assign({endpoint: String(endpoint).replace(/\/+$/, ''), action: action, args: args || [], title: title,
            onDone: onDone}, extra || {}));
    }

    function renderAnswer($box, res) {
        if (!res || res.status === 'disabled') {
            $box.html('<div class="alert alert-warning">' + esc(S.aiOff) + '</div>');
            return;
        }
        if (res.status !== 'ok') {
            $box.html('<div class="alert alert-danger">' + esc(res.message || S.error) + '</div>');
            return;
        }
        if (res.messages) {
            let html = '<div class="pa-small">' + esc(S.payloadTitle) + ' - ' + esc(res.bytes) + ' bytes</div>';
            res.messages.forEach(function (m) {
                html += '<div class="pa-ai-box"><b>' + esc(m.role) + '</b><pre class="pa-text">' + esc(m.content) +
                    '</pre></div>';
            });
            $box.html(html);
            return;
        }
        $box.html('<pre class="pa-text">' + esc(res.text) + '</pre><div class="pa-small" style="margin-top:6px">' +
            esc(S.model) + ': ' + esc(res.model || '-') + (res.cached ? ' - ' + esc(S.cached) + ' ' +
            when(res.generated_at) : '') + '</div><div class="pa-small">' + esc(S.aiNote) + '</div>');
    }

    function aiDialog(opts) {
        const $body = $('<div class="pa-mod-dialog"/>');
        if (opts.intro) {
            $body.append($('<div style="margin-bottom:8px"/>').html(opts.intro));
        }
        const $box = $('<div class="pa-ai-answer"/>').appendTo($body);
        const buttons = [];
        if (opts.preview) {
            buttons.push({label: S.preview, action: function () {
                $box.text(S.loading);
                opts.preview(function (res) { renderAnswer($box, res); });
            }});
        }
        buttons.push({label: S.ask, cssClass: 'btn-primary', action: function () {
            $box.html('<i class="fa fa-spinner fa-spin"></i> ' + esc(S.asking));
            opts.ask(function (res) {
                renderAnswer($box, res);
                if (opts.onAnswer) {
                    opts.onAnswer(res);
                }
            });
        }});
        buttons.push({label: S.close, action: function (d) { d.close(); }});
        PASimulation.dialog({title: opts.title, message: $body, size: BootstrapDialog.SIZE_WIDE, buttons: buttons});
        if (opts.cached) {
            opts.cached(function (res) {
                if (res && res.status === 'ok' && res.text) {
                    renderAnswer($box, res);
                }
            });
        }
    }

    function info(title, html) {
        PASimulation.dialog({title: title, message: $('<div class="pa-mod-dialog"/>').html(html),
            size: BootstrapDialog.SIZE_WIDE, buttons: [{label: S.close, action: function (d) { d.close(); }}]});
    }

    /** --pa-accent from the active tab of the theme, like the Policy Analyzer page */
    function accent(root) {
        const tab = document.querySelector('.nav-tabs > li.active > a') || document.querySelector('.nav-tabs a');
        if (tab && root) {
            root.style.setProperty('--pa-accent', getComputedStyle(tab).color);
        }
    }

    return {
        setStrings: function (s) { S = Object.assign({}, S, s || {}); },
        S: function () { return S; },
        esc: esc, get: get, post: post, chip: chip, when: when, table: table, b64url: b64url, b64text: b64text,
        simulate: simulate,
        aiDialog: aiDialog, info: info, accent: accent, renderAnswer: renderAnswer
    };
})();
