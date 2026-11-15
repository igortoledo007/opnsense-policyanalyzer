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
 * Reports and notification center (reports.volt): e-mail channel (Use Monit settings by reference, or Import
 * from Monit into own editable settings), periodic report (6 h / daily) with preview, subscriptions to events
 * with minimum severity and throttle, queue/history with resend, sent e-mails. API: /api/policyanalyzer/reports/*.
 * The report e-mail carries the report as a PDF attachment ("Attach PDF"); "Download PDF" fetches the same PDF.
 * Every change is a simulation first (reports_settings, reports_import_monit, reports_send_test).
 */
const PAReports = (function () {
    'use strict';

    const API = '/api/policyanalyzer/reports/';
    const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
    const DEFAULTS = {
        title: 'Reports and notifications',
        subtitle: 'Security report every 6 h / daily and e-mail alerts, through the e-mail setup of Monit.',
        refresh: 'Refresh',
        tabChannel: 'E-mail channel', tabReports: 'Periodic report', tabNotify: 'Notifications', tabHistory: 'Sent e-mails',
        modeMonit: 'Use Monit settings', modeMonitHelp: 'Server, port, TLS, user, password, sender and recipients are read from Services > Monit at every send: always in sync, nothing is copied.',
        modeOwn: 'Own settings (imported from Monit or typed)', modeOwnHelp: 'Independent copy, editable here. The password is kept as a masked secret and never shown.',
        active: 'Active', origin: 'Origin', field: 'Field', value: 'Value',
        host: 'SMTP server', port: 'Port', security: 'Security', verify: 'Verify certificate', minTls: 'Minimum TLS',
        username: 'User', password: 'Password', passwordKeep: 'empty: keep %s', passwordNone: 'empty: no password',
        sender: 'Sender', recipients: 'Recipients', recipientsHelp: 'Comma separated',
        recipientsMonit: 'Recipients (empty: the Monit alert recipients)',
        guiUrl: 'Address of this GUI for the links in the e-mails', guiUrlHelp: 'Used by "Open in OPNsense" and every link of the reports and notifications (e.g. the public name of the firewall).',
        monitMissing: 'Monit has no mail server configured (Services > Monit > Settings).',
        channelBroken: 'The channel is not usable yet: %s',
        saveChannel: 'Save channel', importMonit: 'Import from Monit', importTitle: 'Import the Monit e-mail settings',
        sendTest: 'Send test', sendTestTitle: 'Send a test e-mail',
        saveTitle: 'Save reports and notifications settings',
        repEnabled: 'Send the periodic report', every6h: 'Every 6 hours', daily: 'Daily at', onlyEvents: 'Every 6 h only when something happened',
        aiSummary: 'Executive summary by the AI (fixed text when the AI is off)', language: 'Language',
        attachPdf: 'Attach the report as PDF', downloadPdf: 'Download PDF', pdfError: 'Unable to build the PDF.',
        sections: 'Sections', sec_posture: 'Posture (exposure)', sec_quarantine: 'Quarantine', sec_findings: 'Policy Analyzer findings',
        sec_traffic: 'Top blocks, ports and countries', sec_cves: 'Relevant CVEs', sec_devices: 'Devices',
        sec_notifications: 'Notifications sent', sec_ai_summary: 'AI executive summary',
        saveReports: 'Save report settings', preview: 'Preview', previewAi: 'Preview with AI summary',
        sendNow: 'Send report now', sendNowTitle: 'Send the report now', htmlView: 'HTML', textView: 'Text',
        cronState: 'Scheduled jobs (System > Settings > Cron)', cronNone: 'none', cronPending: 'saving will change the jobs',
        notifyEnabled: 'Notification center enabled', notifyOn: 'enabled', notifyOff: 'disabled',
        lastRun: 'last run %s', colEvent: 'Event', colSource: 'Source', colSubscribe: 'Subscribe',
        colMinSev: 'Minimum severity', colThrottle: 'Throttle (min)', unavailable: 'module not installed',
        maxPerHour: 'At most e-mails per hour', notifyAi: 'Short AI summary in each alert (fixed text when the AI is off)',
        saveNotify: 'Save notification settings', checkSources: 'Check sources now',
        sourcesTitle: 'What the sources see now (nothing is queued or sent)',
        queue: 'Queue and history', allStatus: 'All', st_queued: 'queued', st_held: 'held (throttle)', st_sent: 'sent',
        st_failed: 'failed', st_suppressed: 'suppressed',
        colWhen: 'When', colType: 'Type', colSev: 'Severity', colTitle: 'Title', colStatus: 'Status', colActions: 'Actions',
        resend: 'Resend', resendConfirm: 'Send this notification again now (an e-mail can not be unsent)?',
        open: 'Open', colSubject: 'Subject', colTo: 'To', colKind: 'Kind', colAi: 'AI', view: 'View',
        throttleHelp: 'Events of the same type inside the throttle window are grouped into one digest e-mail.',
        events: 'events', none: 'none'
    };
    let S = Object.assign({}, DEFAULTS);
    let state = null;
    let noteFilter = '';
    let previewAi = false;
    const E = function (v) { return PAMod.esc(v); };

    function fmt(text) {
        const args = Array.prototype.slice.call(arguments, 1);
        return String(text).replace(/%s/g, function () { return args.length ? args.shift() : ''; });
    }

    function load() {
        PAMod.get(API + 'settings', {}, function (res) {
            state = res;
            renderChannel();
            renderReports();
            renderNotify();
        });
        loadNotes();
        loadHistory();
    }

    function cfg() {
        return JSON.parse(JSON.stringify(state.settings));
    }

    function save(payload, title) {
        PAMod.simulate(API, 'reports_settings', [PAMod.b64url(payload)], title || S.saveTitle, load);
    }

    // ------------------------------------------------------------------ channel

    function renderChannel() {
        const s = state.settings.email;
        const eff = state.effective || {};
        const mon = state.monit || {};
        const $c = $('#par_channel').empty();
        const mode = function (value, label, help) {
            return '<label class="pa-mode' + (s.mode === value ? ' pa-on' : '') + '"><input type="radio" name="par_mode" ' +
                'value="' + value + '"' + (s.mode === value ? ' checked' : '') + '><span><b>' + E(label) +
                (s.mode === value ? ' ' + PAMod.chip(S.active, 'pa-ok') : '') + '</b><span class="pa-small">' + E(help) +
                '</span></span></label>';
        };
        $c.append('<div class="pa-modes">' + mode('monit', S.modeMonit, S.modeMonitHelp) +
            mode('own', S.modeOwn, S.modeOwnHelp) + '</div>');
        if (!mon.available) {
            $c.append('<div class="pa-mod-note pa-warn" style="margin:0 0 8px">' + E(S.monitMissing) + '</div>');
        }
        if (!eff.available) {
            $c.append('<div class="pa-mod-note pa-warn" style="margin:0 0 8px">' + E(fmt(S.channelBroken,
                eff.message || '-')) + '</div>');
        }
        const own = s.mode === 'own';
        const orig = own ? 'plugin' : 'Monit';
        const rows = [[S.host, eff.host, orig], [S.port, eff.port, orig], [S.security, eff.security, orig],
            [S.verify, eff.verify ? 'yes' : 'no', orig], [S.minTls, eff.min_tls, orig],
            [S.username, eff.username || '-', orig], [S.password, eff.password_hint || '-', own ? 'plugin (secret)' : 'Monit'],
            [S.sender, eff.sender, own ? 'plugin' : (mon.sender_source || 'Monit')],
            [S.recipients, (eff.recipients || []).join(', ') || '-', eff.recipients_origin || '-']];
        $c.append('<div class="pa-split"><div>' + PAMod.table([{key: 'f', label: S.field, width: '34%'},
            {key: 'v', label: S.value}, {key: 'o', label: S.origin, width: '30%'}], rows.map(function (r) {
            return {cells: {f: E(r[0]), v: E(r[1] === undefined ? '-' : r[1]), o: '<span class="pa-small">' + E(r[2]) +
                '</span>'}};
        }), {cls: 'pa-kv'}) + '<div class="pa-small" style="margin-top:4px">' + E(eff.origin || '') + '</div></div><div id="par_ownform"></div></div>');
        const field = function (key, label, html) {
            return '<div><label for="par_' + key + '">' + E(label) + '</label>' + html + '</div>';
        };
        let form = '<div class="pa-form-grid">';
        if (own) {
            form += field('host', S.host, '<input class="form-control" id="par_host" value="' + E(s.host) + '">') +
                field('port', S.port, '<input class="form-control" id="par_port" type="number" min="1" max="65535" value="' +
                    E(s.port) + '">') +
                field('security', S.security, '<select class="form-control" id="par_security">' + ['starttls', 'ssl', 'none']
                    .map(function (v) { return '<option' + (v === s.security ? ' selected' : '') + '>' + v + '</option>'; })
                    .join('') + '</select>') +
                field('min_tls', S.minTls, '<select class="form-control" id="par_min_tls">' + ['auto', 'tlsv12', 'tlsv13']
                    .map(function (v) { return '<option' + (v === s.min_tls ? ' selected' : '') + '>' + v + '</option>'; })
                    .join('') + '</select>') +
                field('username', S.username, '<input class="form-control" id="par_username" autocomplete="off" value="' +
                    E(s.username) + '">') +
                field('password', S.password, '<input class="form-control" id="par_password" type="password" ' +
                    'autocomplete="new-password" placeholder="' + E(state.password_hint ? fmt(S.passwordKeep,
                        state.password_hint) : S.passwordNone) + '">') +
                field('sender', S.sender, '<input class="form-control" id="par_sender" value="' + E(s.sender) + '">') +
                '<div><label><input type="checkbox" id="par_verify"' + (s.verify ? ' checked' : '') + '> ' + E(S.verify) +
                '</label></div>';
        }
        form += '<div class="pa-wide">' + '<label for="par_recipients">' + E(own ? S.recipients : S.recipientsMonit) +
            '</label><input class="form-control" id="par_recipients" value="' + E((s.recipients || []).join(', ')) +
            '" placeholder="' + E(own ? S.recipientsHelp : (mon.recipients || []).join(', ')) + '"></div>';
        // base of the links in the e-mails: the address used to reach this GUI (not the internal hostname)
        const gui = (state.settings && state.settings.gui_url) || window.location.origin;
        form += '<div class="pa-wide"><label for="par_gui_url">' + E(S.guiUrl) + '</label><input class="form-control" ' +
            'id="par_gui_url" value="' + E(gui) + '" placeholder="https://fw.example.com"><small class="text-muted">' +
            E(S.guiUrlHelp) + '</small></div></div>';
        form += '<div class="pa-buttons"><button type="button" class="btn btn-primary btn-sm" id="par_save_channel">' +
            '<i class="fa fa-floppy-o"></i> ' + E(S.saveChannel) + '</button>' +
            '<button type="button" class="btn btn-default btn-sm" id="par_import"' + (mon.available ? '' : ' disabled') +
            '><i class="fa fa-download"></i> ' + E(S.importMonit) + '</button>' +
            '<button type="button" class="btn btn-default btn-sm" id="par_test"' + (eff.available ? '' : ' disabled') +
            '><i class="fa fa-paper-plane"></i> ' + E(S.sendTest) + '</button></div>';
        $('#par_ownform').html(form);
    }

    function channelPayload() {
        const c = cfg();
        const own = $('input[name=par_mode]:checked').val() === 'own';
        c.email.mode = own ? 'own' : 'monit';
        c.email.recipients = ($('#par_recipients').val() || '').split(/[\s,;]+/).filter(Boolean);
        if ($('#par_gui_url').length) {
            c.gui_url = ($('#par_gui_url').val() || '').trim().replace(/\/+$/, '');
        }
        if (own && $('#par_host').length) {
            c.email.host = $('#par_host').val().trim();
            c.email.port = parseInt($('#par_port').val(), 10) || 587;
            c.email.security = $('#par_security').val();
            c.email.min_tls = $('#par_min_tls').val();
            c.email.username = $('#par_username').val().trim();
            c.email.sender = $('#par_sender').val().trim();
            c.email.verify = $('#par_verify').prop('checked');
            const pwd = $('#par_password').val();
            if (pwd) {
                c.password = pwd;
            }
        }
        return c;
    }

    // ------------------------------------------------------------------ reports

    function renderReports() {
        const r = state.settings.report;
        const want = state.desired_crons || {};
        const have = state.installed_crons || {};
        let hours = '';
        for (let h = 0; h < 24; h++) {
            hours += '<option value="' + h + '"' + (h === r.daily_hour ? ' selected' : '') + '>' + String(h).padStart(2, '0') +
                ':00</option>';
        }
        const check = function (id, label, on) {
            return '<label><input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + '> ' + E(label) + '</label>';
        };
        const crons = Object.keys(have).map(function (k) {
            return E(k + ' (' + have[k].minutes + ' ' + have[k].hours + ')');
        }).join(', ') || E(S.cronNone);
        $('#par_reports').html(
            '<div class="pa-checks">' + check('par_r_enabled', S.repEnabled, r.enabled) + check('par_r_6h', S.every6h, r.every_6h) +
            '<span>' + check('par_r_daily', S.daily, r.daily) + ' <select class="form-control pa-inline" id="par_r_hour">' + hours + '</select></span>' +
            check('par_r_only', S.onlyEvents, r.only_with_events) + check('par_r_ai', S.aiSummary, r.ai_summary) +
            check('par_r_pdf', S.attachPdf, r.attach_pdf !== false) +
            '<label>' + E(S.language) + ' <select class="form-control pa-inline" id="par_lang"><option value="pt_BR">Português (Brasil)</option><option value="en_US">English</option>' +
            '</select></label></div>' +
            '<div><b>' + E(S.sections) + '</b><div class="pa-checks">' + (state.sections || []).map(function (sec) {
                return '<label><input type="checkbox" class="par-sec" value="' + sec + '"' + (r.sections.indexOf(sec) >= 0 ?
                    ' checked' : '') + '> ' + E(S['sec_' + sec] || sec) + '</label>';
            }).join('') + '</div></div>' +
            '<div class="pa-small">' + E(S.cronState) + ': ' + crons + (JSON.stringify(Object.keys(want).sort()) !==
                JSON.stringify(Object.keys(have).sort()) ? ' &middot; <i>' + E(S.cronPending) + '</i>' : '') + '</div>' +
            '<div class="pa-buttons"><button type="button" class="btn btn-primary btn-sm" id="par_save_reports"><i class="fa ' +
            'fa-floppy-o"></i> ' + E(S.saveReports) + '</button><button type="button" class="btn btn-default btn-sm" ' +
            'id="par_preview"><i class="fa fa-eye"></i> ' + E(S.preview) + '</button><button type="button" class="btn ' +
            'btn-default btn-sm" id="par_preview_ai"><i class="fa fa-magic"></i> ' + E(S.previewAi) + '</button>' +
            '<button type="button" class="btn btn-default btn-sm" id="par_pdf"><i class="fa fa-file-pdf-o"></i> ' +
            E(S.downloadPdf) + '</button>' +
            '<button type="button" class="btn btn-default btn-sm" id="par_send_now"' + ((state.effective || {}).available ? '' :
                ' disabled') + '><i class="fa fa-paper-plane"></i> ' + E(S.sendNow) + '</button>' +
            '<span class="pa-right btn-group" role="group" style="margin-left:auto"><button type="button" class="btn btn-xs ' +
            'btn-default active" data-view="html">' + E(S.htmlView) + '</button><button type="button" class="btn btn-xs ' +
            'btn-default" data-view="text">' + E(S.textView) + '</button></span></div>' +
            '<div id="par_preview_box"></div>');
        $('#par_lang').val(state.settings.language);
    }

    function reportsPayload() {
        const c = cfg();
        c.report.enabled = $('#par_r_enabled').prop('checked');
        c.report.every_6h = $('#par_r_6h').prop('checked');
        c.report.daily = $('#par_r_daily').prop('checked');
        c.report.daily_hour = parseInt($('#par_r_hour').val(), 10);
        c.report.only_with_events = $('#par_r_only').prop('checked');
        c.report.ai_summary = $('#par_r_ai').prop('checked');
        c.report.attach_pdf = $('#par_r_pdf').prop('checked');
        c.report.sections = $('.par-sec:checked').map(function () { return this.value; }).get();
        c.language = $('#par_lang').val();
        return c;
    }

    function showPreview(res, view) {
        const $box = $('#par_preview_box');
        if (!res || res.status !== 'ok') {
            $box.html('<div class="alert alert-danger">' + E((res && res.message) || 'error') + '</div>');
            return;
        }
        $box.data('preview', res);
        if (view === 'text') {
            $box.html('<pre class="pa-text" style="max-height:calc(100vh - 260px);overflow:auto">' + E(res.text) + '</pre>');
            return;
        }
        const frame = document.createElement('iframe');
        frame.className = 'pa-preview-frame';
        frame.setAttribute('sandbox', '');          // no scripts, no same origin: it is only the e-mail
        frame.setAttribute('title', res.subject || 'preview');
        frame.srcdoc = res.html;
        $box.empty().append($('<div class="pa-small"/>').text(res.subject + ' - ' + Math.round(res.size / 1024) + ' KiB'))
            .append(frame);
    }

    /* the PDF comes back as a binary attachment (application/pdf); an error comes back as JSON */
    function downloadPdf(button) {
        const $btn = $(button).prop('disabled', true);
        const $icon = $btn.find('i').attr('class', 'fa fa-spinner fa-spin');
        const fail = function (msg) {
            BootstrapDialog.show({type: BootstrapDialog.TYPE_DANGER, title: S.downloadPdf, message: msg || S.pdfError});
        };
        $.ajax({url: API + 'pdf', method: previewAi ? 'POST' : 'GET',
            data: previewAi ? {kind: 'manual', ai: '1'} : {kind: 'manual'},
            xhrFields: {responseType: 'blob'}, dataType: 'binary', converters: {'* binary': function (v) { return v; }}
        }).done(function (blob, _status, xhr) {
            if (!(blob instanceof Blob) || !/application\/pdf/.test(xhr.getResponseHeader('Content-Type') || '')) {
                if (blob instanceof Blob && blob.text) {
                    blob.text().then(function (txt) {
                        let msg = null;
                        try { msg = JSON.parse(txt).message; } catch (e) { msg = null; }
                        fail(msg);
                    });
                } else {
                    fail();
                }
                return;
            }
            const match = /filename="?([^";]+)"?/.exec(xhr.getResponseHeader('Content-Disposition') || '');
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = match ? match[1] : 'opnsense-relatorio.pdf';
            document.body.appendChild(a);
            a.click();
            a.remove();
            setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
        }).fail(function () { fail(); }).always(function () {
            $icon.attr('class', 'fa fa-file-pdf-o');
            $btn.prop('disabled', false);
        });
    }

    // ------------------------------------------------------------------ notifications

    function renderNotify() {
        PAMod.get(API + 'notifications', {rows: 1}, function (ov) {
            const n = state.settings.notify;
            const avail = {};
            ((ov && ov.events) || []).forEach(function (e) { avail[e.type] = e.available; });
            const rows = Object.keys(state.events || {}).map(function (key) {
                const ev = state.events[key];
                const sub = n.events[key];
                const ok = avail[key] !== false;
                return {cls: ok ? '' : 'pa-unavailable', cells: {
                    ev: E(ev.label), src: '<span class="pa-dot ' + (ok ? 'pa-on-dot' : 'pa-off-dot') + '"></span>' +
                        E(ev.source) + (ok ? '' : '<div class="pa-small">' + E(S.unavailable) + '</div>'),
                    sub: '<input type="checkbox" class="par-ev-on" data-ev="' + key + '"' + (sub.enabled ? ' checked' : '') +
                        (ok ? '' : ' disabled') + (key === 'report' ? ' disabled title="' + E(S.tabReports) + '"' : '') + '>',
                    sev: '<select class="form-control input-sm par-ev-sev" data-ev="' + key + '"' + (ok ? '' : ' disabled') + '>' +
                        SEVERITIES.map(function (s) {
                            return '<option' + (s === sub.min_severity ? ' selected' : '') + '>' + s + '</option>';
                        }).join('') + '</select>',
                    thr: '<input type="number" class="form-control input-sm par-ev-thr" min="0" max="10080" data-ev="' + key +
                        '" value="' + E(sub.throttle_minutes) + '"' + (ok ? '' : ' disabled') + '>'}};
            });
            $('#par_notify').html('<div class="pa-mod-toolbar"><label style="margin:0"><input type="checkbox" ' +
                'id="par_n_enabled"' + (n.enabled ? ' checked' : '') + '> <b>' + E(S.notifyEnabled) + '</b></label> ' +
                PAMod.chip(n.enabled ? S.notifyOn : S.notifyOff, n.enabled ? 'pa-ok' : 'pa-muted-chip') +
                '<span class="pa-small">' + E(fmt(S.lastRun, PAMod.when(ov && ov.last_run))) + '</span>' +
                '<span class="pa-right"><button type="button" class="btn btn-default btn-sm" id="par_sources"><i class="fa ' +
                'fa-search"></i> ' + E(S.checkSources) + '</button></span></div>' +
                PAMod.table([{key: 'ev', label: S.colEvent}, {key: 'src', label: S.colSource, width: '15%'},
                    {key: 'sub', label: S.colSubscribe, width: '90px'}, {key: 'sev', label: S.colMinSev, width: '130px'},
                    {key: 'thr', label: S.colThrottle, width: '110px'}], rows) +
                '<div class="pa-checks" style="margin-top:8px"><label>' + E(S.maxPerHour) + ' <input type="number" ' +
                'class="form-control" id="par_n_max" min="1" max="60" value="' + E(n.max_per_hour) + '" style="display:' +
                'inline-block;width:80px;height:26px"></label><label><input type="checkbox" id="par_n_ai"' +
                (n.ai_summary ? ' checked' : '') + '> ' + E(S.notifyAi) + '</label></div><div class="pa-small">' +
                E(S.throttleHelp) + '</div><div class="pa-buttons"><button type="button" class="btn btn-primary btn-sm" ' +
                'id="par_save_notify"><i class="fa fa-floppy-o"></i> ' + E(S.saveNotify) + '</button></div>');
        });
    }

    function notifyPayload() {
        const c = cfg();
        c.notify.enabled = $('#par_n_enabled').prop('checked');
        c.notify.max_per_hour = parseInt($('#par_n_max').val(), 10) || 6;
        c.notify.ai_summary = $('#par_n_ai').prop('checked');
        $('.par-ev-on').each(function () { c.notify.events[$(this).data('ev')].enabled = this.checked; });
        $('.par-ev-sev').each(function () { c.notify.events[$(this).data('ev')].min_severity = $(this).val(); });
        $('.par-ev-thr').each(function () {
            c.notify.events[$(this).data('ev')].throttle_minutes = Math.max(0, parseInt($(this).val(), 10) || 0);
        });
        return c;
    }

    function loadNotes() {
        PAMod.get(API + 'notifications', {rows: 100, status: noteFilter}, function (res) {
            const rows = ((res && res.rows) || []).map(function (n) {
                return {cells: {
                    when: PAMod.when(n.ts_iso), type: E(n.type), sev: PAMod.chip(n.severity, 'pa-' + n.severity),
                    title: E(n.title) + (n.detail ? '<div class="pa-small">' + E(n.detail) + '</div>' : ''),
                    status: PAMod.chip(S['st_' + n.status] || n.status, n.status === 'sent' ? 'pa-ok' : n.status === 'failed' ?
                        'pa-high' : 'pa-muted-chip') + (n.reason ? '<div class="pa-small">' + E(n.reason) + '</div>' : '') +
                        (n.attempts > 1 ? '<div class="pa-small">x' + E(n.attempts) + '</div>' : ''),
                    actions: (n.link && /^\/ui\//.test(n.link) ? '<a class="btn btn-xs btn-default" href="' + E(n.link) + '">' +
                        E(S.open) + '</a>' : '') + (n.type !== 'report' && n.status !== 'suppressed' ? '<button type="button" ' +
                        'class="btn btn-xs btn-default par-resend" data-id="' + n.id + '"><i class="fa fa-repeat"></i> ' +
                        E(S.resend) + '</button>' : '')}};
            });
            const opts = ['', 'queued', 'held', 'sent', 'failed', 'suppressed'].map(function (s) {
                return '<option value="' + s + '"' + (s === noteFilter ? ' selected' : '') + '>' + E(s ? S['st_' + s] : S.allStatus) +
                    '</option>';
            }).join('');
            $('#par_queue').html('<div class="pa-mod-toolbar"><b>' + E(S.queue) + '</b><select class="form-control" ' +
                'id="par_q_status">' + opts + '</select></div><div class="pa-scroll">' + PAMod.table([
                    {key: 'when', label: S.colWhen, width: '110px'}, {key: 'type', label: S.colType, width: '12%'},
                    {key: 'sev', label: S.colSev, width: '80px'}, {key: 'title', label: S.colTitle},
                    {key: 'status', label: S.colStatus, width: '17%'}, {key: 'actions', label: S.colActions,
                        width: '140px'}], rows) + '</div>');
        });
    }

    function loadHistory() {
        PAMod.get(API + 'history', {rows: 100}, function (res) {
            const rows = ((res && res.rows) || []).map(function (m) {
                return {cells: {
                    when: PAMod.when(m.ts_iso), kind: E(m.kind), subject: E(m.subject) + (m.error ? '<div class="pa-small ' +
                        'text-danger">' + E(m.error) + '</div>' : ''), to: '<span class="pa-small">' + E(m.recipients.join(', ')) +
                        '</span>', status: PAMod.chip(m.status, m.status === 'sent' ? 'pa-ok' : m.status === 'failed' ? 'pa-high' :
                        'pa-muted-chip'), ai: m.ai_used ? '<i class="fa fa-magic"></i>' : '',
                    actions: m.status !== 'skipped' ? '<button type="button" class="btn btn-xs btn-default par-view" ' +
                        'data-id="' + m.id + '"><i class="fa fa-eye"></i> ' + E(S.view) + '</button>' : ''}};
            });
            $('#par_history').html('<div class="pa-scroll">' + PAMod.table([{key: 'when', label: S.colWhen, width: '110px'},
                {key: 'kind', label: S.colKind, width: '110px'}, {key: 'subject', label: S.colSubject},
                {key: 'to', label: S.colTo, width: '18%', cls: 'pa-col-opt'}, {key: 'status', label: S.colStatus, width: '80px'},
                {key: 'ai', label: S.colAi, width: '40px'}, {key: 'actions', label: S.colActions, width: '90px'}], rows) +
                '</div>');
        });
    }

    function bind() {
        const $root = $('#pa_reports');
        $root.on('change', 'input[name=par_mode]', function () {
            state.settings.email.mode = this.value;
            renderChannel();
        });
        $root.on('click', '#par_save_channel', function () { save(channelPayload()); });
        $root.on('click', '#par_import', function () {
            PAMod.simulate(API, 'reports_import_monit', [], S.importTitle, load);
        });
        $root.on('click', '#par_test', function () {
            PAMod.simulate(API, 'reports_send_test', ['test'], S.sendTestTitle, loadHistory);
        });
        $root.on('click', '#par_save_reports', function () { save(reportsPayload()); });
        $root.on('click', '#par_preview, #par_preview_ai', function () {
            const ai = this.id === 'par_preview_ai';
            previewAi = ai;
            $('#par_preview_box').html('<i class="fa fa-spinner fa-spin"></i>');
            const done = function (res) { showPreview(res, $root.find('[data-view].active').data('view')); };
            if (ai) {
                PAMod.post(API + 'preview', {kind: 'manual', ai: '1'}, done);
            } else {
                PAMod.get(API + 'preview', {kind: 'manual'}, done);
            }
        });
        $root.on('click', '[data-view]', function () {
            $root.find('[data-view]').removeClass('active');
            $(this).addClass('active');
            const res = $('#par_preview_box').data('preview');
            if (res) {
                showPreview(res, $(this).data('view'));
            }
        });
        $root.on('click', '#par_pdf', function () { downloadPdf(this); });
        $root.on('click', '#par_send_now', function () {
            PAMod.simulate(API, 'reports_send_test', ['report'], S.sendNowTitle, loadHistory);
        });
        $root.on('click', '#par_save_notify', function () { save(notifyPayload()); });
        $root.on('click', '#par_sources', function () {
            PAMod.get(API + 'notifyPreview', {}, function (res) {
                let html = '';
                Object.keys((res && res.sources) || {}).forEach(function (k) {
                    const v = res.sources[k];
                    html += '<div style="margin-bottom:6px"><b>' + E(k) + '</b>: ' + (v === null ? E(S.unavailable) :
                        (Array.isArray(v) ? (v.length ? '<ul>' + v.map(function (e) {
                            return '<li>' + PAMod.chip(e.severity, 'pa-' + e.severity) + ' ' + E(e.title) + '</li>';
                        }).join('') + '</ul>' : E(S.none)) : E(v.error || ''))) + '</div>';
                });
                PAMod.info(S.sourcesTitle, html);
            });
        });
        $root.on('change', '#par_q_status', function () { noteFilter = $(this).val(); loadNotes(); });
        $root.on('click', '.par-resend', function () {
            const id = $(this).data('id');
            BootstrapDialog.confirm({title: S.resend, message: S.resendConfirm, type: BootstrapDialog.TYPE_WARNING,
                callback: function (ok) {
                    if (ok) {
                        PAMod.post(API + 'resend', {id: String(id)}, function () { loadNotes(); loadHistory(); });
                    }
                }});
        });
        $root.on('click', '.par-view', function () {
            PAMod.get(API + 'message', {id: $(this).data('id')}, function (res) {
                const m = (res && res.message) || {};
                const frame = $('<iframe class="pa-preview-frame" sandbox=""/>').attr('srcdoc', m.html || '');
                PASimulation.dialog({title: m.subject || '', message: $('<div class="pa-mod-dialog"/>').append(frame),
                    size: BootstrapDialog.SIZE_WIDE, buttons: [{label: PAMod.S().close, action: function (d) { d.close(); }}]});
            });
        });
        $root.on('click', '#par_refresh', load);
        $('a[href="#par_tab_' + (location.hash || '').replace('#', '') + '"]').tab('show');
    }

    return {
        DEFAULTS: DEFAULTS,
        setStrings: function (s) { S = Object.assign({}, DEFAULTS, s || {}); },
        init: function () {
            PAMod.accent(document.getElementById('pa_reports'));
            bind();
            load();
        }
    };
})();
