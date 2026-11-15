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
 * Devices page (devices.volt): passive inventory of the LAN (Host discovery, DHCP, ARP, local DNS, IEEE OUI),
 * heuristic type, inferred risk, AI explanation, "mark as known" and the owner's type/name, permanent history.
 * API: /api/policyanalyzer/devices/*. Every change goes through PASimulation (journal, revert).
 */
const PADevices = (function () {
    'use strict';

    const API = '/api/policyanalyzer/devices/';
    const TYPES = ['camera', 'nvr', 'tv', 'phone', 'pc', 'ap', 'iot', 'printer', 'console', 'unknown'];
    const ICONS = {camera: 'fa-video-camera', nvr: 'fa-hdd-o', tv: 'fa-television', phone: 'fa-mobile', pc: 'fa-desktop',
                   ap: 'fa-wifi', iot: 'fa-lightbulb-o', printer: 'fa-print', console: 'fa-gamepad', unknown: 'fa-question'};
    const DEFAULTS = {
        title: 'Devices', subtitle: 'Passive inventory of the local network: nothing is sent to the devices.',
        scan: 'Scan now', refresh: 'Refresh', updateOui: 'Update manufacturer database',
        updateOuiTitle: 'Download the IEEE OUI registry',
        kpiTotal: 'Devices', kpiPresent: 'Present now', kpiNew: 'New (7 days)', kpiUnknown: 'Not marked known',
        kpiHigh: 'High risk', kpiMedium: 'Medium risk',
        lastScan: 'Last scan %s', ouiSource: 'Manufacturers: %s (%s entries)', sources: 'Sources',
        allTypes: 'All types', allRisks: 'All risks', onlyNew: 'New', onlyUnknown: 'Not known', onlyPresent: 'Present',
        search: 'Search name, vendor, IP, MAC', markKnown: 'Mark as known', markUnknown: 'Mark as not known',
        markTitle: 'Mark %s device(s)', selected: '%s selected',
        colName: 'Name', colType: 'Type', colVendor: 'Manufacturer', colIp: 'Address', colIface: 'Interface',
        colFirst: 'First seen', colLast: 'Last seen', colRisk: 'Risk', colActions: 'Actions',
        explain: 'Explain', explainTitle: 'Explain device %s', edit: 'Edit', editTitle: 'Type and name of %s',
        history: 'History', historyTitle: 'History of %s', known: 'known', new: 'new', present: 'present',
        heuristic: 'automatic', owner: 'set by you', aiSuggests: 'AI suggests %s',
        typeAuto: 'Automatic (%s)', name: 'Name', nameHelp: 'Empty: the hostname seen on the network',
        simulate: 'Simulate', why: 'Why this type', riskWhy: 'Why this risk', randomMac: 'random MAC',
        addresses: 'Addresses', events: 'Events', mac: 'MAC',
        type_camera: 'camera', type_nvr: 'NVR/DVR', type_tv: 'TV', type_phone: 'phone', type_pc: 'computer',
        type_ap: 'AP/router', type_iot: 'IoT', type_printer: 'printer', type_console: 'console', type_unknown: 'unknown',
        risk_high: 'high', risk_medium: 'medium', risk_low: 'low', risk_info: 'info', noScan: 'No scan yet: click Scan now.'
    };
    let S = Object.assign({}, DEFAULTS);
    let rows = [];
    let summary = {};
    const selected = new Set();
    const E = function (v) { return PAMod.esc(v); };

    function fmt(text) {
        const args = Array.prototype.slice.call(arguments, 1);
        return String(text).replace(/%s/g, function () { return args.length ? args.shift() : ''; });
    }

    function params() {
        const p = {sort: 'risk', rows: 200};
        const t = $('#pad_type').val();
        const r = $('#pad_risk').val();
        if (t) { p.type = t; }
        if (r) { p.risk = r; }
        if ($('#pad_new').prop('checked')) { p['new'] = '1'; }
        if ($('#pad_unknown').prop('checked')) { p.known = '0'; }
        if ($('#pad_present').prop('checked')) { p.present = '1'; }
        const q = $('#pad_search').val().trim();
        if (q) { p.search = q; }
        return p;
    }

    function load() {
        PAMod.get(API + 'summary', {}, function (res) {
            summary = res || {};
            renderKpis();
        });
        PAMod.get(API + 'list', params(), function (res) {
            rows = (res && res.rows) || [];
            renderTable(res || {});
        });
    }

    function renderKpis() {
        const s = summary;
        const r = s.by_risk || {};
        const tiles = [[s.total, S.kpiTotal, ''], [s.present, S.kpiPresent, 'present'], [s.new_7d, S.kpiNew, 'new'],
            [s.unknown, S.kpiUnknown, 'unknown'], [r.high, S.kpiHigh, 'high'], [r.medium, S.kpiMedium, 'medium']];
        $('#pad_kpis').html(tiles.map(function (t) {
            return '<button type="button" class="pa-kpi" data-kpi="' + t[2] + '"><span class="pa-kpi-n">' + E(t[0] || 0) +
                '</span><span class="pa-kpi-l">' + E(t[1]) + '</span></button>';
        }).join(''));
    }

    function typeHtml(d) {
        let html = '<i class="fa ' + (ICONS[d.type] || 'fa-question') + '"></i> ' + E(S['type_' + d.type] || d.type) +
            '<div class="pa-small">' + E(d.type_source === 'owner' ? S.owner : S.heuristic + ' (' + d.auto_confidence + ')') +
            '</div>';
        if (d.ai && d.ai.type && d.ai.type !== d.type) {
            html += '<div class="pa-small"><i class="fa fa-magic"></i> ' + E(fmt(S.aiSuggests, S['type_' + d.ai.type] ||
                d.ai.type)) + '</div>';
        }
        return html;
    }

    function detailHtml(d) {
        return '<b>' + E(S.why) + '</b><ul>' + (d.auto_why || []).map(function (w) { return '<li>' + E(w) + '</li>'; })
            .join('') + '</ul><b>' + E(S.riskWhy) + '</b><ul>' + ((d.risk_reasons || []).map(function (r) {
            return '<li>' + PAMod.chip(S['risk_' + r.level] || r.level, 'pa-' + r.level) + ' ' + E(r.text) + '</li>';
        }).join('') || '<li>-</li>') + '</ul><span class="pa-small">' + E(S.mac) + ' ' + E(d.mac) +
            (d.randomized ? ' (' + E(S.randomMac) + ')' : '') + (d.hostname_source ? ' &middot; ' + E(d.hostname_source) : '') +
            '</span>';
    }

    function renderTable(res) {
        const meta = [];
        if (res.last_scan) {
            meta.push(E(fmt(S.lastScan, PAMod.when(res.last_scan))));
        }
        const oui = (res.sources || {}).oui;
        if (oui) {
            meta.push(E(fmt(S.ouiSource, (oui.source || '-').split('/').pop(), oui.entries)));
        }
        const src = res.sources || {};
        const flags = ['hostwatch', 'kea', 'arp'].map(function (k) {
            const on = src[k] && src[k].available;
            return '<span class="pa-dot ' + (on ? 'pa-on-dot' : 'pa-off-dot') + '"></span>' + k;
        }).join(' ');
        $('#pad_meta').html('<span>' + meta.join(' &middot; ') + (flags ? ' &middot; ' + E(S.sources) + ': ' + flags : '') +
            '</span><button type="button" class="btn btn-xs btn-default pa-oui"><i class="fa fa-cloud-download"></i> ' +
            E(S.updateOui) + '</button>');
        const cols = [
            {key: 'sel', label: '', width: '30px'}, {key: 'name', label: S.colName, width: '17%'},
            {key: 'type', label: S.colType, width: '12%'}, {key: 'vendor', label: S.colVendor, width: '16%'},
            {key: 'ip', label: S.colIp, width: '12%'}, {key: 'iface', label: S.colIface, width: '8%', cls: 'pa-col-opt'},
            {key: 'first', label: S.colFirst, width: '10%', cls: 'pa-col-opt'}, {key: 'last', label: S.colLast, width: '10%'},
            {key: 'risk', label: S.colRisk, width: '8%'}, {key: 'actions', label: S.colActions, width: '150px'}];
        const out = rows.map(function (d) {
            const tags = (d.is_new ? ' ' + PAMod.chip(S['new'], 'pa-medium') : '') +
                (d.known ? ' ' + PAMod.chip(S.known, 'pa-ok') : '') +
                (d.present ? ' <span class="pa-dot pa-on-dot" title="' + E(S.present) + '"></span>' : '');
            return {attrs: ' id="device-' + d.id + '"', cls: selected.has(d.id) ? 'pa-row-sel' : '', detail: detailHtml(d),
                cells: {
                    sel: '<input type="checkbox" class="pa-sel" data-id="' + d.id + '"' + (selected.has(d.id) ? ' checked' : '') +
                        ' aria-label="select">',
                    name: '<b>' + E(d.name || d.mac) + '</b>' + tags,
                    type: typeHtml(d),
                    vendor: E(d.vendor || (d.randomized ? S.randomMac : '-')),
                    ip: E((d.ip4 || []).join(', ') || (d.ip6 || [])[0] || '-'),
                    iface: E(d.iface_descr || '-'),
                    first: PAMod.when(d.first_seen_iso), last: PAMod.when(d.last_seen_iso),
                    risk: PAMod.chip(S['risk_' + d.risk] || d.risk, 'pa-' + d.risk),
                    actions: '<button type="button" class="btn btn-xs btn-default pa-detail-toggle" title="' + E(S.why) + '">' +
                        '<i class="fa fa-list"></i></button><button type="button" class="btn btn-xs btn-primary pa-explain" ' +
                        'data-id="' + d.id + '"><i class="fa fa-magic"></i> ' + E(S.explain) + '</button>' +
                        '<div class="btn-group"><button type="button" class="btn btn-xs btn-default dropdown-toggle" ' +
                        'data-toggle="dropdown" aria-label="more"><i class="fa fa-ellipsis-v"></i></button>' +
                        '<ul class="dropdown-menu dropdown-menu-right">' +
                        '<li><a href="#" class="pa-known" data-id="' + d.id + '" data-known="' + (d.known ? 0 : 1) + '">' +
                        E(d.known ? S.markUnknown : S.markKnown) + '</a></li>' +
                        '<li><a href="#" class="pa-edit" data-id="' + d.id + '">' + E(S.edit) + '</a></li>' +
                        '<li><a href="#" class="pa-history" data-id="' + d.id + '">' + E(S.history) + '</a></li></ul></div>'
                }};
        });
        $('#pad_table').html(PAMod.table(cols, out, {empty: res.status === 'none' ? S.noScan : undefined}));
        batch();
    }

    function batch() {
        $('#pad_batch').toggle(selected.size > 0);
        $('#pad_batch_n').text(fmt(S.selected, selected.size));
    }

    function byId(id) {
        return rows.find(function (d) { return d.id === id; }) || {};
    }

    function edit(id) {
        const d = byId(id);
        const $f = $('<form class="pa-mod-dialog"/>');
        const $sel = $('<select class="form-control"/>').append($('<option value="auto"/>').text(fmt(S.typeAuto,
            S['type_' + d.auto_type] || d.auto_type)));
        TYPES.forEach(function (t) { $sel.append($('<option/>').val(t).text(S['type_' + t] || t)); });
        $sel.val(d.user_type || 'auto');
        const $name = $('<input type="text" class="form-control" maxlength="80"/>').val(d.user_name || '')
            .attr('placeholder', d.hostname || '');
        $f.append($('<label/>').text(S.colType), $sel, $('<label style="margin-top:8px"/>').text(S.name), $name,
            $('<div class="pa-small"/>').text(S.nameHelp));
        if (d.ai && d.ai.type) {
            $f.append($('<div class="pa-ai-box"/>').text(fmt(S.aiSuggests, S['type_' + d.ai.type] || d.ai.type)));
        }
        PASimulation.dialog({title: fmt(S.editTitle, d.name || d.mac), message: $f, buttons: [
            {label: S.simulate, cssClass: 'btn-primary', action: function (dlg) {
                const typ = $sel.val() === (d.user_type || 'auto') ? '-' : $sel.val();
                const nm = $name.val().trim();
                const nameArg = nm === (d.user_name || '') ? '-' : (nm ? PAMod.b64text(nm) : PAMod.b64text(' '));
                dlg.close();
                PAMod.simulate(API, 'devices_set', [String(id), typ, nameArg], fmt(S.editTitle, d.name || d.mac), load);
            }},
            {label: PAMod.S().close, action: function (dlg) { dlg.close(); }}]});
    }

    function history(id) {
        PAMod.get(API + 'device', {id: id}, function (res) {
            const d = (res && res.device) || {};
            const html = '<b>' + E(S.addresses) + '</b>' + PAMod.table([{key: 'ip', label: S.colIp},
                {key: 'f', label: S.colFirst}, {key: 'l', label: S.colLast}], (d.addresses || []).map(function (a) {
                return {cells: {ip: E(a.ip), f: PAMod.when(a.first_seen), l: PAMod.when(a.last_seen)}};
            })) + '<b style="display:block;margin-top:10px">' + E(S.events) + '</b>' + PAMod.table([{key: 't', label: 'ts',
                width: '130px'}, {key: 'k', label: 'kind', width: '90px'}, {key: 'c', label: ''}], (d.history || []).map(
                function (h) {
                    return {cells: {t: PAMod.when(h.ts), k: E(h.kind), c: E((h.old || '-') + ' -> ' + (h['new'] || '-') +
                        (h.note ? ' (' + h.note + ')' : ''))}};
                }));
            PAMod.info(fmt(S.historyTitle, d.name || d.mac || id), '<div class="pa-mod">' + html + '</div>');
        });
    }

    function bind() {
        const $root = $('#pa_devices');
        $root.on('change', '#pad_type, #pad_risk, #pad_new, #pad_unknown, #pad_present', load);
        let timer = null;
        $root.on('input', '#pad_search', function () {
            clearTimeout(timer);
            timer = setTimeout(load, 300);
        });
        $root.on('click', '.pa-kpi', function () {
            const k = $(this).data('kpi');
            $('#pad_new').prop('checked', k === 'new');
            $('#pad_unknown').prop('checked', k === 'unknown');
            $('#pad_present').prop('checked', k === 'present');
            $('#pad_risk').val(k === 'high' || k === 'medium' ? k : '');
            load();
        });
        $root.on('click', '#pad_scan', function () {
            const $b = $(this).prop('disabled', true);
            PAMod.post(API + 'scan', {}, function () { $b.prop('disabled', false); load(); });
        });
        $root.on('click', '#pad_refresh', load);
        $root.on('click', '.pa-oui', function () {
            PAMod.simulate(API, 'devices_oui_update', [], S.updateOuiTitle, load);
        });
        $root.on('click', '.pa-detail-toggle', function () { $(this).closest('tr').next('.pa-detail-row').toggle(); });
        $root.on('change', '.pa-sel', function () {
            const id = Number($(this).data('id'));
            if (this.checked) { selected.add(id); } else { selected.delete(id); }
            $(this).closest('tr').toggleClass('pa-row-sel', this.checked);
            batch();
        });
        $root.on('click', '.pa-batch-known', function () {
            const ids = Array.from(selected).slice(0, 100);
            PAMod.simulate(API, 'devices_mark_known', [ids.join('+'), $(this).data('known') ? '1' : '0'],
                fmt(S.markTitle, ids.length), function () { selected.clear(); load(); });
        });
        $root.on('click', '.pa-known', function (ev) {
            ev.preventDefault();
            PAMod.simulate(API, 'devices_mark_known', [String($(this).data('id')), String($(this).data('known'))],
                fmt(S.markTitle, 1), load);
        });
        $root.on('click', '.pa-edit', function (ev) { ev.preventDefault(); edit(Number($(this).data('id'))); });
        $root.on('click', '.pa-history', function (ev) { ev.preventDefault(); history(Number($(this).data('id'))); });
        $root.on('click', '.pa-explain', function () {
            const id = Number($(this).data('id'));
            const d = byId(id);
            PAMod.aiDialog({title: fmt(S.explainTitle, d.name || d.mac),
                intro: typeHtml(d) + ' ' + PAMod.chip(S['risk_' + d.risk] || d.risk, 'pa-' + d.risk),
                cached: function (cb) {
                    cb(d.ai && d.ai.text ? {status: 'ok', text: d.ai.text, generated_at: d.ai.at, cached: true} : null);
                },
                preview: function (cb) { PAMod.post(API + 'explain', {id: id, mode: 'preview'}, cb); },
                ask: function (cb) { PAMod.post(API + 'explain', {id: id, mode: 'refresh'}, cb); },
                onAnswer: function (res) { if (res && res.status === 'ok') { load(); } }});
        });
    }

    return {
        DEFAULTS: DEFAULTS,
        setStrings: function (s) { S = Object.assign({}, DEFAULTS, s || {}); },
        init: function () {
            PAMod.accent(document.getElementById('pa_devices'));
            const $t = $('#pad_type');
            TYPES.forEach(function (t) { $t.append($('<option/>').val(t).text(S['type_' + t] || t)); });
            bind();
            load();
        }
    };
})();
