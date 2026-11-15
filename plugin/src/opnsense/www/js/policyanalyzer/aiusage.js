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

/**
 * AI usage page (/ui/policyanalyzer/aiusage, aiusage.volt): which internal hosts use which AI services, from
 * DNS queries (Unbound) and TLS SNI (Suricata). KPI tiles, a stacked day chart, top services, the host list
 * (table on desktop, cards on phones), host details (domains, SNI, JA4) and the blocking proposal with replay
 * (read only: PASimulation.show(plan, {readOnly: true}) + diff + link to the page).
 *
 *   PAAiUsage.init({strings: {...}})
 */
const PAAiUsage = (function () {
    'use strict';

    const API = '/api/policyanalyzer/shadowai/';
    const I = PAInsights;
    const esc = I.esc;
    /* fixed colour per service (entity, never rank); the rest is "Other" */
    const COLOR_ORDER = ['anthropic', 'openai', 'gemini', 'copilot', 'huggingface', 'ollama', 'deepseek', 'perplexity'];
    let S = {
        window: 'Window', days: 'days', refresh: 'Refresh', explain: 'Explain (AI)', propose: 'Block proposal',
        hosts: 'Hosts using AI', services: 'Services', unexpected: 'Unexpected hosts', newItems: 'New (3 days)',
        dns: 'DNS queries', tls: 'TLS connections', perDay: 'Per day (DNS queries + TLS connections)',
        topServices: 'Services by use', hostList: 'Hosts', host: 'Host', usage: 'AI services', total: 'Total',
        lastUse: 'Last use', firstUse: 'First use', actions: 'Actions', details: 'Details', known: 'expected',
        isNew: 'new', elevated: 'elevated risk', other: 'Other', firewall: 'this firewall', close: 'Close',
        loading: 'Reading DNS and TLS data...', noData: 'No AI service seen in this window.', sources: 'Sources',
        dnsSource: 'Unbound DNS', tlsSource: 'Suricata TLS', incomplete: 'partial (time budget)', catalog: 'Catalogue',
        domains: 'Domains', sni: 'TLS server names', ja4: 'JA4 client fingerprints', reason: 'Why expected',
        scope: 'Apply to', scopeAll: 'every client', scopeHost: 'this host', scopeNet: 'this network (CIDR)',
        method: 'Method', methodDns: 'DNS blocklist (Unbound, recommended)', methodAlias: 'Firewall alias + block rule',
        simulate: 'Simulate', showPlan: 'Show plan', replay: 'Replay over the window', wouldBlock: 'would have been blocked',
        affected: 'Hosts affected', conflicts: 'Expected usage that would break', openPage: 'Open page',
        proposalOnly: 'Proposal only: nothing is applied from here.', asking: 'Asking the AI...', error: 'Error',
        selectService: 'Select at least one service.', preview: 'Show data sent', anonymized: 'anonymized',
        notAnonymized: 'not anonymized', cached: 'cached', aiDisclaimer: 'AI text: verify before acting.',
        countsNote: 'Counts are DNS queries and TLS connections, not data volume; content is never seen.',
        unattributed: 'queries without a client address'
    };
    let report = null;
    let days = 7;
    let aiEnabled = false;

    function color(id) {
        const idx = COLOR_ORDER.indexOf(id);
        return idx >= 0 ? I.PALETTE[idx] : I.OTHER;
    }

    function tile(label, value, extra, cls) {
        return '<div class="pa-ins-tile ' + (cls || '') + '"><div class="pa-ins-tile-v">' + esc(value) + '</div>' +
            '<div class="pa-ins-tile-l">' + esc(label) + '</div>' + (extra ? '<div class="pa-ins-tile-x">' + extra +
            '</div>' : '') + '</div>';
    }

    function hostLabel(h) {
        return h.name || h.ip;
    }

    function chips(h) {
        return h.services.map(function (s) {
            return '<span class="pa-ins-svc' + (s.known ? ' pa-known' : '') + '" title="' +
                esc(s.name + ': ' + s.dns + ' DNS, ' + s.tls + ' TLS' + (s.known ? ' — ' + s.known_reason : '')) +
                '"><i style="background:' + color(s.service) + '"></i>' + esc(s.name) + ' <b>' + esc(s.total) + '</b>' +
                (s.known ? ' <span class="pa-ins-badge pa-b-known">' + esc(S.known) + '</span>' : '') +
                (s.new ? ' <span class="pa-ins-badge pa-b-new">' + esc(S.isNew) + '</span>' : '') +
                (s.risk === 'elevated' ? ' <span class="pa-ins-badge pa-b-risk" title="' + esc(S.elevated) +
                    '"><i class="fa fa-exclamation-triangle"></i></span>' : '') + '</span>';
        }).join('');
    }

    function lastOf(h) {
        return h.services.reduce(function (m, s) { return s.last > m ? s.last : m; }, '');
    }

    function render() {
        const root = $('#pa_aiusage');
        if (!report || report.status !== 'ok') {
            root.html(toolbar() + '<div class="alert alert-danger">' + esc((report && report.message) || S.error) +
                '</div>');
            bind();
            return;
        }
        const t = report.totals;
        let html = toolbar();
        html += '<div class="pa-ins-tiles">' +
            tile(S.hosts, t.hosts) + tile(S.services, t.services) +
            tile(S.unexpected, t.unexpected_hosts, '', t.unexpected_hosts ? 'pa-tile-warn' : '') +
            tile(S.newItems, t.new, '', t.new ? 'pa-tile-new' : '') +
            tile(S.dns, t.dns, t.blocked ? esc(t.blocked) + ' blocked' : '') + tile(S.tls, t.tls) + '</div>';
        if (report.new_items && report.new_items.length) {
            html += '<div class="pa-ins-changes">' + report.new_items.map(function (n) {
                return '<span class="pa-ins-tag pa-b-new" data-ip="' + esc(n.host) + '">' + esc(S.isNew) + ': ' +
                    esc(n.name || n.host) + ' → ' + esc(n.service_name) + '</span>';
            }).join('') + '</div>';
        }
        if (!report.hosts.length) {
            html += '<div class="pa-ins-empty text-muted">' + esc(S.noData) + '</div>';
        } else {
            const ids = {};
            report.services.forEach(function (s) { ids[s.id] = s; });
            const series = [];
            COLOR_ORDER.forEach(function (id) {
                if (ids[id]) {
                    series.push({id: id, name: ids[id].name, color: color(id),
                        value: function (d) { return d.by_service[id] || 0; }});
                }
            });
            const others = report.services.filter(function (s) { return COLOR_ORDER.indexOf(s.id) < 0; });
            if (others.length) {
                series.push({id: '_other', name: S.other, color: I.OTHER, value: function (d) {
                    return others.reduce(function (sum, s) { return sum + (d.by_service[s.id] || 0); }, 0);
                }});
            }
            html += '<div class="pa-ins-charts"><div class="pa-ins-chart"><div class="pa-ins-chart-t">' +
                esc(S.perDay) + '</div>' + I.stacked(report.daily, series) + I.legend(series) + '</div>' +
                '<div class="pa-ins-chart"><div class="pa-ins-chart-t">' + esc(S.topServices) + '</div>' +
                I.hbars(report.services.slice(0, 8).map(function (s) {
                    return {label: s.name, value: s.total, color: color(s.id),
                        text: s.total + ' · ' + s.hosts + ' ' + (s.hosts === 1 ? 'host' : 'hosts'),
                        title: s.name + ': ' + s.dns + ' DNS, ' + s.tls + ' TLS, ' + s.hosts + ' hosts (' +
                            s.unexpected_hosts + ' unexpected)'};
                })) + '</div></div>';
            html += '<h3 class="pa-ins-h3">' + esc(S.hostList) + '</h3>';
            html += '<table class="table table-condensed table-hover pa-ins-table hidden-xs"><colgroup>' +
                '<col style="width:200px"/><col/><col style="width:70px"/><col style="width:150px"/>' +
                '<col style="width:100px"/></colgroup><thead><tr><th>' + esc(S.host) + '</th><th>' + esc(S.usage) +
                '</th><th>' + esc(S.total) + '</th><th>' + esc(S.lastUse) + '</th><th>' + esc(S.actions) +
                '</th></tr></thead><tbody>';
            report.hosts.forEach(function (h) {
                html += '<tr class="pa-ai-row" data-ip="' + esc(h.ip) + '"><td><div class="pa-ins-ctitle">' +
                    esc(hostLabel(h)) + (h.firewall ? ' <span class="pa-ins-badge pa-b-known">' + esc(S.firewall) +
                    '</span>' : '') + '</div><div class="text-muted small">' + esc(h.name ? h.ip : '') +
                    (h.vendor ? (h.name ? ' · ' : '') + esc(h.vendor) : '') + '</div></td><td class="pa-ins-chipcell">' +
                    chips(h) + '</td><td>' + esc(h.total) + '</td><td class="small">' + esc(I.when(lastOf(h))) +
                    '</td><td class="pa-ins-btns">' + buttons(h, false) + '</td></tr>';
            });
            html += '</tbody></table><div class="pa-ins-cards visible-xs">';
            report.hosts.forEach(function (h) {
                html += '<div class="pa-ins-card"><div class="pa-ins-card-head"><b>' + esc(hostLabel(h)) + '</b> ' +
                    '<span class="text-muted small">' + esc(h.name ? h.ip : (h.vendor || '')) + '</span></div>' +
                    '<div class="pa-ins-chipcell">' + chips(h) + '</div><div class="small text-muted">' +
                    esc(S.lastUse) + ': ' + esc(I.when(lastOf(h))) + '</div><div class="pa-ins-card-btns">' +
                    buttons(h, true) + '</div></div>';
            });
            html += '</div>';
        }
        const src = report.sources || {};
        html += '<p class="small text-muted pa-ins-sources">' + esc(S.countsNote) + '<br/>' + esc(S.sources) + ': ' +
            esc(S.dnsSource) + ' ' + (src.dns && src.dns.available ? esc(src.dns.rows) + ' rows' :
                esc((src.dns && src.dns.message) || 'n/a')) + ' · ' + esc(S.tlsSource) + ' ' +
            (src.tls && src.tls.available ? esc(src.tls.events) + ' events' + (src.tls.complete ? '' : ' (' +
                esc(S.incomplete) + ')') : 'n/a') + ' · ' + esc(S.catalog) + ' ' +
            esc((report.catalog || {}).version) + ' · ' + esc(I.when(report.generated)) +
            (report.totals.unattributed_dns ? ' · ' + esc(report.totals.unattributed_dns) + ' ' + esc(S.unattributed) :
                '') + '</p>';
        root.html(html);
        bind();
    }

    function buttons(h, block) {
        const cls = block ? 'btn btn-default' : 'btn btn-xs btn-default';
        return '<button type="button" class="' + cls + ' pa-ai-details" data-ip="' + esc(h.ip) + '" title="' +
            esc(S.details) + '"><i class="fa fa-search-plus"></i>' + (block ? ' ' + esc(S.details) : '') + '</button>' +
            (aiEnabled ? '<button type="button" class="' + cls + ' pa-ai-explain" data-ip="' + esc(h.ip) + '" title="' +
                esc(S.explain) + '"><i class="fa fa-magic"></i>' + (block ? ' ' + esc(S.explain) : '') + '</button>' : '') +
            '<button type="button" class="' + cls + ' pa-ai-propose" data-ip="' + esc(h.ip) + '" title="' +
            esc(S.propose) + '"><i class="fa fa-ban"></i>' + (block ? ' ' + esc(S.propose) : '') + '</button>';
    }

    function toolbar() {
        return '<div class="pa-ins-toolbar"><label>' + esc(S.window) + ' <select id="pa_ai_days" class="form-control">' +
            [1, 7, 14, 30].map(function (d) {
                return '<option value="' + d + '"' + (d === days ? ' selected' : '') + '>' + d + ' ' + esc(S.days) +
                    '</option>';
            }).join('') + '</select></label>' +
            '<button class="btn btn-default" id="pa_ai_refresh"><i class="fa fa-refresh"></i> ' + esc(S.refresh) +
            '</button>' + (aiEnabled ? '<button class="btn btn-default" id="pa_ai_explain"><i class="fa fa-magic"></i> ' +
                esc(S.explain) + '</button>' : '') +
            '<button class="btn btn-default" id="pa_ai_propose"><i class="fa fa-ban"></i> ' + esc(S.propose) +
            '</button></div>';
    }

    function bind() {
        $('#pa_ai_days').off('change').on('change', function () {
            days = parseInt($(this).val(), 10) || 7;
            load(false);
        });
        $('#pa_ai_refresh').off('click').on('click', function () { load(true); });
        $('#pa_ai_explain').off('click').on('click', function () { explain({target: 'overview'}); });
        $('#pa_ai_propose').off('click').on('click', function () { propose(null); });
        $('.pa-ai-details').off('click').on('click', function (e) {
            e.stopPropagation();
            details($(this).data('ip'));
        });
        $('.pa-ai-row, .pa-ins-tag[data-ip]').off('click').on('click', function () { details($(this).data('ip')); });
        $('.pa-ai-explain').off('click').on('click', function (e) {
            e.stopPropagation();
            explain({target: 'host', ip: $(this).data('ip')});
        });
        $('.pa-ai-propose').off('click').on('click', function (e) {
            e.stopPropagation();
            propose($(this).data('ip'));
        });
    }

    function host(ip) {
        return (report.hosts || []).find(function (h) { return h.ip === ip; });
    }

    function details(ip) {
        const h = host(ip);
        if (!h) {
            return;
        }
        let html = '<p><b>' + esc(hostLabel(h)) + '</b> ' + esc(h.ip) + (h.mac ? ' · ' + esc(h.mac) : '') +
            (h.vendor ? ' · ' + esc(h.vendor) : '') + '</p>';
        h.services.forEach(function (s) {
            html += '<div class="pa-ins-svcbox"><div><span class="pa-ins-svc"><i style="background:' + color(s.service) +
                '"></i>' + esc(s.name) + '</span> ' + (s.known ? '<span class="pa-ins-badge pa-b-known">' + esc(S.known) +
                '</span> ' : '') + (s.new ? '<span class="pa-ins-badge pa-b-new">' + esc(S.isNew) + '</span>' : '') +
                '</div><table class="table table-condensed pa-ins-kv"><tbody>' +
                '<tr><th>' + esc(S.dns) + '</th><td>' + esc(s.dns) + (s.blocked ? ' (' + esc(s.blocked) + ' blocked)' : '') +
                '</td></tr><tr><th>' + esc(S.tls) + '</th><td>' + esc(s.tls) + '</td></tr>' +
                '<tr><th>' + esc(S.firstUse) + '</th><td>' + esc(I.when(s.first)) + '</td></tr>' +
                '<tr><th>' + esc(S.lastUse) + '</th><td>' + esc(I.when(s.last)) + '</td></tr>' +
                (s.domains.length ? '<tr><th>' + esc(S.domains) + '</th><td>' + s.domains.map(esc).join(', ') +
                    '</td></tr>' : '') +
                (s.sni.length ? '<tr><th>' + esc(S.sni) + '</th><td>' + s.sni.map(esc).join(', ') + '</td></tr>' : '') +
                (s.ja4.length ? '<tr><th>' + esc(S.ja4) + '</th><td>' + s.ja4.map(function (j) {
                    return '<code>' + esc(j.ja4) + '</code> ×' + esc(j.count);
                }).join('<br/>') + '</td></tr>' : '') +
                (s.known ? '<tr><th>' + esc(S.reason) + '</th><td>' + esc(s.known_reason) + '</td></tr>' : '') +
                '</tbody></table></div>';
        });
        html += '<div id="pa_ai_answer"></div>';
        const buttons = [];
        if (aiEnabled) {
            buttons.push({label: S.explain, icon: 'fa fa-magic', action: function () {
                explain({target: 'host', ip: ip}, '#pa_ai_answer');
            }});
        }
        buttons.push({label: S.propose, icon: 'fa fa-ban', action: function (d) { d.close(); propose(ip); }});
        buttons.push({label: S.close, action: function (d) { d.close(); }});
        I.dialog({title: hostLabel(h), message: html, buttons: buttons});
    }

    function explain(payload, target) {
        let dlg = null;
        if (target) {
            $(target).html(I.wait(S.asking));
        } else {
            dlg = I.dialog({title: S.explain, message: I.wait(S.asking),
                buttons: [{label: S.close, action: function (d) { d.close(); }}]});
        }
        ajaxCall(API + 'explain?days=' + days, payload, function (data) {
            const html = I.answer(data, S);
            if (target) {
                $(target).html('<h4><i class="fa fa-magic"></i> ' + esc(S.explain) + '</h4>' + html);
            } else {
                dlg.getModalBody().html(html);
            }
        });
    }

    function propose(ip) {
        const h = ip ? host(ip) : null;
        const pre = h ? h.services.filter(function (s) { return !s.known; }).map(function (s) { return s.service; }) : [];
        const svcs = report.services.length ? report.services : [];
        let html = '<div class="pa-ins-propose"><p class="small text-muted">' + esc(S.proposalOnly) + '</p><h5>' +
            esc(S.services) + '</h5><div class="pa-ins-checks">' + svcs.map(function (s) {
                return '<label class="pa-ins-check"><input type="checkbox" value="' + esc(s.id) + '"' +
                    (pre.indexOf(s.id) >= 0 ? ' checked' : '') + '/> <i style="background:' + color(s.id) + '"></i>' +
                    esc(s.name) + ' <span class="text-muted">(' + esc(s.hosts) + ')</span></label>';
            }).join('') + '</div><h5>' + esc(S.scope) + '</h5><div class="pa-ins-radios">' +
            '<label><input type="radio" name="pa_scope" value="all"' + (h ? '' : ' checked') + '/> ' + esc(S.scopeAll) +
            '</label><label><input type="radio" name="pa_scope" value="host"' + (h ? ' checked' : '') + '/> ' +
            esc(S.scopeHost) + '</label><label><input type="radio" name="pa_scope" value="net"/> ' + esc(S.scopeNet) +
            '</label><input type="text" class="form-control" id="pa_scope_value" value="' + esc(h ? h.ip : '') +
            '" placeholder="192.168.1.0/24"/></div><h5>' + esc(S.method) + '</h5><div class="pa-ins-radios">' +
            '<label><input type="radio" name="pa_method" value="unbound" checked/> ' + esc(S.methodDns) + '</label>' +
            '<label><input type="radio" name="pa_method" value="alias"/> ' + esc(S.methodAlias) + '</label></div>' +
            '<div id="pa_ai_proposal"></div></div>';
        I.dialog({title: S.propose + (h ? ' — ' + hostLabel(h) : ''), message: html, buttons: [
            {label: S.simulate, icon: 'fa fa-flask', cssClass: 'btn-primary', action: function () { simulate(); }},
            {label: S.close, action: function (d) { d.close(); }}
        ]});
    }

    function simulate() {
        const services = $('.pa-ins-checks input:checked').map(function () { return $(this).val(); }).get();
        if (!services.length) {
            $('#pa_ai_proposal').html('<div class="alert alert-warning">' + esc(S.selectService) + '</div>');
            return;
        }
        const scope = $('input[name=pa_scope]:checked').val();
        const req = {services: services.join(','), scope: scope, value: $('#pa_scope_value').val(),
            method: $('input[name=pa_method]:checked').val()};
        $('#pa_ai_proposal').html(I.wait(S.simulate + '...'));
        ajaxCall(API + 'propose?days=' + days, req, function (data) {
            if (!data || data.status !== 'ok') {
                $('#pa_ai_proposal').html('<div class="alert alert-danger">' + esc((data && data.message) || S.error) +
                    '</div>');
                return;
            }
            const sim = data.simulation;
            let html = '<h4>' + esc(S.replay) + ' (' + esc(sim.window_days) + ' ' + esc(S.days) + ')</h4>' +
                '<p><b>' + esc(sim.events_blocked) + '</b> ' + esc(S.wouldBlock) + '; ' + esc(S.affected) + ': ' +
                esc(sim.hosts_affected.length) + '</p>';
            if (sim.hosts_affected.length) {
                html += '<ul class="small">' + sim.hosts_affected.map(function (a) {
                    return '<li>' + esc(a.name || a.ip) + ' — ' + esc(a.events) + '</li>';
                }).join('') + '</ul>';
            }
            if (sim.expected_conflicts.length) {
                html += '<div class="alert alert-danger"><b>' + esc(S.conflicts) + '</b><ul>' +
                    sim.expected_conflicts.map(function (c) {
                        return '<li>' + esc((c.name || c.ip) + ': ' + c.service + ' — ' + c.reason) + '</li>';
                    }).join('') + '</ul></div>';
            }
            html += I.diff(data.diff) + '<p><a class="btn btn-default" href="/' + esc(data.page) +
                '" target="_blank" rel="noopener"><i class="fa fa-external-link"></i> ' + esc(S.openPage) + '</a> ';
            if (typeof PASimulation !== 'undefined' && PASimulation.show) {
                html += '<button type="button" class="btn btn-default" id="pa_ai_plan"><i class="fa fa-list"></i> ' +
                    esc(S.showPlan) + '</button>';
            }
            html += '</p>';
            $('#pa_ai_proposal').html(html);
            $('#pa_ai_plan').on('click', function () {
                PASimulation.show(data.plan, {readOnly: true, title: S.propose});
            });
        });
    }

    function load(force) {
        $('#pa_aiusage').html(toolbar() + I.wait(S.loading));
        bind();
        const done = function (data) {
            report = data;
            render();
        };
        if (force) {
            ajaxCall(API + 'run?days=' + days, {}, done);
        } else {
            ajaxGet(API + 'report', {days: days}, done);
        }
    }

    function init(opts) {
        opts = opts || {};
        S = Object.assign(S, opts.strings || {});
        aiEnabled = !!opts.aiEnabled;
        ajaxGet('/api/policyanalyzer/ai/status', {}, function (st) {
            aiEnabled = !!(st && st.enabled);
            if (report) {
                render();
            }
        });
        load(false);
    }

    return {init: init, reload: load};
})();
