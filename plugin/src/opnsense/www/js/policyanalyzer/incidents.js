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
 * Firewall: Incidents (/ui/policyanalyzer/incidents).
 *
 *   PAIncidents.init({strings: {...}, root: '#pa-incidents'})     once, after PASimulation.setStrings()
 *
 * List of cases (severity, title, entities, last activity, state) with filters; the detail of the selected case
 * on the right (>= 1200 px) or in a dialog (full screen on phones): score factors, entities with their actions,
 * AI summary with the suggested actions as buttons, evidence timeline, notes and history. Below 768 px the list
 * is a list of cards. Changes (install, state, note) are journaled; a quarantine suggested by a case opens the
 * existing quarantine_add simulation; nothing is applied without the operator.
 */
const PAIncidents = (function () {
    'use strict';

    const API = '/api/policyanalyzer/incidents/';
    const WIDE = '(min-width: 1200px)';
    const MOBILE = '(max-width: 767px)';
    const ROWS = 25;
    const DURATIONS = ['l1', 'l2', 'l3', 'l4', 'l5'];
    const DURATION_LABELS = {l1: '30 min', l2: '2 h', l3: '2 days', l4: '10 days', l5: '30 days'};

    let S = {
        title: 'Incidents', notInstalled: 'Not installed', installed: 'Correlating every 5 minutes',
        noCron: 'installed, but the cron job is missing', install: 'Install', remove: 'Remove', runNow: 'Run now',
        refresh: 'Refresh', digest: 'Daily digest', tidy: 'Tidy repeats',
        tidyHelp: 'Resolve the open low cases made only by short repeat quarantines (simulated first, undoable)', lastRun: 'last run', nextRun: 'next run', never: 'never',
        open: 'open', new24h: 'new in 24 h', active24h: 'active in 24 h',
        installHelp: 'Installing creates the case database and a cron job every 5 minutes. The simulation shows every step first.',
        sev_critical: 'Critical', sev_high: 'High', sev_medium: 'Medium', sev_low: 'Low',
        st_new: 'New', st_investigating: 'In analysis', st_resolved: 'Resolved', st_false_positive: 'False positive',
        st_open: 'Open (new + in analysis)', any: 'any', state: 'State', severity: 'Severity', rule: 'Rule',
        period: 'Period', search: 'Address, port or title', apply: 'Apply', clear: 'Clear', filters: 'Filters',
        d1: 'last 24 h', d7: 'last 7 days', d30: 'last 30 days', d365: 'last year', dall: 'all',
        caseCol: 'Case', entities: 'Entities', lastActivity: 'Last activity', score: 'Score',
        noCases: 'No cases match the filters.', selectCase: 'Select a case to see its timeline.',
        prev: 'Previous', next: 'Next', page: 'page', of: 'of',
        r_scan_then_allowed: 'Scan then allowed', r_ids_and_allowed: 'IDS + allowed traffic',
        r_internal_to_bad: 'Internal host to bad destination', r_campaign: 'Campaign', r_repeat_offender: 'Repeat offender',
        r_port_spike: 'Port spike',
        k_ext: 'external', k_int: 'internal', k_own: 'firewall', k_port: 'port', k_rule: 'rule',
        factors: 'Why this score', timeline: 'Timeline', notes: 'Notes', history: 'History', addNote: 'Add note',
        notePlaceholder: 'What you checked, who you called, what you decided...', changeState: 'Change state',
        stateNote: 'Note (optional)', confirm: 'Confirm', cancel: 'Cancel', close: 'Close',
        summarize: 'Summarize with AI', resummarize: 'Summarize again', preview: 'Show what would be sent',
        asking: 'Asking the AI, this can take a while...', aiDisabled: 'AI assistance is disabled in the settings.',
        aiSummary: 'AI summary', hypothesis: 'Hypothesis', impact: 'Impact', nextSteps: 'Next steps',
        confidence: 'confidence', suggested: 'Suggested actions', suggestedHelp: 'Each button opens the action with its simulation; nothing runs by itself.',
        aiNote: 'Generated by the AI from the anonymized case. It may be wrong: check the timeline.',
        quarantine: 'Quarantine', quarantineFor: 'Put {ip} in quarantine', duration: 'Duration', liveView: 'Open in Live View',
        copy: 'Copy', inQuarantine: 'in quarantine', level: 'level', recently: 'quarantined recently',
        first: 'first', last: 'last', count: 'count', created: 'created', state_changed: 'state',
        log_created: 'Case created', log_state: 'State changed', log_note: 'Note', log_summary: 'AI summary',
        log_escalated: 'Severity raised', previous: 'previous case', suppressed: 'matches absorbed as false positive',
        journal: 'Recorded in the action history, it can be reverted there.', error: 'Error', done: 'Done',
        day: 'Day', generate: 'Generate with AI', regenerate: 'Generate again', noDigest: 'No digest for this day yet.',
        cases: 'cases', newCases: 'new', byRule: 'by rule', topCases: 'Most relevant cases', generatedAt: 'generated',
        src_filter: 'filter', src_suricata: 'IDS', src_quarantine: 'quarantine', src_dns: 'DNS', src_engine: 'engine',
        alsoMatched: 'Also matched', f_recurrence: 'Recurrence', f_contained: 'Already contained by the quarantine',
        f_allowed_internal: 'Reached an internal host', f_ids_sev1: 'IDS severity 1', f_ids_sev2: 'IDS severity 2',
        f_same_port: 'Allowed traffic on the port of the alert', f_exposed: 'Internet reachable service involved',
        f_allowed_to_bad: 'Traffic to a quarantined address was allowed', f_active_quarantine: 'Destination in quarantine now',
        f_dns: 'Blocked DNS queries', f_volume: 'Event volume', f_wide_scan: 'Wide port scan',
        f_some_allowed: 'Part of it was allowed', f_spike_ratio: 'Far above the usual hour', f_level: 'High quarantine level',
        evidenceMore: 'showing {n} of {total} evidence lines', back: 'Back', incidentComment: 'Incident #{id}',
        ago_s: 'just now', ago_m: '{n} min ago', ago_h: '{n} h ago', ago_d: '{n} d ago'
    };
    let opts = {};
    let $root = null;
    let status = null;
    let filters = {state: 'open', days: '7'};
    let page = 1;
    let selected = null;
    let lastList = null;
    let timer = null;

    const esc = function (v) { return PASimulation.escape(v); };
    const t = function (key, ctx) {
        let text = S[key] !== undefined ? S[key] : key;
        Object.keys(ctx || {}).forEach(function (k) { text = text.replace('{' + k + '}', ctx[k]); });
        return text;
    };

    function b64(text) {
        return btoa(unescape(encodeURIComponent(text)));
    }

    function fmtTime(epoch) {
        if (!epoch) {
            return '-';
        }
        const d = new Date(epoch * 1000);
        const p = function (n) { return String(n).padStart(2, '0'); };
        return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' +
            p(d.getMinutes());
    }

    function ago(epoch) {
        if (!epoch) {
            return '-';
        }
        const sec = Math.max(0, Date.now() / 1000 - epoch);
        if (sec < 60) { return t('ago_s'); }
        if (sec < 3600) { return t('ago_m', {n: Math.floor(sec / 60)}); }
        if (sec < 86400) { return t('ago_h', {n: Math.floor(sec / 3600)}); }
        return t('ago_d', {n: Math.floor(sec / 86400)});
    }

    function sevBadge(sev, score) {
        return '<span class="pa-i-sev pa-i-sev-' + esc(sev) + '">' + esc(t('sev_' + sev)) +
            (score !== undefined ? ' <b>' + esc(score) + '</b>' : '') + '</span>';
    }

    function stateBadge(state) {
        return '<span class="pa-i-state pa-i-st-' + esc(state) + '">' + esc(t('st_' + state)) + '</span>';
    }

    function entityChip(e, withMenu) {
        const kind = e.kind || 'ext';
        let html = '<span class="pa-i-ent pa-i-ent-' + esc(kind) + (e.role === 'primary' ? ' pa-i-ent-primary' : '') +
            '" title="' + esc(t('k_' + kind)) + '"';
        if (withMenu && (kind === 'ext' || kind === 'int' || kind === 'own')) {
            html += ' role="button" tabindex="0" data-ip="' + esc(e.value) + '" data-kind="' + esc(kind) + '"';
        }
        html += '>' + (withMenu ? '<small>' + esc(t('k_' + kind)) + '</small> ' : '');
        if (kind === 'rule') {
            html += esc((e.info && e.info.description) || e.value);
        } else {
            html += '<code>' + esc(e.value) + '</code>';
        }
        const q = e.info && e.info.quarantine;
        if (q) {
            html += ' <span class="pa-i-qtag' + (q.active ? ' pa-i-qtag-on' : '') + '">' +
                esc(q.active ? t('inQuarantine') + ' L' + q.level : t('recently')) + '</span>';
        }
        return html + '</span>';
    }

    function liveViewUrl(ip) {
        return '/ui/diagnostics/firewall/log#field=src&operator=' + encodeURIComponent('=') + '&value=' +
            encodeURIComponent(ip);
    }

    function ruleName(rule) {
        return t('r_' + rule);
    }

    function factorLabel(f) {
        const id = String(f.id || '');
        if (id.indexOf('rule:') === 0) { return t('rule') + ': ' + ruleName(id.slice(5)); }
        if (id.indexOf('also:') === 0) { return t('alsoMatched') + ': ' + ruleName(id.slice(5)); }
        return S['f_' + id] !== undefined ? S['f_' + id] : f.label;
    }

    /* ------------------------------------------------------------------------------------- header */

    function renderHeader() {
        const $h = $root.find('.pa-i-head').empty();
        if (!status) {
            return;
        }
        const left = $('<div class="pa-i-head-state"/>');
        if (!status.installed) {
            left.append('<span class="label label-default">' + esc(t('notInstalled')) + '</span> ')
                .append($('<button class="btn btn-primary btn-xs"/>').text(t('install')).on('click', install))
                .append(' <small class="text-muted">' + esc(t('installHelp')) + '</small>');
            $h.append(left);
            return;
        }
        const cron = (status.cron || []).length > 0;
        left.append('<span class="label ' + (cron ? 'label-success' : 'label-warning') + '">' +
            esc(cron ? t('installed') : t('noCron')) + '</span>');
        if (!cron) {
            left.append(' ').append($('<button class="btn btn-primary btn-xs"/>').text(t('install')).on('click', install));
        }
        const last = status.last_run || {};
        left.append(' <small class="text-muted">' + esc(t('lastRun')) + ': ' +
            esc(last.ts ? fmtTime(Date.parse(last.ts) / 1000) : t('never')) +
            (last.duration_ms !== undefined ? ' (' + esc(last.duration_ms) + ' ms)' : '') + '</small>');
        $h.append(left);
        const counts = status.counts || {};
        const sev = counts.open_by_severity || {};
        const cards = $('<div class="pa-i-cards"/>');
        // each card: count in the severity colour and a bar with its share of all open cases (incidents.css)
        const openTotal = ['critical', 'high', 'medium', 'low'].reduce(function (sum, k) { return sum + (Number(sev[k]) || 0); }, 0);
        ['critical', 'high', 'medium', 'low'].forEach(function (s) {
            const on = filters.severity === s;
            const n = Number(sev[s]) || 0;
            const share = openTotal ? Math.round(n * 1000 / openTotal) / 10 : 0;
            const card = $('<button type="button" class="pa-i-card pa-i-card-' + s + (on ? ' pa-i-card-on' : '') +
                (n ? '' : ' pa-i-card-empty') + '"/>')
                .attr('aria-pressed', on ? 'true' : 'false')
                .attr('title', share + '%')
                .css('--pa-share', share + '%')
                .html('<span class="pa-i-count">' + esc(n) + '</span><span class="pa-i-card-label">' +
                    esc(t('sev_' + s)) + '</span><span class="pa-i-share" aria-hidden="true"><span></span></span>');
            card.on('click', function () {
                filters.severity = on ? '' : s;
                filters.state = 'open';
                page = 1;
                syncFilterForm();
                loadList();
                renderHeader();
            });
            cards.append(card);
        });
        cards.append('<div class="pa-i-card pa-i-card-info"><span class="pa-i-count"><i class="fa fa-plus-circle" ' +
            'aria-hidden="true"></i> ' + esc(counts.new_24h || 0) + '</span><span class="pa-i-card-label">' + esc(t('new24h')) +
            '</span></div>');
        $h.append(cards);
        const tools = $('<div class="pa-i-tools btn-group"/>');
        tools.append($('<button class="btn btn-default btn-sm"/>').html('<i class="fa fa-refresh"></i> ' + esc(t('refresh')))
            .on('click', refresh));
        tools.append($('<button class="btn btn-default btn-sm"/>').html('<i class="fa fa-play"></i> ' + esc(t('runNow')))
            .on('click', runNow));
        tools.append($('<button class="btn btn-default btn-sm"/>').html('<i class="fa fa-newspaper-o"></i> ' + esc(t('digest')))
            .on('click', function () { openDigest('today'); }));
        tools.append($('<button class="btn btn-default btn-sm"/>').html('<i class="fa fa-compress"></i> ' + esc(t('tidy')))
            .attr('title', t('tidyHelp'))
            .on('click', function () {
                PASimulation.run({action: 'incidents_tidy', args: [], endpoint: API.replace(/\/$/, ''),
                                  title: t('title') + ': ' + t('tidy'), onDone: refresh});
            }));
        $h.append(tools);
    }

    function install() {
        PASimulation.run({action: 'install_incidents', args: [], endpoint: API.replace(/\/$/, ''),
                          title: t('title') + ': ' + t('install'), onDone: refresh});
    }

    function runNow() {
        const btn = $root.find('.pa-i-tools button').eq(1).prop('disabled', true);
        ajaxCall(API + 'run', {}, function (data) {
            btn.prop('disabled', false);
            if (!data || data.status !== 'ok') {
                BootstrapDialog.alert({type: BootstrapDialog.TYPE_WARNING, title: t('error'),
                                       message: esc((data && data.message) || t('error'))});
            }
            refresh();
        });
    }

    /* ------------------------------------------------------------------------------------- filters */

    function buildFilters() {
        const $f = $root.find('.pa-i-filters').empty();
        const sel = function (name, items) {
            const s = $('<select class="form-control input-sm"/>').attr('name', name).attr('aria-label', t(name));
            items.forEach(function (i) { s.append($('<option/>').val(i[0]).text(i[1])); });
            return s;
        };
        $f.append($('<label class="pa-i-f"/>').append('<span>' + esc(t('state')) + '</span>').append(sel('state', [
            ['open', t('st_open')], ['new', t('st_new')], ['investigating', t('st_investigating')],
            ['resolved', t('st_resolved')], ['false_positive', t('st_false_positive')], ['', t('any')]])));
        $f.append($('<label class="pa-i-f"/>').append('<span>' + esc(t('severity')) + '</span>').append(sel('severity', [
            ['', t('any')], ['critical', t('sev_critical')], ['high', t('sev_high')], ['medium', t('sev_medium')],
            ['low', t('sev_low')]])));
        $f.append($('<label class="pa-i-f"/>').append('<span>' + esc(t('rule')) + '</span>').append(sel('rule', [
            ['', t('any')]].concat(['scan_then_allowed', 'ids_and_allowed', 'internal_to_bad', 'campaign',
                                    'repeat_offender', 'port_spike'].map(function (r) { return [r, ruleName(r)]; })))));
        $f.append($('<label class="pa-i-f"/>').append('<span>' + esc(t('period')) + '</span>').append(sel('days', [
            ['1', t('d1')], ['7', t('d7')], ['30', t('d30')], ['365', t('d365')], ['', t('dall')]])));
        $f.append($('<label class="pa-i-f pa-i-f-search"/>').append('<span>' + esc(t('search')) + '</span>')
            .append('<input type="search" class="form-control input-sm" name="search" maxlength="64" ' +
                'pattern="[0-9A-Za-z:./_-]*" placeholder="203.0.113.9, 22/tcp"/>'));
        const go = $('<button type="submit" class="btn btn-primary btn-sm"/>').text(t('apply'));
        const clear = $('<button type="button" class="btn btn-default btn-sm"/>').text(t('clear'));
        $f.append($('<div class="pa-i-f pa-i-f-buttons"/>').append(go).append(' ').append(clear));
        $f.on('submit', function (e) {
            e.preventDefault();
            filters = {};
            $f.find('select, input').each(function () {
                const v = String($(this).val() || '').trim();
                if (v) { filters[this.name] = v; }
            });
            page = 1;
            loadList();
            renderHeader();
        });
        clear.on('click', function () {
            filters = {state: 'open', days: '7'};
            syncFilterForm();
            page = 1;
            loadList();
            renderHeader();
        });
        syncFilterForm();
    }

    function syncFilterForm() {
        const $f = $root.find('.pa-i-filters');
        $f.find('select, input').each(function () { $(this).val(filters[this.name] || ''); });
    }

    /* ------------------------------------------------------------------------------------- list */

    function loadList() {
        if (!status || !status.installed) {
            $root.find('.pa-i-list').html('<div class="pa-i-empty">' + esc(t('installHelp')) + '</div>');
            return;
        }
        const params = Object.assign({page: page, rows: ROWS}, filters);
        ajaxGet(API + 'search', params, function (data) {
            lastList = data || {rows: []};
            renderList();
        });
    }

    function entitiesHtml(row, max) {
        const ents = (row.entities || []).filter(function (e) { return e.kind !== 'rule'; }).slice(0, max);
        let html = ents.map(function (e) { return entityChip(e, false); }).join(' ');
        const more = (row.entity_count || 0) - ents.length;
        if (more > 0) {
            html += ' <small class="text-muted">+' + esc(more) + '</small>';
        }
        return html;
    }

    function rulesHtml(row) {
        return (row.rules || []).map(function (r) {
            return '<span class="pa-i-rule">' + esc(ruleName(r)) + '</span>';
        }).join(' ');
    }

    function renderList() {
        const $l = $root.find('.pa-i-list').empty();
        const rows = (lastList && lastList.rows) || [];
        if (!rows.length) {
            $l.html('<div class="pa-i-empty">' + esc((lastList && lastList.message) || t('noCases')) + '</div>');
            renderPager();
            return;
        }
        if (window.matchMedia(MOBILE).matches) {
            const cards = $('<div class="pa-i-mcards" role="list"/>');
            rows.forEach(function (row) {
                const card = $('<div class="pa-i-mcard" role="listitem" tabindex="0"/>').attr('data-id', row.id)
                    .toggleClass('pa-i-sel', selected === row.id)
                    .addClass('pa-i-row-' + String(row.severity || 'low').replace(/[^a-z]/g, ''))
                    .append('<div class="pa-i-mcard-top">' + sevBadge(row.severity, row.score) + ' ' + stateBadge(row.state) +
                        ' <small class="text-muted">#' + esc(row.id) + '</small></div>')
                    .append('<div class="pa-i-mcard-title">' + esc(row.title) + '</div>')
                    .append('<div class="pa-i-mcard-ents">' + entitiesHtml(row, 2) + '</div>')
                    .append('<div class="pa-i-mcard-foot"><span>' + rulesHtml(row) + '</span><small class="text-muted">' +
                        esc(ago(row.last_activity)) + '</small></div>');
                cards.append(card);
            });
            $l.append(cards);
        } else {
            const table = $('<table class="table table-condensed table-hover pa-i-table"><thead><tr>' +
                '<th class="pa-i-c-sev">' + esc(t('severity')) + '</th><th class="pa-i-c-title">' + esc(t('caseCol')) +
                '</th><th class="pa-i-c-ents">' + esc(t('entities')) + '</th><th class="pa-i-c-last">' +
                esc(t('lastActivity')) + '</th><th class="pa-i-c-state">' + esc(t('state')) + '</th></tr></thead><tbody></tbody></table>');
            rows.forEach(function (row) {
                const tr = $('<tr tabindex="0"/>').attr('data-id', row.id).toggleClass('pa-i-sel', selected === row.id)
                    .addClass('pa-i-row-' + String(row.severity || 'low').replace(/[^a-z]/g, ''));
                tr.append('<td class="pa-i-c-sev">' + sevBadge(row.severity, row.score) + '</td>');
                tr.append('<td class="pa-i-c-title"><div class="pa-i-title">' + esc(row.title) + '</div><div>' +
                    rulesHtml(row) + ' <small class="text-muted">#' + esc(row.id) + '</small></div></td>');
                tr.append('<td class="pa-i-c-ents">' + entitiesHtml(row, 2) + '</td>');
                tr.append('<td class="pa-i-c-last" title="' + esc(fmtTime(row.last_activity)) + '">' +
                    esc(ago(row.last_activity)) + '<br/><small class="text-muted">' + esc(fmtTime(row.last_activity)) +
                    '</small></td>');
                tr.append('<td class="pa-i-c-state">' + stateBadge(row.state) + '</td>');
                table.find('tbody').append(tr);
            });
            $l.append(table);
        }
        $l.find('[data-id]').on('click keydown', function (e) {
            if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') {
                return;
            }
            e.preventDefault();
            select(parseInt($(this).attr('data-id'), 10));
        });
        renderPager();
        if (window.matchMedia(WIDE).matches && !selected && rows.length) {
            select(rows[0].id);
        }
    }

    function renderPager() {
        const $p = $root.find('.pa-i-pager').empty();
        const total = (lastList && lastList.total) || 0;
        const pages = Math.max(1, Math.ceil(total / ROWS));
        if (pages <= 1) {
            $p.html('<small class="text-muted">' + esc(total) + ' ' + esc(t('cases')) + '</small>');
            return;
        }
        const prev = $('<button class="btn btn-default btn-xs"/>').text(t('prev')).prop('disabled', page <= 1)
            .on('click', function () { page -= 1; loadList(); });
        const next = $('<button class="btn btn-default btn-xs"/>').text(t('next')).prop('disabled', page >= pages)
            .on('click', function () { page += 1; loadList(); });
        $p.append(prev).append(' <small>' + esc(t('page')) + ' ' + esc(page) + ' ' + esc(t('of')) + ' ' + esc(pages) +
            ' · ' + esc(total) + ' ' + esc(t('cases')) + '</small> ').append(next);
    }

    /* ------------------------------------------------------------------------------------- detail */

    function select(id) {
        selected = id;
        $root.find('.pa-i-list [data-id]').removeClass('pa-i-sel');
        $root.find('.pa-i-list [data-id="' + id + '"]').addClass('pa-i-sel');
        ajaxGet(API + 'case', {id: id}, function (data) {
            if (!data || data.status !== 'ok') {
                showDetail($('<div class="alert alert-warning"/>').text((data && data.message) || t('error')), null);
                return;
            }
            showDetail(renderDetail(data.case), data.case);
        });
    }

    function showDetail($content, kase) {
        if (window.matchMedia(WIDE).matches) {
            $root.find('.pa-i-detail').empty().append($content);
            return;
        }
        if (opts.dialog) {
            opts.dialog.close();
        }
        opts.dialog = PASimulation.dialog({
            title: kase ? '#' + kase.id + ' · ' + kase.title : t('title'),
            message: $('<div class="pa-i-detail pa-i-detail-dialog"/>').append($content),
            size: BootstrapDialog.SIZE_WIDE,
            buttons: [{label: t('close'), action: function (d) { d.close(); }}],
            onhidden: function () { opts.dialog = null; }
        });
    }

    function section(title, body, extra) {
        return $('<section class="pa-i-sec"/>').append($('<h4/>').text(title).append(extra || '')).append(body);
    }

    function renderDetail(c) {
        const $d = $('<div class="pa-i-case"/>').attr('data-id', c.id);
        const head = $('<div class="pa-i-case-head"/>');
        head.append('<div class="pa-i-case-badges">' + sevBadge(c.severity, c.score) + ' ' + stateBadge(c.state) +
            ' <small class="text-muted">#' + esc(c.id) + '</small></div>');
        head.append($('<h3 class="pa-i-case-title"/>').text(c.title));
        head.append('<div class="pa-i-case-meta text-muted"><span>' + esc(t('first')) + ': ' + esc(fmtTime(c.first_seen)) +
            '</span><span>' + esc(t('last')) + ': ' + esc(fmtTime(c.last_activity)) + ' (' + esc(ago(c.last_activity)) +
            ')</span>' + (c.previous_id ? '<span>' + esc(t('previous')) + ' #' + esc(c.previous_id) + '</span>' : '') +
            (c.suppressed ? '<span>' + esc(c.suppressed) + ' ' + esc(t('suppressed')) + '</span>' : '') + '</div>');
        $d.append(head);

        const actions = $('<div class="pa-i-case-actions"/>');
        const stateGroup = $('<div class="btn-group"/>');
        stateGroup.append('<button type="button" class="btn btn-default btn-sm dropdown-toggle" data-toggle="dropdown" ' +
            'aria-haspopup="true" aria-expanded="false"><i class="fa fa-flag"></i> ' + esc(t('changeState')) +
            ' <span class="caret"></span></button>');
        const menu = $('<ul class="dropdown-menu"/>');
        ['new', 'investigating', 'resolved', 'false_positive'].forEach(function (s) {
            if (s === c.state) { return; }
            menu.append($('<li/>').append($('<a href="#"/>').text(t('st_' + s)).on('click', function (e) {
                e.preventDefault();
                changeState(c, s);
            })));
        });
        stateGroup.append(menu);
        actions.append(stateGroup);
        const aiBtn = $('<button type="button" class="btn btn-primary btn-sm pa-i-ai-btn"/>')
            .html('<i class="fa fa-magic"></i> ' + esc(c.summary ? t('resummarize') : t('summarize')))
            .on('click', function () { summarize(c, false, $(this)); });
        const prevBtn = $('<button type="button" class="btn btn-link btn-sm"/>').text(t('preview'))
            .on('click', function () { summarize(c, true, $(this)); });
        if (status && status.ai_enabled === false) {
            aiBtn.prop('disabled', true).attr('title', t('aiDisabled'));
        }
        actions.append(' ').append(aiBtn).append(prevBtn);
        $d.append(actions);
        $d.append('<div class="pa-i-ai-slot"></div>');
        if (c.summary && c.summary.data) {
            $d.find('.pa-i-ai-slot').append(renderSummary(c, c.summary.data, c.summary.ts));
        }

        const factors = $('<ul class="pa-i-factors"/>');
        (c.factors || []).forEach(function (f) {
            factors.append('<li><span class="pa-i-pts' + (f.points < 0 ? ' pa-i-pts-neg' : '') + '">' +
                (f.points > 0 ? '+' : '') + esc(f.points) + '</span> ' + esc(factorLabel(f)) +
                (f.detail ? ' <small class="text-muted">' + esc(f.detail) + '</small>' : '') + '</li>');
        });
        factors.append('<li class="pa-i-total"><span class="pa-i-pts">=' + esc(c.score) + '</span> ' +
            sevBadge(c.severity) + '</li>');
        $d.append(section(t('factors'), factors));

        const ents = $('<div class="pa-i-ents"/>');
        (c.entities || []).forEach(function (e) { ents.append(entityChip(e, true)).append(' '); });
        ents.on('click keydown', '[data-ip]', function (e) {
            if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') {
                return;
            }
            e.preventDefault();
            entityMenu(c, $(this));
        });
        $d.append(section(t('entities'), ents));

        const tl = $('<ol class="pa-i-timeline"/>');
        (c.evidence || []).slice().sort(function (a, b) {
            return (b.last || b.ts || 0) - (a.last || a.ts || 0);
        }).forEach(function (ev) {
            const when = ev.first && ev.last && ev.last - ev.first > 59 ?
                fmtTime(ev.first) + ' → ' + fmtTime(ev.last).slice(11) : fmtTime(ev.last || ev.first || ev.ts);
            tl.append('<li class="pa-i-ev pa-i-ev-' + esc(ev.source) + '"><div class="pa-i-ev-when">' + esc(when) +
                ' <span class="pa-i-src">' + esc(t('src_' + ev.source)) + '</span>' +
                (ev.rule ? ' <span class="pa-i-rule">' + esc(ruleName(ev.rule)) + '</span>' : '') +
                (ev.count > 1 ? ' <span class="badge">' + esc(ev.count) + '</span>' : '') +
                '</div><div class="pa-i-ev-text">' + esc(ev.text) + '</div></li>');
        });
        const more = c.evidence_total > (c.evidence || []).length ?
            ' <small class="text-muted">' + esc(t('evidenceMore', {n: (c.evidence || []).length, total: c.evidence_total})) +
            '</small>' : '';
        $d.append(section(t('timeline'), tl, more));

        const notes = $('<div class="pa-i-notes"/>');
        (c.notes || []).forEach(function (n) {
            notes.append($('<div class="pa-i-note"/>').append('<small class="text-muted">' + esc(fmtTime(n.ts)) + '</small> ')
                .append($('<span/>').text(n.text)));
        });
        const form = $('<form class="pa-i-noteform"/>')
            .append($('<textarea class="form-control" rows="2" maxlength="180"/>').attr('placeholder', t('notePlaceholder'))
                .attr('aria-label', t('addNote')))
            .append($('<button type="submit" class="btn btn-default btn-sm"/>').text(t('addNote')));
        form.on('submit', function (e) {
            e.preventDefault();
            const text = $(this).find('textarea').val().trim();
            if (!text) { return; }
            ajaxCall(API + 'note', {id: c.id, note: text}, function (data) { afterChange(data, c.id); });
        });
        notes.append(form);
        $d.append(section(t('notes'), notes));

        const log = $('<ul class="pa-i-log"/>');
        (c.log || []).slice().reverse().forEach(function (l) {
            let text = t('log_' + l.kind);
            if (l.kind === 'state') {
                text += ': ' + t('st_' + l.from_state) + ' → ' + t('st_' + l.to_state);
            }
            log.append('<li><small class="text-muted">' + esc(fmtTime(l.ts)) + '</small> ' + esc(text) +
                (l.note ? ' <span class="text-muted">— ' + esc(l.note) + '</span>' : '') + '</li>');
        });
        $d.append(section(t('history'), log));
        return $d;
    }

    function renderSummary(c, s, ts) {
        const box = $('<div class="pa-i-ai"/>');
        box.append('<h4><i class="fa fa-magic"></i> ' + esc(t('aiSummary')) + ' <small class="text-muted">' +
            esc(fmtTime(ts)) + (s.model ? ' · ' + esc(s.model) : '') +
            (s.confidence ? ' · ' + esc(t('confidence')) + ': ' + esc(s.confidence) : '') + '</small></h4>');
        if (s.summary) { box.append($('<p class="pa-i-ai-summary"/>').text(s.summary)); }
        const dl = $('<dl class="pa-i-ai-dl"/>');
        if (s.hypothesis) { dl.append($('<dt/>').text(t('hypothesis'))).append($('<dd/>').text(s.hypothesis)); }
        if (s.impact) { dl.append($('<dt/>').text(t('impact'))).append($('<dd/>').text(s.impact)); }
        if (dl.children().length) { box.append(dl); }
        if ((s.next_steps || []).length) {
            const ol = $('<ol class="pa-i-steps"/>');
            s.next_steps.forEach(function (step) { ol.append($('<li/>').text(step)); });
            box.append($('<div/>').append($('<strong/>').text(t('nextSteps'))).append(ol));
        }
        if ((s.actions || []).length) {
            const bar = $('<div class="pa-i-suggested"/>').append($('<strong/>').text(t('suggested')))
                .append(' <small class="text-muted">' + esc(t('suggestedHelp')) + '</small>');
            const btns = $('<div class="pa-i-suggested-btns"/>');
            s.actions.forEach(function (a) { btns.append(actionButton(c, a)); });
            box.append(bar.append(btns));
        }
        box.append('<p class="pa-i-ai-note text-muted"><small>' + esc(t('aiNote')) + '</small></p>');
        return box;
    }

    function actionButton(c, a) {
        let btn;
        if (a.kind === 'quarantine') {
            btn = $('<button type="button" class="btn btn-danger btn-sm"/>')
                .html('<i class="fa fa-ban"></i> ' + esc(t('quarantineFor', {ip: a.target})) + ' · ' +
                    esc(DURATION_LABELS[a.duration] || a.duration));
            btn.on('click', function () { quarantine(c, a.target, a.duration); });
        } else if (a.kind === 'state') {
            btn = $('<button type="button" class="btn btn-default btn-sm"/>')
                .html('<i class="fa fa-flag"></i> ' + esc(t('st_' + a.state)));
            btn.on('click', function () { changeState(c, a.state); });
        } else {
            btn = $('<a class="btn btn-default btn-sm" target="_blank" rel="noopener"/>').attr('href', a.url)
                .html('<i class="fa fa-external-link"></i> ' + esc(a.label));
        }
        if (a.why) {
            btn.attr('title', a.why);
        }
        return $('<span class="pa-i-sbtn"/>').append(btn).append(a.why ? '<small class="text-muted">' + esc(a.why) + '</small>' : '');
    }

    function entityMenu(c, $chip) {
        const ip = $chip.attr('data-ip');
        const kind = $chip.attr('data-kind');
        const body = $('<div class="pa-i-entmenu"/>');
        body.append($('<a class="btn btn-default btn-block" target="_blank" rel="noopener"/>').attr('href', liveViewUrl(ip))
            .html('<i class="fa fa-list"></i> ' + esc(t('liveView'))));
        if (kind === 'ext') {
            const row = $('<div class="pa-i-qrow"/>');
            const sel = $('<select class="form-control"/>').attr('aria-label', t('duration'));
            DURATIONS.forEach(function (d) { sel.append($('<option/>').val(d).text(DURATION_LABELS[d])); });
            row.append($('<label/>').text(t('duration'))).append(sel);
            body.append(row).append($('<button class="btn btn-danger btn-block"/>')
                .html('<i class="fa fa-ban"></i> ' + esc(t('quarantineFor', {ip: ip})))
                .on('click', function () { dlg.close(); quarantine(c, ip, sel.val()); }));
        }
        body.append($('<button class="btn btn-default btn-block"/>').html('<i class="fa fa-copy"></i> ' + esc(t('copy')))
            .on('click', function () {
                if (navigator.clipboard) { navigator.clipboard.writeText(ip); }
                dlg.close();
            }));
        const dlg = PASimulation.dialog({title: ip, message: body, size: BootstrapDialog.SIZE_SMALL,
                                         buttons: [{label: t('close'), action: function (d) { d.close(); }}]});
    }

    function quarantine(c, ip, duration) {
        /* the existing quarantine action, with its simulation (guards, level, the rule) */
        PASimulation.run({action: 'quarantine_add', args: [ip, DURATIONS.includes(duration) ? duration : 'l1',
                                                           b64(t('incidentComment', {id: c.id}))],
                          title: t('quarantineFor', {ip: ip}), onDone: function () { select(c.id); }});
    }

    function changeState(c, state) {
        const body = $('<div/>').append($('<p/>').html(stateBadge(c.state) + ' → ' + stateBadge(state)))
            .append($('<label/>').text(t('stateNote')))
            .append($('<textarea class="form-control" rows="3" maxlength="180"/>').attr('placeholder', t('notePlaceholder')))
            .append('<p class="text-muted"><small>' + esc(t('journal')) + '</small></p>');
        PASimulation.dialog({
            title: t('changeState') + ' · #' + c.id, message: body,
            buttons: [{label: t('cancel'), action: function (d) { d.close(); }},
                      {label: t('confirm'), cssClass: 'btn-primary', action: function (d) {
                          const note = body.find('textarea').val().trim();
                          d.close();
                          ajaxCall(API + 'state', {id: c.id, state: state, note: note}, function (data) {
                              afterChange(data, c.id);
                          });
                      }}]
        });
    }

    function afterChange(data, id) {
        if (!data || data.status === 'error') {
            BootstrapDialog.alert({type: BootstrapDialog.TYPE_WARNING, title: t('error'),
                                   message: esc((data && data.message) || t('error'))});
        }
        refresh();
        select(id);
    }

    function summarize(c, preview, $btn) {
        const slot = $root.find('.pa-i-case[data-id="' + c.id + '"] .pa-i-ai-slot').add(
            $('.pa-i-detail-dialog .pa-i-case[data-id="' + c.id + '"] .pa-i-ai-slot'));
        if (!preview) {
            slot.html('<div class="pa-i-ai pa-i-ai-wait"><i class="fa fa-spinner fa-pulse"></i> ' + esc(t('asking')) + '</div>');
            $btn.prop('disabled', true);
        }
        ajaxCall(API + 'summarize', {id: c.id, preview: preview ? 1 : 0}, function (data) {
            $btn.prop('disabled', false);
            if (preview) {
                const msgs = (data && data.messages) || [];
                PASimulation.dialog({title: t('preview'), size: BootstrapDialog.SIZE_WIDE,
                    message: $('<pre class="pa-i-payload"/>').text(msgs.map(function (m) {
                        return '[' + m.role + ']\n' + m.content;
                    }).join('\n\n') || (data && data.message) || ''),
                    buttons: [{label: t('close'), action: function (d) { d.close(); }}]});
                return;
            }
            if (!data || data.status !== 'ok') {
                slot.html($('<div class="alert alert-warning"/>').text((data && data.message) ||
                    (data && data.status === 'disabled' ? t('aiDisabled') : t('error'))));
                return;
            }
            slot.empty().append(renderSummary(c, data.summary, Date.now() / 1000));
        });
    }

    /* ------------------------------------------------------------------------------------- digest */

    function openDigest(day) {
        const body = $('<div class="pa-i-digest"/>');
        const form = $('<form class="form-inline pa-i-digest-form"/>')
            .append($('<label/>').text(t('day') + ' '))
            .append($('<input type="date" class="form-control input-sm"/>').val(day === 'today' ? '' : day))
            .append(' ').append($('<button type="submit" class="btn btn-default btn-sm"/>').text(t('apply')));
        const content = $('<div class="pa-i-digest-body"/>');
        body.append(form).append(content);
        const load = function (d, mode) {
            const params = {day: d || 'today'};
            const cb = function (data) { renderDigest(content, data, d); };
            if (mode === 'generate') {
                content.find('.pa-i-digest-ai').html('<i class="fa fa-spinner fa-pulse"></i> ' + esc(t('asking')));
                ajaxCall(API + 'digest?day=' + encodeURIComponent(params.day), {day: params.day, mode: 'generate'}, cb);
            } else {
                ajaxGet(API + 'digest', params, cb);
            }
        };
        form.on('submit', function (e) { e.preventDefault(); load(form.find('input').val()); });
        content.on('click', '.pa-i-gen', function () { load(form.find('input').val(), 'generate'); });
        PASimulation.dialog({title: t('digest'), message: body, size: BootstrapDialog.SIZE_WIDE,
                             buttons: [{label: t('close'), action: function (d) { d.close(); }}]});
        load(day === 'today' ? '' : day);
    }

    function renderDigest($c, data, day) {
        $c.empty();
        if (!data || (data.status !== 'ok' && !data.totals)) {
            $c.append($('<div class="alert alert-warning"/>').text((data && data.message) || t('error')));
            return;
        }
        const tot = data.totals || {};
        const sev = tot.by_severity || {};
        $c.append('<p><strong>' + esc(data.day || tot.day) + '</strong> · ' + esc(tot.cases || 0) + ' ' + esc(t('cases')) +
            ' · ' + esc(tot.new_cases || 0) + ' ' + esc(t('newCases')) + ' · ' +
            ['critical', 'high', 'medium', 'low'].map(function (s) {
                return sevBadge(s) + ' ' + esc(sev[s] || 0);
            }).join(' ') + '</p>');
        const ai = $('<div class="pa-i-digest-ai pa-i-ai"/>');
        const d = data.digest && data.digest.data;
        if (data.status === 'disabled' || data.status === 'error') {
            ai.append($('<div class="alert alert-warning"/>').text(data.message || t('error')));
        }
        if (d && d.text) {
            ai.append('<h4><i class="fa fa-magic"></i> ' + esc(t('aiSummary')) + ' <small class="text-muted">' +
                esc(t('generatedAt')) + ' ' + esc(fmtTime(data.digest.ts)) + (d.model ? ' · ' + esc(d.model) : '') +
                '</small></h4>');
            d.text.split(/\n+/).forEach(function (p) { ai.append($('<p/>').text(p)); });
            ai.append('<p class="pa-i-ai-note text-muted"><small>' + esc(t('aiNote')) + '</small></p>');
        } else {
            ai.append($('<p class="text-muted"/>').text(t('noDigest')));
        }
        const gen = $('<button type="button" class="btn btn-primary btn-sm pa-i-gen"/>')
            .html('<i class="fa fa-magic"></i> ' + esc(d && d.text ? t('regenerate') : t('generate')));
        if (status && status.ai_enabled === false) {
            gen.prop('disabled', true).attr('title', t('aiDisabled'));
        }
        ai.append(gen);
        $c.append(ai);
        const top = tot.top_cases || [];
        if (top.length) {
            const ul = $('<ul class="pa-i-digest-top"/>');
            top.forEach(function (c) {
                ul.append('<li>' + sevBadge(c.severity, c.score) + ' ' + stateBadge(c.state) + ' ' + esc(c.title) + '</li>');
            });
            $c.append($('<h4/>').text(t('topCases'))).append(ul);
        }
    }

    /* ------------------------------------------------------------------------------------- lifecycle */

    function refresh() {
        ajaxGet(API + 'status', {}, function (data) {
            status = data || {};
            renderHeader();
            loadList();
        });
    }

    function init(o) {
        opts = o || {};
        S = Object.assign({}, S, opts.strings || {});
        $root = $(opts.root || '#pa-incidents');
        $root.html('<div class="pa-i-head"></div><form class="pa-i-filters" role="search"></form>' +
            '<div class="pa-i-body"><div class="pa-i-left"><div class="pa-i-list"></div><div class="pa-i-pager"></div></div>' +
            '<div class="pa-i-detail" aria-live="polite"><div class="pa-i-empty">' + esc(t('selectCase')) + '</div></div></div>');
        buildFilters();
        refresh();
        let width = window.innerWidth;
        $(window).on('resize', function () {
            const crossed = [768, 1200].some(function (b) { return (width < b) !== (window.innerWidth < b); });
            width = window.innerWidth;
            if (crossed && lastList) {
                renderList();
            }
        });
        clearInterval(timer);
        timer = setInterval(function () {
            if (!document.hidden && !$('.modal.in').length) {
                refresh();
            }
        }, 60000);
    }

    return {init: init, refresh: refresh, select: select, openDigest: openDigest};
})();
