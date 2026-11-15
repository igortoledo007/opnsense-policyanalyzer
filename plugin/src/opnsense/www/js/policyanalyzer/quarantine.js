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
 * "Quarantine" tab of the Policy Analyzer page (automatic quarantine, rule "Max Cyber IA").
 *
 *   PAQuarantine.init({strings: {...}, onChange: function () {}})   once, after PASimulation.setStrings()
 *   PAQuarantine.refresh()                                          status + grid (when the tab is shown)
 *
 * Every change goes through PASimulation (simulate, confirm, apply) and the action journal; the backend
 * recomputes and validates everything (guards included). Desktop: UIBootgrid with the priority columns
 * (address, level, remaining, reason, actions) always visible, the others in the column chooser.
 * Below 768 px the same search is a list of label | value cards with a compact action menu.
 * Install, Setup, Repair and Remove open the quarantine setup assistant (quarantine-setup.js, PAQSetup): the
 * installation is done and undone step by step there.
 */
const PAQuarantine = (function () {
    'use strict';

    const API = '/api/policyanalyzer/quarantine/';
    const MOBILE = '(max-width: 767px)';
    const BATCH_MAX = 30;
    const LEVELS = {1: '30 min', 2: '2 h', 3: '2 days', 4: '10 days', 5: '30 days', 6: 'permanent'};
    const DURATIONS = ['auto', 'l1', 'l2', 'l3', 'l4', 'l5', 'permanent'];

    let S = {
        notInstalled: 'Not installed', active: 'Active', paused: 'Paused', ruleOn: 'rule on', ruleOff: 'rule off',
        install: 'Install', remove: 'Remove', pause: 'Pause', resume: 'Resume', add: 'Add manually',
        nextRun: 'next run', lastRun: 'last run', never: 'never', offenses: 'offenses', offensesCol: 'Offenses', newIn24h: 'new in 24 h',
        offenses24h: 'offenses in 24 h', expired24h: 'expired in 24 h', topCountries: 'Top countries',
        topAsns: 'Top ASNs', perm: 'permanent', release: 'Release', extend: 'Extend', extendNext: 'Next level',
        permanent: 'Make permanent', neverBlock: 'Never block (pa_never_block)', history: 'History of this address',
        liveView: 'Open in Live View', actions: 'Actions', selected: 'selected', batchMax: 'at most {n} at a time',
        address: 'Address', level: 'Level', remaining: 'Remaining', reason: 'Reason', state: 'State',
        firstSeen: 'First seen', lastOffense: 'Last offense', blockedFor: 'Blocked for', origin: 'Origin',
        country: 'Country', asn: 'ASN', hits: 'Hits', comment: 'Comment', auto: 'automatic', manual: 'manual',
        st_active: 'active', st_expired: 'expired', st_released: 'released', st_permanent: 'permanent',
        r_base: 'base', r_scan: 'scan', r_bait: 'bait', r_suricata: 'suricata', r_manual: 'manual',
        filters: 'Filters', apply: 'Apply', clear: 'Clear', year: 'Year', any: 'any', search: 'Address or comment',
        exportCsv: 'Export CSV', kindOffenses: 'Offenses', kindEvents: 'Entries and exits', kindYearly: 'Per year',
        prev: 'Previous', next: 'Next', loadMore: 'Load more', noEntries: 'No entries match the filters.',
        target: 'Address, network, range or ASN', targetHelp: '203.0.113.5, 203.0.113.0/24, 203.0.113.10-203.0.113.20 or AS64500',
        duration: 'Duration', dAuto: 'ladder (automatic)', simulate: 'Simulate', guards: 'Protected addresses',
        settings: 'Settings', change: 'Change', copy: 'Copy', time: 'Time', events: 'Events', ports: 'Ports',
        detail: 'Detail', iface: 'Interface', kind: 'Kind', prefixes: 'prefixes', perYear: 'Per year',
        firstLast: 'first / last', maxLevel: 'max level', error: 'Error', close: 'Close', until: 'until',
        installHelp: 'Installing creates the aliases pa_quarantine and pa_never_block, the rule "Max Cyber IA" and a cron job every 5 minutes. The simulation shows every step first.',
        purge: 'Also delete the history database (every offense of every year). This can not be undone.',
        set_reset_days: 'Days without offenses before the level goes back to zero',
        set_scan_ports: 'Port scan: distinct destination ports', set_scan_window: 'Port scan: window (seconds)',
        set_bait_ports: 'Bait ports (separated by +)', set_suricata: 'Use Suricata alerts (1/0)',
        set_suricata_severity: 'Suricata: highest severity number that counts (1 = only the most severe)',
        set_max_active: 'Maximum active pf entries', set_syn_only: 'TCP: count only connection attempts (1/0)',
        set_budget: 'Seconds per run'
    };
    let opts = {};
    let grid = null;
    let status = null;
    let skew = 0;                       // server clock - browser clock (seconds)
    let filters = {};
    let mobilePage = 1;
    const mobileSel = new Set();
    const histState = {kind: 'offenses', page: 1, rows: 25};
    let ticker = null;

    const esc = function (v) { return PASimulation.escape(v); };
    const t = function (key, ctx) {
        let text = S[key] !== undefined ? S[key] : key;
        Object.keys(ctx || {}).forEach(function (k) { text = text.replace('{' + k + '}', ctx[k]); });
        return text;
    };

    function b64(text) {
        return btoa(unescape(encodeURIComponent(text)));
    }

    function nowSec() {
        return Date.now() / 1000 + skew;
    }

    function fmtDur(sec) {
        if (sec === null || sec === undefined) {
            return '∞';
        }
        sec = Math.max(0, Math.round(sec));
        const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
        if (d) { return d + 'd ' + h + 'h'; }
        if (h) { return h + 'h ' + String(m).padStart(2, '0') + 'm'; }
        return m + 'm ' + String(sec % 60).padStart(2, '0') + 's';
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

    function levelBadge(level) {
        level = parseInt(level, 10) || 0;
        if (!level) {
            return '<span class="label label-default">-</span>';
        }
        return '<span class="label pa-q-level pa-q-l' + level + '" title="' + esc(LEVELS[level]) + '">' +
            (level === 6 ? '∞' : 'L' + level) + ' · ' + esc(level === 6 ? t('perm') : LEVELS[level]) + '</span>';
    }

    function reasonBadge(reason) {
        return reason ? '<span class="pa-q-reason pa-q-r-' + esc(reason) + '">' + esc(t('r_' + reason)) + '</span>' : '-';
    }

    function stateBadge(state) {
        const cls = {active: 'label-danger', permanent: 'label-danger', expired: 'label-default',
                     released: 'label-success'}[state] || 'label-default';
        return '<span class="label ' + cls + '">' + esc(t('st_' + state)) + '</span>';
    }

    function remainingHtml(row) {
        if (row.state === 'permanent') {
            return '<span class="pa-q-perm">∞</span>';
        }
        if (row.state !== 'active' || !row.until) {
            return '<span class="text-muted">-</span>';
        }
        return '<span class="pa-q-countdown" data-until="' + esc(row.until) + '">' + esc(fmtDur(row.until - nowSec())) +
            '</span>';
    }

    function blockedForHtml(row) {
        if (!row.since) {
            return '-';
        }
        const total = row.until ? row.until - row.since : null;
        return esc(fmtDur(total)) + ' <small class="text-muted">(' + esc(fmtTime(row.since)) + ')</small>';
    }

    function addressHtml(row) {
        let html = '<code class="pa-q-addr">' + esc(row.addr) + '</code>';
        if (row.kind === 'asn') {
            html += ' <small class="text-muted">' + esc(row.prefixes || 0) + ' ' + esc(t('prefixes')) + '</small>';
        }
        if (row.comment) {
            html += '<br/><small class="text-muted pa-q-comment">' + esc(row.comment) + '</small>';
        }
        return html;
    }

    function countryHtml(row) {
        return (row.country ? esc(row.country) : '') + (row.asn && row.kind !== 'asn' ?
            ' <small class="text-muted">AS' + esc(row.asn) + '</small>' : '') || '-';
    }

    function liveViewUrl(row) {
        if (row.kind === 'ip') {
            return '/ui/diagnostics/firewall/log#field=src&operator=' + encodeURIComponent('=') + '&value=' +
                encodeURIComponent(row.addr);
        }
        if (row.kind === 'net' && row.addr.indexOf(':') < 0) {
            const parts = row.addr.split('/');
            const octets = Math.max(1, Math.min(3, Math.floor(parseInt(parts[1], 10) / 8)));
            return '/ui/diagnostics/firewall/log#field=src&operator=' + encodeURIComponent('~') + '&value=' +
                encodeURIComponent(parts[0].split('.').slice(0, octets).join('.') + '.');
        }
        return null;
    }

    /* ------------------------------------------------------------------------------------- changes */

    function run(action, args, title, extra) {
        PASimulation.run(Object.assign({action: action, args: args || [], title: title, onDone: refresh}, extra || {}));
    }

    function selection() {
        if (window.matchMedia(MOBILE).matches || !grid) {
            return Array.from(mobileSel);
        }
        return $('#grid-quarantine').bootgrid('getSelectedRows') || [];
    }

    function idsToken(ids) {
        return ids.slice(0, BATCH_MAX).map(String).join('+');
    }

    function rowMenu(row) {
        const box = $('<div class="pa-q-menu"/>');
        const add = function (icon, label, handler, cls) {
            box.append($('<button type="button" class="btn btn-default btn-block"/>').addClass(cls || '')
                .html('<span class="fa fa-fw ' + icon + '"></span> ' + esc(label)).click(function () {
                    dlg.close();
                    handler();
                }));
        };
        const blocked = row.state === 'active' || row.state === 'permanent';
        let dlg = null;
        if (blocked) {
            add('fa-unlock', t('release'), function () { run('quarantine_release', [String(row.id)], t('release') + ' ' + row.addr); });
        }
        if (row.state !== 'permanent') {
            add('fa-level-up', t('extend') + ': ' + t('extendNext'), function () {
                run('quarantine_extend', [String(row.id), 'next'], t('extend') + ' ' + row.addr);
            });
            const sel = $('<div class="input-group pa-q-extend"/>');
            const select = $('<select class="form-control"/>');
            ['l1', 'l2', 'l3', 'l4', 'l5'].forEach(function (k) {
                select.append($('<option/>').val(k).text(LEVELS[k.slice(1)]));
            });
            sel.append(select).append($('<span class="input-group-btn"/>').append(
                $('<button type="button" class="btn btn-default"/>').text(t('extend')).click(function () {
                    dlg.close();
                    run('quarantine_extend', [String(row.id), select.val()], t('extend') + ' ' + row.addr);
                })));
            box.append(sel);
            add('fa-ban', t('permanent'), function () { run('quarantine_permanent', [String(row.id)], t('permanent') + ' ' + row.addr); },
                'btn-danger-outline');
        }
        if (row.kind !== 'asn') {
            add('fa-shield', t('neverBlock'), function () { run('never_block_add', [String(row.id)], t('neverBlock') + ' ' + row.addr); });
        }
        add('fa-history', t('history'), function () { showEntry(row.id); });
        const live = liveViewUrl(row);
        if (live) {
            box.append($('<a class="btn btn-default btn-block"/>').attr('href', live).attr('target', '_blank')
                .attr('rel', 'noopener').html('<span class="fa fa-fw fa-eye"></span> ' + esc(t('liveView'))));
        }
        if (navigator.clipboard) {
            add('fa-clipboard', t('copy') + ' ' + row.addr, function () { navigator.clipboard.writeText(row.addr); });
        }
        dlg = PASimulation.dialog({title: row.addr, message: box, size: BootstrapDialog.SIZE_SMALL,
                                   cssClass: 'pa-q-menu-dialog',
                                   buttons: [{label: t('close'), action: function (d) { d.close(); }}]});
    }

    function rowButtons(row) {
        const blocked = row.state === 'active' || row.state === 'permanent';
        return (blocked ? '<button type="button" class="btn btn-xs btn-default pa-q-release" data-id="' + esc(row.id) +
            '" title="' + esc(t('release')) + '"><span class="fa fa-fw fa-unlock"></span></button> ' : '') +
            '<button type="button" class="btn btn-xs btn-default pa-q-more" data-id="' + esc(row.id) + '" title="' +
            esc(t('actions')) + '"><span class="fa fa-fw fa-ellipsis-v"></span></button>';
    }

    let rowsById = {};

    /* row buttons: delegated, the grid re-renders its cells */
    function bindRows() {
        $('#pa_q_root').off('click.paq').on('click.paq', '.pa-q-release', function (e) {
            e.preventDefault();
            e.stopPropagation();
            const row = rowsById[$(this).data('id')];
            run('quarantine_release', [String($(this).data('id'))], t('release') + ' ' + (row ? row.addr : ''));
        }).on('click.paq', '.pa-q-more', function (e) {
            e.preventDefault();
            e.stopPropagation();
            const row = rowsById[$(this).data('id')];
            if (row) {
                rowMenu(row);
            }
        });
    }

    /* ------------------------------------------------------------------------------------- header */

    function renderHeader(data) {
        status = data || {};
        if (status.now) {
            skew = Date.parse(status.now) / 1000 - Date.now() / 1000;
        }
        const head = $('#pa_q_state').empty();
        const installed = !!status.installed;
        let badge;
        if (!installed) {
            badge = '<span class="label label-default pa-q-badge">' + esc(t('notInstalled')) + '</span>';
        } else if (status.paused || !(status.rule || {}).enabled) {
            badge = '<span class="label label-warning pa-q-badge">' + esc(t('paused')) + '</span>';
        } else {
            badge = '<span class="label label-success pa-q-badge">' + esc(t('active')) + '</span>';
        }
        const last = status.last_run || {};
        head.append('<div class="pa-q-state-line">' + badge + ' <b>Max Cyber IA</b> <small class="text-muted">' +
            esc((status.rule || {}).present ? ((status.rule.enabled ? t('ruleOn') : t('ruleOff'))) : '') + '</small></div>');
        if (installed) {
            head.append('<div class="text-muted pa-q-runs"><small>' + esc(t('nextRun')) + ': ' +
                esc(status.next_run ? fmtTime(Date.parse(status.next_run) / 1000) : '-') + ' · ' + esc(t('lastRun')) + ': ' +
                esc(last.ts ? fmtTime(Date.parse(last.ts) / 1000) + ' (' + (last.duration_ms || 0) + ' ms, ' +
                    (last.offenses || 0) + ' ' + t('offenses') + ')' : t('never')) + '</small></div>');
        } else {
            head.append('<p class="text-muted"><small>' + esc(t('installHelp')) + '</small></p>');
        }
        $('#pa_q_install').toggle(!installed || (status.warning_actions || []).some(function (w) {
            return w.action && w.action.id === 'install_quarantine';
        }));
        $('#pa_q_remove, #pa_q_add_toggle, #pa_q_settings, #pa_q_body, #pa_q_setup').toggle(installed);
        $('#pa_q_pause').toggle(installed && !status.paused && !!(status.rule || {}).enabled);
        $('#pa_q_resume').toggle(installed && (!!status.paused || ((status.rule || {}).present && !status.rule.enabled)));

        const warn = $('#pa_q_warnings').empty();
        (status.warning_actions || []).forEach(function (w) {
            if (w.action && w.action.id === 'install_quarantine' && !installed) {
                return;                                    // the Install button is right there
            }
            const item = $('<div class="alert alert-warning pa-q-warning"/>').text(w.warning + ' ');
            item.append(PASimulation.actionButton(w, 'btn-sm btn-default'));
            warn.append(item);
        });
        if (status.status === 'error') {
            warn.append($('<div class="alert alert-danger"/>').text(status.message || t('error')));
        }

        const counts = status.counts || {};
        const byLevel = counts.active_by_level || {};
        const cards = $('#pa_q_cards').empty();
        // each card: count in the level's severity colour, label, and a bar with the level's share of all active
        // entries (the colour ramp and the bar come from policyanalyzer.css, data-level and --pa-share)
        const activeTotal = [1, 2, 3, 4, 5, 6].reduce(function (sum, l) { return sum + (Number(byLevel[l]) || 0); }, 0);
        [1, 2, 3, 4, 5, 6].forEach(function (level) {
            const n = Number(byLevel[level]) || 0;
            const share = activeTotal ? Math.round(n * 1000 / activeTotal) / 10 : 0;
            cards.append($('<button type="button" class="pa-q-card"/>').attr('data-level', level)
                .attr('title', share + '%')
                .css('--pa-share', share + '%')
                .toggleClass('pa-q-card-on', String(filters.level || '') === String(level))
                .toggleClass('pa-q-card-empty', n === 0)
                .html('<span class="pa-q-count">' + esc(n) + '</span><span class="pa-q-card-label">' +
                    (level === 6 ? '∞ ' + esc(t('perm')) : 'L' + level + ' · ' + esc(LEVELS[level])) + '</span>' +
                    '<span class="pa-q-share" aria-hidden="true"><span></span></span>'));
        });
        cards.find('.pa-q-card').click(function () {
            const lvl = String($(this).data('level'));
            filters.level = filters.level === lvl ? '' : lvl;
            if (filters.level) {
                filters.state = 'blocked';
                $('#pa_q_f_state').val('blocked');
            }
            reloadList();
            renderHeader(status);
        });
        const facts = $('#pa_q_facts').empty();
        [['new', 'fa-plus-circle', counts.new_24h, 'newIn24h'], ['offenses', 'fa-bolt', counts.offenses_24h, 'offenses24h'],
            ['expired', 'fa-hourglass-end', counts.expired_24h, 'expired24h']].forEach(function (f) {
            facts.append('<span class="pa-q-fact pa-q-fact-' + f[0] + '"><i class="fa fa-fw ' + f[1] + '" aria-hidden="true"></i>' +
                '<b>' + esc(f[2] || 0) + '</b> <span>' + esc(t(f[3])) + '</span></span>');
        });
        const tops = $('#pa_q_tops').empty();
        const chipList = function (title, items, key, fmt) {
            if (!items || !items.length) {
                return;
            }
            const line = $('<div class="pa-q-top"/>').append($('<small class="text-muted pa-q-top-title"/>').text(title));
            const max = items.reduce(function (m, it) { return Math.max(m, Number(it.count) || 0); }, 0) || 1;
            items.forEach(function (it) {
                // chip with a bar behind it: its count against the largest one of the list
                line.append($('<button type="button" class="btn btn-xs btn-default pa-q-chip"/>')
                    .css('--pa-bar', Math.round((Number(it.count) || 0) * 100 / max) + '%')
                    .append($('<span class="pa-q-chip-key"/>').text(fmt(it)), $('<span class="pa-q-chip-n"/>').text(it.count))
                    .click(function () {
                        filters[key] = String(it[key]);
                        $('#pa_q_f_' + key).val(filters[key]);
                        reloadList();
                    }));
            });
            tops.append(line);
        };
        chipList(t('topCountries'), counts.top_countries, 'country', function (it) { return it.country; });
        chipList(t('topAsns'), counts.top_asns, 'asn', function (it) { return 'AS' + it.asn; });

        const years = (status.years || []).slice();
        const thisYear = new Date().getFullYear();
        if (years.indexOf(thisYear) < 0) {
            years.unshift(thisYear);
        }
        ['#pa_q_f_year', '#pa_q_h_year'].forEach(function (id) {
            const el = $(id);
            const cur = el.val();
            el.find('option:not([value=""])').remove();
            years.forEach(function (y) { el.append($('<option/>').val(String(y)).text(String(y))); });
            el.val(cur || (id === '#pa_q_h_year' ? String(thisYear) : ''));
        });
        renderSettings();
    }

    function loadStatus() {
        ajaxGet(API + 'status', {}, function (data) {
            renderHeader(data || {status: 'error'});
        });
    }

    /* ------------------------------------------------------------------------------------- list */

    function readFilters() {
        ['year', 'state', 'reason', 'origin', 'country', 'asn'].forEach(function (k) {
            filters[k] = ($('#pa_q_f_' + k).val() || '').trim();
        });
        filters.country = (filters.country || '').toUpperCase();
        filters.searchPhrase = ($('#pa_q_f_search').val() || '').trim();
    }

    function requestFilters(request) {
        ['year', 'state', 'reason', 'origin', 'country', 'asn', 'level'].forEach(function (k) {
            if (filters[k]) {
                request[k] = filters[k];
            }
        });
        if (window.matchMedia(MOBILE).matches && filters.searchPhrase) {
            request.searchPhrase = filters.searchPhrase;
        }
        return request;
    }

    function updateBatch() {
        const ids = selection();
        /* always shown (no layout jump when the first row is ticked), the buttons only work with 1..30 rows */
        const bar = $('#pa_q_batch');
        bar.toggleClass('pa-q-batch-on', ids.length > 0);
        bar.find('.pa-q-batch-count').text(ids.length + ' ' + t('selected') +
            (ids.length > BATCH_MAX ? ' (' + t('batchMax', {n: BATCH_MAX}) + ')' : ''));
        bar.find('button, select').prop('disabled', ids.length === 0 || ids.length > BATCH_MAX);
    }

    function initGrid() {
        grid = $('#grid-quarantine').UIBootgrid({
            search: API + 'search',
            datakey: 'id',
            options: {
                rowCount: [20, 50, 100, 500],
                selection: true,
                multiSelect: true,
                responsive: true,
                formatters: {
                    addr: function (c, row) { rowsById[row.id] = row; return addressHtml(row); },
                    level: function (c, row) { return levelBadge(row.level); },
                    remaining: function (c, row) { return remainingHtml(row); },
                    reason: function (c, row) { return reasonBadge(row.reason); },
                    state: function (c, row) { return stateBadge(row.state); },
                    when: function (c, row) { return esc(fmtTime(row[c.id])); },
                    blocked: function (c, row) { return blockedForHtml(row); },
                    origin: function (c, row) { return esc(t(row.origin)); },
                    country: function (c, row) { return countryHtml(row); },
                    asn: function (c, row) { return row.asn ? 'AS' + esc(row.asn) : '-'; },
                    commands: function (c, row) { rowsById[row.id] = row; return rowButtons(row); }
                },
                requestHandler: requestFilters
            }
        });
        grid.on('loaded.rs.jquery.bootgrid', function () {
            updateBatch();
            tick();
        });
        grid.on('selected.rs.jquery.bootgrid deselected.rs.jquery.bootgrid', updateBatch);
    }

    function mobileCard(row) {
        rowsById[row.id] = row;
        const card = $('<div class="pa-q-cardrow"/>').toggleClass('pa-q-sel', mobileSel.has(row.id));
        const head = $('<div class="pa-q-cr-head"/>');
        const check = $('<input type="checkbox" class="pa-q-check"/>').prop('checked', mobileSel.has(row.id))
            .attr('aria-label', row.addr).on('change', function () {
                $(this).prop('checked') ? mobileSel.add(row.id) : mobileSel.delete(row.id);
                card.toggleClass('pa-q-sel', $(this).prop('checked'));
                updateBatch();
            });
        head.append($('<label class="pa-q-check-wrap"/>').append(check));
        head.append($('<div class="pa-q-cr-addr"/>').html(addressHtml(row)));
        head.append($('<div class="pa-q-cr-actions"/>').html(rowButtons(row)));
        card.append(head);
        const dl = $('<dl class="pa-q-kv"/>');
        const kv = function (label, html) { dl.append($('<dt/>').text(label)).append($('<dd/>').html(html)); };
        kv(t('level'), levelBadge(row.level));
        kv(t('remaining'), remainingHtml(row));
        kv(t('reason'), reasonBadge(row.reason) + ' <small class="text-muted">' + esc(t(row.origin)) + '</small>');
        kv(t('state'), stateBadge(row.state));
        kv(t('offensesCol'), esc(row.offenses));
        kv(t('lastOffense'), esc(fmtTime(row.last_offense)));
        kv(t('firstSeen'), esc(fmtTime(row.first_seen)));
        kv(t('country'), countryHtml(row));
        card.append(dl);
        return card;
    }

    function renderMobile(append) {
        if (!window.matchMedia(MOBILE).matches) {
            return;
        }
        const request = requestFilters({current: mobilePage, rowCount: 20});
        ajaxCall(API + 'search', request, function (data) {
            const box = $('#pa_q_mobile');
            if (!append) {
                box.empty();
            }
            box.find('.pa-q-more-rows').remove();
            const rows = (data && data.rows) || [];
            if (!rows.length && !append) {
                box.append($('<div class="pa-empty text-muted"/>').text(t('noEntries')));
            }
            rows.forEach(function (row) { box.append(mobileCard(row)); });
            if ((data.total || 0) > mobilePage * 20) {
                box.append($('<button type="button" class="btn btn-default btn-block pa-q-more-rows"/>').text(t('loadMore'))
                    .click(function () { mobilePage += 1; renderMobile(true); }));
            }
            tick();
        });
    }

    function reloadList() {
        mobilePage = 1;
        /* the grid is hidden on phones (and while another tab is shown): reload it only when it is visible */
        if (grid && !window.matchMedia(MOBILE).matches && $('#grid-quarantine').closest('.tab-pane').hasClass('active')) {
            $('#grid-quarantine').bootgrid('reload');
        }
        renderMobile(false);
    }

    function tick() {
        const now = nowSec();
        $('.pa-q-countdown').each(function () {
            const until = parseFloat($(this).data('until'));
            const left = until - now;
            $(this).text(left > 0 ? fmtDur(left) : '0m 00s').toggleClass('pa-q-soon', left > 0 && left < 300);
        });
    }

    /* ------------------------------------------------------------------------------------- dialogs */

    function offenseTable(rows) {
        if (!rows.length) {
            return '<p class="text-muted">-</p>';
        }
        return '<table class="table table-condensed table-striped pa-q-kvtable"><thead><tr><th>' + esc(t('time')) +
            '</th><th>' + esc(t('reason')) + '</th><th>' + esc(t('level')) + '</th><th>' + esc(t('events')) + '</th><th>' +
            esc(t('ports')) + '</th><th>' + esc(t('detail')) + '</th><th>' + esc(t('iface')) + '</th></tr></thead><tbody>' +
            rows.map(function (o) {
                return '<tr><td data-label="' + esc(t('time')) + '">' + esc(fmtTime(o.ts)) + '</td><td data-label="' +
                    esc(t('reason')) + '">' + reasonBadge(o.reason) + (o.limited ? ' <span class="label label-warning">limit</span>' : '') +
                    '</td><td data-label="' + esc(t('level')) + '">' + levelBadge(o.level) + '</td><td data-label="' +
                    esc(t('events')) + '">' + esc(o.events || '-') + '</td><td data-label="' + esc(t('ports')) + '"><code>' +
                    esc(o.ports || '-') + '</code></td><td data-label="' + esc(t('detail')) + '">' + esc(o.detail || '') +
                    '</td><td data-label="' + esc(t('iface')) + '">' + esc(o.iface || '-') + '</td></tr>';
            }).join('') + '</tbody></table>';
    }

    function eventTable(rows) {
        if (!rows.length) {
            return '<p class="text-muted">-</p>';
        }
        return '<table class="table table-condensed pa-q-kvtable"><thead><tr><th>' + esc(t('time')) + '</th><th>' +
            esc(t('kind')) + '</th><th>' + esc(t('level')) + '</th><th>' + esc(t('until')) + '</th><th>' +
            esc(t('comment')) + '</th></tr></thead><tbody>' + rows.map(function (e) {
                return '<tr><td data-label="' + esc(t('time')) + '">' + esc(fmtTime(e.ts)) + '</td><td data-label="' +
                    esc(t('kind')) + '">' + esc(e.kind) + '</td><td data-label="' + esc(t('level')) + '">' +
                    (e.level ? levelBadge(e.level) : '-') + '</td><td data-label="' + esc(t('until')) + '">' +
                    esc(e.until ? fmtTime(e.until) : '-') + '</td><td data-label="' + esc(t('comment')) + '">' +
                    esc(e.note || '') + (e.addr ? ' <code>' + esc(e.addr) + '</code>' : '') + '</td></tr>';
            }).join('') + '</tbody></table>';
    }

    function showEntry(id) {
        ajaxGet(API + 'entry', {id: id}, function (data) {
            if (!data || data.status !== 'ok') {
                PASimulation.dialog({type: BootstrapDialog.TYPE_DANGER, title: t('error'), message: esc((data && data.message) || t('error'))});
                return;
            }
            const e = data.entry;
            let html = '<dl class="pa-q-kv pa-q-kv-wide">';
            [[t('address'), addressHtml(e)], [t('state'), stateBadge(e.state)], [t('level'), levelBadge(e.level)],
             [t('remaining'), remainingHtml(e)], [t('firstSeen'), esc(fmtTime(e.first_seen))],
             [t('lastOffense'), esc(fmtTime(e.last_offense))], [t('offensesCol'), esc(e.offenses)], [t('hits'), esc(e.hits)],
             [t('country'), countryHtml(e)], [t('origin'), esc(t(e.origin))]].forEach(function (kv) {
                html += '<dt>' + esc(kv[0]) + '</dt><dd>' + kv[1] + '</dd>';
            });
            html += '</dl>';
            if ((data.prefixes || []).length) {
                html += '<p><b>' + esc(t('prefixes')) + ':</b> <code>' + esc(data.prefixes.join(' ')) + '</code></p>';
            }
            if ((data.yearly || []).length) {
                html += '<h4>' + esc(t('perYear')) + '</h4><table class="table table-condensed pa-q-kvtable"><thead><tr><th>' +
                    esc(t('year')) + '</th><th>' + esc(t('offensesCol')) + '</th><th>' + esc(t('firstLast')) + '</th><th>' +
                    esc(t('maxLevel')) + '</th><th>' + esc(t('reason')) + '</th></tr></thead><tbody>' +
                    data.yearly.map(function (y) {
                        return '<tr><td data-label="' + esc(t('year')) + '">' + esc(y.year) + '</td><td data-label="' +
                            esc(t('offensesCol')) + '">' + esc(y.offenses) + '</td><td data-label="' + esc(t('firstLast')) + '">' +
                            esc(fmtTime(y.first_seen)) + ' / ' + esc(fmtTime(y.last_seen)) + '</td><td data-label="' +
                            esc(t('maxLevel')) + '">' + levelBadge(y.max_level) + '</td><td data-label="' + esc(t('reason')) +
                            '">' + (y.reasons || []).map(reasonBadge).join(' ') + '</td></tr>';
                    }).join('') + '</tbody></table>';
            }
            html += '<h4>' + esc(t('kindOffenses')) + ' (' + data.offenses.length + ')</h4>' + offenseTable(data.offenses);
            html += '<h4>' + esc(t('kindEvents')) + ' (' + data.events.length + ')</h4>' + eventTable(data.events);
            const buttons = [];
            const live = liveViewUrl(e);
            if (live) {
                buttons.push({label: t('liveView'), action: function () { window.open(live, '_blank', 'noopener'); }});
            }
            buttons.push({label: t('actions'), cssClass: 'btn-primary', action: function (d) { d.close(); rowMenu(e); }});
            buttons.push({label: t('close'), action: function (d) { d.close(); }});
            PASimulation.dialog({title: t('history') + ': ' + e.addr, message: html, size: BootstrapDialog.SIZE_WIDE,
                                 buttons: buttons, onshown: tick});
        });
    }

    function showGuards() {
        ajaxGet(API + 'guards', {}, function (data) {
            let html = '';
            if (!data || data.status !== 'ok') {
                html = '<div class="alert alert-danger">' + esc((data && data.message) || t('error')) + '</div>';
            } else {
                html += '<p class="text-muted">' + esc((data.implicit || []).join(', ')) + '</p>';
                Object.keys(data.labels || {}).forEach(function (label) {
                    const items = data.labels[label] || [];
                    if (!items.length) {
                        return;
                    }
                    html += '<details class="pa-sim-info"' + (items.length <= 12 ? ' open' : '') + '><summary><b>' +
                        esc(label) + '</b> (' + items.length + ')</summary><p class="pa-q-guard-list">' +
                        items.map(function (i) {
                            return '<code title="' + esc(i.note || '') + '">' + esc(i.addr) + '</code>';
                        }).join(' ') + '</p></details>';
                });
                (data.notes || []).forEach(function (n) { html += '<div class="alert alert-warning">' + esc(n) + '</div>'; });
            }
            PASimulation.dialog({title: t('guards'), message: html, size: BootstrapDialog.SIZE_WIDE,
                                 buttons: [{label: t('close'), action: function (d) { d.close(); }}]});
        });
    }

    function renderSettings() {
        const box = $('#pa_q_settings_body').empty();
        const settings = (status && status.settings) || {};
        Object.keys(settings).forEach(function (key) {
            if (S['set_' + key] === undefined) {
                return;
            }
            const id = 'pa_q_set_' + key;
            const row = $('<div class="pa-q-setting"/>');
            row.append($('<label/>').attr('for', id).text(t('set_' + key)));
            const input = $('<input type="text" class="form-control"/>').attr('id', id).val(String(settings[key]));
            row.append($('<div class="input-group"/>').append(input).append($('<span class="input-group-btn"/>').append(
                $('<button type="button" class="btn btn-default"/>').text(t('change')).click(function () {
                    const value = input.val().trim().replace(/[ ,]+/g, '+');
                    run('quarantine_settings', [key, value], t('settings') + ': ' + key);
                }))));
            box.append(row);
        });
    }

    /* ------------------------------------------------------------------------------------- history */

    function loadHistory() {
        const params = {kind: histState.kind, page: histState.page, rows: histState.rows,
                        year: $('#pa_q_h_year').val() || '', ip: ($('#pa_q_h_ip').val() || '').trim()};
        ajaxGet(API + 'history', params, function (data) {
            const box = $('#pa_q_history').empty();
            if (!data || data.status !== 'ok') {
                box.append($('<div class="alert alert-danger"/>').text((data && data.message) || t('error')));
                return;
            }
            const rows = data.rows || [];
            if (histState.kind === 'yearly') {
                box.html(rows.length ? '<table class="table table-condensed table-striped pa-q-kvtable"><thead><tr><th>' +
                    esc(t('address')) + '</th><th>' + esc(t('offensesCol')) + '</th><th>' + esc(t('firstLast')) + '</th><th>' +
                    esc(t('maxLevel')) + '</th><th>' + esc(t('reason')) + '</th><th>' + esc(t('country')) +
                    '</th></tr></thead><tbody>' + rows.map(function (y) {
                        return '<tr><td data-label="' + esc(t('address')) + '"><a href="#" class="pa-q-open" data-id="' +
                            esc(y.entry_id) + '"><code>' + esc(y.addr) + '</code></a></td><td data-label="' + esc(t('offensesCol')) +
                            '">' + esc(y.offenses) + '</td><td data-label="' + esc(t('firstLast')) + '">' + esc(fmtTime(y.first_seen)) +
                            ' / ' + esc(fmtTime(y.last_seen)) + '</td><td data-label="' + esc(t('maxLevel')) + '">' +
                            levelBadge(y.max_level) + '</td><td data-label="' + esc(t('reason')) + '">' +
                            (y.reasons || []).map(reasonBadge).join(' ') + '</td><td data-label="' + esc(t('country')) + '">' +
                            esc(y.country || '-') + '</td></tr>';
                    }).join('') + '</tbody></table>' : '<p class="text-muted">-</p>');
            } else if (histState.kind === 'events') {
                box.html(eventTable(rows));
            } else {
                box.html(rows.length ? offenseTable(rows).replace('<th>' + esc(t('time')) + '</th>',
                    '<th>' + esc(t('time')) + '</th><th>' + esc(t('address')) + '</th>') : '<p class="text-muted">-</p>');
                box.find('tbody tr').each(function (i) {
                    $(this).children().first().after($('<td/>').attr('data-label', t('address')).html(
                        '<a href="#" class="pa-q-open" data-id="' + esc(rows[i].entry_id) + '"><code>' + esc(rows[i].addr) + '</code></a>'));
                });
            }
            box.find('.pa-q-open').click(function (e) { e.preventDefault(); showEntry($(this).data('id')); });
            const pages = Math.max(1, Math.ceil((data.total || 0) / histState.rows));
            const nav = $('<div class="pa-q-pager"/>');
            nav.append($('<button type="button" class="btn btn-default"/>').text(t('prev')).prop('disabled', histState.page <= 1)
                .click(function () { histState.page -= 1; loadHistory(); }));
            nav.append($('<span class="text-muted"/>').text(' ' + histState.page + ' / ' + pages + ' (' + (data.total || 0) + ') '));
            nav.append($('<button type="button" class="btn btn-default"/>').text(t('next')).prop('disabled', histState.page >= pages)
                .click(function () { histState.page += 1; loadHistory(); }));
            box.append(nav);
        });
    }

    /* ------------------------------------------------------------------------------------- init */

    function refresh() {
        loadStatus();
        reloadList();
        if ($('#pa_q_history_box').is('[open]')) {
            loadHistory();
        }
        if (opts.onChange) {
            opts.onChange();
        }
    }

    /* the installation is done and undone step by step in the assistant (the composite action stays for the CLI) */
    function openSetup(step) {
        if (window.PAQSetup) {
            PAQSetup.open({step: step, onClose: refresh});
        } else {
            run('install_quarantine', [], t('install'));
        }
    }

    function bind() {
        $('#pa_q_install').click(function () { openSetup(); });
        $('#pa_q_setup').click(function () { openSetup(); });
        $('#pa_q_remove').click(function () {
            if (window.PAQSetup) {
                PAQSetup.removeAll();
                return;
            }
            run('remove_quarantine', [], t('remove'), {choice: {label: t('purge'), flags: ['purge_db=yes'], checked: false}});
        });
        $('#pa_q_pause').click(function () { run('quarantine_pause', [], t('pause')); });
        $('#pa_q_resume').click(function () { run('quarantine_resume', [], t('resume')); });
        $('#pa_q_guards').click(showGuards);
        $('#pa_q_settings').click(function () { $('#pa_q_settings_box').toggle(); });
        $('#pa_q_add_toggle').click(function () { $('#pa_q_add_box').toggle(); $('#pa_q_target').focus(); });
        $('#pa_q_filters_toggle').click(function () { $('#pa_q_filters').toggleClass('pa-q-open'); });
        const durSel = $('#pa_q_duration').empty();
        DURATIONS.forEach(function (d) {
            durSel.append($('<option/>').val(d).text(d === 'auto' ? t('dAuto') : (d === 'permanent' ? t('perm') : LEVELS[d.slice(1)])));
        });
        $('#pa_q_add_form').on('submit', function (e) {
            e.preventDefault();
            const target = ($('#pa_q_target').val() || '').trim();
            const comment = ($('#pa_q_comment').val() || '').trim();
            if (!target) {
                $('#pa_q_target').focus();
                return;
            }
            let token = '-';
            if (comment) {
                let cut = comment;
                while (new TextEncoder().encode(cut).length > 180) {
                    cut = cut.slice(0, -1);
                }
                token = b64(cut);
            }
            run('quarantine_add', [target, $('#pa_q_duration').val(), token], t('add') + ': ' + target);
        });
        $('#pa_q_f_apply').click(function () { readFilters(); filters.level = ''; reloadList(); if (status) { renderHeader(status); } });
        $('#pa_q_f_clear').click(function () {
            $('#pa_q_filters').find('select, input').val('');
            filters = {};
            reloadList();
            if (status) {
                renderHeader(status);
            }
        });
        $('#pa_q_export').click(function () {
            const year = $('#pa_q_f_year').val() || $('#pa_q_h_year').val() || String(new Date().getFullYear());
            const ip = ($('#pa_q_h_ip').val() || '').trim();
            window.location.href = API + 'export?year=' + encodeURIComponent(year) + (ip ? '&ip=' + encodeURIComponent(ip) : '');
        });
        $('#pa_q_h_kind').change(function () { histState.kind = $(this).val(); histState.page = 1; loadHistory(); });
        $('#pa_q_h_year, #pa_q_h_ip').change(function () { histState.page = 1; loadHistory(); });
        $('#pa_q_history_box').on('toggle', function () { if (this.open) { loadHistory(); } });
        $('#pa_q_batch_release').click(function () {
            run('quarantine_release', [idsToken(selection())], t('release') + ' (' + selection().length + ')');
        });
        $('#pa_q_batch_extend').click(function () {
            run('quarantine_extend', [idsToken(selection()), $('#pa_q_batch_level').val()], t('extend') + ' (' + selection().length + ')');
        });
        $('#pa_q_batch_permanent').click(function () {
            run('quarantine_permanent', [idsToken(selection())], t('permanent') + ' (' + selection().length + ')');
        });
        const batchSel = $('#pa_q_batch_level').empty().append($('<option/>').val('next').text(t('extendNext')));
        ['l1', 'l2', 'l3', 'l4', 'l5'].forEach(function (k) { batchSel.append($('<option/>').val(k).text(LEVELS[k.slice(1)])); });
        /* buttons of the warnings (outside a PASimulation dialog) */
        $('#pa_q_root').on('click', '.pa-sim-action', function () {
            let args = [];
            try {
                args = JSON.parse($(this).attr('data-args') || '[]');
            } catch (err) {
                args = [];
            }
            if ($(this).data('action') === 'install_quarantine') {
                openSetup();                               // repair = the assistant at the first step not done
                return;
            }
            run($(this).data('action'), Array.isArray(args) ? args.map(String) : [], String($(this).data('label')));
        });
        window.matchMedia(MOBILE).addEventListener('change', function () { reloadList(); updateBatch(); });
    }

    /* the theme's opaque background behind the tab, for the fixed batch bar on phones */
    function themeBackground() {
        let el = document.getElementById('pa_q_root');
        while (el) {
            const bg = getComputedStyle(el).backgroundColor;
            if (bg && bg !== 'transparent' && !/rgba\(.*,\s*0\)$/.test(bg)) {
                document.getElementById('pa_q_root').style.setProperty('--pa-q-bg', bg);
                return;
            }
            el = el.parentElement;
        }
    }

    function init(options) {
        opts = options || {};
        themeBackground();
        S = Object.assign({}, S, opts.strings || {});
        bind();
        bindRows();
        initGrid();
        loadStatus();
        renderMobile(false);
        if (ticker === null) {
            ticker = setInterval(tick, 1000);
            setInterval(function () {
                if ($('#quarantine').hasClass('active') && !document.hidden) {
                    loadStatus();
                }
            }, 60000);
        }
    }

    return {init: init, refresh: refresh, fmtDur: fmtDur, showGuards: showGuards};
})();
