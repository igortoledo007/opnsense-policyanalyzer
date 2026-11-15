{#
 # Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/policyanalyzer.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/simulation.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/aiqueue.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/airouting.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/recommend.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/quarantine.js') }}"></script>
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/setup.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/setup.js') }}"></script>
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/quarantine-setup.css') }}">
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/console.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/markdown.js') }}"></script>
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/insights.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/insights-common.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/quarantine-setup.js') }}"></script>
{# AI setup assistant (modal): its strings, registered before the page script below #}
{{ partial("OPNsense/PolicyAnalyzer/setup") }}
{# quarantine setup assistant (modal over the Quarantine tab): its strings #}
{{ partial("OPNsense/PolicyAnalyzer/quarantine_setup") }}
{{ partial("OPNsense/PolicyAnalyzer/minrule") }}
<script>
    'use strict';

    $(document).ready(function () {
        const esc = PASimulation.escape;
        const T = {
            high: "{{ lang._('High') }}",
            medium: "{{ lang._('Medium') }}",
            low: "{{ lang._('Low') }}",
            info: "{{ lang._('Info') }}",
            details: "{{ lang._('Details') }}",
            explain: "{{ lang._('Explain with AI') }}",
            explainAll: "{{ lang._('Explain all findings with AI') }}",
            preview: "{{ lang._('Show what would be sent') }}",
            close: "{{ lang._('Close') }}",
            analyzing: "{{ lang._('Analyzing the rule set...') }}",
            asking: "{{ lang._('Asking the AI, this can take a while...') }}",
            noReport: "{{ lang._('No analysis yet. Click Analyze to review the rule set.') }}",
            lastRun: "{{ lang._('Last analysis') }}",
            rules: "{{ lang._('rules') }}",
            rulesTitle: "{{ lang._('Rules') }}",
            enabled: "{{ lang._('enabled') }}",
            countersSince: "{{ lang._('rule counters since') }}",
            noCounters: "{{ lang._('rule counters not available, usage based findings are skipped') }}",
            affected: "{{ lang._('affected') }}",
            coveredBy: "{{ lang._('covered by') }}",
            legacy: "{{ lang._('legacy') }}",
            legacyHint: "{{ lang._('Legacy rule: open Firewall: Rules: Migration to convert it before editing') }}",
            editRule: "{{ lang._('Open the rule in Firewall: Rules (new tab)') }}",
            detail: "{{ lang._('Detail') }}",
            recommendation: "{{ lang._('Recommendation') }}",
            aliases: "{{ lang._('Aliases') }}",
            evidence: "{{ lang._('Evidence') }}",
            aiDisclaimer: "{{ lang._('AI generated text based only on the data above. It can be wrong: verify it against the evidence. Nothing was changed on this firewall.') }}",
            anonymized: "{{ lang._('anonymized') }}",
            notAnonymized: "{{ lang._('NOT anonymized') }}",
            truncated: "{{ lang._('The answer was cut off at the maximum length.') }}",
            refusal: "{{ lang._('The model declined to answer') }}",
            error: "{{ lang._('Error') }}",
            revert: "{{ lang._('Revert') }}",
            reverted: "{{ lang._('reverted') }}",
            none: "{{ lang._('None (AI disabled)') }}",
            noneHelp: "{{ lang._('No AI provider: nothing ever leaves this firewall.') }}",
            local: "{{ lang._('Local') }}",
            api: "{{ lang._('API') }}",
            wizardHint: "{{ lang._('The model server on this firewall is prepared by the AI setup (storage, runtime, model).') }}",
            configured: "{{ lang._('configured') }}",
            notConfigured: "{{ lang._('not configured') }}",
            clearSecret: "{{ lang._('Clear') }}",
            listModels: "{{ lang._('List models') }}",
            testConnection: "{{ lang._('Test connection') }}",
            saveFirst: "{{ lang._('Save the settings first, this uses the saved values.') }}",
            prepareStorage: "{{ lang._('Prepare storage') }}",
            free: "{{ lang._('free on') }}",
            missing: "{{ lang._('does not exist yet') }}",
            notWritable: "{{ lang._('not writable') }}",
            notLocal: "{{ lang._('not a local filesystem') }}",
            saveSettings: "{{ lang._('Save settings') }}",
            settingsChange: "{{ lang._('Settings change') }}",
            reachable: "{{ lang._('Connection OK') }}",
            modelMissing: "{{ lang._('the selected model is not available on the server') }}",
            noChanges: "{{ lang._('No changes to save.') }}",
            date: "{{ lang._('Date') }}",
            action: "{{ lang._('Action') }}",
            result: "{{ lang._('Result') }}",
            changes: "{{ lang._('Changes') }}",
            noFindings: "{{ lang._('No findings match the selected filters.') }}",
            openSetup: "{{ lang._('Open AI setup') }}",
            ramInUse: "{{ lang._('this firewall uses {used} of RAM right now') }}",
            total: "{{ lang._('total') }}",
            notPrivate: "{{ lang._('This does not look like a private or LAN address: the data would leave your network.') }}",
            runtimeUnknown: "{{ lang._('Runtime state not available.') }}",
            runtimeMissing: "{{ lang._('Not installed yet: use the AI setup to install it.') }}",
            runtimeRunning: "{{ lang._('Installed and running') }}",
            runtimeStopped: "{{ lang._('Installed, not running') }}",
            modelsInstalled: "{{ lang._('models') }}",
            limits: "{{ lang._('limits') }}",
            running: "{{ lang._('running') }}",
            cancelJob: "{{ lang._('Cancel') }}"
        };
        PASimulation.setStrings({
            simulate: "{{ lang._('Simulation') }}",
            nothing: "{{ lang._('Nothing to do: the system is already in the requested state.') }}",
            steps: "{{ lang._('Steps') }}",
            command: "{{ lang._('Command') }}",
            effect: "{{ lang._('Effect') }}",
            warnings: "{{ lang._('Warnings') }}",
            irreversible: "{{ lang._('Can not be reverted later') }}",
            revert: "{{ lang._('How to revert') }}",
            risk: "{{ lang._('Risk') }}",
            space: "{{ lang._('Disk space') }}",
            confirm: "{{ lang._('I reviewed the steps above and want to apply them.') }}",
            confirm2: "{{ lang._('I understand that part of this can not be undone or that other changes depend on it.') }}",
            apply: "{{ lang._('Apply') }}",
            close: "{{ lang._('Close') }}",
            cancel: "{{ lang._('Cancel') }}",
            done: "{{ lang._('Done') }}",
            failed: "{{ lang._('Failed') }}",
            completed: "{{ lang._('Completed steps') }}",
            journal: "{{ lang._('Recorded in the action history, it can be reverted from there.') }}",
            error: "{{ lang._('Error') }}",
            running: "{{ lang._('Running in the background') }}",
            cancel_job: "{{ lang._('Cancel') }}",
            cancel_confirm: "{{ lang._('Cancel the running job? It rolls back what it changed so far.') }}",
            technical: "{{ lang._('Technical details') }}",
            finished: "{{ lang._('Finished') }}",
            step: "{{ lang._('Step') }}"
        });

        PARecommend.setStrings({
            title: "{{ lang._('Recommended for this hardware') }}",
            none: "{{ lang._('No model fits this hardware as a local runtime: use a model server in your network.') }}",
            perFinding: "{{ lang._('s per finding') }}",
            ram: "{{ lang._('RAM') }}",
            disk: "{{ lang._('download') }}",
            backend: "{{ lang._('backend') }}",
            use: "{{ lang._('Use this model') }}",
            alternatives: "{{ lang._('Alternatives') }}",
            showAll: "{{ lang._('Show all {n} alternatives') }}",
            settings: "{{ lang._('Suggested settings') }}",
            notes: "{{ lang._('Notes') }}",
            estimates: "{{ lang._('Estimates are rough; run the benchmark in the AI setup for real numbers.') }}",
            unavailable: "{{ lang._('Recommendations are not available (the AI setup component is not installed).') }}",
            recommended: "{{ lang._('recommended') }}",
            possible: "{{ lang._('possible') }}",
            not_recommended: "{{ lang._('not recommended') }}"
        });

        const SEVERITY_CLASS = {high: 'danger', medium: 'warning', low: 'info', info: 'default'};
        const PAIR_TYPES = ['shadowed', 'redundant', 'duplicate'];
        let aiStatus = {enabled: false};

        /******************************************************************************************************
         * findings
         ******************************************************************************************************/
        function severityBadge(sev) {
            return '<span class="label label-' + (SEVERITY_CLASS[sev] || 'default') + '">' + esc(T[sev] || sev) +
                '</span>';
        }

        function ruleHref(rule) {
            /* ref comes from the analyzer (e.g. ui/firewall/filter#search=<uuid>); always opened as a new page load */
            if (typeof rule.ref === 'string' && /^ui\/[A-Za-z0-9_\/#=.:-]+$/.test(rule.ref)) {
                return '/' + rule.ref;
            }
            return rule.uuid ? '/ui/firewall/filter#search=' + encodeURIComponent(rule.uuid) : null;
        }

        function ruleLabel(rule) {
            let txt = (rule.interface || rule.priority_group || '?') + ' #' + (rule.sequence !== undefined ? rule.sequence : '?');
            txt += ' ' + (rule.action || '');
            if (rule.description) {
                txt += ' — ' + rule.description;
            }
            return txt;
        }

        function renderRules(rules, type) {
            return (rules || []).map(function (rule, idx) {
                let role = '';
                if (rules.length === 2 && PAIR_TYPES.includes(type)) {
                    role = '<small class="text-muted">' + esc(idx === 0 ? T.affected : T.coveredBy) + ':</small> ';
                }
                const href = ruleHref(rule);
                let html = role + (href ?
                    '<a class="pa-rule-link" href="' + esc(href) + '" target="_blank" rel="noopener noreferrer" title="' + esc(T.editRule) +
                    '">' + esc(ruleLabel(rule)) + '</a>' : esc(ruleLabel(rule)));
                if (rule.source === 'legacy') {
                    html += ' <a href="/ui/firewall/migration" target="_blank" rel="noopener noreferrer" title="' +
                        esc(T.legacyHint) + '"><span class="label label-default">' + esc(T.legacy) + '</span></a>';
                }
                if (rule.enabled === false) {
                    html += ' <span class="label label-default">off</span>';
                }
                return html;
            }).join('<br/>');
        }

        const grid = $("#grid-findings").UIBootgrid({
            search: '/api/policyanalyzer/analysis/search',
            datakey: 'id',
            options: {
                rowCount: [20, 50, 100, -1],
                selection: false,
                multiSelect: false,
                responsive: true,           // wrap cell text (titles, rules) instead of cutting it off
                formatters: {
                    severity: function (column, row) {
                        return severityBadge(row.severity);
                    },
                    rules: function (column, row) {
                        return renderRules(row.rules, row.type);
                    },
                    commands: function (column, row) {
                        let html = '<button type="button" class="btn btn-xs btn-default pa-details bootgrid-tooltip" ' +
                            'title="' + esc(T.details) + '" data-row-id="' + esc(row.id) + '">' +
                            '<span class="fa fa-search-plus fa-fw"></span></button> ';
                        html += '<button type="button" class="btn btn-xs btn-default pa-explain bootgrid-tooltip" ' +
                            'title="' + esc(T.explain) + '" data-row-id="' + esc(row.id) + '"' +
                            (aiStatus.enabled ? '' : ' style="display:none"') + '>' +
                            '<span class="fa fa-magic fa-fw"></span></button>';
                        return html;
                    }
                },
                requestHandler: function (request) {
                    const sev = $('#filter_severity').val() || [];
                    const types = $('#filter_type').val() || [];
                    if (sev.length) {
                        request['severity'] = sev;
                    }
                    if (types.length) {
                        request['type'] = types;
                    }
                    return request;
                }
            }
        });
        function bindRowButtons() {
            $('.pa-details').off('click').on('click', function () {
                showDetails($(this).data('row-id'));
            });
            $('.pa-explain').off('click').on('click', function () {
                explain($(this).data('row-id'));
            });
        }

        /* below 768 px the grid is hidden (CSS) and the same search is shown as a list of cards:
         * UIBootgrid's "responsive" option of 26.7 only wraps cell text, it has no card/collapse mode */
        function renderMobileList() {
            const request = {current: 1, rowCount: -1};
            const sev = $('#filter_severity').val() || [];
            const types = $('#filter_type').val() || [];
            if (sev.length) {
                request['severity'] = sev;
            }
            if (types.length) {
                request['type'] = types;
            }
            ajaxCall('/api/policyanalyzer/analysis/search', request, function (data) {
                const box = $('#pa_mobile_list').empty();
                const rows = (data && data.rows) || [];
                if (!rows.length) {
                    box.append($('<div class="pa-empty text-muted"/>').text(T.noFindings));
                }
                rows.forEach(function (row) {
                    const card = $('<div class="pa-finding-card"/>');
                    card.append('<div class="pa-fc-head">' + severityBadge(row.severity) + ' <code>' + esc(row.type) +
                        '</code></div>');
                    card.append($('<div class="pa-fc-title"/>').text(row.title));
                    card.append('<div class="pa-fc-rules">' + renderRules(row.rules, row.type) + '</div>');
                    card.append('<div class="pa-fc-actions">' +
                        '<button type="button" class="btn btn-default pa-details" data-row-id="' + esc(row.id) + '">' +
                        '<span class="fa fa-search-plus fa-fw"></span> ' + esc(T.details) + '</button>' +
                        '<button type="button" class="btn btn-default pa-explain" data-row-id="' + esc(row.id) + '"' +
                        (aiStatus.enabled ? '' : ' style="display:none"') + '>' +
                        '<span class="fa fa-magic fa-fw"></span> ' + esc(T.explain) + '</button></div>');
                    box.append(card);
                });
                bindRowButtons();
            });
        }

        grid.on('loaded.rs.jquery.bootgrid', function () {
            bindRowButtons();
            renderMobileList();
        });
        $('#filter_severity, #filter_type').on('changed.bs.select', function () {
            $('#grid-findings').bootgrid('reload');
        });

        function loadSummary() {
            ajaxGet('/api/policyanalyzer/analysis/summary', {}, function (data) {
                if (!data || data.status !== 'ok') {
                    $('#pa_lastrun').text(T.noReport);
                    ['high', 'medium', 'low', 'info'].forEach(function (s) { $('#pa_count_' + s).text('-'); });
                    return;
                }
                const sum = data.summary || {};
                const bySev = sum.by_severity || {};
                ['high', 'medium', 'low', 'info'].forEach(function (s) {
                    $('#pa_count_' + s).text(bySev[s] || 0);
                });
                let txt = T.lastRun + ': ' + (data.generated || '?') + ' (' + (data.duration_ms || 0) + ' ms) — ' +
                    (sum.rules || 0) + ' ' + T.rules + ', ' + (sum.enabled || 0) + ' ' + T.enabled + '. ';
                if (data.stats_available && data.stats && data.stats.counters_since) {
                    txt += T.countersSince + ' ' + data.stats.counters_since + '.';
                } else if (!data.stats_available) {
                    txt += T.noCounters + '.';
                }
                $('#pa_lastrun').text(txt);
                const selected = $('#filter_type').val() || [];
                $('#filter_type').empty();
                $.each(data.types || {}, function (type, count) {
                    $('#filter_type').append($('<option/>').val(type).text(type + ' (' + count + ')')
                        .prop('selected', selected.includes(type)));
                });
                $('#filter_type').selectpicker('refresh');
            });
        }

        $('.pa-card').click(function () {
            $('#filter_severity').selectpicker('val', [$(this).data('severity')]);
            $('#grid-findings').bootgrid('reload');
        });

        $('#act_analyze').click(function () {
            const btn = $(this);
            const started = Date.now();
            btn.prop('disabled', true);
            $('#act_analyze_progress').addClass('fa fa-spinner fa-pulse');
            $('#pa_progress').show().find('span').text(T.analyzing + ' 0 s');
            const timer = setInterval(function () {
                $('#pa_progress span').text(T.analyzing + ' ' + Math.round((Date.now() - started) / 1000) + ' s');
            }, 1000);
            ajaxCall('/api/policyanalyzer/analysis/analyze', {}, function (data) {
                clearInterval(timer);
                btn.prop('disabled', false);
                $('#act_analyze_progress').removeClass('fa fa-spinner fa-pulse');
                $('#pa_progress').hide();
                if (!data || data.status !== 'ok') {
                    PASimulation.dialog({type: BootstrapDialog.TYPE_DANGER, title: T.error,
                        message: esc((data && data.message) || T.error)});
                }
                loadSummary();
                $('#grid-findings').bootgrid('reload');
            });
        });

        function showDetails(id) {
            ajaxGet('/api/policyanalyzer/analysis/finding/' + encodeURIComponent(id), {}, function (data) {
                if (!data || data.status !== 'ok') {
                    PASimulation.dialog({type: BootstrapDialog.TYPE_WARNING, title: T.error,
                        message: esc((data && data.message) || T.error)});
                    return;
                }
                const f = data.finding;
                let html = '<p>' + severityBadge(f.severity) + ' <code>' + esc(f.type) + '</code></p>';
                html += '<h4>' + esc(T.detail) + '</h4><p>' + esc(f.detail) + '</p>';
                html += '<h4>' + esc(T.recommendation) + '</h4><p>' + esc(f.recommendation) + '</p>';
                html += '<h4>' + esc(T.rulesTitle) + '</h4><p>' + renderRules(f.rules, f.type) + '</p>';
                (f.rules || []).forEach(function (rule) {
                    if (rule.summary) {
                        html += '<pre style="white-space:pre-wrap">' + esc(rule.summary) + '</pre>';
                    }
                });
                if (f.aliases && f.aliases.length) {
                    html += '<h4>' + esc(T.aliases) + '</h4><p>' + f.aliases.map(function (a) {
                        return '<a href="/ui/firewall/alias#search=' + encodeURIComponent(a) +
                            '" target="_blank" rel="noopener noreferrer">' + esc(a) + '</a>';
                    }).join(', ') + '</p>';
                }
                html += '<h4>' + esc(T.evidence) + '</h4><pre style="white-space:pre-wrap">' +
                    esc(JSON.stringify(f.evidence || {}, null, 2)) + '</pre>';
                html += '<div id="pa_ai_answer"></div>';
                const buttons = [];
                if (aiStatus.enabled) {
                    buttons.push({label: T.explain, cssClass: 'btn-primary', action: function () {
                        explain(f.id, '#pa_ai_answer');
                    }});
                }
                if (['permissive', 'wan_exposed'].indexOf(f.type) >= 0 && f.rules && f.rules[0] && window.PAMinRule) {
                    buttons.push({label: "{{ lang._('Minimal rule') }}", cssClass: 'btn-default',
                                  action: function () { PAMinRule.open(f.rules[0].uuid); }});
                }
                buttons.push({label: T.preview, action: function () { preview(f.id); }});
                buttons.push({label: T.close, action: function (d) { d.close(); }});
                PASimulation.dialog({title: f.title, message: html, size: BootstrapDialog.SIZE_WIDE, buttons: buttons});
            });
        }

        function renderAnswer(data) {
            if (!data) {
                return '<div class="alert alert-danger">' + esc(T.error) + '</div>';
            }
            if (data.status === 'refusal') {
                return '<div class="alert alert-warning"><b>' + esc(T.refusal) + '</b><br/>' + esc(data.message) + '</div>';
            }
            if (data.status !== 'ok') {
                return '<div class="alert alert-danger">' + esc(data.message || T.error) + '</div>';
            }
            let html = '<div class="well">' + (window.PAMarkdown ? PAMarkdown.render(data.text) : esc(data.text)) + '</div>';
            if (data.truncated) {
                html += '<div class="alert alert-warning">' + esc(T.truncated) + '</div>';
            }
            html += '<p class="text-muted"><small>' + esc(data.provider || '') + ' / ' + esc(data.model || '') + ', ' +
                esc(Math.round((data.duration_ms || 0) / 100) / 10) + ' s, ' +
                esc(data.anonymized ? T.anonymized : T.notAnonymized) + '<br/>' + esc(T.aiDisclaimer) + '</small></p>';
            return html;
        }

        function explain(id, target) {
            const wait = '<p><i class="fa fa-spinner fa-pulse"></i> ' + esc(T.asking) + '</p>';
            let dialog = null;
            if (target) {
                $(target).html(wait);
            } else {
                dialog = PASimulation.dialog({title: T.explain, message: wait, size: BootstrapDialog.SIZE_WIDE,
                    buttons: [{label: T.close, action: function (d) { d.close(); }}]});
            }
            ajaxCall('/api/policyanalyzer/ai/explain', {id: id}, function (data) {
                const html = renderAnswer(data);
                if (target) {
                    $(target).html('<h4>' + esc(T.explain) + '</h4>' + html);
                } else {
                    dialog.getModalBody().html(html);
                }
            });
        }

        function preview(id) {
            ajaxCall('/api/policyanalyzer/ai/explain', {id: id, preview: 1}, function (data) {
                let html;
                if (!data || data.status !== 'ok') {
                    html = '<div class="alert alert-danger">' + esc((data && data.message) || T.error) + '</div>';
                } else {
                    html = '<p>' + esc(data.anonymized ? T.anonymized : T.notAnonymized) + ', ' + esc(data.bytes) +
                        ' bytes</p>' + (data.messages || []).map(function (m) {
                            return '<h5>' + esc(m.role) + '</h5><pre style="white-space:pre-wrap">' + esc(m.content) + '</pre>';
                        }).join('');
                }
                PASimulation.dialog({title: T.preview, message: html, size: BootstrapDialog.SIZE_WIDE,
                    buttons: [{label: T.close, action: function (d) { d.close(); }}]});
            });
        }

        $('#act_explain_all').click(function () { explain('all'); });
        $('#act_preview_all').click(function () { preview('all'); });

        function loadAiStatus() {
            ajaxGet('/api/policyanalyzer/ai/status', {}, function (data) {
                aiStatus = data && data.status === 'ok' ? data : {enabled: false};
                $('#act_explain_all').toggle(!!aiStatus.enabled);
                $('.pa-explain').toggle(!!aiStatus.enabled);
            });
        }

        /******************************************************************************************************
         * action history (undo journal)
         ******************************************************************************************************/
        let historyTimer = null;
        function loadHistory() {
            clearTimeout(historyTimer);
            ajaxGet('/api/policyanalyzer/ai/job', {}, function (jobData) {
                const job = jobData && jobData.job;
                const box = $('#pa_history_job').empty().hide();
                if (PASimulation.isActive(job)) {
                    box.show().append($('<div class="pa-finding-card"/>')
                        .append('<span class="label label-info">' + esc(T.running) + '</span>')
                        .append(PASimulation.renderJob(job))
                        .append($('<button type="button" class="btn btn-warning"/>').text(T.cancelJob)
                            .click(function () { PASimulation.cancelJob(loadHistory); })));
                    historyTimer = setTimeout(loadHistory, 3000);
                }
            });
            ajaxGet('/api/policyanalyzer/change/history', {}, function (data) {
                const body = $('#pa_history tbody').empty();
                ((data && data.items) || []).forEach(function (item) {
                    const tr = $('<tr/>');
                    tr.append($('<td/>').attr('data-label', T.date).text(item.ts || item.id));
                    tr.append($('<td/>').attr('data-label', T.action).text(item.description || item.action));
                    tr.append($('<td/>').attr('data-label', T.result).html(esc(item.status) + (item.reverted ?
                        ' <span class="label label-default">' + esc(T.reverted) + ' ' + esc(item.reverted.ts || '') + '</span>' : '')));
                    tr.append($('<td/>').attr('data-label', T.changes).html((item.summary || []).map(esc).join('<br/>')));
                    const td = $('<td/>');
                    if (item.revertible) {
                        $('<button type="button" class="btn btn-xs btn-default"/>')
                            .html('<span class="fa fa-undo fa-fw"></span> ' + esc(T.revert))
                            .click(function () {
                                /* the install of the local runtime offers "also delete the downloaded models" */
                                PASetup.revertEntry(item, refreshAll);
                            }).appendTo(td);
                    }
                    tr.append(td);
                    body.append(tr);
                });
            });
        }

        /******************************************************************************************************
         * settings: shared fields come from forms/settings.xml, provider choice and fields from the registry
         ******************************************************************************************************/
        let registry = {providers: []};
        let saved = {};          // flattened saved values
        let secretHints = {};

        function optionValue(node) {
            if (node !== null && typeof node === 'object') {
                for (const key in node) {
                    if (node[key] && node[key].selected) {
                        return key;
                    }
                }
                return '';
            }
            return node === undefined || node === null ? '' : String(node);
        }

        function flatten(obj, prefix, out) {
            out = out || {};
            $.each(obj || {}, function (key, value) {
                const path = prefix ? prefix + '.' + key : key;
                const isOptions = value && typeof value === 'object' &&
                    Object.values(value).some(function (v) { return v && typeof v === 'object' && 'selected' in v; });
                if (value && typeof value === 'object' && !isOptions) {
                    flatten(value, path, out);
                } else {
                    out[path] = optionValue(value);
                }
            });
            return out;
        }

        function byId(id) {
            return $(document.getElementById(id));
        }

        function currentProvider() {
            return byId('policyanalyzer.ai.provider').val() || 'none';
        }

        function choiceCard(value, icon, label, help, groupLabel) {
            return '<label class="panel panel-default pa-choice" data-value="' + esc(value) + '">' +
                '<input type="radio" name="pa_choice" value="' + esc(value) + '">' +
                '<span class="pa-choice-icon fa fa-fw ' + esc(icon) + '" aria-hidden="true"></span>' +
                '<span class="pa-choice-text"><span class="pa-choice-name">' + esc(label) + '</span>' +
                (groupLabel ? ' <span class="label label-default pa-choice-group">' + esc(groupLabel) + '</span>' : '') +
                (help ? '<span class="pa-choice-desc text-muted">' + esc(help) + '</span>' : '') +
                '</span></label>';
        }

        function markChoice(value) {
            const box = $('#pa_provider_choice');
            box.find('input[name=pa_choice]').each(function () {
                $(this).prop('checked', $(this).val() === value);
            });
            box.find('.pa-choice').each(function () {
                const on = $(this).data('value') === value;
                $(this).toggleClass('panel-primary pa-choice-selected', on).toggleClass('panel-default', !on);
            });
        }

        function renderChooser() {
            const box = $('#pa_provider_choice').empty();
            const groups = registry.groups || {local: T.local, api: T.api};
            box.append(choiceCard('none:', 'fa-ban', T.none, T.noneHelp, ''));
            Object.keys(groups).forEach(function (group) {
                const items = [];
                registry.providers.forEach(function (p) {
                    (p.choices || []).forEach(function (c) {
                        if ((c.group || p.group) === group) {
                            items.push({provider: p, choice: c});
                        }
                    });
                });
                if (!items.length) {
                    return;
                }
                const title = group === 'local' ? T.local : (group === 'api' ? T.api : groups[group]);
                box.append($('<h5 class="pa-choice-header"/>').text(title));
                items.forEach(function (it) {
                    const icon = it.choice.icon || (group === 'api' ? 'fa-cloud' : 'fa-server');
                    box.append(choiceCard(it.provider.id + ':' + it.choice.id, icon, it.choice.label,
                        it.choice.help, it.choice.badge || title));
                });
            });
            box.find('input[name=pa_choice]').change(function () {
                const value = $(this).val();
                markChoice(value);
                const parts = value.split(':');
                selectChoice(parts[0], parts[1], true);
            });
        }

        function findChoice(providerId, choiceId) {
            const p = registry.providers.find(function (x) { return x.id === providerId; });
            if (!p) {
                return {provider: null, choice: null};
            }
            return {provider: p, choice: (p.choices || []).find(function (c) { return c.id === choiceId; }) || null};
        }

        function guessChoice() {
            const provider = saved['policyanalyzer.ai.provider'] || 'none';
            const p = registry.providers.find(function (x) { return x.id === provider; });
            if (!p) {
                return 'none:';
            }
            const match = (p.choices || []).find(function (c) {
                return Object.keys(c.set || {}).every(function (k) {
                    return saved['policyanalyzer.' + p.id + '.' + k] === String(c.set[k]);
                });
            });
            return p.id + ':' + (match ? match.id : '');
        }

        function selectChoice(providerId, choiceId, userAction) {
            byId('policyanalyzer.ai.provider').val(providerId);
            const sel = findChoice(providerId, choiceId);
            const detail = $('#pa_provider_detail');
            const card = $('#pa_provider_choice .pa-choice').filter(function () {
                return $(this).attr('data-value') === providerId + ':' + (choiceId || '');
            });
            const open = function () {
                renderProviderFields(sel.provider, sel.choice, userAction);
                if (!sel.provider || !card.length) {
                    detail.hide();
                    return;
                }
                detail.insertAfter(card);
                if (userAction) {
                    detail.hide().slideDown(220);
                } else {
                    detail.show();
                }
            };
            if (userAction && detail.is(':visible')) {
                /* the previous provider's block closes first */
                detail.stop(true, true).slideUp(160, open);
            } else {
                open();
            }
        }

        function fieldVisible(provider, field) {
            return Object.keys(field.show_if || {}).every(function (k) {
                const el = byId('policyanalyzer.' + provider.id + '.' + k);
                return el.length && el.val() === String(field.show_if[k]);
            });
        }

        function renderProviderFields(provider, choice, userAction) {
            const box = $('#pa_provider_fields').empty();
            $('#pa_privacy').hide();
            $('#pa_ai_buttons').toggle(!!provider);
            if (!provider) {
                return;
            }
            $('#pa_privacy').show().toggleClass('alert-warning', provider.group === 'api' || !!provider.privacy_warn)
                .toggleClass('alert-info', provider.group !== 'api').text(provider.privacy || '');
            if (choice && choice.wizard) {
                box.append('<div class="alert alert-info">' + esc(T.wizardHint) + '</div>');
            }
            const table = $('<table class="table table-striped table-condensed"><tbody></tbody></table>');
            (provider.fields || []).forEach(function (field) {
                const id = 'policyanalyzer.' + provider.id + '.' + field.id;
                const preset = choice && choice.set && field.id in choice.set;
                const value = preset ? String(choice.set[field.id]) :
                    (saved[id] !== undefined && saved[id] !== '' ? saved[id] : (field.default || ''));
                let input;
                if (preset) {
                    table.append($('<input type="hidden"/>').attr('id', id).val(value));
                    return;
                }
                if (field.type === 'choice') {
                    /* sub-parameter: segmented radio group stored in a hidden input, drives show_if of other fields */
                    const hidden = $('<input type="hidden"/>').attr('id', id).val(value);
                    const group = $('<div class="pa-segment" role="radiogroup"/>').attr('aria-label', field.label);
                    $.each(field.options || {}, function (k, label) {
                        const opt = $('<label class="pa-segment-option"/>');
                        const radio = $('<input type="radio"/>').attr('name', 'pa_seg_' + field.id).val(k)
                            .prop('checked', k === value);
                        opt.append(radio).append($('<span class="pa-segment-label"/>').text(label));
                        if (field.option_help && field.option_help[k]) {
                            opt.append($('<span class="pa-segment-desc text-muted"/>').text(field.option_help[k]));
                        }
                        const mark = function (on, el) {
                            el.toggleClass('active panel-primary', on).toggleClass('panel-default', !on);
                        };
                        opt.addClass('panel');
                        mark(k === value, opt);
                        radio.on('change', function () {
                            hidden.val(k).trigger('change');
                            group.find('.pa-segment-option').each(function () { mark(false, $(this)); });
                            mark(true, opt);
                        });
                        group.append(opt);
                    });
                    input = $('<div/>').append(hidden).append(group);
                } else if (field.type === 'recommend') {
                    /* reusable block (PARecommend), fills the target field with the concrete model name */
                    input = $('<div/>');
                    const targetId = 'policyanalyzer.' + provider.id + '.' + (field.target || 'model');
                    const budgetId = field.budget ? 'policyanalyzer.' + provider.id + '.' + field.budget : null;
                    const recOpts = {onUse: function (name) {
                        const el = byId(targetId);
                        if (el.is('select') && !el.find('option[value="' + name + '"]').length) {
                            el.append($('<option/>').val(name).text(name));
                        }
                        el.val(name).trigger('change');
                        if (el.hasClass('selectpicker')) {
                            el.selectpicker('refresh');
                        }
                    }};
                    const recBox = input;
                    const loadRec = function () {
                        const budget = budgetId ? byId(budgetId).val() : '';
                        recOpts.params = budget ? {budget: budget} : {};
                        PARecommend.load(recBox, recOpts);
                    };
                    /* the budget field is rendered before this one; reload when it changes */
                    setTimeout(function () {
                        loadRec();
                        if (budgetId) {
                            let recTimer = null;
                            byId(budgetId).on('change keyup', function () {
                                clearTimeout(recTimer);
                                recTimer = setTimeout(loadRec, 600);
                            });
                        }
                    }, 0);
                } else if (field.type === 'status') {
                    input = $('<div class="pa-status-box"/>').attr('data-probe', field.probe || '');
                    input.append($('<div class="pa-status-text"/>'));
                    if (field.wizard_url) {
                        $('<a class="btn btn-default pa-wizard-link" data-pa-setup="1"/>').attr('href', field.wizard_url)
                            .html('<span class="fa fa-magic fa-fw"></span> ' + esc(T.openSetup)).appendTo(input);
                    }
                    runtimeStatus(input);
                } else if (field.type === 'dropdown') {
                    input = $('<select class="selectpicker" data-width="348px"/>').attr('id', id);
                    $.each(field.options || {}, function (k, label) {
                        input.append($('<option/>').val(k).text(label));
                    });
                    input.val(value);
                } else if (field.type === 'integer') {
                    input = $('<input type="number" class="form-control pa-number"/>').attr('id', id).val(value);
                    if (field.min !== undefined) {
                        input.attr('min', field.min);
                    }
                    if (field.max !== undefined) {
                        input.attr('max', field.max);
                    }
                } else if (field.type === 'password') {
                    input = $('<input type="password" autocomplete="new-password" class="form-control"/>').attr('id', id);
                } else {
                    input = $('<input type="text" class="form-control"/>').attr('id', id).val(value);
                }
                const cell = $('<td/>').append(input);
                if (field.secret) {
                    const hint = secretHints[provider.id + '.' + field.id] || '';
                    cell.append($('<small class="text-muted"/>').text(hint ? T.configured + ' ' + hint : T.notConfigured));
                    if (hint) {
                        $('<button type="button" class="btn btn-xs btn-default" style="margin-left:8px"/>')
                            .text(T.clearSecret).click(function () { clearSecret(provider.id + '.' + field.id, field.label); })
                            .appendTo(cell);
                    }
                }
                if (field.probe === 'hw_profile') {
                    if (field.unit) {
                        cell.append($('<span class="pa-unit"/>').text(' ' + field.unit));
                    }
                    const note = $('<div class="text-muted pa-hw-note"/>');
                    cell.append(note);
                    ajaxGet('/api/policyanalyzer/ai/hw_profile', {}, function (hw) {
                        const mem = (hw && hw.memory) || {};
                        if (mem.total_bytes && mem.available_bytes !== null && mem.available_bytes !== undefined) {
                            const used = Math.round(100 * (mem.total_bytes - mem.available_bytes) / mem.total_bytes);
                            note.text(T.ramInUse.replace('{used}', used + '%') + ' (' +
                                (mem.total_bytes / 1073741824).toFixed(1) + ' GiB ' + T.total + ')');
                        }
                    });
                }
                if (field.warn_public) {
                    const warn = $('<div class="text-warning pa-public-warn" style="display:none"/>').text(T.notPrivate);
                    cell.append(warn);
                    const check = function () { warn.toggle(!isPrivateUrl(input.val())); };
                    input.on('change keyup', check);
                    check();
                }
                if (field.list_models) {
                    $('<button type="button" class="btn btn-default btn-xs" style="margin-left:8px"/>')
                        .html('<span class="fa fa-list fa-fw"></span> ' + esc(T.listModels))
                        .click(function () { listModels(id, field.type); }).appendTo(cell);
                }
                if (field.storage) {
                    cell.append('<div class="pa-storage-info"><small></small> ' +
                        '<button type="button" class="btn btn-xs btn-primary pa-prepare" style="display:none">' +
                        esc(T.prepareStorage) + '</button></div>');
                    input.on('change keyup', function () { storageInfo($(this).val(), cell); });
                    storageInfo(value, cell);
                }
                if (field.help) {
                    cell.append($('<div class="text-muted"/>').append($('<small/>').text(field.help)));
                }
                table.find('tbody').append($('<tr/>').attr('data-field', field.id)
                    .append($('<td style="width:25%"/>').text(field.label)).append(cell));
            });
            box.append(table);
            box.find('.selectpicker').selectpicker();
            const updateVisibility = function () {
                (provider.fields || []).forEach(function (field) {
                    table.find('tr[data-field="' + field.id + '"]').toggle(fieldVisible(provider, field));
                });
            };
            box.find('select, input').on('change', updateVisibility);
            updateVisibility();
        }

        /* LAN check for URLs of servers that should stay in the local network */
        function isPrivateUrl(url) {
            let host;
            try {
                host = new URL(url).hostname.replace(/^\[|\]$/g, '').toLowerCase();
            } catch (e) {
                return true;            // nothing typed yet or not a URL: the model validation reports it
            }
            const m = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
            if (m) {
                const a = +m[1], b = +m[2];
                return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
                    (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
            }
            if (host.includes(':')) {
                return host === '::1' || /^f[cd]/.test(host) || /^fe[89ab]/.test(host);
            }
            return !host.includes('.') || /\.(lan|local|home\.arpa|internal|localdomain|intranet|corp|home)$/.test(host);
        }

        function runtimeStatus(box) {
            ajaxGet('/api/policyanalyzer/ai/runtime', {}, function (data) {
                const txt = box.find('.pa-status-text');
                if (!data || data.status !== 'ok') {
                    txt.text(T.runtimeUnknown);
                    return;
                }
                let line = data.installed ? (data.running ? T.runtimeRunning : T.runtimeStopped) : T.runtimeMissing;
                if (data.version) {
                    line += ' — Ollama ' + data.version;
                }
                if (data.models && data.models.length !== undefined) {
                    line += ' — ' + data.models.length + ' ' + T.modelsInstalled;
                }
                if (data.limits && data.limits.threads) {
                    line += ' — ' + T.limits + ': ' + data.limits.threads + ' threads, ctx ' + (data.limits.ctx || '?');
                }
                txt.text(line);
            });
        }

        let storageTimer = null;
        function storageInfo(path, cell) {
            clearTimeout(storageTimer);
            storageTimer = setTimeout(function () {
                ajaxGet('/api/policyanalyzer/ai/storage', {path: path}, function (data) {
                    const info = cell.find('.pa-storage-info small');
                    const btn = cell.find('.pa-prepare');
                    btn.hide();
                    if (!data || data.status !== 'ok') {
                        info.text((data && data.message) || '');
                        return;
                    }
                    const gb = data.free_bytes !== null ? (data.free_bytes / 1073741824).toFixed(1) + ' GiB' : '?';
                    let txt = gb + ' ' + T.free + ' ' + (data.dataset || data.mountpoint || data.checked_path);
                    if (!data.exists) {
                        txt += ' — ' + path + ' ' + T.missing;
                        btn.show().off('click').click(function () {
                            if (saved['policyanalyzer.ollama.models_dir'] !== path) {
                                PASimulation.dialog({type: BootstrapDialog.TYPE_WARNING, title: T.prepareStorage,
                                    message: esc(T.saveFirst)});
                                return;
                            }
                            PASimulation.run({action: 'prepare_storage', title: T.prepareStorage, onDone: function () {
                                storageInfo(path, cell);
                                loadHistory();
                            }});
                        });
                    } else if (!data.writable) {
                        txt += ' — ' + T.notWritable;
                    }
                    if (data.local === false) {
                        txt += ' — ' + T.notLocal;
                    }
                    info.text(txt);
                });
            }, 400);
        }

        function isDirty() {
            const now = flatten(getFormData('frm_settings'));
            return Object.keys(now).some(function (k) {
                return now[k] !== (saved[k] === undefined ? '' : saved[k]) &&
                    !(secretHints[k.replace('policyanalyzer.', '')] !== undefined && now[k] === '');
            });
        }

        function listModels(fieldId, type) {
            if (isDirty()) {
                PASimulation.dialog({type: BootstrapDialog.TYPE_WARNING, title: T.listModels, message: esc(T.saveFirst)});
                return;
            }
            ajaxGet('/api/policyanalyzer/ai/models', {}, function (data) {
                let html;
                if (!data || data.status !== 'ok') {
                    html = '<div class="alert alert-danger">' + esc((data && data.message) || T.error) + '</div>';
                } else {
                    html = '<table class="table table-condensed table-hover"><tbody>' + (data.models || []).map(function (m) {
                        return '<tr class="pa-model" style="cursor:pointer" data-name="' + esc(m.name) + '"><td><b>' +
                            esc(m.name) + '</b></td><td>' + esc(m.label || m.parameters || '') + '</td><td>' +
                            esc(m.quantization || '') + '</td><td>' +
                            esc(m.size ? (m.size / 1073741824).toFixed(1) + ' GiB' : '') + '</td></tr>';
                    }).join('') + '</tbody></table>';
                }
                PASimulation.dialog({title: T.listModels, message: html, size: BootstrapDialog.SIZE_WIDE,
                    buttons: [{label: T.close, action: function (d) { d.close(); }}],
                    onshown: function (d) {
                        d.getModalBody().find('.pa-model').click(function () {
                            const el = byId(fieldId);
                            const name = $(this).data('name');
                            if (type === 'dropdown' && !el.find('option[value="' + name + '"]').length) {
                                el.append($('<option/>').val(name).text(name));
                            }
                            el.val(name);
                            if (el.hasClass('selectpicker')) {
                                el.selectpicker('refresh');
                            }
                            d.close();
                        });
                    }});
            });
        }

        $('#act_test').click(function () {
            if (isDirty()) {
                PASimulation.dialog({type: BootstrapDialog.TYPE_WARNING, title: T.testConnection, message: esc(T.saveFirst)});
                return;
            }
            $('#act_test_progress').addClass('fa fa-spinner fa-pulse');
            ajaxCall('/api/policyanalyzer/ai/test', {}, function (data) {
                $('#act_test_progress').removeClass('fa fa-spinner fa-pulse');
                let html;
                if (!data || data.status !== 'ok') {
                    html = '<div class="alert alert-danger">' + esc((data && data.message) || T.error) + '</div>';
                } else {
                    html = '<div class="alert ' + (data.model_available ? 'alert-success' : 'alert-warning') + '">' +
                        esc(T.reachable) + ': ' + esc(data.endpoint) + ' (' + esc(data.version) + ', ' +
                        esc(data.duration_ms) + ' ms)' + (data.model_available ? '' : '<br/>' + esc(data.model) + ': ' +
                        esc(T.modelMissing)) + '</div>';
                }
                PASimulation.dialog({title: T.testConnection, message: html,
                    buttons: [{label: T.close, action: function (d) { d.close(); }}]});
            });
        });

        function clearSecret(field, label) {
            PASimulation.show({
                status: 'ok', risk: 'low',
                steps: [{description: label + ': ' + T.clearSecret, command: 'settings: ' + field + ' = ""',
                         effect: T.configured + ' ' + (secretHints[field] || '') + ' → ' + T.notConfigured}],
                revert: ["{{ lang._('Revert from the action history restores the previous value.') }}"]
            }, {
                title: T.clearSecret + ' ' + label,
                apply: function (dialog, done) {
                    ajaxCall('/api/policyanalyzer/settings/clear_secret', {field: field}, function (data) {
                        done({status: data && data.result === 'saved' ? 'ok' : 'error', done: !!(data && data.result === 'saved'),
                              journal_id: data && data.journal_id, message: data && data.message});
                    });
                },
                onDone: refreshAll
            });
        }

        $('#act_save').click(function () {
            const now = flatten(getFormData('frm_settings'));
            const steps = [];
            Object.keys(now).sort().forEach(function (k) {
                const old = saved[k] === undefined ? '' : saved[k];
                const short = k.replace('policyanalyzer.', '');
                if (secretHints[short] !== undefined) {
                    if (now[k] !== '') {
                        steps.push({description: short, command: 'settings: ' + short,
                                    effect: (secretHints[short] ? T.configured + ' ' + secretHints[short] : T.notConfigured) +
                                        ' → ' + T.configured + ' ****' + now[k].slice(-4)});
                    }
                } else if (now[k] !== old) {
                    steps.push({description: short, command: 'settings: ' + short + ' = ' + now[k],
                                effect: (old === '' ? '(empty)' : old) + ' → ' + (now[k] === '' ? '(empty)' : now[k])});
                }
            });
            if (!steps.length) {
                PASimulation.dialog({title: T.saveSettings, message: esc(T.noChanges)});
                return;
            }
            PASimulation.show({
                status: 'ok', risk: 'low', steps: steps,
                revert: ["{{ lang._('Revert from the action history restores the previous values.') }}"]
            }, {
                title: T.settingsChange,
                apply: function (dialog, done) {
                    saveFormToEndpoint('/api/policyanalyzer/settings/set', 'frm_settings', function (data) {
                        done({status: 'ok', done: true, completed: steps.map(function (s) { return s.description; }),
                              journal_id: data.journal_id});
                    }, false, function (data) {
                        done({status: 'error', done: false, message: "{{ lang._('Please correct the highlighted fields.') }}"});
                    });
                },
                onDone: refreshAll
            });
        });

        function loadSettings() {
            ajaxGet('/api/policyanalyzer/settings/get', {}, function (data) {
                if (!data || !data.policyanalyzer) {
                    return;
                }
                setFormData('frm_settings', data);
                formatTokenizersUI();
                $('.selectpicker').selectpicker('refresh');
                saved = flatten({policyanalyzer: data.policyanalyzer});
                secretHints = data.secret_hints || {};
                ajaxGet('/api/policyanalyzer/ai/providers', {}, function (reg) {
                    registry = reg && reg.providers ? reg : {providers: []};
                    renderChooser();
                    const choice = guessChoice();
                    markChoice(choice);
                    const parts = choice.split(':');
                    selectChoice(parts[0], parts[1], false);
                });
            });
        }

        function refreshAll() {
            loadSettings();
            loadAiStatus();
            loadHistory();
        }
        let aiRoutingStarted = false;
        function startAiRouting() {
            if (aiRoutingStarted) {
                PAAIRouting.refresh();
                return;
            }
            aiRoutingStarted = true;
            PAAIRouting.init({strings: {
                presets: "{{ lang._('Presets') }}",
                fallback: "{{ lang._('Fallback provider') }}",
                fallbackHelp: "{{ lang._('Used when the provider of a scenario fails (bridge down, timeout). auto: the Ollama of this firewall, when the AI setup installed it.') }}",
                scenario: "{{ lang._('Scenario') }}", provider: "{{ lang._('Provider') }}", model: "{{ lang._('Model') }}",
                mode: "{{ lang._('Mode') }}", timeout: "{{ lang._('Timeout (s)') }}", edit: "{{ lang._('Edit') }}",
                budget: "{{ lang._('Context budget (tokens)') }}", retries: "{{ lang._('Correction attempts') }}",
                reset: "{{ lang._('Follow the global provider') }}", simulate: "{{ lang._('Simulate') }}",
                sync: "{{ lang._('synchronous') }}", queue: "{{ lang._('background queue') }}",
                queueTitle: "{{ lang._('AI queue') }}", cron: "{{ lang._('Cron job of the queue') }}",
                kick: "{{ lang._('Run the queue now') }}", refresh: "{{ lang._('Refresh') }}",
                jobs: "{{ lang._('Latest jobs') }}", stats: "{{ lang._('Statistics per scenario and model (90 days)') }}",
                cancel: "{{ lang._('Cancel') }}", none: "{{ lang._('nothing yet') }}"
            }});
        }

        // tabs: keep the hash in sync
        if (window.location.hash !== '') {
            $('a[href="' + window.location.hash + '"]').click();
        }
        $('.nav-tabs a').on('shown.bs.tab', function (e) {
            history.pushState(null, null, e.target.hash);
            if (e.target.hash === '#history') {
                loadHistory();
            }
            if (e.target.hash === '#quarantine') {
                PAQuarantine.refresh();
            }
            if (e.target.hash === '#settings') {
                startAiRouting();
            }
        });

        $('#frm_settings').append($('#pa_provider_block'));
        if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            $.fx.off = true;
        }
        /* accent colour of the active theme (no fixed colours in the plugin CSS) */
        const activeTab = document.querySelector('#maintabs > li.active > a');
        if (activeTab) {
            document.getElementById('pa_root').style.setProperty('--pa-accent', getComputedStyle(activeTab).color);
        }
        $('#filter_severity, #filter_type').selectpicker();
        loadSummary();
        refreshAll();
        if (window.location.hash === '#settings') {
            startAiRouting();
        }
        PAQuarantine.init({strings: {
                notInstalled: "{{ lang._('Not installed') }}",
                active: "{{ lang._('Active') }}",
                paused: "{{ lang._('Paused') }}",
                ruleOn: "{{ lang._('rule on') }}",
                ruleOff: "{{ lang._('rule off') }}",
                install: "{{ lang._('Install') }}",
                remove: "{{ lang._('Remove') }}",
                pause: "{{ lang._('Pause') }}",
                resume: "{{ lang._('Resume') }}",
                add: "{{ lang._('Add manually') }}",
                nextRun: "{{ lang._('next run') }}",
                lastRun: "{{ lang._('last run') }}",
                never: "{{ lang._('never') }}",
                offenses: "{{ lang._('offenses') }}",
                offensesCol: "{{ lang._('Offenses') }}",
                newIn24h: "{{ lang._('new in 24 h') }}",
                offenses24h: "{{ lang._('offenses in 24 h') }}",
                expired24h: "{{ lang._('expired in 24 h') }}",
                topCountries: "{{ lang._('Top countries') }}",
                topAsns: "{{ lang._('Top ASNs') }}",
                perm: "{{ lang._('permanent') }}",
                release: "{{ lang._('Release') }}",
                extend: "{{ lang._('Extend') }}",
                extendNext: "{{ lang._('Next level') }}",
                permanent: "{{ lang._('Make permanent') }}",
                neverBlock: "{{ lang._('Never block (pa_never_block)') }}",
                history: "{{ lang._('History of this address') }}",
                liveView: "{{ lang._('Open in Live View') }}",
                actions: "{{ lang._('Actions') }}",
                selected: "{{ lang._('selected') }}",
                batchMax: "{{ lang._('at most {n} at a time') }}",
                address: "{{ lang._('Address') }}",
                level: "{{ lang._('Level') }}",
                remaining: "{{ lang._('Remaining') }}",
                reason: "{{ lang._('Reason') }}",
                state: "{{ lang._('State') }}",
                firstSeen: "{{ lang._('First seen') }}",
                lastOffense: "{{ lang._('Last offense') }}",
                blockedFor: "{{ lang._('Blocked for') }}",
                origin: "{{ lang._('Origin') }}",
                country: "{{ lang._('Country') }}",
                asn: "{{ lang._('ASN') }}",
                hits: "{{ lang._('Hits') }}",
                comment: "{{ lang._('Comment') }}",
                auto: "{{ lang._('automatic') }}",
                manual: "{{ lang._('manual') }}",
                st_active: "{{ lang._('active') }}",
                st_expired: "{{ lang._('expired') }}",
                st_released: "{{ lang._('released') }}",
                st_permanent: "{{ lang._('permanent') }}",
                r_base: "{{ lang._('base') }}",
                r_scan: "{{ lang._('scan') }}",
                r_bait: "{{ lang._('bait') }}",
                r_suricata: "{{ lang._('suricata') }}",
                r_manual: "{{ lang._('manual') }}",
                filters: "{{ lang._('Filters') }}",
                apply: "{{ lang._('Apply') }}",
                clear: "{{ lang._('Clear') }}",
                year: "{{ lang._('Year') }}",
                any: "{{ lang._('any') }}",
                search: "{{ lang._('Address or comment') }}",
                exportCsv: "{{ lang._('Export CSV') }}",
                kindOffenses: "{{ lang._('Offenses') }}",
                kindEvents: "{{ lang._('Entries and exits') }}",
                kindYearly: "{{ lang._('Per year') }}",
                prev: "{{ lang._('Previous') }}",
                next: "{{ lang._('Next') }}",
                loadMore: "{{ lang._('Load more') }}",
                noEntries: "{{ lang._('No entries match the filters.') }}",
                duration: "{{ lang._('Duration') }}",
                dAuto: "{{ lang._('ladder (automatic)') }}",
                simulate: "{{ lang._('Simulate') }}",
                guards: "{{ lang._('Protected addresses') }}",
                settings: "{{ lang._('Settings') }}",
                change: "{{ lang._('Change') }}",
                copy: "{{ lang._('Copy') }}",
                time: "{{ lang._('Time') }}",
                events: "{{ lang._('Events') }}",
                ports: "{{ lang._('Ports') }}",
                detail: "{{ lang._('Detail') }}",
                iface: "{{ lang._('Interface') }}",
                kind: "{{ lang._('Kind') }}",
                prefixes: "{{ lang._('prefixes') }}",
                perYear: "{{ lang._('Per year') }}",
                firstLast: "{{ lang._('first / last') }}",
                maxLevel: "{{ lang._('max level') }}",
                error: "{{ lang._('Error') }}",
                close: "{{ lang._('Close') }}",
                until: "{{ lang._('until') }}",
                installHelp: "{{ lang._('Install opens the quarantine setup: ledger, aliases pa_quarantine and pa_never_block, the rule Max Cyber IA, scenarios, a cron job every 5 minutes and the first run, one step at a time; every step is simulated first and can be undone alone.') }}",
                purge: "{{ lang._('Also delete the history database (every offense of every year). This can not be undone.') }}",
                set_reset_days: "{{ lang._('Days without offenses before the level goes back to zero') }}",
                set_scan_ports: "{{ lang._('Port scan: distinct destination ports') }}",
                set_scan_window: "{{ lang._('Port scan: window (seconds)') }}",
                set_bait_ports: "{{ lang._('Bait ports (separated by +)') }}",
                set_suricata: "{{ lang._('Use Suricata alerts (1/0)') }}",
                set_suricata_severity: "{{ lang._('Suricata: highest severity number that counts (1 = only the most severe)') }}",
                set_max_active: "{{ lang._('Maximum active pf entries') }}",
                set_syn_only: "{{ lang._('TCP: count only connection attempts (1/0)') }}",
                set_budget: "{{ lang._('Seconds per run') }}"
            }});
        /* AI setup assistant: [data-pa-setup] buttons, #setup[-N] and the /ui/policyanalyzer/setup route open the modal */
        /* quarantine setup assistant: Install / Setup / Repair / Remove of the Quarantine tab and #qsetup[-N] open it */
        PAQSetup.bind({onClose: function () { PAQuarantine.refresh(); }});
        PASetup.bind({onClose: refreshAll,
                      autoOpen: {% if openSetup is defined and openSetup %}true{% else %}false{% endif %}});
    });
</script>


<div id="pa_root">
<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#findings">{{ lang._('Findings') }}</a></li>
    <li><a data-toggle="tab" href="#quarantine">{{ lang._('Quarantine') }}</a></li>
    <li><a data-toggle="tab" href="#history">{{ lang._('Action history') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="findings" class="tab-pane fade in active">
        <div class="container-fluid" style="padding-top: 10px;">
            <div class="row">
                <div class="col-md-12 pa-toolbar">
                    <button class="btn btn-primary" id="act_analyze" type="button">
                        <b>{{ lang._('Analyze') }}</b> <i id="act_analyze_progress"></i>
                    </button>
                    <button class="btn btn-default" id="act_explain_all" type="button" style="display:none">
                        <span class="fa fa-magic fa-fw"></span> {{ lang._('Explain all findings with AI') }}
                    </button>
                    <button class="btn btn-default" id="act_preview_all" type="button">
                        <span class="fa fa-eye fa-fw"></span> {{ lang._('Show what would be sent') }}
                    </button>
                    <button class="btn btn-default" id="act_setup" type="button" data-pa-setup="1">
                        <span class="fa fa-magic fa-fw"></span> {{ lang._('AI setup') }}
                    </button>
                    <span id="pa_progress" style="display:none; margin-left: 10px;"><span></span></span>
                    <p class="text-muted" style="margin-top: 8px;"><small id="pa_lastrun"></small></p>
                    <p class="text-muted"><small>{{ lang._('The analysis is read only: it never changes rules or settings. Links open the rule in Firewall: Rules where you decide what to change.') }}</small></p>
                </div>
            </div>
            <div class="row">
                <div class="col-xs-6 col-md-3"><div class="panel panel-danger pa-card" data-severity="high"><div class="pa-count" id="pa_count_high">-</div>{{ lang._('High') }}</div></div>
                <div class="col-xs-6 col-md-3"><div class="panel panel-warning pa-card" data-severity="medium"><div class="pa-count" id="pa_count_medium">-</div>{{ lang._('Medium') }}</div></div>
                <div class="col-xs-6 col-md-3"><div class="panel panel-info pa-card" data-severity="low"><div class="pa-count" id="pa_count_low">-</div>{{ lang._('Low') }}</div></div>
                <div class="col-xs-6 col-md-3"><div class="panel panel-default pa-card" data-severity="info"><div class="pa-count" id="pa_count_info">-</div>{{ lang._('Info') }}</div></div>
            </div>
            <div class="row" style="margin-bottom: 10px;">
                <div class="col-md-12 pa-filters">
                    <select id="filter_severity" multiple="multiple" data-title="{{ lang._('Severity') }}" data-width="200px">
                        <option value="high">{{ lang._('High') }}</option>
                        <option value="medium">{{ lang._('Medium') }}</option>
                        <option value="low">{{ lang._('Low') }}</option>
                        <option value="info">{{ lang._('Info') }}</option>
                    </select>
                    <select id="filter_type" multiple="multiple" data-title="{{ lang._('Type') }}" data-width="260px" data-live-search="true"></select>
                </div>
            </div>
        </div>
        <div id="pa_mobile_list" class="pa-mobile-list"></div>
        <div class="pa-grid-wrap">
        <table id="grid-findings" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
            <tr>
                <th data-column-id="id" data-type="string" data-identifier="true" data-visible="false">{{ lang._('ID') }}</th>
                <th data-column-id="severity" data-type="string" data-formatter="severity" data-width="7em">{{ lang._('Severity') }}</th>
                <th data-column-id="type" data-type="string" data-width="10em">{{ lang._('Type') }}</th>
                <th data-column-id="title" data-type="string">{{ lang._('Finding') }}</th>
                <th data-column-id="rules" data-type="string" data-formatter="rules" data-sortable="false">{{ lang._('Rules') }}</th>
                <th data-column-id="recommendation" data-type="string" data-sortable="false">{{ lang._('Recommendation') }}</th>
                <th data-column-id="commands" data-formatter="commands" data-sortable="false" data-width="6em">{{ lang._('Commands') }}</th>
            </tr>
            </thead>
            <tbody></tbody>
        </table>
        </div>
    </div>

    <div id="quarantine" class="tab-pane fade in">
        <div class="container-fluid pa-q" id="pa_q_root">
            <div class="pa-q-head">
                <div id="pa_q_state" class="pa-q-state"></div>
                <div class="pa-q-buttons">
                    <button class="btn btn-primary" id="pa_q_install" type="button" style="display:none">
                        <span class="fa fa-fw fa-shield"></span> {{ lang._('Install') }}</button>
                    <button class="btn btn-default" id="pa_q_setup" type="button" style="display:none"
                            title="{{ lang._('Reopen the quarantine setup at the current step') }}">
                        <span class="fa fa-fw fa-magic"></span> {{ lang._('Setup') }}</button>
                    <button class="btn btn-default" id="pa_q_pause" type="button" style="display:none">
                        <span class="fa fa-fw fa-pause"></span> {{ lang._('Pause') }}</button>
                    <button class="btn btn-primary" id="pa_q_resume" type="button" style="display:none">
                        <span class="fa fa-fw fa-play"></span> {{ lang._('Resume') }}</button>
                    <button class="btn btn-default" id="pa_q_add_toggle" type="button" style="display:none">
                        <span class="fa fa-fw fa-plus"></span> {{ lang._('Add manually') }}</button>
                    <button class="btn btn-default" id="pa_q_guards" type="button">
                        <span class="fa fa-fw fa-life-ring"></span> {{ lang._('Protected addresses') }}</button>
                    <button class="btn btn-default" id="pa_q_settings" type="button" style="display:none">
                        <span class="fa fa-fw fa-sliders"></span> {{ lang._('Settings') }}</button>
                    <button class="btn btn-default" id="pa_q_remove" type="button" style="display:none">
                        <span class="fa fa-fw fa-trash"></span> {{ lang._('Remove') }}</button>
                </div>
            </div>
            <div id="pa_q_warnings"></div>
            <div id="pa_q_body" style="display:none">
                <div id="pa_q_cards" class="pa-q-cards" role="group" aria-label="{{ lang._('Active entries per level') }}"></div>
                <div id="pa_q_facts" class="pa-q-facts"></div>
                <div id="pa_q_tops"></div>

                <div id="pa_q_add_box" class="panel panel-default pa-q-panel" style="display:none">
                    <form id="pa_q_add_form" class="pa-q-add" autocomplete="off">
                        <div class="pa-q-field pa-q-field-wide">
                            <label for="pa_q_target">{{ lang._('Address, network, range or ASN') }}</label>
                            <input type="text" class="form-control" id="pa_q_target" maxlength="90"
                                   placeholder="203.0.113.5 · 203.0.113.0/24 · 203.0.113.10-203.0.113.20 · AS64500"/>
                        </div>
                        <div class="pa-q-field">
                            <label for="pa_q_duration">{{ lang._('Duration') }}</label>
                            <select class="form-control" id="pa_q_duration"></select>
                        </div>
                        <div class="pa-q-field pa-q-field-wide">
                            <label for="pa_q_comment">{{ lang._('Comment') }}</label>
                            <input type="text" class="form-control" id="pa_q_comment" maxlength="120"/>
                        </div>
                        <div class="pa-q-field pa-q-field-btn">
                            <button class="btn btn-primary" type="submit"><span class="fa fa-fw fa-flask"></span>
                                {{ lang._('Simulate') }}</button>
                        </div>
                    </form>
                    <p class="text-muted pa-q-help"><small>{{ lang._('The guards apply here too: private, own and protected addresses are refused, protected addresses inside a network stay reachable. Networks bigger than /16 (IPv4) or /32 (IPv6), ASNs with many prefixes and permanent entries ask for a second confirmation.') }}</small></p>
                </div>

                <div id="pa_q_settings_box" class="panel panel-default pa-q-panel" style="display:none">
                    <div id="pa_q_settings_body" class="pa-q-settings"></div>
                </div>

                <div class="pa-q-toolbar">
                    <button class="btn btn-default pa-q-filters-toggle" id="pa_q_filters_toggle" type="button">
                        <span class="fa fa-fw fa-filter"></span> {{ lang._('Filters') }}</button>
                    <div id="pa_q_filters" class="pa-q-filters">
                        <select id="pa_q_f_year" class="form-control" aria-label="{{ lang._('Year') }}">
                            <option value="">{{ lang._('Year') }}: {{ lang._('any') }}</option></select>
                        <select id="pa_q_f_state" class="form-control" aria-label="{{ lang._('State') }}">
                            <option value="">{{ lang._('State') }}: {{ lang._('any') }}</option>
                            <option value="blocked">{{ lang._('blocked now') }}</option>
                            <option value="active">{{ lang._('active') }}</option>
                            <option value="permanent">{{ lang._('permanent') }}</option>
                            <option value="expired">{{ lang._('expired') }}</option>
                            <option value="released">{{ lang._('released') }}</option></select>
                        <select id="pa_q_f_reason" class="form-control" aria-label="{{ lang._('Reason') }}">
                            <option value="">{{ lang._('Reason') }}: {{ lang._('any') }}</option>
                            <option value="base">base</option><option value="scan">scan</option>
                            <option value="bait">bait</option><option value="suricata">suricata</option>
                            <option value="manual">manual</option></select>
                        <select id="pa_q_f_origin" class="form-control" aria-label="{{ lang._('Origin') }}">
                            <option value="">{{ lang._('Origin') }}: {{ lang._('any') }}</option>
                            <option value="auto">{{ lang._('automatic') }}</option>
                            <option value="manual">{{ lang._('manual') }}</option></select>
                        <input id="pa_q_f_country" class="form-control" maxlength="2" placeholder="{{ lang._('Country') }} (BR)"
                               aria-label="{{ lang._('Country') }}"/>
                        <input id="pa_q_f_asn" class="form-control" maxlength="10" inputmode="numeric"
                               placeholder="{{ lang._('ASN') }}" aria-label="{{ lang._('ASN') }}"/>
                        <input id="pa_q_f_search" class="form-control pa-q-mobile-only" maxlength="64"
                               placeholder="{{ lang._('Address or comment') }}" aria-label="{{ lang._('Address or comment') }}"/>
                        <button class="btn btn-primary" id="pa_q_f_apply" type="button">{{ lang._('Apply') }}</button>
                        <button class="btn btn-default" id="pa_q_f_clear" type="button">{{ lang._('Clear') }}</button>
                        <button class="btn btn-default" id="pa_q_export" type="button">
                            <span class="fa fa-fw fa-download"></span> {{ lang._('Export CSV') }}</button>
                    </div>
                </div>

                <div id="pa_q_batch" class="pa-q-batch">
                    <span class="pa-q-batch-count"></span>
                    <button class="btn btn-default" id="pa_q_batch_release" type="button">
                        <span class="fa fa-fw fa-unlock"></span> {{ lang._('Release') }}</button>
                    <span class="pa-q-batch-extend">
                        <select id="pa_q_batch_level" class="form-control" aria-label="{{ lang._('Extend') }}"></select>
                        <button class="btn btn-default" id="pa_q_batch_extend" type="button">
                            <span class="fa fa-fw fa-level-up"></span> {{ lang._('Extend') }}</button>
                    </span>
                    <button class="btn btn-default" id="pa_q_batch_permanent" type="button">
                        <span class="fa fa-fw fa-ban"></span> {{ lang._('Make permanent') }}</button>
                </div>

                <div id="pa_q_mobile" class="pa-q-mobile"></div>
                <div id="pa_q_grid_wrap" class="pa-q-grid-wrap">
                    <table id="grid-quarantine" class="table table-condensed table-hover table-striped">
                        <thead>
                        <tr>
                            <th data-column-id="id" data-type="numeric" data-identifier="true" data-visible="false">ID</th>
                            <th data-column-id="addr" data-formatter="addr" data-min-width="150">{{ lang._('Address') }}</th>
                            <th data-column-id="level" data-formatter="level" data-width="110">{{ lang._('Level') }}</th>
                            <th data-column-id="until" data-formatter="remaining" data-width="100">{{ lang._('Remaining') }}</th>
                            <th data-column-id="reason" data-formatter="reason" data-width="90">{{ lang._('Reason') }}</th>
                            <th data-column-id="state" data-formatter="state" data-width="90">{{ lang._('State') }}</th>
                            <th data-column-id="offenses" data-type="numeric" data-width="80">{{ lang._('Offenses') }}</th>
                            <th data-column-id="country" data-formatter="country" data-width="100">{{ lang._('Country') }}</th>
                            <th data-column-id="last_offense" data-formatter="when" data-width="135">{{ lang._('Last offense') }}</th>
                            <th data-column-id="first_seen" data-formatter="when" data-visible="false" data-width="135">{{ lang._('First seen') }}</th>
                            <th data-column-id="since" data-formatter="blocked" data-visible="false" data-sortable="false">{{ lang._('Blocked for') }}</th>
                            <th data-column-id="origin" data-formatter="origin" data-visible="false" data-width="90">{{ lang._('Origin') }}</th>
                            <th data-column-id="asn" data-formatter="asn" data-visible="false" data-width="100">{{ lang._('ASN') }}</th>
                            <th data-column-id="hits" data-type="numeric" data-visible="false" data-width="70">{{ lang._('Hits') }}</th>
                            <th data-column-id="commands" data-formatter="commands" data-sortable="false" data-width="90">{{ lang._('Actions') }}</th>
                        </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>

                <details id="pa_q_history_box" class="pa-q-history">
                    <summary><b>{{ lang._('History') }}</b> <small class="text-muted">{{ lang._('kept forever: every offense and every entry and exit, by year') }}</small></summary>
                    <div class="pa-q-filters pa-q-open pa-q-history-filters">
                        <select id="pa_q_h_kind" class="form-control" aria-label="{{ lang._('Kind') }}">
                            <option value="offenses">{{ lang._('Offenses') }}</option>
                            <option value="events">{{ lang._('Entries and exits') }}</option>
                            <option value="yearly">{{ lang._('Per year') }}</option></select>
                        <select id="pa_q_h_year" class="form-control" aria-label="{{ lang._('Year') }}">
                            <option value="">{{ lang._('Year') }}: {{ lang._('any') }}</option></select>
                        <input id="pa_q_h_ip" class="form-control" maxlength="64" placeholder="{{ lang._('Address') }}"
                               aria-label="{{ lang._('Address') }}"/>
                    </div>
                    <div id="pa_q_history"></div>
                </details>
            </div>
        </div>
    </div>

    <div id="history" class="tab-pane fade in">
        <div class="container-fluid" style="padding-top: 10px;">
            <p class="text-muted"><small>{{ lang._('Every change made from this page (settings, storage, ...) is recorded here. Revert first shows a simulation of what will be undone.') }}</small></p>
            <div id="pa_history_job" style="display:none"></div>
            <table id="pa_history" class="table table-condensed table-striped">
                <thead>
                <tr>
                    <th>{{ lang._('Date') }}</th>
                    <th>{{ lang._('Action') }}</th>
                    <th>{{ lang._('Result') }}</th>
                    <th>{{ lang._('Changes') }}</th>
                    <th></th>
                </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <div id="settings" class="tab-pane fade in">
        {{ partial("layout_partials/base_form",['fields':settingsForm,'id':'frm_settings'])}}
        <!-- moved into frm_settings on load, so one getFormData() covers shared and provider fields -->
        <div id="pa_provider_block" class="container-fluid">
            <input type="hidden" id="policyanalyzer.ai.provider" value="none"/>
            <h4>{{ lang._('AI provider') }}</h4>
            <div id="pa_provider_choice" class="pa-choices" role="radiogroup" aria-label="{{ lang._('AI provider') }}"></div>
        </div>
        <!-- expands right below the selected provider card (moved there by selectChoice) -->
        <div id="pa_provider_detail" class="pa-provider-detail" style="display:none">
            <div id="pa_privacy" class="alert" style="display:none"></div>
            <div id="pa_provider_fields"></div>
        </div>
        <div class="container-fluid pa-settings-actions">
            <button class="btn btn-primary" id="act_save" type="button"><b>{{ lang._('Save') }}</b></button>
            <span id="pa_ai_buttons" style="display:none">
                <button class="btn btn-default" id="act_test" type="button">{{ lang._('Test connection') }} <i id="act_test_progress"></i></button>
            </span>
            <p class="text-muted" style="margin-top: 8px;"><small>{{ lang._('Saving first shows the changes; every save is recorded in the action history and can be reverted. Test connection and List models use the saved settings and never send findings.') }}</small></p>
        </div>
        <!-- AI per scenario (js/policyanalyzer/airouting.js): routing table, presets, fallback, queue -->
        <div class="container-fluid pa-airouting" id="pa_airouting">
            <h4>{{ lang._('AI per scenario') }}</h4>
            <p class="text-muted"><small>{{ lang._('Each AI feature of the plugin is a scenario with its own provider, model and limits. Empty fields follow the global provider above. Long scenarios on the local runtime go to a background queue: the page shows the position and the estimate and receives the answer when it is ready. Every change is simulated first and recorded in the action history.') }}</small></p>
            <div id="pa_airouting_body"><i class="fa fa-spinner fa-pulse"></i></div>
            <h4>{{ lang._('AI queue') }}</h4>
            <p id="pa_airouting_cron"></p>
            <div id="pa_airouting_queue"></div>
        </div>
    </div>
</div>
</div>
