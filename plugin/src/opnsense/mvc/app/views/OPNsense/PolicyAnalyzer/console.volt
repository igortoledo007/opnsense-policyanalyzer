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

{#
 # AI Console (read only): "Ask the firewall" and "Explain this" for filter log events, rules and Suricata
 # alerts. Logic in js/policyanalyzer/console.js, Markdown in js/policyanalyzer/markdown.js, styles in
 # css/policyanalyzer/console.css. API: /api/policyanalyzer/console/* (Api/ConsoleController.php).
 #}

<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/policyanalyzer.css') }}">
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/console.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/simulation.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/aiqueue.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/markdown.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/console.js') }}"></script>
<script>
    'use strict';

    $(document).ready(function () {
        PAConsole.init({strings: {
            readOnly: "{{ lang._('Read only') }}",
            aiOff: "{{ lang._('AI disabled') }}",
            aiOffHelp: "{{ lang._('AI assistance is disabled: you can still look at the data and at what would be sent. Enable it in Firewall: Policy Analyzer: Settings.') }}",
            anonymized: "{{ lang._('anonymized') }}",
            notAnonymized: "{{ lang._('NOT anonymized') }}",
            language: "{{ lang._('Answer language') }}",
            langAuto: "{{ lang._('Automatic (settings / GUI)') }}",
            langPt: "{{ lang._('Portuguese (Brazil)') }}",
            langEn: "{{ lang._('English') }}",
            emptyChat: "{{ lang._('Ask about this firewall in plain words. The question is routed to read-only data sources (filter log, rules and counters, aliases, quarantine, findings, exposure, host names, configuration changes, IDS alerts); only that evidence, anonymized, goes to the AI.') }}",
            placeholder: "{{ lang._('e.g. why can host 192.168.1.50 not reach example.com? / what changed since yesterday?') }}",
            send: "{{ lang._('Ask') }}",
            preview: "{{ lang._('Show what would be sent') }}",
            previewShort: "{{ lang._('Preview') }}",
            clear: "{{ lang._('Clear conversation') }}",
            clearShort: "{{ lang._('Clear') }}",
            suggestions: "{{ lang._('Suggestions') }}",
            thinking: "{{ lang._('Collecting the evidence and asking the AI...') }}",
            collecting: "{{ lang._('Collecting the evidence...') }}",
            showSent: "{{ lang._('Show what was sent') }}",
            sentTitle: "{{ lang._('What was sent to the AI') }}",
            wouldSendTitle: "{{ lang._('What would be sent to the AI') }}",
            copy: "{{ lang._('Copy') }}",
            copied: "{{ lang._('Copied') }}",
            sources: "{{ lang._('Sources') }}",
            incomplete: "{{ lang._('partial') }}",
            unavailable: "{{ lang._('no data') }}",
            trimmed: "{{ lang._('context trimmed to fit') }}",
            bytes: "{{ lang._('bytes') }}",
            placeholders: "{{ lang._('placeholders') }}",
            seconds: "{{ lang._('s') }}",
            disclaimer: "{{ lang._('AI generated, based only on the evidence collected for the question. It can be wrong: check the cited evidence. Proposals are text only; nothing is ever applied from this page.') }}",
            refusal: "{{ lang._('The model declined to answer') }}",
            error: "{{ lang._('Error') }}",
            close: "{{ lang._('Close') }}",
            explain: "{{ lang._('Explain') }}",
            explainTitleLog: "{{ lang._('Explain this log event') }}",
            explainTitleRule: "{{ lang._('Explain this rule') }}",
            explainTitleAlert: "{{ lang._('Explain this alert') }}",
            truncated: "{{ lang._('The answer was cut off at the maximum length.') }}",
            history: "{{ lang._('earlier questions sent') }}",
            refresh: "{{ lang._('Refresh') }}",
            loading: "{{ lang._('Loading...') }}",
            noRows: "{{ lang._('Nothing found for these filters.') }}",
            any: "{{ lang._('any') }}",
            time: "{{ lang._('Time') }}",
            iface: "{{ lang._('Interface') }}",
            action: "{{ lang._('Action') }}",
            dir: "{{ lang._('Dir') }}",
            proto: "{{ lang._('Proto') }}",
            src: "{{ lang._('Source') }}",
            dst: "{{ lang._('Destination') }}",
            rule: "{{ lang._('Rule') }}",
            position: "#",
            description: "{{ lang._('Description') }}",
            evaluations: "{{ lang._('Evaluations') }}",
            packets: "{{ lang._('Packets') }}",
            states: "{{ lang._('States') }}",
            findings: "{{ lang._('Findings') }}",
            disabled: "{{ lang._('disabled') }}",
            floating: "{{ lang._('Floating') }}",
            severity: "{{ lang._('Severity') }}",
            signature: "{{ lang._('Signature') }}",
            linesRead: "{{ lang._('lines read') }}",
            partialRead: "{{ lang._('only part of the log was read within the time budget') }}",
            countersSince: "{{ lang._('counters since') }}",
            noCounters: "{{ lang._('rule counters not available') }}",
            openRule: "{{ lang._('Open in Firewall: Rules') }}",
            noEve: "{{ lang._('Suricata is not writing alerts (eve.json) on this firewall.') }}",
            proposalNote: "{{ lang._('Any proposal above is text only: nothing was changed on this firewall.') }}",
            collectMs: "{{ lang._('evidence collected in') }}",
            carried: "{{ lang._('follow-up of the previous question') }}"
        }});
    });
</script>

<div id="pa_console">
    <div class="pa-c-head">
        <span class="pa-c-state" id="pa_c_state"><i class="fa fa-spinner fa-pulse"></i></span>
        <span class="pa-c-badge pa-c-ok" title="{{ lang._('The console only reads data and shows text.') }}">
            <i class="fa fa-lock"></i> {{ lang._('Read only') }}</span>
        <label class="sr-only" for="pa_c_lang">{{ lang._('Answer language') }}</label>
        <select id="pa_c_lang" title="{{ lang._('Answer language') }}">
            <option value="auto">{{ lang._('Language: automatic') }}</option>
            <option value="pt_BR">Português (Brasil)</option>
            <option value="en_US">English</option>
        </select>
    </div>

    <ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
        <li class="active"><a data-toggle="tab" href="#ask"><i class="fa fa-comments-o"></i> {{ lang._('Ask the firewall') }}</a></li>
        <li><a data-toggle="tab" href="#log"><i class="fa fa-list"></i> {{ lang._('Firewall log') }}</a></li>
        <li><a data-toggle="tab" href="#rules"><i class="fa fa-shield"></i> {{ lang._('Rules') }}</a></li>
        <li><a data-toggle="tab" href="#alerts"><i class="fa fa-bell"></i> {{ lang._('IDS alerts') }}</a></li>
    </ul>

    <div class="tab-content content-box">
        <div id="ask" class="tab-pane fade in active">
            <div style="padding: 10px">
                <div class="pa-c-chat" id="pa_c_chat" aria-live="polite"></div>
                <div class="pa-c-suggest" id="pa_c_suggest"></div>
                <form class="pa-c-input" id="pa_c_form" autocomplete="off">
                    <label class="sr-only" for="pa_c_question">{{ lang._('Question') }}</label>
                    <textarea id="pa_c_question" class="form-control" rows="2" maxlength="600"></textarea>
                    <div class="pa-c-actions">
                        <button class="btn btn-primary" type="submit" id="pa_c_send">
                            <i class="fa fa-paper-plane"></i> {{ lang._('Ask') }}</button>
                        <button class="btn btn-default" type="button" id="pa_c_preview"
                                title="{{ lang._('Show what would be sent') }}">
                            <i class="fa fa-eye"></i> {{ lang._('Preview') }}</button>
                        <button class="btn btn-default" type="button" id="pa_c_clear"
                                title="{{ lang._('Clear conversation') }}">
                            <i class="fa fa-eraser"></i> {{ lang._('Clear') }}</button>
                    </div>
                </form>
                <div class="pa-c-foot" id="pa_c_foot"></div>
            </div>
        </div>

        <div id="log" class="tab-pane fade">
            <div style="padding: 10px">
                <form class="pa-c-filters" id="pa_c_log_form" autocomplete="off">
                    <label>{{ lang._('Address') }}<input type="text" name="ip" placeholder="192.168.1.50 / 10.0.0.0/24"></label>
                    <label>{{ lang._('Port') }}<input type="text" name="port" class="pa-c-narrow" inputmode="numeric"></label>
                    <label>{{ lang._('Action') }}<select name="action" class="pa-c-narrow">
                        <option value="">{{ lang._('any') }}</option>
                        <option value="block">block</option>
                        <option value="pass">pass</option></select></label>
                    <label>{{ lang._('Interface') }}<select name="iface"><option value="">{{ lang._('any') }}</option></select></label>
                    <label>{{ lang._('Direction') }}<select name="dir" class="pa-c-narrow">
                        <option value="">{{ lang._('any') }}</option>
                        <option value="in">in</option>
                        <option value="out">out</option></select></label>
                    <label>{{ lang._('Events') }}<select name="limit" class="pa-c-narrow">
                        <option value="50">50</option><option value="100">100</option><option value="200">200</option></select></label>
                    <button class="btn btn-default" type="submit"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
                </form>
                <div class="pa-c-info" id="pa_c_log_info"></div>
                <div class="pa-c-scroll">
                    <table class="table table-condensed table-striped pa-c-table" id="pa_c_log_table">
                        <thead><tr>
                            <th style="width: 132px">{{ lang._('Time') }}</th><th style="width: 92px">{{ lang._('Interface') }}</th>
                            <th style="width: 58px">{{ lang._('Action') }}</th>
                            <th class="pa-c-hide-md" style="width: 38px">{{ lang._('Dir') }}</th>
                            <th class="pa-c-hide-md" style="width: 50px">{{ lang._('Proto') }}</th>
                            <th>{{ lang._('Source') }}</th><th>{{ lang._('Destination') }}</th><th>{{ lang._('Rule') }}</th>
                            <th style="width: 96px"></th>
                        </tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="rules" class="tab-pane fade">
            <div style="padding: 10px">
                <form class="pa-c-filters" id="pa_c_rules_form" autocomplete="off">
                    <label>{{ lang._('Search') }}<input type="text" name="search"></label>
                    <label>{{ lang._('Interface') }}<select name="iface"><option value="">{{ lang._('any') }}</option></select></label>
                    <label>{{ lang._('Action') }}<select name="action" class="pa-c-narrow">
                        <option value="">{{ lang._('any') }}</option>
                        <option value="pass">pass</option><option value="block">block</option>
                        <option value="reject">reject</option><option value="match">match</option></select></label>
                    <label class="pa-c-check"><input type="checkbox" name="unused" value="1"> {{ lang._('Unused only (0 packets)') }}</label>
                    <button class="btn btn-default" type="submit"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
                </form>
                <div class="pa-c-info" id="pa_c_rules_info"></div>
                <div class="pa-c-scroll">
                    <table class="table table-condensed table-striped pa-c-table" id="pa_c_rules_table">
                        <thead><tr>
                            <th style="width: 40px">#</th><th style="width: 92px">{{ lang._('Interface') }}</th>
                            <th style="width: 64px">{{ lang._('Action') }}</th><th>{{ lang._('Description') }}</th>
                            <th class="pa-c-num pa-c-hide-md" style="width: 92px">{{ lang._('Evaluations') }}</th>
                            <th class="pa-c-num" style="width: 80px">{{ lang._('Packets') }}</th>
                            <th class="pa-c-num pa-c-hide-md" style="width: 60px">{{ lang._('States') }}</th>
                            <th style="width: 120px">{{ lang._('Findings') }}</th><th style="width: 132px"></th>
                        </tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="alerts" class="tab-pane fade">
            <div style="padding: 10px">
                <form class="pa-c-filters" id="pa_c_alerts_form" autocomplete="off">
                    <label>{{ lang._('Severity') }}<select name="severity">
                        <option value="">{{ lang._('all') }}</option>
                        <option value="1">1 ({{ lang._('high') }})</option>
                        <option value="2">1-2</option>
                        <option value="3">1-3</option></select></label>
                    <label>{{ lang._('Address') }}<input type="text" name="ip"></label>
                    <label>{{ lang._('Days') }}<select name="days" class="pa-c-narrow">
                        <option value="1">1</option><option value="7" selected>7</option><option value="14">14</option></select></label>
                    <label>{{ lang._('Alerts') }}<select name="limit" class="pa-c-narrow">
                        <option value="50">50</option><option value="100">100</option><option value="200">200</option></select></label>
                    <button class="btn btn-default" type="submit"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
                </form>
                <div class="pa-c-info" id="pa_c_alerts_info"></div>
                <div class="pa-c-scroll">
                    <table class="table table-condensed table-striped pa-c-table" id="pa_c_alerts_table">
                        <thead><tr>
                            <th style="width: 132px">{{ lang._('Time') }}</th><th style="width: 46px">{{ lang._('Sev') }}</th>
                            <th>{{ lang._('Signature') }}</th><th style="width: 165px">{{ lang._('Source') }}</th>
                            <th style="width: 165px">{{ lang._('Destination') }}</th>
                            <th class="pa-c-hide-md" style="width: 74px">{{ lang._('Action') }}</th><th style="width: 96px"></th>
                        </tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
