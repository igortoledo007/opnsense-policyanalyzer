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
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/anomalies.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/simulation.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/aiqueue.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/anomalies.js') }}"></script>
<script>
    $(document).ready(function () {
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
            technical: "{{ lang._('Technical details') }}"
        });
        PAAnomalies.init({strings: {
            high: "{{ lang._('High') }}", medium: "{{ lang._('Medium') }}", low: "{{ lang._('Low') }}",
            info: "{{ lang._('Info') }}",
            open: "{{ lang._('open') }}", expected: "{{ lang._('expected') }}", resolved: "{{ lang._('resolved') }}",
            t_beaconing: "{{ lang._('Beaconing') }}", t_dga: "{{ lang._('DGA domains') }}",
            t_dns_tunnel: "{{ lang._('DNS tunnel') }}", t_volume: "{{ lang._('Outbound volume') }}",
            t_rare_destination: "{{ lang._('Rare destination') }}", t_new_device: "{{ lang._('New device') }}",
            t_internal_scan: "{{ lang._('Internal scan') }}", t_dns_bypass: "{{ lang._('DNS bypass') }}",
            t_new_domain: "{{ lang._('New domain') }}", t_tls: "{{ lang._('TLS') }}",
            notInstalled: "{{ lang._('The anomaly detection is not scheduled yet.') }}",
            install: "{{ lang._('Install (simulate first)') }}",
            installed: "{{ lang._('Scheduled every 15 minutes') }}",
            lastRun: "{{ lang._('last run') }}", never: "{{ lang._('never') }}", ago: "{{ lang._('ago') }}",
            runNow: "{{ lang._('Run now') }}", running: "{{ lang._('Running...') }}",
            noFindings: "{{ lang._('No findings match the filters.') }}",
            noData: "{{ lang._('No data yet: the first run learns the network, findings appear after it.') }}",
            selectOne: "{{ lang._('Select a finding to see its factors.') }}",
            factors: "{{ lang._('Factors') }}", factor: "{{ lang._('Factor') }}", value: "{{ lang._('Value') }}",
            threshold: "{{ lang._('Threshold') }}", counted: "{{ lang._('Counted') }}",
            evidence: "{{ lang._('Evidence') }}", parameters: "{{ lang._('Parameters') }}",
            occurrences: "{{ lang._('Occurrences') }}", firstSeen: "{{ lang._('First seen') }}",
            lastSeen: "{{ lang._('Last seen') }}", score: "{{ lang._('Score') }}", host: "{{ lang._('Host') }}",
            type: "{{ lang._('Type') }}", severity: "{{ lang._('Severity') }}", status: "{{ lang._('Status') }}",
            finding: "{{ lang._('Finding') }}", search: "{{ lang._('Search host, domain, port...') }}",
            all: "{{ lang._('All') }}", allTypes: "{{ lang._('All types') }}", allStatus: "{{ lang._('Any status') }}",
            days: "{{ lang._('days') }}", current: "{{ lang._('now') }}", baseline: "{{ lang._('baseline') }}",
            explain: "{{ lang._('Explain with AI') }}", explainHost: "{{ lang._('Explain host with AI') }}",
            preview: "{{ lang._('Show what would be sent') }}", asking: "{{ lang._('Asking the AI...') }}",
            aiDisabled: "{{ lang._('AI assistance is disabled: enable it in the Policy Analyzer settings.') }}",
            aiDisclaimer: "{{ lang._('Generated by AI from the factors above: it may be wrong. Nothing was changed.') }}",
            anonymized: "{{ lang._('anonymized') }}", notAnonymized: "{{ lang._('not anonymized') }}",
            suggested: "{{ lang._('Suggested actions') }}",
            suggestedNote: "{{ lang._('Nothing runs by itself: changes open a simulation first and are journaled.') }}",
            hostProfile: "{{ lang._('Host profile') }}", normal: "{{ lang._('Normal for this host') }}",
            now: "{{ lang._('Now') }}", expect: "{{ lang._('Mark as expected') }}",
            expectScope: "{{ lang._('What is expected') }}",
            scopeFinding: "{{ lang._('only this finding (same kind, host and key)') }}",
            scopeHost: "{{ lang._('every finding of this kind for this host') }}",
            scopeAll: "{{ lang._('everything from this host') }}",
            comment: "{{ lang._('Comment (why it is expected)') }}", simulate: "{{ lang._('Simulate') }}",
            resolve: "{{ lang._('Close finding') }}", back: "{{ lang._('Back') }}",
            exceptions: "{{ lang._('Exceptions') }}", noExceptions: "{{ lang._('No exceptions.') }}",
            remove: "{{ lang._('Remove') }}", settings: "{{ lang._('Parameters') }}",
            settingsNote: "{{ lang._('Changed values are applied through a simulation and journaled.') }}",
            sources: "{{ lang._('Sources') }}", cost: "{{ lang._('Cost of the last runs') }}",
            ok: "{{ lang._('ok') }}", missing: "{{ lang._('missing') }}", partial: "{{ lang._('partial') }}",
            device: "{{ lang._('Device') }}", vendor: "{{ lang._('Vendor') }}", mac: "{{ lang._('MAC') }}",
            outHour: "{{ lang._('outbound this hour') }}", outUsual: "{{ lang._('usual for this hour') }}",
            dnsHour: "{{ lang._('DNS queries per hour') }}", nxHour: "{{ lang._('NXDOMAIN per hour') }}",
            countries: "{{ lang._('Countries') }}", topDst: "{{ lang._('Top destinations (24 h)') }}",
            learned: "{{ lang._('learned') }}", domains: "{{ lang._('domains') }}",
            fingerprints: "{{ lang._('TLS fingerprints') }}", findings: "{{ lang._('Findings') }}",
            uninstall: "{{ lang._('Stop the schedule') }}", new24: "{{ lang._('new in 24 h') }}",
            error: "{{ lang._('Error') }}", close: "{{ lang._('Close') }}", more: "{{ lang._('More') }}",
            readOnly: "{{ lang._('Detectors are deterministic and read only; the AI only explains. Nothing is blocked automatically.') }}"
        }});
    });
</script>

<div class="content-box pa-an" id="pa_an_root">
    <div class="pa-an-head">
        <div class="pa-an-state" id="pa_an_state"><i class="fa fa-spinner fa-pulse"></i></div>
        <div class="pa-an-tools">
            <button class="btn btn-default btn-sm" id="pa_an_run" type="button"><i class="fa fa-play fa-fw"></i> {{ lang._('Run now') }}</button>
            <button class="btn btn-default btn-sm" id="pa_an_exceptions" type="button"><i class="fa fa-check-square-o fa-fw"></i> {{ lang._('Exceptions') }}</button>
            <button class="btn btn-default btn-sm" id="pa_an_settings" type="button"><i class="fa fa-sliders fa-fw"></i> {{ lang._('Parameters') }}</button>
            <a class="btn btn-default btn-sm" href="/ui/policyanalyzer/#history"><i class="fa fa-history fa-fw"></i> {{ lang._('Action history') }}</a>
        </div>
    </div>
    <div class="pa-an-cards" id="pa_an_cards">
        <button type="button" class="pa-an-card sev-high" data-severity="high"><b id="pa_an_c_high">-</b><span>{{ lang._('High') }}</span></button>
        <button type="button" class="pa-an-card sev-medium" data-severity="medium"><b id="pa_an_c_medium">-</b><span>{{ lang._('Medium') }}</span></button>
        <button type="button" class="pa-an-card sev-low" data-severity="low"><b id="pa_an_c_low">-</b><span>{{ lang._('Low') }}</span></button>
        <button type="button" class="pa-an-card sev-info" data-severity="info"><b id="pa_an_c_info">-</b><span>{{ lang._('Info') }}</span></button>
        <div class="pa-an-types" id="pa_an_types"></div>
    </div>
    <div class="pa-an-filters">
        <select id="pa_an_f_type" class="form-control input-sm"></select>
        <select id="pa_an_f_status" class="form-control input-sm">
            <option value="open">{{ lang._('open') }}</option>
            <option value="expected">{{ lang._('expected') }}</option>
            <option value="resolved">{{ lang._('resolved') }}</option>
            <option value="">{{ lang._('Any status') }}</option>
        </select>
        <select id="pa_an_f_days" class="form-control input-sm">
            <option value="1">24 h</option>
            <option value="7" selected>7 {{ lang._('days') }}</option>
            <option value="30">30 {{ lang._('days') }}</option>
            <option value="">{{ lang._('All') }}</option>
        </select>
        <input id="pa_an_f_search" class="form-control input-sm" type="search" placeholder="{{ lang._('Search host, domain, port...') }}">
        <span class="pa-an-host-filter" id="pa_an_f_host" style="display:none"></span>
    </div>
    <div class="pa-an-body">
        <div class="pa-an-list" id="pa_an_list"></div>
        <div class="pa-an-detail" id="pa_an_detail"></div>
    </div>
    <p class="pa-an-note text-muted"><small>{{ lang._('Detectors are deterministic and read only; the AI only explains. Nothing is blocked automatically.') }}</small></p>
</div>
