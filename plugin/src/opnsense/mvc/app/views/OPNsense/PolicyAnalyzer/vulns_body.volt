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
 # Vulnerabilities (body): used by vulns.volt (page /ui/policyanalyzer/vulns) and, once index.volt includes it, as
 # a tab of the Policy Analyzer page (partial OPNsense/PolicyAnalyzer/vulns_body). JS: vulns.js.
 # The strings block below is generated from PAVulns.DEFAULTS and the PAMod defaults (same keys, translated).
 #}
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/modules.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/modules.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/vulns.js') }}"></script>
<script>
    'use strict';
    $(document).ready(function () {
        PAMod.setStrings({
            loading: "{{ lang._('Loading...') }}",
            error: "{{ lang._('Error') }}",
            none: "{{ lang._('Nothing to show.') }}",
            close: "{{ lang._('Close') }}",
            preview: "{{ lang._('Show what is sent') }}",
            ask: "{{ lang._('Ask the AI') }}",
            asking: "{{ lang._('Asking the AI... (it may take a while)') }}",
            aiOff: "{{ lang._('The AI is disabled in the Policy Analyzer settings.') }}",
            aiNote: "{{ lang._('The AI only explains and suggests: nothing is changed. Apply any change yourself, with its simulation.') }}",
            payloadTitle: "{{ lang._('Exactly what would be sent (anonymised when the option is on)') }}",
            model: "{{ lang._('Model') }}",
            cached: "{{ lang._('Stored answer from') }}",
            never: "{{ lang._('never') }}"
        });
        PAVulns.setStrings({
            title: "{{ lang._('Vulnerabilities') }}",
            subtitle: "{{ lang._('CVEs of the inventory ranked by exposure and real exploitation (KEV, EPSS). Read only.') }}",
            refresh: "{{ lang._('Refresh') }}",
            updateIntel: "{{ lang._('Update KEV/EPSS') }}",
            updateIntelTitle: "{{ lang._('Update CISA KEV and FIRST EPSS') }}",
            openExposure: "{{ lang._('Exposure report') }}",
            kpiTotal: "{{ lang._('CVEs') }}",
            kpiKev: "{{ lang._('In KEV') }}",
            kpiReview: "{{ lang._('Under review') }}",
            p1: "{{ lang._('P1 critical') }}",
            p2: "{{ lang._('P2 high') }}",
            p3: "{{ lang._('P3 medium') }}",
            p4: "{{ lang._('P4 low') }}",
            tabList: "{{ lang._('Prioritised') }}",
            tabReview: "{{ lang._('Under review') }}",
            tabRules: "{{ lang._('How the priority works') }}",
            colPrio: "{{ lang._('Priority') }}",
            colCve: "{{ lang._('CVE') }}",
            colPkg: "{{ lang._('Package') }}",
            colExposure: "{{ lang._('Exposure') }}",
            colKev: "{{ lang._('KEV') }}",
            colEpss: "{{ lang._('EPSS') }}",
            colCvss: "{{ lang._('CVSS') }}",
            colWhy: "{{ lang._('Why') }}",
            colActions: "{{ lang._('Actions') }}",
            colKind: "{{ lang._('Kind') }}",
            colSubject: "{{ lang._('Component') }}",
            colReason: "{{ lang._('Why it is here') }}",
            colCandidates: "{{ lang._('Candidates') }}",
            colAi: "{{ lang._('AI suggestion') }}",
            colDecision: "{{ lang._('Decision') }}",
            details: "{{ lang._('Details') }}",
            explain: "{{ lang._('Explain') }}",
            explainTitle: "{{ lang._('Explain %s') }}",
            suggest: "{{ lang._('AI suggestion') }}",
            suggestTitle: "{{ lang._('Mapping suggestion for %s') }}",
            decide: "{{ lang._('Decide') }}",
            decideTitle: "{{ lang._('Decision on %s') }}",
            internet: "{{ lang._('internet') }}",
            internet_maybe: "{{ lang._('internet (maybe)') }}",
            lan: "{{ lang._('internal only') }}",
            none: "{{ lang._('no listener') }}",
            kevNone: "{{ lang._('no KEV cache: the KEV signal is missing') }}",
            kevStale: "{{ lang._('the KEV cache is %s days old') }}",
            kevAt: "{{ lang._('KEV collected %s (%s entries, %s)') }}",
            epssAt: "{{ lang._('EPSS cached for %s of %s CVEs') }}",
            noNetwork: "{{ lang._('No network is used unless you click Update (simulation first).') }}",
            exposureAge: "{{ lang._('Exposure report from %s') }}",
            noReport: "{{ lang._('No exposure report yet: run it in the Exposure tab of the Policy Analyzer.') }}",
            factors: "{{ lang._('Factors') }}",
            services: "{{ lang._('Services') }}",
            fixed: "{{ lang._('Fixed in') }}",
            refs: "{{ lang._('References') }}",
            suricata: "{{ lang._('Suricata rules') }}",
            mapped: "{{ lang._('mapped by you') }}",
            confirmed: "{{ lang._('confirmed finding') }}",
            kind_package_unmapped: "{{ lang._('package without service') }}",
            kind_dependency_link: "{{ lang._('dependency only') }}",
            kind_service_unknown: "{{ lang._('unknown service') }}",
            kind_binary_unowned: "{{ lang._('binary without package') }}",
            kind_advisory_unclear: "{{ lang._('advisory unclear') }}",
            kind_cve_unscored: "{{ lang._('CVE without score') }}",
            pending: "{{ lang._('pending') }}",
            decided: "{{ lang._('decided') }}",
            expired: "{{ lang._('decision expired') }}",
            decMap: "{{ lang._('It runs inside this service (priority follows its exposure)') }}",
            decNone: "{{ lang._('No network path (library only)') }}",
            decIgnore: "{{ lang._('Ignore for') }}",
            days: "{{ lang._('days') }}",
            decFinding: "{{ lang._('Confirm as a real finding') }}",
            decClear: "{{ lang._('Remove my decision (back to pending)') }}",
            comment: "{{ lang._('Comment (optional)') }}",
            simulate: "{{ lang._('Simulate') }}",
            aiSays: "{{ lang._('AI suggests') }}"
        });
        PAVulns.init();
    });
</script>

<div id="pa_vulns" class="pa-mod">
    <div class="pa-mod-head">
        <div>
            <h2><i class="fa fa-bug"></i> {{ lang._('Vulnerabilities') }}</h2>
            <div class="pa-mod-sub">{{ lang._('CVEs of the inventory ranked by exposure and real exploitation (KEV, EPSS). Read only.') }}</div>
        </div>
        <div class="pa-mod-actions">
            <a class="btn btn-default btn-sm" href="/ui/policyanalyzer/#exposure"><i class="fa fa-shield"></i> {{ lang._('Exposure report') }}</a>
            <button type="button" class="btn btn-default btn-sm" id="pav_refresh"><i class="fa fa-refresh"></i> {{ lang._('Refresh') }}</button>
        </div>
    </div>
    <div class="pa-mod-kpis" id="pav_kpis"></div>
    <div class="pa-mod-note" id="pav_intel"></div>
    <ul class="nav nav-tabs" role="tablist">
        <li class="active"><a data-toggle="tab" href="#pav_tab_list">{{ lang._('Prioritised') }}</a></li>
        <li><a data-toggle="tab" href="#pav_tab_review">{{ lang._('Under review') }} <span class="badge" id="pav_review_count">0</span></a></li>
        <li><a data-toggle="tab" href="#pav_tab_rules">{{ lang._('How the priority works') }}</a></li>
    </ul>
    <div class="tab-content">
        <div id="pav_tab_list" class="tab-pane fade in active"><div class="pa-scroll" id="pav_list"></div></div>
        <div id="pav_tab_review" class="tab-pane fade">
            <p class="pa-small">{{ lang._('Components the inventory can not map with confidence. The AI may suggest a mapping; only your decision (with simulation, recorded in the action history) changes the priority.') }}</p>
            <div class="pa-scroll" id="pav_review"></div>
        </div>
        <div id="pav_tab_rules" class="tab-pane fade">
            <table class="pa-tbl">
                <colgroup><col style="width:120px"><col></colgroup>
                <thead><tr><th>{{ lang._('Priority') }}</th><th>{{ lang._('Condition') }}</th></tr></thead>
                <tbody>
                <tr><td data-label="{{ lang._('Priority') }}"><span class="pa-chip pa-p1">P1</span></td><td data-label="{{ lang._('Condition') }}">{{ lang._('Reachable from the internet AND (in CISA KEV OR EPSS >= 0.5)') }}</td></tr>
                <tr><td data-label="{{ lang._('Priority') }}"><span class="pa-chip pa-p2">P2</span></td><td data-label="{{ lang._('Condition') }}">{{ lang._('Reachable from the internet AND CVSS >= 7, OR in KEV while not exposed') }}</td></tr>
                <tr><td data-label="{{ lang._('Priority') }}"><span class="pa-chip pa-p3">P3</span></td><td data-label="{{ lang._('Condition') }}">{{ lang._('Internal only (LAN/VPN) AND CVSS >= 7, OR EPSS >= 0.1, OR exposed without a high score') }}</td></tr>
                <tr><td data-label="{{ lang._('Priority') }}"><span class="pa-chip pa-p4">P4</span></td><td data-label="{{ lang._('Condition') }}">{{ lang._('Everything else, typically a library without a listening socket') }}</td></tr>
                </tbody>
            </table>
            <p class="pa-small" style="margin-top:8px">{{ lang._('"Maybe" reachable counts as reachable and is shown as such. Thresholds: /var/db/policyanalyzer/vulns-settings.json (epss_high, epss_medium, cvss_high). KEV and EPSS come from a local cache with its date; they are downloaded only with "Update KEV/EPSS", after the simulation, and EPSS only receives CVE ids.') }}</p>
        </div>
    </div>
</div>
