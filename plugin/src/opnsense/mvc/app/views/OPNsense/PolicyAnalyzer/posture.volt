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
 # Posture (read only): health check of the configuration and the system, score with history, AI "Explain
 # check" and "Executive summary". Logic in js/policyanalyzer/posture.js (+ insights-common.js, minrule.js),
 # styles in css/policyanalyzer/insights.css. API: /api/policyanalyzer/posture/* (Api/PostureController.php).
 #}

<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/policyanalyzer.css') }}">
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/console.css') }}">
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/insights.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/simulation.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/aiqueue.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/markdown.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/insights-common.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/posture.js') }}"></script>
{{ partial('OPNsense/PolicyAnalyzer/minrule') }}
<script>
    'use strict';
    $(document).ready(function () {
        PAPosture.init({aiStatusUrl: '/api/policyanalyzer/ai/status', strings: {
            run: "{{ lang._('Run now') }}",
            running: "{{ lang._('Running the checks...') }}",
            summaryAi: "{{ lang._('Executive summary (AI)') }}",
            explain: "{{ lang._('Explain (AI)') }}",
            preview: "{{ lang._('Show data sent') }}",
            details: "{{ lang._('Details') }}",
            fix: "{{ lang._('Fix (proposal)') }}",
            openPage: "{{ lang._('Open page') }}",
            simulate: "{{ lang._('Simulate') }}",
            minrule: "{{ lang._('Minimal rule') }}",
            close: "{{ lang._('Close') }}",
            evidence: "{{ lang._('Evidence') }}",
            recommendation: "{{ lang._('Recommendation') }}",
            references: "{{ lang._('References') }}",
            all: "{{ lang._('All') }}",
            search: "{{ lang._('Search checks') }}",
            pass: "{{ lang._('Pass') }}", warn: "{{ lang._('Warn') }}", fail: "{{ lang._('Fail') }}",
            na: "{{ lang._('N/A') }}",
            high: "{{ lang._('high') }}", medium: "{{ lang._('medium') }}", low: "{{ lang._('low') }}",
            info: "{{ lang._('info') }}",
            score: "{{ lang._('Posture score') }}",
            generated: "{{ lang._('Generated') }}",
            previous: "{{ lang._('since the previous run') }}",
            trend: "{{ lang._('Score trend (90 days)') }}",
            newFailures: "{{ lang._('New problem') }}",
            fixed: "{{ lang._('Fixed') }}",
            noChecks: "{{ lang._('No check matches the filter.') }}",
            asking: "{{ lang._('Asking the AI...') }}",
            error: "{{ lang._('Error') }}",
            aiDisabled: "{{ lang._('AI assistance is disabled in the settings.') }}",
            anonymized: "{{ lang._('anonymized') }}", notAnonymized: "{{ lang._('not anonymized') }}",
            cached: "{{ lang._('cached') }}",
            aiDisclaimer: "{{ lang._('AI generated text: verify it before acting on it.') }}",
            fixNote: "{{ lang._('Proposal only: nothing is changed from here. Change it on the page, then run the checks again.') }}",
            category: "{{ lang._('Category') }}", check: "{{ lang._('Check') }}", result: "{{ lang._('Result') }}",
            severity: "{{ lang._('Severity') }}", actions: "{{ lang._('Actions') }}",
            noHistory: "{{ lang._('run the checks on other days to see the trend') }}",
            policyReport: "{{ lang._('rule analysis from') }}",
            empty: "{{ lang._('No posture report yet.') }}"
        }});
        $('#pa_post_minrule').click(function () { PAMinRule.pick(); });
    });
</script>

<div class="content-box pa-ins-root" style="padding: 8px 12px;">
    <div class="pull-right"><button type="button" class="btn btn-default btn-sm" id="pa_post_minrule">
        <i class="fa fa-compress"></i> {{ lang._('Minimal rule') }}</button></div>
    <div id="pa_posture"></div>
    <p class="small text-muted">{{ lang._('Deterministic checks inspired by the CIS Controls v8 and NIST SP 800-41/800-53 (there is no official CIS benchmark for OPNsense). Read only: every fix is a proposal for you to apply in the GUI.') }}</p>
</div>
