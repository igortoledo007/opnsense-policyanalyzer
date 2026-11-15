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
 # Minimal rule dialog (js/policyanalyzer/minrule.js, PAMinRule): strings only. Included by posture.volt and,
 # once integrated, by index.volt for the "Minimal rule" action of permissive / wan_exposed findings.
 # Needs insights-common.js, simulation.js (and markdown.js for the AI answer) loaded before it.
 #}
<script src="{{ cache_safe('/ui/js/policyanalyzer/minrule.js') }}"></script>
<script>
    'use strict';
    PAMinRule.setStrings({
        title: "{{ lang._('Minimal rule from the observed traffic') }}",
        pick: "{{ lang._('Choose a rule to narrow') }}",
        window: "{{ lang._('Window') }}",
        days: "{{ lang._('days') }}",
        analyzing: "{{ lang._('Reading the filter log / NetFlow of the rule...') }}",
        rule: "{{ lang._('Rule') }}",
        observed: "{{ lang._('Observed') }}",
        coverage: "{{ lang._('Coverage of the observed traffic') }}",
        changes: "{{ lang._('Proposed changes') }}",
        field: "{{ lang._('Field') }}",
        from: "{{ lang._('Now') }}",
        to: "{{ lang._('Proposed') }}",
        aliases: "{{ lang._('New aliases') }}",
        extra: "{{ lang._('Additional rules') }}",
        wouldBlock: "{{ lang._('Observed traffic the proposal would block') }}",
        nothingBlocked: "{{ lang._('Nothing observed would be blocked.') }}",
        warnings: "{{ lang._('Notes') }}",
        diff: "{{ lang._('Diff (for the rule editor)') }}",
        openRule: "{{ lang._('Open rule') }}",
        simulate: "{{ lang._('Simulate') }}",
        explain: "{{ lang._('Explain risk (AI)') }}",
        close: "{{ lang._('Close') }}",
        confidence: "{{ lang._('Confidence') }}",
        exact: "{{ lang._('filter log (exact)') }}",
        approx: "{{ lang._('NetFlow (approximate)') }}",
        noTraffic: "{{ lang._('No traffic attributed to this rule in the window.') }}",
        reasons: "{{ lang._('Why') }}",
        noCandidates: "{{ lang._('No permissive pass rule found.') }}",
        error: "{{ lang._('Error') }}",
        asking: "{{ lang._('Asking the AI...') }}",
        nothingToNarrow: "{{ lang._('The rule already matches only what was observed.') }}",
        high: "{{ lang._('high') }}", medium: "{{ lang._('medium') }}", low: "{{ lang._('low') }}",
        none: "{{ lang._('none') }}",
        proposalOnly: "{{ lang._('Proposal only: open the rule and change it yourself; nothing is applied from here.') }}",
        aiDisabled: "{{ lang._('AI assistance is disabled in the settings.') }}",
        anonymized: "{{ lang._('anonymized') }}", notAnonymized: "{{ lang._('not anonymized') }}",
        cached: "{{ lang._('cached') }}",
        aiDisclaimer: "{{ lang._('AI generated text: verify it before acting on it.') }}",
        logs: "{{ lang._('logs') }}", nolog: "{{ lang._('no log') }}"
    });
</script>
