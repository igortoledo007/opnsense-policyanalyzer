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
 # AI usage on the network (read only): DNS queries (Unbound) and TLS SNI (Suricata) to the AI services of the
 # catalogue (scripts/policyanalyzer/shadowai/data/ai-services.json + the optional local file), per host and
 # day. Logic in js/policyanalyzer/aiusage.js, styles in css/policyanalyzer/insights.css.
 # API: /api/policyanalyzer/shadowai/* (Api/ShadowaiController.php).
 #}

<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/policyanalyzer.css') }}">
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/console.css') }}">
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/insights.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/simulation.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/aiqueue.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/markdown.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/insights-common.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/aiusage.js') }}"></script>
<script>
    'use strict';
    $(document).ready(function () {
        PAAiUsage.init({strings: {
            window: "{{ lang._('Window') }}", days: "{{ lang._('days') }}", refresh: "{{ lang._('Refresh') }}",
            explain: "{{ lang._('Explain (AI)') }}", propose: "{{ lang._('Block proposal') }}",
            hosts: "{{ lang._('Hosts using AI') }}", services: "{{ lang._('Services') }}",
            unexpected: "{{ lang._('Unexpected hosts') }}", newItems: "{{ lang._('New (3 days)') }}",
            dns: "{{ lang._('DNS queries') }}", tls: "{{ lang._('TLS connections') }}",
            perDay: "{{ lang._('Per day (DNS queries + TLS connections)') }}",
            topServices: "{{ lang._('Services by use') }}", hostList: "{{ lang._('Hosts') }}",
            host: "{{ lang._('Host') }}", usage: "{{ lang._('AI services') }}", total: "{{ lang._('Total') }}",
            lastUse: "{{ lang._('Last use') }}", firstUse: "{{ lang._('First use') }}",
            actions: "{{ lang._('Actions') }}", details: "{{ lang._('Details') }}", known: "{{ lang._('expected') }}",
            isNew: "{{ lang._('new') }}", elevated: "{{ lang._('elevated risk') }}", other: "{{ lang._('Other') }}",
            firewall: "{{ lang._('this firewall') }}", close: "{{ lang._('Close') }}",
            loading: "{{ lang._('Reading DNS and TLS data...') }}",
            noData: "{{ lang._('No AI service seen in this window.') }}", sources: "{{ lang._('Sources') }}",
            incomplete: "{{ lang._('partial (time budget)') }}", catalog: "{{ lang._('Catalogue') }}",
            domains: "{{ lang._('Domains') }}", sni: "{{ lang._('TLS server names') }}",
            ja4: "{{ lang._('JA4 client fingerprints') }}", reason: "{{ lang._('Why expected') }}",
            scope: "{{ lang._('Apply to') }}", scopeAll: "{{ lang._('every client') }}",
            scopeHost: "{{ lang._('this host') }}", scopeNet: "{{ lang._('this network (CIDR)') }}",
            method: "{{ lang._('Method') }}", methodDns: "{{ lang._('DNS blocklist (Unbound, recommended)') }}",
            methodAlias: "{{ lang._('Firewall alias + block rule') }}", simulate: "{{ lang._('Simulate') }}", showPlan: "{{ lang._('Show plan') }}",
            replay: "{{ lang._('Replay over the window') }}", wouldBlock: "{{ lang._('would have been blocked') }}",
            affected: "{{ lang._('Hosts affected') }}", conflicts: "{{ lang._('Expected usage that would break') }}",
            openPage: "{{ lang._('Open page') }}",
            proposalOnly: "{{ lang._('Proposal only: nothing is applied from here.') }}",
            asking: "{{ lang._('Asking the AI...') }}", error: "{{ lang._('Error') }}",
            selectService: "{{ lang._('Select at least one service.') }}",
            anonymized: "{{ lang._('anonymized') }}", notAnonymized: "{{ lang._('not anonymized') }}",
            cached: "{{ lang._('cached') }}",
            aiDisclaimer: "{{ lang._('AI generated text: verify it before acting on it.') }}",
            countsNote: "{{ lang._('Counts are DNS queries and TLS connections, not data volume; the content is never seen.') }}",
            unattributed: "{{ lang._('queries without a client address') }}"
        }});
    });
</script>

<div class="content-box pa-ins-root" style="padding: 8px 12px;">
    <div id="pa_aiusage"></div>
</div>
