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
 # Firewall: Policy Analyzer: Vulnerabilities (/ui/policyanalyzer/vulns, VulnsController). Standalone page: the shared simulation
 # dialog and styles of the plugin, then the body partial (also includable as a tab of index.volt).
 #}
<link rel="stylesheet" href="{{ cache_safe('/ui/css/policyanalyzer/policyanalyzer.css') }}">
<script src="{{ cache_safe('/ui/js/policyanalyzer/simulation.js') }}"></script>
<script src="{{ cache_safe('/ui/js/policyanalyzer/aiqueue.js') }}"></script>
<div class="content-box">
{{ partial('OPNsense/PolicyAnalyzer/vulns_body') }}
</div>
