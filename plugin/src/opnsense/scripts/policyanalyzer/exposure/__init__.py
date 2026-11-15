"""
    Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    Exposure & vulnerabilities: read-only inventory of what runs on the firewall, whether it is
    reachable from the internet (using the rule engine), which known vulnerabilities affect it and
    findings in the Policy Analyzer contract format.

    Modules:
      common      command runner (injectable), paths, small helpers
      services    process/port -> human service map, attack classes per service
      inventory   packages, versions, listening sockets, interfaces, local addresses
      reach       internet reachability per listening service (engine/ rules on WAN interfaces)
      feeds       configurable registry of online sources (KEV, EPSS, NVD, OSV, OPNsense advisories) + cache
      cvss        CVSS v3.x base score from a vector (OSV only gives vectors)
      vulns       pkg audit (VuXML) + optional enrichment, merged and deduplicated per CVE with provenance
      suricata    local Suricata rules that reference a CVE (sid, enabled)
      report      findings, summary (posture) and exposure.json
      adapter     STATUS_PROBES for manage.py (inventory, exposure, vulns, exposure_report) + CLI

    Nothing here changes the firewall. The network is used only when the caller passes "online".
"""

EXPOSURE_VERSION = 1
