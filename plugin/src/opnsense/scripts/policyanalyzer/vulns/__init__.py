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

    Vulnerability prioritisation (read only on the firewall): the CVEs of the exposure inventory
    (exposure.json) ranked P1..P4 with CISA KEV and FIRST EPSS from a local cache, the review queue
    ("Under review") and AI explanations. See CONTRACT.md ("Vulnerability prioritisation").

    Modules:
      common      paths, thresholds, JSON helpers
      intel       KEV / EPSS cache (download only through the change action vulns_intel_update)
      prioritize  P1..P4 with explainable factors, summary for the Max Cyber
      review      review queue and the owner's decisions
      explain     Explain CVE and the mapping suggestion (AI, text only)
      actions     change actions vulns_intel_update, vulns_review_decide
      cli         configd entry point (actions_pa_vulns.conf)
"""

try:                                        # register the change actions when the plugin dispatcher exists
    from ai import changes as _changes      # noqa: F401
    from . import actions as _actions       # noqa: F401
except ImportError:                         # pragma: no cover
    pass
