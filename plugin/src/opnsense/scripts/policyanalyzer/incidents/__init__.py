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

    Incident triage (Policy Analyzer: Incidents): a light XDR / SOAR style correlation of the Suricata alerts,
    the filter log (blocks and passes), the quarantine offenses (read only) and the blocked DNS queries of
    Unbound into cases per entity (external address, internal host, port) and time window, with an explainable
    score, a timeline of summarized evidence, states (new, investigating, resolved, false positive), notes, and
    AI summaries / daily digests that only summarize, classify and recommend (never apply).

    Modules:
      common    names, rules and weights, settings, Context (paths), helpers
      store     SQLite /var/db/policyanalyzer/incidents.db (cases kept forever, observations 48 h)
      collect   readers: filter log and eve.json (quarantine/sources.py), quarantine.db read only, Unbound DuckDB
      rules     the correlation rules
      engine    the 5 minute run (cron "pa_incidents run"), case merging and score, read only views
      triage    AI: summarize a case (suggested actions from a closed candidate list), daily digest
      actions   change actions registered in ai/changes.py: install_incidents, remove_incidents,
                incident_state, incident_note
      cli       entry point of the configd actions (service/conf/actions.d/actions_pa_incidents.conf)
      model.php the cron job, through the core cron model (System: Settings: Cron)
"""

try:                                        # register the change actions when the plugin dispatcher exists
    from ai import changes as _changes      # noqa: F401
    from . import actions as _actions       # noqa: F401
except ImportError:                         # pragma: no cover - standalone (tests import the modules)
    pass
