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

    Automatic quarantine of external offenders (Max Cyber IA): block in quick on the WAN interfaces for
    sources in the pf table of the External alias pa_quarantine, with an escalating ladder
    (30 min, 2 h, 2 days, 10 days, 30 days), scenarios (base, scan, bait, suricata), guards and a ledger
    kept forever in SQLite.  See CONTRACT.md ("Automatic quarantine").

    Modules:
      common    names, ladder, settings, runner, context, target parsing, interval set
      store     SQLite ledger (entries, offenses, events, yearly, ...)
      sources   filter log and Suricata EVE readers with position markers
      fwconfig  read only facts of config.xml (WAN, rules, aliases, cron, guard sources)
      guards    what is never quarantined
      lookup    country / ASN from the core's local GeoIP and ASN data
      pf        the pa_quarantine pf table
      engine    the run, the sync and the read only views
      actions   change actions (plan / apply / revert) registered in ai/changes.py: entries, pause, settings
      steps     the installation as steps of the assistant (qsetup_*), install_quarantine, remove_quarantine
      wizard    read only state of every step of the assistant and the preview of the scenarios
      cli       "manage.py quarantine <command>"
      model.php the core models (aliases, rule, cron)
"""

try:                                        # register the change actions when the plugin dispatcher exists
    from ai import changes as _changes      # noqa: F401
    from . import actions as _actions       # noqa: F401
    from . import steps as _steps           # noqa: F401
except ImportError:                         # pragma: no cover - standalone (tests import the modules)
    pass
