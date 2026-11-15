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

    Anomalies (lightweight NDR/UEBA of the LAN): deterministic, explainable detectors over data the core
    already keeps (NetFlow, Unbound DuckDB, Host discovery, Kea/dnsmasq leases, filter log, Suricata TLS
    events).  Findings and baselines in /var/db/policyanalyzer/anomalies.db; the AI only explains.

    Modules:
      common     names, parameters, context, helpers (entropy, MAD, Bowley skewness, factor)
      netcfg     internal networks, firewall addresses, local domains, DNS redirect (config.xml, read only)
      sources    readers with markers (flowd, DuckDB, hostwatch, leases, filter log, eve.json TLS, Insight)
      dnsfeat    domain features (registrable domain, bigram model, name score, CDN list)
      detectors  the detectors (pure functions)
      store      SQLite store
      engine     the periodic run and the read only views
      actions    change actions (install/remove, expected, exceptions, resolve, settings)
      explain    Explain anomaly / Explain host (Assistant)
      cli        command line of the configd actions (actions_pa_anomalies.conf)
      model.php  the cron job through the core model
"""

try:                                        # register the change actions when the plugin dispatcher exists
    from ai import changes as _changes      # noqa: F401
    from . import actions as _actions       # noqa: F401
except ImportError:                         # pragma: no cover - standalone
    pass
