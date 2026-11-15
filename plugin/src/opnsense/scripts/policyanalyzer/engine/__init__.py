"""
    Copyright (c) 2026 Igor Toledo
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

    Policy Analyzer engine: deterministic, read-only analysis of the OPNsense
    firewall policy (MVC rules in //OPNsense/Firewall/Filter and legacy
    <filter><rule> entries).

    Modules:
      ipset       interval sets used for addresses and ports
      config      config.xml parser (interfaces, groups, VIPs, aliases, rules)
      resolve     alias / address / port resolution with lower and upper bounds
      rules       rule normalization into a match space + containment tests
      stats       pf rule counters (configd "filter rule stats")
      detectors   the individual detectors
      report      finding construction and JSON output
"""

ENGINE_VERSION = 1


def analyze(config_path, stats=None, stats_meta=None):
    """ run the full analysis and return the result dictionary (contract version 1)
        :param config_path: path to config.xml
        :param stats: dict label -> counters (rule_stats.py format) or None when unavailable
        :param stats_meta: dict with extra information about the counters (since, keepcounters, source)
    """
    from .report import build_report
    return build_report(config_path, stats, stats_meta or {})
