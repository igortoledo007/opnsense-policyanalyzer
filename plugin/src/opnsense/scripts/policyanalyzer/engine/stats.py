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

    pf rule counters, read through the same source as the GUI (FilterController::searchRuleAction uses
    configd "filter rule stats", i.e. /usr/local/opnsense/scripts/filter/rule_stats.py, which parses
    "pfctl -sr -v" and aggregates the counters per rule label). MVC rules are labelled with their uuid, legacy
    rules with an md5 hash calculated by PHP (Util::calcRuleHash), which this engine does not reproduce.

    Counters restart when the ruleset is reloaded (every filter reload writes /tmp/rules.debug), unless
    "set keepcounters" is enabled: up to 26.7 System: Settings: Advanced (<system><keepcounters/>), from 27.1
    Firewall: Settings (//OPNsense/Firewall/Filter/settings/filter/keep_counters). See config.py.
"""

import datetime
import json
import os
import re
import subprocess

RULE_STATS_SCRIPT = '/usr/local/opnsense/scripts/filter/rule_stats.py'
CONFIGCTL = '/usr/local/sbin/configctl'
RULES_DEBUG = '/tmp/rules.debug'


def _parse(text):
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError('unexpected stats format')
    result = {}
    for label, counters in data.items():
        if isinstance(counters, dict):
            result[label] = counters
    return result


def _ruleset_loaded_at():
    try:
        mtime = os.stat(RULES_DEBUG).st_mtime
    except OSError:
        return None
    return datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc).replace(microsecond=0).isoformat()


def _boot_time():
    try:
        proc = subprocess.run(['/sbin/sysctl', '-n', 'kern.boottime'], capture_output=True, text=True, timeout=10)
        match = re.search(r'sec\s*=\s*(\d+)', proc.stdout)
    except (OSError, subprocess.SubprocessError):
        return None
    if not match:
        return None
    return datetime.datetime.fromtimestamp(int(match.group(1)), datetime.timezone.utc).isoformat()


def load_stats(path=None, timeout=60):
    """ :return: (stats dict or None, meta dict) """
    meta = {'source': None, 'ruleset_loaded': None, 'boot_time': None, 'error': None}
    if path:
        try:
            with open(path, 'r') as handle:
                stats = _parse(handle.read())
            meta['source'] = 'file'
            return stats, meta
        except (OSError, ValueError) as exc:
            meta['error'] = 'unable to read stats file: %s' % exc.__class__.__name__
            return None, meta
    commands = []
    if os.geteuid() == 0 and os.path.isfile(RULE_STATS_SCRIPT):
        commands.append(([RULE_STATS_SCRIPT], 'rule_stats.py'))
    if os.path.isfile(CONFIGCTL):
        commands.append(([CONFIGCTL, 'filter', 'rule', 'stats'], 'configctl filter rule stats'))
    for cmd, label in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if proc.returncode != 0 or not proc.stdout.strip():
                continue
            stats = _parse(proc.stdout)
            if not stats:
                continue
            meta['source'] = label
            meta['ruleset_loaded'] = _ruleset_loaded_at()
            meta['boot_time'] = _boot_time()
            return stats, meta
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
    meta['error'] = 'pf rule counters not available'
    return None, meta
