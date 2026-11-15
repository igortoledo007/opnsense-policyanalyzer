#!/usr/local/bin/python3

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

    Minimal rule from the observed traffic — configd: actions_pa_minrule.conf. Read only.

        cli.py candidates                  pass rules worth narrowing (any destination/port/protocol, any source
                                           on a WAN, or a permissive / wan_exposed finding)
        cli.py analyze <uuid> [days]       observed traffic + proposal + coverage (default 7 days, 1-30)
        cli.py explain <uuid> [days] [language] [send|preview]
                                           AI text about the risk of the rule and of the proposal

    The last analysis per rule is kept in /var/db/policyanalyzer/minrule.json (10 rules) so that explain
    reuses it instead of scanning the logs again.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minrule import analyze as engine  # noqa: E402
from posture.common import (UUID_RE, Paths, ai_explain, emit, load_json, now, valid_language,  # noqa: E402
                            write_json)

CACHE = 'minrule.json'
KEEP = 10
MAX_AGE = 1800

EXPLAIN = """You explain a "minimal rule" proposal for one firewall pass rule. The firewall measured the traffic the
rule really matched in a time window and derived the narrowest rule that still covers it.
- Say in one or two sentences why the current rule is risky (what it allows beyond the observed traffic).
- Explain the proposal (the changes and aliases) and its coverage; say what would be blocked, including
  anything not seen in the window (rare jobs, updates), and how confident the measurement is (confidence,
  unit: connections from the filter log are exact, flows from NetFlow are approximate).
- Recommend how to roll it out safely: create the aliases, edit the rule, watch the live log, keep the old
  values to revert. Never say that it was applied.
- 150 to 250 words. Markdown allowed: short paragraphs, bullets, **bold**; no tables."""


def _store(paths, result):
    data = load_json(paths.db(CACHE))
    data = data if isinstance(data, dict) and isinstance(data.get('rules'), dict) else {'rules': {}}
    key = '%s:%s' % (result['rule']['uuid'], result['window_days'])
    result['generated_at'] = now()
    data['rules'][key] = result
    if len(data['rules']) > KEEP:
        for old in sorted(data['rules'], key=lambda k: data['rules'][k].get('generated_at', 0))[:-KEEP]:
            del data['rules'][old]
    try:
        write_json(paths.db(CACHE), data)
    except OSError:
        pass


def cached(paths, uuid, days):
    data = load_json(paths.db(CACHE)) or {}
    item = (data.get('rules') or {}).get('%s:%s' % (uuid, days))
    if isinstance(item, dict) and now() - item.get('generated_at', 0) < MAX_AGE:
        return item
    return None


def ai_view(result):
    proposal = result.get('proposal') or {}
    return {
        'rule': {'summary': result['rule']['summary'], 'description': result['rule']['description'],
                 'logs': result['rule']['log']},
        'window_days': result['window_days'], 'confidence': result.get('confidence'),
        'observed': {k: v for k, v in (result.get('observed') or {}).items()
                     if k in ('total', 'unit', 'days_with_data', 'protocols', 'destinations', 'sources', 'ports',
                              'top_ports')},
        'proposal': {'changes': proposal.get('changes'), 'aliases': [{'name': a['name'], 'type': a['type'],
                                                                      'entries': len(a['content'])}
                                                                     for a in proposal.get('aliases') or []],
                     'extra_rules': proposal.get('extra_rules')},
        'coverage': result.get('coverage'),
        'would_block_examples': (result.get('would_block') or [])[:8],
        'warnings': (result.get('plan') or {}).get('warnings'),
    }


def _days(args, idx):
    if len(args) > idx and args[idx].isdigit() and 1 <= int(args[idx]) <= 30:
        return int(args[idx])
    return 7


def main(argv, paths=None, assistant=None):
    paths = paths or Paths()
    cmd = argv[0] if argv else ''
    args = argv[1:]
    if cmd == 'candidates':
        return engine.candidates(paths)
    if cmd in ('analyze', 'explain'):
        uuid = args[0] if args else ''
        if not (UUID_RE.match(uuid) or re.match(r'^legacy-[0-9]{1,5}$', uuid)):
            return {'status': 'error', 'message': 'invalid rule id'}
        days = _days(args, 1)
        if cmd == 'analyze':
            result = engine.analyze(paths, uuid, days)
            if result.get('status') == 'ok':
                _store(paths, result)
            return result
        result = cached(paths, uuid, days) or engine.analyze(paths, uuid, days)
        if result.get('status') != 'ok':
            return result
        language = valid_language(args[2]) if len(args) > 2 else None
        mode = args[3] if len(args) > 3 and args[3] in ('send', 'preview') else 'send'
        answer = ai_explain(paths, 'minrule-ai.json', 'minrule_explain', EXPLAIN,
                            'Explain the risk of this rule and the minimal rule proposal.', ai_view(result),
                            language, mode, subject='minrule:%s' % uuid, assistant=assistant)
        answer['uuid'] = uuid
        return answer
    return {'status': 'error', 'message': 'unknown command'}


if __name__ == '__main__':
    try:
        emit(main(sys.argv[1:]))
    except Exception as exc:  # noqa: BLE001 - configd expects JSON
        emit({'status': 'error', 'message': '%s: %s' % (exc.__class__.__name__, exc)})
