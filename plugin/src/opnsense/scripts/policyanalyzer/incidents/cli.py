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

    Entry point of the configd actions of the incident triage (actions_pa_incidents.conf):

        cli.py run                                  the 5 minute correlation (cron "pa_incidents run")
        cli.py status | summary                     state and counters; summary: light, for the Max Cyber widget
        cli.py list <filters> <sort> <page:rows>    filters "state=open|new|investigating|resolved|false_positive+
                                                    severity=high+rule=campaign+days=7+search=203.0.113" ("-": none),
                                                    sort "last_activity|score|created|id:asc|desc" ("-": newest)
        cli.py case <id>                            one case: entities, rules, evidence, notes, history, summary
        cli.py summarize <id> <language> <send|preview>   AI summary of a case (preview: payload only)
        cli.py digest <YYYY-MM-DD|today> <language> <cached|generate>   daily digest
        cli.py plan|apply <action> [args...]        the change actions of this package (install_incidents,
                                                    remove_incidents, incident_state, incident_note), journaled
                                                    by ai/changes.py like every other change of the plugin

    Output is always one JSON document.
"""

import json
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ''):
    # run as a script: import the packages from scripts/policyanalyzer, not the modules next to us
    sys.path = [p for p in sys.path if os.path.abspath(p or '.') != _HERE]
    sys.path.insert(0, os.path.dirname(_HERE))

from ai import changes  # noqa: E402
from incidents import actions as _actions  # noqa: E402,F401  (registers the change actions)
from incidents import common, engine as engine_mod, triage  # noqa: E402

ACTIONS = ('install_incidents', 'remove_incidents', 'incident_state', 'incident_note', 'incidents_tidy')
FILTER_KEYS = ('state', 'severity', 'rule', 'days', 'search')
SEARCH_RE = re.compile(r'^[0-9A-Za-z:./_-]{1,64}$')
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')
TOKEN_RE = re.compile(r'^[A-Za-z0-9_.:/=+-]{0,255}$')
ENGINE_FACTORY = engine_mod.Engine
USAGE = 'usage: cli.py run|status|summary|list|case|summarize|digest|plan|apply ...'


def emit(data):
    sys.stdout.write(json.dumps(data, ensure_ascii=False) + '\n')


def parse_filters(token, now):
    filters = {}
    if not token or token == '-':
        return filters
    for part in token.split('+'):
        key, _sep, value = part.partition('=')
        if key not in FILTER_KEYS or not value:
            raise ValueError('invalid filter: %s' % part)
        if key == 'state':
            if value not in common.STATES + ('open',):
                raise ValueError('invalid state')
            filters['state'] = value
        elif key == 'severity':
            if value not in common.SEVERITIES:
                raise ValueError('invalid severity')
            filters['severity'] = value
        elif key == 'rule':
            if value not in common.RULES:
                raise ValueError('invalid rule')
            filters['rule'] = value
        elif key == 'days':
            if not value.isdigit() or not 0 < int(value) <= 3650:
                raise ValueError('invalid days')
            filters['since'] = int(now) - int(value) * 86400
        else:
            if not SEARCH_RE.match(value):
                raise ValueError('invalid search')
            filters['search'] = value
    return filters


def parse_sort(token):
    if not token or token == '-':
        return ('last_activity', 'desc')
    field, _sep, direction = token.partition(':')
    if field not in ('last_activity', 'score', 'created', 'id', 'state', 'first_seen'):
        raise ValueError('invalid sort')
    return (field, 'asc' if direction == 'asc' else 'desc')


def parse_page(token, default_rows=25):
    match = re.match(r'^(\d{1,6}):(\d{1,3})$', token or '')
    if not match:
        return 1, default_rows
    return int(match.group(1)) or 1, max(1, min(int(match.group(2)), 200))


def language(token):
    return token if token and LANG_RE.match(token) else 'en_US'


def main(argv):
    args = [a for a in argv[1:] if a != '']
    if not args:
        emit({'status': 'error', 'message': USAGE})
        return 1
    cmd, rest = args[0], args[1:]
    if any(not TOKEN_RE.match(a) for a in rest):
        emit({'status': 'error', 'message': 'invalid argument'})
        return 1
    eng = ENGINE_FACTORY()
    try:
        if cmd == 'run':
            emit(eng.run())
        elif cmd == 'status':
            emit(eng.status())
        elif cmd == 'summary':
            emit(eng.summary())
        elif cmd in ('list', 'case', 'summarize', 'digest') and not eng.installed():
            emit({'status': 'error', 'installed': False, 'message': 'the incident triage is not installed'})
        elif cmd == 'list':
            rest += ['-', '-', '-']
            page, rows = parse_page(rest[2])
            emit(eng.search(parse_filters(rest[0], eng.now()), parse_sort(rest[1]), page, rows))
        elif cmd == 'case' and rest:
            emit(eng.case_detail(common.valid_case_id(rest[0])))
        elif cmd == 'summarize' and rest:
            rest += ['', '', '']
            emit(triage.summarize(eng, common.valid_case_id(rest[0]), language(rest[1]), preview=rest[2] == 'preview'))
        elif cmd == 'digest':
            rest += ['', '', '']
            day = rest[0] if rest[0] and rest[0] != 'today' else time.strftime('%Y-%m-%d', time.localtime(eng.now()))
            common.local_day_bounds(day)
            emit(triage.digest(eng, day, language(rest[1]), mode='generate' if rest[2] == 'generate' else 'cached'))
        elif cmd in ('plan', 'apply') and rest and rest[0] in ACTIONS:
            emit(changes.run(cmd, rest[0], rest[1:]))
        else:
            emit({'status': 'error', 'message': USAGE})
            return 1
    except ValueError as exc:
        emit({'status': 'error', 'message': str(exc)})
    except OSError as exc:
        emit({'status': 'error', 'message': str(exc)})
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
