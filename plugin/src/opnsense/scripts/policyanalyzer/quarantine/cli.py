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

    "manage.py quarantine <command>" (configd actions quarantine_*):

        run                                 the 5 minute run (cron)
        sync                                expire + pf table = ledger (boot hook)
        index                               build the country/ASN index (background)
        status | summary | guards
        list <filters> <sort> <page:rows>   filters "state=active+reason=scan+country=BR+asn=13335+year=2026+
                                            origin=manual+level=3+search=203.0.113" ("-": none),
                                            sort "field:asc|desc" ("-": last offense, newest first)
        history <offenses|events|yearly> <ip|-> <YYYY|YYYYMMDD-YYYYMMDD|-> <page:rows>
        export <YYYY|YYYYMMDD-YYYYMMDD|-> <ip|->      CSV of the offenses
        entry <id|address>                  one entry with its whole history (every year)
        wizard                              state of every step of the quarantine assistant (detected now)
        preview <key=value:...|->           what the scenarios would decide with the logs of the last 5 min

    Changes (add, release, extend, permanent, never block, pause, resume, settings, install, remove) are
    change actions: "manage.py plan|apply <action> ..." (see actions.py).
"""

import json
import re
import sys

from . import common, engine as engine_mod, wizard

TOKEN_RE = re.compile(r'^[A-Za-z0-9_.:/=+-]{0,255}$')
SEARCH_RE = re.compile(r'^[0-9A-Za-z:./_-]{0,64}$')
FILTER_KEYS = ('state', 'reason', 'origin', 'country', 'asn', 'year', 'level', 'search')
ENGINE_FACTORY = engine_mod.Engine


def _page(token, default_rows=20):
    match = re.match(r'^(\d{1,6}):(-?\d{1,4})$', token or '')
    if not match:
        return 1, default_rows
    page, rows = int(match.group(1)) or 1, int(match.group(2))
    if rows != -1:
        rows = max(1, min(rows, 500))
    return page, rows


def parse_filters(token):
    filters = {}
    if not token or token == '-':
        return filters
    for part in token.split('+'):
        key, _sep, value = part.partition('=')
        if key not in FILTER_KEYS or not value:
            raise ValueError('invalid filter: %s' % part)
        if key == 'search':
            if not SEARCH_RE.match(value):
                raise ValueError('invalid search')
        elif key in ('asn', 'year', 'level'):
            if not value.isdigit():
                raise ValueError('invalid %s' % key)
        elif key == 'country':
            if not re.match(r'^[A-Z]{2}$', value):
                raise ValueError('invalid country')
        elif key == 'state' and value not in common.STATES + ('blocked',):
            raise ValueError('invalid state')
        elif key == 'reason' and value not in common.REASONS:
            raise ValueError('invalid reason')
        elif key == 'origin' and value not in ('auto', 'manual'):
            raise ValueError('invalid origin')
        filters[key] = value
    return filters


def parse_sort(token):
    if not token or token == '-':
        return None
    field, _sep, direction = token.partition(':')
    from .store import SORTABLE
    if field not in SORTABLE or direction not in ('asc', 'desc'):
        raise ValueError('invalid sort')
    return field, direction


def parse_address(token):
    if not token or token == '-':
        return None
    if not re.match(r'^[0-9A-Fa-f:./]{1,64}$|^AS\d{1,10}$', token):
        raise ValueError('invalid address')
    return token


def _engine_options(eng):
    return {'runtime_guards': eng.runtime_guards, 'resolver': eng.resolver}


def main(args, out=sys.stdout):
    args = [a for a in args if a != '']
    for arg in args:
        if not TOKEN_RE.match(arg):
            out.write(json.dumps({'status': 'error', 'message': 'invalid argument'}) + '\n')
            return 1
    cmd, rest = (args[0], args[1:]) if args else ('', [])
    eng = ENGINE_FACTORY()
    try:
        if cmd == 'run':
            result = eng.run()
        elif cmd == 'sync':
            result = eng.sync()
        elif cmd == 'index':
            result = eng.index()
        elif cmd == 'status':
            result = eng.status()
        elif cmd == 'summary':
            result = eng.summary()
        elif cmd == 'guards':
            result = eng.guards_report()
        elif cmd == 'list':
            rest += ['-', '-', '']
            page, rows = _page(rest[2])
            result = eng.search(parse_filters(rest[0]), parse_sort(rest[1]), page, rows)
        elif cmd == 'history':
            rest += ['offenses', '-', '-', '']
            kind = rest[0] if rest[0] in ('offenses', 'events', 'yearly') else 'offenses'
            page, rows = _page(rest[3], 50)
            result = eng.history(kind, parse_address(rest[1]), rest[2], page, rows)
        elif cmd == 'export':
            rest += ['-', '-']
            out.write(eng.export_csv(rest[0], parse_address(rest[1])))
            return 0
        elif cmd == 'entry':
            if not rest:
                raise ValueError('entry id or address required')
            result = eng.entry_detail(rest[0] if rest[0].isdigit() else parse_address(rest[0]))
        elif cmd == 'wizard':
            result = wizard.state(eng.ctx, engine_options=_engine_options(eng))
        elif cmd == 'preview':
            token = rest[0] if rest else '-'
            values = {} if token == '-' else wizard.parse_scenarios(token)
            result = wizard.preview(eng.ctx, values, engine_options=_engine_options(eng))
        else:
            result = {'status': 'error', 'message': 'usage: manage.py quarantine run|sync|index|status|summary|'
                                                    'guards|list|history|export|entry|wizard|preview ...'}
    except (ValueError, common.QuarantineError) as exc:
        result = {'status': 'error', 'message': str(exc)}
    out.write(json.dumps(result) + '\n')
    return 0
