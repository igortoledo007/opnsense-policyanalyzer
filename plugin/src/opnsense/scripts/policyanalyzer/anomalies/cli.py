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

    Anomaly detection command line (configd actions in actions_pa_anomalies.conf: "configctl pa_anomalies ...").

        cli.py run                                  the 15 minute run (cron); nice 20 from configd
        cli.py summary                              light counters (Max Cyber)
        cli.py status                               installation, sources, runs, settings, network
        cli.py list <filters> <sort> <page:rows>    filters "status=open+severity=high+type=dga+host=10.0.0.5+
                                                    days=7+search=abc" ("-": none), sort "field:asc|desc"
        cli.py finding <id>                         one finding with factors, occurrences, series, actions
        cli.py host <ip>                            host profile (normal vs. now)
        cli.py explain <finding|host> <id|ip> <language> <send|preview>
        cli.py index                                build the country/ASN index (background, when the
                                                    quarantine has none)
        cli.py plan|apply <action> [args...]        change actions of actions.py (and revert <journal id> of
                                                    their journal entries)

    Output: one JSON document.  Only "run", "index" and "apply" write, and only below /var/db/policyanalyzer
    (plus the cron job of install/remove through the core model).
"""

import ipaddress
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ''):
    sys.path = [p for p in sys.path if os.path.abspath(p or '.') != _HERE]
    sys.path.insert(0, os.path.dirname(_HERE))

from anomalies import common, engine as engine_mod  # noqa: E402

FILTER_KEYS = {
    'status': re.compile(r'^(open|expected|resolved)$'),
    'severity': re.compile(r'^(high|medium|low|info)$'),
    'type': re.compile(r'^[a-z_]{2,24}$'),
    'host': re.compile(r'^[0-9A-Fa-f:.]{2,45}$'),
    'days': re.compile(r'^\d{1,4}$'),
    'search': re.compile(r'^[0-9A-Za-z:./_-]{1,64}$'),
}
SORT_RE = re.compile(r'^(severity|score|last_seen|first_seen|host|type|occurrences|status):(asc|desc)$')
TOKEN_RE = re.compile(r'^[A-Za-z0-9_.:/=+-]{0,255}$')
CONTEXT = common.Context


def emit(data, out=None):
    (out or sys.stdout).write(json.dumps(data, ensure_ascii=False, default=str) + '\n')


def parse_filters(token):
    filters = {}
    if not token or token == '-':
        return filters
    for part in token.split('+'):
        key, _sep, value = part.partition('=')
        if key not in FILTER_KEYS or not FILTER_KEYS[key].match(value):
            raise ValueError('invalid filter: %s' % part)
        filters[key] = value
    return filters


def parse_page(token):
    match = re.match(r'^(\d{1,6}):(-?\d{1,4})$', token or '')
    if not match:
        return 1, 25
    page, rows = int(match.group(1)) or 1, int(match.group(2))
    return page, (rows if rows == -1 else max(1, min(rows, 500)))


def valid_ip(text):
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError('invalid address')


def change(mode, args):
    from ai import changes, journal
    from anomalies import actions
    if not args:
        raise ValueError('an action is required')
    name = args[0]
    if name == 'revert':
        entry = journal.load(args[1] if len(args) > 1 else '')
        if entry.get('action') not in actions.NAMES:
            raise ValueError('not an anomaly change')
    elif name not in actions.NAMES:
        raise ValueError('not an anomaly change')
    if any(not TOKEN_RE.match(a or '') for a in args[1:]):
        raise ValueError('invalid argument')
    return changes.run(mode, name, args[1:])


def build_index(ctx):
    """ the country/ASN index of the quarantine, built into anomalies-lookup.db (same format) """
    import fcntl
    from quarantine import lookup as qlookup
    os.makedirs(os.path.dirname(ctx.index_lock), mode=0o750, exist_ok=True)
    fd = os.open(ctx.index_lock, os.O_RDWR | os.O_CREAT, 0o640)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return {'status': 'busy'}

        class _C:
            geoip_dir = ctx.geoip_dir
            asn_csv = ctx.asn_csv
            lookup_db = ctx.lookup_db
        return qlookup.build(_C)
    finally:
        os.close(fd)


def main(argv, out=None, ctx=None):
    args = [a for a in argv if a != '']
    if not args:
        emit({'status': 'error', 'message': 'usage: cli.py run|summary|status|list|finding|host|explain|index|'
                                            'plan|apply'}, out)
        return 1
    ctx = ctx or CONTEXT()
    eng = engine_mod.Engine(ctx)
    cmd, rest = args[0], args[1:]
    try:
        if cmd == 'run':
            emit(eng.run(), out)
        elif cmd == 'summary':
            emit(eng.summary(), out)
        elif cmd == 'status':
            emit(eng.status(), out)
        elif cmd == 'list':
            filters = parse_filters(rest[0] if rest else '-')
            sort_token = rest[1] if len(rest) > 1 else '-'
            sort = tuple(sort_token.split(':')) if SORT_RE.match(sort_token) else ('-', 'desc')
            page, rows = parse_page(rest[2] if len(rest) > 2 else '')
            emit(eng.search(filters, sort, page, rows), out)
        elif cmd == 'finding':
            if not rest or not common.ID_RE.match(rest[0]):
                raise ValueError('invalid finding id')
            emit(eng.finding(rest[0]), out)
        elif cmd == 'host':
            emit(eng.host(valid_ip(rest[0] if rest else '')), out)
        elif cmd == 'explain':
            from anomalies import explain
            kind = rest[0] if rest else ''
            language = rest[2] if len(rest) > 2 and common.LANG_RE.match(rest[2]) else None
            mode = rest[3] if len(rest) > 3 and rest[3] in ('send', 'preview') else 'send'
            if kind == 'finding':
                if len(rest) < 2 or not common.ID_RE.match(rest[1]):
                    raise ValueError('invalid finding id')
                data = eng.finding(rest[1])
                if data.get('status') != 'ok':
                    return emit(data, out) or 0
                payload = explain.compact_finding(data['finding'])
                result = explain.ask('finding', rest[1], payload, language, mode, ctx.config_xml)
                result['actions'] = data['finding']['actions']
            elif kind == 'host':
                ip = valid_ip(rest[1] if len(rest) > 1 else '')
                profile = eng.host(ip)
                result = explain.ask('host', ip, explain.compact_host(profile), language, mode, ctx.config_xml)
                result['actions'] = profile['actions']
            else:
                raise ValueError('explain finding|host')
            emit(result, out)
        elif cmd == 'index':
            emit(build_index(ctx), out)
        elif cmd in ('plan', 'apply'):
            emit(change(cmd, rest), out)
        else:
            emit({'status': 'error', 'message': 'unknown command'}, out)
            return 1
    except ValueError as exc:
        emit({'status': 'error', 'message': str(exc)}, out)
    except common.AnomalyError as exc:
        emit({'status': 'error', 'message': str(exc)}, out)
    except OSError as exc:
        emit({'status': 'error', 'message': 'store not available: %s' % exc}, out)
    except Exception as exc:     # noqa: BLE001  sqlite3 errors and the like: always one JSON document
        emit({'status': 'error', 'message': '%s: %s' % (type(exc).__name__, exc)}, out)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
