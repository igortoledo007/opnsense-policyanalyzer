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

    Command line of the local collectors (configd: actions_pa_collect.conf).  Output: one JSON document.

        cli.py run <config|health|flows|all> [rescan]     one collector run (flock per kind; busy -> skipped)
        cli.py status                                      last runs, sizes, ranges, cron jobs, settings
        cli.py query <name> [args...]                      read interface (query.CLI), e.g.
                                                           query top_sources 7d now 10
        cli.py import <file> [plan|apply]                  history exported from the LAN computer
        cli.py import_undo <imp...id>
        cli.py schedule <plan|apply> <create|remove>       change action collect_schedule (journalized)
        cli.py settings <plan|apply> <k=v+k=v|defaults>    change action collect_settings (journalized)
        cli.py settings show
        cli.py revert <plan|apply> <journal id>            revert one of the two actions above
        cli.py maintain <config|health|flows>              compaction / retention / size limit now
"""

import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ''):
    sys.path = [p for p in sys.path if os.path.abspath(p or '.') != _HERE]
    sys.path.insert(0, os.path.dirname(_HERE))

from collect import common, importer, query, store  # noqa: E402

USAGE = ('usage: cli.py run <config|health|flows|all> | status | query <name> [args] | import <file> [plan|apply] | '
         'import_undo <id> | schedule <plan|apply> <create|remove> | settings <plan|apply|show> [spec] | '
         'revert <plan|apply> <id> | maintain <kind>')
OWN_ACTIONS = ('collect_schedule', 'collect_settings')


def emit(data):
    sys.stdout.write(json.dumps(data, default=str) + '\n')


def run_kind(ctx, kind, rescan=False):
    from collect import config, flows, health
    settings = common.load_settings(ctx)
    ctx.ensure_dirs()
    with common.Lock(os.path.join(ctx.dir, '%s.lock' % kind)) as lock:
        if not lock.acquired:
            return {'status': 'busy', 'kind': kind, 'message': 'a previous %s run is still active' % kind}
        deadline = time.monotonic() + common.BUDGET[kind]
        started = time.monotonic()
        try:
            if kind == 'config':
                result = config.run(ctx, settings, deadline, rescan=rescan)
            elif kind == 'health':
                result = health.run(ctx, settings, deadline)
            else:
                result = flows.run(ctx, settings, deadline)
        except Exception as exc:                       # noqa: BLE001 - recorded, the next run tries again
            result = {'status': 'error', 'kind': kind, 'message': '%s: %s' % (type(exc).__name__, exc)}
        result['seconds'] = round(time.monotonic() - started, 2)
        for path in ctx.db.values():
            for suffix in ('', '-wal', '-shm'):
                if os.path.exists(path + suffix):
                    store.file_mode(path + suffix)
        return result


def status(ctx):
    from collect import actions
    cov = query.Query(ctx).coverage()
    return {'status': 'ok', 'dir': ctx.dir, 'collectors': cov, 'cron': actions.cron_jobs(ctx),
            'settings': common.load_settings(ctx),
            'imports_waiting': sorted(f for f in (os.listdir(ctx.import_dir) if os.path.isdir(ctx.import_dir) else [])
                                      if importer.NAME_RE.match(f))}


def change(mode, name, args):
    from ai import changes
    import collect as _pkg          # noqa: F401  registers the actions
    if name != 'revert' and name not in OWN_ACTIONS:
        raise ValueError('unknown action')
    if name == 'revert':
        from ai import journal
        entry = journal.load(args[0] if args else '')
        if entry.get('action') not in OWN_ACTIONS:
            raise ValueError('not a collector change (use the Action history of the Policy Analyzer)')
    return changes.run(mode, name, args)


def main(argv, ctx=None):
    ctx = ctx or common.Context()
    args = [a for a in argv if a != '']
    if not args:
        emit({'status': 'error', 'message': USAGE})
        return 1
    cmd, rest = args[0], args[1:]
    try:
        if cmd == 'run' and rest and rest[0] in common.KINDS + ('all',):
            kinds = common.KINDS if rest[0] == 'all' else (rest[0],)
            results = [run_kind(ctx, k, rescan='rescan' in rest[1:]) for k in kinds]
            emit(results[0] if len(results) == 1 else {'status': 'ok', 'runs': results})
        elif cmd == 'status':
            emit(status(ctx))
        elif cmd == 'query' and rest:
            emit(query.run_cli(query.Query(ctx), rest[0], rest[1:]))
        elif cmd == 'import' and rest:
            mode = rest[1] if len(rest) > 1 else 'plan'
            if mode == 'plan':
                emit(importer.plan(ctx, rest[0]))
            elif mode == 'apply':
                emit(importer.apply(ctx, rest[0], common.load_settings(ctx)))
            else:
                raise ValueError(USAGE)
        elif cmd == 'import_undo' and rest:
            emit(importer.undo(ctx, rest[0]))
        elif cmd == 'schedule' and len(rest) == 2 and rest[0] in ('plan', 'apply'):
            emit(change(rest[0], 'collect_schedule', rest[1:]))
        elif cmd == 'settings' and rest and rest[0] == 'show':
            emit({'status': 'ok', 'settings': common.load_settings(ctx), 'defaults': common.DEFAULTS})
        elif cmd == 'settings' and len(rest) == 2 and rest[0] in ('plan', 'apply'):
            emit(change(rest[0], 'collect_settings', rest[1:]))
        elif cmd == 'revert' and len(rest) == 2 and rest[0] in ('plan', 'apply'):
            emit(change(rest[0], 'revert', rest[1:]))
        elif cmd == 'maintain' and rest and rest[0] in common.KINDS:
            con = store.open_db(ctx, rest[0])
            emit({'status': 'ok', 'kind': rest[0],
                  'maintenance': store.maintain(ctx, rest[0], con, common.load_settings(ctx), ctx.clock(), force=True)})
            con.close()
        else:
            emit({'status': 'error', 'message': USAGE})
            return 1
    except ValueError as exc:
        emit({'status': 'error', 'message': str(exc)})
    except (OSError, ImportError) as exc:
        emit({'status': 'error', 'message': '%s: %s' % (type(exc).__name__, exc)})
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
