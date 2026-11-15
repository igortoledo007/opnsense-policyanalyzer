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

    Command line / background worker of the local AI runtime setup, prints JSON.

    The GUI goes through the plugin's generic dispatcher (manage.py plan|apply
    <action>, configd change_plan/change_apply), where every action of this
    package is registered (adapter.py).  This script is the detached worker
    for long actions and a shell equivalent for the console:

        run.py plan  <action> [params...]          read only
        run.py apply <action> [params...]
        run.py plan|apply revert <journal id> [+delete_models] [+force]
        run.py plan  status_runtime | job | history
        run.py apply cancel
        run.py _worker <job> <lock fd> <action> <args json> [official id]   (internal)
"""

import json
import os
import sys

_HERE = globals().get('__file__') or ''
if os.path.isfile(_HERE):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(_HERE))))

from setup import actions, adapter, common       # noqa: E402

MODES = ('plan', 'apply', '_worker')


def _out(data):
    sys.stdout.write(json.dumps(data, indent=2, sort_keys=True, default=str) + '\n')


def main(argv):
    if len(argv) < 2 or argv[0] not in MODES:
        _out({'status': 'error', 'message': 'usage: run.py plan|apply <action> [params]'})
        return 2
    mode, action = argv[0], argv[1]
    if mode == '_worker':
        # internal: run.py _worker <job_id> <lock_fd> <action> <args_json> [official_target]
        adapter.worker(argv[1], argv[2], argv[3], json.loads(argv[4]), argv[5] if len(argv) > 5 else None)
        return 0
    known = set(actions.ACTIONS) | set(actions.READ_ONLY) | set(actions.CONTROL)
    if action not in known:
        _out({'status': 'error', 'message': 'unknown action %s' % action})
        return 2
    ctx = common.Context()
    official = None
    try:
        args = actions.parse_cli_args(action, argv[2:])
        if action == 'revert':
            args['journal'], official = adapter.resolve_journal_id(args.get('journal'))
    except ValueError as exc:
        _out({'status': 'error', 'action': action, 'message': str(exc)})
        return 2
    if mode == 'plan':
        _out(actions.plan(action, args, ctx))
        return 0
    planned = None
    if action == 'revert':
        planned = actions.revert_plan(args['journal'], args, ctx)
    elif action in actions.ACTIONS:
        planned = actions.plan(action, args, ctx)
    if planned is not None and planned.get('background'):
        _out(adapter.spawn(action, args, ctx, planned, official_target=official))
        return 0
    result = actions.apply(action, args, ctx)
    if action == 'revert' and result.get('status') == 'ok':
        adapter.mark_official_reverted(official, result)
    elif action in actions.ACTIONS:
        result['official_journal'] = adapter.record_apply(action, args, result, ctx)
    _out(result)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
