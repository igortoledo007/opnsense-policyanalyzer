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

    configd entry point of the device inventory (actions_pa_devices.conf). One JSON document on stdout.

      cli.py scan                                     passive scan now (writes only devices.db)
      cli.py summary                                  light counts for the Max Cyber / reports (scans when stale)
      cli.py list <filters|-> <sort> <page:rows>      filters: type=camera+risk=high+known=0+present=1+new=1+search=x
      cli.py device <id>                              one device with addresses and history
      cli.py oui                                      manufacturer database in use
      cli.py explain <id> <language> <refresh|preview>
      cli.py plan|apply <devices_mark_known|devices_set|devices_oui_update|revert> [args...]
"""

import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ''):
    sys.path = [p for p in sys.path if os.path.abspath(p or '.') != _HERE]
    sys.path.insert(0, os.path.dirname(_HERE))

from devices import explain, inventory, oui, view  # noqa: E402

OWN_ACTIONS = ('devices_mark_known', 'devices_set', 'devices_oui_update', 'revert')
USAGE = 'usage: cli.py scan|summary|list|device|oui|explain|plan|apply ...'


def run(argv):
    args = [a for a in argv if a != '']
    if not args:
        raise ValueError(USAGE)
    cmd, rest = args[0], args[1:] + ['', '', '']
    if cmd == 'scan':
        return inventory.scan()
    if cmd == 'summary':
        inventory.ensure_fresh()
        return view.summary()
    if cmd == 'list':
        inventory.ensure_fresh()
        page, rows = 1, 50
        match = re.match(r'^(\d{1,5}):(\d{1,3})$', rest[2])
        if match:
            page, rows = int(match.group(1)), int(match.group(2))
        sort = rest[1] if rest[1] in ('risk', 'last_seen', 'first_seen', 'name', 'type') else 'risk'
        return view.listing(None if rest[0] == '-' else rest[0], sort, page, rows)
    if cmd == 'device':
        if not re.match(r'^\d{1,9}$', rest[0]):
            raise ValueError('invalid device id')
        return view.device(int(rest[0]))
    if cmd == 'oui':
        return dict(oui.OUI().status(), status='ok')
    if cmd == 'explain':
        if not re.match(r'^\d{1,9}$', rest[0]):
            raise ValueError('invalid device id')
        return explain.explain(int(rest[0]), rest[1], 'preview' if rest[2] == 'preview' else 'refresh')
    if cmd in ('plan', 'apply'):
        from ai import changes
        from devices import actions  # noqa: F401
        if args[1:2] and args[1] in OWN_ACTIONS:
            return changes.run(cmd, args[1], args[2:])
        raise ValueError('unknown action')
    raise ValueError(USAGE)


def main(argv=None):
    try:
        result = run(sys.argv[1:] if argv is None else argv)
    except ValueError as exc:
        result = {'status': 'error', 'message': str(exc)}
    except OSError as exc:
        result = {'status': 'error', 'message': 'unable to read the state: %s' % exc}
    sys.stdout.write(json.dumps(result) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
