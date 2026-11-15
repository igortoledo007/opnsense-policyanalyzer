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

    Undo journal: one JSON file per applied change in
    /var/db/policyanalyzer/undo/<id>.json

        {
          "id": "20261107T183000-1a2b3c",
          "ts": "2026-11-07T18:30:00-0300",
          "action": "prepare_storage",
          "args": {...},
          "status": "ok" | "error" | "partial",
          "completed": ["command", ...],
          "state": {...},                 action specific data needed to revert
          "irreversible": ["..."],        what a revert can not bring back
          "depends_on": ["<id>", ...],    journals this change builds upon
          "reverted": null | {"ts", "status", "completed", "warnings"}
        }
"""

import json
import os
import re
import secrets
import time

UNDO_DIR = os.environ.get('POLICYANALYZER_UNDO', '/var/db/policyanalyzer/undo')
ID_RE = re.compile(r'^\d{8}T\d{6}-[0-9a-f]{6}$')


def new_id():
    return time.strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(3)


def _path(entry_id):
    if not isinstance(entry_id, str) or not ID_RE.match(entry_id):
        raise ValueError('invalid journal id')
    return os.path.join(UNDO_DIR, entry_id + '.json')


def write(entry):
    os.makedirs(UNDO_DIR, mode=0o750, exist_ok=True)
    path = _path(entry['id'])
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(entry, handle, indent=1, sort_keys=True)
    os.replace(tmp, path)
    return entry


def create(action, args, result, state=None, irreversible=None, depends_on=None):
    status = 'ok' if result.get('done') else ('partial' if result.get('completed') else 'error')
    return write({
        'id': new_id(),
        'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'action': action,
        'args': args,
        'status': status,
        'completed': list(result.get('completed') or []),
        'state': state or {},
        'irreversible': list(irreversible or []),
        'depends_on': list(depends_on or []),
        'reverted': None,
    })


def load(entry_id):
    try:
        with open(_path(entry_id)) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        raise ValueError('journal entry not found')


def entries():
    """ all journal entries, newest first """
    result = []
    try:
        names = os.listdir(UNDO_DIR)
    except OSError:
        return result
    for name in names:
        if name.endswith('.json') and ID_RE.match(name[:-5]):
            try:
                result.append(load(name[:-5]))
            except ValueError:
                continue
    result.sort(key=lambda e: e['id'], reverse=True)
    return result


def dependents(entry_id):
    """ newer, not reverted entries that depend on entry_id (revert those first) """
    return [e for e in entries() if entry_id in (e.get('depends_on') or []) and not e.get('reverted')]


def mark_reverted(entry_id, result):
    entry = load(entry_id)
    entry['reverted'] = {
        'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'status': result.get('status'),
        'completed': list(result.get('completed') or []),
        'warnings': list(result.get('warnings') or []),
    }
    return write(entry)
