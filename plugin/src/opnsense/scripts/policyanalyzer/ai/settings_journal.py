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

    Journal for settings saved through the MVC form.

    The API calls "snapshot" right before saving and "record" right after;
    the difference becomes an undo journal entry (action "settings") whose
    revert restores the previous values.  The values are applied back by the
    API through the model (apply_via "gui"), so validation and config.xml
    handling stay in one place.  Secrets are never shown: fields listed in
    SECRET_FIELDS are displayed as "configured ****1234".
"""

import json
import os

from . import journal
from .config import CONFIG_XML, read_mount

SNAPSHOT = os.environ.get('POLICYANALYZER_SNAPSHOT', '/var/db/policyanalyzer/settings.snapshot.json')
SECRET_FIELDS = ('claude.apikey', 'claudecode.token')


def flatten(data, prefix=''):
    result = {}
    for key, value in (data or {}).items():
        path = '%s.%s' % (prefix, key) if prefix else key
        if isinstance(value, dict):
            result.update(flatten(value, path))
        else:
            result[path] = value
    return result


def display(field, value):
    if field in SECRET_FIELDS:
        return ('configured ****%s' % value[-4:]) if value else 'not configured'
    return value if value != '' else '(empty)'


def _write_private(path, data):
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle)
    os.replace(path + '.tmp', path)


def snapshot(mount, path=CONFIG_XML):
    _write_private(SNAPSHOT, flatten(read_mount(mount, path)))
    return {'status': 'ok'}


def record(mount, path=CONFIG_XML):
    """ diff snapshot -> current config; :return: journal id or None when nothing changed """
    try:
        with open(SNAPSHOT) as handle:
            before = json.load(handle)
    except (OSError, ValueError):
        before = None
    after = flatten(read_mount(mount, path))
    _write_private(SNAPSHOT, after)
    if before is None:
        return {'status': 'ok', 'journal_id': None, 'message': 'no snapshot, nothing recorded'}
    changes = [
        {'field': f, 'old': before.get(f, ''), 'new': after.get(f, '')}
        for f in sorted(set(before) | set(after)) if before.get(f, '') != after.get(f, '')
    ]
    if not changes:
        return {'status': 'ok', 'journal_id': None}
    entry = journal.create(
        'settings', {'fields': [c['field'] for c in changes]},
        {'done': True, 'completed': ['%s: %s -> %s' % (c['field'], display(c['field'], c['old']),
                                                        display(c['field'], c['new'])) for c in changes]},
        state={'changes': changes},
    )
    return {'status': 'ok', 'journal_id': entry['id']}


def revert_plan(entry, mount='OPNsense/policyanalyzer', path=None):
    current = flatten(read_mount(mount, path or CONFIG_XML))
    steps, warnings, values = [], [], {}
    for change in (entry.get('state') or {}).get('changes', []):
        field = change['field']
        now = current.get(field, '')
        if now == change['old']:
            continue
        if now != change['new']:
            warnings.append('%s was changed again later (now %s), it will still be set back to %s' % (
                field, display(field, now), display(field, change['old'])))
        values[field] = change['old']
        steps.append({
            'description': 'Set %s back to %s' % (field, display(field, change['old'])),
            'command': 'settings: %s = %s' % (field, display(field, change['old'])),
            'effect': 'currently %s' % display(field, now),
        })
    return {
        'status': 'ok', 'steps': steps, 'warnings': warnings, 'irreversible': [],
        'requires_confirmation': bool(steps), 'risk': 'low' if steps else 'none',
        'apply_via': 'gui', 'values': values,
    }
