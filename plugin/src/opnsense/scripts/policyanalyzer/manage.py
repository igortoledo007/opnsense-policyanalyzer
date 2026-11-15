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

    System side of the AI layer: read-only status probes and the generic
    plan/apply runner for actions that change the firewall.

    Usage (via configd):
        manage.py status storage [path]      models directory: exists, writable, dataset, free space
        manage.py status runtime             local runtime (jail, Ollama, models), when setup/ is present
        manage.py status setup_job           progress of the running/last background setup job
        manage.py status hw_profile          hardware profile used by the recommendations
        manage.py status recommend [budget]  models that fit this hardware (budget: % of RAM for the model)
        manage.py list                       registered change actions
        manage.py plan <action> [args...]    simulate, nothing is changed
        manage.py apply <action> [args...]   execute the (recomputed) plan, write an undo journal entry
        manage.py plan revert <id> [flag...] simulate reverting a journal entry (flags: force, keep_models=no)
        manage.py apply revert <id>          revert it (entries with apply_via=gui are applied by the API)
        manage.py history                    undo journal, newest first
        manage.py settings snapshot          remember the settings before the GUI saves them
        manage.py settings record            journal the difference after the GUI saved them
        manage.py settings reverted <id>     mark a settings entry reverted after the API restored it
        manage.py quarantine <command> ...   automatic quarantine: run, sync, index, status, summary, guards,
                                             list, history, export, entry (see quarantine/cli.py)

    Output is always one JSON document.
"""

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai import AIConfig, changes, journal, settings_journal, storage  # noqa: E402

MOUNT = 'OPNsense/policyanalyzer'
CONFIG_XML = os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')
NAME_RE = re.compile(r'^[a-z][a-z0-9_]{0,63}$')
USAGE = ('usage: manage.py status storage [path] | list | history | plan <action> [args] | apply <action> [args] | '
         'settings snapshot|record|reverted <id>')


def emit(data):
    sys.stdout.write(json.dumps(data) + '\n')


def status_storage(args):
    path = args[0] if args and args[0] else None
    if path is None:
        path = AIConfig.from_opnsense(MOUNT, path=CONFIG_XML).options.get('models_dir') or storage.DEFAULT_MODELS_DIR
    return storage.inspect(path)


STATUS = {'storage': status_storage}

try:
    # optional local runtime component (scripts/policyanalyzer/setup)
    from setup import adapter as _setup_adapter  # noqa: E402
    # runtime, setup_job, hw_profile, recommend
    STATUS.update(_setup_adapter.STATUS_PROBES)
except (ImportError, AttributeError):
    _setup_adapter = None

try:
    # exposure & vulnerabilities (read only): inventory, exposure, vulns, exposure_report
    from exposure import adapter as _exposure_adapter  # noqa: E402
    STATUS.update(_exposure_adapter.STATUS_PROBES)
except (ImportError, AttributeError):  # pragma: no cover - package not shipped
    _exposure_adapter = None


def settings_cmd(args):
    sub = args[0] if args else ''
    if sub == 'snapshot':
        return settings_journal.snapshot(MOUNT, CONFIG_XML)
    if sub == 'record':
        return settings_journal.record(MOUNT, CONFIG_XML)
    if sub == 'reverted' and len(args) > 1:
        entry = journal.load(args[1])
        if entry.get('action') != 'settings' or entry.get('reverted'):
            raise ValueError('not a pending settings entry')
        journal.mark_reverted(args[1], {'status': 'ok', 'completed': ['settings restored by the API']})
        return {'status': 'ok', 'id': args[1]}
    raise ValueError(USAGE)


def main(argv):
    args = [a for a in argv[1:] if a != '']
    if not args:
        emit({'status': 'error', 'message': USAGE})
        return 1
    cmd, rest = args[0], args[1:]
    changes.load_extensions()
    try:
        if cmd == 'status' and rest and rest[0] in STATUS:
            try:
                emit(STATUS[rest[0]](rest[1:]))
            except TypeError:
                if not rest[1:]:
                    raise
                # probe that does not take arguments (yet): ignore them
                emit(STATUS[rest[0]]())
        elif cmd == 'list':
            emit(changes.describe())
        elif cmd == 'history':
            emit(changes.history())
        elif cmd == 'settings':
            emit(settings_cmd(rest))
        elif cmd == 'quarantine':
            from quarantine import cli as quarantine_cli
            return quarantine_cli.main(rest)
        elif cmd in ('plan', 'apply') and rest and NAME_RE.match(rest[0]):
            emit(changes.run(cmd, rest[0], rest[1:]))
        else:
            emit({'status': 'error', 'message': USAGE})
            return 1
    except ValueError as exc:
        emit({'status': 'error', 'message': str(exc)})
    except (OSError, subprocess.SubprocessError) as exc:
        emit({'status': 'error', 'done': False, 'message': str(exc)})
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
