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

    Generic plan/apply ("simulate, then apply") and revert for every action
    that changes something on the firewall.

    Contract (JSON, returned by plan, apply and their revert variants):
        {
          "status": "ok" | "error",
          "action": "<name>" | "revert",
          "target": "<journal id>",             revert only
          "args": {...},                        validated arguments
          "steps": [{"description", "command", "effect"}],
          "warnings": ["..."],
          "irreversible": ["..."],              what a later revert can NOT undo (shown before Apply)
          "revert": ["..."],                    how this change will be reverted (plan only)
          "requires_confirmation": bool,        false when there is nothing to do
          "requires_double_confirmation": bool, irreversible parts or dependent changes
          "risk": "none" | "low" | "medium" | "high",
          "space": "free form note on disk usage" (optional),
          "apply_via": "backend" | "gui",       "gui": the API applies "values" through the model
          "done": bool,                         apply only
          "completed": ["command", ...],        apply only
          "journal_id": "<id>",                 apply only, entry to revert later
          "message": "..."                      on error
        }

    Rules every action must follow:
      * plan() never changes anything; apply() recomputes the plan itself
        and runs exactly those steps (nothing executable comes from the
        client, only the validated arguments);
      * idempotent: running apply twice is harmless, existing objects are
        never destroyed or modified unless the plan says so;
      * every apply returns "state" (what it created/changed and the previous
        values), the dispatcher stores it in the undo journal;
      * revert_plan(entry)/revert_apply(entry) only undo what that entry
        recorded and refuse (with a warning) when it is no longer safe;
      * every executed step is logged.

    Adding an action (e.g. install_runtime, pull_model, set_limits,
    benchmark): subclass ChangeAction, implement parse_args/plan/apply and
    revert_plan/revert_apply, decorate with @register, in a module imported
    by one of the extension packages listed in EXTENSIONS
    (scripts/policyanalyzer/<package>/__init__.py imports its action
    modules).  The GUI simulation dialog, the history tab and the
    /api/policyanalyzer/change/* endpoints need no changes.
"""

import importlib
import inspect
import re
import sys

from . import journal, settings_journal, storage

# sibling packages of "ai" that may register more actions (loaded when present)
EXTENSIONS = ('setup', 'quarantine', 'incidents', 'reports', 'vulns', 'devices', 'anomalies', 'collect')

REGISTRY = {}
RISKS = ('none', 'low', 'medium', 'high')
# optional revert flags, simple tokens after the journal id: "force", "keep_models=no"
FLAG_RE = re.compile(r'^([a-z][a-z0-9_]{0,31})(?:=([A-Za-z0-9_.-]{0,32}))?$')


def register(cls):
    REGISTRY[cls.name] = cls
    return cls


class ChangeAction:
    name = ''
    description = ''
    revertible = True

    def parse_args(self, args):
        """ :param args: list of strings from configd; :return: dict of validated kwargs or raise ValueError """
        raise NotImplementedError

    def plan(self, **kwargs):
        raise NotImplementedError

    def apply(self, **kwargs):
        """ :return: contract dict plus "state" (stored in the journal), "depends_on" (journal ids, optional) """
        raise NotImplementedError

    def revert_plan(self, entry, flags=None):
        """ :param flags: dict of optional revert flags, e.g. {"force": True, "keep_models": "no"} """
        raise ValueError('this action can not be reverted')

    def revert_apply(self, entry, flags=None):
        raise ValueError('this action can not be reverted')


@register
class PrepareStorage(ChangeAction):
    name = 'prepare_storage'
    description = 'Create the local model storage (ZFS dataset and/or directory below /var/db/)'

    def parse_args(self, args):
        if not args or not args[0]:
            raise ValueError('a path is required')
        return {'path': storage.validate_prepare_path(args[0])}

    def plan(self, path):
        return storage.plan(path)

    def apply(self, path):
        return storage.prepare(path)

    def revert_plan(self, entry):
        return storage.revert_plan(entry)

    def revert_apply(self, entry):
        return storage.revert_apply(entry)


@register
class Settings(ChangeAction):
    """ settings are saved by the MVC form; this action only exists to revert them """
    name = 'settings'
    description = 'AI settings saved from the GUI (revert restores the previous values)'

    def parse_args(self, args):
        raise ValueError('settings are changed through the settings form')

    def revert_plan(self, entry):
        return settings_journal.revert_plan(entry)

    def revert_apply(self, entry):
        raise ValueError('settings are restored by the API through the model, use apply_via=gui')


# per scenario AI routing and the cron job of the AI queue (ai_routing, ai_queue_schedule)
from . import routing_actions  # noqa: E402
routing_actions.register(sys.modules[__name__])


def _public(result):
    """ drop internal fields (argv, state) and normalise the contract """
    result = dict(result)
    result.pop('state', None)
    result['steps'] = [
        {k: step.get(k) for k in ('description', 'command', 'effect')} for step in result.get('steps', [])
    ]
    result.setdefault('warnings', [])
    result.setdefault('irreversible', [])
    result.setdefault('apply_via', 'backend')
    result.setdefault('requires_confirmation', bool(result['steps']))
    result.setdefault('requires_double_confirmation', bool(result['irreversible']) and bool(result['steps']))
    if result.get('risk') not in RISKS:
        result['risk'] = 'low' if result['steps'] else 'none'
    return result


def _error(name, message):
    return {'status': 'error', 'action': name, 'message': message, 'steps': [], 'warnings': [],
            'irreversible': [], 'requires_confirmation': False, 'requires_double_confirmation': False}


def load_extensions(packages=EXTENSIONS):
    """ import optional extension packages; a broken extension never hides the built-in actions """
    for package in packages:
        try:
            importlib.import_module(package)
        except ImportError:
            continue
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write('policyanalyzer: extension %s failed to load: %s\n' % (package, exc))


def parse_flags(tokens):
    flags = {}
    for token in tokens:
        match = FLAG_RE.match(token or '')
        if not match:
            raise ValueError('invalid revert flag')
        flags[match.group(1)] = match.group(2) if match.group(2) is not None else True
    return flags


def _call_revert(method, entry, flags):
    """ pass flags only to implementations that accept them (older ones take just the entry) """
    try:
        accepts = len(inspect.signature(method).parameters) >= 2
    except (TypeError, ValueError):
        accepts = False
    return method(entry, flags) if accepts else method(entry)


def _revert(mode, args):
    entry_id = args[0] if args else ''
    flags = parse_flags(args[1:])
    entry = journal.load(entry_id)
    if entry.get('reverted'):
        return _error('revert', 'this change was already reverted on %s' % entry['reverted'].get('ts'))
    if entry.get('action') not in REGISTRY:
        return _error('revert', 'the action "%s" is not available anymore' % entry.get('action'))
    action = REGISTRY[entry['action']]()
    if not action.revertible:
        return _error('revert', 'this action can not be reverted')
    plan = _call_revert(action.revert_plan, entry, flags)
    deps = journal.dependents(entry_id)
    if deps:
        plan.setdefault('warnings', []).insert(0, 'revert these later changes first: %s' % ', '.join(
            '%s (%s)' % (d['id'], d['action']) for d in deps))
        plan['requires_double_confirmation'] = True
    if entry.get('irreversible'):
        plan.setdefault('irreversible', []).extend(entry['irreversible'])
    plan.update({'action': 'revert', 'target': entry_id, 'reverts': entry['action'], 'flags': flags})
    if mode == 'plan' or plan.get('apply_via') == 'gui':
        return plan
    if deps:
        return _error('revert', plan['warnings'][0])
    result = _call_revert(action.revert_apply, entry, flags)
    result.update({'action': 'revert', 'target': entry_id, 'reverts': entry['action']})
    if result.get('status') == 'ok' or result.get('completed'):
        journal.mark_reverted(entry_id, result)
    return result


def run(mode, name, args):
    """ :param mode: "plan" or "apply" """
    try:
        if name == 'revert':
            return _public(_revert(mode, list(args)))
        if name not in REGISTRY:
            return _error(name, 'unknown action')
        action = REGISTRY[name]()
        kwargs = action.parse_args(list(args))
        result = action.plan(**kwargs) if mode == 'plan' else action.apply(**kwargs)
    except ValueError as exc:
        return _error(name, str(exc))
    result.setdefault('action', name)
    if mode == 'plan':
        result.pop('done', None)
    elif result.get('completed'):
        entry = journal.create(name, result.get('args', kwargs), result, state=result.get('state'),
                               irreversible=result.get('irreversible'), depends_on=result.get('depends_on'))
        result['journal_id'] = entry['id']
    return _public(result)


def history():
    items = []
    for entry in journal.entries():
        cls = REGISTRY.get(entry.get('action'))
        items.append({
            'id': entry['id'], 'ts': entry.get('ts'), 'action': entry.get('action'),
            'description': cls.description if cls else entry.get('action'),
            'status': entry.get('status'), 'args': entry.get('args'),
            'summary': entry.get('completed'), 'reverted': entry.get('reverted'),
            'revertible': bool(cls and cls.revertible and not entry.get('reverted')),
        })
    return {'status': 'ok', 'items': items}


def describe():
    items = [{'name': n, 'description': c.description} for n, c in sorted(REGISTRY.items())]
    return {'status': 'ok', 'actions': items}
