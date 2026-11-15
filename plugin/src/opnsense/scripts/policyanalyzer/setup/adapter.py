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

    Glue between this package and the generic change dispatcher of the plugin
    (ai/changes.py + ai/journal.py, configd "policyanalyzer change_plan|change_apply").

    - Every setup action is registered as a ChangeAction, so the GUI
      simulation dialog, the history tab and "revert" work unchanged.
    - The official undo entry is the one in /var/db/policyanalyzer/undo/<id>.json
      (ai/journal.py); our executor journal (inverse steps, previous file
      contents, ...) travels in its "state" and is also kept, step by step,
      in /var/db/policyanalyzer/setup-journal/ for crash safety.
    - Long actions run in a detached worker (run.py _worker): apply returns
      status "started" without "completed", so the dispatcher does not
      journal it; the worker writes the official entry itself when it ends
      (and marks the target entry reverted for a background revert).
    - Without the plugin (tests, or bundled for a read only plan) the
      package works on its own: register() is a no-op.
"""

import json
import os
import subprocess
import sys

from . import actions, common

try:                                            # the plugin's generic dispatcher, when installed
    from ai import changes as _changes, journal as _journal
except ImportError:                             # pragma: no cover - standalone use
    _changes = _journal = None

OFFICIAL_ID_LEN = 22
CONTEXT_FACTORY = common.Context                # replaced by the tests


def _ctx():
    return CONTEXT_FACTORY()                            # YYYYmmddTHHMMSS-xxxxxx (ai/journal.py)

DESCRIPTIONS = {
    'install_runtime': 'Install the local AI runtime (Ollama in an isolated FreeBSD jail)',
    'uninstall_runtime': 'Remove the local AI runtime jail (models are kept unless asked)',
    'start_runtime': 'Start the local AI runtime jail',
    'stop_runtime': 'Stop the local AI runtime jail',
    'enable_runtime': 'Start the local AI runtime at boot',
    'disable_runtime': 'Do not start the local AI runtime at boot',
    'set_limits': 'Change the CPU, thread, context and priority limits of the local AI runtime',
    'enable_racct': 'Enable kernel resource accounting (kern.racct.enable=1) for the AI jail RAM limit; '
                    'takes effect after the next reboot',
    'pull_model': 'Download a model for the local AI runtime',
    'remove_model': 'Remove a model of the local AI runtime',
    'benchmark': 'Measure the local AI runtime speed (nothing is changed)',
    'import_gguf': 'Import a GGUF model (file copied to /var/db/ai/models/import/ or downloaded from Hugging Face) '
                   'into the local AI runtime',
}


def available():
    return _changes is not None and _journal is not None


# ------------------------------------------------------------------ contract mapping


def to_contract(result):
    """ our plan/apply dict -> ai/changes.py contract (extra keys are kept) """
    out = dict(result)
    out['status'] = 'error' if result.get('status') in ('error', 'blocked', 'failed', 'cancelled') else \
        result.get('status', 'ok')
    if result.get('errors'):
        out['message'] = '; '.join(result['errors'])
    if result.get('undo'):
        out['revert'] = [result['undo']]
    out['steps'] = [{'description': s.get('description'), 'command': s.get('command'),
                     'effect': ('already done' if s.get('already') else s.get('effect')) or ''}
                    for s in result.get('steps', [])]
    out.setdefault('warnings', [])
    out.setdefault('irreversible', [])
    if 'requires_confirmation' not in out:
        out['requires_confirmation'] = bool(out['steps']) and out['status'] == 'ok'
    out['requires_double_confirmation'] = bool(result.get('requires_double_confirmation')) or (
        bool(out['irreversible']) and out['requires_confirmation'] and result.get('risk') in ('medium', 'high'))
    out['apply_via'] = 'backend'
    return out


def depends_on_storage():
    """ official ids of the prepare_storage entries the runtime/models build upon """
    if not available():
        return []
    return [e['id'] for e in _journal.entries()
            if e.get('action') == 'prepare_storage' and not e.get('reverted') and e.get('status') == 'ok'][:1]


def apply_contract(action, result, ctx):
    """ result of actions.apply() -> contract with done/completed/state for ai/journal.py """
    out = to_contract(result)
    ok = result.get('status') == 'ok'
    out['done'] = ok
    out['completed'] = [e['description'] for e in result.get('executed', []) if e.get('status') == 'done'] \
        if ok else []
    if ok and result.get('journal'):
        out['state'] = {'setup_journal': result['journal'], 'journal': common.load_journal(ctx, result['journal'])}
        out['irreversible'] = out['state']['journal'].get('irreversible', [])
        out['depends_on'] = depends_on_storage() if action in ('install_runtime', 'pull_model') else []
        common.drop_working_copy(ctx, result['journal'])     # the journal now travels in "state"
    return out


def record_apply(action, args, result, ctx):
    """ worker / run.py: write the official undo entry; :return: its id or None """
    if ctx.official is None or result.get('status') != 'ok' or not result.get('journal'):
        return None
    contract = apply_contract(action, result, ctx)
    entry = ctx.official.create(action, args, contract, state=contract.get('state'),
                                irreversible=contract.get('irreversible'), depends_on=contract.get('depends_on'))
    return entry['id']


def setup_journal_of(official_id):
    """ official entry id -> our journal id """
    if not available():
        raise ValueError('journal entry not found')
    entry = _journal.load(official_id)
    sid = (entry.get('state') or {}).get('setup_journal')
    if not sid:
        raise ValueError('journal entry %s is not a runtime setup action' % official_id)
    return sid


def official_of(setup_journal_id):
    if not available():
        return None
    for entry in _journal.entries():
        if (entry.get('state') or {}).get('setup_journal') == setup_journal_id:
            return entry['id']
    return None


def resolve_journal_id(value):
    """ accept both the official id and ours; :return: (setup_journal_id, official_id or None) """
    if isinstance(value, str) and len(value) == OFFICIAL_ID_LEN and available():
        return setup_journal_of(value), value
    common.validate_journal_id(value or '')
    return value, official_of(value)


def mark_official_reverted(official_id, result, ctx=None):
    official = ctx.official if ctx is not None else _journal
    if official is not None and official_id:
        official.mark_reverted(official_id, {'status': 'ok' if result.get('status') == 'ok' else 'error',
                                             'completed': [e.get('description') for e in result.get('executed', [])
                                                           if e.get('status') == 'done'],
                                             'warnings': result.get('warnings', [])})


# ------------------------------------------------------------------ background worker


def spawn(action, args, ctx, planned, official_target=None):
    """ take the lock, start run.py _worker detached (it inherits the lock) """
    if not ctx.is_root:
        return {'status': 'error', 'action': action, 'message': 'apply must run as root (configd)'}
    if planned.get('status') != 'ok':
        return planned
    try:
        lock = common.Lock(ctx).acquire()
    except common.BusyError as exc:
        return {'status': 'error', 'action': action, 'message': str(exc)}
    job_id = common.new_journal_id(ctx, 'job')
    state = common.State(ctx)
    state.update_job(id=job_id, action=action, args=args, status='queued', started=int(ctx.clock()),
                     pid=None, journal=None, official=None, result=None, step=None, step_index=0,
                     step_total=len(planned.get('steps', [])), bytes_done=None, bytes_total=None, finished=None)
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'run.py')
    proc = subprocess.Popen([sys.executable, '-I', script, '_worker', job_id, str(lock.fd), action,
                             json.dumps(args), official_target or ''],
                            pass_fds=(lock.fd,), start_new_session=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    state.update_job(pid=proc.pid)
    os.close(lock.fd)        # the worker keeps the flock (same open file description)
    return {'status': 'started', 'action': action, 'job': job_id, 'pid': proc.pid, 'done': False,
            'completed': [], 'steps': planned.get('steps', []),
            'message': 'running in background; poll "policyanalyzer_setup plan job" for progress'}


def worker(job_id, fd, action, args, official_target=None, ctx=None):
    ctx = ctx or _ctx()
    lock = common.Lock(ctx, fd=int(fd))
    state = common.State(ctx)
    state.update_job(pid=os.getpid(), status='running')
    try:
        result = actions.apply(action, args, ctx, lock=lock, state=state, job_id=job_id)
        if action == 'revert':
            if result.get('status') == 'ok':
                mark_official_reverted(official_target or official_of(result.get('reverted')), result, ctx)
        else:
            result['official_journal'] = record_apply(action, args, result, ctx)
    except Exception as exc:                    # noqa: BLE001
        result = {'status': 'failed', 'action': action, 'message': str(exc)}
    state.finish_job({'ok': 'done'}.get(result.get('status'), result.get('status')), result)
    try:
        os.unlink(ctx.cancel_file)
    except OSError:
        pass
    lock.release()
    return result


# ------------------------------------------------------------------ status probes (for manage.py STATUS)


def status_runtime(args=None):
    """ manage.py status runtime: jail, Ollama version, listeners, models, running job """
    return runtime_status()


def status_job(args=None):
    """ manage.py status setup_job: progress of the running / last background job (setup-state.json) """
    ctx = _ctx()
    data = common.State(ctx).load()
    data['busy'] = common.lock_holder(ctx)
    return {'status': 'ok', 'job': data.get('job'), 'history': data.get('history', []), 'busy': data['busy']}


def status_hw_profile(args=None):
    """ manage.py status hw_profile: CPU/flags, RAM, bandwidth inputs, GPUs, Vulkan, load, heavy services """
    from . import recommend
    return dict(recommend.hw_profile(_ctx()), status='ok')


def status_recommend(args=None):
    """ manage.py status recommend [budget_pct]: candidates, verdicts and the recommended model """
    from . import recommend
    tokens = [a for a in (args or []) if a]
    try:
        budget = recommend.validate_budget(tokens[0] if tokens else None)
    except ValueError as exc:
        return {'status': 'error', 'message': str(exc)}
    return dict(recommend.recommend(recommend.hw_profile(_ctx()), budget_pct=budget), status='ok')


# names for manage.py STATUS (the plugin wires them): manage.py status <name>
STATUS_PROBES = {
    'runtime': status_runtime,
    'setup_job': status_job,
    'hw_profile': status_hw_profile,
    'recommend': status_recommend,
}


def runtime_status():
    from . import runtime
    ctx = _ctx()
    result = runtime.status(ctx)
    result['warning_actions'] = actions.warning_actions(ctx, result['warnings'])
    return dict(result, status='ok')


def revert_args(flags):
    """ dispatcher revert flags -> args of actions.revert_plan/revert_apply (only the known ones) """
    flags = dict(flags or {})
    args = {}
    if 'keep_models' in flags:
        args['keep_models'] = flags['keep_models']
    if 'force' in flags:
        args['force'] = flags['force']
    return args


# ------------------------------------------------------------------ registration


def register():
    if not available():
        return
    for name in actions.ACTIONS:
        _changes.register(_make_class(name))
    _changes.register(_cancel_class())


def _cancel_class():
    class SetupCancel(_changes.ChangeAction):
        """ control only: stops the running background job, which rolls itself back (nothing to journal) """
        name = 'setup_cancel'
        description = 'Cancel the running AI setup job (it rolls back what it changed)'
        revertible = False

        def parse_args(self, args):
            if [a for a in args if a]:
                raise ValueError('setup_cancel takes no arguments')
            return {}

        def plan(self):
            return to_contract(actions.plan('cancel', {}, _ctx()))

        def apply(self):
            result = actions.apply('cancel', {}, _ctx())
            out = to_contract(result)
            out['done'] = result.get('status') == 'ok'
            out['completed'] = []           # nothing to revert: no journal entry
            return out
    return SetupCancel


def _make_class(action_name):
    class SetupAction(_changes.ChangeAction):
        name = action_name
        description = DESCRIPTIONS.get(action_name, action_name)
        revertible = action_name != 'benchmark'

        def parse_args(self, args):
            return {'args': actions.parse_cli_args(self.name, list(args))}

        def plan(self, args):
            return to_contract(actions.plan(self.name, args, _ctx()))

        def apply(self, args):
            ctx = _ctx()
            planned = actions.plan(self.name, args, ctx)
            if planned.get('background') and planned.get('status') == 'ok':
                return to_contract(spawn(self.name, args, ctx, planned))
            result = actions.apply(self.name, args, ctx)
            return apply_contract(self.name, result, ctx)

        def revert_plan(self, entry, flags=None):
            """ :param flags: optional {"force": True, "keep_models": "no"} from the dispatcher """
            sid = (entry.get('state') or {}).get('setup_journal')
            if not sid:
                raise ValueError('this entry has no runtime journal')
            return to_contract(actions.revert_plan(sid, revert_args(flags), _ctx()))

        def revert_apply(self, entry, flags=None):
            sid = (entry.get('state') or {}).get('setup_journal')
            if not sid:
                raise ValueError('this entry has no runtime journal')
            ctx = _ctx()
            args = revert_args(flags)
            planned = actions.revert_plan(sid, args, ctx)
            if planned.get('background') and planned.get('status') == 'ok':
                # not "ok": the dispatcher must not mark it reverted yet, the worker does it at the end
                return to_contract(spawn('revert', dict(args, journal=sid), ctx, planned,
                                         official_target=entry['id']))
            result = actions.revert_apply(sid, args, ctx)
            out = to_contract(result)
            out['completed'] = [e['description'] for e in result.get('executed', []) if e.get('status') == 'done'] \
                if result.get('status') == 'ok' else []
            return out

    SetupAction.__name__ = 'Setup_' + action_name
    return SetupAction
