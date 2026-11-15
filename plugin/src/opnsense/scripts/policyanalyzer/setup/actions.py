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

    plan / apply / revert for the local AI runtime.

        plan(action, args, ctx)           read only
        apply(action, args, ctx)          executes plan(action, args) recomputed here (never the client's copy)
        revert_plan(journal_id, args)     read only
        revert_apply(journal_id, args)    executes the undo, itself journaled (so it can be reverted too)

    Plan format (shared with ai/storage.py):
        {status: ok|blocked|error, action, args, steps: [{type, description, command, argv, effect, undo,
         already}], warnings, errors, irreversible, download_bytes, space_needed, space_free, space_path,
         requires_confirmation, reversible, undo, risk, background, busy}
"""

import os
import time

from . import common, filepool, gguf, ops, runtime, models
from .common import SetupError, BusyError

ACTIONS = {
    'install_runtime': runtime.install_plan,
    'uninstall_runtime': runtime.uninstall_plan,
    'start_runtime': runtime.start_plan,
    'stop_runtime': runtime.stop_plan,
    'enable_runtime': lambda ctx, args: runtime.boot_plan(ctx, args, True),
    'disable_runtime': lambda ctx, args: runtime.boot_plan(ctx, args, False),
    'set_limits': runtime.set_limits_plan,
    'enable_racct': runtime.enable_racct_plan,
    'pull_model': models.pull_plan,
    'remove_model': models.remove_plan,
    'benchmark': models.benchmark_plan,
    'import_gguf': gguf.import_plan,
    'create_file_pool': filepool.create_plan,
    'remove_file_pool': filepool.remove_plan,
}
READ_ONLY = ('status_runtime', 'history', 'job', 'hw_profile', 'recommend')
CONTROL = ('cancel', 'revert')

# positional parameters (configd passes them in this order) and accepted key=value keys
POSITIONAL = {
    'pull_model': ['model'],
    'remove_model': ['model'],
    'benchmark': ['model'],
    'set_limits': ['cpus', 'threads', 'ctx', 'nice', 'mem_gb'],
    'revert': ['journal'],
    'install_runtime': ['branch', 'cpus'],
    'recommend': ['budget_pct'],
    'import_gguf': ['source', 'name'],
    'create_file_pool': ['size', 'arc_mb'],
    'remove_file_pool': ['confirm'],
}
KEYS = {
    'install_runtime': {'branch', 'cpus', 'threads', 'ctx', 'nice', 'mem_gb', 'keep_alive', 'start', 'boot'},
    'uninstall_runtime': {'remove_dataset', 'confirm'},
    'set_limits': {'cpus', 'threads', 'ctx', 'nice', 'mem_gb', 'keep_alive'},
    'pull_model': {'model', 'custom', 'large'},
    'remove_model': {'model'},
    'benchmark': {'model'},
    'revert': {'journal', 'keep_models', 'force'},
    'recommend': {'budget_pct'},
    'import_gguf': {'source', 'name', 'sha256', 'template', 'cleanup'},
    'create_file_pool': {'size', 'arc_mb', 'image'},
    'remove_file_pool': {'confirm', 'image'},
}


FLAGS = {
    'install_runtime': {'no_start': ('start', 'no'), 'no_boot': ('boot', 'no')},
    'uninstall_runtime': {'remove_dataset': ('remove_dataset', 'yes')},
    'pull_model': {'custom': ('custom', 'yes'), 'large': ('large', 'yes')},
    'import_gguf': {'cleanup': ('cleanup', 'yes')},
    'revert': {'delete_models': ('keep_models', 'no'), 'force': ('force', 'yes')},
}
EXTRA_POSITIONAL = {'uninstall_runtime': ['confirm']}


def parse_cli_args(action, tokens):
    """
    configd tokens -> args dict.  Accepted forms (the GUI dispatcher allows only [A-Za-z0-9/_.:@+-]):
      positional values in POSITIONAL order, "+flag" switches (FLAGS), and key=value (shell use only);
      set_limits also accepts one token "cpus/threads/ctx/nice" (e.g. 2-3/2/8192/20);
      a cpu list may use "_" instead of "," (0_2).  Empty tokens (configd padding) are ignored.
    """
    import re
    args = {}
    tokens = [t for t in tokens if t not in (None, '')]
    if action == 'set_limits' and len(tokens) == 1 and tokens[0].count('/') in (3, 4):
        tokens = tokens[0].split('/')
    positional = list(POSITIONAL.get(action, [])) + list(EXTRA_POSITIONAL.get(action, []))
    allowed = KEYS.get(action, set())
    flags = FLAGS.get(action, {})
    for token in tokens:
        if not re.match(r'^[A-Za-z0-9._:,=/@+-]{1,255}$', token) or '..' in token:
            raise ValueError('invalid parameter')
        if token.startswith('+'):
            if token[1:] not in flags:
                raise ValueError('unknown switch %s for %s' % (token, action))
            key, value = flags[token[1:]]
            args[key] = value
        elif '=' in token:
            key, value = token.split('=', 1)
            if key not in allowed:
                raise ValueError('unknown parameter %s for %s' % (key, action))
            args[key] = value
        elif positional:
            args[positional.pop(0)] = token
        else:
            raise ValueError('too many parameters for %s' % action)
    if 'cpus' in args:
        args['cpus'] = args['cpus'].replace('_', ',')
    return args


# ------------------------------------------------------------------ warning -> action hints

REBOOT_LINK = {'label': 'System: Power: Reboot', 'url': '/ui/core/reboot'}


def _limits_token(ctx):
    lim = dict(common.DEFAULT_LIMITS)
    lim.update(runtime.current_limits(ctx))
    return '%s/%s/%s/%s' % (lim['cpus'].replace(',', '_'), lim['threads'], lim['ctx'], lim['nice'])


# (regex on the message, builder(match, plan_args, ctx) -> hint dict)
HINTS = [
    (r'kern\.racct\.enable=0', lambda m, a, c: {'action': {'id': 'enable_racct', 'args': [],
                                                           'label': 'Enable RAM limit support (RCTL)'}}),
    (r'takes effect after the next reboot', lambda m, a, c: {'link': REBOOT_LINK}),
    (r'RCTL is available now but the jail has no RAM limit', lambda m, a, c: {
        'action': {'id': 'set_limits', 'args': [_limits_token(c)], 'label': 'Apply the RAM limit (set_limits)'}}),
    (r'runtime (is )?not installed', lambda m, a, c: {'action': {'id': 'install_runtime', 'args': [],
                                                               'label': 'Install the local runtime'}}),
    (r'runtime is not running', lambda m, a, c: {'action': {'id': 'start_runtime', 'args': [],
                                                          'label': 'Start the local runtime'}}),
    (r'no model installed', lambda m, a, c: {'action': {'id': 'pull_model', 'args': [],
                                                      'label': 'Download a model (see the recommendation)'}}),
    (r'does not exist \(prepare the storage first\)', lambda m, a, c: {
        'action': {'id': 'prepare_storage', 'args': ['/var/db/ai/models'], 'label': 'Prepare the model storage'}}),
    (r'pass large=yes', lambda m, a, c: {'action': {'id': 'pull_model', 'args': [a.get('model', ''), '+large'],
                                                  'label': 'Download anyway (+large)'}}),
    (r'another setup action is running', lambda m, a, c: {'action': {'id': 'setup_cancel', 'args': [],
                                                                   'label': 'Cancel the running job'}}),
    (r'listening outside 127\.0\.0\.1', lambda m, a, c: {'action': {'id': 'stop_runtime', 'args': [],
                                                                    'label': 'Stop the runtime'}}),
    (r'revert them first: (\S+)', lambda m, a, c: {'action': {
        'id': 'revert', 'args': [_official_or(c, m.group(1))], 'label': 'Revert the newer action first'}}),
    (r'not enough space', lambda m, a, c: {'action': {'id': 'remove_model', 'args': [],
                                                    'label': 'Remove a model to free space'}}),
]


def _official_or(ctx, sid):
    try:
        return common.load_journal(ctx, sid).get('official') or sid
    except (SetupError, ValueError):
        return sid


def warning_actions(ctx, messages, plan_args=None):
    """ [{warning, action: {id, label, args}} | {warning, link: {label, url}}] for the UI buttons """
    import re
    out = []
    for text in messages:
        for pattern, build in HINTS:
            match = re.search(pattern, text)
            if match:
                hint = build(match, plan_args or {}, ctx)
                hint['warning'] = text
                out.append(hint)
    return out


# ------------------------------------------------------------------ plan


def _finish_plan(ctx, action, raw, args):
    steps = [ops.describe(dict(s)) for s in raw.get('steps', [])]
    for step in steps:
        step['already'] = ops.predict(ctx, step)
        if step.get('type') in ('write_file',) and step.get('content') is not None and len(step['content']) > 4000:
            step['content'] = step['content'][:4000] + '\n...'
    errors = list(raw.get('errors', []))
    busy = common.lock_holder(ctx)
    if busy:
        errors.append('another setup action is running (%s)' % busy)
    pending = [s for s in steps if not s['already']]
    result = {
        'status': 'blocked' if errors else 'ok',
        'action': action,
        'args': raw.get('args', args),
        'steps': steps,
        'warnings': raw.get('warnings', []),
        'errors': errors,
        'irreversible': raw.get('irreversible', []),
        'download_bytes': raw.get('download_bytes', 0),
        'space_needed': raw.get('space_needed'),
        'space_free': raw.get('space_free'),
        'space_path': raw.get('space_path'),
        'space': '%s needed, %s free' % (common.fmt_bytes(raw.get('space_needed')),
                                         common.fmt_bytes(raw.get('space_free')))
        if raw.get('space_needed') is not None else None,
        'requires_confirmation': bool(pending) and not errors,
        'reversible': raw.get('changes', True) is not False,
        'undo': raw.get('undo'),
        'risk': raw.get('risk', 'low') if pending else 'none',
        'ports': raw.get('ports', []),
        'background': bool(raw.get('background')),
        'busy': busy,
    }
    result['warning_actions'] = warning_actions(ctx, result['errors'] + result['warnings'], result['args']
                                                if isinstance(result['args'], dict) else {})
    for key in ('model', 'space_freed', 'previous', 'target', 'dependents', 'superseded', 'blocked_by',
                'reboot_required', 'links', 'file_pool'):
        if key in raw:
            result[key] = raw[key]
    return result


def plan(action, args=None, ctx=None):
    ctx = ctx or common.Context()
    args = dict(args or {})
    try:
        if action == 'status_runtime':
            result = runtime.status(ctx)
            result['warning_actions'] = warning_actions(ctx, result['warnings'])
            return {'status': 'ok', 'action': action, 'result': result, 'steps': [],
                    'requires_confirmation': False}
        if action == 'history':
            return {'status': 'ok', 'action': action, 'result': history(ctx), 'steps': []}
        if action in ('hw_profile', 'recommend'):
            from . import recommend
            profile = recommend.hw_profile(ctx)
            return {'status': 'ok', 'action': action, 'steps': [],
                    'result': profile if action == 'hw_profile'
                    else recommend.recommend(profile, budget_pct=args.get('budget_pct'))}
        if action == 'job':
            return {'status': 'ok', 'action': action, 'result': common.State(ctx).load(), 'steps': []}
        if action == 'cancel':
            return _cancel_plan(ctx)
        if action == 'revert':
            return revert_plan(args.get('journal'), args, ctx)
        if action not in ACTIONS:
            raise ValueError('unknown action %s' % action)
        raw = ACTIONS[action](ctx, args)
        return _finish_plan(ctx, action, raw, args)
    except (ValueError, SetupError) as exc:
        return {'status': 'error', 'action': action, 'message': str(exc), 'steps': []}


# ------------------------------------------------------------------ apply


def _strip_for_journal(plan_result):
    return [{k: s.get(k) for k in ('type', 'description', 'command', 'effect', 'undo')} for s in plan_result['steps']]


def apply(action, args=None, ctx=None, lock=None, state=None, job_id=None):
    ctx = ctx or common.Context()
    args = dict(args or {})
    if action == 'cancel':
        return cancel(ctx)
    if action == 'revert':
        return revert_apply(args.get('journal'), args, ctx, lock=lock, state=state, job_id=job_id)
    if action in READ_ONLY:
        return plan(action, args, ctx)
    if not ctx.is_root:
        return {'status': 'error', 'action': action, 'message': 'apply must run as root (configd)'}
    own_lock = lock is None
    try:
        lock = lock or common.Lock(ctx).acquire()
    except BusyError as exc:
        return {'status': 'error', 'action': action, 'message': str(exc)}
    try:
        try:
            raw = ACTIONS[action](ctx, args) if action in ACTIONS else None
        except (ValueError, SetupError) as exc:
            return {'status': 'error', 'action': action, 'message': str(exc)}
        if raw is None:
            return {'status': 'error', 'action': action, 'message': 'unknown action %s' % action}
        planned = _finish_plan(ctx, action, raw, args)
        planned['errors'] = [e for e in planned['errors'] if not e.startswith('another setup action')]
        if planned['errors']:
            planned['status'] = 'blocked'
            return planned
        return _execute(ctx, action, raw, planned, state=state, job_id=job_id)
    finally:
        if own_lock:
            lock.release()


def _execute(ctx, action, raw, planned, state=None, job_id=None, extra=None):
    log = common.SetupLog(ctx)
    try:
        os.unlink(ctx.cancel_file)
    except OSError:
        pass
    ctx.cancel_check = lambda: common.check_cancel(ctx, job_id)
    started = time.time()
    log.record(action=action, phase='start', args=planned['args'], job=job_id,
               steps=[s['description'] for s in planned['steps']])
    if raw.get('changes') is False:
        # benchmark: nothing to journal or revert
        try:
            result = {}
            for step in raw['steps']:
                ops.execute_step(ctx, step)
                result = step.get('result', result)
            out = {'status': 'ok', 'action': action, 'result': result}
        except Exception as exc:                # noqa: BLE001
            out = {'status': 'failed', 'action': action, 'message': str(exc)}
        log.record(action=action, phase='end', status=out['status'], seconds=round(time.time() - started, 1))
        return out
    journal = {
        'id': common.new_journal_id(ctx, action if action != 'revert' else 'revert'),
        'action': action,
        'args': planned['args'],
        'created': int(ctx.clock()),
        'seq': time.time_ns(),          # orders journals created within the same second
        'status': 'running',
        'job': job_id,
        'plan': _strip_for_journal(planned),
        'irreversible': planned['irreversible'],
        'undo': planned['undo'],
        'resources': raw.get('resources', []),
        'previous': raw.get('previous'),
        'post_revert': raw.get('post_revert', []),
        'revert_action': raw.get('revert_action'),
        'inverse': [],
    }
    journal.update(extra or {})
    common.save_journal(ctx, journal)
    if state is not None:
        state.update_job(journal=journal['id'], status='running')
    result = ops.run_steps(ctx, raw['steps'], journal, state=state, log=log, job_id=job_id)
    result['action'] = action
    result['duration_s'] = round(time.time() - started, 1)
    if result['status'] == 'ok' and not journal['inverse'] and not journal.get('revert_action') \
            and all(e['status'] == 'skipped' or e['description'].startswith(('Wait', 'Check'))
                    for e in journal['executed']):
        # nothing changed (idempotent re-run): no journal entry, nothing to revert
        try:
            os.unlink(common.journal_path(ctx, journal['id']))
        except OSError:
            pass
        result['journal'] = None
        result['nothing_changed'] = True
    if result['status'] == 'ok':
        result['warnings'] = planned['warnings']
        result['undo'] = ('apply revert %s' % result['journal']) if result['journal'] else None
        if action == 'install_runtime' or action == 'start_runtime':
            bad = ops.foreign_listeners(ctx, 11434)
            if bad:
                result['warnings'] = result['warnings'] + ['port 11434 also listens on %s' % ', '.join(bad)]
    else:
        common.drop_working_copy(ctx, journal['id'])   # rolled back: nothing to revert, details in setup.log
    log.record(action=action, phase='end', status=result['status'], journal=journal['id'],
               seconds=result['duration_s'], message=result.get('message'))
    return result


# ------------------------------------------------------------------ revert

JAIL_SCOPED = {'jail', 'boot', 'limits', 'run'}


def _order(journal):
    return (journal.get('created') or 0, journal.get('seq') or 0, journal.get('id'))


def _later(ctx, journal):
    return [j for j in common.list_journals(ctx)
            if _order(j) > _order(journal)
            and j.get('status') == 'applied' and not j.get('reverted_by') and j.get('action') != 'revert']


def revert_plan(journal_id, args=None, ctx=None):
    ctx = ctx or common.Context()
    args = dict(args or {})
    try:
        common.validate_journal_id(journal_id or '')
        journal = common.load_journal(ctx, journal_id)
        raw = _revert_raw(ctx, journal, args)
        result = _finish_plan(ctx, 'revert', raw, {'journal': journal_id})
        result['target'] = {'id': journal['id'], 'action': journal['action'], 'created': journal.get('created'),
                            'args': journal.get('args'), 'official': journal.get('official')}
        if raw.get('superseded') or raw.get('dependents') or raw.get('blocked_by'):
            result['requires_double_confirmation'] = result['requires_confirmation']
        return result
    except (ValueError, SetupError) as exc:
        return {'status': 'error', 'action': 'revert', 'message': str(exc), 'steps': []}


def _revert_raw(ctx, journal, args):
    keep_models = common.as_bool(args.get('keep_models'), True, 'keep_models')
    force = common.as_bool(args.get('force'), False, 'force')
    errors, warnings, irreversible = [], [], []
    if journal.get('reverted_by'):
        errors.append('already reverted by %s' % journal['reverted_by'])
    elif journal.get('status') == 'superseded':
        errors.append('superseded by the revert %s' % journal.get('superseded_by'))
    elif journal.get('status') != 'applied':
        errors.append('journal status is %s: nothing to revert (failed actions are rolled back automatically)'
                      % journal.get('status'))
    resources = set(journal.get('resources') or [])
    later = _later(ctx, journal)
    superseded, dependents, blocked = [], [], []
    for other in later:
        other_res = set(other.get('resources') or [])
        if 'jail' in resources and other_res <= (JAIL_SCOPED | {r for r in other_res if r.startswith('model:')}):
            if any(r.startswith('model:') for r in other_res):
                dependents.append(other)
            else:
                superseded.append(other)
        elif resources & other_res:
            blocked.append(other)
    if blocked and not force:
        errors.append('newer actions change the same thing; revert them first: %s'
                      % ', '.join('%s (%s)' % (j['id'], j['action']) for j in blocked))
    elif blocked:
        warnings.append('force=yes: newer actions on the same resource are overridden: %s'
                        % ', '.join(j['id'] for j in blocked))
    if superseded:
        warnings.append('these later actions are undone together and marked superseded: %s'
                        % ', '.join('%s (%s)' % (j['id'], j['action']) for j in superseded))
    steps = []
    download = 0
    if journal.get('revert_action'):
        spec = journal['revert_action']
        sub = ACTIONS[spec['action']](ctx, dict(spec.get('args') or {}))
        steps = sub['steps']
        errors += sub.get('errors', [])
        warnings += sub.get('warnings', [])
        irreversible += sub.get('irreversible', [])
        download = sub.get('download_bytes', 0)
        resources_out = sub.get('resources', [])
        revert_inverse_kind = 'action'
    else:
        steps = [dict(s) for s in journal.get('inverse', [])]
        post = [dict(s) if s.get('always') else dict(s, skip_unless=runtime.jls_check())
                for s in journal.get('post_revert') or []]
        steps += post
        resources_out = list(resources)
        revert_inverse_kind = 'inverse'
        for step in steps:
            ops.describe(step)
            if step['type'] == 'model_restore':
                import json as _json
                manifest = _json.loads(step['manifest'])
                size = sum(s for d, s in ops.manifest_digests(manifest)
                           if not os.path.isfile(ops.blob_path(ctx, d)))
                download += size
                irreversible.append('%s downloaded again from registry.ollama.ai' % common.fmt_bytes(size))
    if dependents:
        names = []
        for dep in dependents:
            model = (dep.get('args') or {}).get('model')
            if model:
                names.append(model)
        if keep_models:
            warnings.append('models downloaded after this install are kept in /var/db/ai/models: %s '
                            '(pass keep_models=no to delete them as well)' % ', '.join(names))
        else:
            for dep in dependents:
                for inv in dep.get('inverse') or []:
                    if inv['type'] == 'model_remove':
                        steps.insert(0, dict(inv, only_blobs=None, manifest_b64=None))
            irreversible.append('models deleted: %s' % ', '.join(names))
    for step in steps:
        ops.describe(step)
    return {'steps': steps, 'errors': errors, 'warnings': warnings, 'irreversible': irreversible,
            'download_bytes': download, 'undo': 'the revert is journaled too and can itself be reverted',
            'resources': resources_out, 'risk': 'medium' if journal.get('revert_action') else 'low',
            'background': bool(journal.get('revert_action')) or any(s['type'] == 'model_restore' for s in steps),
            'args': {'journal': journal['id'], 'keep_models': keep_models},
            'superseded': [j['id'] for j in superseded],
            'dependents': [j['id'] for j in dependents],
            'blocked_by': [j['id'] for j in blocked],
            '_kind': revert_inverse_kind,
            'revert_action': None}


def revert_apply(journal_id, args=None, ctx=None, lock=None, state=None, job_id=None):
    ctx = ctx or common.Context()
    args = dict(args or {})
    if not ctx.is_root:
        return {'status': 'error', 'action': 'revert', 'message': 'apply must run as root (configd)'}
    try:
        common.validate_journal_id(journal_id or '')
    except ValueError as exc:
        return {'status': 'error', 'action': 'revert', 'message': str(exc)}
    own_lock = lock is None
    try:
        lock = lock or common.Lock(ctx).acquire()
    except BusyError as exc:
        return {'status': 'error', 'action': 'revert', 'message': str(exc)}
    try:
        try:
            journal = common.load_journal(ctx, journal_id)
            raw = _revert_raw(ctx, journal, args)
        except (ValueError, SetupError) as exc:
            return {'status': 'error', 'action': 'revert', 'message': str(exc)}
        planned = _finish_plan(ctx, 'revert', raw, args)
        planned['errors'] = [e for e in planned['errors'] if not e.startswith('another setup action')]
        if planned['errors']:
            planned['status'] = 'blocked'
            return planned
        result = _execute(ctx, 'revert', raw, planned, state=state, job_id=job_id,
                          extra={'reverts': journal['id'], 'reverts_action': journal['action']})
        if result['status'] == 'ok':
            revert_journal = common.load_journal(ctx, result['journal']) if result['journal'] else None
            common.update_journal(ctx, journal['id'], status='reverted', reverted_by=result['journal'] or 'noop',
                                  revert_journal=revert_journal)
            if result['journal']:
                common.drop_working_copy(ctx, result['journal'])
            for other_id in raw.get('superseded', []) + (raw.get('dependents', []) if not
                                                         common.as_bool(args.get('keep_models'), True) else []):
                common.update_journal(ctx, other_id, status='superseded', superseded_by=journal['id'],
                                      official_reverted={'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                                                         'status': 'superseded', 'completed': [],
                                                         'warnings': ['undone by the revert of %s (%s)'
                                                                      % (journal.get('official') or journal['id'],
                                                                         journal['action'])]})
        result['reverted'] = journal['id']
        return result
    finally:
        if own_lock:
            lock.release()


# ------------------------------------------------------------------ cancel / history


def _cancel_plan(ctx):
    job = common.State(ctx).load().get('job') or {}
    running = job.get('status') == 'running' and common.lock_holder(ctx) is not None
    return {'status': 'ok' if running else 'blocked', 'action': 'cancel',
            'steps': [{'type': 'cancel', 'description': 'Cancel %s (job %s)' % (job.get('action'), job.get('id')),
                       'command': 'write %s' % ctx.cancel_file,
                       'effect': 'the running step stops; what this job changed is rolled back'}] if running else [],
            'errors': [] if running else ['no setup action is running'],
            'warnings': [], 'irreversible': ['bytes already downloaded'] if running else [],
            'requires_confirmation': running, 'job': job}


def cancel(ctx):
    plan_result = _cancel_plan(ctx)
    if plan_result['status'] != 'ok':
        return {'status': 'error', 'action': 'cancel', 'message': 'no setup action is running'}
    job = plan_result['job']
    common.write_atomic(ctx.cancel_file, (job.get('id') or '*') + '\n', 0o600)
    common.SetupLog(ctx).record(action='cancel', job=job.get('id'))
    return {'status': 'ok', 'action': 'cancel', 'job': job.get('id'),
            'message': 'cancel requested; the job rolls back and stops'}


def history(ctx):
    items = []
    for journal in reversed(common.list_journals(ctx)):
        later = _later(ctx, journal) if journal.get('status') == 'applied' else []
        items.append({
            'id': journal['id'], 'action': journal['action'], 'args': journal.get('args'),
            'created': journal.get('created'), 'status': journal.get('status'),
            'reverted_by': journal.get('reverted_by'), 'reverts': journal.get('reverts'),
            'revertable': journal.get('status') == 'applied' and not journal.get('reverted_by'),
            'irreversible': journal.get('irreversible'),
            'newer_on_same_resource': [j['id'] for j in later
                                       if set(j.get('resources') or []) & set(journal.get('resources') or [])],
        })
    return items
