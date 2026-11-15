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

    Change actions of the anomaly detection (plan = simulation, apply = journaled, revert from the action
    history), registered in ai/changes.py:

      install_anomalies                         SQLite store + cron "*/15 pa_anomalies run" + cron restart
      remove_anomalies [purge_db=yes]           cron removed; purge_db also deletes anomalies.db (irreversible)
      anomaly_expect <id> <finding|host|all> <comment base64|->
                                                exception: findings that match are "expected" from now on
      anomaly_exception_del <exception id>      the exception stops matching (revert re-enables it)
      anomaly_resolve <id>                      the finding is closed (a new occurrence opens it again)
      anomaly_settings <key=value[:key=value...]>   detector parameters (common.PARAMS)

    Nothing here touches rules, aliases or pf: the only firewall object is the cron job, created through the
    core model (model.php).
"""

import base64
import json
import os
import re

from ai import changes

from . import common, engine as engine_mod, store as store_mod

SCOPES = ('finding', 'host', 'all')
SETTINGS_RE = re.compile(r'^[a-z_0-9]{1,32}=\d{1,8}(:[a-z_0-9]{1,32}=\d{1,8}){0,15}$')
CONTEXT_FACTORY = common.Context


def ctx():
    return CONTEXT_FACTORY()


def _step(description, command, effect, already=False, **extra):
    step = {'description': description, 'command': command, 'effect': 'already done' if already else effect,
            'already': already}
    step.update(extra)
    return step


def _plan(steps, warnings=None, risk='low', revert=None, info=None, irreversible=None, double=False, **extra):
    todo = [s for s in steps if not s.get('already')]
    out = {'status': 'ok', 'steps': [{k: s[k] for k in ('description', 'command', 'effect')} for s in steps],
           'warnings': list(warnings or []), 'revert': list(revert or []), 'risk': risk if todo else 'none',
           'requires_confirmation': bool(todo), 'requires_double_confirmation': bool(double and todo),
           'irreversible': list(irreversible or []), 'info': info or []}
    if not todo:
        out['steps'] = []
    out.update(extra)
    return out


def php(c, *args):
    rc, out, err = c.runner.run([c.php, c.model_php] + [str(a) for a in args], timeout=60)
    try:
        data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except ValueError:
        data = {}
    if rc != 0 or data.get('status') != 'ok':
        raise common.AnomalyError('core model (%s): %s' % (args[0], data.get('message') or err.strip() or rc))
    return data


def configctl(c, *args):
    rc, out, err = c.runner.run([c.configctl] + list(args), timeout=120)
    if rc != 0:
        raise common.AnomalyError('configctl %s: %s' % (' '.join(args), (err or out).strip() or rc))
    return out


def _decode_comment(token):
    if token in (None, '', '-'):
        return ''
    try:
        text = base64.b64decode(token, validate=True).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise ValueError('the comment must be base64 (UTF-8)')
    text = ' '.join(text.split())
    if len(text) > 200:
        raise ValueError('the comment is limited to 200 characters')
    return text


def _info_detectors():
    return [{'title': 'Detectors (deterministic; the AI only explains)', 'items': [
        '%s: %s' % (k, v) for k, v in common.TYPE_TITLES.items()]},
        {'title': 'Sources read (never written)', 'items': [
            'NetFlow /var/log/flowd.log* (core parser)', 'Unbound /var/unbound/data/unbound.duckdb (read only, '
            'core DbConnection)', 'Host discovery /var/db/hostwatch/hosts.db, Kea / dnsmasq leases',
            'filter log /var/log/filter/latest.log', 'Suricata TLS events /var/log/suricata/eve.json',
            'Insight /var/netflow/src_addr_details_086400.sqlite (first run seed)']},
        {'title': 'Budget per run', 'items': [
            'nice 20, wall clock %d s, RLIMIT_CPU %d s, at most %d flows and %d DNS rows' % (
                common.DEFAULTS['budget_s'], common.DEFAULTS['cpu_s'], common.DEFAULTS['max_flows'],
                common.DEFAULTS['max_dns_rows'])]}]


# ------------------------------------------------------------------ install / remove


@changes.register
class InstallAnomalies(changes.ChangeAction):
    name = 'install_anomalies'
    description = 'Anomalies: create the store and schedule the detection every 15 minutes'

    def parse_args(self, args):
        if args:
            raise ValueError('install_anomalies takes no argument')
        return {}

    def _steps(self, c):
        eng = engine_mod.Engine(c)
        jobs = eng.cron_jobs()
        return [
            _step('Create the anomaly store', 'sqlite3 %s (WAL, 0640)' % c.db, 'findings, baselines and exceptions',
                  already=os.path.exists(c.db), id='db'),
            _step('Schedule the detection', 'cron job: %s, minutes */15, hours * (%s)' % (common.CRON_COMMAND,
                                                                                         common.CRON_DESCR),
                  'runs every 15 minutes with nice 20', already=bool(jobs), id='cron'),
            _step('Apply the cron configuration', 'configctl cron restart', 'cron reloads its table',
                  already=bool(jobs), id='cron_restart'),
        ], jobs

    def plan(self):
        c = ctx()
        steps, _jobs = self._steps(c)
        return _plan(steps, risk='low', info=_info_detectors(),
                     warnings=['The first run reads the last %d h of NetFlow and the Unbound history to seed the '
                               'baselines; volume, rare destination, new domain and TLS findings wait %d days of '
                               'learning per host.' % (common.DEFAULTS['first_hours'],
                                                       common.DEFAULTS['learning_days'])],
                     revert=['Undo removes the cron job created here; the store and its history are kept'])

    def apply(self):
        c = ctx()
        steps, _jobs = self._steps(c)
        completed, created = [], {'cron': None, 'db': False}
        try:
            for step in steps:
                if step['already']:
                    continue
                if step['id'] == 'db':
                    store_mod.Store(c.db).close()
                    created['db'] = True
                elif step['id'] == 'cron':
                    created['cron'] = php(c, 'cron_add').get('uuid')
                elif step['id'] == 'cron_restart':
                    configctl(c, 'cron', 'restart')
                completed.append(step['command'])
        except common.AnomalyError as exc:
            if created['cron']:
                try:
                    php(c, 'cron_del', created['cron'])
                    configctl(c, 'cron', 'restart')
                except common.AnomalyError:
                    pass
            return {'status': 'error', 'message': str(exc), 'done': False, 'completed': completed,
                    'steps': steps, 'state': created}
        return {'status': 'ok', 'done': True, 'completed': completed, 'steps': steps, 'state': created, 'args': {}}

    def revert_plan(self, entry):
        c = ctx()
        uuid = (entry.get('state') or {}).get('cron')
        jobs = [j for j in engine_mod.Engine(c).cron_jobs() if j['uuid'] == uuid]
        steps = []
        if jobs:
            steps = [_step('Remove the cron job', 'System: Settings: Cron: delete %s' % uuid, 'no more runs',
                           id='cron', uuid=uuid),
                     _step('Apply the cron configuration', 'configctl cron restart', 'cron reloads', id='cron_restart')]
        return _plan(steps, risk='low', warnings=[] if jobs else ['the cron job created by this change is gone'])

    def revert_apply(self, entry):
        c = ctx()
        plan = self.revert_plan(entry)
        uuid = (entry.get('state') or {}).get('cron')
        completed = []
        if plan['steps']:
            php(c, 'cron_del', uuid)
            completed.append('cron_del %s' % uuid)
            configctl(c, 'cron', 'restart')
            completed.append('configctl cron restart')
        return {'status': 'ok', 'done': True, 'completed': completed, 'steps': plan['steps']}


@changes.register
class RemoveAnomalies(changes.ChangeAction):
    name = 'remove_anomalies'
    description = 'Anomalies: stop the scheduled detection (optionally delete the store)'

    def parse_args(self, args):
        purge = False
        for arg in args:
            if arg == 'purge_db=yes':
                purge = True
            elif arg not in ('', 'purge_db=no'):
                raise ValueError('unknown argument: %s' % arg)
        return {'purge_db': purge}

    def _steps(self, c, purge_db):
        jobs = engine_mod.Engine(c).cron_jobs()
        steps = []
        for job in jobs:
            steps.append(_step('Remove the cron job', 'System: Settings: Cron: delete %s' % job['uuid'],
                               'no more runs', id='cron', uuid=job['uuid']))
        if jobs:
            steps.append(_step('Apply the cron configuration', 'configctl cron restart', 'cron reloads',
                               id='cron_restart'))
        if purge_db and os.path.exists(c.db):
            steps.append(_step('Delete the anomaly store', 'rm %s %s-wal %s-shm' % (c.db, c.db, c.db),
                               'every finding, exception and baseline is lost', id='purge'))
        return steps

    def plan(self, purge_db=False):
        c = ctx()
        steps = self._steps(c, purge_db)
        irreversible = ['the findings history, the exceptions and the baselines'] if purge_db and \
            any(s['id'] == 'purge' for s in steps) else []
        return _plan(steps, risk='medium' if irreversible else 'low', irreversible=irreversible,
                     double=bool(irreversible),
                     revert=['Undo schedules the detection again' + ('' if irreversible else
                                                                      '; the store was kept')])

    def apply(self, purge_db=False):
        c = ctx()
        steps = self._steps(c, purge_db)
        completed, removed = [], {'cron': [], 'purged': False}
        for step in steps:
            if step['id'] == 'cron':
                php(c, 'cron_del', step['uuid'])
                removed['cron'].append(step['uuid'])
            elif step['id'] == 'cron_restart':
                configctl(c, 'cron', 'restart')
            elif step['id'] == 'purge':
                for suffix in ('', '-wal', '-shm'):
                    try:
                        os.unlink(c.db + suffix)
                    except FileNotFoundError:
                        pass
                removed['purged'] = True
            completed.append(step['command'])
        return {'status': 'ok', 'done': True, 'completed': completed, 'steps': steps, 'state': removed,
                'args': {'purge_db': purge_db},
                'irreversible': ['the findings history, the exceptions and the baselines'] if removed['purged']
                else []}

    def revert_plan(self, entry):
        c = ctx()
        state = entry.get('state') or {}
        jobs = engine_mod.Engine(c).cron_jobs()
        steps = []
        if state.get('cron') and not jobs:
            steps = [_step('Schedule the detection again', 'cron job: %s */15' % common.CRON_COMMAND,
                           'runs every 15 minutes', id='cron'),
                     _step('Apply the cron configuration', 'configctl cron restart', 'cron reloads', id='cron_restart')]
        return _plan(steps, warnings=['the deleted store can not be restored'] if state.get('purged') else [])

    def revert_apply(self, entry):
        c = ctx()
        plan = self.revert_plan(entry)
        completed = []
        if plan['steps']:
            store_mod.Store(c.db).close()
            php(c, 'cron_add')
            completed.append('cron_add')
            configctl(c, 'cron', 'restart')
            completed.append('configctl cron restart')
        return {'status': 'ok', 'done': True, 'completed': completed, 'steps': plan['steps']}


# ------------------------------------------------------------------ findings


def _open_store(c):
    if not os.path.exists(c.db):
        raise ValueError('the anomaly detection is not installed yet (no store)')
    return store_mod.Store(c.db)


def _exception_for(f, scope):
    if scope == 'finding':
        return f['type'], f['host'], f['key'] or ''
    if scope == 'host':
        return f['type'], f['host'], '*'
    return '*', f['host'], '*'


@changes.register
class AnomalyExpect(changes.ChangeAction):
    name = 'anomaly_expect'
    description = 'Anomalies: mark a finding as expected (exception)'

    def parse_args(self, args):
        if len(args) < 2 or not common.ID_RE.match(args[0] or '') or args[1] not in SCOPES:
            raise ValueError('usage: anomaly_expect <finding id> <finding|host|all> [comment base64]')
        return {'fid': args[0], 'scope': args[1], 'comment': _decode_comment(args[2] if len(args) > 2 else '-')}

    def _matching(self, st, kind, host, key):
        rows = st.db.execute("SELECT id, status, exception_id, type, host, key, mac FROM findings "
                             "WHERE status = 'open'").fetchall()
        exc = {'type': kind, 'host': host, 'key': key}
        return [dict(r) for r in rows if engine_mod.match_exception(dict(r), [dict(exc, id=0)])]

    def plan(self, fid, scope, comment):
        c = ctx()
        st = _open_store(c)
        try:
            f = st.finding(fid)
            if f is None:
                raise ValueError('finding not found')
            kind, host, key = _exception_for(f, scope)
            match = self._matching(st, kind, host, key)
        finally:
            st.close()
        what = {'finding': 'this %s finding of %s (%s)' % (f['type'], host, key or 'any'),
                'host': 'every %s finding of %s' % (f['type'], host),
                'all': 'every finding of %s' % host}[scope]
        steps = [_step('Add an exception', 'exception: type=%s host=%s key=%s comment="%s"' % (kind, host, key,
                                                                                             comment),
                       'matching findings are recorded as "expected" (kept in the history, out of the open list)'),
                 _step('Mark %d open finding(s) as expected' % len(match),
                       'findings: %s' % (', '.join(m['id'] for m in match[:10]) or '-'), 'status expected')]
        return _plan(steps, risk='low', info=[{'title': 'Scope', 'items': [what]}],
                     warnings=['an exception hides future findings of the same kind; review it in Exceptions'],
                     revert=['Undo deletes the exception and reopens these findings'])

    def apply(self, fid, scope, comment):
        c = ctx()
        st = _open_store(c)
        try:
            f = st.finding(fid)
            if f is None:
                raise ValueError('finding not found')
            kind, host, key = _exception_for(f, scope)
            st.begin()
            match = self._matching(st, kind, host, key)
            exc_id = st.add_exception(kind, host, key, comment, c.clock(), finding_id=fid)
            for m in match:
                st.set_status(m['id'], 'expected', exc_id)
            st.commit()
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['exception %d' % exc_id, '%d finding(s)' % len(match)],
                'steps': [], 'args': {'fid': fid, 'scope': scope, 'comment': comment},
                'state': {'exception': exc_id, 'findings': [[m['id'], m['status'], m['exception_id']]
                                                            for m in match]}}

    def revert_plan(self, entry):
        state = entry.get('state') or {}
        return _plan([_step('Disable exception %s' % state.get('exception'), 'exception: active = 0', 'stops matching'),
                      _step('Reopen %d finding(s)' % len(state.get('findings') or []), 'status open', 'back in the list')])

    def revert_apply(self, entry):
        c = ctx()
        state = entry.get('state') or {}
        st = _open_store(c)
        try:
            st.begin()
            st.set_exception_active(state.get('exception'), False)
            for fid, status, exc in state.get('findings') or []:
                st.set_status(fid, status, exc)
            st.commit()
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['exception disabled', 'findings reopened'], 'steps': []}


@changes.register
class AnomalyExceptionDel(changes.ChangeAction):
    name = 'anomaly_exception_del'
    description = 'Anomalies: delete an exception'

    def parse_args(self, args):
        if not args or not (args[0] or '').isdigit():
            raise ValueError('usage: anomaly_exception_del <exception id>')
        return {'exc_id': int(args[0])}

    def plan(self, exc_id):
        c = ctx()
        st = _open_store(c)
        try:
            row = st.db.execute('SELECT * FROM exceptions WHERE id = ? AND active = 1', (exc_id,)).fetchone()
        finally:
            st.close()
        if row is None:
            return _plan([])
        return _plan([_step('Delete exception %d' % exc_id, 'exception: type=%s host=%s key=%s' % (
            row['type'], row['host'], row['key']), 'new findings of this kind are open again')],
            revert=['Undo enables the exception again'])

    def apply(self, exc_id):
        c = ctx()
        st = _open_store(c)
        try:
            st.set_exception_active(exc_id, False)
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['exception %d disabled' % exc_id], 'steps': [],
                'args': {'exc_id': exc_id}, 'state': {'exception': exc_id}}

    def revert_plan(self, entry):
        return _plan([_step('Enable exception %s again' % (entry.get('state') or {}).get('exception'),
                            'exception: active = 1', 'matches again')])

    def revert_apply(self, entry):
        c = ctx()
        st = _open_store(c)
        try:
            st.set_exception_active((entry.get('state') or {}).get('exception'), True)
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['exception enabled'], 'steps': []}


@changes.register
class AnomalyResolve(changes.ChangeAction):
    name = 'anomaly_resolve'
    description = 'Anomalies: close a finding (a new occurrence reopens it)'

    def parse_args(self, args):
        if not args or not common.ID_RE.match(args[0] or ''):
            raise ValueError('usage: anomaly_resolve <finding id>')
        return {'fid': args[0]}

    def plan(self, fid):
        c = ctx()
        st = _open_store(c)
        try:
            f = st.finding(fid)
        finally:
            st.close()
        if f is None:
            raise ValueError('finding not found')
        if f['status'] == 'resolved':
            return _plan([])
        return _plan([_step('Close the finding', 'finding %s: status %s -> resolved' % (fid, f['status']),
                            'out of the open list until it happens again')], revert=['Undo restores the status'])

    def apply(self, fid):
        c = ctx()
        st = _open_store(c)
        try:
            f = st.finding(fid)
            if f is None:
                raise ValueError('finding not found')
            st.set_status(fid, 'resolved', f.get('exception_id'))
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['finding %s resolved' % fid], 'steps': [],
                'args': {'fid': fid}, 'state': {'fid': fid, 'status': f['status'], 'exception': f.get('exception_id')}}

    def revert_plan(self, entry):
        return _plan([_step('Restore the status', 'status %s' % (entry.get('state') or {}).get('status'), '')])

    def revert_apply(self, entry):
        c = ctx()
        state = entry.get('state') or {}
        st = _open_store(c)
        try:
            st.set_status(state.get('fid'), state.get('status'), state.get('exception'))
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['status restored'], 'steps': []}


@changes.register
class AnomalySettings(changes.ChangeAction):
    name = 'anomaly_settings'
    description = 'Anomalies: change detector parameters'

    def parse_args(self, args):
        token = args[0] if args else ''
        if not SETTINGS_RE.match(token or ''):
            raise ValueError('usage: anomaly_settings key=value[:key=value...]')
        values = {}
        for part in token.split(':'):
            key, _sep, value = part.partition('=')
            values[key] = common.validate_setting(key, value)
        return {'values': values}

    def plan(self, values):
        c = ctx()
        st = _open_store(c)
        try:
            current = common.effective_settings(st.settings())
        finally:
            st.close()
        steps = [_step('Set %s' % k, '%s: %s -> %s' % (k, current[k], v), common.PARAMS[k][3],
                       already=current[k] == v) for k, v in values.items()]
        return _plan(steps, revert=['Undo restores the previous values'])

    def apply(self, values):
        c = ctx()
        st = _open_store(c)
        try:
            stored = st.settings()
            previous = {k: stored.get(k) for k in values}
            for k, v in values.items():
                st.set_setting(k, None if v == common.DEFAULTS[k] else v)
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['%s=%s' % kv for kv in values.items()], 'steps': [],
                'args': {'values': values}, 'state': {'previous': previous}}

    def revert_plan(self, entry):
        prev = (entry.get('state') or {}).get('previous') or {}
        return _plan([_step('Restore %s' % k, '%s = %s' % (k, v if v is not None else 'default'), '')
                      for k, v in prev.items()])

    def revert_apply(self, entry):
        c = ctx()
        st = _open_store(c)
        try:
            for k, v in ((entry.get('state') or {}).get('previous') or {}).items():
                st.set_setting(k, v)
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['settings restored'], 'steps': []}


NAMES = ('install_anomalies', 'remove_anomalies', 'anomaly_expect', 'anomaly_exception_del', 'anomaly_resolve',
         'anomaly_settings')
