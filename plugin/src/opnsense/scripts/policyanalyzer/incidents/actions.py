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

    Change actions of the incident triage (plan -> apply -> revert through ai/changes.py, journaled in
    /var/db/policyanalyzer/undo/<id>.json, listed in the Action history of the Policy Analyzer page).

      install_incidents                  the database and the cron job "pa_incidents run" every 5 minutes
                                         (System: Settings: Cron, through the core model, incidents/model.php)
      remove_incidents                   removes the cron job; the database (the history) is kept
      incident_state <id> <state> <note> state of a case: new | investigating | resolved | false_positive,
                                         optional note (base64 or "-")
      incident_note <id> <note>          note on a case (base64)

    Nothing here touches the filter, a rule, an alias or a pf table.  The quarantine of an address suggested by
    a case is the existing quarantine_add action of the quarantine (simulated in the same dialog).
"""

import base64
import os

from quarantine import actions as qactions, fwconfig

from . import common, store as store_mod

try:
    from ai.changes import ChangeAction, register
except ImportError:                                  # pragma: no cover - standalone use
    class ChangeAction:                              # noqa: D101
        name = ''
        description = ''
        revertible = True

    def register(cls):
        return cls

CONTEXT_FACTORY = common.Context                     # replaced by the tests

_step = qactions._step
_plan = qactions._plan


def _ctx():
    return CONTEXT_FACTORY()


def _crons(ctx):
    try:
        cfg = fwconfig.FirewallConfig(ctx.config_xml)
    except ValueError:
        return []
    return [j for j in cfg.cron_jobs() if j['command'] == common.CRON_COMMAND]


def decode_note(token, required=False):
    if not token or token == '-':
        if required:
            raise common.IncidentError('a note is required')
        return None
    try:
        text = base64.b64decode(token.encode(), validate=True).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise common.IncidentError('invalid note')
    text = common.clean_text(text, common.NOTE_MAX)
    if required and not text:
        raise common.IncidentError('a note is required')
    return text or None


# ====================================================================== install / remove


@register
class InstallIncidents(ChangeAction):
    name = 'install_incidents'
    description = 'Incidents: create the case database and the cron job (correlation every 5 minutes)'

    def parse_args(self, args):
        if args and args[0]:
            raise ValueError('install_incidents takes no arguments')
        return {}

    def build(self, ctx):
        crons = _crons(ctx)
        db = os.path.exists(ctx.db)
        steps = [
            _step('Create the case database', 'sqlite3 %s (WAL, 0640)' % ctx.db,
                  'cases, evidence, notes, AI summaries kept forever; observations 48 h, baselines 8 days',
                  already=db, id='db'),
            _step('Schedule the correlation every 5 minutes (System: Settings: Cron)',
                  'cron job: %s "%s", minutes %s, hours *' % (common.CRON_COMMAND, common.CRON_DESCR,
                                                             common.CRON_MINUTES),
                  'reads the new log lines, quarantine offenses and DNS blocks, correlates them into cases (<= 20 s)',
                  already=bool(crons), id='cron'),
            _step('Apply the cron configuration', 'configctl cron restart', 'cron reloads its table',
                  already=bool(crons), id='cron_restart'),
        ]
        info = [{'title': 'Correlation rules', 'items': [
            'scan_then_allowed: port scan followed by an allowed inbound connection from the same address',
            'ids_and_allowed: Suricata alert and allowed traffic of the same external address',
            'internal_to_bad: internal host talking to a quarantined address, blocked by a rule or by the DNS '
            'blocklist',
            'campaign: many sources against one port, compared with its usual hour',
            'repeat_offender: an address back in quarantine after the previous one expired',
            'port_spike: anomalous number of events on one port (baseline of the last hours)']},
            {'title': 'Read only sources', 'items': [
                ctx.filter_log, ctx.eve, ctx.quarantine_db + ' (read only)',
                ctx.unbound_db + (' (present)' if os.path.exists(ctx.unbound_db) else ' (not present: DNS skipped)')]},
            {'title': 'The AI', 'items': [
                'Summaries and the daily digest are asked from the AI only when you press the buttons',
                'Suggested actions are buttons that open the usual simulation; nothing runs automatically']}]
        return _plan(steps, risk='low', info=info,
                     revert=['Undo removes the cron job created here; the case database is kept'])

    def plan(self):
        return self.build(_ctx())

    def apply(self):
        ctx = _ctx()
        plan = self.build(ctx)
        completed, created = [], {'db': False, 'cron': None}
        todo = [s for s in plan['steps'] if s['effect'] != 'already done']
        try:
            if not os.path.exists(ctx.db):
                store_mod.Store(ctx.db, create=True).close()
                created['db'] = True
                completed.append('Create the case database')
            if not _crons(ctx):
                created['cron'] = qactions.php(ctx, 'cron_add').get('uuid')
                completed.append('Schedule the correlation every 5 minutes (System: Settings: Cron)')
                qactions.configctl(ctx, 'cron', 'restart')
                completed.append('Apply the cron configuration')
        except (ValueError, OSError):
            if created['cron']:
                try:
                    qactions.php(ctx, 'cron_del', created['cron'])
                except ValueError:
                    pass
            raise
        out = dict(plan, done=True, completed=completed, state={'created': created})
        out['steps'] = plan['steps'] if todo else []
        return out

    def revert_plan(self, entry, flags=None):
        ctx = _ctx()
        created = (entry.get('state') or {}).get('created') or {}
        steps = []
        job = next((j for j in _crons(ctx) if j['uuid'] == created.get('cron')), None)
        if job:
            steps.append(_step('Remove the cron job', 'System: Settings: Cron: delete %s' % job['uuid'],
                               'no more correlation runs', id='cron', uuid=job['uuid']))
            steps.append(_step('Apply the cron configuration', 'configctl cron restart', 'cron reloads',
                               id='cron_restart'))
        warnings = ['the case database is kept (history)'] if created.get('db') else []
        return _plan(steps, warnings=warnings, risk='low')

    def revert_apply(self, entry, flags=None):
        ctx = _ctx()
        plan = self.revert_plan(entry, flags)
        completed = []
        created = (entry.get('state') or {}).get('created') or {}
        job = next((j for j in _crons(ctx) if j['uuid'] == created.get('cron')), None)
        if job:
            qactions.php(ctx, 'cron_del', job['uuid'])
            completed.append('Remove the cron job')
            qactions.configctl(ctx, 'cron', 'restart')
            completed.append('Apply the cron configuration')
        return dict(plan, status='ok', done=True, completed=completed)


@register
class RemoveIncidents(ChangeAction):
    name = 'remove_incidents'
    description = 'Incidents: remove the cron job (the case database is kept)'

    def parse_args(self, args):
        if args and args[0]:
            raise ValueError('remove_incidents takes no arguments')
        return {}

    def build(self, ctx):
        crons = _crons(ctx)
        steps = [_step('Remove the cron job', 'System: Settings: Cron: delete %s' % j['uuid'], 'no more runs',
                       id='cron', uuid=j['uuid']) for j in crons]
        if crons:
            steps.append(_step('Apply the cron configuration', 'configctl cron restart', 'cron reloads',
                               id='cron_restart'))
        return _plan(steps, risk='low', warnings=['the case database (%s) is kept' % ctx.db],
                     revert=['Undo schedules the correlation again'])

    def plan(self):
        return self.build(_ctx())

    def apply(self):
        ctx = _ctx()
        plan = self.build(ctx)
        completed, removed = [], []
        for job in _crons(ctx):
            qactions.php(ctx, 'cron_del', job['uuid'])
            removed.append(job['uuid'])
            completed.append('Remove the cron job')
        if removed:
            qactions.configctl(ctx, 'cron', 'restart')
            completed.append('Apply the cron configuration')
        return dict(plan, done=True, completed=completed, state={'removed': removed})

    def revert_plan(self, entry, flags=None):
        ctx = _ctx()
        removed = (entry.get('state') or {}).get('removed') or []
        steps = []
        if removed and not _crons(ctx):
            steps.append(_step('Schedule the correlation again (cron */5)', 'cron job: %s' % common.CRON_COMMAND,
                               'runs every 5 minutes', id='cron_add'))
            steps.append(_step('Apply the cron configuration', 'configctl cron restart', 'cron reloads',
                               id='cron_restart'))
        return _plan(steps, risk='low')

    def revert_apply(self, entry, flags=None):
        ctx = _ctx()
        plan = self.revert_plan(entry, flags)
        completed = []
        if plan['steps']:
            qactions.php(ctx, 'cron_add')
            completed.append('Schedule the correlation again (cron */5)')
            qactions.configctl(ctx, 'cron', 'restart')
            completed.append('Apply the cron configuration')
        return dict(plan, status='ok', done=True, completed=completed)


# ====================================================================== cases


def _open_case(ctx, case_id):
    if not os.path.exists(ctx.db):
        raise common.IncidentError('the incident triage is not installed')
    st = store_mod.Store(ctx.db)
    case = st.case(case_id)
    if case is None:
        st.close()
        raise common.IncidentError('case %d not found' % case_id)
    return st, case


@register
class IncidentState(ChangeAction):
    name = 'incident_state'
    description = 'Incidents: change the state of a case (new, in analysis, resolved, false positive)'

    def parse_args(self, args):
        args = list(args) + ['', '', '']
        state = args[1]
        if state not in common.STATES:
            raise common.IncidentError('invalid state (%s)' % ', '.join(common.STATES))
        return {'case_id': common.valid_case_id(args[0]), 'state': state, 'note': decode_note(args[2])}

    def plan(self, case_id, state, note=None):
        st, case = _open_case(_ctx(), case_id)
        st.close()
        steps = []
        if case['state'] != state:
            steps.append(_step('Case #%d: %s -> %s' % (case_id, case['state'], state),
                               'incidents.db: cases.state', 'recorded in the case history and the action history'))
        if note:
            steps.append(_step('Add a note to case #%d' % case_id, 'incidents.db: notes', note[:80]))
        warnings = []
        if state == 'false_positive':
            warnings.append('new matches of %s during the next 7 days are added to this case without reopening it' %
                            case['primary_value'])
        return _plan(steps, risk='none' if not steps else 'low', warnings=warnings,
                     revert=['Undo restores the previous state (%s) and removes the note' % case['state']],
                     args={'case_id': case_id, 'state': state, 'note': bool(note)})

    def apply(self, case_id, state, note=None):
        ctx = _ctx()
        plan = self.plan(case_id, state, note)
        st, case = _open_case(ctx, case_id)
        now = ctx.clock()
        completed, note_id = [], None
        try:
            st.begin()
            if case['state'] != state:
                st.update_case(case_id, state=state, updated=int(now))
                st.log(case_id, now, 'state', from_state=case['state'], to_state=state, note=note)
                completed.append('Case #%d: %s -> %s' % (case_id, case['state'], state))
            if note:
                note_id = st.add_note(case_id, now, note)
                if case['state'] == state:
                    st.log(case_id, now, 'note', note=note)
                completed.append('Add a note to case #%d' % case_id)
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
        return dict(plan, done=True, completed=completed,
                    state={'case_id': case_id, 'previous': case['state'], 'state': state, 'note_id': note_id})

    def revert_plan(self, entry, flags=None):
        s = entry.get('state') or {}
        st, case = _open_case(_ctx(), int(s.get('case_id') or 0))
        st.close()
        steps = []
        if case['state'] != s.get('previous'):
            steps.append(_step('Case #%d: %s -> %s' % (case['id'], case['state'], s.get('previous')),
                               'incidents.db: cases.state', 'previous state restored'))
        if s.get('note_id'):
            steps.append(_step('Remove the note of this change', 'incidents.db: notes (hidden, kept)', 'note hidden'))
        warnings = []
        if case['state'] != s.get('state'):
            warnings.append('the case changed again after this action (now %s)' % case['state'])
        return _plan(steps, risk='none' if not steps else 'low', warnings=warnings)

    def revert_apply(self, entry, flags=None):
        ctx = _ctx()
        s = entry.get('state') or {}
        plan = self.revert_plan(entry, flags)
        st, case = _open_case(ctx, int(s.get('case_id') or 0))
        now = ctx.clock()
        completed = []
        try:
            st.begin()
            if s.get('previous') in common.STATES and case['state'] != s['previous']:
                st.update_case(case['id'], state=s['previous'], updated=int(now))
                st.log(case['id'], now, 'state', from_state=case['state'], to_state=s['previous'],
                       note='reverted from the action history', journal_id=entry.get('id'))
                completed.append('Case #%d: %s -> %s' % (case['id'], case['state'], s['previous']))
            if s.get('note_id'):
                st.delete_note(s['note_id'])
                completed.append('Remove the note of this change')
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
        return dict(plan, status='ok', done=True, completed=completed)


@register
class IncidentNote(ChangeAction):
    name = 'incident_note'
    description = 'Incidents: add a note to a case'

    def parse_args(self, args):
        args = list(args) + ['', '']
        return {'case_id': common.valid_case_id(args[0]), 'note': decode_note(args[1], required=True)}

    def plan(self, case_id, note):
        st, _case = _open_case(_ctx(), case_id)
        st.close()
        return _plan([_step('Add a note to case #%d' % case_id, 'incidents.db: notes', note[:80])], risk='low',
                     revert=['Undo hides the note'], args={'case_id': case_id})

    def apply(self, case_id, note):
        ctx = _ctx()
        plan = self.plan(case_id, note)
        st, _case = _open_case(ctx, case_id)
        now = ctx.clock()
        try:
            st.begin()
            note_id = st.add_note(case_id, now, note)
            st.log(case_id, now, 'note', note=note)
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
        return dict(plan, done=True, completed=['Add a note to case #%d' % case_id],
                    state={'case_id': case_id, 'note_id': note_id})

    def revert_plan(self, entry, flags=None):
        return _plan([_step('Hide the note', 'incidents.db: notes (hidden, kept)', 'note hidden')], risk='low')

    def revert_apply(self, entry, flags=None):
        ctx = _ctx()
        s = entry.get('state') or {}
        st, case = _open_case(ctx, int(s.get('case_id') or 0))
        try:
            st.begin()
            st.delete_note(int(s.get('note_id') or 0))
            st.log(case['id'], ctx.clock(), 'note', note='note hidden (reverted)', journal_id=entry.get('id'))
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
        return dict(self.revert_plan(entry), status='ok', done=True, completed=['Hide the note'])


@register
class TidyRepeatOffenders(ChangeAction):
    """ resolve the open low cases made only by the repeat_offender rule below a quarantine level (noise) """
    name = 'incidents_tidy'
    description = 'Incidents: resolve the open low cases of short repeat quarantines (noise)'

    def parse_args(self, args):
        return {}

    def _targets(self, st, max_level):
        rows = st.db.execute(
            "SELECT c.id, c.state, c.primary_value FROM cases c WHERE c.state IN ('new', 'investigating') "
            "AND c.severity = 'low' AND c.rule = 'repeat_offender' "
            "AND NOT EXISTS (SELECT 1 FROM case_rules r WHERE r.case_id = c.id AND r.rule != 'repeat_offender') "
            "ORDER BY c.id").fetchall()
        return [dict(r) for r in rows]

    def plan(self):
        ctx = _ctx()
        if not os.path.exists(ctx.db):
            raise common.IncidentError('the incident triage is not installed')
        st = store_mod.Store(ctx.db, readonly=True)
        try:
            level = int(st.settings().get('repeat_min_level', 3))
            targets = self._targets(st, level)
        finally:
            st.close()
        steps = []
        if targets:
            steps.append(_step('Resolve %d open low case(s) made only by short repeat quarantines' % len(targets),
                               'incidents.db: cases.state -> resolved (+ note)',
                               'the addresses stay in the quarantine and in its history; new repeats below level %d '
                               'no longer open cases' % level))
        return _plan(steps, risk='none' if not steps else 'low',
                     revert=['Undo restores the previous state of each case and removes the notes'],
                     args={'count': len(targets)})

    def apply(self):
        ctx = _ctx()
        plan = self.plan()
        st = store_mod.Store(ctx.db)
        now = ctx.clock()
        changed = []
        note = 'Resolved in bulk: short repeat quarantine (routine noise); see the Quarantine tab for the address.'
        try:
            st.begin()
            for c in self._targets(st, 0):
                st.update_case(c['id'], state='resolved', updated=int(now))
                note_id = st.add_note(c['id'], now, note)
                st.log(c['id'], now, 'state', from_state=c['state'], to_state='resolved', note=note)
                changed.append({'id': c['id'], 'previous': c['state'], 'note_id': note_id})
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
        return dict(plan, done=True, completed=['%d case(s) resolved' % len(changed)], state={'changed': changed})

    def revert_plan(self, entry, flags=None):
        n = len((entry.get('state') or {}).get('changed') or [])
        steps = [_step('Restore the previous state of %d case(s)' % n, 'incidents.db: cases.state', 'reopened')] if n else []
        return _plan(steps, risk='none' if not steps else 'low')

    def revert_apply(self, entry, flags=None):
        ctx = _ctx()
        plan = self.revert_plan(entry, flags)
        st = store_mod.Store(ctx.db)
        now = ctx.clock()
        done = 0
        try:
            st.begin()
            for c in (entry.get('state') or {}).get('changed') or []:
                case = st.case(int(c['id']))
                if case and case['state'] == 'resolved' and c.get('previous') in common.STATES:
                    st.update_case(case['id'], state=c['previous'], updated=int(now))
                    st.log(case['id'], now, 'state', from_state='resolved', to_state=c['previous'],
                           note='reverted from the action history', journal_id=entry.get('id'))
                    done += 1
                if c.get('note_id'):
                    st.delete_note(c['note_id'])
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
        return dict(plan, status='ok', done=True, completed=['%d case(s) reopened' % done])
