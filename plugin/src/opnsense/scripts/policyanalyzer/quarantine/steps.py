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

    The installation of the quarantine as steps of the assistant (WIZARD.md, "Quarantine wizard"): every step
    is its own change action (plan -> apply -> revert through ai/changes.py, one journal entry each), so each
    one can be done and undone from the GUI.  Owner's rule: "every step must be done and undone through the GUI".

      qsetup_rule_log <uuid> <on|off>          1 Check: logging of a WireGuard pass rule (the 24 h guard)
      qsetup_ledger [create|detach|purge]      2 Ledger; undo of create removes it only while empty, a ledger
                                                 with history is only disconnected (renamed, kept); deleting
                                                 needs "purge" (double confirmation, irreversible)
      qsetup_aliases [create|remove]           3 Aliases pa_quarantine (External) and pa_never_block (Network)
      qsetup_never_block <add|del> <address>   3 one entry of pa_never_block
      qsetup_rule [create [on|off]|remove]     4 the rule "Max Cyber IA" (+ filter reload)
      qsetup_scenarios <key=value:...|defaults> 5 the settings of the scenarios (stored in the ledger)
      qsetup_schedule [create|remove]          6 cron */5 + boot hook
      qsetup_activate                          7 enable the rule, not paused, first run now; undo = pause

    install_quarantine and remove_quarantine (CLI shortcuts) chain these actions and write one journal entry per
    step plus their own, whose revert reverts those steps in reverse order.
"""

import base64
import ipaddress
import os
import re
import time

from . import actions as A, common, engine as engine_mod, fwconfig, pf, store as store_mod, wizard

ChangeAction = A.ChangeAction
register = A.register

DETACHED_RE = re.compile(r'^%s\d{8}T\d{6}(-\d{1,3})?\.db$' % common.DETACHED_PREFIX)
UUID_RE = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'


def _need(warning, action_id, label, args):
    """ a missing prerequisite: the plan has no steps and the warning brings the button that solves it """
    return {'warning': warning, 'action': {'id': action_id, 'label': label, 'args': list(args)}}


def _todo(steps):
    return [s for s in steps if not s.get('already')]


def _usage(ctx):
    st = store_mod.Store(ctx.db)
    try:
        return wizard.ledger_usage(st, ctx.clock())
    finally:
        st.close()


def _reload(ctx):
    A.configctl(ctx, 'filter', 'reload')


class _Step(A._Base):
    """ build() describes the steps (shared by plan, apply and the composites), execute() runs them """
    modes = ('create',)
    risk = 'low'

    def parse_args(self, args):
        mode = args[0] if args and args[0] else self.modes[0]
        if mode not in self.modes:
            raise ValueError('mode: %s' % ' | '.join(self.modes))
        if len([a for a in args if a]) > 1:
            raise ValueError('too many arguments')
        return {'mode': mode}

    def build(self, ctx, **kw):
        raise NotImplementedError

    def execute(self, ctx, built, **kw):
        """ :return: {"completed": [...], "state": {...}} or raise QuarantineError / OSError """
        raise NotImplementedError

    def plan(self, **kw):
        ctx = self.ctx()
        b = self.build(ctx, **kw)
        return A._plan(b['steps'], b.get('warnings'), risk=b.get('risk', self.risk), revert=b.get('revert'),
                       info=b.get('info'), double=b.get('double', False), irreversible=b.get('irreversible'),
                       warning_actions=b.get('warning_actions', []))

    def apply(self, **kw):
        ctx = self.ctx()
        if not ctx.is_root:
            return {'status': 'error', 'message': 'apply must run as root (configd)'}
        b = self.build(ctx, **kw)
        if b.get('blocked'):
            return {'status': 'error', 'done': False, 'message': b['warning_actions'][0]['warning'],
                    'warning_actions': b['warning_actions']}
        if not _todo(b['steps']):
            return {'status': 'ok', 'done': True, 'completed': [], 'warnings': ['nothing to do']}
        try:
            res = self.execute(ctx, b, **kw)
        except (common.QuarantineError, OSError) as exc:
            return {'status': 'error', 'done': False, 'completed': [], 'message': str(exc)}
        out = {'status': 'ok', 'done': True, 'completed': res['completed'], 'state': res.get('state', {}),
               'warnings': res.get('warnings', b.get('warnings') or []), 'irreversible': b.get('irreversible') or []}
        out.update(res.get('extra', {}))
        return out

    # revert: implemented through rbuild(entry, flags) -> built, rexecute(ctx, built, entry, flags)
    def rbuild(self, ctx, entry, flags):
        raise ValueError('this change can not be reverted')

    def rexecute(self, ctx, built, entry, flags):
        raise NotImplementedError

    def revert_plan(self, entry, flags=None):
        ctx = self.ctx()
        b = self.rbuild(ctx, entry, flags or {})
        return A._plan(b['steps'], b.get('warnings'), risk=b.get('risk', self.risk), revert=b.get('revert'),
                       info=b.get('info'), double=b.get('double', False), irreversible=b.get('irreversible'),
                       warning_actions=b.get('warning_actions', []))

    def revert_apply(self, entry, flags=None):
        ctx = self.ctx()
        b = self.rbuild(ctx, entry, flags or {})
        if b.get('blocked'):
            return {'status': 'error', 'done': False, 'message': b['warning_actions'][0]['warning']}
        if not _todo(b['steps']):
            return {'status': 'ok', 'done': True, 'completed': ['nothing left to undo'], 'warnings': b.get('warnings')}
        try:
            res = self.rexecute(ctx, b, entry, flags or {})
        except (common.QuarantineError, OSError) as exc:
            return {'status': 'error', 'done': False, 'message': str(exc)}
        return {'status': 'ok', 'done': True, 'completed': res['completed'], 'warnings': res.get('warnings', [])}


# ====================================================================== 1 check: WireGuard rule logging


@register
class SetupRuleLog(_Step):
    name = 'qsetup_rule_log'
    description = 'Quarantine setup 1 (Check): log a WireGuard pass rule (24 h guard of WireGuard clients)'

    def parse_args(self, args):
        args = list(args) + ['', '']
        if not re.match(UUID_RE, args[0] or ''):
            raise ValueError('invalid rule uuid')
        if args[1] not in ('on', 'off'):
            raise ValueError('on | off')
        return {'uuid': args[0], 'value': args[1]}

    def _rule(self, ctx, uuid):
        cfg = A._engine(ctx).config()
        rule = next((r for r in cfg.rules() if r['uuid'] == uuid), None)
        if rule is None:
            raise ValueError('rule %s not found' % uuid)
        return cfg, rule

    def build(self, ctx, uuid, value):
        cfg, rule = self._rule(ctx, uuid)
        if rule['action'] != 'pass' or rule['description'] == common.RULE_DESCR:
            raise ValueError('only the logging of a pass rule can be changed here')
        on = value == 'on'
        if on and not rule['log'] and rule not in wizard.wireguard_unlogged(cfg):
            raise ValueError('the rule is not a WAN pass rule to a WireGuard port')
        already = rule['log'] == on
        name = rule['description'] or rule['uuid']
        steps = [A._step('%s logging of the rule "%s" (sequence %d)' % ('Enable' if on else 'Disable', name,
                                                                     rule['sequence']),
                         'Firewall: Rules (model OPNsense\\Firewall\\Filter): %s log = %d' % (uuid, int(on)),
                         'allowed WireGuard clients appear in the filter log and stay protected for 24 h' if on
                         else 'the rule stops logging', already=already),
                 A._step('Reload the rules', 'configctl filter reload', 'existing states are kept', already=already)]
        return {'steps': steps, 'rule': rule, 'revert': ['Undo sets the logging back to %s' % ('off' if on else 'on')],
                'warnings': ['about one log line per WireGuard handshake is added to the filter log'] if on else []}

    def execute(self, ctx, b, uuid, value):
        A.php(ctx, 'rule_log', uuid, '1' if value == 'on' else '0')
        _reload(ctx)
        return {'completed': ['logging of "%s" %s' % (b['rule']['description'] or uuid, value), 'rules reloaded'],
                'state': {'uuid': uuid, 'before': b['rule']['log']}}

    def rbuild(self, ctx, entry, flags):
        state = entry.get('state') or {}
        b = self.build(ctx, state.get('uuid'), 'on' if state.get('before') else 'off')
        b['revert'] = []
        return b

    def rexecute(self, ctx, b, entry, flags):
        state = entry.get('state') or {}
        return self.execute(ctx, b, state.get('uuid'), 'on' if state.get('before') else 'off')


# ====================================================================== 2 ledger


def _rule_blocks(ctx, cfg, what):
    if cfg.quarantine_rules():
        return _need('Remove the rule "%s" first (step 4): without the ledger nobody would expire its entries (%s).' %
                     (common.RULE_DESCR, what), 'qsetup_rule', 'Remove the rule (simulate first)', ['remove'])
    return None


def _detach(ctx):
    lock = engine_mod.Lock(ctx.lock_file)
    lock.acquire(wait=25)
    try:
        st = store_mod.Store(ctx.db)
        try:
            st.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        finally:
            st.close()
        stamp = time.strftime('%Y%m%dT%H%M%S', time.localtime(ctx.clock()))
        archive = os.path.join(ctx.state_dir, '%s%s.db' % (common.DETACHED_PREFIX, stamp))
        n = 1
        while os.path.exists(archive):
            n += 1
            archive = os.path.join(ctx.state_dir, '%s%s-%d.db' % (common.DETACHED_PREFIX, stamp, n))
        os.rename(ctx.db, archive)
        for suffix in ('-wal', '-shm'):
            if os.path.exists(ctx.db + suffix):
                os.unlink(ctx.db + suffix)
    finally:
        lock.release()
    return archive


def _delete_ledger(ctx, lookup=True):
    removed = []
    for path in (ctx.db, ctx.db + '-wal', ctx.db + '-shm') + ((ctx.lookup_db,) if lookup else ()):
        if os.path.exists(path):
            os.unlink(path)
            removed.append(os.path.basename(path))
    return removed


def _flush_table(ctx):
    try:
        pf.Table(ctx).flush()
    except common.QuarantineError:
        pass                                    # table not loaded: nothing to empty


@register
class SetupLedger(_Step):
    name = 'qsetup_ledger'
    description = 'Quarantine setup 2 (Ledger): create, connect again, disconnect or delete the quarantine database'
    modes = ('create', 'attach', 'detach', 'purge')

    def parse_args(self, args):
        args = [a for a in args if a]
        mode = args[0] if args else 'create'
        if mode not in self.modes:
            raise ValueError('mode: create | attach <name> | detach | purge')
        if mode == 'attach':
            if len(args) != 2 or not DETACHED_RE.match(args[1]):
                raise ValueError('attach needs the name of a disconnected ledger (%s<date>.db)' %
                                 common.DETACHED_PREFIX)
            return {'mode': mode, 'name': args[1]}
        if len(args) > 1:
            raise ValueError('too many arguments')
        return {'mode': mode}

    def build(self, ctx, mode, name=None, assume_no_rule=False):
        exists = os.path.exists(ctx.db)
        if mode == 'attach':
            path = os.path.join(ctx.state_dir, name)
            if not os.path.exists(path):
                raise ValueError('%s does not exist' % name)
            if exists:
                return {'steps': [], 'blocked': True, 'warning_actions': [_need(
                    'A ledger is connected (%s): disconnect it first to connect %s.' % (ctx.db, name),
                    'qsetup_ledger', 'Disconnect the current ledger', ['detach'])]}
            return {'steps': [A._step('Connect the ledger %s again' % name, 'mv %s %s' % (path, ctx.db),
                                      'its history and settings are back', id='attach', path=path),
                              A._step('Synchronize the pf table', 'pfctl -t %s ...' % common.ALIAS,
                                      'entries still in quarantine are blocked again (when the rule exists)',
                                      id='sync')],
                    'revert': ['Undo disconnects it again']}
        if mode == 'create':
            warnings, wa = [], []
            detached = wizard.detached_ledgers(ctx)
            if detached and not exists:
                last = detached[-1]
                wa.append(_need('%d disconnected ledger(s) with history are kept (latest: %s, %d bytes): you can '
                                'connect it again instead of creating a new one.' % (len(detached), last['name'],
                                                                                    last['bytes']),
                                'qsetup_ledger', 'Connect %s again' % last['name'], ['attach', last['name']]))
            steps = [A._step('Create the quarantine ledger %s (SQLite, WAL; the history is kept forever)' % ctx.db,
                             'sqlite3 %s (schema %d)' % (ctx.db, store_mod.SCHEMA_VERSION),
                             'new database; the log readers start at the current end of the filter log and eve.json',
                             already=exists, id='db')]
            return {'steps': steps, 'warnings': warnings, 'warning_actions': wa, 'revert': [
                'Undo deletes the ledger only while it is empty; once it holds history Undo only disconnects it '
                '(renamed to %s<date>.db and kept); deleting it needs the explicit option with a double '
                'confirmation' % common.DETACHED_PREFIX]}
        if not exists:
            return {'steps': [], 'warnings': ['there is no ledger at %s' % ctx.db]}
        cfg = A._engine(ctx).config()
        need = None if assume_no_rule else _rule_blocks(ctx, cfg, 'disconnect' if mode == 'detach' else 'delete')
        if need:
            return {'steps': [], 'warning_actions': [need], 'blocked': True}
        usage = _usage(ctx)
        hist = '%d entries, %d offenses%s' % (usage['entries'], usage['offenses'], ', since %s' % usage['history_since']
                                              if usage['history_since'] else '')
        steps = [A._step('Empty the pf table %s' % common.ALIAS, 'pfctl -t %s -T flush' % common.ALIAS,
                         'nothing stays blocked by entries nobody would expire', id='flush')]
        if mode == 'detach':
            steps.append(A._step('Disconnect the ledger (%s): rename it, keep every record' % hist,
                                 'mv %s %s/%s<date>.db' % (ctx.db, ctx.state_dir, common.DETACHED_PREFIX),
                                 'the quarantine is "not installed" for the plugin; Undo connects it again', id='detach'))
            return {'steps': steps, 'usage': usage, 'risk': 'low',
                    'revert': ['Undo renames it back to %s (only while no new ledger exists)' % ctx.db]}
        steps.append(A._step('DELETE the ledger and its whole history (%s)' % hist,
                             'rm %s %s' % (ctx.db, ctx.lookup_db), 'every offense ever recorded is lost', id='purge'))
        return {'steps': steps, 'usage': usage, 'risk': 'high', 'double': True,
                'irreversible': ['the quarantine history (%s) is deleted and can not be restored' % hist]}

    def execute(self, ctx, b, mode, name=None, assume_no_rule=False):
        if mode == 'attach':
            os.rename(b['steps'][0]['path'], ctx.db)
            res = A._engine(ctx).sync()
            return {'completed': ['ledger %s connected again' % name, 'pf table: %s' % res.get('status')],
                    'state': {'attached': name}}
        if mode == 'create':
            st = store_mod.Store(ctx.db, create=True)
            try:
                st.begin()
                st.set_meta('installed', int(ctx.clock()))
                st.set_meta('marker_filter', A._end_marker(ctx.filter_log))
                st.set_meta('marker_eve', A._end_marker(ctx.eve))
                st.set_meta('paused', '0')
                st.commit()
            finally:
                st.close()
            return {'completed': ['ledger %s created (reading starts at the end of the logs)' % ctx.db],
                    'state': {'created': True}}
        _flush_table(ctx)
        if mode == 'detach':
            archive = _detach(ctx)
            return {'completed': ['pf table emptied', 'ledger disconnected: %s' % archive],
                    'state': {'archive': archive}}
        removed = _delete_ledger(ctx)
        return {'completed': ['pf table emptied', 'deleted: %s' % ', '.join(removed)], 'state': {'purged': True}}

    def rbuild(self, ctx, entry, flags):
        state = entry.get('state') or {}
        if state.get('purged'):
            raise ValueError('a deleted ledger can not be restored')
        if state.get('attached'):
            return self.build(ctx, 'detach')
        if state.get('archive'):
            archive = state['archive']
            if not os.path.exists(archive):
                return {'steps': [], 'warnings': ['the disconnected ledger %s does not exist anymore' % archive]}
            if os.path.exists(ctx.db):
                return {'steps': [], 'blocked': True, 'warning_actions': [{
                    'warning': 'A new ledger exists at %s: disconnect it first (step 2) to connect %s again.' % (
                        ctx.db, os.path.basename(archive)),
                    'action': {'id': 'qsetup_ledger', 'label': 'Disconnect the current ledger', 'args': ['detach']}}]}
            return {'steps': [A._step('Connect the ledger %s again' % os.path.basename(archive),
                                      'mv %s %s' % (archive, ctx.db), 'its history and settings are back', id='attach'),
                              A._step('Synchronize the pf table', 'pfctl -t %s ...' % common.ALIAS,
                                      'entries still in quarantine are blocked again', id='sync')]}
        if not os.path.exists(ctx.db):
            return {'steps': [], 'warnings': ['the ledger does not exist anymore']}
        need = _rule_blocks(ctx, A._engine(ctx).config(), 'undo')
        if need:
            return {'steps': [], 'warning_actions': [need], 'blocked': True}
        usage = _usage(ctx)
        purge = bool(flags.get('purge'))
        hist = '%d entries, %d offenses' % (usage['entries'], usage['offenses'])
        if usage['used'] and not purge:
            return {'steps': [A._step('Empty the pf table %s' % common.ALIAS, 'pfctl -t %s -T flush' % common.ALIAS,
                                      'nothing stays blocked', id='flush'),
                              A._step('Disconnect the ledger (it holds history: %s): rename it, keep every record' %
                                      hist, 'mv %s %s/%s<date>.db' % (ctx.db, ctx.state_dir, common.DETACHED_PREFIX),
                                      'kept; step 2 (Ledger) can connect it again', id='detach')],
                    'warning_actions': [{'warning': 'The ledger holds history (%s): Undo only disconnects it.' % hist,
                                         'action': {'id': 'revert', 'label': 'Delete it instead (double confirmation)',
                                                    'args': [entry.get('id'), 'purge']}}]}
        steps = [A._step('Empty the pf table %s' % common.ALIAS, 'pfctl -t %s -T flush' % common.ALIAS, '', id='flush'),
                 A._step('Delete the %s ledger%s' % ('EMPTY' if not usage['used'] else '', ' and its history (%s)' %
                                                     hist if usage['used'] else ''),
                         'rm %s' % ctx.db, 'nothing was recorded in it yet' if not usage['used'] else
                         'every offense ever recorded is lost', id='purge')]
        if usage['used']:
            return {'steps': steps, 'risk': 'high', 'double': True,
                    'irreversible': ['the quarantine history (%s) is deleted and can not be restored' % hist]}
        return {'steps': steps}

    def rexecute(self, ctx, b, entry, flags):
        state = entry.get('state') or {}
        ids = {s['id'] for s in b['steps']}
        if 'attach' in ids:
            os.rename(state['archive'], ctx.db)
            res = A._engine(ctx).sync()
            return {'completed': ['ledger connected again: %s' % ctx.db, 'pf table: +%s' % res.get('added', 0)]}
        _flush_table(ctx)
        if 'detach' in ids:
            return {'completed': ['ledger disconnected: %s' % _detach(ctx)]}
        return {'completed': ['deleted: %s' % ', '.join(_delete_ledger(ctx, lookup=False))]}


# ====================================================================== 3 aliases and pa_never_block


@register
class SetupAliases(_Step):
    name = 'qsetup_aliases'
    description = 'Quarantine setup 3 (Aliases): pa_quarantine (External) and pa_never_block (Network)'
    modes = ('create', 'remove')

    def build(self, ctx, mode, reload=True, assume_no_rule=False):
        cfg = A._engine(ctx).config()
        aliases = cfg.aliases()
        alias_q, alias_n = aliases.get(common.ALIAS), aliases.get(common.NEVER_ALIAS)
        if mode == 'create':
            steps = [
                A._step('Create the alias %s, type External (advanced): its pf table is filled at run time' %
                        common.ALIAS, 'Firewall: Aliases (model OPNsense\\Firewall\\Alias): %s, external, counters' %
                        common.ALIAS, 'table <%s> persist (kept by "filter reload", rebuilt from the ledger at boot)' %
                        common.ALIAS, already=alias_q is not None, id='alias_q'),
                A._step('Create the alias %s, type Network(s), empty: addresses you never want quarantined' %
                        common.NEVER_ALIAS, 'Firewall: Aliases: %s, network' % common.NEVER_ALIAS,
                        'edit it here (step 3) or in Firewall: Aliases; the quarantine reads it on every run',
                        already=alias_n is not None, id='alias_n')]
            if reload:
                steps.append(A._step('Load the alias table', 'configctl filter reload',
                                     'the firewall rules are reloaded once (existing states are kept)',
                                     already=alias_q is not None, id='reload'))
            return {'steps': steps, 'revert': ['Undo removes the aliases created here (not while the rule exists)']}
        need = None if assume_no_rule else _rule_blocks(ctx, cfg, 'it uses %s' % common.ALIAS)
        if need and alias_q is not None:
            return {'steps': [], 'warning_actions': [need], 'blocked': True}
        steps = []
        if alias_q is not None:
            steps.append(A._step('Remove the alias %s' % common.ALIAS, 'Firewall: Aliases: delete %s' % alias_q['uuid'],
                                 'alias deleted', id='alias_q', uuid=alias_q['uuid']))
        if alias_n is not None:
            steps.append(A._step('Remove the alias %s' % common.NEVER_ALIAS, 'Firewall: Aliases: delete %s' %
                                 alias_n['uuid'], 'alias deleted' + (
                                     ' (%d entries saved in the journal, Revert restores them)' % len(alias_n['content'])
                                     if alias_n['content'] else ''), id='alias_n', uuid=alias_n['uuid']))
        if alias_q is not None:
            steps.append(A._step('Reload the rules and drop the pf table', 'configctl filter reload; pfctl -t %s -T kill'
                                 % common.ALIAS, 'the firewall rules are reloaded once', id='reload'))
        return {'steps': steps, 'never_content': alias_n['content'] if alias_n else [],
                'revert': ['Undo creates them again (pa_never_block with its entries)'], 'risk': 'medium'}

    def execute(self, ctx, b, mode, reload=True, assume_no_rule=False):
        completed = []
        if mode == 'create':
            created = {}
            try:
                for step in _todo(b['steps']):
                    if step['id'] == 'alias_q':
                        created['alias_q'] = A.php(ctx, 'alias_add', common.ALIAS).get('uuid')
                    elif step['id'] == 'alias_n':
                        created['alias_n'] = A.php(ctx, 'alias_add', common.NEVER_ALIAS).get('uuid')
                    elif step['id'] == 'reload':
                        _reload(ctx)
                    completed.append(step['description'])
            except (common.QuarantineError, OSError):
                for key in ('alias_n', 'alias_q'):
                    if created.get(key):
                        try:
                            A.php(ctx, 'alias_del', created[key])
                        except common.QuarantineError:
                            pass
                raise
            return {'completed': completed, 'state': {'created': created}}
        removed = {}
        for step in b['steps']:
            if step['id'] in ('alias_q', 'alias_n'):
                A.php(ctx, 'alias_del', step['uuid'])
                removed[step['id']] = True
            elif step['id'] == 'reload':
                _reload(ctx)
                pf.Table(ctx).kill()
            completed.append(step['description'])
        return {'completed': completed, 'state': {'removed': removed, 'never_content': b['never_content']}}

    def rbuild(self, ctx, entry, flags):
        state = entry.get('state') or {}
        cfg = A._engine(ctx).config()
        aliases = cfg.aliases()
        if 'created' in state:
            created = state['created'] or {}
            steps, warnings, double = [], [], False
            if created.get('alias_q') and common.ALIAS in aliases:
                need = _rule_blocks(ctx, cfg, 'it uses %s' % common.ALIAS)
                if need:
                    return {'steps': [], 'warning_actions': [need], 'blocked': True}
                steps.append(A._step('Remove the alias %s' % common.ALIAS, 'Firewall: Aliases: delete %s' %
                                     aliases[common.ALIAS]['uuid'], 'alias deleted', id='alias_q',
                                     uuid=aliases[common.ALIAS]['uuid']))
            if created.get('alias_n') and common.NEVER_ALIAS in aliases:
                content = aliases[common.NEVER_ALIAS]['content']
                if content:
                    double = True
                    warnings.append('%s has %d entr%s now (%s): they are deleted with it' % (
                        common.NEVER_ALIAS, len(content), 'y' if len(content) == 1 else 'ies', ', '.join(content[:10])))
                steps.append(A._step('Remove the alias %s' % common.NEVER_ALIAS, 'Firewall: Aliases: delete %s' %
                                     aliases[common.NEVER_ALIAS]['uuid'], 'alias deleted', id='alias_n',
                                     uuid=aliases[common.NEVER_ALIAS]['uuid']))
            if any(s['id'] == 'alias_q' for s in steps):
                steps.append(A._step('Reload the rules and drop the pf table', 'configctl filter reload; pfctl -t %s '
                                     '-T kill' % common.ALIAS, 'the firewall rules are reloaded once', id='reload'))
            return {'steps': steps, 'warnings': warnings, 'double': double, 'risk': 'medium'}
        removed = state.get('removed') or {}
        steps = []
        if removed.get('alias_q') and common.ALIAS not in aliases:
            steps.append(A._step('Create the alias %s again (External)' % common.ALIAS, 'Firewall: Aliases',
                                 'pf table loaded by the reload', id='alias_q'))
        if removed.get('alias_n') and common.NEVER_ALIAS not in aliases:
            steps.append(A._step('Create the alias %s again with its %d entr%s' % (
                common.NEVER_ALIAS, len(state.get('never_content') or []),
                'y' if len(state.get('never_content') or []) == 1 else 'ies'), 'Firewall: Aliases',
                ', '.join((state.get('never_content') or [])[:10]) or 'empty', id='alias_n'))
        if any(s['id'] == 'alias_q' for s in steps):
            steps.append(A._step('Load the alias table', 'configctl filter reload', 'rules reloaded once', id='reload'))
        return {'steps': steps}

    def rexecute(self, ctx, b, entry, flags):
        state = entry.get('state') or {}
        completed, warnings = [], []
        for step in b['steps']:
            sid = step['id']
            if 'created' in state:
                if sid in ('alias_q', 'alias_n'):
                    A.php(ctx, 'alias_del', step['uuid'])
                elif sid == 'reload':
                    try:
                        _reload(ctx)
                        pf.Table(ctx).kill()
                    except common.QuarantineError as exc:
                        warnings.append('the aliases are removed but the reload failed (%s): reload the rules in '
                                        'Firewall: Rules' % exc)
                        continue
            else:
                if sid == 'alias_q':
                    A.php(ctx, 'alias_add', common.ALIAS)
                elif sid == 'alias_n':
                    content = state.get('never_content') or []
                    A.php(ctx, 'alias_add', common.NEVER_ALIAS,
                          base64.b64encode('\n'.join(content).encode()).decode() if content else '')
                elif sid == 'reload':
                    _reload(ctx)
            completed.append(step['description'])
        return {'completed': completed, 'warnings': warnings}


def parse_never_value(value):
    """ an address or a network (CIDR) for pa_never_block; :return: pf spelling; ValueError when invalid """
    value = (value or '').strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError('enter an address or a network (CIDR), e.g. 203.0.113.7 or 203.0.113.0/28')
    if net.version == 6 and net.network_address.ipv4_mapped is not None:
        raise ValueError('use the IPv4 form')
    return common.pf_text(net)


@register
class SetupNeverBlock(_Step):
    name = 'qsetup_never_block'
    description = 'Quarantine setup 3 (Aliases): add or remove an entry of pa_never_block'

    def parse_args(self, args):
        args = list(args) + ['', '']
        if args[0] not in ('add', 'del'):
            raise ValueError('add | del')
        return {'op': args[0], 'value': parse_never_value(args[1])}

    def build(self, ctx, op, value):
        cfg = A._engine(ctx).config()
        alias = cfg.aliases().get(common.NEVER_ALIAS)
        if alias is None:
            return {'steps': [], 'blocked': True, 'warning_actions': [_need(
                'The alias %s does not exist yet.' % common.NEVER_ALIAS, 'qsetup_aliases', 'Create the aliases',
                ['create'])]}
        present = value in alias['content']
        warnings = []
        net = ipaddress.ip_network(value, strict=False)
        if op == 'add':
            if not common.network_is_external(net) and not common.is_external(net.network_address):
                warnings.append('%s is not public address space: it is never quarantined anyway' % value)
            if os.path.exists(ctx.db):
                st = store_mod.Store(ctx.db)
                try:
                    entry = st.entry_by_addr(value)
                finally:
                    st.close()
                if entry and entry['state'] in ('active', 'permanent'):
                    warnings.append('%s is in quarantine now: the next run releases it (guard_release)' % value)
        steps = [A._step('%s %s %s %s' % ('Add' if op == 'add' else 'Remove', value, 'to' if op == 'add' else 'from',
                                          common.NEVER_ALIAS),
                         'Firewall: Aliases (model): %s %s= %s' % (common.NEVER_ALIAS, '+' if op == 'add' else '-', value),
                         'never quarantined from the next run on' if op == 'add' else 'it can be quarantined again',
                         already=present if op == 'add' else not present)]
        return {'steps': steps, 'warnings': warnings, 'revert': ['Undo %s it again' % ('removes' if op == 'add'
                                                                                     else 'adds')]}

    def execute(self, ctx, b, op, value):
        A.php(ctx, 'alias_entry', common.NEVER_ALIAS, op, value)
        return {'completed': ['%s %s %s' % (common.NEVER_ALIAS, '+' if op == 'add' else '-', value)],
                'state': {'op': op, 'value': value}}

    def rbuild(self, ctx, entry, flags):
        state = entry.get('state') or {}
        return self.build(ctx, 'del' if state.get('op') == 'add' else 'add', state.get('value'))

    def rexecute(self, ctx, b, entry, flags):
        state = entry.get('state') or {}
        return self.execute(ctx, b, 'del' if state.get('op') == 'add' else 'add', state.get('value'))


# ====================================================================== 4 rule


def _position_info(pos):
    return {'title': 'Rule position', 'items': [
        '%s, sequence %d among %d enabled rules of the group' % (
            'floating' if pos['floating'] else 'interface rule', pos['sequence'], pos['group_size']),
        'precedes the WAN pass rules: %s' % (', '.join('"%s" (%d)' % (r['description'] or r['uuid'], r['sequence'])
                                                       for r in pos['wan_pass_rules']) or 'none')]}


def _end_active(ctx):
    """ end the quarantines in force (event "uninstall"); :return: snapshots for the revert """
    snapshots = []
    if not os.path.exists(ctx.db):
        return snapshots
    st = store_mod.Store(ctx.db)
    now = ctx.clock()
    try:
        st.begin()
        for entry in st.active_entries():
            snapshots.append(A._snapshot(entry))
            st.update_entry(entry['id'], state='expired', until=int(now))
            st.add_event(entry['id'], now, 'uninstall', level=entry['level'], origin='manual')
        st.commit()
    finally:
        st.close()
    return snapshots


@register
class SetupRule(_Step):
    name = 'qsetup_rule'
    description = 'Quarantine setup 4 (Rule): create or remove the rule "Max Cyber IA"'
    modes = ('create', 'remove')
    risk = 'medium'

    def parse_args(self, args):
        args = [a for a in args if a]
        mode = args[0] if args else 'create'
        if mode not in self.modes:
            raise ValueError('mode: create [on|off] | remove')
        if mode == 'create':
            enabled = (args[1] if len(args) > 1 else 'on')
            if enabled not in ('on', 'off') or len(args) > 2:
                raise ValueError('create [on|off]')
            return {'mode': mode, 'enabled': enabled == 'on'}
        if len(args) > 1:
            raise ValueError('too many arguments')
        return {'mode': mode}

    def build(self, ctx, mode, enabled=True, assume_alias=False):
        cfg = A._engine(ctx).config()
        wan = cfg.wan_interfaces()
        rules = cfg.quarantine_rules()
        if mode == 'create':
            if not wan:
                raise ValueError('no WAN interface found in the configuration')
            keys = [w['key'] for w in wan]
            pos = fwconfig.rule_position(cfg, keys)
            if not assume_alias and common.ALIAS not in cfg.aliases():
                return {'steps': [], 'blocked': True, 'info': [_position_info(pos)], 'warning_actions': [_need(
                    'The rule uses the alias %s, which does not exist yet (step 3).' % common.ALIAS,
                    'qsetup_aliases', 'Create the aliases (simulate first)', ['create'])]}
            names = ', '.join('%s (%s, %s)' % (w['descr'], w['key'], w['dev']) for w in wan)
            steps = [
                A._step('Create the rule "%s": block in quick, log, IPv4+IPv6, source %s, on %s%s' % (
                    common.RULE_DESCR, common.ALIAS, names, '' if enabled else ', DISABLED (step 7 turns it on)'),
                    'Firewall: Rules (model OPNsense\\Firewall\\Filter): %s, sequence %d, interfaces %s%s' % (
                        'floating' if pos['floating'] else 'interface rule', pos['sequence'], ','.join(keys),
                        '' if enabled else ', enabled = 0'),
                    'evaluated before %s' % ('; '.join('"%s" (%d)' % (r['description'] or r['uuid'], r['sequence'])
                                                       for r in pos['before']) or 'every other rule of its group'),
                    already=bool(rules), id='rule', sequence=pos['sequence'], interfaces=','.join(keys)),
                A._step('Load the new rule and the alias table', 'configctl filter reload',
                        'the firewall rules are reloaded once (existing states are kept)', already=bool(rules),
                        id='reload')]
            warnings = list(pos['warnings'])
            if rules and rules[0]['enabled'] != enabled:
                warnings.append('the rule already exists and is %s: use step 7 (Activate) or Pause to change it' % (
                    'enabled' if rules[0]['enabled'] else 'disabled'))
            return {'steps': steps, 'warnings': warnings, 'info': [_position_info(pos)], 'pos': pos,
                    'revert': ['Undo removes the rule and reloads the rules']}
        if not rules:
            return {'steps': [], 'warnings': ['the rule "%s" does not exist' % common.RULE_DESCR]}
        steps = []
        active = 0
        if os.path.exists(ctx.db):
            st = store_mod.Store(ctx.db)
            try:
                active = len(st.active_entries())
            finally:
                st.close()
            if active:
                steps.append(A._step('End the %d active quarantine(s) in the ledger (recorded as "uninstall")' % active,
                                     'ledger: state -> expired, event uninstall', 'nothing stays blocked', id='mark'))
        if common.ALIAS in cfg.aliases():
            steps.append(A._step('Empty the pf table %s' % common.ALIAS, 'pfctl -t %s -T flush' % common.ALIAS,
                                 'every quarantined address is unblocked', id='flush'))
        for rule in rules:
            steps.append(A._step('Remove the rule "%s"' % common.RULE_DESCR, 'Firewall: Rules: delete %s' % rule['uuid'],
                                 'rule deleted', id='rule', uuid=rule['uuid']))
        steps.append(A._step('Reload the rules', 'configctl filter reload', 'the firewall rules are reloaded once',
                             id='reload'))
        return {'steps': steps, 'rule': {'sequence': rules[0]['sequence'], 'interfaces': rules[0]['interfaces'],
                                         'enabled': rules[0]['enabled']},
                'revert': ['Undo creates the rule again at the same position and restores the quarantines that are '
                           'still valid']}

    def execute(self, ctx, b, mode, enabled=True, assume_alias=False):
        completed = []
        if mode == 'create':
            step = b['steps'][0]
            uuid = A.php(ctx, 'rule_add', step['sequence'], step['interfaces'], '1' if enabled else '0').get('uuid')
            completed.append(step['description'])
            try:
                _reload(ctx)
            except common.QuarantineError as exc:
                try:
                    A.php(ctx, 'rule_del', uuid)
                except common.QuarantineError:
                    pass
                raise common.QuarantineError('%s (the rule was removed again)' % exc)
            completed.append(b['steps'][1]['description'])
            return {'completed': completed, 'state': {'uuid': uuid, 'sequence': step['sequence'],
                                                      'interfaces': step['interfaces'], 'enabled': enabled}}
        snapshots = []
        for step in b['steps']:
            sid = step['id']
            if sid == 'mark':
                snapshots = _end_active(ctx)
            elif sid == 'flush':
                _flush_table(ctx)
            elif sid == 'rule':
                A.php(ctx, 'rule_del', step['uuid'])
            elif sid == 'reload':
                _reload(ctx)
            completed.append(step['description'])
        return {'completed': completed, 'state': {'rule': b['rule'], 'snapshots': snapshots}}

    def rbuild(self, ctx, entry, flags):
        state = entry.get('state') or {}
        cfg = A._engine(ctx).config()
        rules = cfg.quarantine_rules()
        if 'uuid' in state:
            rule = next((r for r in rules if r['uuid'] == state['uuid']), None)
            if rule is None:
                return {'steps': [], 'warnings': ['the rule created by this step does not exist anymore']}
            warnings = []
            if os.path.exists(ctx.db):
                st = store_mod.Store(ctx.db)
                try:
                    active = len(st.active_entries())
                finally:
                    st.close()
                if active:
                    warnings.append('%d entr%s stay active in the ledger: they are blocked again once the rule exists' %
                                    (active, 'y' if active == 1 else 'ies'))
            return {'steps': [A._step('Remove the rule "%s"' % common.RULE_DESCR, 'Firewall: Rules: delete %s' %
                                      rule['uuid'], 'quarantined addresses are not blocked anymore', id='rule',
                                      uuid=rule['uuid']),
                              A._step('Reload the rules', 'configctl filter reload', 'rules reloaded once', id='reload')],
                    'warnings': warnings, 'risk': 'medium'}
        if rules:
            return {'steps': [], 'warnings': ['the rule "%s" exists again' % common.RULE_DESCR]}
        rule = state.get('rule') or {}
        if common.ALIAS not in cfg.aliases():
            return {'steps': [], 'blocked': True, 'warning_actions': [_need(
                'The rule uses the alias %s, which does not exist (step 3).' % common.ALIAS, 'qsetup_aliases',
                'Create the aliases', ['create'])]}
        snaps = state.get('snapshots') or []
        now = ctx.clock()
        valid = [s for s in snaps if s['before'].get('state') == 'permanent' or (s['before'].get('until') or 0) > now]
        steps = [A._step('Create the rule "%s" again (sequence %s, %s%s)' % (
            common.RULE_DESCR, rule.get('sequence'), ','.join(rule.get('interfaces') or []),
            '' if rule.get('enabled', True) else ', disabled'), 'Firewall: Rules (model)', 'blocks again', id='rule'),
                 A._step('Reload the rules', 'configctl filter reload', 'rules reloaded once', id='reload')]
        if snaps:
            steps.append(A._step('Restore %d quarantine(s) (%d still valid)' % (len(snaps), len(valid)),
                                 'ledger: previous state of the entries', 'the history keeps both records', id='restore'))
            steps.append(A._step('Synchronize the pf table', 'pfctl -t %s ...' % common.ALIAS, 'table = ledger',
                                 id='sync'))
        return {'steps': steps, 'rule': rule}

    def rexecute(self, ctx, b, entry, flags):
        state = entry.get('state') or {}
        completed = []
        for step in b['steps']:
            sid = step['id']
            if sid == 'rule' and 'uuid' in step:
                A.php(ctx, 'rule_del', step['uuid'])
            elif sid == 'rule':
                rule = b['rule']
                A.php(ctx, 'rule_add', rule.get('sequence'), ','.join(rule.get('interfaces') or []),
                      '1' if rule.get('enabled', True) else '0')
            elif sid == 'reload':
                _reload(ctx)
            elif sid == 'restore':
                A._restore_entries(ctx, state.get('snapshots') or [], 'reinstall')
            elif sid == 'sync':
                A._engine(ctx).sync()
            completed.append(step['description'])
        return {'completed': completed}


# ====================================================================== 5 scenarios


@register
class SetupScenarios(_Step):
    name = 'qsetup_scenarios'
    description = 'Quarantine setup 5 (Scenarios): thresholds, bait ports, Suricata, limit'

    def parse_args(self, args):
        args = [a for a in args if a]
        if len(args) != 1:
            raise ValueError('one argument: key=value:key=value... or "defaults"')
        return {'values': wizard.parse_scenarios(args[0])}

    def _current(self, ctx):
        st = store_mod.Store(ctx.db)
        try:
            return st.stored_settings()
        finally:
            st.close()

    def build(self, ctx, values):
        if not os.path.exists(ctx.db):
            return {'steps': [], 'blocked': True, 'warning_actions': [_need(
                'The scenarios are stored in the ledger, which does not exist yet (step 2).', 'qsetup_ledger',
                'Create the ledger (simulate first)', ['create'])]}
        stored = self._current(ctx)
        before = common.effective_settings(stored)
        merged = dict(stored)
        for key, value in values.items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        after = common.effective_settings(merged)
        steps, items, same = [], [], []
        for key in wizard.SCENARIO_KEYS:
            changed = str(before[key]) != str(after[key]) or (key in values and values[key] is None and key in stored)
            if changed:
                items.append('%s: %s -> %s' % (key, before[key], after[key]))
            else:
                same.append('%s: %s (unchanged)' % (key, before[key]))
            if changed:
                steps.append(A._step('Set %s' % key, 'quarantine setting %s = %s' % (
                    key, after[key] if values.get(key) is not None else '(default)'),
                    '%s -> %s' % (before[key], after[key]), key=key, value=values.get(key)))
        prev = wizard.preview(ctx, values, engine_options=A.ENGINE_OPTIONS)
        lines = ['%s — %s, level %s (%s), %d event(s)%s%s' % (
            c['addr'], c['reason'], c['level'], c['level_label'], c['events'], ', ports %s' % c['ports'] if c['ports']
            else '', ' — already in quarantine' if c['already'] else '') for c in prev['candidates']]
        title = 'Preview: with the logs of the last 5 min, %d address(es) would enter%s' % (
            prev['entering'], (' (%s)' % ', '.join('%s %d' % kv for kv in sorted(prev['by_reason'].items())))
            if prev['by_reason'] else '')
        if not prev['complete']:
            title += ' — the log covers only %d s' % prev['log']['covers_seconds']
        if len(lines) > 5:
            lines = lines[:5] + ['... and %d more' % (len(lines) - 5)]
        info = [{'title': 'Before / after', 'items': items or ['nothing changes']},
                {'title': title, 'items': lines or ['nobody']},
                {'title': 'Unchanged', 'items': same}]
        return {'steps': steps, 'info': info, 'stored': stored, 'preview': prev,
                'revert': ['Undo restores the previous values']}

    def execute(self, ctx, b, values):
        st = store_mod.Store(ctx.db)
        previous = {}
        try:
            st.begin()
            for step in _todo(b['steps']):
                key = step['key']
                previous[key] = b['stored'].get(key)
                if step['value'] is None:
                    st.db.execute('DELETE FROM settings WHERE key = ?', (key,))
                else:
                    st.set_setting(key, step['value'])
            st.add_event(None, ctx.clock(), 'settings', origin='manual', note='assistant: %s' % ', '.join(
                '%s %s' % (s['key'], s['effect']) for s in _todo(b['steps'])))
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
        return {'completed': ['%s: %s' % (s['key'], s['effect']) for s in _todo(b['steps'])],
                'state': {'previous': previous}}

    def rbuild(self, ctx, entry, flags):
        previous = (entry.get('state') or {}).get('previous') or {}
        if not os.path.exists(ctx.db):
            return {'steps': [], 'warnings': ['the ledger (where the settings live) does not exist anymore']}
        values = {k: (common.validate_setting(k, v) if v is not None else None) for k, v in previous.items()}
        b = self.build(ctx, values)
        b['revert'] = []
        return b

    def rexecute(self, ctx, b, entry, flags):
        previous = (entry.get('state') or {}).get('previous') or {}
        values = {k: (common.validate_setting(k, v) if v is not None else None) for k, v in previous.items()}
        return self.execute(ctx, b, values)


# ====================================================================== 6 schedule


def _write_syshook(ctx):
    os.makedirs(ctx.syshook_dir, mode=0o755, exist_ok=True)
    with open(ctx.syshook, 'w') as handle:
        handle.write(A.SYSHOOK_BODY)
    os.chmod(ctx.syshook, 0o755)


@register
class SetupSchedule(_Step):
    name = 'qsetup_schedule'
    description = 'Quarantine setup 6 (Schedule): cron every 5 minutes and the boot hook'
    modes = ('create', 'remove')

    def build(self, ctx, mode):
        cfg = A._engine(ctx).config()
        crons = cfg.quarantine_cron()
        hook = os.path.exists(ctx.syshook)
        if mode == 'create':
            steps = [
                A._step('Schedule the quarantine every 5 minutes (System: Settings: Cron)',
                        'cron job: %s %s, minutes %s, hours *' % (common.CRON_COMMAND, common.CRON_DESCR,
                                                                   common.CRON_MINUTES),
                        'reads the last 5 min of logs, applies the scenarios, expires and syncs the pf table (<= 20 s)',
                        already=bool(crons), id='cron'),
                A._step('Apply the cron configuration', 'configctl cron restart', 'cron reloads its table',
                        already=bool(crons), id='cron_restart'),
                A._step('Boot hook: rebuild the pf table from the ledger after a reboot', 'write %s' % ctx.syshook,
                        'configctl policyanalyzer quarantine_sync at the end of the boot', already=hook, id='syshook')]
            return {'steps': steps, 'revert': ['Undo removes the cron job and the boot hook created here']}
        steps = []
        for job in crons:
            steps.append(A._step('Remove the cron job', 'System: Settings: Cron: delete %s' % job['uuid'],
                                 'no more runs', id='cron', uuid=job['uuid']))
        if crons:
            steps.append(A._step('Apply the cron configuration', 'configctl cron restart', 'cron reloads',
                                 id='cron_restart'))
        if hook:
            steps.append(A._step('Remove the boot hook', 'rm %s' % ctx.syshook, 'the table is not rebuilt at boot',
                                 id='syshook'))
        return {'steps': steps, 'revert': ['Undo schedules it again']}

    def execute(self, ctx, b, mode):
        completed = []
        if mode == 'create':
            created = {'cron': None, 'syshook': False}
            try:
                for step in _todo(b['steps']):
                    if step['id'] == 'cron':
                        created['cron'] = A.php(ctx, 'cron_add').get('uuid')
                    elif step['id'] == 'cron_restart':
                        A.configctl(ctx, 'cron', 'restart')
                    elif step['id'] == 'syshook':
                        _write_syshook(ctx)
                        created['syshook'] = True
                    completed.append(step['description'])
            except (common.QuarantineError, OSError):
                if created['cron']:
                    try:
                        A.php(ctx, 'cron_del', created['cron'])
                    except common.QuarantineError:
                        pass
                raise
            return {'completed': completed, 'state': {'created': created}}
        removed = {'cron': False, 'syshook': False}
        for step in b['steps']:
            if step['id'] == 'cron':
                A.php(ctx, 'cron_del', step['uuid'])
                removed['cron'] = True
            elif step['id'] == 'cron_restart':
                A.configctl(ctx, 'cron', 'restart')
            elif step['id'] == 'syshook':
                os.unlink(ctx.syshook)
                removed['syshook'] = True
            completed.append(step['description'])
        return {'completed': completed, 'state': {'removed': removed}}

    def rbuild(self, ctx, entry, flags):
        state = entry.get('state') or {}
        cfg = A._engine(ctx).config()
        crons = cfg.quarantine_cron()
        hook = os.path.exists(ctx.syshook)
        steps = []
        if 'created' in state:
            created = state['created'] or {}
            job = next((j for j in crons if j['uuid'] == created.get('cron')), None)
            if job:
                steps.append(A._step('Remove the cron job', 'System: Settings: Cron: delete %s' % job['uuid'],
                                     'no more runs', id='cron', uuid=job['uuid']))
                steps.append(A._step('Apply the cron configuration', 'configctl cron restart', 'cron reloads',
                                     id='cron_restart'))
            if created.get('syshook') and hook:
                steps.append(A._step('Remove the boot hook', 'rm %s' % ctx.syshook, 'removed', id='syshook'))
            return {'steps': steps}
        removed = state.get('removed') or {}
        if removed.get('cron') and not crons:
            steps.append(A._step('Schedule the quarantine again (cron */5)', 'cron job: %s' % common.CRON_COMMAND,
                                 'runs every 5 minutes', id='cron_add'))
            steps.append(A._step('Apply the cron configuration', 'configctl cron restart', 'cron reloads',
                                 id='cron_restart'))
        if removed.get('syshook') and not hook:
            steps.append(A._step('Write the boot hook again', 'write %s' % ctx.syshook, 'table rebuilt at boot',
                                 id='syshook_add'))
        return {'steps': steps}

    def rexecute(self, ctx, b, entry, flags):
        completed = []
        for step in b['steps']:
            sid = step['id']
            if sid == 'cron':
                A.php(ctx, 'cron_del', step['uuid'])
            elif sid == 'cron_add':
                A.php(ctx, 'cron_add')
            elif sid == 'cron_restart':
                A.configctl(ctx, 'cron', 'restart')
            elif sid == 'syshook':
                os.unlink(ctx.syshook)
            elif sid == 'syshook_add':
                _write_syshook(ctx)
            completed.append(step['description'])
        return {'completed': completed}


# ====================================================================== 7 activate


def run_summary(run):
    if not run or run.get('status') != 'ok':
        return 'first run: %s' % ((run or {}).get('message') or (run or {}).get('status') or 'not run')
    reasons = ', '.join('%s %d' % kv for kv in sorted((run.get('by_reason') or {}).items()))
    return 'first run: %d address(es) entered%s; %d source(s) seen, %d protected by the guards, pf table %s' % (
        run.get('offenses', 0), ' (%s)' % reasons if reasons else '', run.get('sources', 0),
        sum((run.get('guarded') or {}).values()), (run.get('table') or {}).get('size', 0))


@register
class SetupActivate(_Step):
    name = 'qsetup_activate'
    description = 'Quarantine setup 7 (Activate): enable the rule and run now (Undo pauses)'

    def parse_args(self, args):
        if [a for a in args if a and a != 'run']:
            raise ValueError('no arguments')
        return {}

    def build(self, ctx):
        cfg = A._engine(ctx).config()
        rules = cfg.quarantine_rules()
        need = []
        if not os.path.exists(ctx.db):
            need.append(_need('There is no ledger yet (step 2).', 'qsetup_ledger', 'Create the ledger', ['create']))
        if common.ALIAS not in cfg.aliases():
            need.append(_need('The alias %s does not exist (step 3).' % common.ALIAS, 'qsetup_aliases',
                              'Create the aliases', ['create']))
        if not rules:
            need.append(_need('The rule "%s" does not exist (step 4).' % common.RULE_DESCR, 'qsetup_rule',
                              'Create the rule', ['create', 'off']))
        if need:
            return {'steps': [], 'blocked': True, 'warning_actions': need}
        rule = rules[0]
        st = store_mod.Store(ctx.db)
        try:
            paused = st.meta('paused') == '1'
        finally:
            st.close()
        prev = wizard.first_run_preview(ctx, engine_options=A.ENGINE_OPTIONS)
        reasons = ', '.join('%s %d' % kv for kv in sorted(prev.get('by_reason', {}).items()))
        steps = [
            A._step('Enable the rule "%s"' % common.RULE_DESCR, 'Firewall: Rules (model): %s enabled = 1' % rule['uuid'],
                    'quarantined addresses are blocked', already=rule['enabled'], id='enable', uuid=rule['uuid']),
            A._step('Reload the rules', 'configctl filter reload', 'existing states are kept', already=rule['enabled'],
                    id='reload'),
            A._step('Mark the quarantine as running (not paused)', 'ledger: meta paused = 0', 'event "resume"',
                    already=not paused, id='resume'),
            A._step('Run the quarantine now (the first run)', 'configctl policyanalyzer quarantine_run',
                    'preview: %d record(s) of the filter log since %s, about %d address(es) enter%s' % (
                        prev.get('records', 0), prev.get('since') or 'the ledger was created', prev.get('entering', 0),
                        ' (%s)' % reasons if reasons else ''), id='run')]
        lines = ['%s — %s, level %s (%s), %d event(s)%s' % (c['addr'], c['reason'], c['level'], c['level_label'],
                                                           c['events'], ' — already in quarantine' if c['already']
                                                           else '') for c in prev.get('candidates', [])]
        if len(lines) > 5:
            lines = lines[:5] + ['... and %d more' % (len(lines) - 5)]
        warnings, wa = [], []
        if not cfg.quarantine_cron():
            wa.append(_need('Not scheduled yet (step 6): only this run happens, nobody expires the entries later.',
                            'qsetup_schedule', 'Schedule it (simulate first)', ['create']))
        if not prev.get('complete', True):
            warnings.append('the preview read only the first %d bytes since the ledger was created' % prev.get('bytes', 0))
        return {'steps': steps, 'warnings': warnings, 'warning_actions': wa, 'paused': paused, 'rule': rule,
                'info': [{'title': 'Preview of the first run: %d address(es)' % prev.get('entering', 0),
                          'items': lines or ['nobody']}],
                'revert': ['Undo pauses the quarantine: the rule is disabled, the ledger keeps recording']}

    def execute(self, ctx, b):
        completed = []
        state = {'enabled_rule': False, 'was_paused': b['paused']}
        steps = {s['id']: s for s in _todo(b['steps'])}
        if 'enable' in steps:
            A.php(ctx, 'rule_enable', b['rule']['uuid'], '1')
            state['enabled_rule'] = True
            completed.append(steps['enable']['description'])
            _reload(ctx)
            completed.append(steps['reload']['description'])
        st = store_mod.Store(ctx.db)
        try:
            st.begin()
            st.set_meta('paused', '0')
            if 'resume' in steps:
                st.add_event(None, ctx.clock(), 'resume', origin='manual', note='assistant: activate')
            st.commit()
        finally:
            st.close()
        if 'resume' in steps:
            completed.append(steps['resume']['description'])
        run = A._engine(ctx).run()
        completed.append(run_summary(run))
        warnings = [] if run.get('status') == 'ok' else ['the first run did not complete (%s): the next scheduled run '
                                                         'does it' % (run.get('message') or run.get('status'))]
        return {'completed': completed, 'state': state, 'warnings': warnings, 'extra': {'run': run}}

    def rbuild(self, ctx, entry, flags):
        cfg = A._engine(ctx).config()
        rules = cfg.quarantine_rules()
        if not rules:
            return {'steps': [], 'warnings': ['the rule "%s" does not exist anymore' % common.RULE_DESCR]}
        paused = False
        if os.path.exists(ctx.db):
            st = store_mod.Store(ctx.db)
            try:
                paused = st.meta('paused') == '1'
            finally:
                st.close()
        already = not rules[0]['enabled'] and paused
        return {'steps': [A._step('Pause: disable the rule "%s"' % common.RULE_DESCR, 'Firewall: Rules (model): '
                                  'enabled = 0; ledger paused = 1', 'not blocked; the ledger keeps recording',
                                  already=already, id='pause'),
                          A._step('Reload the rules', 'configctl filter reload', 'existing states are kept',
                                  already=already, id='reload')],
                'warnings': ['the entries of the first run stay in the ledger (history)']}

    def rexecute(self, ctx, b, entry, flags):
        A.QuarantinePause()._toggle(ctx, False)
        return {'completed': ['rule disabled (paused)', 'rules reloaded']}


# ====================================================================== composites (CLI shortcuts)


def _dispatcher():
    from ai import changes, journal      # the plugin dispatcher (present on the firewall and in the tests)
    return changes, journal


INSTALL_CHAIN = (
    ('qsetup_ledger', {'mode': 'create'}),
    ('qsetup_aliases', {'mode': 'create', 'reload': False}),
    ('qsetup_rule', {'mode': 'create', 'enabled': True, 'assume_alias': True}),
    ('qsetup_schedule', {'mode': 'create'}),
)
REMOVE_CHAIN = (
    ('qsetup_schedule', {'mode': 'remove'}),
    ('qsetup_rule', {'mode': 'remove'}),
    ('qsetup_aliases', {'mode': 'remove', 'assume_no_rule': True}),
)
PURGE_STEP = ('qsetup_ledger', {'mode': 'purge', 'assume_no_rule': True})
STEP_CLASSES = {}


def _step_class(name):
    return STEP_CLASSES[name]


def _journal_args(opts, via):
    args = {k: v for k, v in opts.items() if k in ('mode', 'enabled')}
    args['via'] = via
    return args


def _run_chain(ctx, chain, via):
    """ apply the steps of a chain, one journal entry per step; :return: (done, completed, warnings) or raise """
    changes, journal = _dispatcher()
    done, completed, warnings = [], [], []
    for name, opts in chain:
        inst = _step_class(name)()
        b = inst.build(ctx, **opts)
        if b.get('blocked'):
            raise common.QuarantineError(b['warning_actions'][0]['warning'])
        if not _todo(b['steps']):
            continue
        try:
            res = inst.execute(ctx, b, **opts)
        except (common.QuarantineError, OSError) as exc:
            raise _ChainError(str(exc), done, completed)
        result = {'done': True, 'completed': res['completed']}
        entry = journal.create(name, _journal_args(opts, via), result, state=res.get('state'),
                               irreversible=b.get('irreversible'))
        done.append({'action': name, 'journal_id': entry['id'], 'mode': opts.get('mode')})
        completed.extend(res['completed'])
        warnings.extend(res.get('warnings') or [])
    return done, completed, warnings


class _ChainError(common.QuarantineError):
    def __init__(self, message, done, completed):
        super().__init__(message)
        self.done = done
        self.completed = completed


def _revert_chain(done, skip=()):
    """ revert the journal entries of a chain in reverse order; :return: (completed, warnings, error) """
    changes, journal = _dispatcher()
    completed, warnings = [], []
    for item in reversed(done):
        if item['action'] in skip:
            continue
        try:
            entry = journal.load(item['journal_id'])
        except ValueError:
            warnings.append('journal entry %s not found' % item['journal_id'])
            continue
        if entry.get('reverted'):
            continue
        res = changes.run('apply', 'revert', [item['journal_id']])
        if res.get('status') == 'error':
            return completed, warnings, '%s: %s' % (item['action'], res.get('message'))
        completed.extend(res.get('completed') or [])
        warnings.extend(res.get('warnings') or [])
    return completed, warnings, None


def _revert_chain_plan(done, skip=()):
    changes, journal = _dispatcher()
    steps, warnings, double = [], [], False
    for item in reversed(done):
        if item['action'] in skip:
            continue
        try:
            entry = journal.load(item['journal_id'])
        except ValueError:
            continue
        if entry.get('reverted'):
            continue
        plan = changes.run('plan', 'revert', [item['journal_id']])
        if plan.get('status') == 'error':
            warnings.append('%s: %s' % (item['action'], plan.get('message')))
            continue
        steps.extend(plan.get('steps') or [])
        warnings.extend(plan.get('warnings') or [])
        double = double or plan.get('requires_double_confirmation')
    return steps, warnings, double


def _scenario_info(ctx, wan, settings):
    return {'title': 'Scenarios (every 5 min)', 'items': [
        'base: 1+ blocked inbound connection on %s -> 30 min, repeat offenses 2 h, 2 days, 10 days, 30 days; back '
        'to zero after %d days without offenses' % (', '.join(w['key'] for w in wan), settings['reset_days']),
        'scan: %d+ destination ports in %d s -> at least 2 h' % (settings['scan_ports'], settings['scan_window']),
        'bait ports %s -> at least 2 h' % settings['bait_ports'].replace('+', ', '),
        'Suricata alert severity <= %d from outside -> at least 2 days%s' % (
            settings['suricata_severity'], '' if settings['suricata'] else ' (disabled)'),
        'at most %d active entries (alert above it)' % settings['max_active']]}


@register
class InstallQuarantine(A._Base):
    name = 'install_quarantine'
    description = 'Install the automatic quarantine (steps 2-4 and 6 of the assistant, one journal entry each)'

    def parse_args(self, args):
        if [a for a in args if a]:
            raise ValueError('no arguments (the assistant offers the options step by step)')
        return {}

    def _build(self, ctx):
        steps, info, warnings = [], [], []
        for name, opts in INSTALL_CHAIN:
            b = _step_class(name)().build(ctx, **opts)
            steps.extend(b['steps'])
            warnings.extend(b.get('warnings') or [])
            info.extend(b.get('info') or [])
        eng = A._engine(ctx)
        cfg = eng.config()
        st = eng.open() if eng.installed() else None
        try:
            g = eng.guards(cfg, st, ctx.clock())
        finally:
            if st is not None:
                st.close()
        settings = common.effective_settings(A.st_settings(ctx))
        if not os.path.exists(ctx.eve) and settings['suricata']:
            warnings.append('Suricata eve.json not found (%s): the Suricata scenario stays idle until it exists' %
                            ctx.eve)
        info.extend([_scenario_info(ctx, cfg.wan_interfaces(), settings), A._guard_info(g)])
        if _todo(steps):
            steps.append(A._step('Synchronize the pf table with the ledger', 'pfctl -t %s -T add|delete ...' %
                                 common.ALIAS, 'entries still in quarantine are blocked again', id='sync'))
        return steps, info, warnings

    def plan(self):
        ctx = self.ctx()
        steps, info, warnings = self._build(ctx)
        return A._plan(steps, warnings, risk='medium', info=info, revert=[
            'Revert removes the rule, the aliases, the cron job and the boot hook created by this install (each step '
            'is also in the action history and can be undone alone); the ledger and its history stay '
            '(remove_quarantine with "purge_db=yes" deletes them)'])

    def apply(self):
        ctx = self.ctx()
        if not ctx.is_root:
            return {'status': 'error', 'message': 'apply must run as root (configd)'}
        steps, _info, warnings = self._build(ctx)
        try:
            done, completed, more = _run_chain(ctx, INSTALL_CHAIN, self.name)
        except _ChainError as exc:
            undone, _w, err = _revert_chain(exc.done)
            return {'status': 'error', 'done': False, 'completed': [],
                    'message': '%s (rolled back: %s%s)' % (exc, ', '.join(undone) or 'nothing',
                                                           '; rollback failed: %s' % err if err else '')}
        except common.QuarantineError as exc:
            return {'status': 'error', 'done': False, 'completed': [], 'message': str(exc)}
        if done:
            sync = A._engine(ctx).sync()
            completed.append('pf table synchronized (%s)' % sync.get('status'))
        return {'status': 'ok', 'done': True, 'completed': completed, 'state': {'steps': done},
                'steps': [{k: s[k] for k in ('description', 'command', 'effect')} for s in steps],
                'warnings': warnings + more, 'irreversible': []}

    def revert_plan(self, entry, flags=None):
        ctx = self.ctx()
        done = (entry.get('state') or {}).get('steps') or []
        steps, warnings, double = _revert_chain_plan(done, skip=('qsetup_ledger',))
        return A._plan(steps, warnings + ['the ledger %s and its history are kept (Undo of step 2 in the assistant '
                                          'handles it)' % ctx.db], risk='medium', double=double,
                       revert=['Install again to restore it'])

    def revert_apply(self, entry, flags=None):
        done = (entry.get('state') or {}).get('steps') or []
        completed, warnings, err = _revert_chain(done, skip=('qsetup_ledger',))
        if err:
            return {'status': 'error', 'done': False, 'completed': completed, 'message': err}
        return {'status': 'ok', 'done': True, 'completed': completed, 'warnings': warnings}


@register
class RemoveQuarantine(A._Base):
    name = 'remove_quarantine'
    description = 'Remove the automatic quarantine (inverse steps 6, 4, 3; the ledger is kept unless purge_db=yes)'

    def parse_args(self, args):
        purge = False
        for arg in args:
            if arg in ('purge_db=yes', 'purge_db'):
                purge = True
            elif arg:
                raise ValueError('unknown option (purge_db=yes)')
        return {'purge': purge}

    def _chain(self, purge):
        return REMOVE_CHAIN + ((PURGE_STEP,) if purge else ())

    def plan(self, purge):
        ctx = self.ctx()
        steps, warnings, irreversible = [], [], []
        for name, opts in self._chain(purge):
            b = _step_class(name)().build(ctx, **opts)
            steps.extend(b['steps'])
            warnings.extend(b.get('warnings') or [])
            irreversible.extend(b.get('irreversible') or [])
        if os.path.exists(ctx.db) and not purge:
            warnings.append('the ledger %s and its history are kept (yearly queries keep working)' % ctx.db)
        return A._plan(steps, [w for w in warnings if w != 'the rule "%s" does not exist' % common.RULE_DESCR],
                       risk='high' if purge else 'medium', irreversible=irreversible, double=purge,
                       revert=['Revert installs the quarantine again (pa_never_block keeps its entries%s)' % (
                           '' if purge else ', the quarantines still valid are restored')])

    def apply(self, purge):
        ctx = self.ctx()
        if not ctx.is_root:
            return {'status': 'error', 'message': 'apply must run as root (configd)'}
        try:
            done, completed, warnings = _run_chain(ctx, self._chain(purge), self.name)
        except _ChainError as exc:
            return {'status': 'error', 'done': False, 'completed': exc.completed, 'message': str(exc),
                    'state': {'steps': exc.done}}
        except common.QuarantineError as exc:
            return {'status': 'error', 'done': False, 'completed': [], 'message': str(exc)}
        irreversible = ['the quarantine history was deleted'] if purge else []
        return {'status': 'ok', 'done': True, 'completed': completed, 'state': {'steps': done, 'purged': purge},
                'warnings': warnings, 'irreversible': irreversible}

    def revert_plan(self, entry, flags=None):
        state = entry.get('state') or {}
        steps, warnings, double = _revert_chain_plan(state.get('steps') or [], skip=('qsetup_ledger',))
        if state.get('purged'):
            warnings.append('the history was deleted by the removal and starts empty')
        return A._plan(steps, warnings, risk='medium', double=double, revert=['remove_quarantine removes it again'])

    def revert_apply(self, entry, flags=None):
        state = entry.get('state') or {}
        completed, warnings, err = _revert_chain(state.get('steps') or [], skip=('qsetup_ledger',))
        if err:
            return {'status': 'error', 'done': False, 'completed': completed, 'message': err}
        return {'status': 'ok', 'done': True, 'completed': completed, 'warnings': warnings}


for _cls in (SetupRuleLog, SetupLedger, SetupAliases, SetupNeverBlock, SetupRule, SetupScenarios, SetupSchedule,
             SetupActivate):
    STEP_CLASSES[_cls.name] = _cls

STEP_ACTIONS = {
    'check': ['qsetup_rule_log'], 'ledger': ['qsetup_ledger'], 'aliases': ['qsetup_aliases', 'qsetup_never_block'],
    'rule': ['qsetup_rule'], 'scenarios': ['qsetup_scenarios', 'quarantine_settings'],
    'schedule': ['qsetup_schedule'], 'activate': ['qsetup_activate', 'quarantine_pause', 'quarantine_resume'],
    'finish': ['install_quarantine', 'remove_quarantine'],
}
