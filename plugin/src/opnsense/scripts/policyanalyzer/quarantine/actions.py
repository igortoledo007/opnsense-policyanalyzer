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

    Change actions of the quarantine (plan -> apply -> revert through ai/changes.py, journaled in
    /var/db/policyanalyzer/undo/<id>.json).  Every firewall object is changed through the core models
    (model.php) and applied with configctl; nothing here edits config.xml or reboots the firewall.

      (install_quarantine, remove_quarantine and the steps of the assistant qsetup_*: see steps.py)
      quarantine_add            manual entry: address, CIDR, range or ASN, duration, comment (base64)
      quarantine_release        entry ids ("12+15"), quarantine_extend <ids> <next|l1..l5>,
      quarantine_permanent      <ids>, never_block_add <id> (also adds it to pa_never_block)
      quarantine_pause / quarantine_resume    disable / enable the rule (the ledger keeps recording)
      quarantine_settings       <key> <value>
      update_asn_db             download the ASN database the core uses (rulesets.opnsense.org)
"""

import base64
import gzip
import ipaddress
import json
import os
import re
import shutil
import time
import urllib.request

from . import common, engine as engine_mod, fwconfig, lookup as lookup_mod, pf, store as store_mod

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
ENGINE_OPTIONS = {}                                  # tests: {"runtime_guards": False, "resolver": ...}
SNAPSHOT_FIELDS = ('state', 'level', 'until', 'since', 'last_offense', 'reason', 'origin', 'comment')
IDS_RE = re.compile(r'^\d{1,9}(\+\d{1,9}){0,%d}$' % (common.BATCH_MAX - 1))
SYSHOOK_BODY = '#!/bin/sh\n# Policy Analyzer: rebuild the pa_quarantine pf table from the ledger after boot\n' \
               '/usr/local/sbin/configctl policyanalyzer quarantine_sync > /dev/null 2>&1\nexit 0\n'


def _ctx():
    return CONTEXT_FACTORY()


def _engine(ctx):
    return engine_mod.Engine(ctx, **ENGINE_OPTIONS)


def _step(description, command, effect, already=False, **extra):
    step = {'description': description, 'command': command, 'effect': 'already done' if already else effect,
            'already': already}
    step.update(extra)
    return step


def _plan(steps, warnings=None, risk='medium', revert=None, info=None, double=False, irreversible=None, **extra):
    todo = [s for s in steps if not s.get('already')]
    out = {'status': 'ok', 'steps': [{k: s[k] for k in ('description', 'command', 'effect')} for s in steps],
           'warnings': list(warnings or []), 'revert': list(revert or []), 'risk': risk if todo else 'none',
           'requires_confirmation': bool(todo), 'requires_double_confirmation': bool(double and todo),
           'irreversible': list(irreversible or []), 'info': info or []}
    if not todo:
        out['steps'] = []
    out.update(extra)
    return out


def php(ctx, *args):
    rc, out, err = ctx.runner.run([ctx.php, ctx.model_php] + [str(a) for a in args], timeout=60)
    try:
        data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except ValueError:
        data = {}
    if rc != 0 or data.get('status') != 'ok':
        raise common.QuarantineError('core model (%s): %s' % (args[0], data.get('message') or err.strip() or rc))
    return data


def configctl(ctx, *args, timeout=300):
    rc, out, err = ctx.runner.run([ctx.configctl] + list(args), timeout=timeout)
    if rc != 0:
        raise common.QuarantineError('configctl %s: %s' % (' '.join(args), (err or out).strip() or rc))
    return out


def _guard_info(guards):
    info = []
    desc = guards.describe()
    for label, items in desc['labels'].items():
        if items:
            info.append('%s (%d): %s' % (label, len(items), ', '.join(i['addr'] for i in items[:40]) +
                                         (' ...' if len(items) > 40 else '')))
    info.append('always: %s' % ', '.join(desc['implicit']))
    return {'title': 'Guards: never put in quarantine', 'items': info + desc['notes']}


def _end_marker(path):
    try:
        st = os.stat(os.path.realpath(path))
    except OSError:
        return None
    return {'dev': st.st_dev, 'ino': st.st_ino, 'offset': st.st_size}


# ====================================================================== shared by the steps (steps.py)


class _Base(ChangeAction):
    revertible = True

    def ctx(self):
        return _ctx()


def st_settings(ctx):
    if not os.path.exists(ctx.db):
        return {}
    st = store_mod.Store(ctx.db)
    try:
        return st.stored_settings()
    finally:
        st.close()


def _snapshot(entry):
    return {'addr': entry['addr'], 'existed': True, 'before': {k: entry.get(k) for k in SNAPSHOT_FIELDS}}


def _restore_entries(ctx, snapshots, note):
    st = store_mod.Store(ctx.db)
    now = ctx.clock()
    try:
        st.begin()
        for snap in snapshots:
            entry = st.entry_by_addr(snap['addr'])
            if entry is None:
                continue
            if snap.get('existed'):
                st.update_entry(entry['id'], **snap['before'])
            else:
                st.update_entry(entry['id'], state='released', until=int(now))
            st.add_event(entry['id'], now, 'revert', level=snap.get('before', {}).get('level'), origin='manual',
                         note=note)
        st.commit()
    finally:
        st.close()


# ====================================================================== entries


def parse_ids(token):
    if not isinstance(token, str) or not IDS_RE.match(token):
        raise ValueError('invalid selection (entry ids separated by "+", at most %d)' % common.BATCH_MAX)
    return sorted({int(x) for x in token.split('+')})


def decode_comment(token):
    if not token or token == '-':
        return None
    try:
        text = base64.b64decode(token.encode(), validate=True).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise ValueError('invalid comment')
    text = ''.join(ch for ch in text if ch.isprintable()).strip()
    return text[:common.COMMENT_MAX] or None


def _until_text(level, now):
    if level >= common.PERMANENT:
        return 'permanent'
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(now + common.ttl(level)))


class _EntryAction(_Base):
    """ shared plan/apply/revert for actions that change entries of the ledger """

    def _open(self, ctx):
        eng = _engine(ctx)
        if not eng.installed():
            raise ValueError('the quarantine is not installed')
        return eng, eng.open()

    def revert_plan(self, entry, flags=None):
        state = entry.get('state') or {}
        snaps = state.get('snapshots') or []
        steps = [_step('Restore %s as it was before (%s)' % (s['addr'], 'new entry: released' if not s['existed']
                                                              else s['before'].get('state')),
                       'ledger: %s' % s['addr'], 'the history keeps both records') for s in snaps]
        if state.get('never_block'):
            steps.append(_step('Remove %s from %s' % (state['never_block'], common.NEVER_ALIAS),
                               'Firewall: Aliases: %s' % common.NEVER_ALIAS, 'it can be quarantined again'))
        steps.append(_step('Synchronize the pf table', 'pfctl -t %s ...' % common.ALIAS, 'table = ledger'))
        return _plan(steps, risk='low')

    def revert_apply(self, entry, flags=None):
        ctx = self.ctx()
        state = entry.get('state') or {}
        try:
            if state.get('never_block'):
                php(ctx, 'alias_entry', common.NEVER_ALIAS, 'del', state['never_block'])
            _restore_entries(ctx, state.get('snapshots') or [], 'revert of %s' % entry.get('id'))
            _engine(ctx).sync()
        except (common.QuarantineError, OSError) as exc:
            return {'status': 'error', 'done': False, 'message': str(exc)}
        return {'status': 'ok', 'done': True, 'completed': ['entries restored', 'pf table synchronized']}


@register
class QuarantineAdd(_EntryAction):
    name = 'quarantine_add'
    description = 'Put an address, network, range or ASN in quarantine (manual)'

    def parse_args(self, args):
        args = list(args) + ['', '', '']
        target = common.parse_target(args[0])
        duration = args[1] or 'auto'
        if duration != 'auto' and duration not in common.DURATIONS:
            raise ValueError('duration: auto, l1..l5 or permanent')
        return {'target': target['label'] if target['kind'] != 'net' or len(target['nets']) == 1 else args[0],
                'duration': duration, 'comment': decode_comment(args[2])}

    def _resolve(self, ctx, eng, st, parsed, duration, now):
        """ :return: (items [{addr, kind, nets, level, asn}], warnings, double) """
        cfg = eng.config()
        g = eng.guards(cfg, st, now)
        settings = st.settings()
        warnings, double = [], False
        nets = parsed['nets']
        if parsed['kind'] == 'asn':
            nets, _mtime = lookup_mod.asn_prefixes(ctx, parsed['asn'])
            if not nets:
                raise ValueError('AS%d has no prefixes in the local ASN database' % parsed['asn'])
            dropped = [n for n in nets if not common.network_is_external(n)]
            nets = [n for n in nets if common.network_is_external(n)]
            if dropped:
                warnings.append('%d prefix(es) of AS%d are not public and are left out' % (len(dropped), parsed['asn']))
            if len(nets) > common.ASN_CONFIRM_PREFIXES:
                double = True
                warnings.append('AS%d announces %d prefixes' % (parsed['asn'], len(nets)))
        for net in nets:
            if net.prefixlen == net.max_prefixlen:
                why = g.check(net.network_address)
                if why is not None:
                    raise ValueError('%s is protected (%s) and is never quarantined' % (net.network_address, why))
                continue
            if parsed['kind'] != 'asn' and not common.network_is_external(net):
                raise ValueError('%s is not public address space' % net)
            try:
                if common.check_network_size(net):
                    double = True
                    warnings.append('%s is bigger than /%d' % (net, common.V4_CONFIRM_PREFIX if net.version == 4
                                                               else common.V6_CONFIRM_PREFIX))
            except ValueError:
                if parsed['kind'] == 'asn':
                    continue
                raise
            for label, sub in g.overlapping(net):
                if sub == net:
                    raise ValueError('%s is entirely protected (%s)' % (net, label))
                warnings.append('%s covers protected %s (%s): it stays reachable (excluded with !%s)' % (
                    net, common.pf_text(sub), label, common.pf_text(sub)))
        items = []
        if parsed['kind'] == 'asn':
            items.append({'addr': parsed['label'], 'kind': 'asn', 'nets': nets, 'asn': parsed['asn']})
        else:
            for net in nets:
                items.append({'addr': common.pf_text(net), 'kind': 'ip' if net.prefixlen == net.max_prefixlen
                              else 'net', 'nets': [net], 'asn': None})
        for item in items:
            entry = st.entry_by_addr(item['addr'])
            if duration == 'auto':
                item['level'] = engine_mod.next_level(entry, now, settings, 1)
            else:
                item['level'] = common.DURATIONS[duration]
            if item['level'] >= common.PERMANENT:
                double = True
            item['entry'] = entry
        new_pf = sum(len(i['nets']) for i in items)
        current = engine_mod.pf_count(st)
        if current + new_pf > settings['max_active']:
            raise ValueError('the limit of %d active entries would be exceeded (%d + %d)' % (
                settings['max_active'], current, new_pf))
        return items, warnings, double

    def plan(self, target, duration, comment):
        parsed = common.parse_target(target)
        ctx = self.ctx()
        eng, st = self._open(ctx)
        try:
            now = ctx.clock()
            items, warnings, double = self._resolve(ctx, eng, st, parsed, duration, now)
        finally:
            st.close()
        steps = []
        for item in items:
            steps.append(_step('Quarantine %s (%s%s) at level %d (%s), until %s' % (
                item['addr'], item['kind'], ', %d prefixes' % len(item['nets']) if item['kind'] == 'asn' else '',
                item['level'], common.LEVEL_LABELS[item['level']], _until_text(item['level'], now)),
                'ledger: manual entry%s' % (', comment "%s"' % comment if comment else ''),
                'inbound connections from it are blocked by "%s"' % common.RULE_DESCR))
        steps.append(_step('Synchronize the pf table', 'pfctl -t %s -T add ...' % common.ALIAS,
                           '%d pf entr%s' % (sum(len(i['nets']) for i in items),
                                             'y' if sum(len(i['nets']) for i in items) == 1 else 'ies')))
        return _plan(steps, warnings, risk='medium' if double else 'low', double=double,
                     revert=['Revert restores the previous state of the entries (the history keeps the record)'])

    def apply(self, target, duration, comment):
        parsed = common.parse_target(target)
        ctx = self.ctx()
        eng, st = self._open(ctx)
        lock = engine_mod.Lock(ctx.lock_file)
        try:
            lock.acquire(wait=25)
        except common.BusyError as exc:
            st.close()
            return {'status': 'error', 'message': str(exc)}
        snaps = []
        try:
            now = ctx.clock()
            items, _warnings, _double = self._resolve(ctx, eng, st, parsed, duration, now)
            lk = lookup_mod.Lookup(ctx)
            st.begin()
            for item in items:
                entry = item['entry']
                if entry is None:
                    country, asn = (None, item['asn'])
                    if item['kind'] == 'ip':
                        country, asn = lk.lookup(item['nets'][0].network_address)
                    entry = st.create_entry(item['addr'], item['kind'], now, country=country, asn=asn, level=0,
                                            state='expired', origin='manual')
                    snaps.append({'addr': item['addr'], 'existed': False, 'before': {}})
                else:
                    snaps.append(_snapshot(entry))
                if item['kind'] == 'asn':
                    st.set_asn_prefixes(entry['id'], [str(n) for n in item['nets']], now)
                found = {'ts': now, 'primary': 'manual', 'reasons': ['manual'], 'events': None,
                         'ports': None, 'detail': comment, 'iface': None}
                eng._offend(st, entry, found, item['level'], now, {}, origin='manual', note=comment)
                if comment:
                    st.update_entry(entry['id'], comment=comment)
            st.commit()
            lk.close()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
            lock.release()
        sync = eng.sync()
        for item in items:
            if item['kind'] == 'ip':
                pf.Table(ctx).kill_states(item['addr'])
        return {'status': 'ok', 'done': True, 'completed': ['%s quarantined' % i['addr'] for i in items] +
                ['pf table: +%s' % sync.get('added', 0)], 'state': {'snapshots': snaps}}


class _IdsAction(_EntryAction):
    verb = ''

    def parse_args(self, args):
        args = list(args) + ['', '']
        return {'ids': parse_ids(args[0]), 'option': args[1]}

    def _entries(self, st, ids):
        entries = [st.entry(i) for i in ids]
        missing = [str(i) for i, e in zip(ids, entries) if e is None]
        if missing:
            raise ValueError('entries not found: %s' % ', '.join(missing))
        return entries

    def change(self, st, entry, option, now, settings):
        """ :return: (fields, event kind, description) or None when nothing changes """
        raise NotImplementedError

    def plan(self, ids, option):
        ctx = self.ctx()
        eng, st = self._open(ctx)
        try:
            now = ctx.clock()
            settings = st.settings()
            steps = []
            double = False
            for entry in self._entries(st, ids):
                change = self.change(st, entry, option, now, settings)
                if change is not None:
                    steps.append(_step(change[2], 'ledger: %s' % entry['addr'], change[3] if len(change) > 3 else ''))
                    double = double or change[0].get('state') == 'permanent'
            if steps:
                steps.append(_step('Synchronize the pf table', 'pfctl -t %s ...' % common.ALIAS, 'table = ledger'))
            return _plan(steps, risk='medium' if double else 'low', double=double,
                         revert=['Revert restores the previous state of the entries'])
        finally:
            st.close()

    def apply(self, ids, option):
        ctx = self.ctx()
        eng, st = self._open(ctx)
        lock = engine_mod.Lock(ctx.lock_file)
        try:
            lock.acquire(wait=25)
        except common.BusyError as exc:
            st.close()
            return {'status': 'error', 'message': str(exc)}
        snaps, completed, extra = [], [], {}
        try:
            now = ctx.clock()
            settings = st.settings()
            entries = self._entries(st, ids)
            pre = self.before_apply(ctx, entries, option)
            if pre:
                extra.update(pre)
            st.begin()
            for entry in entries:
                change = self.change(st, entry, option, now, settings)
                if change is None:
                    continue
                snaps.append(_snapshot(entry))
                fields, kind = change[0], change[1]
                st.update_entry(entry['id'], **fields)
                st.add_event(entry['id'], now, kind, level=fields.get('level', entry['level']),
                             until=fields.get('until', entry['until']), origin='manual')
                completed.append(change[2])
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            st.close()
            lock.release()
        eng.sync()
        state = {'snapshots': snaps}
        state.update(extra)
        return {'status': 'ok', 'done': bool(completed), 'completed': completed, 'state': state}

    def before_apply(self, ctx, entries, option):
        return None


@register
class QuarantineRelease(_IdsAction):
    name = 'quarantine_release'
    description = 'Release entries from the quarantine'

    def change(self, st, entry, option, now, settings):
        if entry['state'] not in ('active', 'permanent'):
            return None
        return ({'state': 'released', 'until': int(now)}, 'release', 'Release %s' % entry['addr'],
                'inbound connections from it are allowed again by the rules')


@register
class QuarantineExtend(_IdsAction):
    name = 'quarantine_extend'
    description = 'Extend the quarantine of entries (next level or a chosen duration)'

    def parse_args(self, args):
        out = super().parse_args(args)
        if out['option'] not in ('next',) + tuple(k for k in common.DURATIONS if k != 'permanent'):
            raise ValueError('extend: next or l1..l5')
        return out

    def change(self, st, entry, option, now, settings):
        if entry['state'] == 'permanent':
            return None
        current = int(entry['level'] or 0)
        level = min(current + 1, 5) if option == 'next' else max(current, common.DURATIONS[option])
        rung = level if option == 'next' else common.DURATIONS[option]
        base = max(int(now), int(entry['until'] or 0)) if entry['state'] == 'active' and option != 'next' else int(now)
        until = max(int(entry['until'] or 0) if entry['state'] == 'active' else 0, base + common.ttl(rung))
        fields = {'state': 'active', 'level': level, 'until': until}
        if entry['state'] != 'active':
            fields['since'] = int(now)
            fields['last_offense'] = int(now)
        return (fields, 'extend', 'Extend %s to level %d, until %s' % (
            entry['addr'], level, time.strftime('%Y-%m-%d %H:%M', time.localtime(until))), 'blocked longer')


@register
class QuarantinePermanent(_IdsAction):
    name = 'quarantine_permanent'
    description = 'Make the quarantine of entries permanent (until released by hand)'

    def change(self, st, entry, option, now, settings):
        if entry['state'] == 'permanent':
            return None
        fields = {'state': 'permanent', 'level': common.PERMANENT, 'until': None}
        if entry['state'] != 'active':
            fields['since'] = int(now)
            fields['last_offense'] = int(now)
        return (fields, 'permanent', 'Block %s permanently (no expiry, released only by hand)' % entry['addr'],
                'kept across reboots by the boot hook')


@register
class NeverBlockAdd(_IdsAction):
    name = 'never_block_add'
    description = 'Move an entry to pa_never_block (released now, never quarantined again)'

    def parse_args(self, args):
        out = super().parse_args(args)
        if len(out['ids']) != 1:
            raise ValueError('one entry at a time')
        return out

    def change(self, st, entry, option, now, settings):
        if entry['kind'] == 'asn':
            raise ValueError('an ASN can not be added to %s: add its networks one by one' % common.NEVER_ALIAS)
        fields = {'state': 'released', 'until': int(now)} if entry['state'] in ('active', 'permanent') else {}
        return (fields, 'never_block', 'Add %s to %s and release it' % (entry['addr'], common.NEVER_ALIAS),
                'never quarantined again (edit the alias to undo by hand, or Revert)')

    def plan(self, ids, option):
        out = super().plan(ids, option)
        if out.get('steps'):
            out['steps'].insert(0, {'description': 'Add the entry to the alias %s' % common.NEVER_ALIAS,
                                    'command': 'Firewall: Aliases (model): %s += address' % common.NEVER_ALIAS,
                                    'effect': 'config saved; no rule reload needed'})
        return out

    def before_apply(self, ctx, entries, option):
        target = entries[0]['addr']
        php(ctx, 'alias_entry', common.NEVER_ALIAS, 'add', target)
        return {'never_block': target}


# ====================================================================== pause / settings / ASN database


class _RuleToggle(_Base):
    enable = True
    kind = ''

    def parse_args(self, args):
        return {}

    def _rule(self, ctx):
        rules = fwconfig.FirewallConfig(ctx.config_xml).quarantine_rules()
        if not rules:
            raise ValueError('the rule "%s" does not exist: install the quarantine first' % common.RULE_DESCR)
        return rules[0]

    def plan(self):
        ctx = self.ctx()
        rule = self._rule(ctx)
        already = rule['enabled'] == self.enable
        steps = [_step('%s the rule "%s"' % ('Enable' if self.enable else 'Disable', common.RULE_DESCR),
                       'Firewall: Rules (model): enabled = %d' % int(self.enable),
                       'quarantined addresses are %s' % ('blocked again' if self.enable else
                                                         'not blocked (the ledger keeps recording)'),
                       already=already),
                 _step('Reload the rules', 'configctl filter reload', 'existing states are kept', already=already)]
        return _plan(steps, risk='low', revert=['Revert %s it again' % ('disables' if self.enable else 'enables')])

    def _toggle(self, ctx, enable):
        rule = self._rule(ctx)
        php(ctx, 'rule_enable', rule['uuid'], '1' if enable else '0')
        configctl(ctx, 'filter', 'reload')
        if os.path.exists(ctx.db):
            st = store_mod.Store(ctx.db)
            try:
                st.begin()
                st.set_meta('paused', '0' if enable else '1')
                st.add_event(None, ctx.clock(), 'resume' if enable else 'pause', origin='manual')
                st.commit()
            finally:
                st.close()

    def apply(self):
        ctx = self.ctx()
        if not ctx.is_root:
            return {'status': 'error', 'message': 'apply must run as root (configd)'}
        try:
            self._toggle(ctx, self.enable)
        except (common.QuarantineError, OSError) as exc:
            return {'status': 'error', 'done': False, 'message': str(exc)}
        return {'status': 'ok', 'done': True, 'completed': ['rule %s' % ('enabled' if self.enable else 'disabled'),
                                                            'rules reloaded'], 'state': {}}

    def revert_plan(self, entry, flags=None):
        steps = [_step('%s the rule "%s"' % ('Disable' if self.enable else 'Enable', common.RULE_DESCR),
                       'Firewall: Rules (model)', ''), _step('Reload the rules', 'configctl filter reload', '')]
        return _plan(steps, risk='low')

    def revert_apply(self, entry, flags=None):
        ctx = self.ctx()
        try:
            self._toggle(ctx, not self.enable)
        except (common.QuarantineError, OSError, ValueError) as exc:
            return {'status': 'error', 'done': False, 'message': str(exc)}
        return {'status': 'ok', 'done': True, 'completed': ['rule toggled back']}


@register
class QuarantinePause(_RuleToggle):
    name = 'quarantine_pause'
    description = 'Pause the quarantine (disable the rule "Max Cyber IA", keep the ledger)'
    enable = False


@register
class QuarantineResume(_RuleToggle):
    name = 'quarantine_resume'
    description = 'Resume the quarantine (enable the rule "Max Cyber IA")'
    enable = True


@register
class QuarantineSettings(_Base):
    name = 'quarantine_settings'
    description = 'Change a quarantine setting'

    def parse_args(self, args):
        args = list(args) + ['', '']
        key = args[0]
        if key not in common.DEFAULTS:
            raise ValueError('unknown setting')
        return {'key': key, 'value': common.validate_setting(key, args[1])}

    def _current(self, ctx, key):
        if not os.path.exists(ctx.db):
            raise ValueError('the quarantine is not installed')
        st = store_mod.Store(ctx.db)
        try:
            return st.stored_settings().get(key), st.settings()[key]
        finally:
            st.close()

    def plan(self, key, value):
        ctx = self.ctx()
        _stored, current = self._current(ctx, key)
        steps = [] if str(current) == str(value) else [
            _step('Set %s' % key, 'quarantine setting %s = %s' % (key, value), '%s -> %s' % (current, value))]
        return _plan(steps, risk='low', revert=['Revert restores %s = %s' % (key, current)])

    def apply(self, key, value):
        ctx = self.ctx()
        stored, current = self._current(ctx, key)
        st = store_mod.Store(ctx.db)
        try:
            st.begin()
            st.set_setting(key, value)
            st.add_event(None, ctx.clock(), 'settings', origin='manual', note='%s: %s -> %s' % (key, current, value))
            st.commit()
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['%s = %s' % (key, value)],
                'state': {'key': key, 'stored': stored}}

    def revert_plan(self, entry, flags=None):
        state = entry.get('state') or {}
        return _plan([_step('Restore %s' % state.get('key'), 'quarantine setting',
                            'back to %s' % (state.get('stored') if state.get('stored') is not None else 'the default'))],
                     risk='low')

    def revert_apply(self, entry, flags=None):
        ctx = self.ctx()
        state = entry.get('state') or {}
        st = store_mod.Store(ctx.db)
        try:
            st.begin()
            if state.get('stored') is None:
                st.db.execute('DELETE FROM settings WHERE key = ?', (state.get('key'),))
            else:
                st.set_setting(state['key'], state['stored'])
            st.add_event(None, ctx.clock(), 'settings', origin='manual', note='revert %s' % state.get('key'))
            st.commit()
        finally:
            st.close()
        return {'status': 'ok', 'done': True, 'completed': ['setting restored']}


@register
class UpdateAsnDb(_Base):
    name = 'update_asn_db'
    description = 'Download the ASN database used by the core (rulesets.opnsense.org) for ASN entries'
    URL = lookup_mod.ASN_SOURCE
    OPENER = staticmethod(urllib.request.urlopen)     # tests replace it

    def parse_args(self, args):
        return {}

    def plan(self):
        ctx = self.ctx()
        exists = os.path.exists(ctx.asn_csv)
        steps = [_step('Download the ASN database (about 10 MB compressed, 30 MB on disk)', 'GET %s' % self.URL,
                       '%s %s' % ('replace' if exists else 'create', ctx.asn_csv)),
                 _step('Index it for the country/ASN columns', 'quarantine index (background, nice 20)',
                       ctx.lookup_db)]
        return _plan(steps, risk='low', irreversible=['the downloaded bytes'],
                     warnings=['the firewall contacts rulesets.opnsense.org (the same source as the ASN aliases '
                               'of the core, which also refreshes this file daily while an ASN alias exists)'],
                     revert=['Revert restores the previous file (or removes it if there was none)'])

    def apply(self):
        ctx = self.ctx()
        if not ctx.is_root:
            return {'status': 'error', 'message': 'apply must run as root (configd)'}
        backup = os.path.join(ctx.state_dir, 'asn.csv.previous')
        existed = os.path.exists(ctx.asn_csv)
        tmp = ctx.asn_csv + '.%d.tmp' % os.getpid()
        try:
            os.makedirs(os.path.dirname(ctx.asn_csv), mode=0o750, exist_ok=True)
            if existed:
                shutil.copy2(ctx.asn_csv, backup)
            count = 0
            with self.OPENER(self.URL, timeout=60) as resp, open(tmp, 'w') as handle:
                with gzip.GzipFile(fileobj=resp) as gz:
                    for raw in gz:
                        parts = raw.decode('utf-8', 'replace').strip().split()
                        if len(parts) == 2:
                            handle.write('%s,%s\n' % tuple(parts))
                            count += 1
            if count < 1000:
                raise common.QuarantineError('the download has only %d entries' % count)
            os.chmod(tmp, 0o640)
            os.replace(tmp, ctx.asn_csv)
        except (OSError, EOFError, common.QuarantineError) as exc:
            if os.path.exists(tmp):
                os.unlink(tmp)
            return {'status': 'error', 'done': False, 'message': 'download failed: %s' % exc}
        if os.path.exists(ctx.db):
            st = store_mod.Store(ctx.db)
            try:
                st.begin()
                st.del_meta('index_started')
                st.commit()
                _engine(ctx)._maybe_index(st, ctx.clock(), None)
            finally:
                st.close()
        return {'status': 'ok', 'done': True, 'completed': ['%d prefixes saved in %s' % (count, ctx.asn_csv)],
                'state': {'existed': existed, 'backup': backup if existed else None},
                'irreversible': ['the downloaded bytes']}

    def revert_plan(self, entry, flags=None):
        ctx = self.ctx()
        state = entry.get('state') or {}
        return _plan([_step('Restore the previous ASN database' if state.get('existed') else 'Remove the ASN database',
                            'cp %s %s' % (state.get('backup'), ctx.asn_csv) if state.get('existed')
                            else 'rm %s' % ctx.asn_csv, '')], risk='low')

    def revert_apply(self, entry, flags=None):
        ctx = self.ctx()
        state = entry.get('state') or {}
        try:
            if state.get('existed') and state.get('backup') and os.path.exists(state['backup']):
                shutil.copy2(state['backup'], ctx.asn_csv)
            elif not state.get('existed') and os.path.exists(ctx.asn_csv):
                os.unlink(ctx.asn_csv)
        except OSError as exc:
            return {'status': 'error', 'done': False, 'message': str(exc)}
        return {'status': 'ok', 'done': True, 'completed': ['ASN database restored']}


ACTIONS = (QuarantineAdd, QuarantineRelease, QuarantineExtend, QuarantinePermanent, NeverBlockAdd, QuarantinePause,
           QuarantineResume, QuarantineSettings, UpdateAsnDb)


def _unused():  # pragma: no cover - keep linters quiet about optional imports
    return ipaddress
