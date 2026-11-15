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

    Change actions of the collectors (plan/apply/revert with the undo journal of ai/changes.py):

        collect_schedule <create|remove>     the 3 cron jobs, through the core cron model (model.php):
                                               */5 * "pa_collect run" flows
                                               7   * "pa_collect run" health
                                               3   * "pa_collect run" config
                                             + configctl cron restart.  Revert removes only the jobs that
                                             apply created (or adds back the ones it removed).
        collect_settings <key=value+key=value...|defaults>
                                             /var/db/policyanalyzer/collect/settings.json (retention, size
                                             limits, DNS source...); revert puts the previous file back.

    Registered when the package is imported next to ai/ (collect/__init__.py); cli.py "schedule" /
    "settings" / "revert" use the same dispatcher, so the journal entries are shared with the GUI history.
"""

import json
import os
import subprocess
import xml.etree.ElementTree as ET

from . import common

CRON_COMMAND = 'pa_collect run'
SCHEDULE = {'flows': ('*/5', '*'), 'health': ('7', '*'), 'config': ('3', '*')}


def cron_jobs(ctx):
    """ {kind: {"uuid", "minutes", "hours", "enabled"}} of the collector jobs in config.xml """
    try:
        root = ET.parse(ctx.config_xml).getroot()
    except (OSError, ET.ParseError):
        return {}
    out = {}
    for node in root.findall('./OPNsense/cron/jobs/job'):
        if (node.findtext('command') or '').strip() != CRON_COMMAND:
            continue
        kind = (node.findtext('parameters') or '').strip()
        if kind in SCHEDULE:
            out[kind] = {'uuid': node.get('uuid'), 'minutes': node.findtext('minutes'),
                         'hours': node.findtext('hours'), 'enabled': (node.findtext('enabled') or '1') != '0'}
    return out


def _run(argv, timeout=120):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                          stdin=subprocess.DEVNULL)
    out = proc.stdout.decode('utf-8', 'replace')
    if proc.returncode != 0:
        raise ValueError('%s failed: %s' % (' '.join(argv), (proc.stderr.decode('utf-8', 'replace') or out)[:300]))
    return out


def _sources_info(ctx):
    from . import flows
    settings = common.load_settings(ctx)
    root = common.load_config(ctx)
    dns = flows.dns_source(ctx, settings, root)
    items = []
    if dns == 'unbound':
        items.append('DNS: Unbound, %s' % ('statistics database %s (Reporting > Unbound DNS)' % ctx.unbound_db
                                            if os.path.exists(ctx.unbound_db) else
                                            'resolver log (statistics are off: enable them for client/action)'))
    elif dns == 'dnsmasq':
        items.append('DNS: dnsmasq log %s (needs "Log queries")' % ctx.dnsmasq_log)
    else:
        items.append('DNS: no resolver enabled, DNS is not collected')
    items.append('Blocks: %s (first run: the whole current daily file)' % ctx.filter_log)
    items.append('Config: %s and %s/config-*.xml (first run: the whole backup history)' % (ctx.config_xml,
                                                                                           ctx.backup_dir))
    items.append('Retention %d days, hourly detail %d days, size limits flows %d MiB / health %d MiB / config '
                 '%d MiB' % (settings['retention_days'], settings['compact_after_days'], settings['max_mb_flows'],
                             settings['max_mb_health'], settings['max_mb_config']))
    return items


def register(changes, ctx_factory=common.Context):

    @changes.register
    class CollectSchedule(changes.ChangeAction):
        name = 'collect_schedule'
        description = 'Local collectors: cron jobs for flows (every 5 min), health and config (hourly)'
        RUN = staticmethod(_run)
        CTX = None                       # tests

        def ctx(self):
            return self.CTX or ctx_factory()

        def parse_args(self, args):
            args = [a for a in args if a]
            if len(args) != 1 or args[0] not in ('create', 'remove'):
                raise ValueError('usage: collect_schedule <create|remove>')
            return {'op': args[0]}

        def _steps(self, ctx, op, only=None):
            jobs = cron_jobs(ctx)
            steps = []
            kinds = [k for k in SCHEDULE if only is None or k in only]
            if op == 'create':
                todo = [k for k in kinds if k not in jobs or not jobs[k]['enabled'] or
                        (jobs[k]['minutes'], jobs[k]['hours']) != SCHEDULE[k]]
                for k in todo:
                    steps.append({'description': 'Add the cron job %s %s * * * "%s %s"' % (
                        SCHEDULE[k][0], SCHEDULE[k][1], CRON_COMMAND, k),
                        'command': 'model.php cron_set %s' % k, 'effect': 'System: Settings: Cron', 'kind': k,
                        'existed': k in jobs})
            else:
                todo = [k for k in kinds if k in jobs]
                for k in todo:
                    steps.append({'description': 'Remove the cron job "%s %s"' % (CRON_COMMAND, k),
                                  'command': 'model.php cron_del %s' % k, 'effect': 'the %s collector stops' % k,
                                  'kind': k, 'existed': True})
            if steps:
                steps.append({'description': 'Apply the cron configuration', 'command': 'configctl cron restart',
                              'effect': 'cron reloads its table'})
            return steps

        def plan(self, op, only=None):
            ctx = self.ctx()
            steps = self._steps(ctx, op, only)
            warnings = []
            if op == 'create':
                warnings.append('while the LAN computer still runs opn.py, both collect side by side: compare with '
                                '"configctl pa_collect query compare 7d" before turning its timers off')
            info = [{'title': 'Sources', 'items': _sources_info(ctx)},
                    {'title': 'Files', 'items': ['%s/{config,health,flows}.db (0640), hmac.key (0600), settings.json'
                                                 % ctx.dir]}]
            return {'status': 'ok', 'args': {'op': op}, 'steps': steps, 'warnings': warnings, 'irreversible': [],
                    'revert': ['Revert %s only the cron jobs this change %s; the databases are kept' % (
                        'removes' if op == 'create' else 'adds back', 'created' if op == 'create' else 'removed')],
                    'risk': 'low' if steps else 'none', 'info': info}

        def apply(self, op, only=None):
            ctx = self.ctx()
            result = self.plan(op, only)
            steps = result['steps']
            if not steps:
                return dict(result, done=True, completed=[])
            touched = []
            completed = []
            for step in steps:
                if 'kind' in step:
                    self.RUN([ctx.php, ctx.model_php, 'cron_set' if op == 'create' else 'cron_del', step['kind']])
                    if not step['existed'] or op == 'remove':
                        touched.append(step['kind'])
                    completed.append(step['description'])
            self.RUN([ctx.configctl, 'cron', 'restart'])
            completed.append('Apply the cron configuration')
            if op == 'create':
                ctx.ensure_dirs()
            for step in steps:
                step.pop('kind', None)
                step.pop('existed', None)
            return dict(result, done=True, completed=completed, state={'op': op, 'kinds': touched})

        def revert_plan(self, entry):
            state = entry.get('state') or {}
            kinds = state.get('kinds') or []
            op = 'remove' if state.get('op') == 'create' else 'create'
            result = self.plan(op, only=kinds)
            for step in result['steps']:
                step.pop('kind', None)
                step.pop('existed', None)
            return result

        def revert_apply(self, entry):
            state = entry.get('state') or {}
            op = 'remove' if state.get('op') == 'create' else 'create'
            return self.apply(op, only=state.get('kinds') or [])

    @changes.register
    class CollectSettings(changes.ChangeAction):
        name = 'collect_settings'
        description = 'Local collectors: retention, compaction, size limits and DNS source'
        CTX = None

        def ctx(self):
            return self.CTX or ctx_factory()

        def parse_args(self, args):
            args = [a for a in args if a]
            if len(args) != 1:
                raise ValueError('usage: collect_settings <key=value+key=value...|defaults>')
            if args[0] == 'defaults':
                return {'spec': 'defaults'}
            values = {}
            for pair in args[0].split('+'):
                if '=' not in pair:
                    raise ValueError('expected key=value')
                key, value = pair.split('=', 1)
                values[key] = common.validate_setting(key, value)
            return {'spec': json.dumps(values, sort_keys=True)}

        def _target(self, ctx, spec):
            try:
                with open(ctx.settings_file) as handle:
                    raw = handle.read()
            except OSError:
                raw = None
            if spec == 'defaults':
                return raw, None
            current = {}
            if raw:
                try:
                    current = json.loads(raw)
                except ValueError:
                    current = {}
            current.update(json.loads(spec))
            return raw, current

        def plan(self, spec):
            ctx = self.ctx()
            raw, target = self._target(ctx, spec)
            before = common.load_settings(ctx)
            after = dict(common.DEFAULTS, **(target or {}))
            steps = [{'description': 'Set %s: %s -> %s' % (k, before.get(k), after.get(k)),
                      'command': 'write %s' % ctx.settings_file, 'effect': 'next collector runs'}
                     for k in sorted(after) if before.get(k) != after.get(k)]
            warnings = []
            if after['retention_days'] < before['retention_days']:
                warnings.append('a shorter retention deletes the older days at the next daily maintenance')
            return {'status': 'ok', 'args': {'spec': spec}, 'steps': steps, 'warnings': warnings,
                    'irreversible': ['days deleted by a shorter retention do not come back with the revert']
                    if warnings else [], 'revert': ['Revert restores the previous settings.json'],
                    'risk': 'low' if steps else 'none'}

        def apply(self, spec):
            ctx = self.ctx()
            result = self.plan(spec)
            if not result['steps']:
                return dict(result, done=True, completed=[])
            raw, target = self._target(ctx, spec)
            ctx.ensure_dirs()
            if target is None:
                try:
                    os.unlink(ctx.settings_file)
                except FileNotFoundError:
                    pass
            else:
                common.write_json_atomic(ctx.settings_file, target)
            return dict(result, done=True, completed=[s['description'] for s in result['steps']],
                        state={'previous': raw})

        def revert_plan(self, entry):
            ctx = self.ctx()
            return {'status': 'ok', 'steps': [{'description': 'Restore the previous collector settings',
                                               'command': 'write %s' % ctx.settings_file,
                                               'effect': 'next collector runs'}],
                    'warnings': [], 'irreversible': [], 'risk': 'low'}

        def revert_apply(self, entry):
            ctx = self.ctx()
            previous = (entry.get('state') or {}).get('previous')
            if previous is None:
                try:
                    os.unlink(ctx.settings_file)
                except FileNotFoundError:
                    pass
            else:
                tmp = ctx.settings_file + '.tmp'
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
                with os.fdopen(fd, 'w') as handle:
                    handle.write(previous)
                os.replace(tmp, ctx.settings_file)
            plan = self.revert_plan(entry)
            return dict(plan, done=True, completed=[s['description'] for s in plan['steps']])

    return CollectSchedule, CollectSettings
