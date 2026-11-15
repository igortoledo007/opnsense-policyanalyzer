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

    Change actions of the reports and notification center (plan / apply / revert, journal in
    /var/db/policyanalyzer/undo/):

      reports_settings <base64url JSON>   save the settings (channel, report schedule, sections, subscriptions,
                                          notification center on/off) and reconcile the cron jobs of the core
                                          (System > Settings > Cron, origin PolicyAnalyzer) through reports/model.php:
                                            report_6h     pa_reports send 6h      0 0,6,12,18 * * *  (without the daily hour)
                                            report_daily  pa_reports send daily   0 <hour> * * *
                                            report_weekly pa_reports send weekly  <min> <hour> * * <day> (Mon 07:30)
                                            notify        pa_reports notify       */5 * * * *
                                          then "configctl cron restart". Revert restores settings, secret and jobs.
      reports_import_monit                copy the Monit e-mail settings into the plugin (mode "own"), password into
                                          the secret file (never shown). Double confirmation when own settings exist.
      reports_send_test <test|report>     send a test message (or the report now, with the PDF attached when
                                          "Attach PDF" is on) through the active channel;
                                          an e-mail can not be unsent (not revertible)

    The JSON payload never carries the Monit password; an own password ("password") goes straight to the secret
    file and never into the journal.
"""

import os
import shutil

from ai import changes

from . import common, deliver, monit, settings

CRON = {'report_6h': 'pa_reports send 6h', 'report_daily': 'pa_reports send daily',
        'report_weekly': 'pa_reports send weekly', 'notify': 'pa_reports notify'}
SECRET_FIELDS = ('password',)


def _runner():
    return common.Runner()


RUNNER_FACTORY = _runner


def cron_jobs(root=None):
    root = root if root is not None else common.config_root()
    out = {}
    if root is None:
        return out
    for node in root.findall('./OPNsense/cron/jobs/job'):
        command = (node.findtext('command') or '').strip()
        params = (node.findtext('parameters') or '').strip()
        full = (command + ' ' + params).strip()     # the core keeps the action in command and its arguments apart
        for kind, cmd in CRON.items():
            if full == cmd:
                out[kind] = {'uuid': node.get('uuid'), 'minutes': (node.findtext('minutes') or '').strip(),
                             'hours': (node.findtext('hours') or '').strip(),
                             'weekdays': (node.findtext('weekdays') or '*').strip() or '*',
                             'enabled': (node.findtext('enabled') or '1').strip() == '1'}
    return out


def desired_crons(cfg):
    out = {}
    rp = cfg['report']
    if rp['enabled'] and rp['every_6h']:
        hours = [h for h in range(0, 24, 6) if not (rp['daily'] and h == rp['daily_hour'])]
        out['report_6h'] = {'minutes': '0', 'hours': ','.join(str(h) for h in hours)}
    if rp['enabled'] and rp['daily']:
        out['report_daily'] = {'minutes': '0', 'hours': str(rp['daily_hour'])}
    if rp['enabled'] and rp.get('weekly', True):
        out['report_weekly'] = {'minutes': str(rp.get('weekly_minute', 30)), 'hours': str(rp.get('weekly_hour', 7)),
                                'weekdays': str(rp.get('weekly_day', 1))}
    if cfg['notify']['enabled']:
        out['notify'] = {'minutes': '*/5', 'hours': '*'}
    return out


def cron_steps(want, have):
    steps = []
    for kind in sorted(set(want) | set(have)):
        w, h = want.get(kind), have.get(kind)
        wd = (w or {}).get('weekdays') or '*'
        if w and (not h or (h['minutes'], h['hours'], h.get('weekdays') or '*') != (w['minutes'], w['hours'], wd) or
                  not h['enabled']):
            steps.append({'description': '%s cron job "%s": minute %s, hour %s%s' % (
                'Update' if h else 'Add', CRON[kind], w['minutes'], w['hours'],
                ', weekday %s' % wd if wd != '*' else ''),
                          'command': 'model.php cron_set %s %s %s%s' % (kind, w['minutes'], w['hours'],
                                                                       ' %s' % wd if wd != '*' else ''),
                          'effect': 'System > Settings > Cron (origin PolicyAnalyzer)', 'op': 'set', 'kind': kind,
                          'minutes': w['minutes'], 'hours': w['hours'], 'weekdays': wd})
        elif h and not w:
            steps.append({'description': 'Remove cron job "%s"' % CRON[kind],
                          'command': 'model.php cron_del %s' % kind, 'effect': 'no more scheduled runs',
                          'op': 'del', 'kind': kind})
    if steps:
        steps.append({'description': 'Apply the cron configuration', 'command': 'configctl cron restart',
                      'effect': 'cron reloads its table', 'op': 'restart'})
    return steps


def _php(*args):
    import json
    model = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model.php')
    rc, out, err = RUNNER_FACTORY()([common.paths()['php'], model] + [str(a) for a in args], 60)
    try:
        data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except ValueError:
        data = {}
    if rc != 0 or data.get('status') != 'ok':
        raise ValueError('core model (%s): %s' % (args[0], data.get('message') or err.strip() or rc))
    return data


def _run_cron_steps(steps):
    done = []
    for step in steps:
        if step['op'] == 'set':
            extra = [step['weekdays']] if step.get('weekdays', '*') != '*' else []
            _php('cron_set', step['kind'], step['minutes'], step['hours'], *extra)
        elif step['op'] == 'del':
            _php('cron_del', step['kind'])
        elif step['op'] == 'restart':
            rc, out, err = RUNNER_FACTORY()([common.paths()['configctl'], 'cron', 'restart'], 120)
            if rc != 0:
                raise ValueError('configctl cron restart: %s' % ((err or out).strip() or rc))
        done.append(step['command'])
    return done


def _public_steps(steps):
    return [{k: s[k] for k in ('description', 'command', 'effect')} for s in steps]


def _diff(old, new, prefix=''):
    out = []
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key), new.get(key)
        if isinstance(a, dict) and isinstance(b, dict):
            out.extend(_diff(a, b, prefix + key + '.'))
        elif a != b:
            out.append('%s%s: %s -> %s' % (prefix, key, _short(a), _short(b)))
    return out


def _short(value):
    text = ', '.join(map(str, value)) if isinstance(value, list) else str(value)
    return text if len(text) < 80 else text[:77] + '...'


def _secret_backup():
    path = common.paths()['secret']
    if not os.path.exists(path):
        return None
    backup = '%s.%s.bak' % (path, common.token())
    shutil.copy2(path, backup)
    os.chmod(backup, 0o600)
    return backup


def _secret_restore(backup):
    path = common.paths()['secret']
    if backup and os.path.exists(backup) and os.path.dirname(backup) == os.path.dirname(path):
        os.replace(backup, path)
        return 'own SMTP password restored'
    if not backup and os.path.exists(path):
        os.unlink(path)
        return 'own SMTP password removed'
    return None


@changes.register
class ReportsSettings(changes.ChangeAction):
    name = 'reports_settings'
    description = 'Reports & notifications: save the settings and schedule the cron jobs'

    def parse_args(self, args):
        data = common.b64decode_json(args[0] if args else '')
        password = data.pop('password', None)
        clear = bool(data.pop('password_clear', False))
        if password is not None and (not isinstance(password, str) or len(password) > 256 or
                                     any(c in password for c in '\r\n')):
            raise ValueError('invalid password')
        cfg = settings.validate(data)
        if password and cfg['email']['mode'] != 'own':
            raise ValueError('a password is only stored for the own channel (mode "own")')
        return {'cfg': cfg, 'password': password or None, 'clear': clear}

    def _plan(self, cfg, password, clear):
        old = settings.load()
        diff = _diff(old, cfg)
        steps = []
        if diff:
            steps.append({'description': 'Save the reports & notifications settings (%d change(s))' % len(diff),
                          'command': 'write %s' % common.paths()['settings'], 'effect': 'used by the next run',
                          'op': 'settings'})
        if password or clear:
            steps.append({'description': 'Store a new own SMTP password' if password else 'Remove the own SMTP password',
                          'command': 'write %s (0600, never shown)' % common.paths()['secret'],
                          'effect': 'used only by the own channel', 'op': 'secret'})
        steps += cron_steps(desired_crons(cfg), cron_jobs())
        warnings = []
        chan = settings.effective_smtp(cfg)
        if (cfg['report']['enabled'] or cfg['notify']['enabled']) and not chan.get('available'):
            warnings.append('the e-mail channel is not usable yet: %s' % chan.get('message'))
        if cfg['email']['mode'] == 'own' and cfg['email']['security'] == 'none':
            warnings.append('the own channel sends in plain text (no TLS): the password and the reports travel '
                            'unencrypted')
        return old, steps, diff, warnings, chan

    def plan(self, cfg, password, clear):
        _old, steps, diff, warnings, chan = self._plan(cfg, password, clear)
        info = [{'title': 'Changed settings', 'items': diff or ['none']},
                {'title': 'E-mail channel', 'items': ['mode: %s' % cfg['email']['mode'],
                                                      'server: %s:%s (%s)' % (chan.get('host') or '-', chan.get('port') or '-',
                                                                              chan.get('security') or '-'),
                                                      'origin: %s' % chan.get('origin'),
                                                      'recipients: %s (%s)' % (', '.join(chan.get('recipients') or []) or '-',
                                                                               chan.get('recipients_origin') or '-')]}]
        return {'status': 'ok', 'steps': _public_steps(steps), 'risk': 'low' if steps else 'none', 'warnings': warnings,
                'revert': ['Undo restores the previous settings, the own password and the cron jobs.'],
                'info': info, 'args': {'mode': cfg['email']['mode'], 'report': cfg['report']['enabled'],
                                       'notify': cfg['notify']['enabled']}}

    def apply(self, cfg, password, clear):
        old, steps, _diff_, _w, _c = self._plan(cfg, password, clear)
        before_crons = cron_jobs()
        state = {'settings': old, 'secret_backup': None, 'secret_changed': False,
                 'crons': {k: {'minutes': v['minutes'], 'hours': v['hours']} for k, v in before_crons.items()}}
        completed = []
        if any(s['op'] == 'secret' for s in steps):
            state['secret_backup'] = _secret_backup()
            state['secret_changed'] = True
            settings.set_secret(password if password else '')
            completed.append('own SMTP password %s' % ('stored' if password else 'removed'))
        settings.save(cfg)
        completed.append('settings saved')
        try:
            completed += _run_cron_steps([s for s in steps if s['op'] in ('set', 'del', 'restart')])
        except ValueError as exc:
            return {'status': 'error', 'done': False, 'completed': completed, 'state': state, 'steps': [],
                    'message': str(exc), 'args': {'mode': cfg['email']['mode']}}
        return {'status': 'ok', 'done': True, 'completed': completed, 'state': state, 'steps': [],
                'args': {'mode': cfg['email']['mode'], 'report': cfg['report']['enabled'],
                         'notify': cfg['notify']['enabled']}}

    def revert_plan(self, entry):
        st = entry.get('state') or {}
        prev = settings.validate(st.get('settings') or {})
        steps = [{'description': 'Restore the previous reports & notifications settings',
                  'command': 'write %s' % common.paths()['settings'], 'effect': 'previous values', 'op': 'settings'}]
        if st.get('secret_changed'):
            steps.append({'description': 'Restore the previous own SMTP password', 'command': 'write secret (0600)',
                          'effect': 'the password before this change', 'op': 'secret'})
        steps += cron_steps(st.get('crons') or {}, cron_jobs())
        return {'status': 'ok', 'steps': _public_steps(steps), 'risk': 'low', 'warnings': [], 'revert': [],
                'info': [{'title': 'Settings after the revert', 'items': _diff(settings.load(), prev) or ['unchanged']}]}

    def revert_apply(self, entry):
        st = entry.get('state') or {}
        completed = []
        if st.get('secret_changed'):
            msg = _secret_restore(st.get('secret_backup'))
            if msg:
                completed.append(msg)
        settings.save(st.get('settings') or {})
        completed.append('settings restored')
        completed += _run_cron_steps([s for s in cron_steps(st.get('crons') or {}, cron_jobs())
                                      if s['op'] in ('set', 'del', 'restart')])
        return {'status': 'ok', 'done': True, 'completed': completed, 'steps': []}


@changes.register
class ReportsImportMonit(changes.ChangeAction):
    name = 'reports_import_monit'
    description = 'Reports & notifications: copy the Monit e-mail settings into the plugin (own channel)'

    def parse_args(self, args):
        return {}

    def _values(self):
        mon = monit.read()
        if mon is None:
            raise ValueError('Monit has no mail server configured (Services > Monit > Settings)')
        return mon

    def plan(self):
        mon = self._values()
        cur = settings.load()
        own = cur['email']['mode'] == 'own' or bool(cur['email']['host'])
        new_email = {'mode': 'own', 'host': mon['host'], 'port': mon['port'], 'security': mon['security'],
                     'verify': mon['verify'], 'min_tls': mon['min_tls'], 'username': mon['username'],
                     'sender': mon['sender'], 'recipients': mon['recipients']}
        diff = _diff({k: cur['email'].get(k) for k in new_email}, new_email)
        items = ['server: %s (Monit: %s)' % (mon['host'], ', '.join(mon['hosts'])), 'port: %s' % mon['port'],
                 'security: %s, verify certificate: %s, minimum TLS: %s' % (mon['security'], mon['verify'],
                                                                            mon['min_tls']),
                 'user: %s' % (mon['username'] or '(none)'), 'sender: %s (%s)' % (mon['sender'], mon['sender_source']),
                 'recipients: %s' % (', '.join(mon['recipients']) or '(none)'),
                 'password: %s' % ('copied into the plugin secret file, never shown' if mon['password_set']
                                   else 'Monit has none')]
        return {'status': 'ok', 'risk': 'low',
                'steps': [{'description': 'Copy the Monit e-mail settings into the plugin and switch to the own channel',
                           'command': 'write %s' % common.paths()['settings'],
                           'effect': 'the plugin settings become independent of Monit and editable'},
                          {'description': 'Copy the Monit SMTP password into the plugin secret file',
                           'command': 'write %s (0600)' % common.paths()['secret'],
                           'effect': 'shown only as ****, never returned'}],
                'warnings': (['own e-mail settings already exist: importing overwrites them'] if own else []) +
                            ['after the import, changes in Monit are no longer followed (use "Use Monit settings" '
                             'for that)'],
                'requires_double_confirmation': own,
                'info': [{'title': 'Values that will be copied', 'items': items},
                         {'title': 'Changes', 'items': diff or ['none']}],
                'revert': ['Undo restores the previous e-mail settings and password.'], 'args': {}}

    def apply(self):
        mon = self._values()
        cfg = settings.load()
        old = settings.load()
        cfg['email'].update({'mode': 'own', 'host': mon['host'], 'port': mon['port'], 'security': mon['security'],
                             'verify': mon['verify'], 'min_tls': mon['min_tls'], 'username': mon['username'],
                             'sender': mon['sender'], 'recipients': mon['recipients'], 'imported_at': common.iso()})
        backup = _secret_backup()
        settings.set_secret(monit.password())
        settings.save(cfg)
        return {'status': 'ok', 'done': True, 'steps': [], 'args': {},
                'completed': ['Monit e-mail settings copied (own channel)', 'password copied (masked)'],
                'state': {'settings': old, 'secret_backup': backup, 'secret_changed': True}}

    def revert_plan(self, entry):
        return {'status': 'ok', 'risk': 'low', 'warnings': [], 'revert': [],
                'steps': [{'description': 'Restore the e-mail settings and password before the import',
                           'command': 'write %s, %s' % (common.paths()['settings'], common.paths()['secret']),
                           'effect': 'channel mode %s' % ((entry.get('state') or {}).get('settings') or {})
                           .get('email', {}).get('mode', 'monit')}]}

    def revert_apply(self, entry):
        st = entry.get('state') or {}
        completed = []
        msg = _secret_restore(st.get('secret_backup'))
        if msg:
            completed.append(msg)
        settings.save(st.get('settings') or {})
        completed.append('settings restored')
        return {'status': 'ok', 'done': True, 'steps': [], 'completed': completed}


@changes.register
class ReportsSendTest(changes.ChangeAction):
    name = 'reports_send_test'
    description = 'Reports & notifications: send a test e-mail (or the report now) through the active channel'
    revertible = False

    def parse_args(self, args):
        what = (args[0] if args else 'test') or 'test'
        if what not in ('test', 'report'):
            raise ValueError('choose test or report')
        return {'what': what}

    def plan(self, what):
        cfg = settings.load()
        chan = settings.effective_smtp(cfg)
        if not chan.get('available'):
            return {'status': 'error', 'message': chan.get('message') or 'the e-mail channel is not configured',
                    'steps': []}
        subject = deliver.test_message(cfg)[0] if what == 'test' else 'report (sections: %s)%s' % (', '.join(
            cfg['report']['sections']), '; PDF attached' if cfg['report'].get('attach_pdf', True) else
            '; no PDF ("Attach PDF" is off)')
        return {'status': 'ok', 'risk': 'low',
                'steps': [{'description': 'Send %s to %s' % ('a test message' if what == 'test' else 'the report now',
                                                            ', '.join(chan['recipients'])),
                           'command': 'SMTP %s:%s (%s%s)' % (chan['host'], chan['port'], chan['security'],
                                                             ', certificate verified' if chan['verify'] else
                                                             ', certificate NOT verified'),
                           'effect': 'subject: %s; sender %s' % (subject, chan['sender'])}],
                'irreversible': ['an e-mail can not be unsent'],
                'requires_double_confirmation': False,
                'warnings': ['the report calls the AI for the executive summary when it is enabled'] if what == 'report'
                else [],
                'info': [{'title': 'Channel', 'items': ['mode: %s' % chan['mode'], 'origin: %s' % chan['origin'],
                                                        'user: %s' % (chan['username'] or '(none)'),
                                                        'password: %s' % chan['password_hint']]}],
                'args': {'what': what}}

    def apply(self, what, smtp_factory=None):
        if what == 'report':
            result = deliver.send_report('manual', scheduled=False, smtp_factory=smtp_factory)
        else:
            from . import store
            cfg = settings.load()
            subject, html_body, text = deliver.test_message(cfg)
            db = store.connect()
            try:
                result = deliver.send_and_record(db, 'test', subject, html_body, text, cfg, smtp_factory=smtp_factory)
            finally:
                db.close()
        ok = result.get('status') == 'sent'
        return {'status': 'ok' if ok else 'error', 'done': ok, 'steps': [], 'args': {'what': what},
                'completed': ['sent to %s' % ', '.join(result.get('recipients') or [])] if ok else [],
                'message': None if ok else result.get('error'), 'state': {'message_id': result.get('message_id')},
                'irreversible': ['an e-mail can not be unsent']}
