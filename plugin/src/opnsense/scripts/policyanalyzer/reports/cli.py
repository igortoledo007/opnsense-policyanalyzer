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

    configd entry point of the reports and the notification center (actions_pa_reports.conf). One JSON document.

      cli.py settings                              settings (no secret), effective channel with origins, Monit view
      cli.py monit                                 what "Import from Monit" would copy (never the password)
      cli.py preview <6h|daily|weekly|manual> [ai]  report HTML/text, nothing sent or stored (AI only with "ai")
      cli.py preview <kind> pdf|aipdf              the report PDF (base64 in "pdf"), for the download button
      cli.py send <6h|daily|weekly> [wait]         scheduled run (cron): respects the settings; starts the detached
                                                   run and returns at once ("wait": in this process, as before)
      cli.py send_run <6h|daily|weekly>            the detached run itself (log: /var/log/policyanalyzer/reports.log)
      cli.py notify                                scheduled run of the notification center (cron)
      cli.py notify_preview                        what the detectors see now, nothing queued or sent
      cli.py history <page:rows> [kind]            e-mails sent / failed / skipped
      cli.py message <id>                          one stored e-mail (HTML and text)
      cli.py notifications <page:rows> [status]    queue and history, subscriptions, sources state
      cli.py resend <notification id>              queue again and send now (no throttle)
      cli.py summary                               light view for the Max Cyber
      cli.py plan|apply <reports_settings|reports_import_monit|reports_send_test|revert> [args...]
"""

import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ''):
    sys.path = [p for p in sys.path if os.path.abspath(p or '.') != _HERE]
    sys.path.insert(0, os.path.dirname(_HERE))

from reports import actions, common, deliver, monit, notify, settings, store  # noqa: E402

OWN_ACTIONS = ('reports_settings', 'reports_import_monit', 'reports_send_test', 'revert')
USAGE = 'usage: cli.py settings|monit|preview|send|notify|history|message|notifications|resend|summary|plan|apply'


def _page(token, rows=25):
    match = re.match(r'^(\d{1,5}):(\d{1,3})$', token or '')
    return (int(match.group(1)), int(match.group(2))) if match else (1, rows)


def summary():
    cfg = settings.load()
    chan = settings.effective_smtp(cfg)
    out = {'status': 'ok', 'reports_enabled': cfg['report']['enabled'], 'notify_enabled': cfg['notify']['enabled'],
           'channel': {'mode': cfg['email']['mode'], 'available': bool(chan.get('available'))},
           'schedule': actions.desired_crons(cfg), 'installed_crons': sorted(actions.cron_jobs()),
           'last_report': None, 'last_failure': None, 'notifications': {}, 'running': deliver.running_reports()}
    db = store.connect(readonly=True)
    if db is None:
        return out
    try:
        row = db.execute("SELECT id, ts, kind, status, subject FROM messages WHERE kind LIKE 'report%' "
                         "AND status != 'skipped' ORDER BY ts DESC LIMIT 1").fetchone()
        if row:
            out['last_report'] = {'id': row[0], 'ts': common.iso(row[1]), 'kind': row[2], 'status': row[3],
                                  'subject': row[4]}
        row = db.execute("SELECT ts, kind, error FROM messages WHERE status = 'failed' ORDER BY ts DESC LIMIT 1") \
            .fetchone()
        if row:
            out['last_failure'] = {'ts': common.iso(row[0]), 'kind': row[1], 'error': row[2]}
        out['notifications'] = dict(db.execute('SELECT status, count(*) FROM notifications WHERE ts >= ? '
                                               'GROUP BY status', (int(common.now()) - 86400,)).fetchall())
        out['last_notify_run'] = store.meta_get(db, 'last_notify_run')
    finally:
        db.close()
    return out


def notify_preview():
    """ run the detectors against a throw-away copy of the markers: nothing is queued or sent """
    import sqlite3
    cfg = settings.load()
    mem = sqlite3.connect(':memory:')
    mem.executescript(store.SCHEMA)
    real = store.connect(readonly=True)
    if real is not None:
        for key, value in real.execute('SELECT key, value FROM meta'):
            mem.execute('INSERT INTO meta (key, value) VALUES (?, ?)', (key, value))
        real.close()
    out = {}
    for name, func in notify.DETECTORS:
        try:
            events = func(mem, int(common.now()))
        except Exception as exc:            # noqa: BLE001
            out[name] = {'error': str(exc)[:200]}
            continue
        out[name] = None if events is None else events[:20]
    mem.close()
    return {'status': 'ok', 'sources': out, 'available': notify.sources_state(), 'enabled': cfg['notify']['enabled']}


def run(argv):
    args = [a for a in argv if a != '']
    if not args:
        raise ValueError(USAGE)
    cmd, rest = args[0], args[1:] + ['', '']
    if cmd == 'settings':
        return dict(settings.public(), installed_crons=actions.cron_jobs(),
                    desired_crons=actions.desired_crons(settings.load()))
    if cmd == 'monit':
        return dict(monit.public(), status='ok')
    if cmd == 'preview':
        kind = rest[0] if rest[0] in ('6h', 'daily', 'weekly', 'manual') else 'manual'
        return deliver.preview_report(kind, ai=rest[1] in ('ai', 'aipdf'), pdf=rest[1] in ('pdf', 'aipdf'))
    if cmd == 'send':
        if rest[0] not in ('6h', 'daily', 'weekly'):
            raise ValueError('send 6h|daily|weekly')
        if rest[1] == 'wait':
            return deliver.run_report(rest[0])
        return deliver.start_report(rest[0])
    if cmd == 'send_run':
        if rest[0] not in ('6h', 'daily', 'weekly'):
            raise ValueError('send_run 6h|daily|weekly')
        return deliver.run_report(rest[0])
    if cmd == 'notify':
        return notify.run(scheduled=True)
    if cmd == 'notify_preview':
        return notify_preview()
    if cmd == 'history':
        page, rows = _page(rest[0])
        db = store.connect(readonly=True)
        if db is None:
            return {'status': 'ok', 'total': 0, 'rows': []}
        try:
            total, items = store.messages(db, page, rows, rest[1] if rest[1] in (
                'report', 'test', 'notification', 'digest') else None)
        finally:
            db.close()
        return {'status': 'ok', 'total': total, 'rows': items, 'page': page}
    if cmd == 'message':
        if not re.match(r'^\d{1,9}$', rest[0]):
            raise ValueError('invalid message id')
        db = store.connect(readonly=True)
        if db is None:
            return {'status': 'error', 'message': 'not found'}
        try:
            msg = store.message(db, int(rest[0]))
        finally:
            db.close()
        return {'status': 'ok', 'message': msg} if msg else {'status': 'error', 'message': 'not found'}
    if cmd == 'notifications':
        page, rows = _page(rest[0], 50)
        status = rest[1] if rest[1] in ('queued', 'held', 'sent', 'failed', 'suppressed') else None
        return notify.overview(page, rows, status)
    if cmd == 'resend':
        if not re.match(r'^\d{1,9}$', rest[0]):
            raise ValueError('invalid notification id')
        return notify.resend(int(rest[0]))
    if cmd == 'summary':
        return summary()
    if cmd in ('plan', 'apply'):
        from ai import changes
        if args[1:2] and args[1] in OWN_ACTIONS:
            return changes.run(cmd, args[1], args[2:])
        raise ValueError('unknown action')
    raise ValueError(USAGE)


def main(argv=None):
    try:
        result = run(sys.argv[1:] if argv is None else argv)
    except ValueError as exc:
        result = {'status': 'error', 'message': str(exc)}
    except OSError as exc:
        result = {'status': 'error', 'message': 'unable to read the state: %s' % exc}
    sys.stdout.write(json.dumps(result) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
