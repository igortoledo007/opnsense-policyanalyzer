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

    Building and sending the e-mails: the periodic report, the test message, and the shared "send and record"
    used by the notification center. Every attempt is recorded in reports.db (messages).

    Scheduled reports run detached (start_report): the cron entry "configctl pa_reports send <kind>" returns at
    once with {"status": "started", "pid"}, the child "cli.py send_run <kind>" holds the lock of the kind (a
    second start while one runs answers "running"), writes JSON lines to /var/log/policyanalyzer/reports.log and
    records an unexpected error as a failed message in the history. The AI part is bounded (aisum.AI_SECONDS).
"""

import base64
import fcntl
import json
import os
import subprocess
import sys
import time
import traceback

from . import aisum, collect, common, mailer, pdfreport, render, settings, store

PERIODS = {'6h': 6 * 3600, 'daily': 86400, 'weekly': 7 * 86400, 'manual': 86400}
SMTP_FACTORY = None          # tests replace it (fake SMTP); never None in the tests
PDF_MAX_BYTES = 2 * 1024 * 1024      # hard limit of the attachment (target < 300 KB, see pdfreport.MAX_BYTES)


def hostname(root=None):
    root = root if root is not None else common.config_root()
    if root is None:
        return 'OPNsense'
    host = (root.findtext('./system/hostname') or 'OPNsense').strip()
    domain = (root.findtext('./system/domain') or '').strip()
    return host + ('.' + domain if domain else '')


def channel(cfg):
    chan = settings.effective_smtp(cfg, with_password=True)
    if not chan.get('available'):
        raise mailer.MailError(chan.get('message') or 'the e-mail channel is not configured')
    return chan


def channel_label(chan):
    return '%s:%s (%s, %s)' % (chan['host'], chan['port'], chan['security'], chan['origin'])


def send_and_record(db, kind, subject, html_body, text, cfg, period=(None, None), summary=None, ai_used=False,
                    smtp_factory=None, recipients=None, attachments=None):
    started = time.monotonic()
    chan = None
    try:
        chan = channel(cfg)
        if recipients:
            chan['recipients'] = recipients
        msg = mailer.build(subject, chan['sender'], chan['recipients'], text, html_body, hostname=None,
                           attachments=attachments)
        mailer.send(msg, chan, smtp_factory=smtp_factory or SMTP_FACTORY)
        status, error = 'sent', None
    except mailer.MailError as exc:
        status, error = 'failed', str(exc)
    msg_id = store.add_message(db, kind, subject, (chan or {}).get('recipients') or [], status, error, period,
                               html_body, text, summary, ai_used, 1, int((time.monotonic() - started) * 1000),
                               channel_label(chan) if chan else None)
    db.commit()
    return {'status': status, 'error': error, 'message_id': msg_id,
            'recipients': (chan or {}).get('recipients') or [], 'channel': channel_label(chan) if chan else None,
            'attachments': [{'name': a[0], 'size': len(a[1])} for a in attachments or []]}


def build_pdf(rep, cfg):
    """ (filename, bytes, error): the PDF of a built report; a failure never blocks the e-mail """
    try:
        name, data = pdfreport.report(rep['data'], rep['summary'], cfg['language'], rep.get('hostname') or '',
                                      cfg['report']['sections'], rep.get('base') or '',
                                      charts_on=cfg['report'].get('charts', True))
    except Exception as exc:                # noqa: BLE001 - the e-mail goes without the attachment
        return None, None, 'PDF not generated: %s' % str(exc)[:200]
    if len(data) > PDF_MAX_BYTES:
        return None, None, 'PDF not attached: %d bytes (limit %d)' % (len(data), PDF_MAX_BYTES)
    return name, data, None


def period(kind, now):
    """
    (since, until) of a report: the last 6 h / 24 h up to now; weekly = the 7 whole local days that end at the
    midnight of today (Monday 07:30 covers Monday..Sunday of the previous week, like the old relatorio.py --semanal)
    """
    now = int(now)
    if kind != 'weekly':
        return now - PERIODS.get(kind, 86400), now
    tm = time.localtime(now)
    until = int(time.mktime((tm.tm_year, tm.tm_mon, tm.tm_mday, 0, 0, 0, 0, 0, -1)))
    since = int(time.mktime((tm.tm_year, tm.tm_mon, tm.tm_mday - 7, 0, 0, 0, 0, 0, -1)))
    return since, until


NOTIFY_CONTEXT_HOURS = 24


def build_notification_pdf(events, summary, cfg, host, base, now):
    """ (filename, bytes, error) of the PDF attached to a notification; a failure never blocks the e-mail """
    try:
        now = int(now)
        since = now - NOTIFY_CONTEXT_HOURS * 3600
        metrics = collect.metrics(since, now) if cfg['report'].get('charts', True) else {}
        cves = None
        if events and events[0].get('type') == 'vuln_kev_p1':
            cves = collect.cves()
        name, data = pdfreport.notification(events, summary, cfg['language'], host, base, metrics, cves,
                                            NOTIFY_CONTEXT_HOURS, now=now)
    except Exception as exc:                # noqa: BLE001 - the e-mail goes without the attachment
        return None, None, 'PDF not generated: %s' % str(exc)[:200]
    if len(data) > PDF_MAX_BYTES:
        return None, None, 'PDF not attached: %d bytes (limit %d)' % (len(data), PDF_MAX_BYTES)
    return name, data, None


def build_report(kind, cfg, now=None, db=None, assistant=None, ai=True):
    now = int(common.now() if now is None else now)
    since, now = period(kind, now)
    previous = None
    if db is not None:
        try:
            previous = json.loads(store.meta_get(db, 'last_report_posture', 'null') or 'null')
        except ValueError:
            previous = None
    sections = cfg['report']['sections']
    data = collect.build(kind, since, now, sections, db, previous, charts=cfg['report'].get('charts', True))
    language = cfg['language']
    summary = None
    if 'ai_summary' in sections:
        summary = aisum.executive(data, language, enabled=ai and cfg['report']['ai_summary'], assistant=assistant)
    root = common.config_root()
    base = common.gui_base(root, cfg.get('gui_url'))
    subject, html_body, text = render.report(data, summary, language, base, hostname(root), sections)
    return {'data': data, 'summary': summary, 'subject': subject, 'html': html_body, 'text': text,
            'period': (since, now), 'has_events': collect.has_events(data), 'hostname': hostname(root), 'base': base}


def send_report(kind, scheduled=False, now=None, smtp_factory=None, assistant=None):
    """ kind 6h | daily | weekly | manual ; scheduled = called by cron (respects the settings) """
    cfg = settings.load()
    if scheduled:
        if not cfg['report']['enabled']:
            return {'status': 'skipped', 'reason': 'reports are disabled'}
        if (kind == '6h' and not cfg['report']['every_6h']) or (kind == 'daily' and not cfg['report']['daily']) or \
                (kind == 'weekly' and not cfg['report'].get('weekly', True)):
            return {'status': 'skipped', 'reason': 'this schedule is off'}
    db = store.connect()
    try:
        rep = build_report(kind, cfg, now, db, assistant)
        if scheduled and kind == '6h' and cfg['report']['only_with_events'] and not rep['has_events']:
            store.add_message(db, 'report_6h', rep['subject'], [], 'skipped', 'nothing happened in the period',
                              rep['period'], '', '', None)
            db.commit()
            return {'status': 'skipped', 'reason': 'nothing happened in the period'}
        short = _short(rep['data'])
        attachments = None
        if cfg['report'].get('attach_pdf', True):
            name, blob, pdf_error = build_pdf(rep, cfg)
            if blob:
                attachments = [(name, blob, 'application/pdf')]
                short['pdf'] = {'name': name, 'size': len(blob)}
            else:
                short['pdf'] = {'error': pdf_error}
        result = send_and_record(db, 'report_' + kind, rep['subject'], rep['html'], rep['text'], cfg, rep['period'],
                                 short, bool(rep['summary'] and rep['summary'].get('ai')), smtp_factory,
                                 attachments=attachments)
        if result['status'] == 'sent':
            post = rep['data'].get('posture') or {}
            store.meta_set(db, 'last_report_posture', json.dumps({'posture': post.get('posture'),
                                                                   'kev': post.get('kev')}))
            store.add_notification(db, {'key': 'report:%s' % result['message_id'], 'type': 'report',
                                        'source': 'reports', 'severity': 'info', 'title': rep['subject'],
                                        'link': render.LINKS['reports']}, status='sent')
            db.execute("UPDATE notifications SET sent_at = ?, message_id = ? WHERE key = ?",
                       (int(common.now()), result['message_id'], 'report:%s' % result['message_id']))
        db.commit()
        return dict(result, subject=rep['subject'], ai_summary=bool(rep['summary'] and rep['summary'].get('ai')),
                    pdf=short.get('pdf'))
    finally:
        db.close()


def _short(data):
    """ what the history keeps next to the bodies (counts only) """
    out = {}
    for key in ('posture', 'quarantine', 'findings', 'traffic', 'cves', 'devices'):
        sec = data.get(key) or {}
        if not sec.get('available'):
            continue
        out[key] = {k: sec.get(k) for k in ('posture', 'active', 'new', 'findings', 'blocked_in', 'counts', 'kev',
                                            'total', 'new_count') if sec.get(k) is not None}
    return out


def preview_report(kind='manual', ai=False, pdf=False):
    """
    nothing is sent or stored; ai=False by default (the preview button may ask for it).
    pdf=True: only the PDF, base64 in "pdf" (configd answers text; the controller decodes it and serves the file)
    """
    cfg = settings.load()
    db = store.connect(readonly=True)
    try:
        rep = build_report(kind, cfg, None, db, ai=ai)
    finally:
        if db is not None:
            db.close()
    ai_used = bool(rep['summary'] and rep['summary'].get('ai'))
    if pdf:
        name, blob, error = build_pdf(rep, cfg)
        if not blob:
            return {'status': 'error', 'message': error}
        return {'status': 'ok', 'name': name, 'size': len(blob), 'ai_summary': ai_used, 'subject': rep['subject'],
                'pdf': base64.b64encode(blob).decode('ascii')}
    return {'status': 'ok', 'subject': rep['subject'], 'html': rep['html'], 'text': rep['text'],
            'has_events': rep['has_events'], 'ai_summary': ai_used, 'size': len(rep['html'].encode()),
            'attach_pdf': bool(cfg['report'].get('attach_pdf', True)), 'pdf_name': pdfreport.filename(rep['data'])}


def test_message(cfg=None):
    cfg = cfg or settings.load()
    root = common.config_root()
    chan = settings.effective_smtp(cfg, root)
    label = '%s:%s (%s, %s)' % (chan.get('host'), chan.get('port'), chan.get('security'), chan.get('origin')) \
        if chan.get('host') else chan.get('message', '-')
    return render.test_message(cfg['language'], common.gui_base(root, cfg.get('gui_url')), label, hostname(root))


# ------------------------------------------------------------------ detached scheduled run


def _lock_path(kind):
    return os.path.join(common.paths()['db'], 'reports-%s.lock' % kind)


def _try_lock(kind):
    """ :return: the fd holding the exclusive lock of the kind, or None when another run holds it """
    path = _lock_path(kind)
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _lock_owner(kind):
    try:
        with open(_lock_path(kind)) as handle:
            return int(handle.read().strip() or 0) or None
    except (OSError, ValueError):
        return None


def running_reports():
    """ {kind: pid} of the scheduled reports being built now """
    out = {}
    for kind in ('6h', 'daily', 'weekly'):
        if not os.path.exists(_lock_path(kind)):
            continue
        fd = _try_lock(kind)
        if fd is None:
            out[kind] = _lock_owner(kind)
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    return out


def log_line(doc, path=None):
    path = path or common.paths()['reports_log']
    try:
        os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
        with open(path, 'a') as handle:
            handle.write(json.dumps(dict({'ts': common.iso(common.now())}, **doc), default=str) + '\n')
    except OSError:
        pass


def start_report(kind, spawn=None):
    """
    cron / configd: start the detached run of a scheduled report and return at once.
    :param spawn: callable(argv, log_path) -> pid (tests); default: a new session, stdio on the log file
    """
    fd = _try_lock(kind)
    if fd is None:
        return {'status': 'running', 'kind': kind, 'pid': _lock_owner(kind),
                'message': 'a %s report is already being built' % kind}
    os.close(fd)                    # the child takes it again (a concurrent start then finds it held)
    script = os.path.join(common.paths()['scripts'], 'reports', 'cli.py')
    argv = [sys.executable, script, 'send_run', kind]
    log = common.paths()['reports_log']
    pid = (spawn or _spawn)(argv, log)
    log_line({'event': 'started', 'kind': kind, 'pid': pid})
    return {'status': 'started', 'kind': kind, 'pid': pid, 'log': log}


def _spawn(argv, log_path):
    os.makedirs(os.path.dirname(log_path), mode=0o750, exist_ok=True)
    with open(log_path, 'a') as out, open(os.devnull, 'rb') as devnull:
        proc = subprocess.Popen(argv, stdin=devnull, stdout=out, stderr=out, start_new_session=True,
                                close_fds=True, cwd='/', env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    return proc.pid


def run_report(kind, smtp_factory=None, assistant=None, now=None):
    """ the detached child: lock, send_report, every outcome in the log and an error also in the history """
    fd = _try_lock(kind)
    if fd is None:
        res = {'status': 'running', 'kind': kind, 'pid': _lock_owner(kind)}
        log_line(dict(res, event='skipped'))
        return res
    started = time.monotonic()
    try:
        os.ftruncate(fd, 0)
        os.write(fd, ('%d\n' % os.getpid()).encode())
        try:
            res = send_report(kind, scheduled=True, now=now, smtp_factory=smtp_factory, assistant=assistant)
        except Exception as exc:            # noqa: BLE001 - never die silently: history + log
            res = {'status': 'failed', 'error': '%s: %s' % (exc.__class__.__name__, exc)}
            log_line({'event': 'traceback', 'kind': kind, 'trace': traceback.format_exc(limit=6)[-2000:]})
            try:
                db = store.connect()
                try:
                    store.add_message(db, 'report_' + kind, 'report %s' % kind, [], 'failed', res['error'][:500],
                                      (None, None), '', '', None,
                                      duration_ms=int((time.monotonic() - started) * 1000))
                    db.commit()
                finally:
                    db.close()
            except Exception:               # noqa: BLE001
                pass
        res = dict(res, seconds=round(time.monotonic() - started, 1))
        log_line(dict({k: v for k, v in res.items() if k not in ('html', 'text')}, event='finished', kind=kind))
        return res
    finally:
        try:
            os.ftruncate(fd, 0)
        except OSError:
            pass
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
