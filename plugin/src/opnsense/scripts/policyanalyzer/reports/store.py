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

    reports.db (SQLite, 0640): every e-mail the plugin builds and its delivery, and the notification queue.

      messages       one row per e-mail (report_6h, report_daily, report_manual, test, notification, digest):
                     subject, recipients, status (sent | failed | skipped), error, period, the HTML and text
                     bodies (zlib), the data summary, whether the AI summary was used, attempts
      notifications  one row per event (unique key): type, source, severity, title, detail, link, data,
                     status queued | held | sent | failed | suppressed, reason, attempts, next_try, message_id
      meta           markers of the event sources, last runs, baselines
    History is permanent (no automatic cleanup); bodies are compressed (~5-15 KiB per report).
"""

import json
import os
import sqlite3
import zlib

from . import common

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, subject TEXT, recipients TEXT,
    status TEXT NOT NULL, error TEXT, period_from INTEGER, period_to INTEGER, html BLOB, text BLOB,
    summary TEXT, ai_used INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER,
    channel TEXT);
CREATE INDEX IF NOT EXISTS messages_ts ON messages (ts);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, key TEXT NOT NULL UNIQUE, type TEXT NOT NULL, source TEXT,
    severity TEXT NOT NULL, title TEXT, detail TEXT, link TEXT, data TEXT, status TEXT NOT NULL, reason TEXT,
    attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER, sent_at INTEGER, message_id INTEGER);
CREATE INDEX IF NOT EXISTS notifications_status ON notifications (status, type);
CREATE INDEX IF NOT EXISTS notifications_ts ON notifications (ts);
"""

MSG_COLS = ('id', 'ts', 'kind', 'subject', 'recipients', 'status', 'error', 'period_from', 'period_to', 'summary',
            'ai_used', 'attempts', 'duration_ms', 'channel')
NOTE_COLS = ('id', 'ts', 'key', 'type', 'source', 'severity', 'title', 'detail', 'link', 'data', 'status', 'reason',
             'attempts', 'next_try', 'sent_at', 'message_id')


def connect(readonly=False):
    path = common.paths()['reports_db']
    if readonly:
        if not os.path.exists(path):
            return None
        return sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=5)
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    fresh = not os.path.exists(path)
    db = sqlite3.connect(path, timeout=10)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript(SCHEMA)
    if fresh:
        for suffix in ('', '-wal', '-shm'):
            try:
                os.chmod(path + suffix, 0o640)
            except OSError:
                pass
    return db


def meta_get(db, key, default=None):
    row = db.execute('SELECT value FROM meta WHERE key = ?', (key,)).fetchone()
    return row[0] if row else default


def meta_set(db, key, value):
    db.execute('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)', (key, str(value)))


def _z(text):
    return zlib.compress((text or '').encode('utf-8'), 9)


def _unz(blob):
    try:
        return zlib.decompress(blob).decode('utf-8') if blob else ''
    except zlib.error:
        return ''


def add_message(db, kind, subject, recipients, status, error=None, period=(None, None), html='', text='',
                summary=None, ai_used=False, attempts=1, duration_ms=None, channel=None, ts=None):
    cur = db.execute('INSERT INTO messages (ts, kind, subject, recipients, status, error, period_from, period_to, '
                     'html, text, summary, ai_used, attempts, duration_ms, channel) '
                     'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                     (int(ts or common.now()), kind, subject, ','.join(recipients or []), status,
                      (error or '')[:500] or None, period[0], period[1], _z(html), _z(text),
                      json.dumps(summary) if summary is not None else None, int(bool(ai_used)), attempts,
                      duration_ms, channel))
    return cur.lastrowid


def _msg(row):
    rec = dict(zip(MSG_COLS, row))
    rec['ts_iso'] = common.iso(rec['ts'])
    rec['recipients'] = [r for r in (rec['recipients'] or '').split(',') if r]
    try:
        rec['summary'] = json.loads(rec['summary']) if rec['summary'] else None
    except ValueError:
        rec['summary'] = None
    rec['ai_used'] = bool(rec['ai_used'])
    return rec


def messages(db, page=1, rows=25, kind=None):
    where, args = '', []
    if kind:
        where, args = 'WHERE kind LIKE ?', [kind + '%']
    total = db.execute('SELECT count(*) FROM messages %s' % where, args).fetchone()[0]
    rows = max(1, min(200, rows))
    found = db.execute('SELECT %s FROM messages %s ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?'
                       % (', '.join(MSG_COLS), where), args + [rows, (max(1, page) - 1) * rows]).fetchall()
    return total, [_msg(r) for r in found]


def message(db, msg_id):
    row = db.execute('SELECT %s, html, text FROM messages WHERE id = ?' % ', '.join(MSG_COLS), (msg_id,)).fetchone()
    if not row:
        return None
    rec = _msg(row[:len(MSG_COLS)])
    rec['html'], rec['text'] = _unz(row[-2]), _unz(row[-1])
    return rec


def note(row):
    rec = dict(zip(NOTE_COLS, row))
    rec['ts_iso'] = common.iso(rec['ts'])
    rec['sent_at_iso'] = common.iso(rec['sent_at']) if rec['sent_at'] else None
    try:
        rec['data'] = json.loads(rec['data']) if rec['data'] else {}
    except ValueError:
        rec['data'] = {}
    return rec


def add_notification(db, event, status='queued', reason=None):
    """ :return: id, or None when the key is already known (dedupe) """
    try:
        cur = db.execute('INSERT INTO notifications (ts, key, type, source, severity, title, detail, link, data, '
                         'status, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                         (int(event.get('ts') or common.now()), event['key'][:200], event['type'], event.get('source'),
                          event['severity'], (event.get('title') or '')[:300], (event.get('detail') or '')[:2000],
                          (event.get('link') or '')[:300], json.dumps(event.get('data') or {})[:8000], status,
                          reason))
    except sqlite3.IntegrityError:
        return None
    return cur.lastrowid


def notifications(db, status=None, page=1, rows=50):
    where, args = '', []
    if status:
        where, args = 'WHERE status = ?', [status]
    total = db.execute('SELECT count(*) FROM notifications %s' % where, args).fetchone()[0]
    found = db.execute('SELECT %s FROM notifications %s ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?'
                       % (', '.join(NOTE_COLS), where), args + [rows, (max(1, page) - 1) * rows]).fetchall()
    return total, [note(r) for r in found]
