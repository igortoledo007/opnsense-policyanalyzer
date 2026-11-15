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

    Background queue of AI jobs (SQLite /var/db/policyanalyzer/ai-queue.db).

    A scenario routed with mode "queue" does not wait for the model: the
    Assistant stores a job with the command line of the module that asked
    (the same configd script and arguments) and returns at once
    {"status": "queued", "job": {...}}.  One worker at a time (flock on
    ai-queue.lock), started on demand and by a light cron job, runs the jobs in
    order: it executes that command again with PA_AI_JOB=<id> in the
    environment, so the module does its usual post processing (parsing,
    storing the answer next to the case/device/CVE...) and the Assistant
    answers synchronously inside it.  The JSON the module prints is the job
    result the GUI receives by polling.

        jobqueue.py work [--once]        run the queued jobs (cron, on demand); exits when the queue is empty
        jobqueue.py kick                 start a detached worker if none is running
        jobqueue.py list [limit]         jobs, statistics per scenario/model, worker state
        jobqueue.py job <id>             one job with its position and estimate; the result when finished
        jobqueue.py cancel <id>          cancel a queued job (a running one is stopped)

    Same input, same answer: the model answers are kept in the "cache" table
    keyed by the SHA-256 of scenario + provider + model + the exact messages
    (anonymized), so a repeated job is answered without calling the model.
    Duplicate jobs (same key, still queued or running) are merged.
"""

import fcntl
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DB_PATH = os.environ.get('POLICYANALYZER_AI_QUEUE', '/var/db/policyanalyzer/ai-queue.db')
SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_RESULT = 4 * 1024 * 1024
KEEP_JOBS = 2000
KEEP_RESULT_DAYS = 14
DEFAULT_CACHE_TTL = 7 * 86400
MAX_JOB_SECONDS = 4 * 3600
STATUSES = ('queued', 'running', 'done', 'error', 'cancelled')

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    scenario TEXT NOT NULL,
    subject TEXT,
    status TEXT NOT NULL,
    created INTEGER NOT NULL,
    started INTEGER,
    finished INTEGER,
    provider TEXT,
    model TEXT,
    label TEXT,
    route TEXT,
    argv TEXT NOT NULL,
    language TEXT,
    timeout INTEGER,
    eta INTEGER,
    pid INTEGER,
    runs INTEGER NOT NULL DEFAULT 0,
    calls INTEGER NOT NULL DEFAULT 0,
    cached_calls INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    model_seconds REAL,
    attempts INTEGER,
    format_ok INTEGER,
    lang_ok INTEGER,
    fallback INTEGER NOT NULL DEFAULT 0,
    provider_used TEXT,
    model_used TEXT,
    result TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, id);
CREATE INDEX IF NOT EXISTS jobs_key ON jobs(key, status);
CREATE INDEX IF NOT EXISTS jobs_scenario ON jobs(scenario, finished);
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    scenario TEXT,
    created INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    provider TEXT,
    model TEXT,
    text TEXT NOT NULL,
    meta TEXT,
    hits INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


def now():
    return int(time.time())


def lock_path(path=None):
    return os.path.splitext(path or DB_PATH)[0] + '.lock'


def connect(path=None, readonly=False):
    path = path or DB_PATH
    if readonly:
        if not os.path.exists(path):
            return None
        db = sqlite3.connect('file:%s?mode=ro' % path, uri=True, timeout=10)
    else:
        os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
        fresh = not os.path.exists(path)
        db = sqlite3.connect(path, timeout=30)
        if fresh:
            os.chmod(path, 0o640)
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)
    db.row_factory = sqlite3.Row
    return db


def _row(row):
    if row is None:
        return None
    item = dict(row)
    for key in ('route', 'argv'):
        try:
            item[key] = json.loads(item[key]) if item.get(key) else None
        except ValueError:
            item[key] = None
    item.pop('result', None)
    return item


# ------------------------------------------------------------------ cache


def cache_get(key, path=None):
    """ :return: {"text", "provider", "model", "meta", "created"} or None """
    try:
        db = connect(path)
    except (OSError, sqlite3.Error):
        return None
    try:
        row = db.execute('SELECT * FROM cache WHERE key = ? AND expires > ?', (key, now())).fetchone()
        if row is None:
            return None
        db.execute('UPDATE cache SET hits = hits + 1 WHERE key = ?', (key,))
        db.commit()
        item = dict(row)
        try:
            item['meta'] = json.loads(item.get('meta') or '{}')
        except ValueError:
            item['meta'] = {}
        return item
    except sqlite3.Error:
        return None
    finally:
        db.close()


def cache_put(key, scenario, text, provider, model, meta=None, ttl=DEFAULT_CACHE_TTL, path=None):
    try:
        db = connect(path)
    except (OSError, sqlite3.Error):
        return False
    try:
        t = now()
        db.execute('INSERT OR REPLACE INTO cache (key, scenario, created, expires, provider, model, text, meta, hits) '
                   'VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)',
                   (key, scenario, t, t + int(ttl), provider, model, text, json.dumps(meta or {}, default=str)))
        db.commit()
        return True
    except sqlite3.Error:
        return False
    finally:
        db.close()


# ------------------------------------------------------------------ jobs


def valid_argv(argv):
    """ only a plugin script with string arguments may be queued (and run by the worker) """
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
        return False
    if any('\x00' in a for a in argv):
        return False
    script = os.path.realpath(argv[0])
    base = os.path.realpath(SCRIPTS_DIR) + os.sep
    return script.startswith(base) and script.endswith('.py') and os.path.isfile(script)


def current_argv():
    """ command line of this process, as the worker must run it again (without --stream) """
    return [os.path.abspath(sys.argv[0])] + [a for a in sys.argv[1:] if a != '--stream']


def enqueue(scenario, key, argv, subject=None, route=None, language=None, eta=None, timeout=None, path=None):
    """ :return: job dict (an identical queued/running job is reused) """
    if not valid_argv(argv):
        raise ValueError('this command can not be queued')
    db = connect(path)
    try:
        row = db.execute("SELECT * FROM jobs WHERE key = ? AND status IN ('queued', 'running') ORDER BY id "
                         "LIMIT 1", (key,)).fetchone()
        if row is not None:
            job = _row(row)
            job['merged'] = True
            return dict(job, **position(db, job))
        route = route or {}
        cur = db.execute('INSERT INTO jobs (key, scenario, subject, status, created, provider, model, label, route, '
                         'argv, language, timeout, eta) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                         (key, scenario, subject, 'queued', now(), route.get('provider'), route.get('model'),
                          route.get('label'), json.dumps(route, default=str), json.dumps(list(argv)), language,
                          int(min(timeout or MAX_JOB_SECONDS, MAX_JOB_SECONDS)), int(eta) if eta else None))
        db.commit()
        job = _row(db.execute('SELECT * FROM jobs WHERE id = ?', (cur.lastrowid,)).fetchone())
        return dict(job, **position(db, job))
    finally:
        db.close()


def estimate(db, scenario, model, fallback_eta=None):
    """ seconds a job of this scenario/model takes: average of the last 20 finished, else the catalog value """
    row = db.execute("SELECT AVG(finished - started) AS s, COUNT(*) AS n FROM (SELECT finished, started FROM jobs "
                     "WHERE scenario = ? AND IFNULL(model_used, model) = ? AND status = 'done' AND started IS NOT "
                     "NULL AND calls > cached_calls ORDER BY id DESC LIMIT 20)", (scenario, model)).fetchone()
    if row is not None and row['n'] and row['s'] is not None:
        return int(row['s'])
    if fallback_eta:
        return int(fallback_eta)
    from ai.scenarios import CATALOG
    return int((CATALOG.get(scenario) or {}).get('eta') or 300)


def position(db, job):
    """ {"position": n (1 = next / running now), "ahead": n, "eta_seconds": s} """
    if job['status'] not in ('queued', 'running'):
        return {'position': None, 'ahead': 0, 'eta_seconds': None}
    t = now()
    running = db.execute("SELECT * FROM jobs WHERE status = 'running' ORDER BY id LIMIT 1").fetchone()
    if job['status'] == 'running':
        left = estimate(db, job['scenario'], job['model'], job.get('eta')) - (t - (job['started'] or t))
        return {'position': 0, 'ahead': 0, 'eta_seconds': max(15, left)}
    ahead_rows = db.execute("SELECT scenario, model, eta FROM jobs WHERE status = 'queued' AND id < ? ORDER BY id",
                            (job['id'],)).fetchall()
    eta = sum(estimate(db, r['scenario'], r['model'], r['eta']) for r in ahead_rows)
    ahead = len(ahead_rows)
    if running is not None:
        ahead += 1
        left = estimate(db, running['scenario'], running['model'], running['eta']) - (t - (running['started'] or t))
        eta += max(15, left)
    eta += estimate(db, job['scenario'], job['model'], job.get('eta'))
    return {'position': ahead + 1, 'ahead': ahead, 'eta_seconds': int(eta)}


def get(job_id, path=None, with_result=True):
    db = connect(path, readonly=True)
    if db is None:
        return {'status': 'error', 'message': 'job not found'}
    try:
        row = db.execute('SELECT * FROM jobs WHERE id = ?', (int(job_id),)).fetchone()
        if row is None:
            return {'status': 'error', 'message': 'job not found'}
        job = _row(row)
        job.pop('argv', None)
        job.update(position(db, job))
        job['queue_seconds'] = (job['started'] or now()) - job['created'] if job['status'] != 'cancelled' else None
        job['run_seconds'] = ((job['finished'] or now()) - job['started']) if job['started'] else None
        out = {'status': 'ok', 'job': job}
        if with_result and job['status'] in ('done', 'error') and row['result']:
            try:
                out['result'] = json.loads(row['result'])
            except ValueError:
                out['result'] = None
        return out
    finally:
        db.close()


def add_metrics(job_id, path=None, **m):
    """ called by the Assistant inside a job, once per model call (map/reduce sums up) """
    try:
        db = connect(path)
    except (OSError, sqlite3.Error):
        return
    try:
        db.execute('UPDATE jobs SET calls = calls + 1, cached_calls = cached_calls + ?, '
                   'prompt_tokens = IFNULL(prompt_tokens, 0) + ?, completion_tokens = IFNULL(completion_tokens, 0) + ?, '
                   'model_seconds = IFNULL(model_seconds, 0) + ?, attempts = IFNULL(attempts, 0) + ?, '
                   'format_ok = MIN(IFNULL(format_ok, 1), ?), lang_ok = MIN(IFNULL(lang_ok, 1), ?), '
                   'fallback = MAX(fallback, ?), provider_used = ?, model_used = ? WHERE id = ?',
                   (1 if m.get('cached') else 0, m.get('prompt_tokens') or 0, m.get('completion_tokens') or 0,
                    (m.get('duration_ms') or 0) / 1000.0, m.get('attempts') or 1,
                    0 if m.get('format_ok') is False else 1, 0 if m.get('lang_ok') is False else 1,
                    1 if m.get('fallback') else 0, m.get('provider'), m.get('model'), int(job_id)))
        db.commit()
    except sqlite3.Error:
        pass
    finally:
        db.close()


def cancel(job_id, path=None):
    db = connect(path)
    try:
        row = db.execute('SELECT * FROM jobs WHERE id = ?', (int(job_id),)).fetchone()
        if row is None:
            return {'status': 'error', 'message': 'job not found'}
        if row['status'] == 'queued':
            db.execute("UPDATE jobs SET status = 'cancelled', finished = ? WHERE id = ?", (now(), row['id']))
            db.commit()
            return {'status': 'ok', 'cancelled': True}
        if row['status'] == 'running' and row['pid']:
            try:
                os.killpg(int(row['pid']), signal.SIGTERM)
            except OSError:
                pass
            db.execute("UPDATE jobs SET status = 'cancelled', finished = ?, error = ? WHERE id = ?",
                       (now(), 'cancelled while running', row['id']))
            db.commit()
            return {'status': 'ok', 'cancelled': True, 'stopped': True}
        return {'status': 'ok', 'cancelled': False, 'message': 'the job already finished'}
    finally:
        db.close()


def stats(db, days=90):
    """ per scenario and model: what the catalog (docs/ia-local-catalogo.md) is filled with """
    since = now() - days * 86400
    rows = db.execute("""
        SELECT scenario, IFNULL(model_used, model) AS model, IFNULL(provider_used, provider) AS provider,
               COUNT(*) AS jobs, SUM(status = 'done') AS ok, SUM(status = 'error') AS errors,
               AVG(started - created) AS queue_s, AVG(finished - started) AS run_s, MAX(finished - started) AS run_max,
               AVG(prompt_tokens) AS prompt_tokens, AVG(completion_tokens) AS completion_tokens,
               AVG(format_ok) AS format_ok, AVG(lang_ok) AS lang_ok, SUM(fallback) AS fallback,
               AVG(attempts * 1.0 / NULLIF(calls - cached_calls, 0)) AS attempts, SUM(cached_calls) AS cached
          FROM jobs WHERE created >= ? AND status IN ('done', 'error')
         GROUP BY scenario, IFNULL(model_used, model), IFNULL(provider_used, provider)
         ORDER BY scenario""", (since,)).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        for k in ('queue_s', 'run_s', 'prompt_tokens', 'completion_tokens'):
            item[k] = int(item[k]) if item[k] is not None else None
        for k in ('format_ok', 'lang_ok', 'attempts'):
            item[k] = round(item[k], 2) if item[k] is not None else None
        out.append(item)
    return out


def worker_state(path=None):
    """ is a worker holding the lock right now? """
    try:
        fd = os.open(lock_path(path), os.O_RDONLY)
    except OSError:
        return {'running': False}
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return {'running': False}
    except OSError:
        return {'running': True}
    finally:
        os.close(fd)


def listing(limit=50, path=None):
    db = connect(path, readonly=True)
    out = {'status': 'ok', 'jobs': [], 'stats': [], 'counts': {s: 0 for s in STATUSES},
           'worker': worker_state(path)}
    if db is None:
        return out
    try:
        for row in db.execute('SELECT status, COUNT(*) AS n FROM jobs GROUP BY status'):
            out['counts'][row['status']] = row['n']
        for row in db.execute('SELECT * FROM jobs ORDER BY id DESC LIMIT ?', (max(1, min(int(limit), 500)),)):
            job = _row(row)
            job.pop('argv', None)
            job.update(position(db, job))
            job['queue_seconds'] = (job['started'] - job['created']) if job['started'] else None
            job['run_seconds'] = (job['finished'] - job['started']) if job['started'] and job['finished'] else None
            out['jobs'].append(job)
        out['stats'] = stats(db)
        row = db.execute('SELECT COUNT(*) AS n, SUM(hits) AS hits FROM cache WHERE expires > ?', (now(),)).fetchone()
        out['cache'] = {'entries': row['n'], 'hits': row['hits'] or 0}
    finally:
        db.close()
    return out


# ------------------------------------------------------------------ worker


def _run_command(argv, env, timeout, on_start=None):
    """ :return: (rc, stdout, stderr); the child is a process group leader, killed on timeout """
    proc = subprocess.Popen([sys.executable] + list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, env=env, cwd='/', start_new_session=True)
    if on_start is not None:
        on_start(proc.pid)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()
        proc.communicate()
        return 124, b'', b'timeout after %d s' % timeout
    return proc.returncode, out, err


def _last_json(raw):
    text = (raw or b'').decode('utf-8', 'replace')
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            return doc
    except ValueError:
        pass
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith('{'):
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            if isinstance(doc, dict):
                return doc
    return None


def _recover(db):
    """ we hold the lock: a "running" job belongs to a worker that died """
    for row in db.execute("SELECT id, runs FROM jobs WHERE status = 'running'").fetchall():
        if row['runs'] < 2:
            db.execute("UPDATE jobs SET status = 'queued', pid = NULL WHERE id = ?", (row['id'],))
        else:
            db.execute("UPDATE jobs SET status = 'error', finished = ?, error = ? WHERE id = ?",
                       (now(), 'interrupted twice (worker stopped)', row['id']))
    db.commit()


def _prune(db):
    t = now()
    db.execute('DELETE FROM cache WHERE expires <= ?', (t,))
    db.execute("UPDATE jobs SET result = NULL WHERE finished < ? AND result IS NOT NULL", (t - KEEP_RESULT_DAYS * 86400,))
    db.execute("DELETE FROM jobs WHERE id <= (SELECT id FROM jobs ORDER BY id DESC LIMIT 1 OFFSET ?) "
               "AND status NOT IN ('queued', 'running')", (KEEP_JOBS,))
    db.commit()


def run_job(db, row, runner=None, path=None):
    job_id = row['id']
    try:
        argv = json.loads(row['argv'])
    except ValueError:
        argv = None
    route = json.loads(row['route'] or '{}') if row['route'] else {}
    if not valid_argv(argv):
        db.execute("UPDATE jobs SET status = 'error', finished = ?, error = ? WHERE id = ?",
                   (now(), 'invalid command', job_id))
        db.commit()
        return 'error'
    db.execute("UPDATE jobs SET status = 'running', started = ?, runs = runs + 1 WHERE id = ?", (now(), job_id))
    db.commit()
    env = dict(os.environ)
    env.update({'PA_AI_JOB': str(job_id), 'PA_AI_INLINE': '1', 'PYTHONDONTWRITEBYTECODE': '1'})
    if path:
        env['POLICYANALYZER_AI_QUEUE'] = path
    if route.get('role') == 'fallback':
        env['PA_AI_ROUTE'] = 'fallback'
    timeout = int(row['timeout'] or MAX_JOB_SECONDS)
    runner = runner or _run_command

    def note_pid(pid):
        db.execute('UPDATE jobs SET pid = ? WHERE id = ?', (pid, job_id))
        db.commit()
    try:
        rc, out, err = runner(argv, env, timeout, note_pid)
    except Exception as exc:                    # noqa: BLE001
        rc, out, err = 1, b'', str(exc).encode()
    current = db.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone()
    if current is not None and current['status'] == 'cancelled':
        return 'cancelled'
    doc = _last_json(out)
    if doc is None:
        message = (err or b'').decode('utf-8', 'replace').strip()[-400:] or 'rc=%s, no JSON answer' % rc
        db.execute("UPDATE jobs SET status = 'error', finished = ?, error = ? WHERE id = ?", (now(), message, job_id))
        db.commit()
        return 'error'
    if doc.get('status') == 'queued':
        doc = {'status': 'error', 'message': 'the job was queued again instead of running'}
    status = 'done' if doc.get('status') == 'ok' else 'error'
    blob = json.dumps(doc, ensure_ascii=False, default=str)
    if len(blob) > MAX_RESULT:
        blob = json.dumps({'status': 'error', 'message': 'result too large'})
        status = 'error'
    db.execute('UPDATE jobs SET status = ?, finished = ?, result = ?, error = ? WHERE id = ?',
               (status, now(), blob, None if status == 'done' else str(doc.get('message') or '')[:400], job_id))
    db.commit()
    return status


def work(once=False, path=None, runner=None, max_jobs=500):
    """ :return: {"status": "ok"|"busy", "ran": n} """
    path = path or DB_PATH
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    fd = os.open(lock_path(path), os.O_RDWR | os.O_CREAT, 0o640)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return {'status': 'busy', 'ran': 0}
    ran = []
    try:
        db = connect(path)
        try:
            _recover(db)
            while len(ran) < max_jobs:
                row = db.execute("SELECT * FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
                if row is None:
                    break
                ran.append({'id': row['id'], 'status': run_job(db, row, runner, path)})
                if once:
                    break
            _prune(db)
        finally:
            db.close()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    return {'status': 'ok', 'ran': len(ran), 'jobs': ran}


def spawn_worker(path=None):
    """ start a detached worker unless one is running (it exits by itself when the queue is empty) """
    if worker_state(path)['running']:
        return False
    env = dict(os.environ)
    if path:
        env['POLICYANALYZER_AI_QUEUE'] = path
    for key in ('PA_AI_JOB', 'PA_AI_INLINE', 'PA_AI_ROUTE'):
        env.pop(key, None)
    subprocess.Popen([sys.executable, os.path.abspath(__file__), 'work'], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                     env=env, cwd='/')
    return True


def emit(doc):
    sys.stdout.write(json.dumps(doc, default=str) + '\n')


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    args = [a for a in argv[2:] if a]
    try:
        if cmd == 'work':
            emit(work(once='--once' in args))
        elif cmd == 'kick':
            emit({'status': 'ok', 'started': spawn_worker()})
        elif cmd == 'list':
            emit(listing(int(args[0]) if args and args[0].isdigit() else 50))
        elif cmd == 'job' and args and args[0].isdigit():
            emit(get(int(args[0])))
        elif cmd == 'cancel' and args and args[0].isdigit():
            emit(cancel(int(args[0])))
        else:
            emit({'status': 'error', 'message': 'usage: jobqueue.py work|kick|list [n]|job <id>|cancel <id>'})
            return 1
    except (sqlite3.Error, OSError, ValueError) as exc:
        emit({'status': 'error', 'message': str(exc)})
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
