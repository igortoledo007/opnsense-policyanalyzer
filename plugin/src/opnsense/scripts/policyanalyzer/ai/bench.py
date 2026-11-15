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

    Bench of the local AI: every scenario of the catalog (ai/scenarios.py) on every local model, with the same
    pipeline as the plugin (prompts, anonymization, route limits of the "local_only" preset, validation with one
    correction, JSON Schema, map/reduce), run detached on this firewall, one heavy request at a time.

        bench.py start <plan> [retry]   matriz | noturno | avaliacao; resumes the unfinished plan of the same name
                                    (avaliacao also takes reps=N, only=a,b, reeval, w_eff=0.7: ai/evaluate.py)
                                    ("retry": the failed steps of the unfinished rounds run again, also the
                                    scenario steps recorded with an Ollama 503/busy/timeout error)
        bench.py status             plan, rounds, current step, last host sample, events
        bench.py stop               stops the runner (the current step goes back to pending), unloads the models
        bench.py kick               resumes an unfinished plan that was not stopped by hand (cron, after a reboot)
        bench.py report [md|json]   the catalog (docs/ia-local-catalogo.md layout) built from the database
        bench.py import <jsonl> [label]   imports earlier measurements (scratchpad bench3.py / bench.py lines)
        bench.py run                the runner itself (started by "start"/"kick", flock + pid file)
        bench.py step               one step, JSON on stdin, JSON result on stdout (child of the runner)

    Isolation (explicit, only inside the bench processes, see isolate()): the audit log is a NullAuditLog, the
    queue cache is never read or written, the routing is an in-memory copy of "local_only" with the model under
    test and mode "sync", the fallback is "none" and the only provider is the Ollama of 127.0.0.1.  The step
    child of a scenario also refuses every file write (open/os.*) and opens SQLite read-only.  Nothing here runs
    a change action; only the "queue" round goes through configctl like a user would (read-only actions that
    answer with the AI, the production queue, cache and audit are then used on purpose).

    State: SQLite /var/db/policyanalyzer/ai-bench.db (plans, rounds, steps, samples, events, meta).  Safety: the
    runner pauses between steps while the active WAN (dpinger) has loss > 2 % or delay > 50 ms, or the load
    average is above 3.5, sustained for three samples, and stops the current step when that lasts; it waits while
    a production AI job (ai-queue.db) or a brief generation is running, or while another process is connected to
    the Ollama port (sockstat: a report or notification of cron answering with the AI in its own process; a step
    that failed while someone else held Ollama goes back to pending).  Every step error, runner error and the exit
    of the runner are events; the sampler writes a heartbeat (meta "heartbeat").  E-mail: one message per finished round
    (at most one every 15 minutes, the rest is merged) and a final "Done", through the channel of the
    reports module.
"""

import base64
import fcntl
import traceback
import json
import math
import os
import re
import signal
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import i18n                       # noqa: E402

DB_PATH = os.environ.get('POLICYANALYZER_AI_BENCH', '/var/db/policyanalyzer/ai-bench.db')
RUN_DIR = os.environ.get('POLICYANALYZER_RUN_DIR', '/var/run')
PID_FILE = os.path.join(RUN_DIR, 'policyanalyzer-ai-bench.pid')
LOCK_FILE = os.path.join(RUN_DIR, 'policyanalyzer-ai-bench.lock')
QUEUE_DB = os.environ.get('POLICYANALYZER_AI_QUEUE', '/var/db/policyanalyzer/ai-queue.db')
BRIEF_LOCK = os.environ.get('POLICYANALYZER_BRIEF_LOCK', '/var/db/policyanalyzer/ai-brief.lock')
OLLAMA_URL = 'http://127.0.0.1:11434'
OLLAMA_PORT = 11434
CONFIGCTL = '/usr/local/sbin/configctl'
SCRIPT = os.path.abspath(__file__)
# the language the models are evaluated in: the bench asks for (and checks) Brazilian Portuguese answers
LANG = 'pt_BR'

MODEL_ORDER = ('qwen2.5:3b', 'foundation-sec:8b', 'qwen3:30b-a3b')   # light -> heavy, one group per model
PLANS = {
    'matriz': ('matrix',),
    'noturno': ('baseline', 'matrix', 'repeat', 'params', 'switch', 'threads', 'queue', 'resilience', 'quality'),
    # per scenario evaluation (ai/evaluate.py): one round "eval:<model>" per candidate, made when the plan is created
    'avaliacao': ('eval',),
}
EVAL_PLAN = 'avaliacao'
EVAL_PREFIX = 'eval:'
SCENARIO_KINDS = ('scenario', 'eval')           # steps that answer with the AI through the plugin pipeline
# the texts of the e-mails and of the catalog (report_md) are the sections "bench" and "bench_md" of
# i18n/<language>.json, in the language of the evaluation reports (evaluate.report_language); the events of the
# database stay in English (they are a log)


def texts(language=None, name='bench'):
    return _evaluate().texts(language, name)


def round_label(name, t):
    return t['rounds'].get(name, name)


SAMPLE_SECONDS = 30
SAMPLE_FAST = 10                  # during the "threads" round
LOSS_MAX = 2.0                    # % on the active WAN (dpinger)
RTT_MAX = 50.0                    # ms on the active WAN (dpinger)
LOAD_MAX = 3.5                    # 1 min load average with the default share (4 cores, Ollama pinned to 2)
LOAD_HEADROOM = 1.5               # load the firewall itself may add on top of the threads given to the model
DEFAULT_THREADS, DEFAULT_CTX = 2, 8192
SUSTAIN = 3                       # consecutive samples
MAIL_INTERVAL = 900               # s between e-mails
MAX_STEP_SECONDS = 4 * 3600
IDLE_SECONDS = 180
OTHER_CPU = 40.0                 # %CPU of the model process with no bench step running: someone else uses it
CONTENTION_CHECK = 30             # s between the checks for other Ollama clients while a step runs
MAX_STEP_RUNS = 3                 # a step that failed under contention runs again up to this many times
MAX_LOOP_ERRORS = 5               # consecutive unexpected errors of the runner loop before it gives up
# not a measurement: Ollama refused the request (OLLAMA_MAX_QUEUE full, 503) or was not reachable
BUSY_RE = re.compile(r'(HTTP 503|server busy|maximum pending requests|cannot reach|connection refused|'
                     r'connection reset|Service Unavailable)', re.I)
TIMEOUT_RE = re.compile(r'(timed out|timeout after)', re.I)
# evaluation data (Portuguese on purpose, see LANG): the fixed console questions asked to the model under test;
# QUESTIONS_EN is the same set in English, for a bench run in English
QUESTIONS = ('Quem mais foi bloqueado hoje?', 'Houve alertas do Suricata nas últimas 24 horas?',
             'Quais portas da WAN foram mais procuradas hoje?', 'Algum dispositivo da LAN gerou muitos bloqueios hoje?')
QUESTIONS_EN = ('Who else was blocked today?', 'Were there Suricata alerts in the last 24 hours?',
                'Which WAN ports were probed the most today?', 'Did any LAN device cause many blocks today?')
QUALITY_SCENARIOS = ('explain_finding', 'explain_cve', 'incident_summary', 'anomaly_explain', 'console_ask')

SCHEMA = """
CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, status TEXT NOT NULL, created INTEGER NOT NULL,
    started INTEGER, finished INTEGER, stop_requested INTEGER NOT NULL DEFAULT 0, imported INTEGER NOT NULL DEFAULT 0,
    label TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS rounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id INTEGER NOT NULL, idx INTEGER NOT NULL, name TEXT NOT NULL,
    status TEXT NOT NULL, started INTEGER, finished INTEGER, summary TEXT);
CREATE TABLE IF NOT EXISTS steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT, round_id INTEGER NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL,
    model TEXT, scenario TEXT, variant INTEGER NOT NULL DEFAULT 0, params TEXT, status TEXT NOT NULL,
    runs INTEGER NOT NULL DEFAULT 0, started INTEGER, finished INTEGER, result TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS steps_round ON steps(round_id, status, seq);
CREATE TABLE IF NOT EXISTS samples (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, step_id INTEGER,
    data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS samples_step ON samples(step_id);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL,
    message TEXT);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


def now():
    return int(time.time())


def iso(ts=None):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(ts if ts is not None else time.time()))


def emit(doc):
    sys.stdout.write(json.dumps(doc, ensure_ascii=False, default=str) + '\n')
    sys.stdout.flush()


# ------------------------------------------------------------------ database


def connect(path=None):
    path = path or DB_PATH
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    fresh = not os.path.exists(path)
    db = sqlite3.connect(path, timeout=60)
    db.row_factory = sqlite3.Row
    if fresh:
        os.chmod(path, 0o640)
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript(SCHEMA)
    _compute().ensure(db)
    return db


def meta_get(db, key, default=None):
    row = db.execute('SELECT v FROM meta WHERE k = ?', (key,)).fetchone()
    if row is None:
        return default
    try:
        return json.loads(row['v'])
    except ValueError:
        return default


def meta_set(db, key, value):
    db.execute('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)', (key, json.dumps(value, default=str)))
    db.commit()


def event(db, kind, message):
    db.execute('INSERT INTO events (ts, kind, message) VALUES (?, ?, ?)', (now(), kind, str(message)[:2000]))
    db.commit()


def loads(text, default=None):
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def active_plan(db):
    return db.execute("SELECT * FROM plans WHERE status IN ('queued', 'running', 'stopped') AND imported = 0 "
                      "ORDER BY id DESC LIMIT 1").fetchone()


def create_plan(db, name, tokens=None):
    """ :param tokens: options of the "avaliacao" plan (reps=N, only=a,b, reeval, w_eff=x) """
    if name not in PLANS:
        raise ValueError('unknown plan "%s" (use: %s)' % (name, ', '.join(PLANS)))
    if name == EVAL_PLAN:
        from ai import evaluate
        evaluate.parse_options(tokens)          # invalid options: nothing is created
    cur = db.execute('INSERT INTO plans (name, status, created) VALUES (?, ?, ?)', (name, 'queued', now()))
    names = PLANS[name]
    if name == EVAL_PLAN:
        names = evaluate.plan_rounds(db, cur.lastrowid, tokens)
    for idx, rname in enumerate(names):
        db.execute('INSERT INTO rounds (plan_id, idx, name, status) VALUES (?, ?, ?, ?)',
                   (cur.lastrowid, idx, rname, 'pending'))
    db.commit()
    return cur.lastrowid


def add_steps(db, round_id, steps):
    base = db.execute('SELECT COALESCE(MAX(seq), 0) AS m FROM steps WHERE round_id = ?', (round_id,)).fetchone()['m']
    for i, st in enumerate(steps, 1):
        db.execute('INSERT INTO steps (round_id, seq, kind, model, scenario, variant, params, status) '
                   'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                   (round_id, base + i, st['kind'], st.get('model'), st.get('scenario'), st.get('variant', 0),
                    json.dumps(st.get('params') or {}), 'pending'))
    db.commit()


def step_rows(db, plan_id=None, kind='scenario', round_name=None, status='done', imported=None):
    """ :return: list of dicts (step + parsed result + round name) """
    sql = ('SELECT s.*, r.name AS round_name, r.plan_id AS plan_id, p.imported AS imported FROM steps s '
           'JOIN rounds r ON r.id = s.round_id JOIN plans p ON p.id = r.plan_id WHERE s.kind = ?')
    args = [kind]
    if status:
        sql += ' AND s.status = ?'
        args.append(status)
    if plan_id is not None:
        sql += ' AND (r.plan_id = ? OR p.imported = 1)'
        args.append(plan_id)
    if round_name:
        sql += ' AND r.name = ?'
        args.append(round_name)
    if imported is not None:
        sql += ' AND p.imported = ?'
        args.append(1 if imported else 0)
    out = []
    for row in db.execute(sql + ' ORDER BY s.id', args):
        item = dict(row)
        item['params'] = loads(item['params'], {})
        item['result'] = loads(item['result'], {}) or {}
        out.append(item)
    return out


# ------------------------------------------------------------------ Ollama (raw)


def ollama(path, body=None, timeout=900):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(OLLAMA_URL + path, data=data, headers={'Content-Type': 'application/json'},
                                 method='POST' if data else 'GET')
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b'null')


def installed_models():
    try:
        return [m['name'] for m in (ollama('/api/tags', timeout=15) or {}).get('models') or []]
    except (OSError, ValueError, urllib.error.URLError):
        return []


def loaded_models():
    try:
        return [{'name': m.get('name'), 'size_gib': round((m.get('size') or 0) / 2 ** 30, 2),
                 'vram_gib': round((m.get('size_vram') or 0) / 2 ** 30, 2), 'ctx': m.get('context_length')}
                for m in (ollama('/api/ps', timeout=10) or {}).get('models') or []]
    except (OSError, ValueError, urllib.error.URLError):
        return None


def unload_all():
    for m in loaded_models() or []:
        try:
            ollama('/api/generate', {'model': m['name'], 'keep_alive': 0}, timeout=120)
        except (OSError, ValueError, urllib.error.URLError):
            pass


def bench_models():
    """ installed local models in the bench order (light -> heavy), others after """
    have = installed_models()
    ordered = [m for m in MODEL_ORDER if m in have]
    return ordered + sorted(m for m in have if m not in ordered and not m.startswith('import'))


# ------------------------------------------------------------------ host samples (read only)


def _sh(cmd, timeout=20):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


def parse_ms(text):
    m = re.search(r'([\d.]+)', str(text or ''))
    return float(m.group(1)) if m else None


def active_wan(gateways):
    """ dpinger status -> the gateway with the lowest priority that is not down (the default route) """
    best = None
    for name, gw in (gateways or {}).items():
        if str(gw.get('status')) in ('down', 'force_down'):
            continue
        try:
            prio = int(gw.get('priority') or 255)
        except ValueError:
            prio = 255
        if best is None or prio < best[0]:
            best = (prio, name, gw)
    if best is None:
        return None
    return {'name': best[1], 'delay_ms': parse_ms(best[2].get('delay')), 'loss': parse_ms(best[2].get('loss'))}


def ollama_runner():
    """ (%cpu, rss GiB) of the model processes in the jail (llama-server on Ollama 0.34, "ollama runner" before) """
    rows = [l.split(None, 2) for l in _sh('jexec ollama ps -axo rss,%cpu,command').splitlines()
            if 'llama-server' in l or 'runner' in l]
    rows = [r for r in rows if len(r) == 3 and r[0].isdigit()]
    if not rows:
        return None, None
    return round(sum(float(r[1]) for r in rows), 1), round(sum(int(r[0]) for r in rows) / 2 ** 20, 2)


def sample():
    d = {'ts': now()}
    m = re.search(r'\{\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)', _sh('sysctl -n vm.loadavg'))
    d['load'] = [float(x) for x in m.groups()] if m else None
    temps = [float(v) for v in re.findall(r'dev\.cpu\.\d+\.temperature: ([\d.]+)', _sh('sysctl dev.cpu'))]
    d['temp_max'] = max(temps) if temps else None
    top = _sh('top -b -d2 -s1 -o cpu 5')
    m = re.findall(r'CPU:\s*([\d.]+)% user,\s*([\d.]+)% nice,\s*([\d.]+)% system,\s*([\d.]+)% interrupt,\s*([\d.]+)% idle', top)
    if m:
        u, n, s, i, idle = (float(x) for x in m[-1])
        d['cpu'] = {'user': u, 'nice': n, 'system': s, 'interrupt': i, 'idle': idle}
    m = re.search(r'Mem: (.*)', top)
    d['mem'] = m.group(1).strip() if m else None
    m = re.search(r'([\d.]+)([MG]) Free', d['mem'] or '')
    d['mem_free_gib'] = (float(m.group(1)) / (1024 if m.group(2) == 'M' else 1)) if m else None
    cpu, rss = ollama_runner()
    if cpu is not None:
        d['ollama_cpu'] = cpu
        d['ollama_rss_gib'] = rss
    d['models'] = loaded_models()
    try:
        gws = json.loads(_sh('pluginctl -r return_gateways_status') or '{}').get('dpinger') or {}
    except ValueError:
        gws = {}
    d['wan'] = active_wan(gws)
    ping = _sh('ping -q -c 5 -i 0.2 -t 5 1.1.1.1', 10)
    lm = re.search(r'([\d.]+)% packet loss', ping)
    rm = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)', ping)
    d['ping'] = {'loss': float(lm.group(1)) if lm else None, 'avg': float(rm.group(2)) if rm else None,
                 'max': float(rm.group(3)) if rm else None}
    stats = _sh('tail -c 60000 /var/log/suricata/stats.log')
    block = stats[stats.rfind('Date:'):] if 'Date:' in stats else ''
    sur = {}
    for key in ('capture.kernel_packets', 'capture.kernel_drops', 'decoder.pkts', 'detect.alert', 'ips.blocked',
                'ips.dropped'):
        vals = re.findall(r'^%s\s*\|\s*Total\s*\|\s*(\d+)' % re.escape(key), block, re.M)
        if vals:
            sur[key] = sum(int(x) for x in vals)
    d['suricata'] = sur or None
    return d


def share(limits=None):
    """ :return: (threads, num_ctx) the jail gives to the model now (runtime-limits.json), with the defaults """
    limits = _compute().read_limits() if limits is None else limits

    def num(key, default):
        try:
            return int(limits.get(key)) or default
        except (TypeError, ValueError):
            return default
    return num('threads', DEFAULT_THREADS), num('ctx', DEFAULT_CTX)


def load_max(threads=None, cores=None):
    """ load average the guard tolerates: the threads of the model plus the headroom of the firewall, never more
        than the cores of the host (above that there is a queue). 2 threads on 4 cores = 3.5; 3 threads = 4.0 """
    threads = threads or share()[0]
    cores = cores or os.cpu_count() or 4
    return min(float(cores), threads + LOAD_HEADROOM)


def plan_compute(db, plan_id):
    """ the compute profile most steps of a plan ran with ({} when none was stamped) """
    row = db.execute('SELECT c.data FROM steps s JOIN rounds r ON r.id = s.round_id JOIN compute_profiles c ON c.id = '
                     's.compute_id WHERE r.plan_id = ? GROUP BY c.id ORDER BY COUNT(*) DESC LIMIT 1', (plan_id,)).fetchone()
    return loads(row['data'], {}) if row else {}


def unsafe(samples):
    """ :param samples: newest first; :return: reason when the last SUSTAIN samples all break a limit """
    if len(samples) < SUSTAIN:
        return None
    recent = samples[:SUSTAIN]
    if all((s.get('wan') or {}).get('loss') is not None and s['wan']['loss'] > LOSS_MAX for s in recent):
        return 'WAN %s loss > %.0f %%' % (recent[0]['wan']['name'], LOSS_MAX)
    if all((s.get('wan') or {}).get('delay_ms') is not None and s['wan']['delay_ms'] > RTT_MAX for s in recent):
        return 'WAN %s delay > %.0f ms' % (recent[0]['wan']['name'], RTT_MAX)
    limit = load_max()
    if all(s.get('load') and s['load'][0] > limit for s in recent):
        return 'load average > %.1f' % limit
    return None


def recent_samples(db, n=SUSTAIN + 2):
    return [loads(r['data'], {}) for r in db.execute('SELECT data FROM samples ORDER BY id DESC LIMIT ?', (n,))]


# ------------------------------------------------------------------ production activity (do not compete)


def _locked(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def ollama_clients(exclude=(), text=None):
    """
    processes connected to the Ollama port that are not ours (sockstat, root sees every user): a report or a
    notification sent by cron, the AI queue worker, a brief, a manual curl.  :return: [{pid, user, command}]
    """
    text = _sh('sockstat -46 -c -P tcp -p %d' % OLLAMA_PORT) if text is None else text
    out, seen = [], set()
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 7 or not cols[2].isdigit() or not cols[-1].endswith(':%d' % OLLAMA_PORT):
            continue                        # header, closed socket, or the server side (local = :11434)
        pid = int(cols[2])
        if pid in exclude or pid in seen or cols[1].startswith(('ollama', 'llama')):
            continue
        seen.add(pid)
        out.append({'pid': pid, 'user': cols[0], 'command': cols[1]})
    for item in out:
        cmd = _sh('ps -o command= -p %d' % item['pid'], 5).strip()
        if cmd:
            item['command'] = cmd[:160]
    return out


def transient_error(text, contention=False):
    """ True when the error says nothing about the model: Ollama busy/unreachable, or a timeout under contention """
    text = str(text or '')
    return bool(BUSY_RE.search(text) or (contention and TIMEOUT_RE.search(text)))


def describe_clients(clients):
    return ', '.join('pid %d (%s)' % (c['pid'], c['command']) for c in clients[:3])


def production_busy(check_cpu=True, exclude=None):
    """ :return: reason when a production AI job, a brief generation or another Ollama client is running """
    clients = ollama_clients(exclude if exclude is not None else (os.getpid(),))
    if clients:
        return 'Ollama in use by another process: %s' % describe_clients(clients)
    try:
        db = sqlite3.connect('file:%s?mode=ro' % QUEUE_DB, uri=True, timeout=10)
        try:
            n = db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued', 'running')").fetchone()[0]
        finally:
            db.close()
        if n:
            return '%d job(s) in the AI queue' % n
    except sqlite3.Error:
        pass
    if _locked(BRIEF_LOCK):
        return 'AI brief generation running'
    if check_cpu:
        cpu, _rss = ollama_runner()
        if cpu is not None and cpu > OTHER_CPU:
            return 'Ollama busy with another client (%.0f %% CPU)' % cpu
    return None


# ------------------------------------------------------------------ quality (objective, automatic)

# the patterns below read the answers of the model: Portuguese AND English words on purpose (evaluation data)
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)
PORT_RES = (re.compile(r'(?i)\b(?:porta|portas|port|ports|dport|sport)\s*(?:de destino\s*|de origem\s*)?'
                       r'(?:tcp|udp)?\s*[:#]?\s*(\d{1,5})\b'),
            re.compile(r'(?i)\b(\d{1,5})\s*/\s*(?:tcp|udp)\b'),
            re.compile(r'(?i)\b(?:tcp|udp)\s*/\s*(\d{1,5})\b'))
UNSAFE_RE = re.compile(r'(?i)(desativ\w* o firewall|desabilit\w* o firewall|disable the firewall|'
                       r'desativ\w* o suricata|desabilit\w* o suricata|disable suricata|allow any any|'
                       r'liber\w* (?:todo o tráfego|tudo)|permit\w* qualquer origem.{0,40}qualquer destino|'
                       r'desativ\w* (?:a )?autentica|chmod 777|senha padrão)')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',
                   re.I)


def mask(text, limit=220):
    """ an excerpt safe for the report and e-mails (no addresses) """
    text = IP_RE.sub('<address>', re.sub(r'\s+', ' ', str(text or ''))).strip()
    return text if len(text) <= limit else text[:limit].rsplit(' ', 1)[0] + '…'


def _present(number, haystack):
    return re.search(r'(?<![\d.])%s(?![\d])' % re.escape(str(number)), haystack) is not None


def evidence_check(answer, evidence):
    """ CVEs, ports and citations of the answer checked against the text the model received """
    answer = str(answer or '')
    evidence = str(evidence or '')
    low_ev = evidence.lower()
    cves = sorted({c.upper() for c in CVE_RE.findall(answer)})
    invented_cves = [c for c in cves if c.lower() not in low_ev]
    ports = set()
    for rx in PORT_RES:
        ports.update(p for p in rx.findall(answer) if 0 < int(p) < 65536)
    invented_ports = sorted((p for p in ports if not _present(p, evidence)), key=int)
    from ai.validate import CITATION_RE
    cites = CITATION_RE.findall(answer)
    bad_cites = [c for c in cites if c[1:].split(':', 1)[0].strip().lower() not in low_ev]
    return {'cves': len(cves), 'invented_cves': invented_cves, 'ports': len(ports), 'invented_ports': invented_ports,
            'citations': len(cites), 'invalid_citations': len(bad_cites),
            'unsafe_advice': sorted({m.group(0).lower() for m in UNSAFE_RE.finditer(answer)})}


def quality(doc):
    """
    score 0-3, automatic: 3 = format (after the correction) and language right, nothing invented, nothing cut;
    -1 for each of: format wrong, language wrong, invented CVE/port or invalid citation or unsafe advice,
    answer cut by num_predict; 0 when there is no answer (error, timeout, empty).
    """
    if doc.get('error') or not (doc.get('text') or '').strip():
        return 0
    score = 3
    if doc.get('fmt_final_ok') is False:
        score -= 1
    if not (doc.get('lang') or {}).get('ok'):
        score -= 1
    ev = doc.get('evidence') or {}
    if ev.get('invented_cves') or ev.get('invented_ports') or ev.get('invalid_citations') or ev.get('unsafe_advice'):
        score -= 1
    if doc.get('truncated'):
        score -= 1
    return max(0, score)


def rubric(doc):
    """ item 6: five criteria 0-3 (automatic, objective proxies) """
    if doc.get('error') or not (doc.get('text') or '').strip():
        return {'precision': 0, 'evidence': 0, 'actions': 0, 'hallucination': 0, 'clarity': 0}
    ev = doc.get('evidence') or {}
    invented = len(ev.get('invented_cves') or []) + len(ev.get('invented_ports') or [])
    precision = 3 - min(2, invented) - (1 if doc.get('fmt_final_ok') is False else 0)
    if ev.get('citations'):
        evidence = round(3 * (1 - ev['invalid_citations'] / float(ev['citations'])))
    else:
        needs = doc.get('scenario', '').startswith('console_')
        evidence = 0 if needs else (2 if not invented else 1)
    inc = doc.get('incident') or {}
    if doc.get('scenario') == 'incident_summary':
        actions = 3 if inc.get('parsed') and not doc.get('invalid_action_ids') else (1 if inc.get('parsed') else 0)
    else:
        actions = 1 if ev.get('unsafe_advice') else 3
    hallucination = 3 - min(3, invented + (ev.get('invalid_citations') or 0))
    lang = doc.get('lang') or {}
    clarity = 0 if not lang.get('ok') else (3 if lang.get('pt', 0) >= 8 * max(1, lang.get('en', 0)) else 2)
    if doc.get('truncated'):
        clarity = max(0, clarity - 1)
    return {'precision': max(0, precision), 'evidence': max(0, evidence), 'actions': actions,
            'hallucination': max(0, hallucination), 'clarity': clarity}


# ------------------------------------------------------------------ isolation of the step child

BLOCKED = []


def write_guard():
    """ the scenario child: no file writes, SQLite read-only (the data builders only read) """
    import builtins
    import io
    real_open, real_osopen, real_connect = builtins.open, os.open, sqlite3.connect
    allowed = (os.devnull,)

    def g_open(file, mode='r', *a, **k):
        if isinstance(mode, str) and any(c in mode for c in 'wax+') and str(file) not in allowed:
            BLOCKED.append('open %s' % file)
            raise PermissionError('bench write guard: %s' % file)
        return real_open(file, mode, *a, **k)

    def g_osopen(path, flags, *a, **k):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC) and str(path) not in allowed:
            BLOCKED.append('os.open %s' % path)
            raise PermissionError('bench write guard: %s' % path)
        return real_osopen(path, flags, *a, **k)

    def blocked(name):
        def fn(*a, **k):
            BLOCKED.append('%s %s' % (name, a[:1]))
            raise PermissionError('bench write guard: os.%s' % name)
        return fn

    def g_makedirs(path, *a, **k):
        if os.path.isdir(path):
            return None
        BLOCKED.append('makedirs %s' % path)
        raise PermissionError('bench write guard: makedirs %s' % path)

    def ro_connect(database, *a, **k):
        if isinstance(database, str) and database != ':memory:':
            path = database[5:].split('?')[0] if database.startswith('file:') else database
            database = 'file:%s?mode=ro' % path
            k['uri'] = True
        return real_connect(database, *a, **k)

    builtins.open = g_open
    io.open = g_open
    os.open = g_osopen
    os.makedirs = g_makedirs
    for name in ('replace', 'rename', 'unlink', 'remove', 'mkdir', 'rmdir', 'chmod', 'chown', 'symlink', 'link',
                 'truncate', 'utime'):
        setattr(os, name, blocked(name))
    sqlite3.connect = ro_connect


class Recorder:
    """ what happened inside one step: Ollama calls, validation results, the task stack """

    def __init__(self):
        self.stack = []
        self.calls = []
        self.checks = []
        self.prompts = []


def isolate(model, overrides=None, nomr=False, recorder=None):
    """
    The explicit bench mode of the plugin pipeline (this process only): NullAuditLog, no queue cache, the
    local_only routing in memory with `model` and mode sync, fallback none, provider = local Ollama with
    per call statistics.  :return: (routing dict, recorder)
    """
    from ai import assistant as amod
    from ai import audit as audit_mod
    from ai import jobqueue
    from ai import mapreduce
    from ai import scenarios as routing_mod
    from ai import validate
    from ai.providers import ProviderError
    from ai.providers.ollama import OllamaProvider

    overrides = dict(overrides or {})
    rec = recorder or Recorder()
    audit_mod.AuditLog.record = lambda self, **kw: None
    jobqueue.cache_get = lambda *a, **k: None
    jobqueue.cache_put = lambda *a, **k: None
    os.environ.pop('PA_AI_JOB', None)
    os.environ.pop('PA_AI_ROUTE', None)
    os.environ['PA_AI_INLINE'] = '1'
    os.environ['PA_AI_BENCH'] = '1'

    entries = routing_mod.preset_scenarios('local_only')
    for entry in entries.values():
        entry['model'] = model
        entry['mode'] = 'sync'
        for key in ('num_ctx', 'num_predict', 'budget', 'timeout', 'retries', 'keep_alive'):
            if key in overrides:
                entry[key] = overrides[key]
    routing = routing_mod.empty_routing()
    routing.update(preset='custom', fallback={'provider': 'none', 'model': ''}, scenarios=entries)
    routing_mod.load_routing = lambda path=None: routing

    orig_check = validate.check

    def check(scenario, text, language=None, ctx=None, checks=None):
        problems = orig_check(scenario, text, language, ctx, checks)
        rec.checks.append({'task': rec.stack[-1] if rec.stack else None, 'problems': problems})
        return problems
    validate.check = check

    orig_ask = amod.Assistant.ask

    def ask(self, task, data, *a, **k):
        rec.stack.append(task.name)
        try:
            return orig_ask(self, task, data, *a, **k)
        finally:
            rec.stack.pop()
    amod.Assistant.ask = ask

    class BenchOllama(OllamaProvider):
        def _payload(self, messages, stream, fmt=None):
            payload = super()._payload(messages, stream, fmt)
            if overrides.get('think') not in (None, ''):
                # evaluation of a model that always reasons in its own format (gpt-oss "harmony"): the level and
                # room for the reasoning, recorded in the setup of the evaluation
                payload['think'] = overrides['think']
                if overrides.get('think_extra') and payload['options'].get('num_predict'):
                    payload['options']['num_predict'] = int(payload['options']['num_predict']) + \
                        int(overrides['think_extra'])
            return payload

        def _read_limited(self, response):
            data = super()._read_limited(response)
            self._raw = data
            return data

        def chat(self, messages, stream=False, on_chunk=None, fmt=None):
            self._raw = None
            if overrides.get('num_thread'):
                self.num_thread = int(overrides['num_thread'])
            call = {'task': rec.stack[-1] if rec.stack else None, 'n_messages': len(messages),
                    'correction': bool(messages) and (messages[-1]['content'].startswith('Your previous answer') or
                                                      'Do not write any reasoning' in messages[-1]['content']),
                    'structured': bool(fmt), 'prompt_bytes': sum(len(m['content'].encode()) for m in messages)}
            if not call['correction']:
                rec.prompts.append('\n'.join(m['content'] for m in messages if m['role'] != 'assistant'))
            t0 = time.monotonic()
            try:
                result = super().chat(messages, stream=False, on_chunk=None, fmt=fmt)
            except ProviderError as exc:
                call.update(wall_s=round(time.monotonic() - t0, 1), error=str(exc), timeout='timeout' in str(exc))
                rec.calls.append(call)
                raise
            try:
                st = json.loads(self._raw) if self._raw else {}
            except ValueError:
                st = {}
            ns = 1e9
            call.update(wall_s=round(time.monotonic() - t0, 1), options=self._payload(messages, False, fmt)['options'],
                        load_s=round((st.get('load_duration') or 0) / ns, 1), prompt_tokens=st.get('prompt_eval_count'),
                        gen_tokens=st.get('eval_count'), total_s=round((st.get('total_duration') or 0) / ns, 1),
                        done_reason=st.get('done_reason'),
                        think=self._payload(messages, False, fmt).get('think'),
                        thinking_chars=len((st.get('message') or {}).get('thinking') or '') or None)
            if st.get('prompt_eval_duration'):
                call['prompt_eval_s'] = round(st['prompt_eval_duration'] / ns, 1)
                call['prompt_tps'] = round(st['prompt_eval_count'] / (st['prompt_eval_duration'] / ns), 1)
            if st.get('eval_duration'):
                call['gen_s'] = round(st['eval_duration'] / ns, 1)
                call['gen_tps'] = round(st['eval_count'] / (st['eval_duration'] / ns), 1)
            rec.calls.append(call)
            return result

    def factory(name, options, timeout=None):
        if name != 'ollama':
            raise ProviderError('bench: only the local Ollama is used (route asked for %s)' % name)
        return BenchOllama(options, timeout=timeout)
    amod.get_provider = factory

    if nomr:
        mapreduce.needed = lambda route, data, budget=None: False
        from console import ask as cask
        cask._map_reduce = lambda *a, **k: None
    return routing, rec


# ------------------------------------------------------------------ scenarios with real data (variant v)


def _pick(seq, v):
    seq = list(seq or [])
    return seq[v % len(seq)] if seq else None


def build_scenario(sid, v, model):
    """ :return: dict {id, subject, run(cfg) -> result, ctx, post, language} or {'skip': reason} """
    from ai import Assistant, Task
    from ai.audit import NullAuditLog

    def plain(task, data, language=LANG):
        def run(cfg):
            a = Assistant(cfg, app='policyanalyzer', audit=NullAuditLog(), inline=True)
            return a.ask(task, data, language=language, subject=task.name)
        return run

    if sid in ('explain_finding', 'explain_set'):
        import explain as pa_explain
        from ai import mapreduce
        report = pa_explain.load_report() or {}
        findings = sorted([f for f in report.get('findings') or [] if isinstance(f, dict)],
                          key=lambda f: pa_explain.SEVERITY_ORDER.get(f.get('severity'), 9))
        if not findings:
            return {'skip': 'no Policy Analyzer report'}
        if sid == 'explain_finding':
            pref = [f for f in findings if f.get('type') in ('permissive', 'wan_exposed', 'shadowed') and f.get('rules')]
            f = _pick(pref or findings, v)
            task, data = pa_explain.subject_data(report, f['id'])
            return {'subject': '%s · %s' % (f.get('severity'), f.get('type')), 'run': plain(task, data)}
        task, data = pa_explain.subject_data(report, 'all')

        def run_set(cfg):
            a = Assistant(cfg, app='policyanalyzer', audit=NullAuditLog(), inline=True)
            route = a.route_for(task)
            if mapreduce.needed(route, data):
                return mapreduce.explain_set(a, task, data, LANG, 'finding:all', route.budget)
            return a.ask(task, data, language=LANG, subject='finding:all')
        return {'subject': '%d achados' % len(findings), 'run': run_set, 'data_tokens': mapreduce.size_tokens(data)}

    if sid in ('war_room_brief', 'war_room_focus'):
        from ai import brief
        inputs = brief.build_inputs()
        if sid == 'war_room_brief':
            return {'subject': 'janela 15 min', 'post': brief.clean_text,
                    'run': plain(Task('war_room_brief', brief.BRIEF_INSTRUCTIONS, 'Write the situational brief.'), inputs)}
        top = (inputs.get('firewall_log') or {}).get('top_blocked_sources') or []
        addrs = [r.get('address') or r.get('ip') or r.get('src') for r in top if isinstance(r, dict)]
        focus = _pick([a for a in addrs if a], v)
        if not focus:
            return {'skip': 'no blocked source in the window'}
        return {'subject': 'origem bloqueada #%d' % (v % len(addrs)), 'post': brief.clean_text,
                'run': plain(Task('war_room_focus', brief.FOCUS_INSTRUCTIONS, 'Write the note about the focus address.'),
                             brief.build_inputs(focus=focus))}

    if sid.startswith('console_'):
        from console import ask as cask
        from console.collectors import filterlog, rules as crules, suricata as csur
        from console.common import Budget, Paths
        paths = Paths()
        if sid == 'console_ask':
            q = QUESTIONS[v % len(QUESTIONS)]
            return {'subject': q, 'run': lambda cfg: cask.cmd_ask({'q': q}, LANG, 'send', paths=paths, config=cfg)}
        if sid == 'console_explain_log':
            rows, _m = filterlog.tail(paths, filterlog.Filter(action='block', proto='tcp'), 40, Budget(8.0),
                                      crules.index(paths))
            good = [r for r in rows if r.get('rid') and r.get('dport') and r.get('dir') == 'in'] or rows
            row = _pick(good, v)
            if not row:
                return {'skip': 'no blocked log line'}
            payload = {'ts': row['ts'], 'iface': row.get('interface'), 'action': row.get('action'), 'dir': row.get('dir'),
                       'proto': row.get('proto'), 'src': row['src_ip'], 'sport': row.get('sport'), 'dst': row['dst_ip'],
                       'dport': row.get('dport'), 'rid': row.get('rid')}
            return {'subject': '%s %s dport %s' % (row.get('action'), row.get('proto'), row.get('dport')),
                    'run': lambda cfg: cask.cmd_explain('log', payload, LANG, 'send', paths=paths, config=cfg)}
        if sid == 'console_explain_rule':
            import explain as pa_explain
            report = pa_explain.load_report() or {}
            uuids = []
            for f in report.get('findings') or []:
                for r in f.get('rules') or []:
                    if r.get('uuid') and r['uuid'] not in uuids:
                        uuids.append(r['uuid'])
            u = _pick(uuids, v)
            if not u:
                return {'skip': 'no rule in the findings'}
            return {'subject': 'finding rule #%d' % (v % len(uuids)),
                    'run': lambda cfg: cask.cmd_explain('rule', {'uuid': u}, LANG, 'send', paths=paths, config=cfg)}
        if sid == 'console_explain_alert':
            arows = []
            for days in (14, 90):
                arows, _m = csur.tail(paths, Budget(10.0), limit=10, days=days)
                if arows:
                    break
            a = _pick(arows, v)
            if not a:
                return {'skip': 'no Suricata alert in 90 days'}
            payload = {'timestamp': a['timestamp'], 'flow_id': a['flow_id'], 'sid': a['sid']}
            return {'subject': 'sid %s' % a['sid'],
                    'run': lambda cfg: cask.cmd_explain('alert', payload, LANG, 'send', paths=paths, config=cfg)}

    if sid in ('incident_summary', 'incident_digest'):
        from incidents import common as icommon, engine as iengine, triage
        ieng = iengine.Engine(icommon.Context())
        if sid == 'incident_summary':
            row = _pick(ieng.search({}, ('score', 'desc'), 1, 10).get('rows'), v)
            if not row:
                return {'skip': 'no incident case'}
            case = ieng.case_detail(row['id'])['case']
            cands = triage.candidates(case)
            task = Task('incident_summary', triage.SUMMARY_INSTRUCTIONS, 'Triage this case and answer with the JSON object.',
                        schema=triage.summary_schema(cands), check_ctx={'valid_ids': [c['id'] for c in cands]})
            return {'subject': 'caso score %s' % case.get('score'), 'run': plain(task, triage.case_payload(case, cands)),
                    'ctx': {'cands': cands}}
        day = time.strftime('%Y-%m-%d', time.localtime(time.time() - 86400 * v))
        ddata = triage.digest_payload(ieng, day)
        if not ddata.get('cases'):
            day = time.strftime('%Y-%m-%d', time.localtime(time.time() - 86400 * (v + 1)))
            ddata = triage.digest_payload(ieng, day)
        return {'subject': '%s, %s casos' % (day, ddata.get('cases')),
                'run': plain(Task('incident_digest', triage.DIGEST_INSTRUCTIONS, 'Write the daily digest.'), ddata)}

    if sid in ('anomaly_explain', 'anomaly_host'):
        from anomalies import common as acommon, engine as aengine, explain as aexplain
        aeng = aengine.Engine(acommon.Context())
        row = _pick(aeng.search({}, ('severity', 'desc'), 1, 10).get('rows'), v)
        fd = aeng.finding(row['id']) if row else {}
        if fd.get('status') != 'ok':
            return {'skip': 'no anomaly finding'}
        if sid == 'anomaly_explain':
            return {'subject': '%s %s' % (fd['finding'].get('severity'), fd['finding'].get('type')),
                    'run': plain(Task('anomaly_explain', aexplain.FINDING_INSTRUCTIONS, 'Explain this anomaly finding.'),
                                 aexplain.compact_finding(fd['finding']))}
        host = fd['finding'].get('host')
        if not host:
            return {'skip': 'anomaly without host'}
        return {'subject': 'host of the finding',
                'run': plain(Task('anomaly_host', aexplain.HOST_INSTRUCTIONS,
                                  'Describe this host: what is normal for it and what is happening now.'),
                             aexplain.compact_host(aeng.host(host)))}

    if sid in ('explain_cve', 'vuln_review_suggest'):
        from vulns import explain as vexplain, prioritize
        pr = prioritize.build()
        if sid == 'explain_cve':
            item = _pick(pr.get('items'), v)
            if not item:
                return {'skip': 'no prioritized CVE'}
            return {'subject': '%s %s' % (item['cve'], item['priority']),
                    'run': plain(Task('explain_cve', vexplain.EXPLAIN_INSTRUCTIONS,
                                      'Explain this vulnerability for this firewall.'), vexplain.cve_data(item))}
        q = _pick(pr.get('review'), v)
        if not q:
            return {'skip': 'empty review queue'}
        data = {'kind': q['kind'], 'component': q['package'] or q['subject'], 'version': q['version'],
                'cves': q['cves'][:20], 'why_in_review': q['reason'],
                'candidates': [{'id': c['id'], 'service': c['service'], 'service_name': c.get('name'),
                                'proto': c.get('proto'), 'port': c.get('port'),
                                'internet_reachable': c.get('internet_reachable'), 'package': c.get('package')}
                               for c in q['candidates']]}
        ids = [c['id'] for c in q['candidates']]
        task = Task('vuln_review_suggest', vexplain.SUGGEST_INSTRUCTIONS, 'Suggest the mapping of this component.',
                    schema=vexplain.mapping_schema(ids), render=vexplain.render_mapping,
                    check_ctx={'first_values': ids + ['none', 'unsure']})
        return {'subject': '%s (%d candidatos)' % (data['component'], len(ids)), 'run': plain(task, data)}

    if sid == 'explain_device':
        from devices import common as dcommon, explain as dexplain, view as dview
        lst = dview.listing(sort='risk', rows=10)
        row = _pick(lst.get('rows') or lst.get('devices'), v)
        dev = dview.device(row['id']) if row else {}
        if dev.get('status') != 'ok':
            return {'skip': 'no device'}
        task = Task('explain_device', dexplain.INSTRUCTIONS, 'Explain this device of the local network.',
                    schema=dexplain.type_schema(), render=dexplain.render_type,
                    check_ctx={'first_values': list(dcommon.TYPES)})
        return {'subject': 'risco %s' % dev['device'].get('risk'), 'run': plain(task, dexplain.device_data(dev['device']))}

    if sid in ('posture_check', 'posture_summary', 'shadowai_overview', 'minrule_explain'):
        from posture import cli as pcli, engine as pengine
        from posture.common import Paths as PPaths, load_json
        ppaths = PPaths()
        if sid == 'shadowai_overview':
            from shadowai import cli as scli
            srep = load_json(ppaths.db('shadowai.json'))
            if not (isinstance(srep, dict) and srep.get('kind') == 'shadowai'):
                return {'skip': 'no shadow AI report'}
            return {'subject': '%d services' % len(srep.get('services') or []),
                    'run': plain(Task('shadowai_overview', scli.OVERVIEW, 'Explain the AI usage on this network.'),
                                 scli.ai_overview(srep))}
        if sid == 'minrule_explain':
            from minrule import analyze as mengine, cli as mcli
            cands = mengine.candidates(ppaths)
            clist = cands.get('rules') or cands.get('candidates') or (cands if isinstance(cands, list) else [])
            for off in range(len(clist)):
                c = clist[(v + off) % len(clist)]
                mres = mcli.cached(ppaths, c.get('uuid'), 7) or mengine.analyze(ppaths, c.get('uuid'), 7)
                if mres.get('status') == 'ok':
                    return {'subject': 'candidata #%d' % ((v + off) % len(clist)),
                            'run': plain(Task('minrule_explain', mcli.EXPLAIN,
                                              'Explain the risk of this rule and the minimal rule proposal.'),
                                         mcli.ai_view(mres))}
            return {'skip': 'no minimal rule candidate'}
        prep = pengine.last(ppaths)
        if prep.get('status', 'ok') != 'ok' or not prep.get('checks'):
            return {'skip': 'no posture assessment'}
        if sid == 'posture_summary':
            return {'subject': 'grade %s' % prep.get('grade'),
                    'run': plain(Task('posture_summary', pcli.EXECUTIVE,
                                      'Write the executive summary of this posture assessment.'), pcli.executive_view(prep))}
        sev = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        failed = sorted([c for c in prep['checks'] if c['result'] == 'fail'], key=lambda c: sev.get(c['severity'], 9))
        fc = _pick(failed, v)
        if not fc:
            return {'skip': 'no failed posture check'}
        return {'subject': '%s' % fc['id'],
                'run': plain(Task('posture_check', pcli.EXPLAIN_CHECK, 'Explain this health check result.'), pcli.ai_view(fc))}

    if sid in ('report_summary', 'notification_summary'):
        from reports import aisum, collect as rcollect, settings as rsettings, store as rstore
        rcfg = rsettings.load()
        rdb = rstore.connect(readonly=True)
        t = int(time.time()) - 86400 * v
        if sid == 'report_summary':
            rdata = rcollect.build('daily', t - 86400, t, rcfg['report']['sections'], rdb, None)
            return {'subject': 'daily -%dd' % v, 'language': rcfg['language'],
                    'run': plain(Task('report_summary', aisum.EXEC_INSTRUCTIONS, 'Write the executive summary of this report.'),
                                 aisum.report_inputs(rdata), rcfg['language'])}
        events = []
        if rdb is not None:
            _t, notes = rstore.notifications(rdb, rows=50)
            events = [{'type': i['type'], 'severity': i['severity'], 'title': i['title'], 'detail': i['detail'],
                       'data': i['data']} for i in notes if i['type'] != 'report']
        if not events and rdb is not None:
            from reports import notify as rnotify
            orig_get, orig_set = rstore.meta_get, rstore.meta_set
            markers = {'marker:quarantine': 0, 'marker:devices': t - 7 * 86400}
            rstore.meta_get = lambda db, key, default=None: markers[key] if key in markers else orig_get(db, key, default)
            rstore.meta_set = lambda *a, **k: None
            try:
                evs = rnotify.detect_quarantine(rdb, t) or rnotify.detect_devices(rdb, t) or []
            finally:
                rstore.meta_get, rstore.meta_set = orig_get, orig_set
            events = [{'type': e['type'], 'severity': e['severity'], 'title': e['title'], 'detail': e.get('detail'),
                       'data': e.get('data')} for e in evs]
        if not events:
            return {'skip': 'no notification event'}
        types = sorted({e['type'] for e in events})
        etype = types[v % len(types)]
        data = [{'type': e['type'], 'severity': e['severity'], 'title': e['title'], 'detail': e.get('detail'),
                 'facts': e.get('data')} for e in events if e['type'] == etype][:20]
        return {'subject': '%d event(s) %s' % (len(data), etype), 'language': rcfg['language'],
                'run': plain(Task('notification_summary', aisum.NOTIFY_INSTRUCTIONS, 'Write the alert summary.'),
                             {'events': data}, rcfg['language'])}

    if sid == 'quicktest':
        def run_quick(_cfg):
            import random
            from setup import quicktest
            from ai.providers import ProviderError
            t0 = time.monotonic()
            res = quicktest.main([model], rng=random.Random(7 + v), now=time.localtime())
            CURRENT.calls.append({'task': 'quicktest', 'wall_s': round(time.monotonic() - t0, 1),
                                  'load_s': res.get('load_seconds'), 'gen_tokens': res.get('tokens'),
                                  'gen_tps': res.get('tokens_per_second')})
            CURRENT.prompts.append(res.get('prompt') or '')
            if res.get('status') != 'ok':
                raise ProviderError(res.get('message'))
            return {'status': 'ok', 'text': res.get('answer') or '', 'attempts': 1, 'problems': []}
        return {'subject': 'seed %d' % (7 + v), 'run': run_quick}
    return {'skip': 'unknown scenario'}


CURRENT = Recorder()

# language heuristic over the answers of the model (evaluation data, Portuguese words on purpose)
PT_RE = re.compile(r'\b(não|que|para|com|uma|são|está|regra|porta|endereço|tráfego|você|também|isso|pelo|pela|'
                   r'como|mais|ou|seu|sua|nos|das|dos|em|ao|à)\b', re.I)
EN_RE = re.compile(r'\b(the|and|is|are|this|that|with|from|which|rule|traffic|should|would|you|your|of|to|it)\b', re.I)
CJK_RE = re.compile(r'[぀-ヿ㐀-鿿가-힯]')


def lang_check(text, language=LANG):
    body = re.sub(r'```.*?```', ' ', str(text or ''), flags=re.S)
    body = re.sub(r'"(id|duration|confidence)"\s*:\s*"[^"]*"', ' ', body)
    pt, en, cjk = len(PT_RE.findall(body)), len(EN_RE.findall(body)), len(CJK_RE.findall(body))
    if str(language or '').lower().startswith('en'):
        return {'pt': pt, 'en': en, 'cjk': cjk, 'ok': en >= 2 and en > 2 * pt and cjk == 0}
    return {'pt': pt, 'en': en, 'cjk': cjk, 'ok': pt >= 2 and pt > 2 * en and cjk == 0}


def summarize_result(sid, result, rec, sc, error, wall):
    """ the stored measurement of one scenario run """
    from ai import validate
    text = (result or {}).get('text') or ''
    doc = {'scenario': sid, 'subject': sc.get('subject'), 'language_requested': sc.get('language') or LANG,
           'error': error, 'wall_s': round(wall, 1), 'status': (result or {}).get('status')}
    if sc.get('post') and text:
        text = sc['post'](text)
    doc['text'] = text
    doc['attempts'] = (result or {}).get('attempts')
    doc['map_reduce'] = (result or {}).get('map_reduce')
    doc['context'] = (result or {}).get('context')
    doc['calls'] = rec.calls
    own = [c for c in rec.checks if c['task'] == sid]
    first = own[0]['problems'] if own else None
    final = (result or {}).get('problems')
    if final is None and own:
        final = own[-1]['problems']
    lang_words = ('not in ', 'Chinese')
    doc['problems_first'] = first
    doc['problems_final'] = final
    doc['fmt_first_ok'] = None if first is None else not [p for p in first if not any(w in p for w in lang_words)]
    doc['fmt_final_ok'] = None if final is None or error else not [p for p in final if not any(w in p for w in lang_words)]
    doc['lang_plugin_ok'] = None if final is None or error else not [p for p in final if any(w in p for w in lang_words)]
    doc['lang'] = lang_check(text, doc['language_requested']) if text else {'ok': False}
    doc['timeout'] = any(c.get('timeout') for c in rec.calls)
    doc['n_calls'] = len(rec.calls)
    doc['corrections'] = sum(1 for c in rec.calls if c.get('correction'))
    doc['parts'] = sum(1 for c in rec.calls if str(c.get('task') or '').endswith('_part'))
    doc['prompt_tokens'] = sum(c.get('prompt_tokens') or 0 for c in rec.calls) or None
    doc['gen_tokens'] = sum(c.get('gen_tokens') or 0 for c in rec.calls) or None
    main_calls = [c for c in rec.calls if c.get('task') == sid and not c.get('correction')]
    if main_calls:
        mc = main_calls[-1]
        doc['main_prompt_tokens'] = mc.get('prompt_tokens')
        doc['first_token_s'] = round((mc.get('load_s') or 0) + (mc.get('prompt_eval_s') or 0), 1)
    tps = [c['prompt_tps'] for c in rec.calls if c.get('prompt_tps')]
    gps = [c['gen_tps'] for c in rec.calls if c.get('gen_tps')]
    doc['prompt_tps'] = round(statistics.median(tps), 1) if tps else None
    doc['gen_tps'] = round(statistics.median(gps), 1) if gps else None
    doc['load_s'] = max([c.get('load_s') or 0 for c in rec.calls] or [0])
    doc['truncated'] = bool((result or {}).get('truncated')) or any(
        c.get('done_reason') == 'length' and c.get('task') == sid for c in rec.calls[-1:])
    doc['citations'] = len(validate.CITATION_RE.findall(text))
    doc['headings'] = len(validate.HEADING_RE.findall(text))
    doc['words'] = validate.words(text)
    if sid == 'incident_summary' and text and sc.get('ctx'):
        from incidents import triage
        p = triage.parse_answer(text, sc['ctx']['cands'])
        valid = {c['id'] for c in sc['ctx']['cands']}
        doc['incident'] = {'parsed': p['parsed'], 'actions': [a['id'] for a in p['actions']],
                           'confidence': p.get('confidence'), 'next_steps': len(p.get('next_steps') or [])}
        try:
            raw = json.loads(text[text.find('{'):text.rfind('}') + 1])
            doc['invalid_action_ids'] = [str(a.get('id')) for a in raw.get('actions') or []
                                         if isinstance(a, dict) and str(a.get('id')) not in valid]
            doc['json_valid'] = True
        except (ValueError, AttributeError):
            doc['json_valid'] = False
    if sid in ('vuln_review_suggest', 'explain_device'):
        first_line = text.strip().splitlines()[0] if text.strip() else ''
        doc['json_valid'] = bool(re.match(r'^(MAPPING|TYPE):\s*\S+', first_line))
    doc['evidence'] = evidence_check(text, '\n'.join(rec.prompts))
    doc['quality'] = quality(doc)
    doc['rubric'] = rubric(doc)
    return doc


# ------------------------------------------------------------------ step kinds (child process)


def step_scenario(st):
    params = st.get('params') or {}
    write_guard()
    overrides = {k: params[k] for k in ('num_ctx', 'num_predict', 'budget', 'timeout', 'retries', 'num_thread',
                                        'keep_alive') if k in params}
    routing, rec = isolate(st['model'], overrides, nomr=bool(params.get('nomr')), recorder=CURRENT)
    from ai import AIConfig
    cfg = AIConfig.from_opnsense('OPNsense/policyanalyzer')
    cfg.enabled = True
    sc = build_scenario(st['scenario'], int(st.get('variant') or 0), st['model'])
    if sc.get('skip'):
        return {'skipped': sc['skip'], 'scenario': st['scenario']}
    t0 = time.monotonic()
    result, error = {}, None
    try:
        result = sc['run'](cfg) or {}
        if result.get('status', 'ok') != 'ok':
            error = result.get('message') or result.get('status')
    except Exception as exc:          # noqa: BLE001
        error = '%s: %s' % (exc.__class__.__name__, exc)
    doc = summarize_result(st['scenario'], result, rec, sc, error, time.monotonic() - t0)
    doc['route'] = routing['scenarios'].get(st['scenario'])
    doc['data_tokens'] = sc.get('data_tokens')
    doc['blocked_writes'] = BLOCKED[:20]
    doc['models_loaded'] = loaded_models()
    return doc


def step_load(st):
    params = st.get('params') or {}
    threads, ctx = share()
    opts = {'num_ctx': int(params.get('num_ctx') or ctx), 'num_thread': int(params.get('num_thread') or threads)}
    before = loaded_models()
    t0 = time.monotonic()
    r = ollama('/api/generate', {'model': st['model'], 'keep_alive': params.get('keep_alive', '30m'), 'options': opts},
               timeout=1200)
    return {'wall_s': round(time.monotonic() - t0, 1), 'load_s': round((r.get('load_duration') or 0) / 1e9, 1),
            'num_ctx': opts['num_ctx'], 'before': before, 'after': loaded_models(), 'label': params.get('label')}


def step_unload(st):
    t0 = time.monotonic()
    if st.get('model'):
        ollama('/api/generate', {'model': st['model'], 'keep_alive': 0}, timeout=120)
    else:
        unload_all()
    return {'wall_s': round(time.monotonic() - t0, 1), 'after': loaded_models()}


def step_idle(st):
    unload_all()
    time.sleep(int((st.get('params') or {}).get('seconds') or IDLE_SECONDS))
    return {'idle_s': int((st.get('params') or {}).get('seconds') or IDLE_SECONDS)}


def _chat(model, prompt, num_predict=48, timeout=900):
    threads, ctx = share()
    body = {'model': model, 'messages': [{'role': 'user', 'content': prompt}], 'stream': False, 'think': False,
            'keep_alive': '30m', 'options': {'num_ctx': ctx, 'num_thread': threads, 'num_predict': num_predict,
                                             'temperature': 0.2}}
    t0 = time.monotonic()
    try:
        r = ollama('/api/chat', body, timeout=timeout)
        return {'ok': True, 'wall_s': round(time.monotonic() - t0, 1), 'gen_tokens': r.get('eval_count'),
                'prompt_tokens': r.get('prompt_eval_count')}
    except urllib.error.HTTPError as exc:
        return {'ok': False, 'wall_s': round(time.monotonic() - t0, 1), 'http': exc.code,
                'error': exc.read(300).decode(errors='replace')}
    except (OSError, ValueError) as exc:
        return {'ok': False, 'wall_s': round(time.monotonic() - t0, 1), 'error': str(exc)}


def step_concurrency(st):
    """ n simultaneous requests straight to Ollama (outside the plugin): serialization and max_queue """
    n = int((st.get('params') or {}).get('n') or 2)
    # the prompts of the resilience steps are evaluation data in Portuguese (see LANG)
    prompt = 'Em uma frase curta, em português: para que serve um firewall?'
    out = [None] * n
    t0 = time.monotonic()

    def worker(i):
        time.sleep(0.2 * i)
        r = _chat(st['model'], prompt)
        r['start_offset_s'] = round(0.2 * i, 1)
        out[i] = r
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return {'n': n, 'requests': out, 'wall_s': round(time.monotonic() - t0, 1)}


def step_short_timeout(st):
    """ a request with a 5 s timeout (the provider of the plugin), then how long a short request waits after it """
    from ai.providers import ProviderError
    from ai.providers.ollama import OllamaProvider
    prov = OllamaProvider({'location': 'local', 'model': st['model'], 'num_ctx': 8192, 'num_predict': 300},
                          timeout=int((st.get('params') or {}).get('timeout') or 5))
    # evaluation data in Portuguese (see LANG)
    filler = ' '.join('Linha %d do registro de teste: bloqueio de varredura na porta %d.' % (i, 1000 + i)
                      for i in range(120))
    t0 = time.monotonic()
    try:
        prov.chat([{'role': 'user', 'content': 'Resuma em português: ' + filler}])
        first = {'error': None}
    except ProviderError as exc:
        first = {'error': str(exc)}
    first['wall_s'] = round(time.monotonic() - t0, 1)
    after = _chat(st['model'], 'Responda só "ok".', num_predict=8)
    return {'timed_out_request': first, 'next_request': after}


def _configctl(args, timeout=1800):
    t0 = time.monotonic()
    proc = subprocess.run([CONFIGCTL] + list(args), capture_output=True, text=True, timeout=timeout)
    doc = None
    for line in reversed((proc.stdout or '').strip().splitlines()):
        if line.strip().startswith('{'):
            try:
                doc = json.loads(line)
                break
            except ValueError:
                continue
    return doc or {'status': 'error', 'message': (proc.stdout or proc.stderr or '')[-300:]}, time.monotonic() - t0


def step_queue(st):
    """ the production path: a read-only AI action through configctl, then the queue until it finishes """
    which = st.get('scenario')
    if which == 'anomaly_explain':
        from anomalies import common as acommon, engine as aengine
        row = _pick(aengine.Engine(acommon.Context()).search({}, ('severity', 'desc'), 1, 5).get('rows'), 0)
        if not row:
            return {'skipped': 'no anomaly finding'}
        args = ['pa_anomalies', 'explain', 'finding', str(row['id']), LANG, 'send']
    elif which == 'console_ask':
        payload = base64.urlsafe_b64encode(json.dumps({'q': QUESTIONS[0], 'lang': LANG}).encode()).decode().rstrip('=')
        args = ['pa_console', 'ask', payload, LANG, 'send']
    elif which == 'explain_finding':
        import explain as pa_explain
        report = pa_explain.load_report() or {}
        pref = [f for f in report.get('findings') or [] if f.get('type') in ('permissive', 'wan_exposed', 'shadowed')]
        f = _pick(pref or report.get('findings'), 0)
        if not f:
            return {'skipped': 'no finding'}
        args = ['policyanalyzer', 'explain', f['id'], LANG, 'send']
    else:
        return {'skipped': 'unsupported scenario for the queue round'}
    t0 = time.monotonic()
    first, enqueue_s = _configctl(args)
    out = {'action': ' '.join(args[:2]), 'enqueue_s': round(enqueue_s, 1), 'first_status': first.get('status'),
           'cached': first.get('cached'), 'route': first.get('route') or first.get('label'),
           'message': mask(first.get('message'), 160) if first.get('message') else None}
    if first.get('status') != 'queued':
        out.update(total_s=round(time.monotonic() - t0, 1), sync=True, attempts=first.get('attempts'),
                   text=mask(first.get('text'), 200))
        return out
    job = first.get('job') or {}
    out.update(job_id=job.get('id'), position=job.get('position'), eta_s=job.get('eta_seconds'), merged=job.get('merged'))
    deadline = time.monotonic() + MAX_STEP_SECONDS - 600
    final = {}
    while time.monotonic() < deadline:
        time.sleep(10)
        final, _s = _configctl(['policyanalyzer', 'ai_queue_job', str(job.get('id'))], timeout=60)
        jstat = (final.get('job') or final).get('status')
        if jstat in ('done', 'error', 'cancelled'):
            break
    jd = final.get('job') or final
    out.update(total_s=round(time.monotonic() - t0, 1), job_status=jd.get('status'),
               queue_s=(jd.get('started') - jd.get('created')) if jd.get('started') and jd.get('created') else None,
               run_s=(jd.get('finished') - jd.get('started')) if jd.get('finished') and jd.get('started') else None,
               attempts=jd.get('attempts'), format_ok=jd.get('format_ok'), lang_ok=jd.get('lang_ok'),
               cached_calls=jd.get('cached_calls'), calls=jd.get('calls'), model=jd.get('model_used') or jd.get('model'))
    if out.get('eta_s') and out.get('total_s'):
        out['eta_error_pct'] = round(100.0 * (out['eta_s'] - out['total_s']) / out['total_s'], 1)
    return out


def _evaluate():
    from ai import evaluate
    return evaluate


def _compute():
    from ai import compute
    return compute


def ollama_version():
    try:
        return (ollama('/api/version', timeout=5) or {}).get('version')
    except (OSError, ValueError, urllib.error.URLError):
        return None


def compute_now(version=None):
    """ the compute profile of a measurement taken now (ai/compute.py): machine + share of the jail + runtime """
    return _compute().profile(ollama_version=version or ollama_version(), ollama_url=OLLAMA_URL)


def compute_line(db, round_id, language=None):
    """ :return: the profile(s) the steps of a round ran with, as text for the e-mail; '' when none is recorded """
    comp = _compute()
    t = texts(language)
    lang = t['_lang']
    ids = [r[0] for r in db.execute('SELECT DISTINCT compute_id FROM steps WHERE round_id = ? AND compute_id IS NOT '
                                    'NULL ORDER BY compute_id', (round_id,))]
    docs = [d for d in (comp.get(db, i) for i in ids) if d]
    if not docs:
        return ''
    if len(docs) == 1:
        return t['compute_one'] % (docs[0]['id'], comp.label(docs[0], lang))
    return t['compute_many'] % (
        len(docs), '; '.join('#%d %s, num_ctx %s' % (d['id'], comp.short(d, lang), d.get('num_ctx') or '?')
                             for d in docs))


STEP_KINDS = {'scenario': step_scenario, 'load': step_load, 'unload': step_unload, 'idle': step_idle,
              'concurrency': step_concurrency, 'short_timeout': step_short_timeout, 'queue': step_queue,
              # per scenario evaluation (ai/evaluate.py)
              'pull': lambda st: _evaluate().step_pull(st), 'eval_setup': lambda st: _evaluate().step_setup(st),
              'eval': lambda st: _evaluate().step_eval(st)}


def cmd_step():
    st = json.loads(sys.stdin.read() or '{}')
    fn = STEP_KINDS.get(st.get('kind'))
    if fn is None:
        emit({'status': 'error', 'message': 'unknown step kind'})
        return 1
    try:
        emit({'status': 'ok', 'result': fn(st)})
    except Exception as exc:          # noqa: BLE001
        emit({'status': 'error', 'message': '%s: %s' % (exc.__class__.__name__, exc)})
    return 0


# ------------------------------------------------------------------ round expansion (runner)


def scenario_ids():
    from ai import scenarios as routing_mod
    return list(routing_mod.CATALOG)


def kind_of(sid):
    from ai import scenarios as routing_mod
    return (routing_mod.CATALOG.get(sid) or {}).get('kind', 'short')


def model_group(model, items, tag, load=True):
    steps = [{'kind': 'unload'}] if load else []
    if load:
        steps.append({'kind': 'load', 'model': model, 'params': {'label': 'cold'}})
    for sid, variant, params in items:
        p = dict(params or {})
        p['tag'] = tag
        steps.append({'kind': 'scenario', 'model': model, 'scenario': sid, 'variant': variant, 'params': p})
    steps.append({'kind': 'unload', 'model': model})
    return steps


def aggregate(rows):
    """ rows of one scenario × model -> summary used by the ranking and the report """
    res = [r['result'] for r in rows if not r['result'].get('skipped')]
    if not res:
        return None
    walls = [r.get('wall_s') or 0 for r in res]
    ok = [r for r in res if not r.get('error')]
    return {
        'n': len(res), 'ok': len(ok),
        'wall_p50': round(statistics.median(walls), 1), 'wall_max': round(max(walls), 1),
        'wall_p90': round(percentile(walls, 90), 1),
        'wall_sd': round(statistics.pstdev(walls), 1) if len(walls) > 1 else 0.0,
        'quality': round(statistics.mean(r.get('quality') or 0 for r in res), 2),
        'fmt_first': frac(r.get('fmt_first_ok') for r in res), 'fmt_final': frac(r.get('fmt_final_ok') for r in res),
        'lang': frac((r.get('lang') or {}).get('ok') for r in res),
        'timeouts': sum(1 for r in res if r.get('timeout')),
        'attempts': round(statistics.mean(r.get('attempts') or 1 for r in ok), 2) if ok else None,
        'prompt_tokens': avg(r.get('main_prompt_tokens') or r.get('prompt_tokens') for r in res),
        'gen_tokens': avg(r.get('gen_tokens') for r in res),
        'first_token_s': avg(r.get('first_token_s') for r in res),
        'parts': max([r.get('parts') or 0 for r in res] or [0]),
        'prompt_tps': avg(r.get('prompt_tps') for r in res), 'gen_tps': avg(r.get('gen_tps') for r in res),
        'truncated': sum(1 for r in res if r.get('truncated')),
    }


def percentile(values, pct):
    values = sorted(v for v in values if v is not None)
    if not values:
        return 0.0
    k = (len(values) - 1) * pct / 100.0
    lo, hi = int(math.floor(k)), int(math.ceil(k))
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def frac(values):
    values = [v for v in values if v is not None]
    return round(sum(1 for v in values if v) / float(len(values)), 2) if values else None


def avg(values):
    values = [v for v in values if v is not None]
    return round(statistics.mean(values), 1) if values else None


def time_limit(sid):
    from ai import scenarios as routing_mod
    meta = routing_mod.CATALOG.get(sid) or {}
    return 300 if meta.get('kind') == 'short' and not meta.get('background') else 1800


def serves(sid, agg):
    """ the criterion of the catalog: format and language >= 90 % after the correction, score >= 2, time """
    if not agg or not agg['ok']:
        return 'no'
    fails = 0
    if (agg['fmt_final'] if agg['fmt_final'] is not None else 1) < 0.9 or (agg['lang'] or 0) < 0.9:
        fails += 1
    if agg['quality'] < 2:
        fails += 1
    if agg['wall_p90'] > time_limit(sid) or agg['timeouts']:
        fails += 1
    return 'yes' if fails == 0 else ('partial' if fails == 1 else 'no')


def ranking(db, plan_id, rounds=('matrix', 'repeat')):
    """ :return: {scenario: [(model, agg, serves), ...] best first} """
    rows = [r for r in step_rows(db, plan_id) if r['round_name'] in rounds or r['imported']]
    groups = {}
    for r in rows:
        if r['model'] in (None, 'fable') or (r['params'] or {}).get('tag', 'matrix') not in ('matrix', 'repeat', 'import'):
            continue
        groups.setdefault(r['scenario'], {}).setdefault(r['model'], []).append(r)
    out = {}
    for sid, models in groups.items():
        items = []
        for model, mrows in models.items():
            agg = aggregate(mrows)
            if agg:
                items.append((model, agg, serves(sid, agg)))
        order = {'yes': 0, 'partial': 1, 'no': 2}
        items.sort(key=lambda x: (order[x[2]], -round(x[1]['quality'] * 2) / 2.0, x[1]['wall_p50']))
        out[sid] = items
    return out


def expand(db, plan, rnd):
    """ :return: the steps of a round, computed when the round starts (from what was measured before) """
    name = rnd['name']
    if name.startswith(EVAL_PREFIX):
        return _evaluate().expand_model(db, plan, rnd)
    models = bench_models()
    sids = scenario_ids()
    if name == 'baseline':
        return [{'kind': 'idle', 'params': {'seconds': IDLE_SECONDS}}]
    if name == 'matrix':
        steps = []
        for m in models:
            steps += model_group(m, [(s, 0, {}) for s in sids], 'matrix')
        return steps
    rank = ranking(db, plan['id'], ('matrix',))
    if name == 'repeat':
        per_model = {}
        for sid in sids:
            items = rank.get(sid) or []
            if items:
                per_model.setdefault(items[0][0], []).extend((sid, v, {}) for v in (0, 1, 2))
            if len(items) > 1:
                per_model.setdefault(items[1][0], []).extend((sid, v, {}) for v in (0, 1))
        steps = []
        for m in [x for x in models if x in per_model]:
            steps += model_group(m, per_model[m], 'repeat')
        return steps
    if name == 'params':
        heavy = []
        for sid, items in rank.items():
            if items:
                heavy.append((items[0][1]['wall_p50'], sid, items[0][0]))
        heavy = sorted(heavy, reverse=True)[:4]
        per_model = {}
        from ai import scenarios as routing_mod
        for _w, sid, model in heavy:
            base = routing_mod.LOCAL_SHORT_ROUTE if kind_of(sid) == 'short' else routing_mod.LOCAL_LONG_ROUTE
            variants = [{'num_ctx': 4096}, {'num_ctx': 16384},
                        {'num_predict': max(200, base['num_predict'] // 2)}, {'num_predict': base['num_predict'] * 2}]
            if (routing_mod.CATALOG.get(sid) or {}).get('mapreduce'):
                variants += [{'budget': 2000}, {'budget': 8000, 'num_ctx': 16384}, {'nomr': True, 'num_ctx': 16384}]
            per_model.setdefault(model, []).extend((sid, 0, v) for v in variants)
        steps = []
        for m in [x for x in models if x in per_model]:
            # same num_ctx together: a different num_ctx reloads the model
            items = sorted(per_model[m], key=lambda it: it[2].get('num_ctx', 8192))
            steps += model_group(m, items, 'params')
        return steps
    if name == 'switch':
        steps = []
        for m in models:
            steps += [{'kind': 'unload'}, {'kind': 'load', 'model': m, 'params': {'label': 'cold', 'num_ctx': 8192}},
                      {'kind': 'load', 'model': m, 'params': {'label': 'warm', 'num_ctx': 8192}},
                      {'kind': 'load', 'model': m, 'params': {'label': 'ctx16k', 'num_ctx': 16384}},
                      {'kind': 'load', 'model': m, 'params': {'label': 'ctx8k_back', 'num_ctx': 8192}}]
        for a, b in zip(models, models[1:] + models[:1]):
            if a != b:
                steps += [{'kind': 'load', 'model': a, 'params': {'label': 'switch_from_%s' % b}},
                          {'kind': 'load', 'model': b, 'params': {'label': 'switch_from_%s' % a}}]
        steps.append({'kind': 'unload'})
        return steps
    if name == 'threads':
        model = (rank.get('explain_cve') or [(models[0] if models else 'qwen2.5:3b',)])[0][0]
        steps = [{'kind': 'idle', 'params': {'seconds': IDLE_SECONDS}},
                 {'kind': 'load', 'model': model, 'params': {'label': 'threads'}}]
        for n in (1, 2, 3, 4):
            steps.append({'kind': 'scenario', 'model': model, 'scenario': 'explain_cve', 'variant': 0,
                          'params': {'tag': 'threads', 'num_thread': n}})
        steps.append({'kind': 'unload'})
        return steps
    if name == 'queue':
        steps = [{'kind': 'unload'}]
        for sid in ('explain_finding', 'anomaly_explain', 'console_ask'):
            steps += [{'kind': 'queue', 'scenario': sid, 'params': {'repeat': 1}},
                      {'kind': 'queue', 'scenario': sid, 'params': {'repeat': 2}}]
        steps.append({'kind': 'unload'})
        return steps
    if name == 'resilience':
        model = models[0] if models else 'qwen2.5:3b'
        return [{'kind': 'unload'}, {'kind': 'load', 'model': model, 'params': {'label': 'resilience'}},
                {'kind': 'concurrency', 'model': model, 'params': {'n': 2}},
                {'kind': 'concurrency', 'model': model, 'params': {'n': 4}},
                {'kind': 'short_timeout', 'model': model, 'params': {'timeout': 5}},
                {'kind': 'unload'}]
    return []          # quality: computed from the measurements (report)


# ------------------------------------------------------------------ e-mail


def send_mail(status, title, text, attachments=None):
    """ :param attachments: [(filename, bytes, mime)] """
    from reports import deliver, mailer, settings
    import html
    import socket
    # status codes OK / FALHA (failure) / INFO are shared with ai/evaluate.py and stored with the pending e-mails
    icon = {'OK': '✅', 'FALHA': '❌', 'INFO': 'ℹ️'}.get(status, '•')
    ch = deliver.channel(settings.load())
    t = texts()
    stamp = i18n.fmt_date(time.time(), t['_lang'])
    subject = t['mail_subject'] % (icon, title)
    body = '%s\n\n%s\n\n— %s · %s' % (title, text, t['mail_footer'], stamp)
    h = ('<p><b>%s %s</b></p><pre style="font:13px monospace">%s</pre><p style="color:#888">%s · %s</p>'
         % (icon, html.escape(title), html.escape(text), html.escape(t['mail_footer']), stamp))
    msg = mailer.build(subject, ch['sender'], ch['recipients'], body, h, hostname=socket.gethostname(),
                       attachments=attachments or None)
    mailer.send(msg, ch)


DONE_PREFIX = 'Done'                 # title of the final e-mail of a plan in older pending queues (now: "final")
MAIL_TRIES = 6                   # an e-mail with attachments (the PDF of a model) is kept and retried this often


class Mailer:
    """
    one e-mail at most every MAIL_INTERVAL; what arrives in between is merged into the next one (all the PDFs
    attached).  Attachments are FILE PATHS (the PDFs stay on disk): an entry with attachments whose sending fails
    goes back to the queue (MAIL_TRIES), so the PDF of a model is never lost.
    """

    def __init__(self, db, sender=None, clock=time.time):
        self.db = db
        self.sender = sender or send_mail
        self.clock = clock

    def queue(self, status, title, text, attachments=None, final=False):
        """ :param final: the last e-mail of a plan (its title is kept when e-mails are merged) """
        pending = meta_get(self.db, 'mail_pending', []) or []
        item = {'status': status, 'title': title, 'text': text}
        if final:
            item['final'] = True
        if attachments:
            item['attachments'] = list(attachments)
        pending.append(item)
        meta_set(self.db, 'mail_pending', pending)
        self.flush()

    @staticmethod
    def read_attachments(paths):
        out, missing = [], []
        for path in paths:
            try:
                with open(path, 'rb') as handle:
                    out.append((os.path.basename(path), handle.read(), 'application/pdf'))
            except OSError:
                missing.append(path)
        return out, missing

    def flush(self, force=False):
        pending = meta_get(self.db, 'mail_pending', []) or []
        if not pending:
            return False
        last = meta_get(self.db, 'mail_last', 0) or 0
        if not force and self.clock() - last < MAIL_INTERVAL:
            return False
        if len(pending) == 1:
            status, title, text = pending[0]['status'], pending[0]['title'], pending[0]['text']
        else:
            t = texts()
            status = 'FALHA' if any(p['status'] == 'FALHA' for p in pending) else pending[-1]['status']
            last_final = pending[-1].get('final') or pending[-1]['title'].startswith(DONE_PREFIX + ':')
            title = pending[-1]['title'] if last_final else \
                (t['merged'] % (len(pending), ', '.join(p['title'] for p in pending)))[:120]
            text = '\n\n'.join('%s %s\n%s' % (t['status'].get(p['status'], p['status']), p['title'], p['text'])
                                 for p in pending)
        paths = [p for item in pending for p in item.get('attachments') or []]
        meta_set(self.db, 'mail_pending', [])
        meta_set(self.db, 'mail_last', self.clock())
        try:
            if paths:
                files, missing = self.read_attachments(paths)
                if missing:
                    text += '\n\n' + texts()['pdf_missing'] % ', '.join(os.path.basename(m) for m in missing)
                self.sender(status, title, text, files)
            else:
                self.sender(status, title, text)
            event(self.db, 'mail', '%s %s%s' % (status, title, ' (%d attachment(s))' % len(paths) if paths else ''))
            return True
        except Exception as exc:          # noqa: BLE001 - the bench goes on without e-mail
            event(self.db, 'mail_error', '%s: %s' % (title, exc))
            keep = []
            for item in pending:
                if item.get('attachments') and item.get('tries', 0) + 1 < MAIL_TRIES:
                    keep.append(dict(item, tries=item.get('tries', 0) + 1))
            if keep:
                meta_set(self.db, 'mail_pending', keep + (meta_get(self.db, 'mail_pending', []) or []))
            return False


def round_summary(db, plan, rnd, language=None):
    """
    :return: (status, title, text) for the e-mail of a finished round (aggregates only, no addresses); an
             evaluation round returns (status, title, text, [pdf paths]) or None (model skipped: no e-mail)
    """
    if rnd['name'].startswith(EVAL_PREFIX):
        return _evaluate().round_summary(db, plan, rnd, language)
    t = texts(language)
    rows = db.execute('SELECT * FROM steps WHERE round_id = ?', (rnd['id'],)).fetchall()
    label = round_label(rnd['name'], t)
    scen = [r for r in rows if r['kind'] in ('scenario', 'queue')]
    done = [r for r in scen if r['status'] == 'done']
    failed = [r for r in scen if r['status'] in ('error', 'skipped')]
    res = [loads(r['result'], {}) for r in done]
    bad = [r for r in res if r.get('error') or r.get('timeout')]
    walls = [r.get('wall_s') or r.get('total_s') for r in res if (r.get('wall_s') or r.get('total_s'))]
    rt = t['round']
    lines = [rt['head'] % (plan['name'], rnd['idx'] + 1, len(PLANS[plan['name']]), label)]
    comp_line = compute_line(db, rnd['id'], t['_lang'])
    if comp_line:
        lines.append(comp_line)
    if scen:
        lines.append(rt['runs'] % (len(done), len(bad), len(failed)))
    if walls:
        lines.append(rt['median'] % (statistics.median(walls), max(walls)))
    scored = [(r.get('quality'), r.get('wall_s'), r.get('scenario')) for r in res if r.get('quality') is not None]
    if scored:
        best = max(scored, key=lambda x: (x[0], -(x[1] or 0)))
        worst = min(scored, key=lambda x: (x[0], -(x[1] or 0)))
        lines.append(rt['highlights'] % (best[2], best[0], best[1] or 0, worst[2], worst[0], worst[1] or 0))
    names = PLANS[plan['name']]
    nxt = names[rnd['idx'] + 1] if rnd['idx'] + 1 < len(names) else None
    lines.append(rt['next'] % (round_label(nxt, t) if nxt else rt['final_report']))
    status = 'FALHA' if scen and not done else 'OK'
    return status, rt['title'] % label, '\n'.join(lines)


# ------------------------------------------------------------------ runner


class Runner:
    def __init__(self, db_path=None):
        self.db_path = db_path or DB_PATH
        self.db = connect(self.db_path)
        self.stop = threading.Event()
        self.child = None
        self.current_step = None
        self.current_round = None
        self.mailer = Mailer(self.db)
        self.last_step_end = 0.0
        self.contention = None
        self.ollama_version = None

    def stamp_compute(self, step_id):
        """ every step carries the compute profile it ran with; a probe that fails never stops a measurement """
        try:
            self.ollama_version = ollama_version() or self.ollama_version
            comp = _compute()
            comp.stamp(self.db, step_id, comp.record(self.db, compute_now(self.ollama_version)))
        except Exception as exc:          # noqa: BLE001
            event(self.db, 'compute', 'step %d without a compute profile: %s' % (step_id, str(exc)[:200]))

    # sampling thread ---------------------------------------------------
    def sampler(self):
        db = connect(self.db_path)
        while not self.stop.is_set():
            try:
                d = sample()
                db.execute('INSERT INTO samples (ts, step_id, data) VALUES (?, ?, ?)',
                           (d['ts'], self.current_step, json.dumps(d)))
                db.execute('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)', ('heartbeat', json.dumps(
                    {'ts': d['ts'], 'pid': os.getpid(), 'step': self.current_step})))
                db.commit()
            except Exception as exc:          # noqa: BLE001
                try:
                    event(db, 'sample_error', str(exc))
                except sqlite3.Error:
                    pass
            self.stop.wait(SAMPLE_FAST if self.current_round == 'threads' else SAMPLE_SECONDS)
        db.close()

    def wait_ready(self, kind):
        """ wait while the firewall is under stress or production AI work is running; False when stopping """
        paused = None
        while not self.stop.is_set():
            reason = unsafe(recent_samples(self.db))
            if reason is None and kind != 'queue':
                # %CPU of ps is a decaying average: right after our own step it is still high
                reason = production_busy(check_cpu=time.monotonic() - self.last_step_end > 90)
            if reason is None:
                if paused:
                    event(self.db, 'resume', 'resumed after: %s' % paused)
                return True
            if reason != paused:
                event(self.db, 'pause', reason)
                paused = reason
            self.stop.wait(SAMPLE_SECONDS)
        return False

    def run_child(self, step):
        params = loads(step['params'], {})
        payload = json.dumps({'id': step['id'], 'kind': step['kind'], 'model': step['model'],
                              'scenario': step['scenario'], 'variant': step['variant'], 'params': params})
        timeout = MAX_STEP_SECONDS
        if step['kind'] in SCENARIO_KINDS:
            from ai import scenarios as routing_mod
            meta = routing_mod.CATALOG.get(step['scenario']) or {}
            per = int(params.get('timeout') or (600 if meta.get('kind') == 'short' else 1800))
            timeout = min(MAX_STEP_SECONDS, per * (2 + (16 if meta.get('mapreduce') else 0)) + 300)
        proc = subprocess.Popen([sys.executable, SCRIPT, 'step'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True, cwd='/',
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.child = proc
        killed = None
        try:
            proc.stdin.write(payload.encode())
            proc.stdin.close()
        except OSError:
            pass
        started = time.monotonic()
        last_check = 0.0
        self.contention = None
        while proc.poll() is None:
            if step['kind'] not in ('queue', 'pull') and time.monotonic() - last_check > CONTENTION_CHECK:
                last_check = time.monotonic()
                clients = ollama_clients((os.getpid(), proc.pid))
                if clients and self.contention is None:
                    self.contention = describe_clients(clients)
                    event(self.db, 'contention', 'step %d waits for Ollama, in use by %s' % (step['id'],
                                                                                          self.contention))
            if self.stop.is_set():
                killed = 'stopped'
            elif time.monotonic() - started > timeout:
                killed = 'step timeout after %d s' % timeout
            elif step['kind'] in SCENARIO_KINDS and unsafe(recent_samples(self.db)):
                killed = 'unsafe: %s' % unsafe(recent_samples(self.db))
            if killed:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    time.sleep(2)
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                break
            time.sleep(2)
        out = proc.stdout.read() if proc.stdout else b''
        err = proc.stderr.read() if proc.stderr else b''
        proc.wait()
        self.child = None
        if killed:
            return None, killed
        doc = None
        for line in reversed(out.decode('utf-8', 'replace').strip().splitlines()):
            if line.startswith('{'):
                try:
                    doc = json.loads(line)
                    break
                except ValueError:
                    continue
        if doc is None:
            return None, (err.decode('utf-8', 'replace')[-500:] or 'no result')
        if doc.get('status') != 'ok':
            return None, doc.get('message')
        return doc['result'], None

    def eval_round(self, step):
        row = self.db.execute('SELECT name FROM rounds WHERE id = ?', (step['round_id'],)).fetchone()
        return bool(row and row['name'].startswith(EVAL_PREFIX))

    def execute(self, step):
        in_eval = self.eval_round(step)
        if in_eval:
            reason = _evaluate().should_skip(self.db, step)
            if reason:
                self.db.execute("UPDATE steps SET status = 'skipped', finished = ?, error = ? WHERE id = ?",
                                (now(), reason, step['id']))
                self.db.commit()
                event(self.db, 'eval', 'step %d (%s %s) skipped: %s' % (step['id'], step['kind'], step['scenario'] or
                                                                       step['model'] or '-', reason))
                return
        self.current_step = step['id']
        self.db.execute("UPDATE steps SET status = 'running', started = ?, runs = runs + 1 WHERE id = ?",
                        (now(), step['id']))
        self.db.commit()
        self.stamp_compute(step['id'])
        result, error = self.run_child(step)
        label = 'step %d (%s %s %s)' % (step['id'], step['kind'], step['model'] or '-', step['scenario'] or '-')
        runs = (step['runs'] or 0) + 1
        if not error and isinstance(result, dict) and result.get('error') and \
                transient_error(result['error'], bool(self.contention)):
            error = str(result['error'])        # a scenario that "ran" against a busy Ollama: not a result
        if error == 'stopped':
            self.db.execute("UPDATE steps SET status = 'pending' WHERE id = ?", (step['id'],))
        elif error and error.startswith('unsafe') and step['runs'] < 2:
            event(self.db, 'step_aborted', 'step %d: %s' % (step['id'], error))
            self.db.execute("UPDATE steps SET status = 'pending', error = ? WHERE id = ?", (error, step['id']))
        elif error and transient_error(error, bool(self.contention)) and runs < MAX_STEP_RUNS:
            # it waited behind another Ollama client (a report from cron): not a result, run it again later
            event(self.db, 'step_retry', '%s: %s; Ollama was in use by %s' % (label, str(error)[:300],
                                                                             self.contention))
            self.db.execute("UPDATE steps SET status = 'pending', error = ? WHERE id = ?",
                            (str(error)[:1000], step['id']))
        elif error:
            event(self.db, 'step_error', '%s: %s' % (label, str(error)[:500]))
            self.db.execute("UPDATE steps SET status = 'error', finished = ?, error = ? WHERE id = ?",
                            (now(), str(error)[:1000], step['id']))
        else:
            status = 'skipped' if result.get('skipped') else 'done'
            self.db.execute('UPDATE steps SET status = ?, finished = ?, result = ?, error = ? WHERE id = ?',
                            (status, now(), json.dumps(result, ensure_ascii=False, default=str),
                             result.get('skipped'), step['id']))
            self.db.commit()
            if in_eval:
                try:
                    _evaluate().on_step_done(self.db, step, result)
                except Exception as exc:          # noqa: BLE001 - the measurement is stored; scoring can be redone
                    event(self.db, 'eval_error', 'step %d: %s: %s' % (step['id'], exc.__class__.__name__, exc))
        self.db.commit()
        self.current_step = None
        self.last_step_end = time.monotonic()

    def loop(self):
        """ one iteration per step; an unexpected error is an event, the step is marked and the loop goes on """
        failures = 0
        while not self.stop.is_set():
            try:
                if self.iterate() is False:
                    return None
                failures = 0
            except Exception as exc:          # noqa: BLE001 - the plan must survive one bad step
                failures += 1
                tail = traceback.format_exc(limit=4)[-1500:]
                step_id = self.current_step
                event(self.db, 'runner_error', '%s: %s%s\n%s' % (
                    exc.__class__.__name__, exc, ' (step %d)' % step_id if step_id else '', tail))
                try:
                    self.db.rollback()
                    if step_id:
                        self.db.execute("UPDATE steps SET status = 'error', finished = ?, error = ? WHERE id = ?",
                                        (now(), ('runner: %s: %s' % (exc.__class__.__name__, exc))[:1000], step_id))
                        self.db.commit()
                except sqlite3.Error:
                    pass
                self.current_step = None
                if self.child is not None:
                    try:
                        os.killpg(self.child.pid, signal.SIGKILL)
                    except OSError:
                        pass
                    self.child = None
                if failures >= MAX_LOOP_ERRORS:
                    raise
                self.stop.wait(SAMPLE_SECONDS)
        return None

    def iterate(self):
        """ :return: False when there is nothing left to do or the runner is stopping, True otherwise """
        self.mailer.flush()
        plan = self.db.execute("SELECT * FROM plans WHERE status IN ('queued', 'running') AND imported = 0 "
                               "AND stop_requested = 0 ORDER BY id LIMIT 1").fetchone()
        if plan is None:
            return False
        if plan['status'] == 'queued':
            self.db.execute("UPDATE plans SET status = 'running', started = COALESCE(started, ?) WHERE id = ?",
                            (now(), plan['id']))
            self.db.commit()
            event(self.db, 'plan', 'plan %s started' % plan['name'])
            if plan['name'] == EVAL_PLAN:
                try:
                    self.mailer.queue(*_evaluate().start_mail(self.db, plan))
                except Exception as exc:          # noqa: BLE001
                    event(self.db, 'eval_error', 'start e-mail: %s' % exc)
        rnd = self.db.execute("SELECT * FROM rounds WHERE plan_id = ? AND status != 'done' ORDER BY idx LIMIT 1",
                              (plan['id'],)).fetchone()
        if rnd is None:
            self.finish(plan)
            return True
        self.current_round = rnd['name']
        if rnd['status'] == 'pending':
            add_steps(self.db, rnd['id'], expand(self.db, plan, rnd))
            self.db.execute("UPDATE rounds SET status = 'running', started = ? WHERE id = ?", (now(), rnd['id']))
            self.db.commit()
            event(self.db, 'round', 'round %s started' % rnd['name'])
        step = self.db.execute("SELECT * FROM steps WHERE round_id = ? AND status = 'pending' ORDER BY seq LIMIT 1",
                               (rnd['id'],)).fetchone()
        if step is None:
            summary = round_summary(self.db, plan, rnd)
            self.db.execute("UPDATE rounds SET status = 'done', finished = ?, summary = ? WHERE id = ?",
                            (now(), json.dumps(summary), rnd['id']))
            self.db.commit()
            if summary:
                self.mailer.queue(*summary)
            return True
        if not self.wait_ready(step['kind']):
            return False
        self.execute(step)
        return True

    def finish(self, plan):
        unload_all()
        self.db.execute("UPDATE plans SET status = 'done', finished = ? WHERE id = ?", (now(), plan['id']))
        self.db.commit()
        attachments = []
        if plan['name'] == EVAL_PLAN:
            lines, attachments = _evaluate().final_mail(self.db, plan)
        else:
            lines = executive_summary(self.db, plan['id'])
        self.db.execute('UPDATE plans SET summary = ? WHERE id = ?', (json.dumps(lines), plan['id']))
        self.db.commit()
        event(self.db, 'plan', 'plan %s finished' % plan['name'])
        last = meta_get(self.db, 'mail_last', 0) or 0
        wait = MAIL_INTERVAL - (time.time() - last)
        if wait > 0:
            self.stop.wait(wait)
        self.mailer.queue('OK', texts()['done_title'] % plan['name'], '\n'.join(lines), attachments, final=True)
        self.mailer.flush(force=True)

    def run(self):
        os.makedirs(RUN_DIR, exist_ok=True)
        fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return {'status': 'busy'}
        with open(PID_FILE, 'w') as handle:
            handle.write('%d\n' % os.getpid())

        def on_term(_sig, _frame):
            self.stop.set()
        signal.signal(signal.SIGTERM, on_term)
        signal.signal(signal.SIGINT, on_term)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)       # the end of the ssh session that started it
        self.db.execute("UPDATE steps SET status = 'pending' WHERE status = 'running'")
        self.db.commit()
        event(self.db, 'runner', 'runner started (pid %d)' % os.getpid())
        sampler = threading.Thread(target=self.sampler, daemon=True)
        sampler.start()
        reason = 'end'
        try:
            self.loop()
            reason = 'stopped' if self.stop.is_set() else 'nothing to do'
        except BaseException as exc:      # noqa: BLE001 - also SystemExit/KeyboardInterrupt: always an event
            reason = 'error: %s: %s' % (exc.__class__.__name__, exc)
            try:
                event(self.db, 'runner_error', '%s\n%s' % (reason, traceback.format_exc(limit=6)[-1500:]))
                t = texts()
                self.mailer.queue('FALHA', t['interrupted'], t['interrupted_text'] % reason)
                self.mailer.flush(force=True)
            except Exception:             # noqa: BLE001
                pass
        finally:
            self.stop.set()
            if self.child is not None:
                try:
                    os.killpg(self.child.pid, signal.SIGKILL)
                except OSError:
                    pass
            self.db.execute("UPDATE steps SET status = 'pending' WHERE status = 'running'")
            self.db.commit()
            try:
                event(self.db, 'runner', 'runner finished (pid %d): %s' % (os.getpid(), reason))
            except sqlite3.Error:
                pass
            unload_all()
            try:
                os.unlink(PID_FILE)
            except OSError:
                pass
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        return {'status': 'ok'}


def runner_pid():
    try:
        with open(PID_FILE) as handle:
            pid = int(handle.read().strip())
        os.kill(pid, 0)
        return pid if _locked(LOCK_FILE) else None
    except (OSError, ValueError):
        return None


def spawn_runner():
    if runner_pid():
        return False
    subprocess.Popen(['/usr/bin/nice', '-n', '10', sys.executable, SCRIPT, 'run'], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                     cwd='/', env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    return True


# ------------------------------------------------------------------ commands


def cmd_start(name, db=None, retry=False, tokens=None):
    """
    :param retry: the failed steps of the unfinished rounds of the resumed plan go back to pending
    :param tokens: options of a new "avaliacao" plan (reps=N, only=a,b, reeval, w_eff=x)
    """
    db = db or connect()
    if name not in PLANS:
        return {'status': 'error', 'message': 'unknown plan "%s" (use: %s)' % (name, ', '.join(PLANS))}
    plan = active_plan(db)
    if plan is not None and plan['name'] != name:
        return {'status': 'error', 'message': 'plan "%s" (#%d) is unfinished: stop it and start it again to resume, '
                                              'or wait for it to finish' % (plan['name'], plan['id'])}
    if plan is None:
        try:
            plan_id = create_plan(db, name, tokens)
        except ValueError as exc:
            return {'status': 'error', 'message': str(exc)}
        resumed = False
    else:
        plan_id = plan['id']
        db.execute("UPDATE plans SET stop_requested = 0, status = CASE WHEN started IS NULL THEN 'queued' ELSE "
                   "'running' END WHERE id = ?", (plan_id,))
        db.commit()
        resumed = True
    retried = 0
    if retry:
        # every round of the plan, finished ones included: a round closed while Ollama refused its steps (503 with
        # the queue full) holds invalid numbers, so it reopens and runs again before the rounds after it
        plan_rounds = "(SELECT id FROM rounds WHERE plan_id = ?)"
        reopen = {r['round_id'] for r in db.execute("SELECT DISTINCT round_id FROM steps WHERE status = 'error' AND "
                                                    "round_id IN " + plan_rounds, (plan_id,))}
        retried = db.execute("UPDATE steps SET status = 'pending', error = NULL WHERE status = 'error' AND round_id IN "
                             + plan_rounds, (plan_id,)).rowcount
        # steps recorded as "done" although Ollama refused them (503 while the queue was full) or timed out
        for row in db.execute("SELECT id, round_id, result FROM steps WHERE status = 'done' AND kind IN "
                              "('scenario', 'eval') AND round_id IN " + plan_rounds, (plan_id,)).fetchall():
            if transient_error((loads(row['result'], {}) or {}).get('error'), contention=True):
                db.execute("UPDATE steps SET status = 'pending', result = NULL, error = NULL WHERE id = ?",
                           (row['id'],))
                reopen.add(row['round_id'])
                retried += 1
        for round_id in reopen:
            db.execute("UPDATE rounds SET status = 'running', finished = NULL WHERE id = ? AND status = 'done'",
                       (round_id,))
        db.commit()
        if retried:
            event(db, 'plan', '%d step(s) with an error run again' % retried)
    started = spawn_runner()
    return {'status': 'ok', 'plan': plan_id, 'name': name, 'resumed': resumed, 'runner_started': started,
            'runner_pid': runner_pid(), 'retried': retried}


def cmd_stop(db=None):
    db = db or connect()
    plan = active_plan(db)
    if plan is not None:
        db.execute("UPDATE plans SET stop_requested = 1, status = 'stopped' WHERE id = ?", (plan['id'],))
        db.commit()
        event(db, 'plan', 'plan %s stopped by hand' % plan['name'])
    pid = runner_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    else:
        unload_all()
    return {'status': 'ok', 'plan': plan['id'] if plan else None, 'signalled': bool(pid)}


def cmd_kick(db=None):
    """ cron / after a reboot: resume an unfinished plan that was not stopped by hand """
    db = db or connect()
    plan = db.execute("SELECT * FROM plans WHERE status IN ('queued', 'running') AND stop_requested = 0 "
                      "AND imported = 0 ORDER BY id LIMIT 1").fetchone()
    if plan is None:
        return {'status': 'ok', 'started': False, 'message': 'nothing to resume'}
    return {'status': 'ok', 'started': spawn_runner(), 'plan': plan['id']}


def cmd_status(db=None):
    db = db or connect()
    plan = db.execute('SELECT * FROM plans WHERE imported = 0 ORDER BY id DESC LIMIT 1').fetchone()
    out = {'status': 'ok', 'runner_pid': runner_pid(), 'plan': None, 'rounds': [], 'events': []}
    if plan is not None:
        out['plan'] = {k: plan[k] for k in ('id', 'name', 'status', 'created', 'started', 'finished', 'stop_requested')}
        for r in db.execute('SELECT * FROM rounds WHERE plan_id = ? ORDER BY idx', (plan['id'],)):
            counts = {row['status']: row['n'] for row in
                      db.execute('SELECT status, COUNT(*) AS n FROM steps WHERE round_id = ? GROUP BY status', (r['id'],))}
            out['rounds'].append({'name': r['name'], 'status': r['status'], 'steps': counts,
                                  'started': r['started'], 'finished': r['finished']})
        cur = db.execute("SELECT s.id, s.kind, s.model, s.scenario, s.variant, s.started FROM steps s JOIN rounds r "
                         "ON r.id = s.round_id WHERE r.plan_id = ? AND s.status = 'running'", (plan['id'],)).fetchone()
        out['current'] = dict(cur) if cur else None
    last = db.execute('SELECT data FROM samples ORDER BY id DESC LIMIT 1').fetchone()
    if last:
        s = loads(last['data'], {})
        out['last_sample'] = {k: s.get(k) for k in ('ts', 'load', 'temp_max', 'cpu', 'mem_free_gib', 'ollama_cpu',
                                                    'models', 'wan', 'ping', 'suricata')}
    out['events'] = [dict(e) for e in db.execute('SELECT ts, kind, message FROM events ORDER BY id DESC LIMIT 12')]
    beat = meta_get(db, 'heartbeat') or {}
    if beat:
        out['heartbeat'] = dict(beat, age_s=now() - int(beat.get('ts') or 0))
    out['production_busy'] = production_busy()
    if plan is not None and plan['name'] == EVAL_PLAN:
        try:
            ev = _evaluate().cmd_status(db)
            out['evaluation'] = {'models': ev['models'], 'best': ev['best'], 'discarded': ev['discarded']}
        except Exception as exc:          # noqa: BLE001
            out['evaluation'] = {'error': str(exc)}
    return out


# ------------------------------------------------------------------ import of earlier measurements


def import_jsonl(path, label=None, db=None):
    """ lines of the scratchpad harness (bench3.py: one per scenario; bench.py: also Fable) -> an imported plan """
    db = db or connect()
    cur = db.execute("INSERT INTO plans (name, status, created, started, finished, imported, label) "
                     "VALUES ('import', 'done', ?, ?, ?, 1, ?)", (now(), now(), now(), label or os.path.basename(path)))
    plan_id = cur.lastrowid
    rid = db.execute("INSERT INTO rounds (plan_id, idx, name, status, finished) VALUES (?, 0, 'import', 'done', ?)",
                     (plan_id, now())).lastrowid
    n = 0
    with open(path) as handle:
        for line in handle:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if 'scenario' not in d or d.get('dry'):
                continue
            model = d.get('model_name') or d.get('model')
            if d.get('model') == 'fable':
                model = 'fable'
            fmt = d.get('format') or {}
            doc = dict(d)
            doc.pop('messages', None)
            doc.setdefault('fmt_final_ok', d.get('fmt_final_ok', fmt.get('ok')))
            doc.setdefault('fmt_first_ok', d.get('fmt_first_ok', fmt.get('ok')))
            if 'json_parsed' in fmt and 'incident' not in doc:
                doc['incident'] = {'parsed': fmt['json_parsed'], 'actions': fmt.get('actions') or []}
                doc['invalid_action_ids'] = fmt.get('invalid_action_ids') or []
            if 'evidence' not in doc:
                prompt = '\n'.join(m.get('content', '') for m in d.get('messages') or [])
                doc['evidence'] = evidence_check(d.get('text'), prompt) if prompt else {}
            doc['quality'] = quality(doc)
            doc['rubric'] = rubric(doc)
            tag = 'reference' if model == 'fable' else 'import'
            db.execute("INSERT INTO steps (round_id, seq, kind, model, scenario, variant, params, status, runs, "
                       "finished, result) VALUES (?, ?, 'scenario', ?, ?, ?, ?, 'done', 1, ?, ?)",
                       (rid, n + 1, model, d['scenario'], int(d.get('variant') or 0), json.dumps({'tag': tag}), now(),
                        json.dumps(doc, ensure_ascii=False, default=str)))
            n += 1
    db.commit()
    return {'status': 'ok', 'plan': plan_id, 'imported': n}


# ------------------------------------------------------------------ report


def fmt_num(v, nd=0, dash='—'):
    if v is None:
        return dash
    if isinstance(v, float) and nd == 0:
        return '%.0f' % v
    return ('%.' + str(nd) + 'f') % v if isinstance(v, (int, float)) else str(v)


def pct(v):
    return '—' if v is None else '%d %%' % round(100 * v)


def recommend(db, plan_id, language=None):
    """ :return: {scenario: {model, alt, mode, timeout, num_predict, budget, why, serves}} """
    from ai import scenarios as routing_mod
    t = texts(language)['recommend']
    rank = ranking(db, plan_id)
    out = {}
    for sid in routing_mod.CATALOG:
        items = rank.get(sid) or []
        meta = routing_mod.CATALOG[sid]
        base = routing_mod.LOCAL_SHORT_ROUTE if meta['kind'] == 'short' else routing_mod.LOCAL_LONG_ROUTE
        if not items:
            out[sid] = {'model': None, 'serves': 'not measured', 'why': t['none']}
            continue
        model, agg, srv = items[0]
        alt = items[1][0] if len(items) > 1 else None
        if srv == 'no':
            out[sid] = {'model': 'claudecode/fable', 'alt': model, 'mode': 'sync', 'timeout': 300, 'serves': srv,
                        'why': t['bridge'] % (model, agg['quality'])}
            continue
        if meta.get('background'):
            mode = 'sync'
        elif agg['wall_p90'] <= 300:
            mode = 'sync'
        else:
            mode = 'queue'
        timeout = int(min(1800, max(120, math.ceil(agg['wall_p90'] * 2 / 60.0) * 60)))
        num_predict = base['num_predict']
        if agg['truncated']:
            num_predict = min(2400, num_predict * 2)
        out[sid] = {'model': model, 'alt': alt, 'mode': mode, 'timeout': timeout, 'num_predict': num_predict,
                    'budget': base['budget'], 'serves': srv,
                    'why': t['why'] % (agg['quality'], agg['wall_p50'], pct(agg['fmt_final']), pct(agg['lang']))}
    return out


def model_costs(db, plan_id):
    out = {}
    for r in step_rows(db, plan_id, kind='load'):
        res = r['result']
        label = (r['params'] or {}).get('label') or res.get('label') or 'load'
        c = out.setdefault(r['model'], {'cold': [], 'warm': [], 'ctx16k': [], 'ctx8k_back': [], 'switch': [], 'ram': []})
        key = 'switch' if label.startswith('switch_from') else (label if label in c else 'cold')
        c[key].append(res.get('wall_s'))
        for m in res.get('after') or []:
            if m.get('name') == r['model'] and m.get('size_gib'):
                c['ram'].append(m['size_gib'])
    for r in step_rows(db, plan_id):
        res = r['result']
        c = out.setdefault(r['model'], {'cold': [], 'warm': [], 'ctx16k': [], 'ctx8k_back': [], 'switch': [], 'ram': []})
        c.setdefault('ptps', []).extend(x['prompt_tps'] for x in res.get('calls') or [] if x.get('prompt_tps'))
        c.setdefault('gtps', []).extend(x['gen_tps'] for x in res.get('calls') or [] if x.get('gen_tps'))
    return out


def impact(db, plan_id):
    """ host samples grouped: idle (baseline) vs inference per model and per num_thread """
    plan_rounds = {r['id']: r['name'] for r in db.execute('SELECT id, name FROM rounds WHERE plan_id = ?', (plan_id,))}
    steps = {}
    for r in db.execute('SELECT s.id, s.kind, s.model, s.params, s.round_id FROM steps s JOIN rounds r ON r.id = '
                        's.round_id WHERE r.plan_id = ?', (plan_id,)):
        p = loads(r['params'], {})
        if r['kind'] == 'idle':
            key = 'idle (no model)'
        elif r['kind'] == 'scenario' and plan_rounds.get(r['round_id']) == 'threads':
            key = 'num_thread %s (%s)' % (p.get('num_thread'), r['model'])
        elif r['kind'] == 'scenario':
            key = 'inference %s' % r['model']
        else:
            continue
        steps[r['id']] = key
    groups = {}
    for row in db.execute('SELECT step_id, data FROM samples WHERE step_id IS NOT NULL'):
        key = steps.get(row['step_id'])
        if key:
            groups.setdefault(key, []).append(loads(row['data'], {}))
    out = {}
    for key, ss in groups.items():
        def vals(fn):
            res = []
            for s in ss:
                try:
                    v = fn(s)
                except (KeyError, TypeError, IndexError):
                    v = None
                if v is not None:
                    res.append(v)
            return res
        load = vals(lambda s: s['load'][0])
        idle = vals(lambda s: s['cpu']['idle'])
        temp = vals(lambda s: s['temp_max'])
        rtt = vals(lambda s: s['wan']['delay_ms'])
        loss = vals(lambda s: s['wan']['loss'])
        ping = vals(lambda s: s['ping']['avg'])
        pmax = vals(lambda s: s['ping']['max'])
        drops = vals(lambda s: s['suricata']['capture.kernel_drops'])
        free = vals(lambda s: s['mem_free_gib'])
        out[key] = {'samples': len(ss), 'load_p50': percentile(load, 50), 'load_max': max(load) if load else None,
                    'cpu_busy_p50': (100 - percentile(idle, 50)) if idle else None,
                    'temp_max': max(temp) if temp else None, 'rtt_p50': percentile(rtt, 50) if rtt else None,
                    'rtt_max': max(rtt) if rtt else None, 'loss_max': max(loss) if loss else None,
                    'ping_p50': percentile(ping, 50) if ping else None, 'ping_max': max(pmax) if pmax else None,
                    'suricata_drops_delta': (max(drops) - min(drops)) if drops else None,
                    'mem_free_min': min(free) if free else None}
    return out


def executive_summary(db, plan_id, language=None):
    t = texts(language)
    e = t['executive']
    rec = recommend(db, plan_id, t['_lang'])
    costs = model_costs(db, plan_id)
    imp = impact(db, plan_id)
    models = {}
    for sid, r in rec.items():
        if r.get('model'):
            models.setdefault(r['model'], []).append(sid)
    local = {m: s for m, s in models.items() if not m.startswith('claudecode')}
    bridge = models.get('claudecode/fable') or []
    lines = []
    lines.append(e['preset'] % (e['hybrid'] if bridge else e['local_only']))
    lines.append(e['models'] % (', '.join(e['model_item'] % (m, len(s)) for m, s in
                                          sorted(local.items(), key=lambda x: -len(x[1]))) or '—'))
    ram = {m: max(c['ram']) for m, c in costs.items() if c.get('ram')}
    total = sum(ram.get(m, 0) for m in local)
    lines.append(e['resident'] % (
        e['one_model'] if len(local) <= 1 or total > 20 else e['two_models'],
        ', '.join('%s %.1f GiB' % (m, v) for m, v in ram.items()) or '—', total))
    cold = {m: max(c['cold']) for m, c in costs.items() if c.get('cold') and all(x is not None for x in c['cold'])}
    lines.append(e['cold'] % (', '.join('%s %.0f s' % (m, v) for m, v in cold.items()) or '—'))
    inf = [v for k, v in imp.items() if k.startswith('inference')]
    idle = imp.get('idle (no model)') or {}
    if inf:
        lines.append(e['impact'] % (
                         max(v['load_max'] or 0 for v in inf), fmt_num(max((v['rtt_max'] or 0) for v in inf), 1),
                         fmt_num(idle.get('rtt_p50'), 1), fmt_num(max((v['loss_max'] or 0) for v in inf), 1),
                         fmt_num(sum((v['suricata_drops_delta'] or 0) for v in inf))))
    else:
        lines.append(e['impact_none'])
    th = sorted((k, v) for k, v in imp.items() if k.startswith('num_thread'))
    comp = plan_compute(db, plan_id)
    limit = load_max(comp.get('jail_threads'), comp.get('cores'))
    safe = [k.split()[1] for k, v in th if (v['load_max'] or 0) <= limit and (v['rtt_max'] or 0) <= RTT_MAX]
    lines.append(e['threads'] % (
        max(safe) if safe else e['not_measured'] % (comp.get('jail_threads') or DEFAULT_THREADS),
        comp.get('jail_cores') or DEFAULT_THREADS, limit))
    lines.append(e['bridge'] % (', '.join(bridge) or e['none']))
    queued = [s for s, r in rec.items() if r.get('mode') == 'queue']
    lines.append(e['queued'] % (', '.join(queued) or e['none']))
    partial = [s for s, r in rec.items() if r.get('serves') == 'partial']
    lines.append(e['partial'] % (', '.join(partial) or e['none']))
    lines.append(e['risks'])
    return lines


def report_md(db=None, language=None):
    db = db or connect()
    t = texts(language, 'bench_md')
    lang = t['_lang']
    tb = texts(lang)
    sv = t['serves']
    plan = db.execute("SELECT * FROM plans WHERE imported = 0 AND status != 'queued' ORDER BY "
                      "(status = 'done') DESC, id DESC LIMIT 1").fetchone()
    plan_id = plan['id'] if plan else -1
    from ai import scenarios as routing_mod
    rows = step_rows(db, plan_id)
    L = []
    L.append(t['title'])
    L.append('')
    L.append(t['intro'] % (iso(), plan['name'] if plan else '—', plan_id,
                           t['status'].get(plan['status'], plan['status']) if plan else '—'))
    L.append('')
    summary = loads(plan['summary'], None) if plan else None
    L.append(t['executive'])
    L.append('')
    for line in summary or executive_summary(db, plan_id, lang):
        L.append(line)
    L.append('')
    L.append(t['compute'])
    L.append('')
    L.extend(_compute().report_lines(db, lambda ts: iso(ts) if ts else '—', lang))
    L.append(t['rounds'])
    L.append('')
    L.append(t['rounds_head'])
    L.append('|---|---|---|---|---|---|')
    for r in db.execute('SELECT * FROM rounds WHERE plan_id = ? ORDER BY idx', (plan_id,)):
        c = {x['status']: x['n'] for x in db.execute('SELECT status, COUNT(*) AS n FROM steps WHERE round_id = ? '
                                                       'GROUP BY status', (r['id'],))}
        L.append('| R%d | %s | %s | %s | %s | %d/%d/%d |' % (
            r['idx'] + 1, round_label(r['name'], tb), t['status'].get(r['status'], r['status']), iso(r['started']) if r['started'] else '—',
            iso(r['finished']) if r['finished'] else '—', c.get('done', 0), c.get('error', 0), c.get('skipped', 0)))
    L.append('')
    L.append(t['results'])
    L.append('')
    L.append(t['results_note'])
    L.append('')
    L.append(t['results_head'])
    L.append('|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|')
    rank = ranking(db, plan_id)
    for sid in routing_mod.CATALOG:
        for model, agg, srv in rank.get(sid) or []:
            L.append('| %s | %s | %d | %s/%s | %s / %s | %s | %s / %s | %s | %s | %s | %d | %.1f | %s |' % (
                sid, model, agg['n'], fmt_num(agg['prompt_tokens']), fmt_num(agg['gen_tokens']), fmt_num(agg['wall_p50']),
                fmt_num(agg['wall_max']), fmt_num(agg['first_token_s']), pct(agg['fmt_first']), pct(agg['fmt_final']),
                pct(agg['lang']), fmt_num(agg['attempts'], 1), agg['parts'] or '—', agg['timeouts'], agg['quality'],
                sv.get(srv, srv)))
        if not rank.get(sid):
            L.append('| %s | — | 0 | — | — | — | — | — | — | — | — | — | %s |' % (sid, sv['not measured']))
    L.append('')
    L.append(t['serves_note'])
    L.append('')
    L.append(t['quality_note'])
    L.append('')
    L.append(t['json'])
    L.append('')
    L.append(t['json_head'])
    L.append('|---|---|---:|---:|---:|---:|')
    for sid in ('incident_summary', 'vuln_review_suggest', 'explain_device'):
        by = {}
        for r in rows:
            if r['scenario'] == sid and r['model'] != 'fable' and not r['result'].get('skipped'):
                by.setdefault(r['model'], []).append(r['result'])
        for model, res in sorted(by.items()):
            L.append('| %s | %s | %d | %s | %s | %d |' % (
                sid, model, len(res), pct(frac(x.get('json_valid') for x in res)), pct(frac(x.get('fmt_final_ok') for x in res)),
                sum(len(x.get('invalid_action_ids') or []) for x in res)))
    L.append('')
    L.append(t['costs'])
    L.append('')
    costs = model_costs(db, plan_id)
    ms = [m for m in costs if m and m != 'fable']
    L.append('| %s | ' % t['measure'] + ' | '.join(ms) + ' |')
    L.append('|---|' + '---:|' * len(ms))

    def cell(m, key, fn=max, nd=0):
        vals = [v for v in costs[m].get(key) or [] if v is not None]
        return fmt_num(fn(vals), nd) if vals else '—'
    L.append('| %s | ' % t['cost_rows']['cold'] + ' | '.join(cell(m, 'cold') for m in ms) + ' |')
    L.append('| %s | ' % t['cost_rows']['warm'] + ' | '.join(cell(m, 'warm') for m in ms) + ' |')
    L.append('| %s | ' % t['cost_rows']['switch'] + ' | '.join(cell(m, 'switch') for m in ms) + ' |')
    L.append('| %s | ' % t['cost_rows']['ctx16k'] + ' | '.join(cell(m, 'ctx16k') for m in ms) + ' |')
    L.append('| %s | ' % t['cost_rows']['ptps'] + ' | '.join(
        cell(m, 'ptps', lambda v: statistics.median(v), 1) for m in ms) + ' |')
    L.append('| %s | ' % t['cost_rows']['gtps'] + ' | '.join(cell(m, 'gtps', lambda v: statistics.median(v), 1) for m in ms) + ' |')
    L.append('| %s | ' % t['cost_rows']['ram'] + ' | '.join(cell(m, 'ram', max, 1) for m in ms) + ' |')
    L.append('')
    imp = impact(db, plan_id)
    L.append(t['impact'])
    L.append('')
    L.append(t['impact_note'] % (
                 SAMPLE_SECONDS, SAMPLE_FAST, LOSS_MAX, RTT_MAX,
                 load_max(*[plan_compute(db, plan_id).get(k) for k in ('jail_threads', 'cores')]), SUSTAIN,
                 LOAD_HEADROOM))
    L.append('')
    L.append(t['impact_head'])
    L.append('|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
    for key in sorted(imp):
        v = imp[key]
        L.append('| %s | %d | %s / %s | %s | %s | %s / %s | %s | %s / %s | %s | %s |' % (
            _situation(key, t), v['samples'], fmt_num(v['load_p50'], 2), fmt_num(v['load_max'], 2), fmt_num(v['cpu_busy_p50']),
            fmt_num(v['temp_max']), fmt_num(v['rtt_p50'], 1), fmt_num(v['rtt_max'], 1), fmt_num(v['loss_max'], 1),
            fmt_num(v['ping_p50'], 1), fmt_num(v['ping_max'], 1), fmt_num(v['suricata_drops_delta']),
            fmt_num(v['mem_free_min'], 1)))
    L.append('')
    th = [r for r in rows if (r['params'] or {}).get('tag') == 'threads']
    if th:
        L.append(t['threads_head'])
        L.append('|---:|---|---:|---:|---:|---:|')
        for r in sorted(th, key=lambda x: x['params'].get('num_thread') or 0):
            res = r['result']
            L.append('| %s | %s | %s | %s | %s | %s |' % (r['params'].get('num_thread'), r['model'], fmt_num(res.get('wall_s')),
                                                          fmt_num(res.get('prompt_tps'), 1), fmt_num(res.get('gen_tps'), 1),
                                                          res.get('quality')))
        L.append('')
    L.append(t['queue'])
    L.append('')
    q = step_rows(db, plan_id, kind='queue')
    if q:
        L.append(t['queue_head'])
        L.append('|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---|---|')
        for r in q:
            x = r['result']
            L.append('| %s (%s) | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (
                x.get('action'), r['scenario'], (r['params'] or {}).get('repeat'), t['sync'] if x.get('sync') else t['queued'],
                fmt_num(x.get('enqueue_s'), 1), fmt_num(x.get('position')), fmt_num(x.get('eta_s')), fmt_num(x.get('queue_s')),
                fmt_num(x.get('run_s')), fmt_num(x.get('total_s')),
                ('%s %%' % x['eta_error_pct']) if x.get('eta_error_pct') is not None else '—',
                t['yes'] if x.get('cached') or x.get('cached_calls') else t['no'],
                x.get('job_status') or x.get('first_status')))
    else:
        L.append(t['not_measured_run'])
    L.append('')
    L.append(t['params'])
    L.append('')
    pr = [r for r in rows if (r['params'] or {}).get('tag') == 'params']
    if pr:
        L.append(t['params_head'])
        L.append('|---|---|---|---:|---:|---:|---:|---:|---|')
        for r in pr:
            x = r['result']
            var = ', '.join('%s=%s' % (k, v) for k, v in sorted(r['params'].items()) if k != 'tag')
            base = [b['result'] for b in rows if b['scenario'] == r['scenario'] and b['model'] == r['model'] and
                    (b['params'] or {}).get('tag', 'matrix') in ('matrix', 'import') and not b['result'].get('skipped')]
            bl = '%s / %s' % (fmt_num(base[0].get('wall_s')), base[0].get('quality')) if base else '—'
            L.append('| %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (
                r['scenario'], r['model'], var, fmt_num(x.get('data_tokens') or (x.get('context') or {}).get('estimated_tokens')),
                x.get('parts') or 0, fmt_num(x.get('wall_s')), x.get('citations'), x.get('quality'), bl))
    else:
        L.append(t['not_measured_run'])
    L.append('')
    L.append(t['repeat'])
    L.append('')
    L.append(t['repeat_head'])
    L.append('|---|---|---:|---:|---:|---:|---:|---:|---:|---:|')
    rep = {}
    for r in rows:
        if (r['params'] or {}).get('tag', 'matrix') in ('matrix', 'repeat') and r['round_name'] in ('matrix', 'repeat') \
                and not r['result'].get('skipped'):
            rep.setdefault((r['scenario'], r['model']), []).append(r)
    for (sid, model), rr in sorted(rep.items()):
        if len(rr) < 2:
            continue
        agg = aggregate(rr)
        L.append('| %s | %s | %d | %d | %s | %s | %s | %s | %s | %.1f |' % (
            sid, model, agg['n'], len({x['variant'] for x in rr}), fmt_num(agg['wall_p50']), fmt_num(agg['wall_p90']),
            fmt_num(agg['wall_sd'], 1), pct(agg['fmt_final']), pct(agg['lang']), agg['quality']))
    L.append('')
    L.append(t['resilience'])
    L.append('')
    for kind in ('concurrency', 'short_timeout'):
        for r in step_rows(db, plan_id, kind=kind):
            x = r['result']
            if kind == 'concurrency':
                reqs = x.get('requests') or []
                L.append(t['concurrency'] % (x.get('n'), r['model'], '; '.join(
                    t['request'] % (i + 1, 'ok' if q_.get('ok') else t['error'] % (q_.get('http') or q_.get('error')),
                                    q_.get('wall_s')) for i, q_ in enumerate(reqs) if q_)))
            else:
                to, n = x.get('timed_out_request') or {}, x.get('next_request') or {}
                L.append(t['timeout'] % ((r['params'] or {}).get('timeout'), to.get('error') or t['answered'],
                                         to.get('wall_s'), n.get('wall_s')))
    L.append('')
    L.append(t['quality'])
    L.append('')
    L.append(t['rubric_note'])
    L.append('')
    L.append(t['rubric_head'])
    L.append('|---|---|---:|---:|---:|---:|---:|---|')
    for sid in QUALITY_SCENARIOS:
        seen = set()
        for r in sorted(rows, key=lambda x: (x['model'] != 'fable', x['model'] or '')):
            if r['scenario'] != sid or r['model'] in seen or r['result'].get('skipped'):
                continue
            seen.add(r['model'])
            x = r['result']
            rb = x.get('rubric') or rubric(x)
            L.append('| %s | %s | %d | %d | %d | %d | %d | %s |' % (
                sid, r['model'], rb['precision'], rb['evidence'], rb['actions'], rb['hallucination'], rb['clarity'],
                mask(x.get('text'), 160).replace('|', '/') or t['no_answer']))
    L.append('')
    L.append(t['decision'])
    L.append('')
    rec = recommend(db, plan_id, lang)
    L.append(t['decision_head'])
    L.append('|---|---|---|---|---:|---:|---:|---|---|')
    for sid, r in rec.items():
        L.append('| %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (
            sid, r.get('model') or '—', r.get('alt') or '—', r.get('mode') or '—', fmt_num(r.get('timeout')),
            fmt_num(r.get('num_predict')), fmt_num(r.get('budget')), sv.get(r.get('serves'), r.get('serves')),
            r.get('why')))
    L.append('')
    L.append(t['applicable'])
    L.append('')
    L.append('```')
    for sid, r in rec.items():
        if not r.get('model'):
            continue
        if r['model'].startswith('claudecode'):
            L.append('ai_routing %s provider=claudecode+model=fable+mode=sync+timeout=300+retries=1' % sid)
        else:
            L.append('ai_routing %s provider=ollama+model=%s+mode=%s+timeout=%d+num_ctx=8192+num_predict=%d+budget=%d'
                     '+keep_alive=30m+retries=1' % (sid, r['model'], r['mode'], r['timeout'], r['num_predict'], r['budget']))
    L.append('```')
    L.append('')
    ev = [dict(e) for e in db.execute("SELECT ts, kind, message FROM events WHERE kind IN ('pause', 'resume', "
                                      "'step_aborted', 'runner_error', 'mail_error') ORDER BY id")]
    if ev:
        L.append(t['events'])
        L.append('')
        for e in ev[-40:]:
            L.append('- %s %s: %s' % (iso(e['ts']), e['kind'], mask(e['message'], 200)))
        L.append('')
    try:
        # the per scenario evaluation (ai/evaluate.py) keeps its section when the catalog is regenerated
        if db.execute("SELECT name FROM sqlite_master WHERE name = 'eval_results'").fetchone() and \
                db.execute('SELECT 1 FROM eval_results LIMIT 1').fetchone():
            L.append(_evaluate().report_md(db, lang))
    except sqlite3.Error:
        pass
    return '\n'.join(L) + '\n'


def _situation(key, t):
    """ the row label of the impact table (the keys are internal: 'idle (no model)', 'inference <model>') """
    if key == 'idle (no model)':
        return t['idle']
    if key.startswith('inference '):
        return t['inference'] % key[len('inference '):]
    return key


def report_json(db=None):
    db = db or connect()
    plan = db.execute("SELECT * FROM plans WHERE imported = 0 ORDER BY id DESC LIMIT 1").fetchone()
    pid = plan['id'] if plan else -1
    rank = ranking(db, pid)
    return {'status': 'ok', 'plan': dict(plan) if plan else None,
            'ranking': {s: [{'model': m, 'agg': a, 'serves': v} for m, a, v in items] for s, items in rank.items()},
            'recommend': recommend(db, pid), 'impact': impact(db, pid), 'summary': executive_summary(db, pid),
            'compute': cmd_compute(db)}


def cmd_compute(db=None, backfill=False):
    """
    the compute profiles of the measurements and the reference throughput per profile and model
    :param backfill: stamp the steps measured before the profile was recorded with the profile of NOW (only right
                     while the jail still has the limits they ran with: run it before a set_limits)
    """
    db = db or connect()
    comp = _compute()
    out = {'status': 'ok'}
    if backfill:
        doc = compute_now()
        out.update(backfilled=comp.backfill(db, doc), profile=doc, label=comp.label(doc))
    out.update(profiles=comp.usage(db), throughput=comp.throughput(db))
    return out


# ------------------------------------------------------------------ main


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    args = [a for a in argv[2:] if a]
    try:
        if cmd == 'step':
            return cmd_step()
        if cmd == 'run':
            emit(Runner().run())
        elif cmd == 'start':
            emit(cmd_start(args[0] if args else 'matriz', retry='retry' in args[1:], tokens=args[1:]))
        elif cmd == 'stop':
            emit(cmd_stop())
        elif cmd == 'kick':
            emit(cmd_kick())
        elif cmd == 'status':
            emit(cmd_status())
        elif cmd == 'report':
            if args and args[0] == 'json':
                emit(report_json())
            else:
                sys.stdout.write(report_md())
        elif cmd == 'compute':
            emit(cmd_compute(backfill=bool(args) and args[0] == 'backfill'))
        elif cmd == 'import' and args:
            emit(import_jsonl(args[0], args[1] if len(args) > 1 else None))
        else:
            emit({'status': 'error', 'message': 'usage: bench.py start <%s> [retry|reps=N|only=a,b|reeval]|status|'
                                                'stop|kick|report [md|json]|compute [backfill]|import <jsonl> [label]' % '|'.join(PLANS)})
            return 1
    except (sqlite3.Error, OSError, ValueError) as exc:
        emit({'status': 'error', 'message': str(exc)})
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
