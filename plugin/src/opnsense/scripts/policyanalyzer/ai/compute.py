"""
    Copyright (c) 2026 Igor Toledo
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

    --------------------------------------------------------------------------------------

    Compute profile of a measurement (ai/bench.py and ai/evaluate.py): on which hardware, and with which share of
    it, the model ran.  A time or a tokens/s figure means nothing without it: the same model on the same firewall
    is ~30 % faster with one more core, and a future, stronger machine must be compared with these numbers.

    One profile = the machine (CPU, cores, SIMD, RAM, memory modules/channels/speed and the theoretical memory
    bandwidth) + the share given to the model (cpuset and threads of the Ollama jail, num_ctx, nice, memory limit)
    + the runtime (Ollama version).  Profiles live in the table compute_profiles of ai-bench.db, one row per
    distinct profile (key = hash of KEY_FIELDS); every step carries steps.compute_id, stamped by the runner when
    the step starts.  The limits file is read again at every step, so a "set_limits" between two steps opens a new
    profile by itself.

    Steps measured before this module existed are stamped by backfill(): it is only correct while the configuration
    of the jail is still the one those steps ran with, so it has to run before the limits change, and it says so
    in an event and in meta "compute_backfill".

    Read only: sysctl, dmesg.boot, dmidecode (root) and the limits file.  Nothing here changes the system.
    The texts (memory_text, short, label, report_lines) come from the section "compute" of i18n/<language>.json, in
    the language of the evaluation reports (evaluate.report_language); the events of the database stay in English.
"""

import hashlib
import json
import os
import platform
import socket
import statistics
import time

import i18n

LIMITS_FILE = os.environ.get('POLICYANALYZER_LIMITS', '/var/db/policyanalyzer/runtime-limits.json')
# what makes two measurements comparable in speed; hostname and nice are information only
KEY_FIELDS = ('cpu', 'cores', 'simd', 'ram_gib', 'mem_modules', 'mem_type', 'mem_speed', 'mem_channels',
              'jail_cpus', 'jail_threads', 'num_ctx', 'ollama_version')

# step params that change the share of the machine for that step alone: such a step is not a sample of the profile
OVERRIDES = ('num_thread', 'num_ctx')

SCHEMA = """
CREATE TABLE IF NOT EXISTS compute_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE, created INTEGER NOT NULL, data TEXT NOT NULL);
"""

_STATIC = None


def ensure(db):
    """ the table and the column steps.compute_id (older databases do not have it) """
    db.executescript(SCHEMA)
    cols = {r[1] for r in db.execute('PRAGMA table_info(steps)')}
    if cols and 'compute_id' not in cols:
        db.execute('ALTER TABLE steps ADD COLUMN compute_id INTEGER')
    db.commit()
    return db


# ------------------------------------------------------------------ probes (read only)


def read_limits(path=None):
    try:
        with open(path or LIMITS_FILE) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def cpuset_cores(cpus):
    """ '2-3' -> 2, '0,2' -> 2, '1-3' -> 3; None when it cannot be read """
    count = 0
    try:
        for part in str(cpus).split(','):
            low, _, high = part.strip().partition('-')
            count += (int(high) if high else int(low)) - int(low) + 1
    except ValueError:
        return None
    return count if count > 0 else None


def simd_of(flags):
    flags = flags or {}
    if flags.get('avx512'):
        return 'AVX-512'
    if flags.get('avx2'):
        return 'AVX2 + VNNI' if flags.get('avx_vnni') else 'AVX2'
    return 'no AVX2' if flags.get('source') else None


def static_profile(ctx=None):
    """ the machine itself; probed once per process (dmidecode needs root: None otherwise) """
    hw = {'hostname': socket.gethostname(), 'os': platform.system(), 'os_release': platform.release(),
          'cpu': None, 'cores': None, 'physical_cores': None, 'simd': None, 'ram_gib': None, 'mem_modules': None,
          'mem_type': None, 'mem_speed': None, 'mem_channels': None, 'mem_bandwidth_gbs': None, 'mem_how': None}
    try:
        from setup import common, recommend
        ctx = ctx or common.Context()

        def num(name):
            try:
                return int(common.sysctl(ctx, name))
            except (ValueError, OSError):
                return None
        hw['cpu'] = common.sysctl(ctx, 'hw.model') or platform.processor() or None
        hw['cores'] = num('hw.ncpu') or os.cpu_count()
        hw['physical_cores'] = num('kern.smp.cores')
        physmem = num('hw.physmem')
        hw['ram_gib'] = round(physmem / 2 ** 30, 1) if physmem else None
        hw['simd'] = simd_of(recommend.cpu_flags(ctx))
        modules = recommend.dmidecode_memory(ctx)
        if modules:
            theoretical, _eff, how = recommend.memory_bandwidth({'cpu': {'model': hw['cpu']},
                                                                'memory': {'modules': modules}})
            speeds = [m['speed'] for m in modules if m.get('speed')]
            hw.update(mem_modules=['%s %s-%s' % (m.get('size'), m.get('type') or '?', m.get('speed') or '?')
                                   for m in modules],
                      mem_type=next((m['type'] for m in modules if m.get('type')), None),
                      mem_speed=min(speeds) if speeds else None,
                      mem_channels=int(round(theoretical * 1000 / 8 / min(speeds))) if speeds else None,
                      mem_bandwidth_gbs=theoretical, mem_how=how)
    except Exception:                 # noqa: BLE001 - a probe never breaks a measurement; the fields stay None
        hw['cores'] = hw['cores'] or os.cpu_count()
    return hw


def profile(ollama_version=None, limits=None, static=None, ollama_url=None):
    """
    the profile of a measurement taken now
    :param static: the machine part (tests); default: probed once and kept for the life of the process
    """
    global _STATIC
    if static is None:
        if _STATIC is None:
            _STATIC = static_profile()
        static = _STATIC
    limits = read_limits() if limits is None else limits
    doc = dict(static)
    doc.update(jail_cpus=limits.get('cpus'), jail_cores=cpuset_cores(limits.get('cpus')) if limits.get('cpus') else
               None, jail_threads=limits.get('threads'), num_ctx=limits.get('ctx'), nice=limits.get('nice'),
               mem_limit_gb=limits.get('mem_gb'), num_parallel=limits.get('num_parallel'),
               ollama_version=ollama_version, ollama_url=ollama_url)
    doc['key'] = key_of(doc)
    return doc


def key_of(doc):
    canon = json.dumps([doc.get(k) for k in KEY_FIELDS], sort_keys=True, default=str)
    return hashlib.sha1(canon.encode()).hexdigest()[:10]


# ------------------------------------------------------------------ storage


def record(db, doc):
    """ :return: id of the profile (one row per distinct key) """
    ensure(db)
    key = doc.get('key') or key_of(doc)
    row = db.execute('SELECT id FROM compute_profiles WHERE key = ?', (key,)).fetchone()
    if row is not None:
        return row[0]
    cur = db.execute('INSERT INTO compute_profiles (key, created, data) VALUES (?, ?, ?)',
                     (key, int(time.time()), json.dumps(dict(doc, key=key), ensure_ascii=False, default=str)))
    db.commit()
    return cur.lastrowid


def stamp(db, step_id, profile_id):
    db.execute('UPDATE steps SET compute_id = ? WHERE id = ?', (profile_id, step_id))
    db.commit()


def get(db, profile_id):
    if profile_id is None:
        return None
    row = db.execute('SELECT data FROM compute_profiles WHERE id = ?', (profile_id,)).fetchone()
    try:
        return dict(json.loads(row[0]), id=profile_id) if row else None
    except ValueError:
        return None


def backfill(db, doc):
    """
    stamp every measured step that has no profile yet (measured before this module, or while it was not installed)
    with <doc>.  Only right while the jail still has the limits those steps ran with: call it BEFORE a set_limits.
    Imported plans (measured elsewhere) are left alone.
    :return: number of steps stamped
    """
    ensure(db)
    pid = record(db, doc)
    cur = db.execute('UPDATE steps SET compute_id = ? WHERE compute_id IS NULL AND started IS NOT NULL AND round_id '
                     'IN (SELECT r.id FROM rounds r JOIN plans p ON p.id = r.plan_id WHERE p.imported = 0)', (pid,))
    count = cur.rowcount
    if count:
        note = {'ts': int(time.time()), 'steps': count, 'profile_id': pid, 'key': doc.get('key')}
        hist = []
        row = db.execute("SELECT v FROM meta WHERE k = 'compute_backfill'").fetchone()
        if row:
            try:
                hist = json.loads(row[0]) or []
            except ValueError:
                hist = []
        db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('compute_backfill', ?)", (json.dumps(hist + [note]),))
        db.execute('INSERT INTO events (ts, kind, message) VALUES (?, ?, ?)',
                   (int(time.time()), 'compute', 'compute profile #%d recorded retroactively on %d step(s): %s'
                    % (pid, count, short(doc, i18n.DEFAULT))))
    db.commit()
    return count


# ------------------------------------------------------------------ text


def _texts(language):
    from ai import evaluate
    lang = evaluate.report_language(language)
    return dict(i18n.section(lang, 'compute'), _lang=lang)


def _n(value, nd=0, language=i18n.DEFAULT):
    if value is None:
        return '?'
    text = ('%.' + str(nd) + 'f') % value
    return text.replace('.', i18n.number_format(language).get('decimal', '.'))


def memory_text(doc, language=None):
    doc = doc or {}
    t = _texts(language)
    lang = t['_lang']
    if not doc.get('mem_modules'):
        return '%s GiB' % _n(doc.get('ram_gib'), 1, lang) if doc.get('ram_gib') else '?'
    ch = doc.get('mem_channels')
    return t['memory'] % (
        _n(doc.get('ram_gib'), 1, lang), len(doc['mem_modules']), doc.get('mem_type') or '?',
        doc.get('mem_speed') or '?', t['one_channel'] if ch == 1 else t['channels'] % (ch or '?'),
        _n(doc.get('mem_bandwidth_gbs'), 1, lang))


def short(doc, language=None):
    """ the share given to the model, e.g. "2 threads on 2 cores (cpus 2-3)" """
    doc = doc or {}
    return _texts(language)['short'] % (doc.get('jail_threads') or '?', doc.get('jail_cores') or '?',
                                        doc.get('jail_cpus') or '?')


def label(doc, language=None):
    """ one line with everything that matters for a comparison """
    doc = doc or {}
    t = _texts(language)
    return t['label'] % (
        doc.get('cpu') or '?', doc.get('cores') or '?', ' (%s)' % doc['simd'] if doc.get('simd') else '',
        short(doc, t['_lang']), doc.get('num_ctx') or '?', memory_text(doc, t['_lang']),
        doc.get('ollama_version') or '?')


# ------------------------------------------------------------------ reference numbers


def usage(db):
    """ the profiles with the steps measured under each one, oldest first """
    ensure(db)
    out = []
    for row in db.execute('SELECT c.id, c.data, COUNT(s.id) AS n, MIN(s.started) AS first, MAX(s.finished) AS last '
                          'FROM compute_profiles c LEFT JOIN steps s ON s.compute_id = c.id GROUP BY c.id '
                          'ORDER BY c.id'):
        try:
            doc = json.loads(row[1])
        except ValueError:
            doc = {}
        out.append(dict(doc, id=row[0], steps=row[2], first=row[3], last=row[4]))
    return out


def throughput(db):
    """
    the reference of this hardware: per profile and model, the median speed of every finished step that reported
    it (reading the prompt and generating, tokens/s) and how many executions it comes from.  Steps that override
    what the profile says (num_thread or num_ctx in their params: rounds "threads" and "params") stay out.
    """
    ensure(db)
    groups = {}
    for row in db.execute("SELECT compute_id, model, result, params FROM steps WHERE status = 'done' AND compute_id "
                          "IS NOT NULL AND model IS NOT NULL AND result IS NOT NULL"):
        try:
            res = json.loads(row[2]) or {}
            params = json.loads(row[3]) if row[3] else {}
        except ValueError:
            continue
        if isinstance(params, dict) and any(k in params for k in OVERRIDES):
            continue
        if not isinstance(res, dict) or res.get('error') or res.get('timeout'):
            continue
        if not (res.get('gen_tps') or res.get('prompt_tps')):
            continue
        g = groups.setdefault((row[0], row[1]), {'gen': [], 'prompt': [], 'n': 0})
        g['n'] += 1
        if res.get('gen_tps'):
            g['gen'].append(float(res['gen_tps']))
        if res.get('prompt_tps'):
            g['prompt'].append(float(res['prompt_tps']))
    out = []
    for (pid, model), g in sorted(groups.items()):
        out.append({'profile_id': pid, 'model': model, 'n': g['n'],
                    'prompt_tps': round(statistics.median(g['prompt']), 1) if g['prompt'] else None,
                    'gen_tps': round(statistics.median(g['gen']), 1) if g['gen'] else None})
    return out


def report_lines(db, stamp_fmt=None, language=None):
    """ the markdown section "Compute profile" of the catalog (bench.report_md) """
    t = _texts(language)
    r_ = t['report']
    lang = t['_lang']
    fmt = stamp_fmt or (lambda ts: i18n.fmt_date(ts, lang) if ts else '—')
    profiles = [p for p in usage(db) if p['steps']]
    L = [r_['intro'], '']
    if not profiles:
        return L + [r_['none'], '']
    L += [r_['head'], '|---:|---|---:|---|---|---:|---:|---|---|---:|---|']
    for p in profiles:
        L.append(r_['row'] % (
            p['id'], p.get('cpu') or '?', p.get('cores') or '?', p.get('simd') or '?', p.get('jail_cores') or '?',
            p.get('jail_cpus') or '?', p.get('jail_threads') or '?', p.get('num_ctx') or '?', memory_text(p, lang),
            p.get('ollama_version') or '?', p['steps'], fmt(p['first']), fmt(p['last'])))
    notes = []
    row = db.execute("SELECT v FROM meta WHERE k = 'compute_backfill'").fetchone()
    if row:
        try:
            notes = json.loads(row[0]) or []
        except ValueError:
            notes = []
    for note in notes:
        L += ['', r_['backfill'] % (note.get('profile_id') or 0, note.get('steps') or 0, fmt(note.get('ts')))]
    rows = throughput(db)
    if rows:
        L += ['', r_['throughput'], '', r_['throughput_head'], '|---:|---|---:|---:|---:|']
        for r in rows:
            L.append('| #%d | %s | %d | %s | %s |' % (r['profile_id'], r['model'], r['n'],
                                                      _n(r['prompt_tps'], 1, lang) if r['prompt_tps'] is not None
                                                      else '—',
                                                      _n(r['gen_tps'], 1, lang) if r['gen_tps'] is not None else '—'))
    return L + ['']
