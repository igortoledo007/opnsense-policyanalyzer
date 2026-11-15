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

    Per scenario evaluation of the local models ("avaliacao" plan of ai/bench.py: same runner, guards, isolation,
    SQLite and e-mail channel).  For every candidate model, in order: download it when missing (change action
    pull_model, one at a time), load it, record its setup and the hardware, then run every synthetic fixture of
    ai/eval_fixtures.py N times (default 3, repetition-major so the prompt cache of Ollama never helps) and score
    each run.  At the end of each model: aggregates per scenario, indication, a PDF and an e-mail; at the end of
    the plan: ranking and the recommended route (recommendation only, the routing is never changed here).

        bench.py start avaliacao [reps=N] [only=a,b] [reeval] [w_eff=0.7]   start / resume (configd ai_bench_start)
        evaluate.py candidates          the catalog, what is installed, sizes, estimated time
        evaluate.py status              progress of the plan and the best model per scenario so far
        evaluate.py report [md|json]    the comparison (docs/ia-local-catalogo.md section)
        evaluate.py pdf <model|final> [file]   the PDF again (default: /var/db/policyanalyzer/ai-eval/)

    Score 0-100 = effectiveness x 0.7 + performance x 0.3 (weights stored with every result).  Effectiveness is
    deterministic (no LLM judge): validation, strict pt-BR, no leaked reasoning, anchoring, key facts, size/format
    and stability between repetitions.  Performance: p50/p95 against the time budget of the scenario (timeout of the
    local_only route), generation tokens/s, time to the first token, resident RAM and host load.  Only measurements
    taken on the firewall (FreeBSD, Ollama on 127.0.0.1, same hardware fingerprint) enter the comparison.
"""

import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
import unicodedata

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import i18n                                # noqa: E402
from ai import bench                       # noqa: E402
from ai import eval_fixtures               # noqa: E402

# evaluation data: the language the models are tested in (the fixtures and the strict language check are
# Brazilian Portuguese); it is not the language of the reports (report_language below)
LANG = 'pt_BR'
PLAN = 'avaliacao'
ROUND_PREFIX = 'eval:'
EVAL_DIR = os.environ.get('POLICYANALYZER_AI_EVAL_DIR', '/var/db/policyanalyzer/ai-eval')
SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANAGE = os.path.join(SCRIPTS_DIR, 'manage.py')
PULL_POLL = 15
PULL_MAX_SECONDS = 4 * 3600 - 600
DEFAULT_REPS = 3
RAM_TOTAL_GIB = 32.0
THINK_EXTRA = 2048                     # num_predict added for the reasoning of a harmony (gpt-oss) model
# plan option think=on (2026-11-13): the reasoning variant of a model, through the route field think of the plugin
# (the production path), recorded as "<model>@think" so it never mixes with the evaluation without reasoning
THINK_SUFFIX = '@think'
THINK_ROUTE = {'think': 'on', 'think_budget': 9000, 'num_ctx': 16384, 'timeout': 1800}

# composite = effectiveness x w_eff + performance x w_perf; stored with every result
WEIGHTS = {'effectiveness': 0.7, 'performance': 0.3}
# effectiveness components (sum 100); "estabilidade" exists only with 2+ runs (its weight then goes to the rest)
EFFECT_WEIGHTS = (('validacao', 20), ('idioma', 15), ('raciocinio', 10), ('ancoragem', 20), ('cobertura', 20),
                  ('formato', 10), ('estabilidade', 5))
# performance components (sum 100)
PERF_WEIGHTS = (('p50', 35), ('p95', 25), ('tps', 15), ('ttft', 10), ('ram', 10), ('carga', 5))
# the stored values of indication and confidence stay as they are (keys of the rows already in ai-bench.db and of
# the JSON of evaluate.py report json); readers see the labels of the catalog (i18n, section "eval": indication,
# confidence, components)
INDICATIONS = ('indicado', 'promissor', 'não indicado')
_LANG_CACHE = {}


def report_language(language=None):
    """
    the language of the evaluation reports (PDFs, e-mails, markdown): <language> when given, else ai.language of
    the settings, where "auto" follows the GUI language (system/language of config.xml); en_US by default.
    Cached per config.xml version (path, mtime, size).
    """
    if language:
        return i18n.normalize(language)
    path = os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')
    try:
        st = os.stat(path)
    except OSError:
        return i18n.DEFAULT
    key = (path, st.st_mtime, st.st_size)
    if _LANG_CACHE.get('key') != key:
        choice = 'auto'
        try:
            from ai.config import AIConfig
            choice = AIConfig.from_opnsense('OPNsense/policyanalyzer', path=path).language
        except Exception:                           # noqa: BLE001 - unreadable settings: the GUI language
            pass
        _LANG_CACHE.update(key=key, value=i18n.resolve(choice, path))
    return _LANG_CACHE['value']


def texts(language=None, name='eval_mail'):
    """ one section of the catalog in the report language, plus '_lang' and '_eval' (the shared labels) """
    lang = report_language(language)
    return dict(i18n.section(lang, name), _lang=lang, _eval=i18n.section(lang, 'eval'))


def indication_label(value, language=None):
    return i18n.section(report_language(language), 'eval')['indication'].get(value, value)
INDICATED_EFF = 80.0
PROMISING_EFF = 65.0
TPS_FULL = 8.0                       # tokens/s of generation that scores 100 (a little faster than reading)
TTFT_GOOD, TTFT_BAD = 15.0, 180.0     # s to the first token
RAM_GOOD, RAM_BAD = 6.0, 24.0         # GiB resident (32 GiB box: 8 GiB stay for the firewall, Suricata, ZFS)
LOAD_GOOD = 2.0                       # load average with the default share (2 threads); see load_bounds

# candidates that fit 32 GiB (tags and sizes checked on registry.ollama.ai on 2026-11-09), most promising first:
# the model that should answer the long scenarios, the current short one, small fast models, then the 7-14B, the
# MoE gpt-oss, the dense 24-27B (slow on 2 cores) and the always thinking qwen3:30b-a3b last
CANDIDATES = (
    {'model': 'qwen3:30b-a3b-instruct-2507-q4_K_M', 'size_gib': 17.28, 'params_b': 30.5, 'active_b': 3.3,
     'family': 'qwen3moe', 'think': 'none', 'why': 'MoE with 3B active and no reasoning mode: the candidate to '
                                                  'replace qwen3:30b-a3b (Thinking) in the long scenarios'},
    {'model': 'qwen2.5:3b', 'size_gib': 1.80, 'params_b': 3.1, 'active_b': 3.1, 'family': 'qwen2',
     'think': 'none', 'why': 'baseline: the current short model of the Local only preset'},
    {'model': 'qwen3:4b-instruct-2507-q4_K_M', 'size_gib': 2.33, 'params_b': 4.0, 'active_b': 4.0,
     'family': 'qwen3', 'think': 'none', 'why': 'direct successor of qwen2.5:3b, instruct version (no reasoning)'},
    {'model': 'gemma3:4b', 'size_gib': 3.12, 'params_b': 4.3, 'active_b': 4.3, 'family': 'gemma3', 'think': 'none',
     'why': 'small and strong in languages other than English'},
    {'model': 'gemma3:12b', 'size_gib': 7.60, 'params_b': 12.2, 'active_b': 12.2, 'family': 'gemma3',
     'think': 'none', 'why': 'middle ground of quality in Portuguese'},
    {'model': 'qwen2.5:7b', 'size_gib': 4.36, 'params_b': 7.6, 'active_b': 7.6, 'family': 'qwen2', 'think': 'none',
     'why': 'same family as the current model, twice the parameters'},
    {'model': 'qwen3:8b', 'size_gib': 4.87, 'params_b': 8.2, 'active_b': 8.2, 'family': 'qwen3',
     'think': 'hybrid', 'why': 'hybrid qwen3: the plugin turns the reasoning off with think=false and /no_think'},
    {'model': 'gpt-oss:20b', 'size_gib': 12.85, 'params_b': 20.9, 'active_b': 3.6, 'family': 'gptoss',
     'think': 'harmony', 'why': 'MoE with 3.6B active; always reasons (harmony format), evaluated with think "low"'},
    {'model': 'granite4:tiny-h', 'size_gib': 3.94, 'params_b': 7.0, 'active_b': 1.0, 'family': 'granitehybrid',
     'think': 'none', 'why': 'hybrid MoE (Mamba) with ~1B active: the fastest per token among the candidates'},
    {'model': 'llama3.1:8b', 'size_gib': 4.58, 'params_b': 8.0, 'active_b': 8.0, 'family': 'llama',
     'think': 'none', 'why': 'market reference in the 8B range'},
    {'model': 'granite3.3:8b', 'size_gib': 4.60, 'params_b': 8.2, 'active_b': 8.2, 'family': 'granite',
     'think': 'hybrid', 'why': 'focused on enterprise use and strict instructions'},
    {'model': 'foundation-sec:8b', 'size_gib': 4.58, 'params_b': 8.0, 'active_b': 8.0, 'family': 'llama',
     'think': 'none', 'installed_only': True,
     'why': 'Llama 3.1 specialized in security (imported GGUF; not in the Ollama registry)'},
    {'model': 'qwen3:14b', 'size_gib': 8.64, 'params_b': 14.8, 'active_b': 14.8, 'family': 'qwen3',
     'think': 'hybrid', 'why': 'larger hybrid qwen3'},
    {'model': 'qwen2.5:14b', 'size_gib': 8.37, 'params_b': 14.8, 'active_b': 14.8, 'family': 'qwen2',
     'think': 'none', 'why': 'larger qwen2.5, no reasoning'},
    {'model': 'phi4:14b', 'size_gib': 8.43, 'params_b': 14.7, 'active_b': 14.7, 'family': 'phi3', 'think': 'none',
     'why': 'good at structured reasoning; Portuguese to be confirmed'},
    {'model': 'mistral-small3.2:24b', 'size_gib': 14.14, 'params_b': 24.0, 'active_b': 24.0, 'family': 'mistral3',
     'think': 'none', 'why': 'dense 24B: high quality, slow on 2 cores'},
    {'model': 'gemma3:27b', 'size_gib': 16.22, 'params_b': 27.4, 'active_b': 27.4, 'family': 'gemma3',
     'think': 'none', 'why': 'the largest gemma3; measures the quality ceiling that fits in 32 GB'},
    {'model': 'qwen3:30b-a3b', 'size_gib': 17.28, 'params_b': 30.5, 'active_b': 3.3, 'family': 'qwen3moe',
     'think': 'forced', 'why': 'the current long model (Thinking-2507: always reasons); goes last'},
)
CATALOG_BY_MODEL = {c['model']: c for c in CANDIDATES}

SCHEMA = """
CREATE TABLE IF NOT EXISTS eval_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id INTEGER, round_id INTEGER, model TEXT NOT NULL, digest TEXT,
    status TEXT NOT NULL, started INTEGER, finished INTEGER, reps INTEGER, weights TEXT, fixtures_version INTEGER,
    options TEXT, setup TEXT, hardware TEXT, pdf_path TEXT, summary TEXT, latest INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS eval_models_round ON eval_models(round_id);
CREATE TABLE IF NOT EXISTS eval_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, eval_id INTEGER NOT NULL, step_id INTEGER, model TEXT, scenario TEXT,
    fixture TEXT, rep INTEGER, ts INTEGER, ok INTEGER, effectiveness REAL, components TEXT, metrics TEXT);
CREATE INDEX IF NOT EXISTS eval_runs_eval ON eval_runs(eval_id, scenario);
CREATE TABLE IF NOT EXISTS eval_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT, eval_id INTEGER NOT NULL, model TEXT NOT NULL, digest TEXT,
    scenario TEXT NOT NULL, ts INTEGER, n INTEGER, n_ok INTEGER, effectiveness REAL, performance REAL,
    composite REAL, w_eff REAL, w_perf REAL, indication TEXT, confidence TEXT, ci95 REAL, p50 REAL, p95 REAL,
    budget INTEGER, fixtures_version INTEGER, data TEXT, latest INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS eval_results_latest ON eval_results(latest, scenario);
"""


def ensure(db):
    db.executescript(SCHEMA)
    return db


def connect(path=None):
    return ensure(bench.connect(path))


def loads(text, default=None):
    return bench.loads(text, default)


def dumps(value):
    return json.dumps(value, ensure_ascii=False, default=str)


# ------------------------------------------------------------------ plan options


def parse_options(tokens):
    """ ["reps=2", "only=a,b", "reeval", "w_eff=0.8", "think=on", "scenarios=a,b"] -> dict (validated) """
    opts = {'reps': DEFAULT_REPS, 'only': [], 'reeval': False, 'w_eff': WEIGHTS['effectiveness'], 'think': False,
            'scenarios': []}
    for tok in tokens or []:
        tok = str(tok or '').strip()
        if not tok or tok == 'retry':
            continue
        if tok == 'reeval':
            opts['reeval'] = True
        elif tok.startswith('reps='):
            opts['reps'] = int(tok[5:])
            if not 1 <= opts['reps'] <= 10:
                raise ValueError('reps must be between 1 and 10')
        elif tok.startswith('only='):
            opts['only'] = [m for m in tok[5:].split(',') if m]
            for m in opts['only']:
                if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$', m):
                    raise ValueError('invalid model name %s' % m)
        elif tok.startswith('think='):
            if tok[6:] not in ('on', 'off'):
                raise ValueError('think must be on or off')
            opts['think'] = tok[6:] == 'on'
        elif tok.startswith('scenarios='):
            known = {fx['scenario'] for fx in eval_fixtures.FIXTURES}
            opts['scenarios'] = [x for x in tok[10:].split(',') if x]
            for x in opts['scenarios']:
                if x not in known:
                    raise ValueError('unknown scenario %s' % x)
        elif tok.startswith('w_eff='):
            opts['w_eff'] = float(tok[6:])
            if not 0.0 <= opts['w_eff'] <= 1.0:
                raise ValueError('w_eff must be between 0 and 1')
        else:
            raise ValueError('unknown option %s (use reps=N, only=a,b, reeval, w_eff=0.7, think=on, scenarios=a,b)'
                             % tok)
    return opts


def plan_models(opts, installed=None):
    """ the ordered models of the plan: the catalog (filtered by only=), then any other installed local model """
    installed = installed if installed is not None else bench.installed_models()
    models = [c['model'] for c in CANDIDATES]
    if opts.get('only'):
        return [m for m in opts['only']]
    extra = sorted(m for m in installed if m not in models and not m.startswith('import'))
    return models + extra


def plan_rounds(db, plan_id, tokens):
    """ called by bench.create_plan: one round per model, the options kept in meta """
    opts = parse_options(tokens)
    bench.meta_set(db, 'eval_options:%d' % plan_id, opts)
    return [ROUND_PREFIX + m for m in plan_models(opts)]


def options(db, plan_id):
    return bench.meta_get(db, 'eval_options:%d' % plan_id) or parse_options([])


def weights_of(opts):
    w = float(opts.get('w_eff', WEIGHTS['effectiveness']))
    return {'effectiveness': round(w, 3), 'performance': round(1.0 - w, 3)}


# ------------------------------------------------------------------ Ollama helpers (read only)


def tags():
    """ {name: /api/tags entry} """
    try:
        return {m['name']: m for m in (bench.ollama('/api/tags', timeout=15) or {}).get('models') or []}
    except (OSError, ValueError, bench.urllib.error.URLError):
        return {}


def show(model):
    try:
        return bench.ollama('/api/show', {'model': model}, timeout=30) or {}
    except (OSError, ValueError, bench.urllib.error.URLError):
        return {}


def classify_think(model, doc):
    """
    how the model reasons and how the evaluation treats it:
      none     no thinking capability: think=false as always
      hybrid   template honours think (qwen3 April 2025, granite3.3): the plugin sends think=false (+ /no_think)
      forced   template always opens <think> (Qwen3 Thinking-2507): the provider sends think=true + 2048 tokens
      harmony  gpt-oss (channels analysis/final): always reasons; evaluated with think "low" + 2048 tokens
    """
    template = str((doc or {}).get('template') or '')
    caps = [str(c) for c in (doc or {}).get('capabilities') or []]
    finetune = str(((doc or {}).get('model_info') or {}).get('general.finetune') or '')
    if '<|channel|>' in template or 'gpt-oss' in model or 'gptoss' in str((doc.get('details') or {}).get('family')
                                                                          if doc else ''):
        return 'harmony'
    if 'thinking' not in caps or 'think' not in template.lower() or finetune.lower() == 'instruct':
        # Ollama 0.34 lists "thinking" for every qwen3moe build, also the 2507 Instruct whose template has no
        # <think> at all: without the word in the template there is nothing to switch off
        return 'none'
    from ai.providers.ollama import forced_thinking
    return 'forced' if forced_thinking(template, finetune) else 'hybrid'


def think_overrides(mode):
    if mode == 'harmony':
        return {'think': 'low', 'think_extra': THINK_EXTRA}
    return {}


def hardware():
    """ where this measurement runs: only the firewall itself counts (see from_firewall) """
    import platform
    import socket

    def sysctl(name):
        return bench._sh('sysctl -n %s' % name, 5).strip()
    hw = {'hostname': socket.gethostname(), 'os': platform.system(), 'os_release': platform.release(),
          'cpu': sysctl('hw.model') or platform.processor(), 'cores': None, 'ram_gib': None,
          'ollama_url': bench.OLLAMA_URL, 'ollama_version': None}
    try:
        hw['cores'] = int(sysctl('hw.ncpu') or os.cpu_count() or 0) or None
    except ValueError:
        hw['cores'] = os.cpu_count()
    try:
        hw['ram_gib'] = round(int(sysctl('hw.physmem')) / 2 ** 30, 1)
    except ValueError:
        hw['ram_gib'] = None
    try:
        hw['ollama_version'] = (bench.ollama('/api/version', timeout=10) or {}).get('version')
    except (OSError, ValueError, bench.urllib.error.URLError):
        pass
    limits = {}
    try:
        with open(os.environ.get('POLICYANALYZER_LIMITS', '/var/db/policyanalyzer/runtime-limits.json')) as fh:
            limits = json.load(fh)
    except (OSError, ValueError):
        pass
    hw['jail_threads'] = limits.get('threads')
    hw['jail_cpus'] = limits.get('cpus')
    hw['source'] = 'firewall' if hw['os'] == 'FreeBSD' and '127.0.0.1' in hw['ollama_url'] else 'outro'
    # the compute profile (ai/compute.py): the share of the machine given to the model and the memory behind it;
    # the same key the steps of the bench carry, so a result can be compared with another hardware later
    try:
        comp = bench.compute_now(hw['ollama_version'])
        for key in COMPUTE_FIELDS:
            hw[key] = comp.get(key)
        hw['compute_key'] = comp.get('key')
    except Exception:                 # noqa: BLE001 - a probe never stops an evaluation
        pass
    return hw


COMPUTE_FIELDS = ('physical_cores', 'simd', 'mem_modules', 'mem_type', 'mem_speed', 'mem_channels',
                  'mem_bandwidth_gbs', 'jail_cores', 'num_ctx', 'nice', 'mem_limit_gb', 'num_parallel')


def share(hw):
    """ what the model was given of the machine: results are only comparable in speed when this is the same """
    hw = hw or {}
    return (hw.get('jail_cpus'), hw.get('jail_threads'), hw.get('num_ctx'))


def share_text(hw, language=None):
    hw = hw or {}
    if not hw.get('jail_threads'):
        return ''
    from ai import compute
    cores = hw.get('jail_cores') or (compute.cpuset_cores(hw['jail_cpus']) if hw.get('jail_cpus') else None)
    text = compute.short(dict(hw, jail_cores=cores), language)
    return '%s, num_ctx %s' % (text, hw['num_ctx']) if hw.get('num_ctx') else text


def mixed_shares(rows, language=None):
    """ :return: {share text: [models]} when the compared results ran with different shares of the machine """
    language = report_language(language)
    groups = {}
    for r in rows:
        if share(r.get('hardware')) != (None, None, None):
            groups.setdefault(share_text(r['hardware'], language), set()).add(r['model'])
    return {k: sorted(v) for k, v in groups.items()} if len(groups) > 1 else {}


def fingerprint(hw):
    hw = hw or {}
    return (hw.get('cpu'), hw.get('cores'), round(float(hw.get('ram_gib') or 0)))


def from_firewall(hw):
    """ a measurement counts only when it ran on the firewall: FreeBSD, the jail Ollama on 127.0.0.1 """
    hw = hw or {}
    return hw.get('source') == 'firewall' and hw.get('os') == 'FreeBSD' and '127.0.0.1' in str(hw.get('ollama_url'))


# ------------------------------------------------------------------ steps (child process of the runner)


def _run_json(argv, timeout=120):
    """ last JSON line of a command (manage.py) """
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    for line in reversed((proc.stdout or '').strip().splitlines()):
        line = line.strip()
        if line.startswith('{'):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return {'status': 'error', 'message': (proc.stdout or proc.stderr or 'no output')[-300:]}


def step_pull(st, clock=time.monotonic, sleep=time.sleep):
    """ download a missing model with the change action pull_model (background job of the setup), and wait """
    model = st['model']
    have = tags()
    if model in have:
        return {'already': True, 'model': model, 'size_gib': round((have[model].get('size') or 0) / 2 ** 30, 2),
                'digest': have[model].get('digest')}
    t0 = clock()
    started = _run_json([sys.executable, MANAGE, 'apply', 'pull_model', model, 'custom=yes', 'large=yes'], 300)
    if started.get('status') == 'error':
        msg = str(started.get('message') or 'pull_model failed')
        if re.search(r'busy|lock|another', msg, re.I):
            # another setup job holds the lock: not a result, the runner tries again later
            raise RuntimeError('setup server busy: %s' % msg[:300])
        raise RuntimeError('pull_model %s: %s' % (model, msg[:400]))
    job = started.get('job')
    final = {}
    while clock() - t0 < PULL_MAX_SECONDS:
        sleep(PULL_POLL)
        state = _run_json([sys.executable, MANAGE, 'status', 'setup_job'], 60)
        cur = state.get('job') or {}
        if job and cur.get('id') not in (None, job):
            hist = [h for h in state.get('history') or [] if h.get('id') == job]
            cur = hist[0] if hist else cur
        if cur.get('status') in ('done', 'failed', 'error', 'cancelled', 'blocked'):
            final = cur
            break
        if not job and started.get('status') in ('ok', 'done'):
            final = {'status': 'done'}
            break
    else:
        raise RuntimeError('pull_model %s: timeout after %d s' % (model, PULL_MAX_SECONDS))
    if final.get('status') != 'done':
        res = final.get('result') or {}
        raise RuntimeError('pull_model %s: %s %s' % (model, final.get('status'), str(res.get('message') or '')[:300]))
    have = tags()
    if model not in have:
        raise RuntimeError('pull_model %s finished but Ollama does not list the model' % model)
    return {'already': False, 'model': model, 'job': job, 'seconds': round(clock() - t0, 1),
            'size_gib': round((have[model].get('size') or 0) / 2 ** 30, 2), 'digest': have[model].get('digest')}


def step_setup(st):
    """ the setup of the model under test (read only): /api/tags, /api/show, /api/ps, route, hardware """
    from ai import scenarios as routing_mod
    model = st['model']
    entry = tags().get(model) or {}
    doc = show(model)
    info = doc.get('model_info') or {}
    details = entry.get('details') or doc.get('details') or {}
    arch = str(info.get('general.architecture') or '')
    ram = None
    for m in bench.loaded_models() or []:
        if m.get('name') == model:
            ram = m.get('size_gib')
    mode = classify_think(model, doc)
    cat = CATALOG_BY_MODEL.get(model) or {}
    routes = routing_mod.preset_scenarios('local_only')
    return {
        'model': model, 'digest': entry.get('digest'), 'size_gib': round((entry.get('size') or 0) / 2 ** 30, 2),
        'family': details.get('family'), 'quantization': details.get('quantization_level'),
        'parameter_size': details.get('parameter_size'),
        'params_b': cat.get('params_b') or (round(info.get('general.parameter_count') / 1e9, 1)
                                            if info.get('general.parameter_count') else None),
        'active_b': cat.get('active_b'),
        'experts': info.get('%s.expert_count' % arch), 'experts_used': info.get('%s.expert_used_count' % arch),
        'context_native': info.get('%s.context_length' % arch) or details.get('context_length'),
        'finetune': info.get('general.finetune'), 'capabilities': doc.get('capabilities') or entry.get('capabilities'),
        'think_mode': mode, 'think_eval': think_overrides(mode) or {'think': False},
        'template_head': str(doc.get('template') or '')[-160:],
        'ram_gib': ram, 'routes': {'short': {k: routing_mod.LOCAL_SHORT_ROUTE[k] for k in
                                             ('num_ctx', 'num_predict', 'timeout', 'retries', 'keep_alive', 'budget')},
                                   'long': {k: routing_mod.LOCAL_LONG_ROUTE[k] for k in
                                            ('num_ctx', 'num_predict', 'timeout', 'retries', 'keep_alive', 'budget')},
                                   'brief_timeout': routes['war_room_brief']['timeout'],
                                   'quicktest_timeout': routes['quicktest']['timeout']},
        'temperature': 0.2, 'hardware': hardware(),
    }


def config_factory():
    from ai import AIConfig
    cfg = AIConfig.from_opnsense('OPNsense/policyanalyzer')
    cfg.enabled = True
    cfg.language = 'auto'              # the evaluation is in pt-BR whatever the GUI language is
    return cfg


def step_eval(st):
    """ one run of one fixture through the plugin pipeline (isolated: no audit, no cache, no file writes) """
    from ai import Assistant
    from ai.audit import NullAuditLog
    params = st.get('params') or {}
    fx = eval_fixtures.get(params['fixture'])
    mode = classify_think(st['model'], show(st['model']))
    bench.write_guard()
    overrides = {k: params[k] for k in ('num_ctx', 'num_predict', 'budget', 'timeout', 'retries', 'keep_alive',
                                        'num_thread') if k in params}
    variant = params.get('think') == 'on'
    if not variant:
        overrides.update(think_overrides(mode))
    routing, rec = bench.isolate(st['model'], overrides, recorder=bench.CURRENT)
    if variant:
        # the reasoning goes through the route (think/think_budget) like in production: no "/no_think", think=true
        # only for a model with the thinking capability, num_predict + think_budget (providers/ollama.py)
        for entry in routing['scenarios'].values():
            entry.update(think=THINK_ROUTE['think'], think_budget=THINK_ROUTE['think_budget'])
    cfg = config_factory()
    task, data, ctx = eval_fixtures.build(fx['id'])
    sc = {'subject': fx['subject'], 'language': LANG, 'ctx': ctx}
    if fx['scenario'] in ('war_room_brief', 'war_room_focus'):
        from ai import brief
        sc['post'] = brief.clean_text
    load_before = _loadavg()
    t0 = time.monotonic()
    result, error = {}, None
    try:
        result = Assistant(cfg, app='policyanalyzer', audit=NullAuditLog(), inline=True).ask(
            task, data, language=LANG, subject='eval:%s' % fx['id']) or {}
        if result.get('status', 'ok') != 'ok':
            error = result.get('message') or result.get('status')
    except Exception as exc:          # noqa: BLE001
        error = '%s: %s' % (exc.__class__.__name__, exc)
    doc = bench.summarize_result(fx['scenario'], result, rec, sc, error, time.monotonic() - t0)
    _cpu, rss = bench.ollama_runner()
    doc.update(fixture=fx['id'], rep=params.get('rep'), route=routing['scenarios'].get(fx['scenario']),
               think_mode=mode, think_eval=({'think': THINK_ROUTE['think'], 'think_budget': THINK_ROUTE['think_budget'],
                                             'via': 'route'} if variant else think_overrides(mode) or {'think': False}),
               load_before=load_before, load_after=_loadavg(), runner_rss_gib=rss,
               models_loaded=bench.loaded_models(), blocked_writes=bench.BLOCKED[:20],
               rejected=bool(error and 'rejected' in str(error)))
    return doc


def _loadavg():
    try:
        return round(os.getloadavg()[0], 2)
    except OSError:
        return None


# ------------------------------------------------------------------ scoring of one run


def _norm(text):
    text = unicodedata.normalize('NFKD', str(text or '').lower())
    return ''.join(c for c in text if not unicodedata.combining(c))


IPV4_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
HOST_RE = re.compile(r'\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:lan|local|home|internal|intranet)\b', re.I)
SAFE_IPS = ('0.0.0.0', '127.0.0.1', '255.255.255.255')


def anchoring(text, hay):
    """ what the answer cites that the input does not have: addresses, ports, CVEs, hosts, citations """
    from ai import validate
    low_hay = hay.lower()
    invented = []
    for ip in sorted(set(IPV4_RE.findall(text))):
        if ip not in SAFE_IPS and ip not in hay and all(0 <= int(x) < 256 for x in ip.split('.')):
            invented.append(ip)
    for cve in sorted({c.upper() for c in bench.CVE_RE.findall(text)}):
        if cve.lower() not in low_hay:
            invented.append(cve)
    ports = set()
    for rx in bench.PORT_RES:
        ports.update(p for p in rx.findall(text) if 0 < int(p) < 65536)
    invented += ['port %s' % p for p in sorted(ports, key=int) if not bench._present(p, hay)]
    for host in sorted({h.lower() for h in HOST_RE.findall(text)}):
        if host not in low_hay:
            invented.append(host)
    bad_cites = []
    for cite in validate.CITATION_RE.findall(text):
        name = cite[1:].split(':', 1)[0].strip().lower()
        if name not in low_hay and name.rstrip('s') not in low_hay:
            bad_cites.append(name)
    unsafe = sorted({m.group(0).lower() for m in bench.UNSAFE_RE.finditer(text)})
    n = len(invented) + len(bad_cites)
    score = 0.0 if unsafe else max(0.0, 1.0 - 0.25 * n)
    return score, {'invented': invented[:12], 'invalid_citations': bad_cites[:6], 'unsafe': unsafe}


def decisive(doc, scenario):
    """ the answer's decision, compared between repetitions (stability) """
    text = str(doc.get('text') or '').strip()
    if scenario in ('vuln_review_suggest', 'explain_device'):
        m = re.match(r'^(?:MAPPING|TYPE):\s*([A-Za-z0-9_.-]+)', text)
        return m.group(1).lower() if m else None
    if scenario == 'incident_summary':
        inc = doc.get('incident') or {}
        return '%s/%s' % (','.join(sorted(inc.get('actions') or [])), inc.get('confidence'))
    # 'falha' (failure) is a stored value: it is compared with the metrics of runs already in ai-bench.db
    return 'ok' if not doc.get('error') and text else 'falha'


def coverage(text, fx, doc):
    norm = _norm(text)
    hits = []
    for pat in fx.get('facts') or []:
        hits.append(bool(re.search(_norm(pat), norm)))
    exp = fx.get('expect') or {}
    if 'first_value' in exp:
        hits.append(decisive(doc, fx['scenario']) in [v.lower() for v in exp['first_value']])
    inc = doc.get('incident') or {}
    if 'actions_any' in exp:
        hits.append(any(a in exp['actions_any'] for a in inc.get('actions') or []))
    if 'confidence_in' in exp:
        hits.append(inc.get('confidence') in exp['confidence_in'])
    forbidden = [p for p in fx.get('forbidden') or [] if re.search(_norm(p), norm)]
    score = (sum(hits) / float(len(hits))) if hits else 1.0
    return max(0.0, score - 0.25 * len(forbidden)), {'facts': len(hits), 'found': sum(hits),
                                                      'missing': [p for p, h in zip(fx.get('facts') or [], hits)
                                                                  if not h][:6],
                                                      'forbidden': forbidden}


def size_target(scenario, fx):
    """ (unit, low, high) the answer should respect """
    from ai import scenarios as routing_mod
    checks = (routing_mod.CATALOG.get(scenario) or {}).get('checks') or {}
    if checks.get('words'):
        lo, hi = checks['words']
        if fx.get('max_words'):
            hi = min(hi, fx['max_words'])
        return 'words', lo, hi
    if checks.get('sentences'):
        lo, hi = checks['sentences']
        return 'sentences', lo, hi
    if checks.get('json'):
        return 'summary sentences', 2, 4
    return 'words', 0, fx.get('max_words') or 300


def size_score(doc, scenario, fx):
    from ai import validate
    if doc.get('truncated'):
        return 0.0, {'truncated': True}
    text = str(doc.get('text') or '')
    unit, lo, hi = size_target(scenario, fx)
    if unit == 'sentences':
        n = validate.sentences(text)
    elif unit == 'summary sentences':
        try:
            summary = json.loads(text[text.find('{'):text.rfind('}') + 1]).get('summary') or ''
        except (ValueError, AttributeError):
            summary = ''
        n = validate.sentences(summary)
    else:
        n = validate.words(text)
    if lo <= n <= hi:
        score = 1.0
    elif n < lo:
        score = max(0.0, n / float(lo))
    else:
        score = max(0.0, 1.0 - (n - hi) / float(hi))
    return score, {'unit': unit, 'n': n, 'low': lo, 'high': hi}


def score_run(doc, fixture_id):
    """
    :return: (effectiveness 0-100 without stability, components 0-1, details).  No answer = 0 everywhere.
      validacao   1 = passed the plugin validation (JSON Schema/first line/sections...) at once; 0.6 = only after
                  the correction attempt (it cost a second call); 0 = still wrong
      idioma      strict pt-BR check of the published texts (mixed English also fails)
      raciocinio  no planning notes leaked into the answer
      ancoragem   1 - 0.25 per address, port, CVE, host or citation absent from the input; 0 with unsafe advice
      cobertura   share of the key facts of the fixture found, -0.25 per forbidden claim
      formato     size inside the requested range (linear decay outside), 0 when cut by num_predict
    """
    from ai import validate
    fx = eval_fixtures.get(fixture_id)
    scenario = fx['scenario']
    text = str(doc.get('text') or '')
    comps = {k: 0.0 for k, _w in EFFECT_WEIGHTS if k != 'estabilidade'}
    details = {}
    if doc.get('error') or not text.strip():
        return 0.0, comps, {'error': str(doc.get('error') or 'empty answer')[:300]}
    final = doc.get('problems_final') or []
    fmt = [p for p in final if not p.startswith('the answer is not in') and 'characters' not in p and
           p != validate.REASONING_PROBLEM]
    if fmt or doc.get('json_valid') is False:
        comps['validacao'] = 0.0
    else:
        comps['validacao'] = 0.6 if doc.get('fmt_first_ok') is False else 1.0
    details['problems'] = final[:4]
    comps['idioma'] = 0.0 if validate.check_language(text, LANG, strict=True) else 1.0
    comps['raciocinio'] = 1.0 if text.lstrip().startswith('{') or not validate.leaked_reasoning(text) else 0.0
    comps['ancoragem'], details['anchoring'] = anchoring(text, eval_fixtures.haystack(fixture_id))
    comps['cobertura'], details['coverage'] = coverage(text, fx, doc)
    comps['formato'], details['size'] = size_score(doc, scenario, fx)
    total = sum(w for k, w in EFFECT_WEIGHTS if k != 'estabilidade')
    eff = 100.0 * sum(comps[k] * w for k, w in EFFECT_WEIGHTS if k != 'estabilidade') / total
    return round(eff, 1), {k: round(v, 3) for k, v in comps.items()}, details


def budget_of(scenario):
    """ the time budget of the scenario: the timeout of its route in the local_only preset """
    from ai import scenarios as routing_mod
    entry = routing_mod.preset_scenarios('local_only').get(scenario) or routing_mod.LOCAL_SHORT_ROUTE
    return int(entry.get('timeout') or 600)


def record_run(db, step, doc, eval_id=None):
    """ the runner side of an "eval" step: score it and keep the metrics (also the host samples of the step) """
    ensure(db)
    params = loads(step['params'], {}) if isinstance(step['params'], str) else (step['params'] or {})
    if eval_id is None:
        row = db.execute('SELECT id FROM eval_models WHERE round_id = ? ORDER BY id DESC LIMIT 1',
                         (step['round_id'],)).fetchone()
        if row is None:
            return None
        eval_id = row['id']
    fixture = params.get('fixture') or doc.get('fixture')
    eff, comps, details = score_run(doc, fixture)
    loads_ = [x for x in (doc.get('load_before'), doc.get('load_after')) if x is not None]
    free = []
    for s in db.execute('SELECT data FROM samples WHERE step_id = ?', (step['id'],)):
        d = loads(s['data'], {}) or {}
        if d.get('load'):
            loads_.append(d['load'][0])
        if d.get('mem_free_gib') is not None:
            free.append(d['mem_free_gib'])
    ram = None
    for m in doc.get('models_loaded') or []:
        if m.get('name') == step['model']:
            ram = m.get('size_gib')
    ok = 0 if doc.get('error') or not str(doc.get('text') or '').strip() else 1
    metrics = {'wall_s': doc.get('wall_s'), 'timeout': bool(doc.get('timeout')) or 'timeout' in str(doc.get('error')),
               'gen_tps': doc.get('gen_tps'), 'prompt_tps': doc.get('prompt_tps'),
               'first_token_s': doc.get('first_token_s'), 'prompt_tokens': doc.get('main_prompt_tokens') or
               doc.get('prompt_tokens'), 'gen_tokens': doc.get('gen_tokens'), 'attempts': doc.get('attempts'),
               'truncated': doc.get('truncated'), 'load_max': max(loads_) if loads_ else None,
               'mem_free_min': min(free) if free else None, 'ram_gib': ram, 'rss_gib': doc.get('runner_rss_gib'),
               'decisive': decisive(doc, doc.get('scenario')), 'rejected': doc.get('rejected'),
               'think_mode': doc.get('think_mode'), 'error': str(doc.get('error'))[:300] if doc.get('error') else None,
               'details': details, 'excerpt': bench.mask(doc.get('text'), 240)}
    db.execute('INSERT INTO eval_runs (eval_id, step_id, model, scenario, fixture, rep, ts, ok, effectiveness, '
               'components, metrics) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
               (eval_id, step['id'], step['model'], doc.get('scenario') or step['scenario'], fixture,
                params.get('rep') or doc.get('rep'), bench.now(), ok, eff, dumps(comps), dumps(metrics)))
    db.commit()
    return eff


# ------------------------------------------------------------------ aggregation per scenario


def _lin(value, good, bad):
    """ 1 at <= good, 0 at >= bad, linear between (good < bad) """
    if value is None:
        return None
    if value <= good:
        return 1.0
    if value >= bad:
        return 0.0
    return 1.0 - (value - good) / float(bad - good)


def _log(value, good, bad):
    """ like _lin on a log scale: each doubling of the time costs the same """
    if value is None:
        return None
    if value <= good:
        return 1.0
    if value >= bad:
        return 0.0
    return 1.0 - math.log(value / good) / math.log(bad / good)


def load_bounds(hw=None):
    """ (load that scores 100, load that scores 0) for the share the run had: the threads of the jail alone are
        free, the limit of the guard (bench.load_max) scores 0. 2 threads on 4 cores = (2.0, 3.5) """
    hw = hw or {}
    threads = hw.get('jail_threads')
    if not threads:
        return LOAD_GOOD, bench.LOAD_MAX
    return float(threads), bench.load_max(threads, hw.get('cores'))


def perf_components(scenario, p50, p95, tps, ttft, ram, load, hw=None):
    """ performance components 0-1 (None = not measured; its weight goes to the others) """
    load_good, load_bad = load_bounds(hw)
    budget = budget_of(scenario)
    target = budget / 6.0
    return {'p50': _log(p50, target, budget), 'p95': _lin(p95, 0.5 * budget, budget),
            'tps': None if tps is None else min(1.0, tps / TPS_FULL), 'ttft': _log(ttft, TTFT_GOOD, TTFT_BAD),
            'ram': _lin(ram, RAM_GOOD, RAM_BAD), 'carga': _lin(load, load_good, load_bad)}


def weighted(comps, table):
    have = [(k, w) for k, w in table if comps.get(k) is not None]
    if not have:
        return 0.0
    return 100.0 * sum(comps[k] * w for k, w in have) / float(sum(w for _k, w in have))


def confidence_of(n, sd):
    if n >= 5 and (sd or 0) <= 10:
        return 'alta'
    if n >= 3:
        return 'média' if (sd or 0) <= 20 else 'baixa'
    return 'baixa'


def indication_of(agg):
    """
    indicado      effectiveness >= 80, p95 inside the budget, no timeout, no run in the wrong language or with
                  leaked reasoning, at least 2 runs with an answer
    promissor     effectiveness >= 65 with at most one timeout, or >= 80 with too few runs (an indication that
                  deserves more samples)
    não indicado  the rest
    """
    eff, n_ok = agg['effectiveness'], agg['n_ok']
    if eff >= INDICATED_EFF and agg['p95'] is not None and agg['p95'] <= agg['budget'] and not agg['timeouts'] \
            and not agg['hard_fails'] and n_ok >= 2:
        return 'indicado'
    if (eff >= PROMISING_EFF and agg['timeouts'] <= 1) or (eff >= INDICATED_EFF and n_ok < 2):
        return 'promissor'
    return 'não indicado'


def aggregate(runs, scenario, weights, ram_gib=None, hw=None):
    """ runs: dicts {ok, effectiveness, components, metrics} of one model x scenario -> the result row """
    n = len(runs)
    budget = budget_of(scenario)
    effs = [r['effectiveness'] or 0.0 for r in runs]
    mean_eff = statistics.mean(effs) if effs else 0.0
    sd = statistics.pstdev(effs) if n > 1 else None
    stab = None
    if n > 1:
        votes = {}
        for r in runs:
            votes[r['metrics'].get('decisive')] = votes.get(r['metrics'].get('decisive'), 0) + 1
        agree = max(votes.values()) / float(n)
        stab = (max(0.0, 1.0 - sd / 20.0) + agree) / 2.0
    w_stab = dict(EFFECT_WEIGHTS)['estabilidade'] / 100.0
    eff = mean_eff * (1 - w_stab) + stab * 100.0 * w_stab if stab is not None else mean_eff
    comps = {}
    for key, _w in EFFECT_WEIGHTS:
        vals = [r['components'].get(key) for r in runs if r['components'].get(key) is not None]
        comps[key] = round(statistics.mean(vals), 3) if vals else None
    comps['estabilidade'] = round(stab, 3) if stab is not None else None
    walls = []
    for r in runs:
        m = r['metrics']
        if m.get('timeout'):
            walls.append(float(budget))
        elif m.get('wall_s'):
            walls.append(float(m['wall_s']))
    ok_runs = [r for r in runs if r['ok']]

    def med(key):
        vals = [r['metrics'].get(key) for r in ok_runs if r['metrics'].get(key) is not None]
        return round(statistics.median(vals), 2) if vals else None
    p50 = round(bench.percentile(walls, 50), 1) if walls else None
    p95 = round(bench.percentile(walls, 95), 1) if walls else None
    rams = [r['metrics'].get('ram_gib') for r in runs if r['metrics'].get('ram_gib')]
    ram = max(rams) if rams else ram_gib
    lds = [r['metrics'].get('load_max') for r in runs if r['metrics'].get('load_max') is not None]
    load = round(bench.percentile(lds, 95), 2) if lds else None
    pc = perf_components(scenario, p50, p95, med('gen_tps'), med('first_token_s'), ram, load, hw)
    perf = weighted(pc, PERF_WEIGHTS)
    hard = sum(1 for r in ok_runs if r['components'].get('idioma') == 0 or r['components'].get('raciocinio') == 0)
    agg = {'scenario': scenario, 'n': n, 'n_ok': len(ok_runs), 'effectiveness': round(eff, 1),
           'effectiveness_runs': round(mean_eff, 1), 'sd': round(sd, 1) if sd is not None else None,
           'ci95': round(1.96 * sd / math.sqrt(n), 1) if sd is not None else None,
           'performance': round(perf, 1), 'composite': round(weights['effectiveness'] * eff +
                                                             weights['performance'] * perf, 1),
           'weights': weights, 'components': comps, 'perf_components': {k: (round(v, 3) if v is not None else None)
                                                                        for k, v in pc.items()},
           'p50': p50, 'p95': p95, 'min': round(min(walls), 1) if walls else None,
           'max': round(max(walls), 1) if walls else None, 'budget': budget, 'gen_tps': med('gen_tps'),
           'prompt_tps': med('prompt_tps'), 'first_token_s': med('first_token_s'), 'ram_gib': ram, 'load_p95': load,
           'timeouts': sum(1 for r in runs if r['metrics'].get('timeout')),
           'rejected': sum(1 for r in runs if r['metrics'].get('rejected')), 'hard_fails': hard,
           'attempts': med('attempts'), 'truncated': sum(1 for r in runs if r['metrics'].get('truncated')),
           'prompt_tokens': med('prompt_tokens'), 'gen_tokens': med('gen_tokens')}
    agg['indication'] = indication_of(agg)
    agg['confidence'] = confidence_of(n, agg['sd'])
    return agg


def eval_runs(db, eval_id):
    out = {}
    for r in db.execute('SELECT * FROM eval_runs WHERE eval_id = ? ORDER BY id', (eval_id,)):
        out.setdefault(r['scenario'], []).append({'ok': r['ok'], 'effectiveness': r['effectiveness'],
                                                  'components': loads(r['components'], {}) or {},
                                                  'metrics': loads(r['metrics'], {}) or {}, 'rep': r['rep'],
                                                  'fixture': r['fixture']})
    return out


def finalize(db, eval_id):
    """ aggregates of a finished model evaluation -> eval_results (marked latest), eval_models done """
    ensure(db)
    ev = db.execute('SELECT * FROM eval_models WHERE id = ?', (eval_id,)).fetchone()
    weights = loads(ev['weights'], WEIGHTS) or WEIGHTS
    setup = loads(ev['setup'], {}) or {}
    rows = []
    for scenario, runs in eval_runs(db, eval_id).items():
        agg = aggregate(runs, scenario, weights, setup.get('ram_gib'), loads(ev['hardware'], {}))
        rows.append(agg)
        db.execute('UPDATE eval_results SET latest = 0 WHERE model = ? AND scenario = ?', (ev['model'], scenario))
        db.execute('INSERT INTO eval_results (eval_id, model, digest, scenario, ts, n, n_ok, effectiveness, performance, '
                   'composite, w_eff, w_perf, indication, confidence, ci95, p50, p95, budget, fixtures_version, data, '
                   'latest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)',
                   (eval_id, ev['model'], ev['digest'], scenario, bench.now(), agg['n'], agg['n_ok'],
                    agg['effectiveness'], agg['performance'], agg['composite'], weights['effectiveness'],
                    weights['performance'], agg['indication'], agg['confidence'], agg['ci95'], agg['p50'], agg['p95'],
                    agg['budget'], ev['fixtures_version'], dumps(agg)))
    db.execute('UPDATE eval_models SET latest = 0 WHERE model = ?', (ev['model'],))
    db.execute("UPDATE eval_models SET status = 'done', finished = ?, latest = 1 WHERE id = ?", (bench.now(), eval_id))
    db.commit()
    return rows


# ------------------------------------------------------------------ history (comparison)


def reference_hardware(db):
    """ the hardware of the most recent evaluation measured on the firewall """
    ensure(db)
    for row in db.execute("SELECT hardware FROM eval_models WHERE hardware IS NOT NULL ORDER BY id DESC"):
        hw = loads(row['hardware'], {})
        if from_firewall(hw):
            return hw
    return None


def history(db, weights=None, language=None):
    """
    latest result of every (model, scenario) measured on the firewall with the reference hardware and the current
    fixtures; the composite is recomputed with <weights> (default: the stored ones) so the comparison is fair.
    :return: (rows, discarded)
    """
    ensure(db)
    ref = reference_hardware(db)
    t = texts(language)['discarded']
    rows, discarded = [], []
    for r in db.execute('SELECT res.*, m.hardware AS hardware, m.setup AS setup FROM eval_results res JOIN eval_models '
                        'm ON m.id = res.eval_id WHERE res.latest = 1 ORDER BY res.id'):
        hw = loads(r['hardware'], {}) or {}
        why = None
        if not from_firewall(hw):
            why = t['outside'] % (hw.get('hostname') or hw.get('os') or t['no_hardware'])
        elif ref is not None and fingerprint(hw) != fingerprint(ref):
            why = t['hardware'] % (hw.get('cpu') or '?')
        elif r['fixtures_version'] != eval_fixtures.FIXTURES_VERSION:
            why = t['fixtures'] % r['fixtures_version']
        item = dict(loads(r['data'], {}) or {}, model=r['model'], digest=r['digest'], eval_id=r['eval_id'],
                    ts=r['ts'], hardware=hw)
        if weights:
            item['composite'] = round(weights['effectiveness'] * item['effectiveness'] +
                                      weights['performance'] * item['performance'], 1)
        (discarded if why else rows).append(dict(item, discarded=why) if why else item)
    return rows, discarded


RANK = {'indicado': 0, 'promissor': 1, 'não indicado': 2}


def best_by_scenario(rows):
    """ {scenario: [row, ...] best first}: indication, then composite, then effectiveness, then p50 """
    out = {}
    for r in rows:
        out.setdefault(r['scenario'], []).append(r)
    for sid in out:
        out[sid].sort(key=lambda r: (RANK.get(r['indication'], 3), -r['composite'], -r['effectiveness'],
                                     r.get('p50') or 1e9))
    return out


def recommend(rows, language=None):
    """
    recommendation only (nothing is applied): per scenario the best "indicado" (else the best "promissor", flagged),
    the mode (sync when p95 <= 300 s or the scenario already runs in the background) and a timeout of 1.5 x p95;
    plus a consolidated route of at most 2 models (MAX_LOADED_MODELS=1: every switch costs a cold load).
    """
    from ai import scenarios as routing_mod
    t = texts(language)['recommend']
    best = best_by_scenario(rows)
    per = {}
    for sid in routing_mod.CATALOG:
        items = [r for r in best.get(sid) or [] if r['indication'] in ('indicado', 'promissor')]
        if not items:
            per[sid] = {'model': None, 'indication': 'nenhum', 'why': t['none']}
            continue
        r = items[0]
        meta = routing_mod.CATALOG[sid]
        mode = 'sync' if meta.get('background') or (r.get('p95') or 0) <= 300 else 'queue'
        timeout = int(min(routing_mod.MAX_TIMEOUT, max(120, math.ceil((r.get('p95') or 60) * 1.5 / 60.0) * 60)))
        base = routing_mod.LOCAL_SHORT_ROUTE if meta['kind'] == 'short' else routing_mod.LOCAL_LONG_ROUTE
        num_predict = base['num_predict'] * (2 if r.get('truncated') else 1)
        per[sid] = {'model': r['model'], 'indication': r['indication'], 'composite': r['composite'],
                    'effectiveness': r['effectiveness'], 'p95': r.get('p95'), 'mode': mode, 'timeout': timeout,
                    'num_predict': num_predict, 'confidence': r.get('confidence'),
                    'why': t['why'] % (r['composite'], r['effectiveness'], r['performance'],
                                       bench.fmt_num(r.get('p95')))}
    models = sorted({r['model'] for r in rows})
    by = {(r['model'], r['scenario']): r for r in rows}
    best_pair, best_total = None, -1.0
    for i, a in enumerate(models):
        for b in models[i:]:
            total = 0.0
            for sid in routing_mod.CATALOG:
                cands = [by.get((m, sid)) for m in {a, b}]
                cands = [c for c in cands if c and c['indication'] != 'não indicado']
                total += max([c['composite'] for c in cands] or [0.0])
            if total > best_total:
                best_pair, best_total = (a, b), total
    consolidated = {}
    if best_pair:
        for sid in routing_mod.CATALOG:
            cands = [by.get((m, sid)) for m in set(best_pair)]
            cands = [c for c in cands if c and c['indication'] != 'não indicado']
            consolidated[sid] = max(cands, key=lambda c: c['composite'])['model'] if cands else None
    return {'per_scenario': per, 'pair': list(best_pair) if best_pair else [], 'consolidated': consolidated}


# ------------------------------------------------------------------ runner hooks (bench.Runner)


def expand_model(db, plan, rnd):
    """ the steps of one model: pull when missing, cold load, setup, the fixtures x reps (rep-major), unload """
    ensure(db)
    from ai import scenarios as routing_mod
    label = rnd['name'][len(ROUND_PREFIX):]
    opts = options(db, plan['id'])
    think = bool(opts.get('think')) or label.endswith(THINK_SUFFIX)
    model = label[:-len(THINK_SUFFIX)] if label.endswith(THINK_SUFFIX) else label
    label = model + (THINK_SUFFIX if think else '')
    have = tags()
    weights = weights_of(opts)
    if model in have and not opts.get('reeval'):
        prev = db.execute("SELECT * FROM eval_models WHERE model = ? AND status = 'done' AND latest = 1 AND digest = ? "
                          "AND fixtures_version = ? AND reps >= ? ORDER BY id DESC LIMIT 1",
                          (label, have[model].get('digest'), eval_fixtures.FIXTURES_VERSION,
                           int(opts.get('reps') or DEFAULT_REPS))).fetchone()
        if prev is not None and from_firewall(loads(prev['hardware'], {})):
            bench.event(db, 'eval', '%s already evaluated (digest %s, evaluation #%d): skipped; use "reeval" to run it again'
                        % (label, str(prev['digest'])[:12], prev['id']))
            return []
    if model not in have and (CATALOG_BY_MODEL.get(model) or {}).get('installed_only'):
        bench.event(db, 'eval', '%s is not installed and is not in the registry: skipped' % model)
        return []
    cur = db.execute("INSERT INTO eval_models (plan_id, round_id, model, digest, status, started, reps, weights, "
                     "fixtures_version, options) VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?, ?)",
                     (plan['id'], rnd['id'], label, (have.get(model) or {}).get('digest'), bench.now(),
                      int(opts.get('reps') or DEFAULT_REPS), dumps(weights), eval_fixtures.FIXTURES_VERSION,
                      dumps(opts)))
    db.commit()
    steps = []
    if model not in have:
        steps.append({'kind': 'pull', 'model': model, 'params': {'tag': 'eval', 'eval_id': cur.lastrowid}})
    steps += [{'kind': 'unload'},
              {'kind': 'load', 'model': model, 'params': {'label': 'cold', 'num_ctx': 8192, 'tag': 'eval'}},
              {'kind': 'eval_setup', 'model': model, 'params': {'tag': 'eval', 'eval_id': cur.lastrowid}}]
    routes = routing_mod.preset_scenarios('local_only')
    for rep in range(1, int(opts.get('reps') or DEFAULT_REPS) + 1):
        for fx in eval_fixtures.FIXTURES:
            if opts.get('scenarios') and fx['scenario'] not in opts['scenarios']:
                continue
            route = routes.get(fx['scenario']) or {}
            params = {'tag': 'eval', 'fixture': fx['id'], 'rep': rep, 'eval_id': cur.lastrowid,
                      'timeout': route.get('timeout')}
            if think:
                params.update(think='on', timeout=THINK_ROUTE['timeout'], num_ctx=THINK_ROUTE['num_ctx'])
            steps.append({'kind': 'eval', 'model': model, 'scenario': fx['scenario'], 'variant': rep,
                          'params': params})
    steps.append({'kind': 'unload', 'model': model})
    return steps


def eval_id_of(db, step):
    params = loads(step['params'], {}) if isinstance(step['params'], str) else (step['params'] or {})
    if params.get('eval_id'):
        return params['eval_id']
    row = db.execute('SELECT id FROM eval_models WHERE round_id = ? ORDER BY id DESC LIMIT 1',
                     (step['round_id'],)).fetchone()
    return row['id'] if row else None


def should_skip(db, step):
    """ :return: reason to skip a step of an evaluation round (download failed, early stop), or None """
    ensure(db)
    if step['kind'] not in ('eval', 'eval_setup', 'load'):
        return None
    failed_pull = db.execute("SELECT 1 FROM steps WHERE round_id = ? AND kind = 'pull' AND status = 'error'",
                             (step['round_id'],)).fetchone()
    if failed_pull:
        return 'model download failed'
    if step['kind'] != 'eval':
        return None
    eid = eval_id_of(db, step)
    if eid is None:
        return None
    prev = db.execute('SELECT ok FROM eval_runs WHERE eval_id = ? AND scenario = ? ORDER BY id', (eid, step['scenario'])
                      ).fetchall()
    if len(prev) >= 2 and not any(r['ok'] for r in prev):
        return 'early stop: %d runs in a row without an answer in this scenario' % len(prev)
    params = loads(step['params'], {}) or {}
    if (params.get('rep') or 1) >= 2:
        first = db.execute('SELECT ok FROM eval_runs WHERE eval_id = ? AND rep = 1', (eid,)).fetchall()
        if len(first) >= 10 and sum(1 for r in first if not r['ok']) >= 0.8 * len(first):
            return 'early stop: the model did not answer %d of %d scenarios in the 1st repetition' % (
                sum(1 for r in first if not r['ok']), len(first))
    return None


def on_step_done(db, step, result):
    """ the runner stored a finished step of an evaluation round """
    ensure(db)
    eid = eval_id_of(db, step)
    if eid is None or not isinstance(result, dict):
        return
    if step['kind'] == 'eval_setup':
        db.execute('UPDATE eval_models SET setup = ?, hardware = ?, digest = COALESCE(?, digest) WHERE id = ?',
                   (dumps(result), dumps(result.get('hardware') or {}), result.get('digest'), eid))
        db.commit()
    elif step['kind'] == 'pull':
        bench.event(db, 'eval', 'model %s %s (%s GiB)' % (step['model'], 'was already installed' if result.get('already')
                                                            else 'downloaded in %s s' % result.get('seconds'),
                                                            result.get('size_gib')))
        if result.get('digest'):
            db.execute('UPDATE eval_models SET digest = ? WHERE id = ?', (result['digest'], eid))
            db.commit()
    elif step['kind'] == 'eval' and not result.get('skipped'):
        record_run(db, step, result, eid)


def round_summary(db, plan, rnd, language=None):
    """ end of one model: aggregates, PDF on disk, e-mail text; None when the model was skipped """
    ensure(db)
    t = texts(language)
    lang = t['_lang']
    m = t['round']
    ev = db.execute('SELECT * FROM eval_models WHERE round_id = ? ORDER BY id DESC LIMIT 1', (rnd['id'],)).fetchone()
    if ev is None:
        return None
    runs = db.execute('SELECT COUNT(*) AS n FROM eval_runs WHERE eval_id = ?', (ev['id'],)).fetchone()['n']
    if not runs:
        db.execute("UPDATE eval_models SET status = 'failed', finished = ? WHERE id = ?", (bench.now(), ev['id']))
        db.commit()
        err = db.execute("SELECT error FROM steps WHERE round_id = ? AND status IN ('error', 'skipped') AND error IS NOT "
                         "NULL ORDER BY id LIMIT 1", (rnd['id'],)).fetchone()
        return ('FALHA', m['failed_title'] % ev['model'],
                m['failed'] % (ev['model'], (err['error'] if err else m['no_run'])) + '\n\n' +
                progress_text(db, plan, True, lang))
    rows = finalize(db, ev['id'])
    attachments = []
    try:
        from ai import eval_pdf
        name, data = eval_pdf.model_pdf(db, ev['id'], lang)
        path = save_pdf(name, data)
        db.execute('UPDATE eval_models SET pdf_path = ? WHERE id = ?', (path, ev['id']))
        db.commit()
        attachments.append(path)
    except Exception as exc:          # noqa: BLE001 - the e-mail goes anyway; "evaluate.py pdf" rebuilds it
        bench.event(db, 'eval_error', 'PDF of %s not generated: %s' % (ev['model'], exc))
    counts = {k: sum(1 for r in rows if r['indication'] == k) for k in INDICATIONS}
    hw = loads(ev['hardware'], {}) or {}
    lines = [m['finished'] % (ev['model'], len(rows), runs),
             m['counts'] % (counts['indicado'], counts['promissor'], counts['não indicado']),
             m['average'] % (
                 statistics.mean(r['composite'] for r in rows), statistics.mean(r['effectiveness'] for r in rows),
                 rows[0]['weights']['effectiveness'], statistics.mean(r['performance'] for r in rows),
                 rows[0]['weights']['performance']) if rows else m['no_aggregates'],
             m['hardware'] % hardware_line(hw, lang), '']
    lines.append(progress_text(db, plan, True, lang))
    status = 'OK' if counts['indicado'] or counts['promissor'] else 'INFO'
    return status, m['title'] % ev['model'], '\n'.join(lines), attachments


def hardware_line(hw, language=None):
    hw = hw or {}
    from ai import compute
    texts_ = texts(language)
    t, lang = texts_['hardware'], texts_['_lang']
    jail = share_text(hw, lang)
    memory = compute.memory_text(hw, lang)
    return t['line'] % (
        hw.get('cpu') or '?', hw.get('cores') or '?', ' (%s)' % hw['simd'] if hw.get('simd') else '', memory,
        t['jail'] % jail if jail else '', hw.get('ollama_version') or '?',
        hw.get('hostname') or '?', '' if from_firewall(hw) else t['outside'])


def save_pdf(name, data):
    os.makedirs(EVAL_DIR, mode=0o750, exist_ok=True)
    path = os.path.join(EVAL_DIR, name)
    with open(path, 'wb') as handle:
        handle.write(data)
    os.chmod(path, 0o640)
    return path


def scoreboard_text(db, limit_models=None, language=None):
    """ the text table of the e-mails: best model per scenario so far, and whether there is an indication """
    from ai import scenarios as routing_mod
    t = texts(language)
    b = t['scoreboard']
    rows, discarded = history(db, language=t['_lang'])
    best = best_by_scenario(rows)
    lines = ['%-22s %-36s %5s  %-15s %s' % (b['scenario'], b['best'], b['score'], b['indication'], b['hint'])]
    for sid in routing_mod.CATALOG:
        items = best.get(sid) or []
        if not items:
            lines.append('%-22s %-36s %5s  %-15s %s' % (sid, '—', '—', '—', b['not_measured']))
            continue
        top = items[0]
        lines.append('%-22s %-36s %5.0f  %-15s %s' % (sid, top['model'][:36], top['composite'],
                                                      t['_eval']['indication'].get(top['indication'],
                                                                                   top['indication']),
                                                      b['hints'].get(top['indication'], '')))
    if discarded:
        lines.append('')
        lines.append(b['discarded'] % len(discarded))
    return '\n'.join(lines)


def progress_text(db, plan, finishing=False, language=None):
    """ :param finishing: called while the current round is closing (it counts as done) """
    rounds = db.execute('SELECT * FROM rounds WHERE plan_id = ? ORDER BY idx', (plan['id'],)).fetchall()
    done = [r for r in rounds if r['status'] == 'done']
    left = [r['name'][len(ROUND_PREFIX):] for r in rounds if r['status'] != 'done']
    if finishing and left:
        left = left[1:]
    t = texts(language)['progress']
    out = [t['done'] % (len(rounds) - len(left), len(rounds))]
    if left:
        out.append(t['next'] % (', '.join(left[:5]) + (' …' if len(left) > 5 else '')))
    out += ['', t['comparison'], scoreboard_text(db, language=language)]
    return '\n'.join(out)


def start_mail(db, plan, language=None):
    t = texts(language)['start']
    opts = options(db, plan['id'])
    models = [r['name'][len(ROUND_PREFIX):] for r in
              db.execute('SELECT name FROM rounds WHERE plan_id = ? ORDER BY idx', (plan['id'],))]
    have = tags()
    est = estimate(models, opts, have)
    lines = [t['started'] % plan['id'],
             t['models'] % ', '.join('%s%s' % (m, '' if m in have else t['download']) for m in models),
             t['fixtures'] % (len(eval_fixtures.FIXTURES), opts.get('reps') or DEFAULT_REPS,
                              weights_of(opts)['effectiveness'], weights_of(opts)['performance']),
             t['estimate'] % (est['hours'], est['download_gib'], est['download_hours']),
             t['mails']]
    return 'INFO', t['title'], '\n'.join(lines)


def final_mail(db, plan, language=None):
    t = texts(language)
    lang = t['_lang']
    f = t['final']
    rows, discarded = history(db, language=lang)
    rec = recommend(rows, language=lang)
    lines = [f['finished'] % plan['id'], '', f['ranking'], scoreboard_text(db, language=lang), '', f['route']]
    for sid, r in rec['per_scenario'].items():
        if r.get('model'):
            lines.append('  %-22s %-36s %-6s timeout %4d  (%s%s)' % (
                sid, r['model'][:36], r['mode'], r['timeout'],
                t['_eval']['indication'].get(r['indication'], r['indication']),
                '' if r['indication'] == 'indicado' else f['check']))
        else:
            lines.append('  %-22s %s' % (sid, f['keep'] % r['why']))
    if rec['pair']:
        lines += ['', f['pair'] % ' + '.join(rec['pair'])]
    lines += ['', f['apply']]
    attachments = []
    try:
        from ai import eval_pdf
        name, data = eval_pdf.final_pdf(db, plan['id'], lang)
        attachments.append(save_pdf(name, data))
    except Exception as exc:          # noqa: BLE001
        bench.event(db, 'eval_error', 'final PDF not generated: %s' % exc)
    return lines, attachments


# ------------------------------------------------------------------ estimates, candidates, status


def est_run_seconds(entry, fx, think='none'):
    """ rough time of one run on the N100 (calibrated on the bench of 08-09/11: qwen2.5:3b ~18 tok/s reading,
    ~6 tok/s writing; speed falls with the active parameters, a little with the total size of MoE models) """
    from ai import scenarios as routing_mod
    task, data, _ctx = eval_fixtures.build(fx['id'])
    prompt = 380 + (len(task.instructions) + len(json.dumps(data, ensure_ascii=False))) / 3.3
    kind = (routing_mod.CATALOG.get(fx['scenario']) or {}).get('kind', 'short')
    gen = 260 if kind == 'short' else 420
    gen += {'harmony': 500, 'forced': 2000}.get(think, 0)
    eff_b = (entry.get('active_b') or entry.get('params_b') or 8.0) + 0.05 * (entry.get('params_b') or 8.0)
    ptps = 18.0 * 3.25 / eff_b
    gtps = 6.0 * 3.25 / eff_b
    return 1.2 * (prompt / ptps + gen / gtps)


def estimate(models, opts=None, have=None):
    opts = opts or parse_options([])
    have = have if have is not None else {}
    reps = int(opts.get('reps') or DEFAULT_REPS)
    total, dl, per = 0.0, 0.0, {}
    for m in models:
        entry = CATALOG_BY_MODEL.get(m) or {'params_b': 8.0, 'active_b': 8.0, 'size_gib': 5.0, 'think': 'none'}
        sec = sum(est_run_seconds(entry, fx, entry.get('think', 'none')) for fx in eval_fixtures.FIXTURES) * reps + 120
        per[m] = round(sec / 3600.0, 1)
        total += sec
        if m not in have and not entry.get('installed_only'):
            dl += entry.get('size_gib') or 0
    return {'hours': round(total / 3600.0, 1), 'per_model_hours': per, 'download_gib': round(dl, 1),
            'download_hours': round(dl * 1024 / 10.0 / 3600.0, 1)}


def cmd_candidates():
    have = tags()
    est = estimate([c['model'] for c in CANDIDATES], None, have)
    items = []
    for c in CANDIDATES:
        t = have.get(c['model'])
        items.append(dict(c, installed=bool(t), installed_size_gib=round((t or {}).get('size', 0) / 2 ** 30, 2) or None,
                          digest=(t or {}).get('digest'), estimated_hours=est['per_model_hours'][c['model']],
                          fits_ram=c['size_gib'] * 1.1 + 2 <= RAM_TOTAL_GIB - 8))
    return {'status': 'ok', 'candidates': items, 'estimate': est, 'fixtures': len(eval_fixtures.FIXTURES),
            'fixtures_version': eval_fixtures.FIXTURES_VERSION}


def cmd_status(db=None):
    db = ensure(db or bench.connect())
    plan = db.execute("SELECT * FROM plans WHERE name = ? AND imported = 0 ORDER BY id DESC LIMIT 1", (PLAN,)).fetchone()
    out = {'status': 'ok', 'plan': dict(plan) if plan else None, 'models': []}
    if plan is not None:
        for ev in db.execute('SELECT id, model, status, digest, started, finished, pdf_path FROM eval_models WHERE '
                             'plan_id = ? ORDER BY id', (plan['id'],)):
            n = db.execute('SELECT COUNT(*) AS n, SUM(ok) AS ok FROM eval_runs WHERE eval_id = ?', (ev['id'],)).fetchone()
            out['models'].append(dict(ev, runs=n['n'], ok=n['ok'] or 0))
        out['progress'] = progress_text(db, plan)
    rows, discarded = history(db)
    out['best'] = {sid: {'model': items[0]['model'], 'composite': items[0]['composite'],
                         'indication': items[0]['indication']} for sid, items in best_by_scenario(rows).items()}
    out['discarded'] = len(discarded)
    out['reference_hardware'] = reference_hardware(db)
    return out


def report_md(db=None, language=None):
    """ the comparison for docs/ia-local-catalogo.md (section "Per scenario evaluation") """
    from ai import scenarios as routing_mod
    db = ensure(db or bench.connect())
    t = texts(language, 'eval_md')
    lang = t['_lang']
    ind = t['_eval']['indication']
    rows, discarded = history(db, language=lang)
    best = best_by_scenario(rows)
    rec = recommend(rows, language=lang)
    hw = reference_hardware(db)
    L = [t['title'], '', t['intro'] % (bench.iso(), hardware_line(hw, lang) if hw else t['no_measurement'],
                                       WEIGHTS['effectiveness'], WEIGHTS['performance'],
                                       eval_fixtures.FIXTURES_VERSION), '']
    mixed = mixed_shares(rows, lang)
    if mixed:
        L += [t['mixed'] % '; '.join('%s (%s)' % (k, ', '.join(v)) for k, v in sorted(mixed.items())), '']
    models = sorted({r['model'] for r in rows})
    if not rows:
        L += [t['no_rows'], '']
    else:
        L += [t['ranking'], '', t['ranking_head'], '|---|---|---|---|']
        for sid in routing_mod.CATALOG:
            cells = ['%s — %.0f (%s)' % (r['model'], r['composite'], ind.get(r['indication'], r['indication']))
                     for r in (best.get(sid) or [])[:3]]
            L.append('| %s | %s |' % (sid, ' | '.join(cells + ['—'] * (3 - len(cells)))))
        letters = t['letters']
        L += ['', t['matrix'], '', t['matrix_head'] % ' | '.join(models), '|---|' + '---|' * len(models)]
        by = {(r['model'], r['scenario']): r for r in rows}
        for sid in routing_mod.CATALOG:
            cells = []
            for m in models:
                r = by.get((m, sid))
                cells.append('%s (%.0f)' % (letters.get(r['indication'], letters['não indicado']), r['composite'])
                             if r else '—')
            L.append('| %s | %s |' % (sid, ' | '.join(cells)))
        L += ['', t['per_model'], '', t['per_model_head'], '|---|---:|---:|---:|---:|---:|---:|---:|']
        for m in models:
            mr = [r for r in rows if r['model'] == m]
            L.append('| %s | %d | %.0f | %.0f | %.0f | %s | %s | %s |' % (
                m, len(mr), statistics.mean(r['effectiveness'] for r in mr),
                statistics.mean(r['performance'] for r in mr), statistics.mean(r['composite'] for r in mr),
                bench.fmt_num(statistics.mean([r['p50'] for r in mr if r.get('p50')] or [0])),
                bench.fmt_num(statistics.median([r['gen_tps'] for r in mr if r.get('gen_tps')] or [0]), 1),
                bench.fmt_num(max([r['ram_gib'] for r in mr if r.get('ram_gib')] or [0]), 1)))
    L += ['', t['route'], '', t['route_head'], '|---|---|---|---|---:|---:|---|']
    for sid, r in rec['per_scenario'].items():
        L.append('| %s | %s | %s | %s | %s | %s | %s |' % (sid, r.get('model') or '—',
                                                           ind.get(r.get('indication'), r.get('indication')),
                                                           r.get('mode') or '—', bench.fmt_num(r.get('timeout')),
                                                           bench.fmt_num(r.get('num_predict')), r.get('why')))
    if rec['pair']:
        L += ['', t['pair'] % ' + '.join(rec['pair'])]
    if discarded:
        L += ['', t['discarded'] % (len(discarded), '; '.join(
            '%s/%s (%s)' % (d['model'], d['scenario'], d['discarded']) for d in discarded[:10]))]
    return '\n'.join(L) + '\n'


def report_json(db=None):
    db = ensure(db or bench.connect())
    rows, discarded = history(db)
    return {'status': 'ok', 'rows': rows, 'discarded': discarded, 'recommend': recommend(rows),
            'reference_hardware': reference_hardware(db)}


def cmd_pdf(target, out=None, db=None):
    from ai import eval_pdf
    db = ensure(db or bench.connect())
    if target == 'final':
        plan = db.execute("SELECT id FROM plans WHERE name = ? ORDER BY id DESC LIMIT 1", (PLAN,)).fetchone()
        name, data = eval_pdf.final_pdf(db, plan['id'] if plan else None)
    else:
        ev = db.execute("SELECT id FROM eval_models WHERE model = ? AND status = 'done' ORDER BY id DESC LIMIT 1",
                        (target,)).fetchone()
        if ev is None:
            return {'status': 'error', 'message': 'no finished evaluation of %s' % target}
        name, data = eval_pdf.model_pdf(db, ev['id'])
    if out:
        with open(out, 'wb') as handle:
            handle.write(data)
        path = out
    else:
        path = save_pdf(name, data)
    return {'status': 'ok', 'path': path, 'bytes': len(data)}


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    args = [a for a in argv[2:] if a]
    try:
        if cmd == 'candidates':
            bench.emit(cmd_candidates())
        elif cmd == 'status':
            bench.emit(cmd_status())
        elif cmd == 'report':
            if args and args[0] == 'json':
                bench.emit(report_json())
            else:
                sys.stdout.write(report_md())
        elif cmd == 'pdf' and args:
            bench.emit(cmd_pdf(args[0], args[1] if len(args) > 1 else None))
        else:
            bench.emit({'status': 'error', 'message': 'usage: evaluate.py candidates|status|report [md|json]|'
                                                      'pdf <model|final> [file]  (start/stop: bench.py start '
                                                      'avaliacao [reps=N] [only=a,b] [reeval])'})
            return 1
    except (OSError, ValueError, KeyError) as exc:
        bench.emit({'status': 'error', 'message': str(exc)})
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
