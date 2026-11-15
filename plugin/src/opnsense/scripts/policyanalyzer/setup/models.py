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

    Models: pull (registry manifest + SHA256-verified blobs, written by the
    host into /var/db/ai/models; the jail has no network), remove and the
    benchmark.

    Why not /api/pull: the jail is loopback only (no egress), so Ollama itself
    can not reach registry.ollama.ai.  The host downloads exactly what
    /api/pull would (same manifest, same blobs, same on-disk layout) and
    reports progress in the same shape ({status, digest, total, completed}).
"""

import json
import os
import time

from . import common
from . import ops
from .common import SetupError

MANIFEST_ACCEPT = 'application/vnd.docker.distribution.manifest.v2+json'
LARGE_MODEL_BYTES = 6 * common.GIB

# allowed without +custom: every candidate of the recommendation table (setup/recommend.py), so the
# recommended model can be pulled directly
def _allowed():
    from .recommend import CANDIDATES
    return {name: {'size_hint': data[0]} for name, data in CANDIDATES.items()}


ALLOWED_MODELS = _allowed()

BENCH_PROMPT = (
    'You are a firewall policy assistant. In at most 60 words, explain to an OPNsense administrator why a '
    'rule that is shadowed by an earlier broader rule never matches, and what to do about it.')


def validate(args):
    name = args.get('model') or args.get('name')
    base, tag = common.validate_model(name or '')
    full = '%s:%s' % (base, tag)
    custom = common.as_bool(args.get('custom'), False, 'custom')
    if full not in ALLOWED_MODELS and not custom:
        raise ValueError('model %s is not in the recommended list; pass custom=yes to allow any library model' % full)
    return base, tag, full, custom


def fetch_manifest(ctx, base, tag):
    url = '%s/v2/library/%s/manifests/%s' % (common.OLLAMA_REGISTRY, base, tag)
    raw = ctx.http.get_bytes(url, headers={'Accept': MANIFEST_ACCEPT}, timeout=20, limit=256 * 1024)
    text = raw.decode('utf-8')
    manifest = json.loads(text)
    if not isinstance(manifest, dict) or manifest.get('schemaVersion') != 2 or not manifest.get('layers'):
        raise SetupError('unexpected manifest for %s:%s' % (base, tag))
    for digest, size in ops.manifest_digests(manifest):
        ops._check_digest(digest)
        if size <= 0:
            raise SetupError('invalid layer size in manifest')
    return text, manifest


def pull_plan(ctx, args):
    base, tag, full, custom = validate(args)
    allow_large = common.as_bool(args.get('large'), False, 'large')
    errors, warnings = [], []
    try:
        raw, manifest = fetch_manifest(ctx, base, tag)
    except Exception as exc:                    # noqa: BLE001
        errors.append('could not read the manifest of %s from registry.ollama.ai: %s' % (full, exc))
        raw, manifest = None, {'layers': []}
    digests = ops.manifest_digests(manifest)
    total = sum(size for _, size in digests)
    missing = sum(size for d, size in digests if not os.path.isfile(ops.blob_path(ctx, d)))
    if manifest.get('layers') and total > LARGE_MODEL_BYTES and not allow_large:
        errors.append('%s is %s (> 6 GiB); pass large=yes to allow large models on this firewall'
                      % (full, common.fmt_bytes(total)))
    # blob sizes come from the manifest; the 20 % margin covers the staging copy and Ollama's own files
    space = common.space_check(ctx, ctx.models_dir, missing, 'model %s' % full)
    errors += space['errors']
    warnings += space['warnings']
    free = space['free']
    if custom:
        warnings.append('custom model outside the recommended list: speed and pt-BR quality not evaluated')
    if not os.path.isdir(ctx.models_dir):
        errors.append('%s does not exist (prepare the storage first)' % ctx.models_dir)
    from .runtime import probe
    info = probe(ctx)
    if not info['installed']:
        warnings.append('runtime not installed yet: the model is stored and becomes available once it is')
    steps = [
        {'type': 'mkdir', 'path': ctx.staging_dir, 'mode': '0750', 'argv': ['/bin/mkdir', '-p', ctx.staging_dir],
         'description': 'Create staging directory'},
        {'type': 'model_pull', 'model': base, 'tag': tag, 'manifest': raw, 'uid': common.JAIL_SERVICE_UID,
         'download_bytes': missing, 'space_bytes': missing,
         'argv': ['GET', '%s/v2/library/%s/blobs/<digest>' % (common.OLLAMA_REGISTRY, base)],
         'command': 'download %d blob(s) of %s from registry.ollama.ai, verify SHA256, write manifest'
                    % (len(digests), full),
         'description': 'Download model %s (%s, %s still missing)' % (full, common.fmt_bytes(total),
                                                                     common.fmt_bytes(missing)),
         'effect': 'files in /var/db/ai/models (blobs/sha256-*, manifests/registry.ollama.ai/library/%s/%s); '
                   'progress in setup-state.json; cancel with "apply cancel"' % (base, tag),
         'undo': 'manifest and the blobs added by this pull are deleted'},
    ]
    if info['running']:
        steps.append({'type': 'wait_http', 'url': common.OLLAMA_URL + '/api/tags', 'timeout': 30,
                      'description': 'Check that Ollama answers (model list)'})
    return {'steps': steps, 'errors': errors, 'warnings': warnings,
            'irreversible': ['%s downloaded from registry.ollama.ai' % common.fmt_bytes(missing)] if missing else [],
            'download_bytes': missing, 'space_needed': missing, 'space_free': free, 'space_path': ctx.models_dir,
            'undo': 'Revert deletes %s and the blobs it added (blobs shared with other models are kept)' % full,
            'resources': ['model:' + full], 'risk': 'low', 'background': True,
            'args': {'model': full, 'custom': custom, 'large': allow_large},
            'model': {'name': full, 'size': total, 'layers': len(digests)}}


def remove_plan(ctx, args):
    name = args.get('model') or args.get('name')
    base, tag = common.validate_model(name or '')
    full = '%s:%s' % (base, tag)
    manifest_file = ops.model_manifest_path(ctx, base, tag)
    manifest = common.read_json(manifest_file)
    errors, warnings = [], []
    if manifest is None:
        errors.append('model %s is not installed' % full)
        manifest = {}
    keep = ops.referenced_digests(ctx, exclude=(base, tag))
    digests = ops.manifest_digests(manifest)
    freed = sum(size for d, size in digests if d not in keep and os.path.isfile(ops.blob_path(ctx, d)))
    from .runtime import probe
    if probe(ctx)['running']:
        warnings.append('if %s is loaded in Ollama its memory is released at the next unload (keep-alive)' % full)
    return {'steps': [{'type': 'model_remove', 'model': base, 'tag': tag, 'uid': common.JAIL_SERVICE_UID,
                       'command': 'delete manifest %s and %d unshared blob(s)' % (full, sum(1 for d, _ in digests
                                                                                         if d not in keep)),
                       'description': 'Remove model %s (frees %s)' % (full, common.fmt_bytes(freed)),
                       'effect': 'blobs shared with other models are kept',
                       'undo': 'download the same digests again'}],
            'errors': errors, 'warnings': warnings,
            'irreversible': ['undoing this downloads %s again from registry.ollama.ai' % common.fmt_bytes(freed)]
            if freed else [],
            'download_bytes': 0, 'space_freed': freed,
            'undo': 'Revert downloads exactly the removed manifest again (%s)' % common.fmt_bytes(freed),
            'resources': ['model:' + full], 'risk': 'low', 'background': False, 'args': {'model': full}}


# ------------------------------------------------------------------ benchmark


def benchmark_plan(ctx, args):
    from .runtime import probe, current_limits
    info = probe(ctx)
    limits = dict(common.DEFAULT_LIMITS)
    limits.update(current_limits(ctx))
    errors = []
    model = args.get('model') or args.get('name')
    if model:
        base, tag = common.validate_model(model)
        model = '%s:%s' % (base, tag)
    else:
        installed = sorted(ops.installed_manifests(ctx))
        model = '%s:%s' % installed[0] if installed else None
    if not info['running']:
        errors.append('runtime is not running (start_runtime)')
    if not model:
        errors.append('no model installed (pull_model)')
    elif not os.path.isfile(ops.model_manifest_path(ctx, *model.split(':', 1))):
        errors.append('model %s is not installed' % model)
    return {'steps': [{'type': 'benchmark', 'model': model, 'threads': limits['threads'], 'ctx': limits['ctx'],
                       'argv': ['POST', common.OLLAMA_URL + '/api/generate'],
                       'command': 'POST %s/api/generate (fixed prompt, num_predict 128, num_thread %d)'
                                  % (common.OLLAMA_URL, limits['threads']),
                       'description': 'Benchmark %s: prompt and generation tokens/s, RAM' % (model or '?'),
                       'effect': 'loads the model (RAM) and uses the jail cpus for about 30-120 s; the model is '
                                 'unloaded after the keep-alive (%s)' % limits['keep_alive']}],
            'errors': errors, 'warnings': [], 'irreversible': [],
            'undo': 'nothing to undo (only %s is written)' % ctx.bench_file,
            'resources': [], 'risk': 'low', 'background': True, 'changes': False,
            'args': {'model': model}}


def run_benchmark(ctx, step):
    body = {'model': step['model'], 'prompt': BENCH_PROMPT, 'stream': False, 'think': False,
            'options': {'num_thread': step['threads'], 'num_ctx': min(step['ctx'], 4096), 'num_predict': 128,
                        'temperature': 0.2, 'seed': 42}}
    started = time.time()
    result = ctx.http.get_json(common.OLLAMA_URL + '/api/generate', timeout=900, body=body) or {}
    wall = time.time() - started
    ns = 1e9

    def rate(count, duration):
        return round(count / (duration / ns), 2) if count and duration else None
    ram = None
    try:
        ps = ctx.http.get_json(common.OLLAMA_URL + '/api/ps', timeout=5) or {}
        for item in ps.get('models') or []:
            if item.get('name') == step['model'] or item.get('model') == step['model']:
                ram = item.get('size')
    except Exception:                           # noqa: BLE001
        pass
    jid = common.jail_jid(ctx)
    rss = None
    if jid is not None:
        out = ctx.runner.read(['/bin/ps', '-ax', '-J', str(jid), '-o', 'rss='])
        values = [int(v) for v in out.split() if v.isdigit()]
        rss = sum(values) * 1024 if values else None
    report = {
        'model': step['model'], 'threads': step['threads'], 'wall_seconds': round(wall, 1),
        'load_seconds': round((result.get('load_duration') or 0) / ns, 2),
        'prompt_tokens': result.get('prompt_eval_count'),
        'prompt_tps': rate(result.get('prompt_eval_count'), result.get('prompt_eval_duration')),
        'gen_tokens': result.get('eval_count'),
        'gen_tps': rate(result.get('eval_count'), result.get('eval_duration')),
        'model_ram_bytes': ram, 'jail_rss_bytes': rss, 'ts': int(time.time()),
    }
    if report['prompt_tps'] and report['gen_tps']:
        # one finding: ~600 tokens in, ~250 out (docs/ollama-local-n100.md 3.4)
        report['estimate_finding_seconds'] = round(600 / report['prompt_tps'] + 250 / report['gen_tps'], 0)
    common.write_json(ctx.bench_file, report, mode=0o644)
    return report
