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

    Import of a local GGUF model into the Ollama of the jail (e.g. Foundation-sec-8B converted on a workstation).

        import_gguf <file.gguf> <name:tag> sha256=<hex> [template=foundation-sec|llama3|chatml|qwen|gguf] [+cleanup]
        import_gguf hf:<owner>/<repo>/<path/file.gguf>[@revision] <name:tag> [template=...] [sha256=<hex>]

    Local file: the administrator copies the .gguf with scp to /var/db/ai/models/import/ (inside the models
    dataset, visible in the jail as /var/lib/ollama/models/import/).  The plan checks the name, the extension,
    the size and the GGUF magic; apply verifies the SHA-256 given by the administrator, writes a Modelfile with
    the chat template of the model family and runs "ollama create <name> -f <Modelfile>" inside the jail.

    Hugging Face: the plan reads https://huggingface.co/api/models/<owner>/<repo>/revision/<rev>?blobs=true
    (read only) for the commit, the size and the SHA-256 of the LFS object; apply downloads
    https://huggingface.co/<owner>/<repo>/resolve/<commit>/<file> (redirects only to the Hugging Face CDN
    hosts, see common.Http) into the import directory, verifies the SHA-256 and imports it as above.

    Revert: "ollama rm <name>" inside the jail and the Modelfile is deleted (a downloaded file too); a local file
    copied by the administrator is kept unless +cleanup removed it after the import (irreversible).
    The model then appears in step 5 of the AI setup like any installed model.
"""

import os
import re

from . import common
from .common import SetupError

IMPORT_SUBDIR = 'import'
MIN_BYTES = 50 * common.MIB
MAX_BYTES = 80 * common.GIB
SHA_RE = re.compile(r'^[0-9a-f]{64}$')
FILE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.gguf$')
HF_RE = re.compile(r'^hf:([A-Za-z0-9][A-Za-z0-9._-]{0,95})/([A-Za-z0-9][A-Za-z0-9._-]{0,95})/'
                   r'((?:[A-Za-z0-9][A-Za-z0-9._-]{0,95}/){0,3}[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.gguf)'
                   r'(?:@([A-Za-z0-9][A-Za-z0-9._-]{0,63}))?$')
HF_API = 'https://huggingface.co/api/models/%s/%s/revision/%s?blobs=true'
HF_RESOLVE = 'https://huggingface.co/%s/%s/resolve/%s/%s'
OLLAMA_BIN = '/usr/local/bin/ollama'

# chat templates (Go templates of Ollama). foundation-sec: the official chat format of Cisco's
# Foundation-Sec-8B-Instruct (<|system|>/<|user|>/<|assistant|>, answers end with <|end_of_text|>);
# llama3: Llama 3.x Instruct.
LLAMA3_TEMPLATE = '''{{- if .System }}<|start_header_id|>system<|end_header_id|>

{{ .System }}<|eot_id|>
{{- end }}
{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 }}
{{- if eq .Role "user" }}<|start_header_id|>user<|end_header_id|>

{{ .Content }}<|eot_id|>{{ if $last }}<|start_header_id|>assistant<|end_header_id|>

{{ end }}
{{- else if eq .Role "assistant" }}<|start_header_id|>assistant<|end_header_id|>

{{ .Content }}{{ if not $last }}<|eot_id|>{{ end }}
{{- end }}
{{- end }}'''
CHATML_TEMPLATE = '''{{- if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}
{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 }}
{{- if eq .Role "user" }}<|im_start|>user
{{ .Content }}<|im_end|>
{{ else if eq .Role "assistant" }}<|im_start|>assistant
{{ .Content }}{{ if not $last }}<|im_end|>
{{ end }}
{{- end }}
{{- if and (ne .Role "assistant") $last }}<|im_start|>assistant
{{ end }}
{{- end }}'''
FOUNDATION_SEC_TEMPLATE = '''{{- if .System }}<|system|>
{{ .System }}
{{ end }}
{{- range $i, $_ := .Messages }}
{{- $last := eq (len (slice $.Messages $i)) 1 }}
{{- if eq .Role "user" }}<|user|>
{{ .Content }}
{{ else if eq .Role "assistant" }}<|assistant|>
{{ .Content }}{{ if not $last }}<|end_of_text|>
{{ end }}
{{- end }}
{{- if and (ne .Role "assistant") $last }}<|assistant|>
{{ end }}
{{- end }}'''
TEMPLATES = {
    'foundation-sec': {'template': FOUNDATION_SEC_TEMPLATE, 'stop': ['<|end_of_text|>', '<|user|>', '<|system|>', '<|eot_id|>'],
                       'label': 'Foundation-Sec-8B-Instruct (Cisco official chat format)'},
    'llama3': {'template': LLAMA3_TEMPLATE, 'stop': ['<|start_header_id|>', '<|end_header_id|>', '<|eot_id|>'],
               'label': 'Llama 3.x Instruct (Llama 3.1/3.2)'},
    'chatml': {'template': CHATML_TEMPLATE, 'stop': ['<|im_start|>', '<|im_end|>'],
               'label': 'ChatML (Qwen 2.x/3, many fine-tunes)'},
    'gguf': {'template': None, 'stop': [], 'label': 'the chat template embedded in the GGUF file'},
}
TEMPLATES['qwen'] = TEMPLATES['chatml']


def import_dir(ctx):
    return os.path.join(ctx.models_dir, IMPORT_SUBDIR)


def jail_path(name):
    return '%s/%s/%s' % (common.JAIL_MODELS_MOUNT, IMPORT_SUBDIR, name)


def modelfile(gguf_name, template):
    spec = TEMPLATES[template]
    lines = ['# written by the Policy Analyzer (import_gguf, template %s)' % template,
             'FROM %s' % jail_path(gguf_name)]
    if spec['template']:
        lines.append('TEMPLATE """%s"""' % spec['template'])
    for stop in spec['stop']:
        lines.append('PARAMETER stop "%s"' % stop)
    lines.append('PARAMETER temperature 0.2')
    return '\n'.join(lines) + '\n'


def validate_args(args):
    source = args.get('source') or ''
    base, tag = common.validate_model(args.get('name') or '')
    template = (args.get('template') or 'llama3').lower()
    if template not in TEMPLATES:
        raise ValueError('template must be one of: %s' % ', '.join(sorted(TEMPLATES)))
    sha = (args.get('sha256') or '').lower()
    if sha and not SHA_RE.match(sha):
        raise ValueError('sha256 must be 64 hexadecimal characters')
    cleanup = common.as_bool(args.get('cleanup'), False, 'cleanup')
    hf = HF_RE.match(source)
    if hf is None and not FILE_RE.match(source):
        raise ValueError('source must be a file name ending in .gguf inside /var/db/ai/models/import/ or '
                         'hf:<owner>/<repo>/<file.gguf>[@revision]')
    if hf is None and not sha:
        raise ValueError('sha256=<hex> is required for a local file (sha256sum on the computer that made it)')
    return source, hf, base, tag, template, sha, cleanup


def _gguf_magic(path):
    with open(path, 'rb') as handle:
        return handle.read(4) == b'GGUF'


def hf_lookup(ctx, owner, repo, path, revision):
    """ :return: {"commit", "size", "sha256", "url"} from the Hugging Face API (read only) """
    data = ctx.http.get_json(HF_API % (owner, repo, revision or 'main'), timeout=20)
    if not isinstance(data, dict) or not isinstance(data.get('siblings'), list):
        raise SetupError('unexpected answer from the Hugging Face API')
    commit = str(data.get('sha') or '')
    if not re.match(r'^[0-9a-f]{40}$', commit):
        raise SetupError('the Hugging Face API did not return the commit of %s/%s' % (owner, repo))
    for item in data['siblings']:
        if isinstance(item, dict) and item.get('rfilename') == path:
            lfs = item.get('lfs') or {}
            sha, size = str(lfs.get('sha256') or '').lower(), lfs.get('size') or item.get('size')
            if not SHA_RE.match(sha) or not isinstance(size, int):
                raise SetupError('%s is not an LFS object with a SHA-256 on Hugging Face' % path)
            return {'commit': commit, 'size': size, 'sha256': sha,
                    'url': HF_RESOLVE % (owner, repo, commit, path)}
    raise SetupError('%s was not found in %s/%s (revision %s)' % (path, owner, repo, revision or 'main'))


def import_plan(ctx, args):
    source, hf, base, tag, template, sha, cleanup = validate_args(args)
    full = '%s:%s' % (base, tag)
    errors, warnings, steps, irreversible = [], [], [], []
    from .ops import model_manifest_path
    from .runtime import probe
    if os.path.exists(model_manifest_path(ctx, base, tag)):
        errors.append('%s is already installed; remove it first (remove_model) or choose another name' % full)
    info = probe(ctx)
    if not info['running']:
        errors.append('the local runtime is not running (start_runtime): ollama create needs it')
    folder = import_dir(ctx)
    download = None
    if hf is not None:
        owner, repo, path, revision = hf.groups()
        gguf_name = os.path.basename(path)
        try:
            download = hf_lookup(ctx, owner, repo, path, revision)
        except Exception as exc:                # noqa: BLE001
            errors.append('could not read %s/%s from huggingface.co: %s' % (owner, repo, exc))
            download = {'commit': None, 'size': 0, 'sha256': sha, 'url': None}
        if sha and download.get('sha256') and sha != download['sha256']:
            errors.append('the SHA-256 given does not match the one published on Hugging Face (%s)'
                          % download['sha256'])
        size = download['size'] or 0
        sha = download.get('sha256') or sha
        target = os.path.join(folder, gguf_name)
        if os.path.exists(target):
            errors.append('%s already exists in the import directory' % gguf_name)
    else:
        gguf_name = source
        target = os.path.join(folder, gguf_name)
        size = 0
        if not os.path.isdir(folder):
            errors.append('%s does not exist: create it and copy the file there with scp' % folder)
        elif os.path.islink(target) or not os.path.isfile(target):
            errors.append('%s is not a regular file in %s' % (gguf_name, folder))
        else:
            size = os.path.getsize(target)
            if not _gguf_magic(target):
                errors.append('%s does not start with the GGUF magic bytes' % gguf_name)
    if size and not MIN_BYTES <= size <= MAX_BYTES:
        errors.append('size %s outside the accepted range (%s - %s)' % (
            common.fmt_bytes(size), common.fmt_bytes(MIN_BYTES), common.fmt_bytes(MAX_BYTES)))
    # the downloaded file and the blob Ollama copies from it are both below /var/db/ai/models
    need = size * (2 if download else 1)
    space = common.space_check(ctx, ctx.models_dir, need, 'the import of %s (the blob is a copy)' % full)
    errors += space['errors']
    warnings += space['warnings']
    free = space['free']
    need = space['needed']
    if template == 'gguf':
        warnings.append('template "gguf": Ollama uses the chat template embedded in the file; if the answers '
                        'look broken, revert and import again with template=llama3 or chatml')
    mf_name = '%s-%s.Modelfile' % (base, tag)
    mf_path = os.path.join(folder, mf_name)
    if download:
        steps.append({'type': 'mkdir', 'path': folder, 'mode': '0755', 'argv': ['/bin/mkdir', '-p', folder],
                      'description': 'Create the import directory %s' % folder})
        steps.append({'type': 'hf_download', 'url': download.get('url'), 'path': target, 'sha256': sha,
                      'size': size, 'download_bytes': size,
                      'command': 'GET %s (redirects only to the Hugging Face CDN), verify SHA-256 %s'
                                 % (download.get('url'), sha),
                      'description': 'Download %s (%s, commit %s)' % (gguf_name, common.fmt_bytes(size),
                                                                     (download.get('commit') or '?')[:12]),
                      'effect': 'file in %s; progress in setup-state.json' % folder,
                      'undo': 'the downloaded file is deleted'})
    else:
        steps.append({'type': 'gguf_verify', 'path': target, 'sha256': sha, 'size': size,
                      'command': 'sha256 %s == %s' % (target, sha),
                      'description': 'Verify the SHA-256 of %s (%s)' % (gguf_name, common.fmt_bytes(size)),
                      'effect': 'read only'})
    steps.append({'type': 'write_file', 'path': mf_path, 'content': modelfile(gguf_name, template), 'mode': '0644',
                  'command': 'write %s (FROM %s, template %s)' % (mf_path, jail_path(gguf_name), template),
                  'description': 'Write the Modelfile (%s)' % TEMPLATES[template]['label'],
                  'effect': 'chat template and stop tokens of the model', 'undo': 'the Modelfile is deleted'})
    create = ['/usr/sbin/jexec', common.JAIL_NAME, '/usr/bin/env', 'HOME=%s' % common.JAIL_SERVICE_HOME,
              'OLLAMA_HOST=127.0.0.1:11434', OLLAMA_BIN]
    steps.append({'type': 'run', 'argv': create + ['create', full, '-f', jail_path(mf_name)],
                  'undo_argv': create + ['rm', full], 'timeout': 7200,
                  'command': 'jexec %s ollama create %s -f %s' % (common.JAIL_NAME, full, jail_path(mf_name)),
                  'description': 'Create the model %s in the local runtime' % full,
                  'effect': 'Ollama copies the weights into its blobs (%s) and writes the manifest'
                            % common.fmt_bytes(size),
                  'undo': 'ollama rm %s' % full})
    if cleanup:
        steps.append({'type': 'unlink', 'path': target, 'argv': ['/bin/rm', target],
                      'description': 'Delete %s after the import (frees %s)' % (gguf_name, common.fmt_bytes(size)),
                      'effect': 'the import directory keeps only the Modelfile'})
        irreversible.append('the source file %s is deleted after the import' % gguf_name)
    steps.append({'type': 'wait_http', 'url': common.OLLAMA_URL + '/api/tags', 'timeout': 30,
                  'description': 'Check that Ollama lists the models'})
    return {'steps': steps, 'errors': errors, 'warnings': warnings, 'irreversible': irreversible,
            'download_bytes': size if download else 0, 'space_needed': need if size else 0, 'space_free': free,
            'space_path': ctx.models_dir,
            'undo': 'Revert runs "ollama rm %s" and deletes the Modelfile%s' % (
                full, ' and the downloaded file' if download else ''),
            'resources': ['model:' + full], 'risk': 'low', 'background': True,
            'args': {'source': source, 'name': full, 'template': template, 'sha256': sha, 'cleanup': cleanup},
            'model': {'name': full, 'size': size, 'template': template, 'source': 'huggingface' if download
                      else 'file', 'commit': download.get('commit') if download else None}}


def verify(ctx, step):
    """ step gguf_verify: size, magic and SHA-256 of the local file """
    path = step['path']
    if os.path.islink(path) or not os.path.isfile(path):
        raise SetupError('%s is not a regular file' % path)
    if step.get('size') and os.path.getsize(path) != step['size']:
        raise SetupError('%s changed size since the plan' % path)
    if not _gguf_magic(path):
        raise SetupError('%s is not a GGUF file' % path)
    got = common.sha256_file(path, cancel=lambda: common.check_cancel(ctx))
    if got != step['sha256']:
        raise SetupError('SHA-256 mismatch for %s: %s' % (os.path.basename(path), got))
    return 'done', []


def download(ctx, step, progress=None):
    """ step hf_download: stream into place with SHA-256 and size check; inverse deletes the file """
    from .ops import _download
    path = step['path']
    if os.path.isfile(path) and os.path.getsize(path) == step['size'] and \
            common.sha256_file(path) == step['sha256']:
        return 'skipped', []
    if not step.get('url'):
        raise SetupError('no download URL')
    _download(ctx, step['url'], path, step['sha256'], step['size'],
              (lambda done, total: progress(done, total)) if progress else None)
    os.chmod(path, 0o644)
    return 'done', [{'type': 'unlink', 'path': path, 'description': 'Delete %s' % path}]
