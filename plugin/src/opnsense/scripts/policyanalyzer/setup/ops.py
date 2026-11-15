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

    Step executor.

    A plan is a list of declarative steps (JSON).  execute_step() runs one
    step, idempotently (a step whose effect is already present is skipped),
    and returns the inverse steps that undo exactly what it changed, captured
    at execution time (previous file contents, owners, ...).  run_steps()
    executes a list, journals the inverses after every step and, on failure
    or cancel, rolls back what it can in reverse order.

    Step types: zfs_create, zfs_destroy, mkdir, rmdir, fetch, unlink, extract,
    write_file, restore_file, chown, restore_owner, mount, umount, run,
    remove_tree, wait_http, wait_ollama, verify_listen, model_pull, model_remove, model_restore,
    gguf_verify, hf_download (GGUF import, gguf.py).
"""

import hashlib
import json
import os
import shutil
import time

from . import common
from .common import SetupError, Cancelled

ALLOWED_TREE_PREFIXES = ('/var/db/ai/',)


def describe(step):
    """ normalise a step for display: always has command / effect / undo """
    step.setdefault('command', ' '.join(step['argv']) if step.get('argv') else step['type'])
    step.setdefault('effect', '')
    step.setdefault('undo', '')
    return step


# ------------------------------------------------------------------ helpers


def _guard_tree(ctx, path):
    """ refuse to delete anything outside the AI area, or with something mounted below it """
    rel = path[len(ctx.root):] if ctx.root and path.startswith(ctx.root) else path
    norm = os.path.normpath(rel)
    if norm != rel.rstrip('/') or not any(norm.startswith(p) for p in ALLOWED_TREE_PREFIXES):
        raise SetupError('refusing to remove %s (outside /var/db/ai)' % path)
    if norm in ('/var/db/ai/models',) or norm.startswith('/var/db/ai/models/'):
        raise SetupError('refusing to remove the models directory %s' % path)
    below = common.mounts_below(ctx, path)
    if below:
        raise SetupError('refusing to remove %s: %s is still mounted' % (path, below[0][1]))


def _run_checked(ctx, argv, timeout=600, env=None):
    rc, out, err = ctx.runner.run(argv, timeout=timeout, env=env, cancel=getattr(ctx, 'cancel_check', None))
    if rc != 0:
        raise SetupError('%s failed (rc=%d): %s' % (' '.join(argv), rc, (err or out).strip()[:400]))
    return out


class Progress:
    """ forwards byte progress of the current step to the state file (throttled) """

    def __init__(self, ctx, state, job_id):
        self.ctx = ctx
        self.state = state
        self.job_id = job_id
        self.last = 0

    def __call__(self, done, total, force=False, **extra):
        common.check_cancel(self.ctx, self.job_id)
        now = time.time()
        if self.state is None or (not force and now - self.last < 1.0):
            return
        self.last = now
        self.state.update_job(bytes_done=done, bytes_total=total, **extra)


def _download(ctx, url, dest, sha256, size, progress, headers=None):
    """ stream url to dest.part, verify sha256 (and size), rename into place """
    part = dest + '.part'
    digest = hashlib.sha256()
    done = 0
    common.ensure_dir(os.path.dirname(dest))
    with ctx.http.open(url, headers=headers, timeout=60) as resp, open(part, 'wb') as out:
        while True:
            block = resp.read(1024 * 1024)
            if not block:
                break
            out.write(block)
            digest.update(block)
            done += len(block)
            if size and done > size:
                break
            if progress:
                progress(done, size)
    if size and done != size:
        os.unlink(part)
        raise SetupError('%s: size mismatch (%d != %d)' % (url, done, size))
    if digest.hexdigest() != sha256:
        os.unlink(part)
        raise SetupError('%s: SHA256 mismatch' % url)
    os.replace(part, dest)
    return done


# ------------------------------------------------------------------ models on disk


def model_manifest_path(ctx, name, tag):
    return os.path.join(ctx.models_dir, 'manifests', 'registry.ollama.ai', 'library', name, tag)


def blob_path(ctx, digest):
    return os.path.join(ctx.models_dir, 'blobs', digest.replace(':', '-'))


def manifest_digests(manifest):
    digests = []
    for item in [manifest.get('config')] + list(manifest.get('layers') or []):
        if isinstance(item, dict) and isinstance(item.get('digest'), str):
            digests.append((item['digest'], int(item.get('size') or 0)))
    return digests


def installed_manifests(ctx):
    """ {(name, tag): manifest dict} of library models on disk """
    base = os.path.join(ctx.models_dir, 'manifests', 'registry.ollama.ai', 'library')
    result = {}
    try:
        names = os.listdir(base)
    except OSError:
        return result
    for name in names:
        try:
            tags = os.listdir(os.path.join(base, name))
        except OSError:
            continue
        for tag in tags:
            data = common.read_json(os.path.join(base, name, tag))
            if isinstance(data, dict):
                result[(name, tag)] = data
    return result


def referenced_digests(ctx, exclude=None):
    refs = set()
    for key, manifest in installed_manifests(ctx).items():
        if key != exclude:
            refs.update(d for d, _ in manifest_digests(manifest))
    return refs


def _check_digest(digest):
    if not isinstance(digest, str) or not digest.startswith('sha256:') or len(digest) != 71 \
            or any(c not in '0123456789abcdef' for c in digest[7:]):
        raise SetupError('invalid digest %r' % (digest,))
    return digest[7:]


# ------------------------------------------------------------------ executor


def execute_step(ctx, step, progress=None):
    """ :return: (status, inverse_steps) with status 'done' or 'skipped' """
    kind = step['type']
    if kind == 'zfs_create':
        if common.dataset_exists(ctx, step['dataset']):
            return 'skipped', []
        argv = ['/sbin/zfs', 'create']
        for prop, value in step.get('properties', []):
            argv += ['-o', '%s=%s' % (prop, value)]
        _run_checked(ctx, argv + [step['dataset']])
        return 'done', [{'type': 'zfs_destroy', 'dataset': step['dataset'],
                         'description': 'Destroy dataset %s' % step['dataset']}]

    if kind == 'zfs_destroy':
        if not common.dataset_exists(ctx, step['dataset']):
            return 'skipped', []
        mountpoint = ctx.runner.read(['/sbin/zfs', 'get', '-H', '-o', 'value', 'mountpoint',
                                      step['dataset']]).strip()
        if mountpoint.startswith('/') and common.mounts_below(ctx, mountpoint):
            raise SetupError('%s still has file systems mounted below %s' % (step['dataset'], mountpoint))
        argv = ['/sbin/zfs', 'destroy'] + (['-r'] if step.get('recursive') else []) + [step['dataset']]
        _run_checked(ctx, argv)
        return 'done', []

    if kind == 'mkdir':
        if os.path.isdir(step['path']):
            return 'skipped', []
        created = []
        probe = step['path']
        while not os.path.exists(probe):
            created.append(probe)
            probe = os.path.dirname(probe)
        mode = int(step.get('mode', '0755'), 8)
        os.makedirs(step['path'], mode=mode)
        # os.makedirs applies the process umask to the intermediate directories (configd: 027 -> 0750), which
        # left e.g. /var/lib of the jail not traversable by the service user: give every directory created here
        # the requested mode explicitly (parents get at least u+rwx,go+rx so the path stays traversable)
        for p in reversed(created):
            os.chmod(p, mode if p == step['path'] else (mode | 0o755))
        return 'done', [{'type': 'rmdir', 'path': p, 'description': 'Remove directory %s if empty' % p}
                        for p in created]

    if kind == 'rmdir':
        try:
            os.rmdir(step['path'])
        except FileNotFoundError:
            return 'skipped', []
        except OSError:
            return 'skipped', []         # not empty: left in place on purpose
        return 'done', []

    if kind == 'fetch':
        dest = step['dest']
        if os.path.isfile(dest) and common.sha256_file(dest) == step['sha256']:
            return 'skipped', [{'type': 'unlink', 'path': dest, 'description': 'Delete %s' % dest}]
        _download(ctx, step['url'], dest, step['sha256'], step.get('size'), progress)
        return 'done', [{'type': 'unlink', 'path': dest, 'description': 'Delete %s' % dest}]

    if kind == 'unlink':
        try:
            os.unlink(step['path'])
        except FileNotFoundError:
            return 'skipped', []
        return 'done', []

    if kind == 'extract':
        marker = step['marker']
        if os.path.exists(marker):
            return 'skipped', []
        _guard_tree(ctx, step['dest'])
        argv = ['/usr/bin/tar', '-xpf', step['archive'], '-C', step['dest']]
        for item in step.get('exclude', []):
            argv += ['--exclude', item]
        inverse = [{'type': 'remove_tree', 'path': step['dest'], 'keep_root': True,
                    'description': 'Remove the extracted files below %s' % step['dest']}]
        try:
            _run_checked(ctx, argv, timeout=3600)
        except SetupError:
            raise _Partial(inverse)
        common.write_atomic(marker, json.dumps({'archive': os.path.basename(step['archive']),
                                                'sha256': step.get('sha256')}) + '\n', 0o644)
        return 'done', inverse

    if kind == 'write_file':
        path = step['path']
        content = step['content'].encode('utf-8') if step.get('content') is not None else None
        mode = int(step.get('mode', '0644'), 8)
        previous = None
        prev_mode = None
        try:
            with open(path, 'rb') as handle:
                previous = handle.read()
            prev_mode = '%04o' % (os.stat(path).st_mode & 0o7777)
        except FileNotFoundError:
            pass
        if previous == content and (content is None or prev_mode == '%04o' % mode):
            return 'skipped', []
        if content is None:
            os.unlink(path)
        else:
            common.write_atomic(path, content, mode, dir_mode=int(step.get('dir_mode', '0755'), 8))
        return 'done', [{'type': 'restore_file', 'path': path, 'content_b64': common.b64(previous),
                         'mode': prev_mode,
                         'description': ('Restore previous %s' % path) if previous is not None
                         else 'Delete %s' % path}]

    if kind == 'restore_file':
        path = step['path']
        data = common.unb64(step.get('content_b64'))
        if data is None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                return 'skipped', []
            return 'done', []
        common.write_atomic(path, data, int(step.get('mode') or '0644', 8))
        return 'done', []

    if kind == 'chown':
        path = step['path']
        st = os.stat(path)
        mode = int(step['mode'], 8) if step.get('mode') else (st.st_mode & 0o7777)
        if st.st_uid == step['uid'] and st.st_gid == step['gid'] and (st.st_mode & 0o7777) == mode:
            return 'skipped', []
        os.chown(path, step['uid'], step['gid'])
        os.chmod(path, mode)
        return 'done', [{'type': 'restore_owner', 'path': path, 'uid': st.st_uid, 'gid': st.st_gid,
                         'mode': '%04o' % (st.st_mode & 0o7777),
                         'description': 'Restore owner %d:%d of %s' % (st.st_uid, st.st_gid, path)}]

    if kind == 'restore_owner':
        if not os.path.exists(step['path']):
            return 'skipped', []
        os.chown(step['path'], step['uid'], step['gid'])
        os.chmod(step['path'], int(step['mode'], 8))
        return 'done', []

    if kind == 'mount':
        if any(m[1] == step['target'] for m in common.mounts(ctx)):
            return 'skipped', []
        _run_checked(ctx, ['/sbin/mount', '-t', step['fstype'], step['source'], step['target']])
        for argv in step.get('after', []):
            _run_checked(ctx, argv)
        return 'done', [{'type': 'umount', 'target': step['target'],
                         'description': 'Unmount %s' % step['target']}]

    if kind == 'umount':
        if not any(m[1] == step['target'] for m in common.mounts(ctx)):
            return 'skipped', []
        _run_checked(ctx, ['/sbin/umount', step['target']])
        return 'done', []

    if kind == 'run':
        if step.get('skip_if'):
            rc, _, _ = ctx.runner.run(step['skip_if'], timeout=30)
            if rc == 0:
                return 'skipped', []
        if step.get('skip_unless'):
            rc, _, _ = ctx.runner.run(step['skip_unless'], timeout=30)
            if rc != 0:
                return 'skipped', []
        _run_checked(ctx, step['argv'], timeout=step.get('timeout', 600), env=step.get('env'))
        if step.get('undo_argv'):
            return 'done', [{'type': 'run', 'argv': step['undo_argv'], 'timeout': step.get('timeout', 600),
                             'description': step.get('undo') or ' '.join(step['undo_argv'])}]
        return 'done', []

    if kind == 'remove_tree':
        path = step['path']
        _guard_tree(ctx, path)
        if not os.path.exists(path):
            return 'skipped', []
        ctx.runner.run(['/bin/chflags', '-R', 'noschg,nouchg', path], timeout=600)
        if step.get('keep_root'):
            for name in os.listdir(path):
                full = os.path.join(path, name)
                if os.path.isdir(full) and not os.path.islink(full):
                    shutil.rmtree(full)
                else:
                    os.unlink(full)
        else:
            shutil.rmtree(path)
        return 'done', []

    if kind == 'tunable':
        return _tunable(ctx, step)

    if kind == 'verify_listen':
        bad = foreign_listeners(ctx, step.get('port', 11434))
        if bad:
            raise SetupError('port %d is listening on %s (only 127.0.0.1 is allowed)'
                             % (step.get('port', 11434), ', '.join(bad)))
        return 'done', []

    if kind == 'wait_ollama':
        return _wait_ollama(ctx, step)

    if kind == 'wait_http':
        deadline = time.time() + step.get('timeout', 60)
        while True:
            try:
                ctx.http.get_json(step['url'], timeout=5)
                return 'done', []
            except Exception:                       # noqa: BLE001 - any failure means "not up yet"
                if time.time() >= deadline:
                    raise SetupError('%s did not answer within %ds' % (step['url'], step.get('timeout', 60)))
                common.check_cancel(ctx)
                time.sleep(2)

    if kind == 'model_pull':
        return _model_pull(ctx, step, progress)

    if kind == 'benchmark':
        from .models import run_benchmark
        step['result'] = run_benchmark(ctx, step)
        return 'done', []

    if kind == 'model_remove':
        return _model_remove(ctx, step)

    if kind == 'gguf_verify':
        from .gguf import verify
        return verify(ctx, step)

    if kind == 'hf_download':
        from .gguf import download
        return download(ctx, step, progress)

    if kind == 'model_restore':
        # undo of a removal: re-download the exact manifest that was removed
        return _model_pull(ctx, dict(step, manifest=step['manifest']), progress)

    raise SetupError('unknown step type %s' % kind)


class _Partial(SetupError):
    """ a step failed half way; carries the inverse of what it may have left behind """

    def __init__(self, inverse):
        super().__init__('partial')
        self.inverse = inverse


def _model_pull(ctx, step, progress):
    name, tag = step['model'], step['tag']
    manifest_raw = step['manifest'] if isinstance(step['manifest'], str) else json.dumps(step['manifest'])
    manifest = json.loads(manifest_raw)
    manifest_file = model_manifest_path(ctx, name, tag)
    previous = common.read_text(manifest_file)
    if previous is not None and previous == manifest_raw:
        missing = [d for d, _ in manifest_digests(manifest) if not os.path.isfile(blob_path(ctx, d))]
        if not missing:
            return 'skipped', []
    blobs_dir = os.path.join(ctx.models_dir, 'blobs')
    staging = os.path.join(ctx.staging_dir, 'blobs')
    common.ensure_dir(blobs_dir, 0o755)
    common.ensure_dir(staging, 0o750)
    digests = manifest_digests(manifest)
    total = sum(size for _, size in digests)
    added = []
    done_bytes = 0
    inverse = []

    def make_inverse():
        return [{'type': 'model_remove', 'model': name, 'tag': tag, 'only_blobs': list(added),
                 'manifest_b64': common.b64(previous.encode()) if previous is not None else None,
                 'description': 'Remove model %s:%s and the blobs it added' % (name, tag)}]
    try:
        for digest, size in digests:
            hexd = _check_digest(digest)
            final = blob_path(ctx, digest)
            if os.path.isfile(final) and os.path.getsize(final) == size:
                done_bytes += size
                continue
            url = '%s/v2/library/%s/blobs/%s' % (common.OLLAMA_REGISTRY, name, digest)
            tmp = os.path.join(staging, 'sha256-' + hexd)
            base = done_bytes

            def layer_progress(done, _total, _digest=digest, _base=base):
                if progress:
                    progress(_base + done, total, layer=_digest)
            _download(ctx, url, tmp, hexd, size, layer_progress)
            os.chmod(tmp, 0o644)
            os.replace(tmp, final)
            added.append(digest)
            done_bytes += size
        common.ensure_dir(os.path.dirname(manifest_file), 0o755)
        common.write_atomic(manifest_file, manifest_raw, 0o644)
        _fix_owner(ctx, step)
        if progress:
            progress(total, total, force=True, layer=None)
    except BaseException:
        inverse = make_inverse()
        raise _Partial(inverse)
    return 'done', make_inverse()


def _fix_owner(ctx, step):
    """ models must be readable by the service user of the jail """
    uid = step.get('uid')
    if uid is None:
        return
    for dirpath, dirnames, filenames in os.walk(ctx.models_dir):
        for item in [dirpath] + [os.path.join(dirpath, f) for f in filenames]:
            try:
                os.chown(item, uid, uid)
            except OSError:
                pass


def _model_remove(ctx, step):
    name, tag = step['model'], step['tag']
    manifest_file = model_manifest_path(ctx, name, tag)
    manifest = common.read_json(manifest_file)
    raw = common.read_text(manifest_file)
    if manifest is None and not step.get('only_blobs'):
        return 'skipped', []
    keep = referenced_digests(ctx, exclude=(name, tag))
    if step.get('only_blobs') is not None:
        candidates = list(step['only_blobs'])
    else:
        candidates = [d for d, _ in manifest_digests(manifest or {})]
    removed = []
    for digest in candidates:
        _check_digest(digest)
        if digest in keep:
            continue
        try:
            os.unlink(blob_path(ctx, digest))
            removed.append(digest)
        except FileNotFoundError:
            pass
    restored_previous = step.get('manifest_b64')
    if restored_previous:
        common.write_atomic(manifest_file, common.unb64(restored_previous), 0o644)
    elif manifest is not None:
        os.unlink(manifest_file)
        for path in (os.path.dirname(manifest_file),):
            try:
                os.rmdir(path)
            except OSError:
                pass
    if raw is None:
        return 'done', []
    return 'done', [{'type': 'model_restore', 'model': name, 'tag': tag, 'manifest': raw, 'uid': step.get('uid'),
                     'description': 'Download %s:%s again (same digests)' % (name, tag)}]


def _tunable_call(ctx, *args):
    rc, out, err = ctx.runner.run([ctx.php, ctx.tunables_php] + list(args), timeout=60)
    try:
        data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
    except ValueError:
        data = {}
    if rc != 0 or data.get('status') != 'ok':
        raise SetupError('tunables model: %s' % (data.get('message') or err.strip() or 'rc=%d' % rc))
    return data


def _tunable(ctx, step):
    """ set (or delete) a system tunable through the core model, inverse = previous entry """
    name = step['name']
    prev = _tunable_call(ctx, 'get', name)
    if step.get('delete'):
        if not prev.get('exists'):
            return 'skipped', []
        _tunable_call(ctx, 'del', name)
    else:
        if prev.get('exists') and prev.get('value') == step['value']:
            return 'skipped', []
        _tunable_call(ctx, 'set', name, step['value'], step.get('descr') or '')
    if prev.get('exists'):
        inverse = {'type': 'tunable', 'name': name, 'value': prev['value'], 'descr': prev.get('descr') or '',
                   'description': 'Restore tunable %s=%s' % (name, prev['value'])}
    else:
        inverse = {'type': 'tunable', 'name': name, 'delete': True,
                   'description': 'Remove tunable %s from System: Settings: Tunables' % name}
    return 'done', [inverse]


def ollama_alive(ctx):
    """ is an ollama process running inside the jail? """
    rc, _, _ = ctx.runner.run(['/usr/sbin/jexec', common.JAIL_NAME, '/bin/pgrep', '-x', 'ollama'], timeout=10)
    return rc == 0


def _wait_ollama(ctx, step):
    """ wait for the API; fail at once (after a short grace) when the process is gone """
    timeout = step.get('timeout', 180)
    grace = step.get('grace', 15)
    started = time.time()
    last = ''
    while True:
        try:
            ctx.http.get_json(step['url'], timeout=5)
            return 'done', []
        except Exception as exc:                    # noqa: BLE001 - any failure means "not up yet"
            last = str(exc)
        elapsed = time.time() - started
        if elapsed >= grace and not ollama_alive(ctx):
            tail = tail_text(ctx.in_jail(common.JAIL_OLLAMA_LOG), 600) or \
                tail_text(ctx.in_jail('/var/log/ollama-%s.log' % common.JAIL_SERVICE_USER), 600) or ''
            raise SetupError('ollama exited inside the jail %ds after the start%s'
                             % (int(elapsed), (': ' + ' | '.join(tail.strip().splitlines()[-4:])) if tail else
                                ' (no log written)'))
        if elapsed >= timeout:
            raise SetupError('%s did not answer within %ds although ollama is running (last error: %s)'
                             % (step['url'], timeout, last[:200]))
        common.check_cancel(ctx)
        time.sleep(step.get('interval', 2))


def tail_text(path, limit=4000):
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            return handle.read().decode('utf-8', 'replace')
    except OSError:
        return None


DIAGNOSE_TYPES = ('wait_ollama', 'wait_http', 'verify_listen')


def needs_diagnostics(step):
    argv = step.get('argv') or []
    return step['type'] in DIAGNOSE_TYPES or step.get('diagnose') or \
        (step['type'] == 'run' and argv[:1] == ['/usr/sbin/jail'] and '-c' in argv) or \
        (step['type'] == 'run' and 'restart' in argv)


def collect_diagnostics(ctx):
    """ read only snapshot of the jail and the Ollama service, taken BEFORE any rollback """
    name = common.JAIL_NAME
    commands = [
        ('jls', ['/usr/sbin/jls', '-v', '-j', name]),
        ('service_status', ['/usr/sbin/jexec', name, '/usr/sbin/service', 'ollama', 'status']),
        ('ps', ['/usr/sbin/jexec', name, '/bin/ps', 'auxww']),
        ('sockstat', ['/usr/bin/sockstat', '-4l', '-j', name]),
        ('id_nobody', ['/usr/sbin/jexec', name, '/usr/bin/id', common.JAIL_SERVICE_USER]),
        ('ls', ['/usr/sbin/jexec', name, '/bin/ls', '-la', common.JAIL_SERVICE_HOME, common.JAIL_MODELS_MOUNT,
                '/var/log', '/var/run']),
        ('mounts', ['/sbin/mount', '-p']),
        ('dmesg', ['/sbin/dmesg']),
    ]
    out = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'commands': {}, 'files': {}}
    for key, argv in commands:
        try:
            rc, stdout, stderr = ctx.runner.run(argv, timeout=10)
        except Exception as exc:                    # noqa: BLE001
            rc, stdout, stderr = -1, '', str(exc)
        text = stdout or ''
        if key == 'dmesg':
            text = '\n'.join(text.splitlines()[-20:])
        elif key == 'mounts':
            text = '\n'.join(l for l in text.splitlines() if '/var/db/ai' in l)
        out['commands'][key] = {'command': ' '.join(argv), 'rc': rc, 'stdout': text[-4000:],
                                'stderr': (stderr or '')[-1000:]}
    files = [
        ('ollama_log', ctx.in_jail(common.JAIL_OLLAMA_LOG)),
        ('ollama_log_port_default', ctx.in_jail('/var/log/ollama-%s.log' % common.JAIL_SERVICE_USER)),
        ('jail_messages', ctx.in_jail('/var/log/messages')),
        ('jail_rc_conf', ctx.in_jail('/etc/rc.conf')),
        ('jail_rc_conf_d_ollama', ctx.in_jail('/etc/rc.conf.d/ollama')),
        ('jail_conf', ctx.jail_conf),
        ('console_log', ctx.root + ctx.console_log),
    ]
    for key, path in files:
        text = tail_text(path)
        if text is not None:
            out['files'][key] = {'path': path, 'tail': text}
    return out


def foreign_listeners(ctx, port):
    """ addresses other than 127.0.0.1 listening on port (sockstat -46l) """
    bad = []
    out = ctx.runner.read(['/usr/bin/sockstat', '-46l', '-p', str(port)])
    for line in out.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 6:
            local = fields[5]
            addr = local.rsplit(':', 1)[0]
            if addr not in ('127.0.0.1',):
                bad.append(local)
    return bad


def predict(ctx, step):
    """ read only guess of whether execute_step() would skip this step """
    kind = step['type']
    if step.get('cleanup'):
        return False                # removes what an earlier step of the same plan creates
    try:
        if kind == 'zfs_create':
            return common.dataset_exists(ctx, step['dataset'])
        if kind == 'zfs_destroy':
            return not common.dataset_exists(ctx, step['dataset'])
        if kind == 'mkdir':
            return os.path.isdir(step['path'])
        if kind in ('fetch',):
            return os.path.isfile(step['dest'])
        if kind == 'extract':
            return os.path.exists(step['marker'])
        if kind == 'write_file':
            current = common.read_text(step['path'])
            return current == step.get('content')
        if kind in ('unlink', 'remove_tree'):
            return not os.path.exists(step['path'])
        if kind == 'mount':
            return any(m[1] == step['target'] for m in common.mounts(ctx))
        if kind == 'umount':
            return not any(m[1] == step['target'] for m in common.mounts(ctx))
        if kind == 'run':
            if step.get('skip_if'):
                return ctx.runner.run(step['skip_if'], timeout=15)[0] == 0
            if step.get('skip_unless'):
                return ctx.runner.run(step['skip_unless'], timeout=15)[0] != 0
            return False
        if kind == 'model_pull':
            manifest = step['manifest'] if isinstance(step['manifest'], str) else json.dumps(step['manifest'])
            return common.read_text(model_manifest_path(ctx, step['model'], step['tag'])) == manifest
        if kind == 'model_remove':
            return not os.path.exists(model_manifest_path(ctx, step['model'], step['tag']))
        if kind == 'chown':
            st = os.stat(step['path'])
            return st.st_uid == step['uid'] and st.st_gid == step['gid'] and \
                (not step.get('mode') or (st.st_mode & 0o7777) == int(step['mode'], 8))
        if kind == 'tunable':
            from .runtime import configured_tunable
            current = configured_tunable(ctx, step['name'])
            return current is None if step.get('delete') else current == step['value']
        if kind in ('wait_http', 'wait_ollama', 'verify_listen', 'gguf_verify'):
            return True             # read only checks, they change nothing
        if kind == 'hf_download':
            return os.path.isfile(step['path']) and os.path.getsize(step['path']) == step.get('size')
    except (OSError, SetupError, ValueError):
        return False
    return False


def run_steps(ctx, steps, journal, state=None, log=None, job_id=None):
    """
    Execute steps in order.  After each step the inverse is prepended to
    journal['inverse'] (so it is always in undo order) and the journal is
    saved.  On error/cancel: roll back the inverses collected in this run.
    :return: result dict
    """
    progress = Progress(ctx, state, job_id)
    journal.setdefault('inverse', [])
    journal.setdefault('executed', [])
    collected = []
    total = len(steps)
    for index, step in enumerate(steps):
        common.check_cancel(ctx, job_id)
        if state is not None:
            state.update_job(step_index=index + 1, step_total=total, step=step.get('description'),
                             bytes_done=None, bytes_total=step.get('download_bytes'))
        started = time.time()
        try:
            status, inverse = execute_step(ctx, step, progress)
        except BaseException as exc:            # includes Cancelled / KeyboardInterrupt
            partial = exc.inverse if isinstance(exc, _Partial) else []
            cause = exc.__cause__ or exc.__context__ if isinstance(exc, _Partial) else exc
            message = str(cause) if cause else str(exc)
            cancelled = isinstance(cause, Cancelled) or isinstance(exc, Cancelled)
            diagnostics = None
            if needs_diagnostics(step) and not cancelled:
                try:
                    diagnostics = collect_diagnostics(ctx)
                except Exception as diag_exc:      # noqa: BLE001 - never hide the original error
                    diagnostics = {'error': str(diag_exc)}
                journal['diagnostics'] = diagnostics
                common.save_journal(ctx, journal)
            if log:
                log.record(journal=journal['id'], step=step.get('description'), status='error', message=message,
                           diagnostics=diagnostics)
            rollback = rollback_steps(ctx, partial + collected, log=log, journal_id=journal['id'])
            journal['status'] = 'cancelled' if cancelled else 'failed'
            journal['error'] = message
            journal['rollback'] = rollback
            journal['inverse'] = [s for s in journal['inverse'] if s not in collected]
            common.save_journal(ctx, journal)
            result = {'status': journal['status'], 'message': message, 'failed_step': step.get('description'),
                      'rollback': rollback, 'journal': journal['id']}
            if diagnostics is not None:
                result['diagnostics'] = diagnostics
            return result
        collected = inverse + collected
        journal['inverse'] = inverse + journal['inverse']
        journal['executed'].append({'description': step.get('description'), 'status': status,
                                    'seconds': round(time.time() - started, 1)})
        common.save_journal(ctx, journal)
        if log:
            log.record(journal=journal['id'], step=step.get('description'), status=status,
                       command=step.get('command'))
    journal['status'] = 'applied'
    common.save_journal(ctx, journal)
    return {'status': 'ok', 'journal': journal['id'], 'executed': journal['executed']}


def rollback_steps(ctx, inverse_steps, log=None, journal_id=None):
    """ best effort: run every inverse, never raise """
    report = []
    for step in inverse_steps:
        try:
            # a cancel request must not stop the rollback itself
            status, _ = execute_step(ctx, step, progress=None) if step['type'] != 'model_restore' \
                else ('skipped', [])
            report.append({'description': step.get('description'), 'status': status})
        except Exception as exc:                # noqa: BLE001
            report.append({'description': step.get('description'), 'status': 'error', 'message': str(exc)[:300]})
        if log:
            log.record(journal=journal_id, rollback=step.get('description'), status=report[-1]['status'])
    return report
