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

    Read-only inspection of the directory that holds local models (the one
    OLLAMA_MODELS points to when the model server runs on this firewall).

    inspect()  reports whether the path exists and is writable, which
               filesystem and (for ZFS) which dataset it lives on, and the
               free space.  Read only.
    plan()     lists what prepare() would do, read only.
    prepare()  creates the storage, only below /var/db/: on a ZFS root a
               dedicated dataset <pool>/ai mounted on /var/db/ai (tuned for
               large, write-once model files) when the path is below it, then
               the directory itself (0750 root:wheel).  Idempotent; it never
               destroys or modifies an existing dataset or directory.
               Without ZFS (UFS) only the directory is created, on the system
               disk; a dataset already mounted on /var/db/ai (the ZFS pool in a
               file of setup/filepool.py) is used as is.
    Nothing here installs or touches the model server.
"""

import os
import re
import subprocess

from .audit import AuditLog

DEFAULT_MODELS_DIR = '/var/db/ai/models'
PATH_RE = re.compile(r'^/[A-Za-z0-9._/-]{0,254}$')
LOCAL_FSTYPES = {'zfs', 'ufs', 'tmpfs', 'ext2fs', 'msdosfs'}
FORBIDDEN_PREFIXES = ('/dev', '/proc', '/tmp', '/var/tmp', '/conf', '/boot')
PREPARE_PREFIX = '/var/db/'
DATASET_NAME = 'ai'
DATASET_MOUNTPOINT = '/var/db/ai'
DATASET_PROPERTIES = (
    ('mountpoint', DATASET_MOUNTPOINT),
    ('recordsize', '1M'),
    ('compression', 'off'),
    ('atime', 'off'),
    ('primarycache', 'metadata'),
)
STORAGE_LOG = '/var/log/policyanalyzer/storage.log'
SHARED_DISK_NOTE = ('without ZFS, models in %s share the system disk with /var (logs, config backups): the setup '
                    'refuses a download that would leave less than 2 GiB free there; a ZFS pool in a file '
                    '(create_file_pool) gives the models a fixed size limit, an Ollama server in the LAN keeps them '
                    'off the firewall')


def validate_path(path):
    """ :return: normalised path or raises ValueError """
    if not isinstance(path, str) or not PATH_RE.match(path):
        raise ValueError('path must be absolute and only contain letters, digits, ".", "_", "-" and "/"')
    if '..' in path.split('/') or '//' in path:
        raise ValueError('path may not contain ".." or empty components')
    path = os.path.normpath(path)
    if path == '/' or any(path == p or path.startswith(p + '/') for p in FORBIDDEN_PREFIXES):
        raise ValueError('path is not allowed for model storage')
    return path


def _run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return ''
    return out.stdout if out.returncode == 0 else ''


def _existing_parent(path):
    probe = path
    while not os.path.exists(probe) and probe != '/':
        probe = os.path.dirname(probe)
    return probe


def _mount_of(path):
    """ :return: (device, mountpoint, fstype) of the filesystem holding path, from `mount -p` """
    best = ('', '/', '')
    for line in _run(['/sbin/mount', '-p']).splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        device, mountpoint, fstype = fields[0], fields[1], fields[2]
        if (path == mountpoint or path.startswith(mountpoint.rstrip('/') + '/')) and len(mountpoint) >= len(best[1]):
            best = (device, mountpoint, fstype)
    return best


def inspect(path, validate=True):
    path = validate_path(path) if validate else os.path.normpath(path)
    probe = _existing_parent(path)
    result = {
        'status': 'ok',
        'path': path,
        'exists': os.path.isdir(path),
        'checked_path': probe,
        'writable': False,
        'filesystem': None,
        'fstype': None,
        'mountpoint': None,
        'local': None,
        'dataset': None,
        'free_bytes': None,
        'total_bytes': None,
    }
    try:
        vfs = os.statvfs(probe)
        result['free_bytes'] = vfs.f_bavail * vfs.f_frsize
        result['total_bytes'] = vfs.f_blocks * vfs.f_frsize
        readonly = bool(vfs.f_flag & getattr(os, 'ST_RDONLY', 1))
        result['writable'] = (not readonly) and os.access(probe, os.W_OK)
    except OSError as exc:
        result.update({'status': 'error', 'message': str(exc)})
        return result
    device, mountpoint, fstype = _mount_of(probe)
    result.update({'filesystem': device or None, 'mountpoint': mountpoint, 'fstype': fstype or None})
    result['local'] = (fstype in LOCAL_FSTYPES) if fstype else None
    if fstype == 'zfs' and device:
        result['dataset'] = device
        avail = _run(['/sbin/zfs', 'get', '-Hp', '-o', 'value', 'available', device]).strip()
        if avail.isdigit():
            result['free_bytes'] = int(avail)
    return result


def validate_prepare_path(path):
    path = validate_path(path)
    if not path.startswith(PREPARE_PREFIX):
        raise ValueError('storage can only be prepared below %s' % PREPARE_PREFIX)
    return path


def _zfs_root_pool():
    """ :return: pool name holding / when the root filesystem is ZFS, else None """
    if _mount_of('/')[2] != 'zfs':
        return None
    name = _run(['/sbin/zfs', 'list', '-H', '-o', 'name', '/']).strip()
    return name.split('/')[0] if name else None


def _dataset_exists(name):
    return _run(['/sbin/zfs', 'list', '-H', '-o', 'name', name]).strip() == name


def _fmt_bytes(value):
    if value is None:
        return 'unknown'
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if value < 1024 or unit == 'TiB':
            return '%.1f %s' % (value, unit) if unit != 'B' else '%d B' % value
        value /= 1024.0


def plan(path):
    """
    :return: change plan in the generic plan/apply format (see ai/changes.py); nothing is executed.
             steps[].argv holds the exact command apply() runs.
    """
    path = validate_prepare_path(path)
    steps = []
    warnings = []
    dataset = None
    pool = _zfs_root_pool()
    below_ds = path == DATASET_MOUNTPOINT or path.startswith(DATASET_MOUNTPOINT + '/')
    if pool and below_ds:
        dataset = '%s/%s' % (pool, DATASET_NAME)
        if _dataset_exists(dataset):
            warnings.append('dataset %s already exists, it is left untouched' % dataset)
        elif os.path.isdir(DATASET_MOUNTPOINT) and _mount_of(DATASET_MOUNTPOINT)[1] != DATASET_MOUNTPOINT \
                and os.listdir(DATASET_MOUNTPOINT):
            # mounting a dataset here would hide existing files
            warnings.append('%s exists and is not empty, no dataset is created' % DATASET_MOUNTPOINT)
            dataset = None
        else:
            argv = ['/sbin/zfs', 'create']
            for prop, value in DATASET_PROPERTIES:
                argv += ['-o', '%s=%s' % (prop, value)]
            argv.append(dataset)
            steps.append({
                'type': 'zfs_create',
                'description': 'Create ZFS dataset %s mounted on %s' % (dataset, DATASET_MOUNTPOINT),
                'argv': argv,
                'effect': 'new dataset sharing the free space of pool %s (no quota or reservation); '
                          'tuned for large write-once files: recordsize=1M, compression=off, atime=off, '
                          'primarycache=metadata' % pool,
            })
    elif pool:
        warnings.append('path is outside %s, only a directory is created on the existing dataset' % DATASET_MOUNTPOINT)
    else:
        device, mountpoint, fstype = _mount_of(DATASET_MOUNTPOINT)
        if below_ds and fstype == 'zfs' and mountpoint == DATASET_MOUNTPOINT:
            # ZFS pool in a file (setup create_file_pool) or another pool already mounted on /var/db/ai
            dataset = device
            warnings.append('%s is the ZFS dataset %s, only a directory is created in it' % (DATASET_MOUNTPOINT,
                                                                                            device))
        else:
            warnings.append('root filesystem is not ZFS, only a directory is created')
            warnings.append(SHARED_DISK_NOTE % path)
    if not os.path.isdir(path):
        steps.append({
            'type': 'mkdir',
            'description': 'Create directory %s' % path,
            'argv': ['/bin/mkdir', '-p', '-m', '0750', path],
            'effect': 'directory (and missing parents) owned by root:wheel, mode 0750',
        })
    else:
        warnings.append('%s already exists, nothing to do' % path)
    info = inspect(_existing_parent(path), validate=False)
    for step in steps:
        step['command'] = ' '.join(step['argv'])
    revert = []
    if any(s['type'] == 'mkdir' for s in steps):
        revert.append('remove the directories created here, only while they are empty')
    if any(s['type'] == 'zfs_create' for s in steps):
        revert.append('destroy dataset %s, only while it holds no files, children or snapshots' % dataset)
    return {
        'revert': revert,
        'irreversible': [],
        'status': 'ok',
        'action': 'prepare_storage',
        'args': {'path': path},
        'steps': steps,
        'warnings': warnings,
        'requires_confirmation': bool(steps),
        'risk': 'low' if steps else 'none',
        'space': 'models typically need 2-50 GiB each; %s free' % _fmt_bytes(info.get('free_bytes')),
        'path': path,
        'dataset': dataset,
    }


def prepare(path, log=None):
    """
    execute plan(path), recomputed here (never taken from the client).
    result['state'] records what this run created, for revert_plan().
    """
    log = log if log is not None else AuditLog(STORAGE_LOG)
    todo = plan(path)
    done = []
    state = {'created_dirs': [], 'created_dataset': None}
    todo['state'] = state
    for step in todo['steps']:
        missing = _missing_dirs(todo['path']) if step['type'] == 'mkdir' else []
        out = subprocess.run(step['argv'], capture_output=True, text=True, timeout=60, check=False)
        entry = {'action': 'prepare_storage', 'step': step['type'], 'command': step['command'], 'rc': out.returncode}
        if out.returncode != 0:
            entry['error'] = (out.stderr or out.stdout).strip()[:500]
            log.record(app='policyanalyzer', status='error', **entry)
            todo.update({'status': 'error', 'done': False, 'completed': done, 'failed': step['command'],
                         'message': entry['error']})
            return todo
        if step['type'] == 'zfs_create':
            state['created_dataset'] = step['argv'][-1]
        elif step['type'] == 'mkdir':
            state['created_dirs'] = missing
            os.chown(todo['path'], 0, 0)
            os.chmod(todo['path'], 0o750)
        log.record(app='policyanalyzer', status='ok', **entry)
        done.append(step['command'])
    info = inspect(todo['path'], validate=False)
    todo.update({'done': True, 'completed': done, 'dataset': info.get('dataset') or todo['dataset'],
                 'available': info.get('free_bytes'), 'exists': info.get('exists')})
    return todo


def _missing_dirs(path):
    """ directories mkdir -p would create, deepest first """
    missing = []
    probe = path
    while probe != '/' and not os.path.exists(probe):
        missing.append(probe)
        probe = os.path.dirname(probe)
    return missing


def _is_empty_dir(path):
    try:
        return os.path.isdir(path) and not os.listdir(path)
    except OSError:
        return False


def revert_plan(entry):
    """ inverse of prepare(): only what that run created, only while empty """
    state = entry.get('state') or {}
    steps, warnings = [], []
    dirs = [d for d in state.get('created_dirs') or [] if os.path.isdir(d)]
    dataset = state.get('created_dataset')
    blocked = False
    # deepest first; a directory is only removable when everything below it goes as well
    for idx, directory in enumerate(dirs):
        children = set(os.listdir(directory)) if os.path.isdir(directory) else set()
        expected = {os.path.basename(d) for d in dirs[:idx] if os.path.dirname(d) == directory}
        if blocked or children - expected:
            warnings.append('%s is not empty, it is kept' % directory)
            blocked = True
            continue
        steps.append({'type': 'rmdir', 'description': 'Remove empty directory %s' % directory,
                      'argv': ['/bin/rmdir', directory], 'effect': 'directory removed'})
    if dataset:
        if not _dataset_exists(dataset):
            warnings.append('dataset %s no longer exists' % dataset)
        else:
            mountpoint = _run(['/sbin/zfs', 'get', '-H', '-o', 'value', 'mountpoint', dataset]).strip()
            others = _run(['/sbin/zfs', 'list', '-H', '-t', 'all', '-r', '-o', 'name', dataset]).split()
            removable = set()
            if not blocked:
                removable = {os.path.basename(d) for d in dirs if os.path.dirname(d) == mountpoint}
            try:
                content = set(os.listdir(mountpoint)) if mountpoint and os.path.isdir(mountpoint) else set()
            except OSError:
                content = {'?'}
            if blocked or content - removable or others != [dataset]:
                warnings.append('dataset %s holds data, children or snapshots: it is kept, only empty folders '
                                'are removed' % dataset)
            else:
                steps.append({'type': 'zfs_destroy',
                              'description': 'Unmount and destroy the empty dataset %s' % dataset,
                              'argv': ['/sbin/zfs', 'destroy', dataset],
                              'effect': 'dataset created by this action is removed, its space returns to the pool'})
    for step in steps:
        step['command'] = ' '.join(step['argv'])
    return {'status': 'ok', 'action': 'revert', 'target': entry.get('id'), 'steps': steps, 'warnings': warnings,
            'irreversible': [], 'requires_confirmation': bool(steps), 'risk': 'low' if steps else 'none'}


def revert_apply(entry, log=None):
    log = log if log is not None else AuditLog(STORAGE_LOG)
    todo = revert_plan(entry)
    done = []
    for step in todo['steps']:
        out = subprocess.run(step['argv'], capture_output=True, text=True, timeout=60, check=False)
        record = {'action': 'revert_prepare_storage', 'step': step['type'], 'command': step['command'],
                  'rc': out.returncode, 'journal': entry.get('id')}
        if out.returncode != 0:
            record['error'] = (out.stderr or out.stdout).strip()[:500]
            log.record(app='policyanalyzer', status='error', **record)
            todo.update({'status': 'error', 'done': False, 'completed': done, 'message': record['error']})
            return todo
        log.record(app='policyanalyzer', status='ok', **record)
        done.append(step['command'])
    todo.update({'done': True, 'completed': done})
    return todo
