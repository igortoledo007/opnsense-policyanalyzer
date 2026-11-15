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

    Shared pieces of the runtime setup: paths (Context), parameter validation,
    command runner, HTTP client, lock, state file, log and undo journals.

    Everything that touches the system goes through Context so the tests can
    point it at a scratch directory and replace the runner / HTTP client.
    Functions used by plan() never write; writers are clearly named
    (write_*, save_*, append_*) and only called from the executor.
"""

import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------- constants

FREEBSD_RELEASE = '15.1-RELEASE'
FREEBSD_ARCH = 'amd64'
FREEBSD_DIST_URL = 'https://download.freebsd.org/releases/%s/%s/' % (FREEBSD_ARCH, FREEBSD_RELEASE)
PKG_ABI = 'FreeBSD:15:amd64'
PKG_BRANCHES = ('quarterly', 'latest')
OLLAMA_REGISTRY = 'https://registry.ollama.ai'
OLLAMA_URL = 'http://127.0.0.1:11434'
OLLAMA_MIN_VERSION = (0, 17, 1)          # CVE-2026-7482 fixed in 0.17.1
JAIL_NAME = 'ollama'
JAIL_IP = '127.0.0.1'
JAIL_SERVICE_USER = 'nobody'
JAIL_SERVICE_UID = 65534
JAIL_MODELS_MOUNT = '/var/lib/ollama/models'   # fixed by the port's rc script for user nobody
JAIL_SERVICE_HOME = '/var/lib/ollama'          # writable HOME: ollama serve creates ~/.ollama/id_ed25519 at start
JAIL_OLLAMA_LOG = '/var/log/ollama.log'        # daemon -o target inside the jail (ollama_log)
GIB = 1024 ** 3
MIB = 1024 ** 2

# Download sizes measured on 2026-11-07 (only used when the live value can not be read).
BASE_TXZ_BYTES_ESTIMATE = 164624792
BASE_EXTRACTED_BYTES_ESTIMATE = 695943538        # sum of file sizes in base.txz
PKG_DOWNLOAD_ESTIMATE = {'quarterly': 171457156, 'latest': 166597579}      # ollama + deps + pkg
PKG_INSTALLED_ESTIMATE = {'quarterly': 865506985, 'latest': 840764781}
SPACE_MARGIN_BYTES = 1 * GIB

DEFAULT_LIMITS = {
    'cpus': '2-3',
    'threads': 2,
    'ctx': 8192,
    'nice': 20,
    'keep_alive': '5m',
    'num_parallel': 1,
    'max_loaded_models': 1,
    'max_queue': 2,
    'mem_gb': 12,
}

# ---------------------------------------------------------------- context


class Context:
    """ every path and system interface used by the setup, overridable for tests """

    def __init__(self, root='', runner=None, http=None, ncpu=None, is_root=None, clock=None, official=False):
        def p(path):
            return root + path if root else path
        self.root = root
        self.ai_dir = p('/var/db/ai')
        self.models_dir = p('/var/db/ai/models')
        self.jail_dir = p('/var/db/ai/jail')
        self.staging_dir = p('/var/db/ai/.staging')
        self.jail_conf_dir = p('/etc/jail.conf.d')
        self.jail_conf = p('/etc/jail.conf.d/%s.conf' % JAIL_NAME)
        self.rc_conf_jail = p('/etc/rc.conf.d/jail')
        self.host_resolv = p('/etc/resolv.conf')
        self.state_dir = p('/var/db/policyanalyzer')
        self.state_file = p('/var/db/policyanalyzer/setup-state.json')
        self.limits_file = p('/var/db/policyanalyzer/runtime-limits.json')
        self.bench_file = p('/var/db/policyanalyzer/benchmark.json')
        self.journal_dir = p('/var/db/policyanalyzer/setup-journal')   # working copies; the official undo entry is ai/journal.py
        self.lock_file = p('/var/db/policyanalyzer/setup.lock')
        self.cancel_file = p('/var/db/policyanalyzer/setup.cancel')
        self.log_file = p('/var/log/policyanalyzer/setup.log')
        self.config_xml = p('/conf/config.xml')
        self.loader_conf = p('/boot/loader.conf')
        self.php = '/usr/local/bin/php'
        here = globals().get('__file__')
        self.tunables_php = os.path.join(os.path.dirname(os.path.abspath(here)), 'tunables.php') if here \
            else '/usr/local/opnsense/scripts/policyanalyzer/setup/tunables.php'
        self.configctl = '/usr/local/sbin/configctl'
        self.console_log = '/var/log/policyanalyzer/jail-%s.console.log' % JAIL_NAME
        self.runner = runner or Runner()
        self.http = http or Http()
        self._ncpu = ncpu
        self._is_root = is_root
        self.clock = clock or time.time
        self._official = official

    @property
    def official(self):
        """ the plugin's undo journal module (ai/journal.py) or None when running standalone """
        if self._official is False:
            try:
                from ai import journal as official_journal
            except ImportError:
                official_journal = None
            self._official = official_journal
        return self._official

    # jail relative paths (inside the jail root)
    def in_jail(self, path):
        return self.jail_dir + path

    @property
    def ncpu(self):
        if self._ncpu is None:
            out = self.runner.read(['/sbin/sysctl', '-n', 'hw.ncpu']).strip()
            self._ncpu = int(out) if out.isdigit() else (os.cpu_count() or 1)
        return self._ncpu

    @property
    def is_root(self):
        return os.geteuid() == 0 if self._is_root is None else self._is_root


class SetupError(Exception):
    pass


class Cancelled(SetupError):
    pass


class BusyError(SetupError):
    pass


# ---------------------------------------------------------------- runner / http


class Runner:
    """ argv only, never a shell """

    def run(self, argv, timeout=600, env=None, cancel=None):
        """ :param cancel: optional callable polled every second, raises to abort (the child is killed) """
        if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
            raise SetupError('invalid command')
        try:
            proc = subprocess.Popen(list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    env=env, stdin=subprocess.DEVNULL)
        except OSError as exc:
            return 127, '', str(exc)
        deadline = time.time() + timeout
        while True:
            try:
                out, err = proc.communicate(timeout=1 if cancel else max(0.1, deadline - time.time()))
                return proc.returncode, out, err
            except subprocess.TimeoutExpired:
                abort = None
                if cancel:
                    try:
                        cancel()
                    except BaseException as exc:      # noqa: BLE001 - re-raised after the child is gone
                        abort = exc
                if abort is not None or time.time() >= deadline:
                    proc.kill()
                    proc.communicate()
                    if abort is not None:
                        raise abort
                    return 124, '', 'timeout after %ds' % timeout

    def read(self, argv, timeout=15):
        """ read only helper: stdout on success, '' otherwise """
        rc, out, _ = self.run(argv, timeout=timeout)
        return out if rc == 0 else ''


# Hugging Face (import_gguf): only the model API and the "resolve" URL of a .gguf, and as redirect targets only the
# CDN hosts of Hugging Face (LFS and Xet storage); every hop is checked, plain http is never followed
HF_ALLOWED_RE = re.compile(r'^https://huggingface\.co/(api/models/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/revision/'
                           r'[A-Za-z0-9._-]+\?blobs=true|[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/resolve/[0-9a-f]{40}/'
                           r'[A-Za-z0-9._/-]+\.gguf)$')
HF_REDIRECT_RE = re.compile(r'^https://(cdn-lfs(-[a-z0-9]+)*\.(huggingface\.co|hf\.co)|'
                            r'cas-bridge\.xethub\.hf\.co|transfer\.xethub\.hf\.co)/')


class _HfRedirect(urllib.request.HTTPRedirectHandler):
    """ follow a redirect only to the Hugging Face CDN (https) """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not HF_REDIRECT_RE.match(newurl or '') and not HF_ALLOWED_RE.match(newurl or ''):
            raise SetupError('redirect to a host outside the Hugging Face CDN refused: %s'
                             % (newurl or '').split('?')[0])
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Http:
    """ tiny urllib wrapper (https/127.0.0.1 only) """

    ALLOWED_PREFIXES = (FREEBSD_DIST_URL, OLLAMA_REGISTRY + '/', OLLAMA_URL + '/')

    def _check(self, url):
        if HF_ALLOWED_RE.match(url or ''):
            return
        if not any(url.startswith(p) for p in self.ALLOWED_PREFIXES):
            raise SetupError('URL not allowed: %s' % url)

    _local_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never proxy 127.0.0.1
    _hf_opener = urllib.request.build_opener(_HfRedirect())

    def open(self, url, data=None, headers=None, timeout=30, method=None):
        self._check(url)
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        if url.startswith(OLLAMA_URL + '/'):
            return self._local_opener.open(req, timeout=timeout)
        if HF_ALLOWED_RE.match(url):
            return self._hf_opener.open(req, timeout=timeout)
        return urllib.request.urlopen(req, timeout=timeout)

    def get_bytes(self, url, headers=None, timeout=30, limit=4 * MIB):
        with self.open(url, headers=headers, timeout=timeout) as resp:
            data = resp.read(limit + 1)
        if len(data) > limit:
            raise SetupError('response too large: %s' % url)
        return data

    def head_size(self, url, timeout=15):
        try:
            with self.open(url, timeout=timeout, method='HEAD') as resp:
                value = resp.headers.get('Content-Length')
                return int(value) if value and value.isdigit() else None
        except (OSError, urllib.error.URLError, SetupError, ValueError):
            return None

    def get_json(self, url, timeout=10, body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {'Content-Type': 'application/json'} if body is not None else {}
        with self.open(url, data=data, headers=headers, timeout=timeout) as resp:
            return json.loads(resp.read(16 * MIB).decode('utf-8', 'replace') or 'null')


# ---------------------------------------------------------------- validation

# the tag keeps the registry's case: quantization tags such as "30b-a3b-instruct-2507-q4_K_M" are mixed case
MODEL_RE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}(:[A-Za-z0-9][A-Za-z0-9._-]{0,63})?$')
CPUSET_RE = re.compile(r'^[0-9]{1,3}(-[0-9]{1,3})?(,[0-9]{1,3}(-[0-9]{1,3})?){0,15}$')
JOURNAL_ID_RE = re.compile(r'^[0-9]{8}T[0-9]{6}-[a-z_]{3,32}-[0-9a-f]{6}$')
KEEP_ALIVE_RE = re.compile(r'^([0-9]{1,3}[smh]|0|-1)$')
YES = ('1', 'yes', 'true', 'on')
NO = ('0', 'no', 'false', 'off', '')
CTX_VALUES = (2048, 4096, 8192, 16384, 32768)


def as_bool(value, default=False, name='flag'):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in YES:
        return True
    if text in NO:
        return False if text else default
    raise ValueError('%s must be yes or no' % name)


def as_int(value, low, high, name):
    text = str(value).strip()
    if not re.match(r'^[0-9]{1,6}$', text):
        raise ValueError('%s must be an integer' % name)
    number = int(text)
    if number < low or number > high:
        raise ValueError('%s must be between %d and %d' % (name, low, high))
    return number


def parse_cpuset(value, ncpu):
    """ '2-3' or '0,2' -> sorted list of cpu ids, validated against ncpu """
    text = str(value).strip()
    if not CPUSET_RE.match(text):
        raise ValueError('cpus must be a cpu list like 2-3 or 0,2')
    cpus = set()
    for part in text.split(','):
        low, _, high = part.partition('-')
        low = int(low)
        high = int(high) if high else low
        if high < low:
            raise ValueError('invalid cpu range %s' % part)
        cpus.update(range(low, high + 1))
    if max(cpus) >= ncpu:
        raise ValueError('cpu %d does not exist (this system has %d cpus)' % (max(cpus), ncpu))
    return sorted(cpus)


def format_cpuset(cpus):
    cpus = sorted(cpus)
    parts = []
    start = prev = cpus[0]
    for cpu in cpus[1:] + [None]:
        if cpu is not None and cpu == prev + 1:
            prev = cpu
            continue
        parts.append(str(start) if start == prev else '%d-%d' % (start, prev))
        if cpu is not None:
            start = prev = cpu
    return ','.join(parts)


def validate_model(name):
    if not isinstance(name, str) or not MODEL_RE.match(name):
        raise ValueError('model name must look like name:tag (name in lowercase; letters, digits, ".", "_", "-")')
    base, _, tag = name.partition(':')
    return base, (tag or 'latest')


def validate_journal_id(value):
    if not isinstance(value, str) or not JOURNAL_ID_RE.match(value):
        raise ValueError('invalid journal id')
    return value


def fmt_bytes(value):
    if value is None:
        return 'unknown'
    value = float(value)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(value) < 1024 or unit == 'TiB':
            return ('%d B' % value) if unit == 'B' else '%.1f %s' % (value, unit)
        value /= 1024.0
    return str(value)


def parse_version(text):
    nums = re.findall(r'[0-9]+', text or '')
    return tuple(int(n) for n in nums[:3]) if nums else None


# ---------------------------------------------------------------- read only system probes


def free_bytes(path):
    probe = path
    while probe and not os.path.exists(probe) and probe != '/':
        probe = os.path.dirname(probe)
    try:
        vfs = os.statvfs(probe or '/')
    except OSError:
        return None
    return vfs.f_bavail * vfs.f_frsize


def mounts(ctx):
    """ [(device, mountpoint, fstype)] from mount -p """
    result = []
    for line in ctx.runner.read(['/sbin/mount', '-p']).splitlines():
        fields = line.split()
        if len(fields) >= 3:
            result.append((fields[0], fields[1], fields[2]))
    return result


def mount_of(ctx, path):
    best = ('', '/', '')
    for device, mountpoint, fstype in mounts(ctx):
        if (path == mountpoint or path.startswith(mountpoint.rstrip('/') + '/')) and len(mountpoint) >= len(best[1]):
            best = (device, mountpoint, fstype)
    return best


def mounts_below(ctx, path):
    prefix = path.rstrip('/') + '/'
    return [m for m in mounts(ctx) if m[1].startswith(prefix)]


def dataset_exists(ctx, name):
    return ctx.runner.read(['/sbin/zfs', 'list', '-H', '-o', 'name', name]).strip() == name


def sysctl(ctx, name):
    return ctx.runner.read(['/sbin/sysctl', '-n', name]).strip()


def jail_jid(ctx):
    out = ctx.runner.read(['/usr/sbin/jls', '-j', JAIL_NAME, 'jid']).strip()
    return int(out) if out.isdigit() else None


def read_text(path, limit=1 * MIB):
    try:
        with open(path, 'rb') as handle:
            return handle.read(limit).decode('utf-8', 'replace')
    except OSError:
        return None


def read_json(path, default=None):
    text = read_text(path, limit=16 * MIB)
    if text is None:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def lock_holder(ctx):
    """ read only: is another setup action running? """
    try:
        fd = os.open(ctx.lock_file, os.O_RDONLY)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    except OSError:
        state = read_json(ctx.state_file, {}) or {}
        return (state.get('job') or {}).get('action') or 'unknown'
    finally:
        os.close(fd)


# ---------------------------------------------------------------- writers (apply only)


def ensure_dir(path, mode=0o750):
    os.makedirs(path, mode=mode, exist_ok=True)


def write_atomic(path, data, mode=0o640, dir_mode=0o750):
    ensure_dir(os.path.dirname(path), dir_mode)
    if isinstance(data, str):
        data = data.encode('utf-8')
    tmp = '%s.tmp.%d' % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json(path, data, mode=0o640):
    write_atomic(path, json.dumps(data, indent=2, sort_keys=True) + '\n', mode)


class Lock:
    """ one setup action at a time (flock, inherited by the background worker) """

    def __init__(self, ctx, fd=None):
        self.ctx = ctx
        self.fd = fd

    def acquire(self):
        if self.fd is not None:
            return self
        ensure_dir(os.path.dirname(self.ctx.lock_file))
        fd = os.open(self.ctx.lock_file, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                raise BusyError('another setup action is running (%s)' % (lock_holder(self.ctx) or 'unknown'))
            raise
        self.fd = fd
        return self

    def release(self):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()


class SetupLog:
    def __init__(self, ctx):
        self.path = ctx.log_file

    def record(self, **event):
        entry = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
        entry.update({k: v for k, v in event.items() if v is not None})
        try:
            ensure_dir(os.path.dirname(self.path))
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            with os.fdopen(fd, 'a') as handle:
                handle.write(json.dumps(entry, sort_keys=True, default=str) + '\n')
        except OSError:
            return False
        return True


class State:
    """ /var/db/policyanalyzer/setup-state.json: current job and progress, polled by the UI """

    def __init__(self, ctx):
        self.ctx = ctx

    def load(self):
        return read_json(self.ctx.state_file, {}) or {}

    def update_job(self, **fields):
        data = self.load()
        job = data.get('job') or {}
        job.update(fields)
        job['updated'] = int(self.ctx.clock())
        data['job'] = job
        write_json(self.ctx.state_file, data)
        return job

    def finish_job(self, status, result=None):
        data = self.load()
        job = data.get('job') or {}
        job.update({'status': status, 'finished': int(self.ctx.clock()), 'pid': None})
        if result is not None:
            job['result'] = result
        history = data.get('history') or []
        history.insert(0, {k: job.get(k) for k in ('id', 'action', 'args', 'status', 'started', 'finished',
                                                     'journal')})
        data['history'] = history[:30]
        data['job'] = job
        write_json(self.ctx.state_file, data)


def check_cancel(ctx, job_id=None):
    text = read_text(ctx.cancel_file)
    if text is not None and (job_id is None or text.strip() in ('', job_id, '*')):
        raise Cancelled('cancelled by the user')


# ---------------------------------------------------------------- journals


def new_journal_id(ctx, action):
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime(ctx.clock()))
    return '%s-%s-%s' % (stamp, action, secrets.token_hex(3))


def journal_path(ctx, journal_id):
    return os.path.join(ctx.journal_dir, validate_journal_id(journal_id) + '.json')


def _official_entries(ctx):
    if ctx.official is None:
        return []
    return [e for e in ctx.official.entries() if isinstance((e.get('state') or {}).get('journal'), dict)]


def _merge_official(entry):
    journal = dict(entry['state']['journal'])
    journal['official'] = entry['id']
    reverted = entry.get('reverted')
    if reverted and journal.get('status') == 'applied':
        journal['status'] = 'superseded' if reverted.get('status') == 'superseded' else 'reverted'
    return journal


def load_journal(ctx, journal_id):
    """ our journal: from the official undo entry (state.journal) or the working copy """
    validate_journal_id(journal_id)
    for entry in _official_entries(ctx):
        if entry['state'].get('setup_journal') == journal_id:
            return _merge_official(entry)
    data = read_json(journal_path(ctx, journal_id))
    if not isinstance(data, dict):
        raise SetupError('journal %s not found' % journal_id)
    return data


def save_journal(ctx, journal):
    """ working copy, rewritten after every step (crash safety); folded into the official entry at the end """
    ensure_dir(ctx.journal_dir)
    write_json(journal_path(ctx, journal['id']), journal, mode=0o600)


def drop_working_copy(ctx, journal_id):
    """ once the official entry holds the journal; kept when running standalone (it is the only copy) """
    if ctx.official is None:
        return
    try:
        os.unlink(journal_path(ctx, journal_id))
    except OSError:
        pass


def update_journal(ctx, journal_id, official_reverted=None, **fields):
    """ change status fields of a finished journal wherever it is stored """
    for entry in _official_entries(ctx):
        if entry['state'].get('setup_journal') == journal_id:
            entry['state']['journal'].update(fields)
            if official_reverted is not None:
                entry['reverted'] = official_reverted
            ctx.official.write(entry)
            return
    data = read_json(journal_path(ctx, journal_id))
    if isinstance(data, dict):
        data.update(fields)
        save_journal(ctx, data)


def list_journals(ctx):
    """ every journal (official entries first, then working copies not yet folded), oldest first """
    result = {}
    for entry in _official_entries(ctx):
        journal = _merge_official(entry)
        result[journal['id']] = journal
    try:
        names = sorted(os.listdir(ctx.journal_dir))
    except OSError:
        names = []
    for name in names:
        if name.endswith('.json') and JOURNAL_ID_RE.match(name[:-5]) and name[:-5] not in result:
            data = read_json(os.path.join(ctx.journal_dir, name))
            if isinstance(data, dict):
                result[data['id']] = data
    items = list(result.values())
    items.sort(key=lambda j: (j.get('created') or 0, j.get('seq') or 0, j.get('id')))
    return items


def b64(data):
    return base64.b64encode(data).decode('ascii') if data is not None else None


def unb64(text):
    return base64.b64decode(text) if text is not None else None


def sha256_file(path, chunk=4 * MIB, cancel=None):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
            if cancel:
                cancel()
    return digest.hexdigest()
