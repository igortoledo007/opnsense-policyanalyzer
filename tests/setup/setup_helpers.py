"""
Helpers for the runtime setup tests: import path, a fake FreeBSD (commands) and a fake HTTP side
(download.freebsd.org, registry.ollama.ai, local Ollama).  Nothing touches the real system or network.
"""

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
SCRIPTS = os.path.join(ROOT, 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from setup import common  # noqa: E402

BASE_TXZ = b'fake base.txz content ' * 100
BASE_SHA = hashlib.sha256(BASE_TXZ).hexdigest()
MANIFEST = ('base-dbg.txz\t%s\t1\tbase_dbg\t"x"\toff\nbase.txz\t%s\t30469\tbase\t"Base"\ton\n'
            % ('0' * 64, BASE_SHA)).encode()


def blob(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest(), data


MODEL_LAYERS = [blob(b'GGUF model weights ' * 50), blob(b'{"template": "x"}'), blob(b'license text')]
MODEL_CONFIG = blob(b'{"model_format":"gguf"}')


def model_manifest(layers=MODEL_LAYERS, config=MODEL_CONFIG, sizes=None):
    return json.dumps({
        'schemaVersion': 2, 'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
        'config': {'digest': config[0], 'size': len(config[1]), 'mediaType': 'application/vnd.docker.container.image.v1+json'},
        'layers': [{'digest': d, 'size': (sizes or {}).get(d, len(b)), 'mediaType': 'application/vnd.ollama.image.model'}
                   for d, b in layers],
    })


class _Resp(io.BytesIO):
    def __init__(self, data, headers=None):
        super().__init__(data)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeHttp(common.Http):
    """ in-memory replacement of common.Http (keeps the URL allow-list check) """

    def __init__(self, system):
        self.system = system
        self.requests = []
        self.blobs = {d: b for d, b in MODEL_LAYERS + [MODEL_CONFIG]}
        other = blob(b'other weights ' * 40)
        self.blobs[other[0]] = other[1]
        self.manifests = {('qwen2.5', '3b'): model_manifest(), ('llama3.2', '3b'): model_manifest(
            layers=[other, MODEL_LAYERS[2]])}
        self.fail_blob_after = None      # callable hook during blob reads
        self.generate = {'response': '{}', 'prompt_eval_count': 120, 'prompt_eval_duration': 6 * 10 ** 9,
                         'eval_count': 64, 'eval_duration': 8 * 10 ** 9, 'load_duration': 2 * 10 ** 9}

    def open(self, url, data=None, headers=None, timeout=30, method=None):
        self._check(url)
        self.requests.append((method or ('POST' if data else 'GET'), url))
        if url == common.FREEBSD_DIST_URL + 'MANIFEST':
            return _Resp(MANIFEST)
        if url == common.FREEBSD_DIST_URL + 'base.txz':
            return _Resp(b'' if method == 'HEAD' else BASE_TXZ, {'Content-Length': str(len(BASE_TXZ))})
        if url.startswith(common.OLLAMA_REGISTRY + '/v2/library/'):
            rest = url[len(common.OLLAMA_REGISTRY + '/v2/library/'):]
            name, kind, ref = rest.split('/', 2)
            if kind == 'manifests':
                if (name, ref) not in self.manifests:
                    raise OSError('404')
                return _Resp(self.manifests[(name, ref)].encode())
            if self.fail_blob_after:
                self.fail_blob_after(ref)
            return _Resp(self.blobs[ref])
        if url.startswith(common.OLLAMA_URL):
            if not self.system.running or self.system.api_down:
                raise OSError('connection refused')
            path = url[len(common.OLLAMA_URL):]
            body = {'/api/version': {'version': '0.34.3'}, '/api/tags': {'models': []},
                    '/api/ps': {'models': [{'name': 'qwen2.5:3b', 'size': 3 * 1024 ** 3}]},
                    '/api/generate': self.generate}[path]
            return _Resp(json.dumps(body).encode())
        raise OSError('unexpected url %s' % url)


class FakeSystem:
    """ answers the FreeBSD commands used by the setup, recording every call """

    def __init__(self, root, zfs=True, racct=False, ncpu=4):
        self.root = root
        self.calls = []
        self.datasets = {'zroot/ai': '/var/db/ai'} if zfs else {}
        self.mounts = [('zroot/ai', '/var/db/ai', 'zfs')] if zfs else []
        self.running = False
        self.sysctl = {'kern.racct.enable': '1' if racct else '0', 'hw.ncpu': str(ncpu),
                       'kern.osrelease': '15.1-RELEASE-p6', 'hw.machine_arch': 'amd64'}
        self.fail_on = None
        self.listeners = ['127.0.0.1:11434']
        self.api_down = False            # jail up but the API never answers
        self.ollama_alive = True         # result of "jexec ollama pgrep -x ollama"
        self.zfs_loaded = zfs            # kldstat -q -m zfs
        self.pools = {'zroot'} if zfs else set()
        self.md = {}                     # unit -> backing file (mdconfig -t vnode)

    def p(self, path):
        return path if path.startswith(self.root) else self.root + path

    def run(self, argv, timeout=600, env=None, cancel=None):
        self.calls.append(list(argv))
        cmd = ' '.join(argv)
        if self.fail_on and self.fail_on in cmd:
            return 1, '', 'simulated failure'
        if cancel:
            cancel()
        prog = argv[0]
        if prog == '/sbin/sysctl' and len(argv) == 2 and '=' in argv[1]:
            name, value = argv[1].split('=', 1)
            self.sysctl[name] = value
            return 0, '%s: x -> %s\n' % (name, value), ''
        if prog == '/sbin/kldstat':
            return (0, '', '') if self.zfs_loaded else (1, '', '')
        if prog == '/sbin/kldload':
            self.zfs_loaded = True
            return 0, '', ''
        if prog == '/sbin/mdconfig':
            return self._mdconfig(argv[1:])
        if prog == '/sbin/zpool':
            return self._zpool(argv[1:])
        if prog == '/sbin/sysctl':
            return (0, self.sysctl[argv[2]] + '\n', '') if argv[2] in self.sysctl else (1, '', 'unknown oid')
        if prog == '/sbin/mount' and argv[1] == '-p':
            return 0, ''.join('%s %s %s rw 0 0\n' % (d, m, f) for d, m, f in self.mounts), ''
        if prog == '/sbin/mount' and argv[1] == '-t':
            self.mounts.append((argv[3], argv[4], argv[2]))
            return 0, '', ''
        if prog == '/sbin/umount':
            self.mounts = [m for m in self.mounts if m[1] != argv[1]]
            return 0, '', ''
        if prog == '/sbin/zfs':
            if argv[1] == 'list' and '-r' in argv:
                name = argv[-1]
                if '-t' in argv:
                    return 0, '', ''             # no snapshots
                lines = ['%s\t%s' % (d, self.datasets[d] or 'none') for d in sorted(self.datasets)
                         if d == name or d.startswith(name + '/')]
                return (0, '\n'.join(lines) + '\n', '') if lines else (1, '', 'no such dataset')
            if argv[1] == 'list':
                return (0, argv[-1] + '\n', '') if argv[-1] in self.datasets else (1, '', 'no such dataset')
            if argv[1] == 'get':
                return 0, self.p(self.datasets.get(argv[-1], '-')) + '\n', ''
            if argv[1] == 'create':
                name = argv[-1]
                explicit = [a.split('=', 1)[1] for a in argv if a.startswith('mountpoint=')]
                mountpoint = explicit[0] if explicit else \
                    self.datasets[name.rsplit('/', 1)[0]] + '/' + name.rsplit('/', 1)[1]
                self.datasets[name] = mountpoint
                os.makedirs(self.p(mountpoint), exist_ok=True)
                self.mounts.append((name, mountpoint, 'zfs'))
                return 0, '', ''
            if argv[1] == 'destroy':
                name = argv[-1]
                for ds in [d for d in self.datasets if d == name or d.startswith(name + '/')]:
                    mountpoint = self.datasets.pop(ds)
                    shutil.rmtree(self.p(mountpoint), ignore_errors=True)
                    self.mounts = [m for m in self.mounts if m[0] != ds]
                return 0, '', ''
        if prog == '/usr/sbin/jls':
            return (0, '7\n', '') if self.running else (1, '', 'jail "ollama" not found')
        if prog == '/usr/sbin/jail':
            self.running = argv[3] == '-c'
            return 0, '', ''
        if prog == '/usr/bin/tar':
            dest = argv[argv.index('-C') + 1]
            for sub in ('bin', 'etc', 'dev', 'var/db', 'usr/share/keys/pkg'):
                os.makedirs(os.path.join(dest, sub), exist_ok=True)
            open(os.path.join(dest, 'bin', 'sh'), 'w').close()
            return 0, '', ''
        if prog == '/usr/sbin/chroot':
            jail = argv[1]
            if argv[3:5] == ['bootstrap', '-y']:
                target = os.path.join(jail, 'usr/local/sbin/pkg')
            elif 'install' in argv:
                target = os.path.join(jail, 'usr/local/bin/ollama')
            else:
                return 0, '', ''
            os.makedirs(os.path.dirname(target), exist_ok=True)
            open(target, 'w').close()
            return 0, '', ''
        if prog == '/bin/test':
            return (0, '', '') if os.path.exists(argv[2]) else (1, '', '')
        if prog == '/usr/bin/sockstat':
            lines = ['USER COMMAND PID FD PROTO LOCAL FOREIGN'] + [
                'nobody ollama 123 3 tcp4 %s *:*' % l for l in (self.listeners if self.running else [])]
            return 0, '\n'.join(lines) + '\n', ''
        if prog == '/usr/local/bin/php' and argv[1].endswith('tunables.php'):
            return self._tunables(argv[2:])
        if prog == '/usr/local/sbin/configctl':
            if argv[1:4] == ['service', 'restart', 'login']:
                os.makedirs(self.root + '/boot', exist_ok=True)
                with open(self.root + '/boot/loader.conf', 'w') as handle:
                    handle.write('# dynamically generated tunables settings follow\n' + ''.join(
                        '%s="%s"\n' % (k, v) for k, v in sorted(self.tunables.items())))
            return 0, 'OK\n', ''
        if prog == '/usr/sbin/jexec' and argv[2:3] == ['/bin/pgrep']:
            return (0, '123\n', '') if (self.running and self.ollama_alive) else (1, '', '')
        if prog == '/usr/sbin/jexec' and not self.running:
            return 1, '', 'jexec: jail "ollama" not found'
        if prog == '/sbin/dmesg':
            return 0, 'line1\nline2\n', ''
        if prog in ('/sbin/devfs', '/bin/chflags', '/usr/bin/cpuset', '/usr/sbin/jexec', '/usr/bin/rctl', '/bin/ps'):
            return 0, '', ''
        return 127, '', 'unexpected command %s' % cmd

    tunables = None

    def _mdconfig(self, args):
        if args[:1] == ['-lv']:
            return 0, ''.join('md%d\tvnode\t 4G\t%s\n' % (u, f) for u, f in sorted(self.md.items())), ''
        if args[:1] == ['-a']:
            unit = int(args[args.index('-u') + 1])
            if unit in self.md:
                return 1, '', 'mdconfig: ioctl(/dev/mdctl): Device busy'
            self.md[unit] = args[args.index('-f') + 1]
            return 0, '', ''
        if args[:1] == ['-d']:
            unit = int(args[args.index('-u') + 1])
            if any(dev == '/dev/md%d' % unit for dev in self.pool_devices.values()):
                return 1, '', 'mdconfig: ioctl(/dev/mdctl): Device busy'
            self.md.pop(unit, None)
            return 0, '', ''
        return 1, '', 'unexpected mdconfig'

    pool_devices = None

    def _zpool(self, args):
        if self.pool_devices is None:
            self.pool_devices = {}
        if args[0] == 'list':
            return (0, args[-1] + '\n', '') if args[-1] in self.pools else (1, '', 'no such pool')
        if args[0] == 'create':
            pool, device = args[-2], args[-1]
            if not device.startswith('/dev/md') or int(device[len('/dev/md'):]) not in self.md:
                return 1, '', 'cannot open %s' % device
            self.pools.add(pool)
            self.pool_devices[pool] = device
            self.datasets[pool] = None
            return 0, '', ''
        if args[0] == 'destroy':
            pool = args[-1]
            for ds in [d for d in self.datasets if d == pool or d.startswith(pool + '/')]:
                mountpoint = self.datasets.pop(ds)
                if mountpoint:
                    shutil.rmtree(self.p(mountpoint), ignore_errors=True)
                    os.makedirs(self.p(mountpoint), exist_ok=True)      # the empty mount point stays
                self.mounts = [m for m in self.mounts if m[0] != ds]
            self.pools.discard(pool)
            self.pool_devices.pop(pool, None)
            return 0, '', ''
        return 1, '', 'unexpected zpool'

    def _tunables(self, args):
        if self.tunables is None:
            self.tunables = {}
        cmd, name = args[0], args[1]
        if name != 'kern.racct.enable':
            return 1, json.dumps({'status': 'error', 'message': 'tunable not allowed'}), ''
        if cmd == 'get':
            return 0, json.dumps({'status': 'ok', 'exists': name in self.tunables,
                                  'value': self.tunables.get(name), 'descr': 'x' if name in self.tunables else None}), ''
        if cmd == 'set':
            self.tunables[name] = args[2]
        elif cmd == 'del':
            self.tunables.pop(name, None)
        self.write_config()
        return 0, json.dumps({'status': 'ok'}), ''

    def write_config(self):
        os.makedirs(self.root + '/conf', exist_ok=True)
        items = ''.join('<item><tunable>%s</tunable><value>%s</value><descr/></item>' % kv
                        for kv in sorted((self.tunables or {}).items()))
        with open(self.root + '/conf/config.xml', 'w') as handle:
            handle.write('<opnsense><sysctl>%s</sysctl></opnsense>' % items)

    def read(self, argv, timeout=15):
        rc, out, _ = self.run(argv, timeout)
        return out if rc == 0 else ''

    def writes(self):
        """ commands that would change the system """
        mutating = ('create', 'destroy', '-c', '-r', '-t', 'bootstrap', 'install', 'clean')
        return [c for c in self.calls
                if (c[0] == '/usr/local/bin/php' and c[2] in ('set', 'del'))
                or c[0] == '/usr/local/sbin/configctl'
                or c[0] in ('/usr/sbin/jail', '/usr/sbin/chroot', '/usr/bin/tar', '/sbin/umount', '/usr/bin/cpuset',
                            '/usr/sbin/jexec', '/usr/bin/rctl', '/sbin/devfs', '/bin/chflags')
                or (c[0] == '/sbin/zfs' and c[1] in mutating) or (c[0] == '/sbin/mount' and c[1] == '-t')
                or c[0] == '/sbin/kldload' or (c[0] == '/sbin/mdconfig' and c[1] in ('-a', '-d'))
                or (c[0] == '/sbin/zpool' and c[1] in ('create', 'destroy', 'export', 'import'))
                or (c[0] == '/sbin/sysctl' and len(c) == 2 and '=' in c[1])]


class SetupTestCase(unittest.TestCase):
    zfs = True
    racct = False

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-setup-test-')
        self.root = os.path.join(self.tmp, 'root')
        os.makedirs(self.root + '/var/db/ai/models')
        os.makedirs(self.root + '/etc/jail.conf.d')
        os.makedirs(self.root + '/etc/rc.conf.d')
        with open(self.root + '/etc/resolv.conf', 'w') as handle:
            handle.write('# generated\ndomain example.lan\nnameserver 127.0.0.1\nsearch example.lan\n')
        self.system = FakeSystem(self.root, zfs=self.zfs, racct=self.racct)
        self.http = FakeHttp(self.system)
        self.ctx = self.make_ctx()
        patcher = mock.patch('os.chown')        # tests do not run as root
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_ctx(self, official=None):
        return common.Context(root=self.root, runner=self.system, http=self.http, ncpu=4, is_root=True,
                              clock=lambda: 1794000000, official=official)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tree(self):
        """ snapshot of every file (path -> bytes) and directory below the fake root """
        out = {}
        for dirpath, dirnames, filenames in os.walk(self.tmp):
            out[dirpath] = None
            for name in filenames:
                with open(os.path.join(dirpath, name), 'rb') as handle:
                    out[os.path.join(dirpath, name)] = handle.read()
        return out

    def read(self, path):
        with open(self.root + path) as handle:
            return handle.read()
