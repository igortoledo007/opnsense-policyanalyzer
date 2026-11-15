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

    Jail runtime: install / uninstall / start / stop / enable / disable /
    set_limits / status.  Every planner here is read only and returns a list
    of declarative steps (see ops.py) plus the metadata shown by the UI.

    Jail design (justified in the setup README of the report):
      - non-VNET jail, ip4.addr = 127.0.0.1 only (no interface, so jail(8)
        never adds or removes an alias on lo0), ip6 disabled.  Every bind in
        the jail is forced to 127.0.0.1, Ollama is reachable by the host at
        127.0.0.1:11434 and the jail has no route to any other network.
      - packages are installed by FreeBSD's own pkg(7)/pkg(8) running chrooted
        in the jail root (host network, jail package database): the OPNsense
        package database and repositories are never used.
      - models live outside the jail, /var/db/ai/models nullfs-mounted rw on
        /var/lib/ollama/models (the path the port's rc script uses for the
        "nobody" service user); they are downloaded by the host (registry
        manifests + SHA256-verified blobs), the jail needs no egress at all.
      - limits: jail cpuset (exec.created cpuset -j), nice via ollama_nice,
        OLLAMA_* env, RCTL memoryuse only when kern.racct.enable=1.
      - boot: /etc/rc.conf.d/jail (jail_enable, jail_list) read by
        /usr/local/etc/rc.freebsd -> /etc/rc.d/jail, which reads
        /etc/jail.conf.d/ollama.conf.
"""

import json
import os
import re

from . import common
from .common import JAIL_NAME, SetupError

PATH_ENV = '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin'
EXTRACT_EXCLUDES = ['./boot', './rescue', './usr/tests', './usr/lib/debug']
JAIL_DATASET_PROPS = [('compression', 'lz4'), ('recordsize', '128K'), ('primarycache', 'all'), ('atime', 'off')]
MARKER = '/.policyanalyzer-base'
HEADER = '# Managed by os-policyanalyzer (Firewall > Policy Analyzer > AI setup). Do not edit by hand.\n'


# ------------------------------------------------------------------ args


def runtime_args(ctx, args, defaults=True):
    """ validate the install / set_limits parameters, merged over the current limits """
    current = current_limits(ctx) if defaults else {}
    out = dict(common.DEFAULT_LIMITS)
    out.update({k: v for k, v in current.items() if k in common.DEFAULT_LIMITS})
    if args.get('cpus') not in (None, ''):
        out['cpus'] = common.format_cpuset(common.parse_cpuset(args['cpus'], ctx.ncpu))
    else:
        out['cpus'] = common.format_cpuset(common.parse_cpuset(out['cpus'], ctx.ncpu)) \
            if _cpus_fit(out['cpus'], ctx.ncpu) else common.format_cpuset([max(0, ctx.ncpu - 1)])
    if args.get('threads') not in (None, ''):
        out['threads'] = common.as_int(args['threads'], 1, ctx.ncpu, 'threads')
    if args.get('ctx') not in (None, ''):
        out['ctx'] = common.as_int(args['ctx'], 2048, 32768, 'ctx')
        if out['ctx'] not in common.CTX_VALUES:
            raise ValueError('ctx must be one of %s' % ', '.join(str(v) for v in common.CTX_VALUES))
    if args.get('nice') not in (None, ''):
        out['nice'] = common.as_int(args['nice'], 0, 20, 'nice')
    if args.get('mem_gb') not in (None, ''):
        out['mem_gb'] = common.as_int(args['mem_gb'], 2, 64, 'mem_gb')
    if args.get('keep_alive') not in (None, ''):
        if not common.KEEP_ALIVE_RE.match(str(args['keep_alive'])):
            raise ValueError('keep_alive must look like 5m, 300s, 1h, 0 or -1')
        out['keep_alive'] = str(args['keep_alive'])
    ncpus = len(common.parse_cpuset(out['cpus'], ctx.ncpu))
    if out['threads'] > ncpus:
        raise ValueError('threads (%d) can not exceed the number of cpus in the set (%d)' % (out['threads'], ncpus))
    return out


def _cpus_fit(text, ncpu):
    try:
        common.parse_cpuset(text, ncpu)
        return True
    except ValueError:
        return False


def current_limits(ctx):
    data = common.read_json(ctx.limits_file, {}) or {}
    return data if isinstance(data, dict) else {}


# ------------------------------------------------------------------ probes (read only)


def probe(ctx):
    jid = common.jail_jid(ctx)
    racct = common.sysctl(ctx, 'kern.racct.enable') == '1'
    ai_dev, ai_mp, ai_fs = common.mount_of(ctx, ctx.ai_dir[len(ctx.root):] if ctx.root else ctx.ai_dir)
    ai_dataset = ai_dev if ai_fs == 'zfs' and ai_mp == '/var/db/ai' else None
    info = {
        'installed': os.path.exists(ctx.jail_dir + MARKER) and os.path.exists(ctx.in_jail('/usr/local/bin/ollama')),
        'base_extracted': os.path.exists(ctx.jail_dir + MARKER),
        'jail_conf': os.path.exists(ctx.jail_conf),
        'running': jid is not None,
        'jid': jid,
        'boot_enabled': JAIL_NAME in _rc_jail_list(common.read_text(ctx.rc_conf_jail) or '')[1]
        and _rc_jail_enabled(common.read_text(ctx.rc_conf_jail) or ''),
        'racct': racct,
        'racct_state': racct_state(ctx),
        'ai_dataset': ai_dataset,
        'jail_dataset': (ai_dataset + '/jail') if ai_dataset else None,
        'jail_dataset_exists': bool(ai_dataset) and common.dataset_exists(ctx, ai_dataset + '/jail'),
        'free_bytes': common.free_bytes(ctx.ai_dir),
        'release': common.sysctl(ctx, 'kern.osrelease'),
        'arch': common.sysctl(ctx, 'hw.machine_arch'),
        'limits': current_limits(ctx),
    }
    return info


RACCT_TUNABLE = 'kern.racct.enable'
REBOOT_URL = '/ui/core/reboot'
TUNABLES_URL = '/ui/core/tunables'


def configured_tunable(ctx, name):
    """ value of a user tunable in config.xml (//sysctl/item), read only; None when absent """
    import xml.etree.ElementTree as ET
    try:
        root = ET.parse(ctx.config_xml).getroot()
    except (OSError, ET.ParseError):
        return None
    for item in root.findall('./sysctl/item'):
        if (item.findtext('tunable') or '').strip() == name:
            value = (item.findtext('value') or '').strip()
            return value or None
    return None


def racct_state(ctx):
    """ RCTL needs kern.racct.enable=1 at boot (loader tunable, read only at run time) """
    now = common.sysctl(ctx, RACCT_TUNABLE) == '1'
    configured = configured_tunable(ctx, RACCT_TUNABLE)
    loader = common.read_text(ctx.loader_conf) or ''
    in_loader = re.search(r'^\s*kern\.racct\.enable\s*=\s*"?1"?', loader, re.M) is not None
    wanted = configured == '1'
    return {'enabled_now': now, 'configured': configured, 'in_loader_conf': in_loader,
            # enabled in the tunables but not yet in the kernel, or removed while the kernel still has it
            'pending_reboot': (wanted and not now) or (now and not wanted and not in_loader),
            'tunables_url': TUNABLES_URL, 'reboot_url': REBOOT_URL}


def jail_conf_has_rctl(ctx):
    return 'rctl -a jail:' in (common.read_text(ctx.jail_conf) or '')


def _rc_jail_list(text):
    """ :return: (other_lines, [jail names]) from /etc/rc.conf.d/jail """
    names = []
    other = []
    for line in text.splitlines():
        match = re.match(r'^\s*jail_list\s*=\s*"?([^"#]*)"?\s*(#.*)?$', line)
        if match:
            names = match.group(1).split()
            continue
        if re.match(r'^\s*jail_enable\s*=', line):
            continue
        if line.strip() == HEADER.strip():
            continue
        other.append(line)
    return other, names


def _rc_jail_enabled(text):
    for line in text.splitlines():
        match = re.match(r'^\s*jail_enable\s*=\s*"?([A-Za-z]+)"?', line)
        if match:
            return match.group(1).lower() == 'yes'
    return False


def render_rc_jail(current_text, enable):
    """ new content of /etc/rc.conf.d/jail with ollama added/removed (None = delete the file) """
    other, names = _rc_jail_list(current_text or '')
    was_enabled = _rc_jail_enabled(current_text or '')
    if enable:
        if JAIL_NAME not in names:
            names.append(JAIL_NAME)
    else:
        names = [n for n in names if n != JAIL_NAME]
    other = [line for line in other if line.strip()]
    if not names and not other:
        return None
    lines = [HEADER.rstrip('\n')] + other
    lines.append('jail_enable="%s"' % ('YES' if (names or was_enabled) else 'NO'))
    lines.append('jail_list="%s"' % ' '.join(names))
    return '\n'.join(lines) + '\n'


# ------------------------------------------------------------------ rendering


def render_jail_conf(ctx, limits, racct):
    real_jail = '/var/db/ai/jail'
    lines = [
        HEADER.rstrip('\n'),
        '# Isolated runtime for the local AI model server (Ollama), loopback only.',
        '%s {' % JAIL_NAME,
        '    path = "%s";' % real_jail,
        '    host.hostname = "%s.jail";' % JAIL_NAME,
        '    # 127.0.0.1 without an interface: jail(8) never adds or removes an alias on lo0,',
        '    # every socket in the jail is bound to 127.0.0.1 and there is no route out.',
        '    ip4.addr = "%s";' % common.JAIL_IP,
        '    ip6 = "disable";',
        '    mount.devfs;',
        '    devfs_ruleset = 4;',
        '    enforce_statfs = 2;',
        '    securelevel = 2;',
        '    children.max = 0;',
        '    mount += "/var/db/ai/models %s%s nullfs rw 0 0";' % (real_jail, common.JAIL_MODELS_MOUNT),
        '    exec.clean;',
        '    exec.start = "/bin/sh /etc/rc";',
        '    exec.stop = "/bin/sh /etc/rc.shutdown jail";',
        '    exec.created = "/usr/bin/cpuset -l %s -j %s";' % (limits['cpus'], JAIL_NAME),
    ]
    if racct:
        lines.append('    exec.created += "/usr/bin/rctl -a jail:%s:memoryuse:deny=%dg";' % (JAIL_NAME, limits['mem_gb']))
        lines.append('    exec.poststop = "/usr/bin/rctl -r jail:%s";' % JAIL_NAME)
    lines += [
        '    exec.consolelog = "%s";' % ctx.console_log,
        '    exec.timeout = 90;',
        '    stop.timeout = 30;',
        '}',
    ]
    return '\n'.join(lines) + '\n'


def render_jail_rc_conf():
    return HEADER + '\n'.join([
        'hostname="%s.jail"' % JAIL_NAME,
        'sendmail_enable="NONE"',
        'syslogd_flags="-ss"',
        'cron_enable="NO"',
        'clear_tmp_enable="YES"',
        'update_motd="NO"',
        'ollama_enable="YES"',
    ]) + '\n'


def render_ollama_rc(limits):
    env = ' '.join([
        'OLLAMA_HOST=%s:11434' % common.JAIL_IP,
        'OLLAMA_NUM_PARALLEL=%d' % limits['num_parallel'],
        'OLLAMA_MAX_LOADED_MODELS=%d' % limits['max_loaded_models'],
        'OLLAMA_MAX_QUEUE=%d' % limits['max_queue'],
        'OLLAMA_KEEP_ALIVE=%s' % limits['keep_alive'],
        'OLLAMA_NOPRUNE=1',
        # the port's rc runs "su -m nobody": HOME stays the one of jail(8) exec.clean (/root), which nobody
        # can not write; ollama serve aborts when it can not create ~/.ollama/id_ed25519
        'HOME=%s' % common.JAIL_SERVICE_HOME,
    ])
    return HEADER + '\n'.join([
        'ollama_user="%s"' % common.JAIL_SERVICE_USER,
        'ollama_log="%s"' % common.JAIL_OLLAMA_LOG,
        'ollama_nice="%d"' % limits['nice'],
        'ollama_context_length="%d"' % limits['ctx'],
        'ollama_use_vulkan="0"',
        'ollama_env="%s"' % env,
    ]) + '\n'


def render_pkg_repo(branch):
    return HEADER + (
        'FreeBSD-ports: {\n'
        '  url: "pkg+https://pkg.FreeBSD.org/${ABI}/%s",\n'
        '  mirror_type: "srv",\n'
        '  signature_type: "fingerprints",\n'
        '  fingerprints: "/usr/share/keys/pkg",\n'
        '  enabled: yes\n'
        '}\n'
        'FreeBSD-ports-kmods: { enabled: no }\n'
        'FreeBSD-base: { enabled: no }\n' % branch)


def render_resolv(ctx):
    """ the host resolver configuration, only nameserver/search/domain/options lines """
    text = common.read_text(ctx.host_resolv) or ''
    keep = [line for line in text.splitlines()
            if re.match(r'^(nameserver|search|domain|options)\s+[A-Za-z0-9.:_ -]+$', line.strip())]
    if not any(line.startswith('nameserver') for line in keep):
        keep.insert(0, 'nameserver 127.0.0.1')
    return HEADER + '\n'.join(keep) + '\n'


def render_limits(limits, branch=None, previous=None):
    data = dict(previous or {})
    data.update(limits)
    if branch:
        data['branch'] = branch
    data['url'] = common.OLLAMA_URL
    return json.dumps(data, indent=2, sort_keys=True) + '\n'


# ------------------------------------------------------------------ step builders

def jail_cmd(ctx, flag):
    return ['/usr/sbin/jail', '-f', ctx.jail_conf[len(ctx.root):] if ctx.root else ctx.jail_conf, flag, JAIL_NAME]


def jls_check():
    return ['/usr/sbin/jls', '-j', JAIL_NAME, 'jid']


def wait_step(description):
    return {'type': 'wait_ollama', 'url': common.OLLAMA_URL + '/api/version', 'timeout': 180, 'grace': 15,
            'description': description, 'command': 'GET %s/api/version (up to 180 s)' % common.OLLAMA_URL,
            'effect': 'none (read only); fails at once if the ollama process dies, with its log'}


def start_steps(ctx):
    return [
        {'type': 'run', 'argv': jail_cmd(ctx, '-c'), 'skip_if': jls_check(), 'undo_argv': jail_cmd(ctx, '-r'),
         'timeout': 180, 'description': 'Start jail %s (runs Ollama inside it)' % JAIL_NAME,
         'effect': 'jail created with 127.0.0.1 only; mounts devfs and the models directory; starts ollama serve',
         'undo': 'stop the jail (jail -r %s)' % JAIL_NAME},
        wait_step('Wait for Ollama to answer on 127.0.0.1:11434'),
        {'type': 'verify_listen', 'port': 11434, 'description': 'Check that port 11434 listens on 127.0.0.1 only',
         'effect': 'none (read only); fails and rolls back if any other address is listening'},
    ]


def stop_steps(ctx):
    return [
        {'type': 'run', 'argv': jail_cmd(ctx, '-r'), 'skip_unless': jls_check(), 'undo_argv': jail_cmd(ctx, '-c'),
         'timeout': 120, 'description': 'Stop jail %s' % JAIL_NAME,
         'effect': 'Ollama stops, loaded model is unloaded, devfs and models mounts are released',
         'undo': 'start the jail again'},
    ]


def boot_step(ctx, enable):
    content = render_rc_jail(common.read_text(ctx.rc_conf_jail), enable)
    return {'type': 'write_file', 'path': ctx.rc_conf_jail, 'content': content, 'mode': '0644',
            'command': ('write %s' % ctx.rc_conf_jail) if content is not None else 'rm %s' % ctx.rc_conf_jail,
            'description': '%s start of jail %s at boot (/etc/rc.conf.d/jail)' % ('Enable' if enable else 'Disable',
                                                                                  JAIL_NAME),
            'effect': 'jail_list %s "%s"; read by rc.freebsd -> /etc/rc.d/jail at boot'
                      % ('contains' if enable else 'no longer contains', JAIL_NAME),
            'undo': 'previous /etc/rc.conf.d/jail is restored from the journal'}


def install_plan(ctx, args):
    branch = args.get('branch') or 'quarterly'
    if branch not in common.PKG_BRANCHES:
        raise ValueError('branch must be one of %s' % ', '.join(common.PKG_BRANCHES))
    start = common.as_bool(args.get('start'), True, 'start')
    boot = common.as_bool(args.get('boot'), True, 'boot')
    limits = runtime_args(ctx, args)
    info = probe(ctx)
    errors, warnings, irreversible = [], [], []

    if info['arch'] and info['arch'] != 'amd64':
        errors.append('the FreeBSD ollama package only exists for amd64 (this system: %s)' % info['arch'])
    if info['release'] and not info['release'].startswith('15.'):
        errors.append('this setup targets FreeBSD 15 (running %s)' % info['release'])
    if not ctx.is_root:
        warnings.append('plan computed without root privileges: some checks may be incomplete')
    warnings += racct_warnings(info)
    if info['running']:
        warnings.append('jail %s is already running; existing parts are kept (idempotent)' % JAIL_NAME)

    manifest = _read_manifest(ctx, errors)
    base_sha = manifest.get('base.txz')
    base_size = ctx.http.head_size(common.FREEBSD_DIST_URL + 'base.txz') or common.BASE_TXZ_BYTES_ESTIMATE
    pkg_bytes = common.PKG_DOWNLOAD_ESTIMATE[branch]
    staging_txz = os.path.join(ctx.staging_dir, 'base-%s.txz' % common.FREEBSD_RELEASE)

    steps = []
    if info['ai_dataset']:
        steps.append({'type': 'zfs_create', 'dataset': info['jail_dataset'], 'properties': JAIL_DATASET_PROPS,
                      'argv': ['/sbin/zfs', 'create'] + sum([['-o', '%s=%s' % p] for p in JAIL_DATASET_PROPS], [])
                      + [info['jail_dataset']],
                      'description': 'Create ZFS dataset %s (mounted on /var/db/ai/jail)' % info['jail_dataset'],
                      'effect': 'child of %s, lz4 compressed, no quota' % info['ai_dataset'],
                      'undo': 'zfs destroy %s' % info['jail_dataset']})
    else:
        warnings.append('/var/db/ai is not a ZFS dataset: the jail is a plain directory')
        steps.append({'type': 'mkdir', 'path': ctx.jail_dir, 'mode': '0755', 'argv': ['/bin/mkdir', '-p', ctx.jail_dir],
                      'description': 'Create directory %s' % ctx.jail_dir, 'undo': 'remove the directory'})
    if not info['base_extracted']:
        steps.append({'type': 'mkdir', 'path': ctx.staging_dir, 'mode': '0750', 'argv': ['/bin/mkdir', '-p', ctx.staging_dir],
                      'description': 'Create staging directory %s' % ctx.staging_dir, 'undo': 'remove it if empty'})
        steps.append({'type': 'fetch', 'url': common.FREEBSD_DIST_URL + 'base.txz', 'dest': staging_txz,
                      'sha256': base_sha, 'size': base_size, 'download_bytes': base_size,
                      'argv': ['fetch', common.FREEBSD_DIST_URL + 'base.txz'],
                      'description': 'Download FreeBSD %s base.txz (%s)' % (common.FREEBSD_RELEASE,
                                                                          common.fmt_bytes(base_size)),
                      'effect': 'verified against SHA256 %s from the official MANIFEST' % (base_sha or '?'),
                      'undo': 'file deleted (the download itself can not be undone)'})
        steps.append({'type': 'extract', 'archive': staging_txz, 'dest': ctx.jail_dir, 'marker': ctx.jail_dir + MARKER,
                      'sha256': base_sha, 'exclude': EXTRACT_EXCLUDES,
                      'argv': ['/usr/bin/tar', '-xpf', staging_txz, '-C', ctx.jail_dir]
                      + sum([['--exclude', e] for e in EXTRACT_EXCLUDES], []),
                      'space_bytes': common.BASE_EXTRACTED_BYTES_ESTIMATE,
                      'description': 'Extract the FreeBSD userland into %s' % ctx.jail_dir,
                      'effect': 'about %s on disk (without /boot, /rescue, tests)'
                                % common.fmt_bytes(common.BASE_EXTRACTED_BYTES_ESTIMATE),
                      'undo': 'jail root removed'})
        steps.append({'type': 'unlink', 'path': staging_txz, 'argv': ['/bin/rm', staging_txz],
                      'cleanup': True, 'description': 'Delete the downloaded archive', 'effect': 'frees %s' % common.fmt_bytes(base_size)})
    else:
        base_size = 0
        warnings.append('FreeBSD userland already extracted in the jail root, not downloaded again')
    if not info['installed']:
        steps.append(_write(ctx.in_jail('/etc/resolv.conf'), render_resolv(ctx), 'DNS for pkg inside the jail root',
                            'copy of the host resolver (127.0.0.1 = local Unbound); used only while installing packages'))
        steps.append(_write(ctx.in_jail('/usr/local/etc/pkg/repos/FreeBSD.conf'), render_pkg_repo(branch),
                            'FreeBSD package repository (%s) for the jail only' % branch,
                            'only the jail root is configured; the host repositories stay disabled'))
        dev = ctx.in_jail('/dev')
        steps.append({'type': 'mount', 'fstype': 'devfs', 'source': 'devfs', 'target': dev,
                      'after': [['/sbin/devfs', '-m', dev, 'ruleset', '4'], ['/sbin/devfs', '-m', dev, 'rule', 'applyset']],
                      'argv': ['/sbin/mount', '-t', 'devfs', 'devfs', dev],
                      'description': 'Temporarily mount devfs (jail ruleset 4) in the jail root for pkg',
                      'undo': 'umount %s' % dev})
        env = {'PATH': PATH_ENV, 'ASSUME_ALWAYS_YES': 'yes', 'HOME': '/root'}
        chroot = ['/usr/sbin/chroot', ctx.jail_dir]
        steps.append({'type': 'run', 'argv': chroot + ['/usr/sbin/pkg', 'bootstrap', '-y'], 'env': env, 'timeout': 900,
                      'skip_if': ['/bin/test', '-x', ctx.in_jail('/usr/local/sbin/pkg')],
                      'description': 'Bootstrap pkg inside the jail root (FreeBSD pkg(7), signature checked)',
                      'effect': 'pkg installed into the jail; package database in the jail (/var/db/pkg of the jail)'})
        steps.append({'type': 'run', 'argv': chroot + ['/usr/local/sbin/pkg', 'install', '-y', '-r', 'FreeBSD-ports',
                                                       'ollama'],
                      'env': env, 'timeout': 3600, 'download_bytes': pkg_bytes,
                      'space_bytes': common.PKG_INSTALLED_ESTIMATE[branch],
                      'skip_if': ['/bin/test', '-x', ctx.in_jail('/usr/local/bin/ollama')],
                      'description': 'Install misc/ollama from the official FreeBSD repository (%s) inside the jail'
                                     % branch,
                      'effect': 'about %s download (ollama, openblas, gcc14 runtime, vulkan-loader...), %s installed'
                                % (common.fmt_bytes(pkg_bytes),
                                   common.fmt_bytes(common.PKG_INSTALLED_ESTIMATE[branch]))})
        steps.append({'type': 'run', 'argv': chroot + ['/usr/local/sbin/pkg', 'clean', '-a', '-y'], 'env': env,
                      'timeout': 300, 'description': 'Clean the package cache of the jail',
                      'effect': 'frees the downloaded packages'})
        steps.append({'type': 'umount', 'target': dev, 'argv': ['/sbin/umount', dev], 'cleanup': True,
                      'description': 'Unmount the temporary devfs'})
    else:
        pkg_bytes = 0
        warnings.append('ollama package already installed in the jail')
    steps.append({'type': 'mkdir', 'path': ctx.in_jail(common.JAIL_MODELS_MOUNT), 'mode': '0755',
                  'argv': ['/bin/mkdir', '-p', ctx.in_jail(common.JAIL_MODELS_MOUNT)],
                  'description': 'Create the mount point for the models inside the jail'})
    steps.append({'type': 'chown', 'path': ctx.in_jail(common.JAIL_SERVICE_HOME), 'uid': common.JAIL_SERVICE_UID,
                  'gid': common.JAIL_SERVICE_UID, 'mode': '0750',
                  'argv': ['/usr/sbin/chown', '%d:%d' % (common.JAIL_SERVICE_UID, common.JAIL_SERVICE_UID),
                           ctx.in_jail(common.JAIL_SERVICE_HOME)],
                  'description': 'Make %s (HOME of the service user) writable by nobody' % common.JAIL_SERVICE_HOME,
                  'effect': 'ollama serve keeps its key pair in %s/.ollama' % common.JAIL_SERVICE_HOME,
                  'undo': 'removed with the jail root'})
    steps.append({'type': 'chown', 'path': ctx.models_dir, 'uid': common.JAIL_SERVICE_UID,
                  'gid': common.JAIL_SERVICE_UID, 'mode': '0755',
                  'argv': ['/usr/sbin/chown', '%d:%d' % (common.JAIL_SERVICE_UID, common.JAIL_SERVICE_UID),
                           ctx.models_dir],
                  'description': 'Give the models directory to the jail service user (nobody, uid 65534)',
                  'effect': 'Ollama in the jail can read and manage the models; mode 0755',
                  'undo': 'previous owner and mode restored'})
    steps.append(_write(ctx.in_jail('/etc/rc.conf'), render_jail_rc_conf(), 'rc.conf of the jail',
                        'only ollama is started; sendmail/cron disabled; syslogd without network'))
    steps.append(_write(ctx.in_jail('/etc/rc.conf.d/ollama'), render_ollama_rc(limits), 'Ollama settings',
                        'OLLAMA_HOST=127.0.0.1:11434, context %d, nice %d, 1 request, 1 model, keep-alive %s'
                        % (limits['ctx'], limits['nice'], limits['keep_alive'])))
    steps.append(_write(ctx.limits_file, render_limits(limits, branch, current_limits(ctx)),
                        'Runtime limits read by the Policy Analyzer client',
                        'threads=%d is sent as num_thread with every request' % limits['threads'], mode='0644',
                        dir_mode='0750'))
    steps.append(_write(ctx.jail_conf, render_jail_conf(ctx, limits, info['racct']),
                        'Jail definition /etc/jail.conf.d/%s.conf' % JAIL_NAME,
                        'cpuset %s%s' % (limits['cpus'], ', RCTL memoryuse %dG' % limits['mem_gb']
                                         if info['racct'] else ', no RCTL (racct disabled)')))
    if boot:
        steps.append(boot_step(ctx, True))
    if start:
        steps += start_steps(ctx)

    download = base_size + pkg_bytes
    needed = (base_size + (common.BASE_EXTRACTED_BYTES_ESTIMATE if base_size else 0)
              + (common.PKG_INSTALLED_ESTIMATE[branch] if pkg_bytes else 0) + pkg_bytes)
    free = info['free_bytes']
    if free is not None and free < needed + common.SPACE_MARGIN_BYTES:
        errors.append('not enough space on /var/db/ai: need %s, %s free' % (common.fmt_bytes(needed),
                                                                              common.fmt_bytes(free)))
    if not base_sha and base_size:
        errors.append('could not read the SHA256 of base.txz from the official MANIFEST')
    if download:
        irreversible.append('%s downloaded from download.freebsd.org and pkg.FreeBSD.org' % common.fmt_bytes(download))
    return {
        'steps': steps, 'errors': errors, 'warnings': warnings, 'irreversible': irreversible,
        'download_bytes': download, 'space_needed': needed, 'space_free': free, 'space_path': '/var/db/ai',
        'args': {'branch': branch, 'start': start, 'boot': boot, 'limits': limits},
        'undo': 'Revert stops the jail, restores /etc/rc.conf.d/jail, removes /etc/jail.conf.d/%s.conf and destroys '
                'the jail root; models in /var/db/ai/models are kept unless you choose otherwise' % JAIL_NAME,
        'resources': ['jail', 'boot', 'limits', 'run'],
        'background': True, 'risk': 'medium',
        'ports': ['127.0.0.1:11434/tcp (Ollama API, no authentication, loopback only)'],
        'post_revert': [],
    }


def _write(path, content, description, effect, mode='0644', dir_mode='0755'):
    return {'type': 'write_file', 'path': path, 'content': content, 'mode': mode, 'dir_mode': dir_mode,
            'argv': None, 'command': 'write %s' % path, 'description': description, 'effect': effect,
            'undo': 'previous content restored (or file removed)'}


def _read_manifest(ctx, errors):
    """ {file: sha256} from the official MANIFEST (read only) """
    try:
        text = ctx.http.get_bytes(common.FREEBSD_DIST_URL + 'MANIFEST', timeout=20).decode('utf-8', 'replace')
    except Exception as exc:                    # noqa: BLE001
        errors.append('MANIFEST download failed: %s' % exc)
        return {}
    result = {}
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) >= 2 and re.match(r'^[0-9a-f]{64}$', fields[1]):
            result[fields[0]] = fields[1]
    return result


def rctl_missing_warning(ctx, info):
    if info['racct_state']['enabled_now'] and info['jail_conf'] and not jail_conf_has_rctl(ctx):
        return ['RCTL is available now but the jail has no RAM limit yet: run set_limits to apply it']
    return []


def racct_warnings(info, for_limits=False):
    state = info['racct_state']
    if state['enabled_now']:
        return []
    if state['pending_reboot']:
        return ['kern.racct.enable=1 is configured but takes effect after the next reboot: the RAM limit (RCTL) '
                'is applied by set_limits after it']
    return ['kern.racct.enable=0: no RAM limit (RCTL) for the jail; enable_racct sets the tunable '
            '(takes effect after the next reboot)%s' % (', then run set_limits' if not for_limits else '')]


def enable_racct_plan(ctx, args):
    state = racct_state(ctx)
    warnings = ['takes effect after the next reboot (System: Power: Reboot); the plugin never reboots the firewall']
    if state['configured'] == '1':
        warnings.insert(0, 'kern.racct.enable=1 is already configured in System: Settings: Tunables')
    if state['enabled_now']:
        warnings = ['RACCT/RCTL is already enabled in the running kernel']
    elif state['configured'] not in (None, '0', '1'):
        warnings.append('the tunable currently has the value %r; it is replaced by 1' % state['configured'])
    reload = [
        {'type': 'run', 'argv': [ctx.configctl, 'service', 'restart', 'login'], 'timeout': 120, 'always': True,
         'skip_if': None, 'description': 'Regenerate /boot/loader.conf from the tunables (as the Tunables page Apply)',
         'effect': 'kern.racct.enable="1" is written to /boot/loader.conf by the core (system_login_configure)'},
        {'type': 'run', 'argv': [ctx.configctl, 'service', 'restart', 'sysctl'], 'timeout': 120, 'always': True,
         'description': 'Apply the run time sysctls (as the Tunables page Apply)',
         'effect': 'kern.racct.enable is a boot time tunable: nothing changes until the reboot'},
    ]
    steps = [{'type': 'tunable', 'name': RACCT_TUNABLE, 'value': '1',
              'descr': 'Resource accounting for the Policy Analyzer AI jail RAM limit (RCTL)',
              'argv': [ctx.php, ctx.tunables_php, 'set', RACCT_TUNABLE, '1', '...'],
              'command': 'Tunables model (OPNsense\\Core\\Tunables): %s = 1' % RACCT_TUNABLE,
              'description': 'Add the tunable %s=1 in System: Settings: Tunables' % RACCT_TUNABLE,
              'effect': 'stored in config.xml (//sysctl/item); enables kernel resource accounting at the next '
                        'boot (small CPU overhead), required by RCTL',
              'undo': 'previous tunable value restored (or the entry removed)'}] + reload
    if state['enabled_now'] or state['configured'] == '1' and state['in_loader_conf']:
        steps = [dict(steps[0])]          # predicted as already done, nothing to apply
    return {'steps': steps, 'errors': [], 'warnings': warnings, 'irreversible': [],
            'undo': 'Revert restores the previous tunable (removes it) and regenerates /boot/loader.conf; '
                    'it also takes effect only after the next reboot',
            'resources': ['tunable:' + RACCT_TUNABLE], 'risk': 'low', 'background': False,
            'args': {}, 'post_revert': [dict(s, description=s['description'] + ' (after the revert)')
                                        for s in reload],
            'reboot_required': not state['enabled_now'],
            'links': [{'label': 'System: Power: Reboot', 'url': REBOOT_URL}]}


def start_plan(ctx, args):
    info = probe(ctx)
    errors = [] if info['installed'] and info['jail_conf'] else ['runtime is not installed (run install_runtime)']
    return {'steps': start_steps(ctx), 'errors': errors,
            'warnings': (['jail is already running, nothing to do'] if info['running'] else [])
            + rctl_missing_warning(ctx, info),
            'irreversible': [], 'undo': 'Revert stops the jail', 'resources': ['run'], 'risk': 'low',
            'ports': ['127.0.0.1:11434/tcp'], 'background': False, 'args': {}}


def stop_plan(ctx, args):
    info = probe(ctx)
    return {'steps': stop_steps(ctx), 'errors': [] if info['jail_conf'] else ['runtime is not installed'],
            'warnings': [] if info['running'] else ['jail is not running, nothing to do'],
            'irreversible': [], 'undo': 'Revert starts the jail again', 'resources': ['run'], 'risk': 'low',
            'background': False, 'args': {}}


def boot_plan(ctx, args, enable):
    info = probe(ctx)
    step = boot_step(ctx, enable)
    warnings = []
    if info['boot_enabled'] == enable:
        warnings.append('already %s at boot' % ('enabled' if enable else 'disabled'))
    return {'steps': [step], 'errors': [] if (info['jail_conf'] or not enable) else ['runtime is not installed'],
            'warnings': warnings, 'irreversible': [], 'undo': 'Revert restores the previous /etc/rc.conf.d/jail',
            'resources': ['boot'], 'risk': 'low', 'background': False, 'args': {}}


def set_limits_plan(ctx, args):
    info = probe(ctx)
    limits = runtime_args(ctx, args)
    previous = current_limits(ctx)
    errors, warnings = [], []
    if not info['jail_conf']:
        errors.append('runtime is not installed (run install_runtime)')
    warnings += racct_warnings(info, for_limits=True)
    steps = [
        _write(ctx.limits_file, render_limits(limits, previous=previous), 'Runtime limits for the Policy Analyzer client',
               'threads=%d (num_thread per request), ctx=%d' % (limits['threads'], limits['ctx']), dir_mode='0750'),
        _write(ctx.in_jail('/etc/rc.conf.d/ollama'), render_ollama_rc(limits), 'Ollama settings in the jail',
               'context %d, nice %d, keep-alive %s' % (limits['ctx'], limits['nice'], limits['keep_alive'])),
        _write(ctx.jail_conf, render_jail_conf(ctx, limits, info['racct']), 'Jail cpuset/RCTL in jail.conf',
               'cpuset %s from the next jail start' % limits['cpus']),
    ]
    post = []
    if info['running']:
        old_cpus = previous.get('cpus') or common.DEFAULT_LIMITS['cpus']
        steps.append({'type': 'run', 'argv': ['/usr/bin/cpuset', '-l', limits['cpus'], '-j', JAIL_NAME],
                      'undo_argv': ['/usr/bin/cpuset', '-l', old_cpus, '-j', JAIL_NAME],
                      'description': 'Apply cpuset %s to the running jail' % limits['cpus'],
                      'effect': 'immediate, no restart', 'undo': 'cpuset %s' % old_cpus})
        if info['racct']:
            steps.append({'type': 'run', 'argv': ['/usr/bin/rctl', '-a', 'jail:%s:memoryuse:deny=%dg'
                                                  % (JAIL_NAME, limits['mem_gb'])],
                          'description': 'Apply RAM limit %dG to the running jail' % limits['mem_gb']})
        restart = {'type': 'run', 'argv': ['/usr/sbin/jexec', JAIL_NAME, '/usr/sbin/service', 'ollama', 'restart'],
                   'timeout': 120, 'description': 'Restart Ollama inside the jail (new context/nice/env)',
                   'effect': 'the loaded model is unloaded; running requests are aborted'}
        steps.append(restart)
        steps.append(wait_step('Wait for Ollama to answer again'))
        post = [dict(restart, description='Restart Ollama with the restored settings')]
    return {'steps': steps, 'errors': errors, 'warnings': warnings, 'irreversible': [],
            'undo': 'Revert restores the previous limits (%s) and restarts Ollama if it is running'
                    % ', '.join('%s=%s' % (k, previous.get(k)) for k in ('cpus', 'threads', 'ctx', 'nice')
                                if k in previous) or 'defaults',
            'resources': ['limits'], 'risk': 'low', 'background': False, 'args': {'limits': limits},
            'post_revert': post, 'previous': {'limits': previous}}


def uninstall_plan(ctx, args):
    info = probe(ctx)
    remove_dataset = common.as_bool(args.get('remove_dataset'), False, 'remove_dataset')
    confirm = args.get('confirm') or ''
    keep_models = not remove_dataset
    errors, warnings, irreversible = [], [], []
    steps = []
    steps += [dict(s, undo_argv=None, undo='') for s in stop_steps(ctx)]
    steps.append(dict(boot_step(ctx, False), description='Remove jail %s from /etc/rc.conf.d/jail' % JAIL_NAME))
    steps.append({'type': 'write_file', 'path': ctx.jail_conf, 'content': None, 'argv': ['/bin/rm', ctx.jail_conf],
                  'description': 'Remove /etc/jail.conf.d/%s.conf' % JAIL_NAME, 'undo': 'file restored'})
    if info['jail_dataset_exists']:
        steps.append({'type': 'zfs_destroy', 'dataset': info['jail_dataset'], 'recursive': True,
                      'argv': ['/sbin/zfs', 'destroy', '-r', info['jail_dataset']],
                      'description': 'Destroy dataset %s (jail root, packages)' % info['jail_dataset'],
                      'effect': 'frees the space of the jail; models are not inside it'})
    elif os.path.exists(ctx.jail_dir):
        steps.append({'type': 'remove_tree', 'path': ctx.jail_dir, 'argv': ['/bin/rm', '-rf', ctx.jail_dir],
                      'description': 'Remove the jail root %s' % ctx.jail_dir})
    irreversible.append('jail root and installed packages are deleted; undoing this downloads them again '
                        '(about %s)' % common.fmt_bytes(common.BASE_TXZ_BYTES_ESTIMATE
                                                         + common.PKG_DOWNLOAD_ESTIMATE['quarterly']))
    if remove_dataset:
        dataset = info['ai_dataset']
        if not dataset:
            errors.append('/var/db/ai is not a ZFS dataset, nothing to destroy')
        elif confirm != dataset:
            errors.append('to destroy %s (all models included) pass confirm=%s' % (dataset, dataset))
        else:
            steps.append({'type': 'zfs_destroy', 'dataset': dataset, 'recursive': True,
                          'argv': ['/sbin/zfs', 'destroy', '-r', dataset],
                          'description': 'Destroy dataset %s with ALL models' % dataset,
                          'effect': 'models are permanently deleted'})
            irreversible.append('dataset %s and every model in it are permanently deleted' % dataset)
    else:
        warnings.append('models in /var/db/ai/models and dataset %s are kept' % (info['ai_dataset'] or '/var/db/ai'))
    if not info['jail_conf'] and not info['base_extracted'] and not info['jail_dataset_exists']:
        warnings.append('runtime is not installed, nothing to remove')
    install_args = {'branch': (current_limits(ctx).get('branch') or 'quarterly'),
                    'start': 'yes' if info['running'] else 'no', 'boot': 'yes' if info['boot_enabled'] else 'no'}
    return {'steps': steps, 'errors': errors, 'warnings': warnings, 'irreversible': irreversible,
            'undo': 'Revert re-installs the runtime (new download) with the same branch and limits' +
                    ('' if keep_models else '; deleted models are NOT restored'),
            'resources': ['jail', 'boot', 'limits', 'run'] + (['models'] if remove_dataset else []),
            'risk': 'high' if remove_dataset else 'medium', 'background': True,
            'args': {'remove_dataset': remove_dataset},
            'revert_action': {'action': 'install_runtime', 'args': install_args}}


def status(ctx):
    info = probe(ctx)
    result = dict(info)
    result['racct'] = dict(info['racct_state'])
    del result['racct_state']
    result['rctl_in_jail_conf'] = jail_conf_has_rctl(ctx)
    result['version'] = None
    result['version_ok'] = None
    result['models'] = []
    result['loaded'] = []
    if info['running']:
        try:
            result['version'] = (ctx.http.get_json(common.OLLAMA_URL + '/api/version', timeout=3) or {}).get('version')
            parsed = common.parse_version(result['version'])
            result['version_ok'] = parsed is not None and parsed >= common.OLLAMA_MIN_VERSION
        except Exception:                       # noqa: BLE001
            result['api'] = 'not answering'
        try:
            ps = ctx.http.get_json(common.OLLAMA_URL + '/api/ps', timeout=3) or {}
            result['loaded'] = [{'name': m.get('name'), 'size': m.get('size')} for m in ps.get('models') or []]
        except Exception:                       # noqa: BLE001
            pass
        from .ops import foreign_listeners
        result['foreign_listeners'] = foreign_listeners(ctx, 11434)
        if result['foreign_listeners']:
            result['warning'] = 'Ollama is listening outside 127.0.0.1: %s' % ', '.join(result['foreign_listeners'])
    from .ops import installed_manifests, manifest_digests
    for (name, tag), manifest in sorted(installed_manifests(ctx).items()):
        result['models'].append({'name': '%s:%s' % (name, tag),
                                 'size': sum(size for _, size in manifest_digests(manifest))})
    warnings = []
    if result.get('warning'):
        warnings.append(result['warning'] + '; stop_runtime stops it')
    if info['jail_conf']:
        warnings += racct_warnings(info) + rctl_missing_warning(ctx, info)
    if result.get('version_ok') is False:
        warnings.append('Ollama %s is below the minimum safe version %s (CVE-2026-7482)'
                        % (result['version'], '.'.join(str(n) for n in common.OLLAMA_MIN_VERSION)))
    result['warnings'] = warnings
    state = common.State(ctx).load()
    result['job'] = state.get('job')
    result['busy'] = common.lock_holder(ctx)
    return result
