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

    ZFS pool in a file, for installations without ZFS (UFS).  Optional, only
    created when the administrator asks for it (create_file_pool).

    An image file in /var/db (/var/db/ai.zpool.img, fully preallocated, size
    chosen by the administrator) is attached as a vnode memory disk
    (mdconfig -t vnode -u <unit>) and holds a pool of its own ("aipool",
    cachefile=none, root dataset not mounted) with the dataset aipool/ai
    mounted on /var/db/ai.  The rest of the setup then sees /var/db/ai as a
    ZFS dataset (jail dataset aipool/ai/jail, uninstall with confirm=aipool/ai)
    and the models can never take more than the image size from the system
    disk.

    Boot: an rc(8) script written by this action
    (/usr/local/etc/rc.d/policyanalyzer_aipool, REQUIRE: FILESYSTEMS,
    BEFORE: jail) attaches the image with the same unit and imports the pool
    with "zpool import -d /dev/md<unit>"; it is enabled in
    /etc/rc.conf.d/policyanalyzer_aipool.  /etc/rc.conf.d/mdconfig with
    zfs_enable is not used: /etc/rc.d/zpool imports from the cache file and
    does not REQUIRE mdconfig, so the order is not guaranteed, and the pool
    keeps cachefile=none so no system cache file ever points to it.

    Undo: revert of create_file_pool (only while the pool holds no files),
    or remove_file_pool confirm=aipool (destroys the pool with its content):
    zpool destroy, mdconfig -d, delete the image and the rc files.
"""

import os
import re

from . import common

POOL_NAME = 'aipool'
POOL_DATASET = POOL_NAME + '/ai'
MOUNTPOINT = '/var/db/ai'
IMAGE_PATH = '/var/db/ai.zpool.img'
IMAGE_RE = re.compile(r'^/var/db/[a-z0-9][a-z0-9._-]{0,48}\.img$')
RC_SCRIPT = '/usr/local/etc/rc.d/policyanalyzer_aipool'
RC_CONF = '/etc/rc.conf.d/policyanalyzer_aipool'
RC_NAME = 'policyanalyzer_aipool'
MD_UNITS = range(10, 100)
SIZE_GB_MIN = 4
SIZE_GB_MAX = 4096
ARC_MB_MIN = 64
ARC_MB_MAX = 65536
# vdev / pool properties (-o) and properties of the (unmounted) root dataset (-O)
POOL_PROPERTIES = [('ashift', '12'), ('cachefile', 'none'), ('autoexpand', 'off'), ('failmode', 'continue')]
ROOT_PROPERTIES = [('mountpoint', 'none'), ('canmount', 'off'), ('atime', 'off'), ('compression', 'off')]
# same tuning as ai/storage.py DATASET_PROPERTIES: large write-once files, no data in the ARC
DATASET_PROPERTIES = [('mountpoint', MOUNTPOINT), ('recordsize', '1M'), ('compression', 'off'), ('atime', 'off'),
                      ('primarycache', 'metadata')]
HEADER = '# Managed by os-policyanalyzer (Firewall > Policy Analyzer > AI setup). Do not edit by hand.\n'


# ------------------------------------------------------------------ read only probes


def md_list(ctx):
    """ {unit: backing file or ''} from mdconfig -lv """
    out = {}
    for line in ctx.runner.read(['/sbin/mdconfig', '-lv']).splitlines():
        fields = line.split()
        if fields and fields[0].startswith('md') and fields[0][2:].isdigit():
            out[int(fields[0][2:])] = fields[3] if len(fields) >= 4 and fields[1] == 'vnode' else ''
    return out


def pool_exists(ctx, pool=POOL_NAME):
    return ctx.runner.read(['/sbin/zpool', 'list', '-H', '-o', 'name', pool]).strip() == pool


def zfs_loaded(ctx):
    return ctx.runner.run(['/sbin/kldstat', '-q', '-m', 'zfs'], timeout=10)[0] == 0


def state(ctx, image=IMAGE_PATH):
    """ read only summary for status and the plans """
    path = ctx.root + image
    units = md_list(ctx)
    unit = next((u for u, f in sorted(units.items()) if f == image), None)
    rc_conf = common.read_text(ctx.root + RC_CONF) or ''
    return {
        'image': image,
        'image_exists': os.path.isfile(path),
        'image_bytes': os.path.getsize(path) if os.path.isfile(path) else None,
        'md_unit': unit,
        'pool': POOL_NAME,
        'pool_imported': pool_exists(ctx),
        'dataset': POOL_DATASET,
        'dataset_mounted': any(m[0] == POOL_DATASET and m[1] == MOUNTPOINT for m in common.mounts(ctx)),
        'boot_enabled': re.search(r'^%s_enable="YES"' % RC_NAME, rc_conf, re.M) is not None,
        'rc_script': os.path.isfile(ctx.root + RC_SCRIPT),
    }


def _configured_unit(ctx):
    match = re.search(r'^%s_unit="([0-9]{1,2})"' % RC_NAME, common.read_text(ctx.root + RC_CONF) or '', re.M)
    return int(match.group(1)) if match else None


def _free_unit(ctx, units):
    for unit in MD_UNITS:
        if unit not in units:
            return unit
    raise common.SetupError('no free md unit between %d and %d' % (MD_UNITS[0], MD_UNITS[-1]))


# files the plugin itself leaves in /var/db/ai after the runtime is removed: they do not block the pool
LEFTOVER_FILES = frozenset(['jail-ollama.console.log'])


def _has_files(path, ignore=()):
    """ anything but empty directories (and the given top-level file names) below path """
    for dirpath, _dirnames, filenames in os.walk(path):
        if dirpath == path:
            filenames = [f for f in filenames if f not in ignore]
        if filenames:
            return True
    return False


# ------------------------------------------------------------------ rendering


def render_rc_script():
    return '\n'.join([
        '#!/bin/sh',
        HEADER.rstrip('\n'),
        '#',
        '# Attaches the image of the Policy Analyzer AI pool (ZFS pool in a file, for UFS installations)',
        '# as a vnode memory disk and imports the pool, before the AI jail starts.',
        '#',
        '# PROVIDE: %s' % RC_NAME,
        '# REQUIRE: FILESYSTEMS',
        '# BEFORE: jail',
        '# KEYWORD: shutdown nojail',
        '',
        '. /etc/rc.subr',
        '',
        'name="%s"' % RC_NAME,
        'rcvar="%s_enable"' % RC_NAME,
        'start_cmd="${name}_start"',
        'stop_cmd="${name}_stop"',
        'status_cmd="${name}_status"',
        'extra_commands="status"',
        '',
        'load_rc_config $name',
        ': ${%s_enable:="NO"}' % RC_NAME,
        ': ${%s_image:="%s"}' % (RC_NAME, IMAGE_PATH),
        ': ${%s_unit:="%d"}' % (RC_NAME, MD_UNITS[0]),
        ': ${%s_pool:="%s"}' % (RC_NAME, POOL_NAME),
        ': ${%s_arc_max:=""}' % RC_NAME,
        '',
        '%s_start()' % RC_NAME,
        '{',
        '\tlocal img unit pool file',
        '\timg="${%s_image}"' % RC_NAME,
        '\tunit="${%s_unit}"' % RC_NAME,
        '\tpool="${%s_pool}"' % RC_NAME,
        '\tif [ ! -f "${img}" ]; then',
        '\t\twarn "${img} not found, pool ${pool} not imported"',
        '\t\treturn 1',
        '\tfi',
        '\t/sbin/kldload -n zfs || return 1',
        '\tif [ -n "${%s_arc_max}" ]; then' % RC_NAME,
        '\t\t/sbin/sysctl -q vfs.zfs.arc.max="${%s_arc_max}" > /dev/null || warn "vfs.zfs.arc.max not set"'
        % RC_NAME,
        '\tfi',
        '\tif /sbin/mdconfig -l -u "${unit}" > /dev/null 2>&1; then',
        '\t\tfile=$(/sbin/mdconfig -lv -u "${unit}" | /usr/bin/awk \'{print $4}\')',
        '\t\tif [ "${file}" != "${img}" ]; then',
        '\t\t\twarn "md${unit} is attached to ${file:-something else}, not to ${img}"',
        '\t\t\treturn 1',
        '\t\tfi',
        '\telse',
        '\t\t/sbin/mdconfig -a -t vnode -f "${img}" -u "${unit}" || return 1',
        '\tfi',
        '\tif ! /sbin/zpool list -H -o name "${pool}" > /dev/null 2>&1; then',
        '\t\t/sbin/zpool import -d "/dev/md${unit}" -o cachefile=none "${pool}" || return 1',
        '\tfi',
        '}',
        '',
        '%s_stop()' % RC_NAME,
        '{',
        '\tif /sbin/zpool list -H -o name "${%s_pool}" > /dev/null 2>&1; then' % RC_NAME,
        '\t\t# a jail that was just removed stays "dying" (jls -d) for up to a minute and keeps its',
        '\t\t# datasets busy: retry the export for up to 75 s, below the default rcshutdown_timeout of 90 s',
        '\t\t_tries=0',
        '\t\tuntil /sbin/zpool export "${%s_pool}" 2> /dev/null; do' % RC_NAME,
        '\t\t\t_tries=$((_tries + 1))',
        '\t\t\tif [ "${_tries}" -ge 25 ]; then',
        '\t\t\t\techo "${%s_pool} is still busy, left imported (the kernel syncs it at shutdown)"' % RC_NAME,
        '\t\t\t\treturn 1',
        '\t\t\tfi',
        '\t\t\tsleep 3',
        '\t\tdone',
        '\tfi',
        '\tif /sbin/mdconfig -l -u "${%s_unit}" > /dev/null 2>&1; then' % RC_NAME,
        '\t\t/sbin/mdconfig -d -u "${%s_unit}"' % RC_NAME,
        '\tfi',
        '}',
        '',
        '%s_status()' % RC_NAME,
        '{',
        # no digits in the last field: rc.freebsd takes the pid of a service from the last field of "status"
        # and kills it after service_stop_timeout; this service has no process
        '\tif /sbin/zpool list -H -o name "${%s_pool}" > /dev/null 2>&1; then' % RC_NAME,
        '\t\techo "${%s_pool} health=$(/sbin/zpool list -H -o health "${%s_pool}")'
        ' free=$(/sbin/zpool list -H -o free "${%s_pool}") is imported"' % (RC_NAME, RC_NAME, RC_NAME),
        '\telse',
        '\t\techo "${%s_pool} is not imported"' % RC_NAME,
        '\tfi',
        '}',
        '',
        'run_rc_command "$1"',
    ]) + '\n'


def render_rc_conf(image, unit, arc_bytes=None):
    return HEADER + '\n'.join([
        '%s_enable="YES"' % RC_NAME,
        '%s_image="%s"' % (RC_NAME, image),
        '%s_unit="%d"' % (RC_NAME, unit),
        '%s_pool="%s"' % (RC_NAME, POOL_NAME),
        '%s_arc_max="%s"' % (RC_NAME, arc_bytes or ''),
    ]) + '\n'


# ------------------------------------------------------------------ args


def validate_args(args):
    size = args.get('size')
    if size in (None, ''):
        raise ValueError('size (GiB of the pool image) is required, e.g. size=40')
    size = common.as_int(str(size).lower().rstrip('g'), SIZE_GB_MIN, SIZE_GB_MAX, 'size')
    arc = args.get('arc_mb')
    arc = common.as_int(arc, ARC_MB_MIN, ARC_MB_MAX, 'arc_mb') if arc not in (None, '') else None
    image = args.get('image') or IMAGE_PATH
    if not IMAGE_RE.match(image) or '..' in image:
        raise ValueError('image must be a file name ending in .img directly below /var/db/')
    return size, arc, image


# ------------------------------------------------------------------ plans


def create_plan(ctx, args):
    size_gb, arc_mb, image = validate_args(args)
    size = size_gb * common.GIB
    errors, warnings = [], []
    info = state(ctx, image)
    from .runtime import probe
    runtime = probe(ctx)
    system = common.target_filesystem(ctx, ctx.root + '/var/db')
    var_db_zfs = system['fstype'] == 'zfs'
    if var_db_zfs:
        errors.append('/var/db is already on ZFS (%s): no pool in a file is needed, prepare_storage creates the '
                      'dataset <pool>/ai directly' % system['device'])
    imported = info['pool_imported']
    ours = imported and info['image_exists'] and info['md_unit'] is not None
    if imported and not ours:
        errors.append('a pool named %s already exists and is not backed by %s' % (POOL_NAME, image))
    if info['image_exists'] and not ours and info['md_unit'] is None:
        errors.append('%s already exists (an earlier pool image?): import it with "service %s start" or delete it '
                      'first' % (image, RC_NAME))
    if info['image_exists'] and info['image_bytes'] != size:
        warnings.append('%s exists with %s; the size of an existing image is never changed'
                        % (image, common.fmt_bytes(info['image_bytes'])))
    mounted_here = common.mount_of(ctx, MOUNTPOINT)
    ai_dir = ctx.root + MOUNTPOINT
    if not info['dataset_mounted'] and mounted_here[1] == MOUNTPOINT:
        errors.append('%s is already a mount point (%s %s)' % (MOUNTPOINT, mounted_here[2], mounted_here[0]))
    elif not info['dataset_mounted'] and os.path.isdir(ai_dir) and _has_files(ai_dir, LEFTOVER_FILES):
        errors.append('%s already holds files (models or the jail): the pool would hide them; remove the runtime '
                      'and the models first (uninstall_runtime +remove_dataset confirm=%s/models)'
                      % (MOUNTPOINT, MOUNTPOINT))
    if runtime['running']:
        errors.append('the local runtime is running: stop it first (stop_runtime)')
    units = md_list(ctx)
    unit = info['md_unit']
    if unit is None:
        configured = _configured_unit(ctx)
        try:
            unit = configured if configured is not None and configured not in units else _free_unit(ctx, units)
        except common.SetupError as exc:
            errors.append(str(exc))
            unit = MD_UNITS[0]
    space = {'free': common.free_bytes(ctx.root + '/var/db'), 'needed': 0}
    if not info['image_exists']:
        space = common.space_check(ctx, ctx.root + '/var/db', size, 'the pool image', exact=True)
        errors += space['errors']
    device = '/dev/md%d' % unit
    arc_bytes = arc_mb * common.MIB if arc_mb else None
    steps = [
        {'type': 'run', 'argv': ['/sbin/kldload', '-n', 'zfs'], 'skip_if': ['/sbin/kldstat', '-q', '-m', 'zfs'],
         'description': 'Load the ZFS kernel module (zfs.ko)',
         'effect': 'ZFS becomes available; the module stays loaded (also after a revert, until the next boot)'},
    ]
    if arc_bytes and common.sysctl(ctx, 'vfs.zfs.arc.max') != str(arc_bytes):
        steps.append({'type': 'run', 'argv': ['/sbin/sysctl', 'vfs.zfs.arc.max=%d' % arc_bytes],
                      'undo_argv': ['/sbin/sysctl', 'vfs.zfs.arc.max=0'],
                      'description': 'Limit the ZFS ARC to %d MiB (vfs.zfs.arc.max)' % arc_mb,
                      'effect': 'RAM used by the ZFS cache stays below %d MiB; applied again at every boot by the '
                                'rc script' % arc_mb,
                      'undo': 'vfs.zfs.arc.max=0 (automatic size)'})
    steps += [
        {'type': 'write_file', 'path': ctx.root + RC_CONF, 'content': render_rc_conf(image, unit, arc_bytes),
         'mode': '0644', 'command': 'write %s' % RC_CONF,
         'description': 'Enable the pool at boot (%s)' % RC_CONF,
         'effect': '%s_enable="YES", image %s, unit md%d' % (RC_NAME, image, unit),
         'undo': 'previous content restored (or the file removed)'},
        {'type': 'write_file', 'path': ctx.root + RC_SCRIPT, 'content': render_rc_script(), 'mode': '0755',
         'command': 'write %s' % RC_SCRIPT,
         'description': 'rc script %s (attach md%d, import %s before the jail starts)' % (RC_SCRIPT, unit, POOL_NAME),
         'effect': 'run by rc.freebsd at boot (REQUIRE: FILESYSTEMS, BEFORE: jail); stop exports the pool',
         'undo': 'file removed'},
        {'type': 'image_create', 'path': ctx.root + image, 'size': size, 'download_bytes': None,
         'command': 'preallocate %s (%s)' % (image, common.fmt_bytes(size)),
         'description': 'Create the pool image %s (%s, preallocated)' % (image, common.fmt_bytes(size)),
         'effect': 'the whole size is reserved on the system disk now, so the pool can never fill it later',
         'undo': 'the image is deleted (only once it is detached)'},
        {'type': 'md_attach', 'path': image, 'unit': unit,
         'argv': ['/sbin/mdconfig', '-a', '-t', 'vnode', '-f', image, '-u', str(unit)],
         'description': 'Attach the image as %s (vnode memory disk)' % device,
         'effect': 'block device backed by the file; no RAM is used for the data',
         'undo': 'mdconfig -d -u %d' % unit},
        {'type': 'zpool_create', 'pool': POOL_NAME, 'device': device, 'properties': POOL_PROPERTIES,
         'root_properties': ROOT_PROPERTIES,
         'argv': ['/sbin/zpool', 'create'] + sum([['-o', '%s=%s' % p] for p in POOL_PROPERTIES], [])
         + sum([['-O', '%s=%s' % p] for p in ROOT_PROPERTIES], []) + [POOL_NAME, device],
         'description': 'Create the ZFS pool %s on %s' % (POOL_NAME, device),
         'effect': 'cachefile=none (imported only by the rc script), root dataset not mounted',
         'undo': 'zpool destroy %s, only while it holds no files' % POOL_NAME},
        {'type': 'zfs_create', 'dataset': POOL_DATASET, 'properties': DATASET_PROPERTIES, 'undo_only_empty': True,
         'argv': ['/sbin/zfs', 'create'] + sum([['-o', '%s=%s' % p] for p in DATASET_PROPERTIES], [])
         + [POOL_DATASET],
         'description': 'Create the dataset %s mounted on %s' % (POOL_DATASET, MOUNTPOINT),
         'effect': 'recordsize=1M, compression=off, atime=off, primarycache=metadata (model data is not kept in '
                   'the ARC)',
         'undo': 'zfs destroy %s, only while it holds no files' % POOL_DATASET},
        {'type': 'mkdir', 'path': ctx.models_dir, 'mode': '0755', 'argv': ['/bin/mkdir', '-p', ctx.models_dir],
         'description': 'Create the models directory %s in the pool' % common.system_path(ctx, ctx.models_dir)},
    ]
    if info['dataset_mounted'] and ours:
        warnings.append('the pool in a file already exists (%s on md%d), nothing to create' % (image, unit))
    if not var_db_zfs:
        warnings += [
            'two file systems are stacked (ZFS inside a file on UFS): every model read goes through both, and a '
            'crash of the firewall can leave the image to be checked by both fsck and zpool scrub',
            'ZFS uses RAM for its cache (ARC); %s' % ('limited to %d MiB here' % arc_mb if arc_mb else
                                                     'pass arc_mb=<MiB> (e.g. 512) to cap it on a small firewall'),
            'an Ollama server in the LAN (provider Ollama, location "lan") keeps the models off the firewall disk',
        ]
    return {'steps': steps, 'errors': errors, 'warnings': warnings, 'irreversible': [],
            'download_bytes': 0, 'space_needed': space.get('needed') or 0, 'space_free': space.get('free'),
            'space_path': '/var/db',
            'undo': 'Revert destroys the pool, detaches md%d and deletes %s and the rc files, only while the pool '
                    'holds no files (otherwise remove_file_pool confirm=%s)' % (unit, image, POOL_NAME),
            'resources': ['storage'], 'risk': 'medium', 'background': True,
            'args': {'size': size_gb, 'arc_mb': arc_mb, 'image': image},
            'file_pool': dict(info, md_unit=unit, size_bytes=size)}


def remove_plan(ctx, args):
    confirm = args.get('confirm') or ''
    errors, warnings, irreversible = [], [], []
    image = args.get('image') or IMAGE_PATH
    if not IMAGE_RE.match(image) or '..' in image:
        raise ValueError('image must be a file name ending in .img directly below /var/db/')
    info = state(ctx, image)
    from .runtime import probe
    runtime = probe(ctx)
    if runtime['running'] or runtime['jail_conf'] or runtime['base_extracted']:
        errors.append('the local runtime is installed: remove it first (uninstall_runtime)')
    unit = info['md_unit'] if info['md_unit'] is not None else _configured_unit(ctx)
    if not info['image_exists'] and not info['pool_imported']:
        warnings.append('no pool in a file found (%s), nothing to remove' % image)
    elif confirm != POOL_NAME:
        errors.append('to destroy the pool %s and everything in it pass confirm=%s' % (POOL_NAME, POOL_NAME))
    foreign = [m for m in common.mounts_below(ctx, MOUNTPOINT) if not m[0].startswith(POOL_NAME + '/')]
    if foreign:
        errors.append('%s is still mounted below %s' % (foreign[0][1], MOUNTPOINT))
    steps = [
        {'type': 'write_file', 'path': ctx.root + RC_CONF, 'content': None, 'argv': ['/bin/rm', RC_CONF],
         'description': 'Disable the pool at boot (remove %s)' % RC_CONF},
        {'type': 'write_file', 'path': ctx.root + RC_SCRIPT, 'content': None, 'argv': ['/bin/rm', RC_SCRIPT],
         'description': 'Remove the rc script %s' % RC_SCRIPT},
        {'type': 'zpool_destroy', 'pool': POOL_NAME, 'argv': ['/sbin/zpool', 'destroy', POOL_NAME],
         'description': 'Destroy the pool %s with ALL its content' % POOL_NAME,
         'effect': 'models and anything else in %s are permanently deleted' % POOL_DATASET},
    ]
    if unit is not None:
        steps.append({'type': 'md_detach', 'path': image, 'unit': unit,
                      'argv': ['/sbin/mdconfig', '-d', '-u', str(unit)],
                      'description': 'Detach md%d' % unit})
    steps.append({'type': 'image_remove', 'path': ctx.root + image, 'argv': ['/bin/rm', image],
                  'description': 'Delete the pool image %s (frees %s on the system disk)'
                                 % (image, common.fmt_bytes(info['image_bytes']))})
    arc = common.sysctl(ctx, 'vfs.zfs.arc.max')
    if arc and arc != '0':
        steps.append({'type': 'run', 'argv': ['/sbin/sysctl', 'vfs.zfs.arc.max=0'],
                      'description': 'Give the ZFS ARC its automatic size back (vfs.zfs.arc.max=0)',
                      'effect': 'the cap set for the pool in a file is lifted now, not only at the next boot'})
    if info['image_exists'] or info['pool_imported']:
        irreversible.append('pool %s and everything in it (models) are permanently deleted' % POOL_NAME)
    size_gb = max(SIZE_GB_MIN, (info['image_bytes'] or 0) // common.GIB) if info['image_bytes'] else None
    return {'steps': steps, 'errors': errors, 'warnings': warnings, 'irreversible': irreversible,
            'download_bytes': 0, 'space_freed': info['image_bytes'] or 0,
            'undo': 'Revert creates an empty pool in a file again (%s GiB); deleted models are NOT restored'
                    % (size_gb or '?'),
            'resources': ['storage'], 'risk': 'high', 'background': False,
            'args': {'confirm': confirm, 'image': image},
            'revert_action': {'action': 'create_file_pool', 'args': {'size': size_gb or SIZE_GB_MIN,
                                                                     'image': image}},
            'file_pool': info}
