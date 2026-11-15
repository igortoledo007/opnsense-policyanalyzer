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

    Health collector (port of "opn.py saude"), one sample per hourly run in health.db, read with local tools
    only (no API):

      sysctl      kern.cp_time (CPU busy/idle averaged since the previous run), vm.loadavg, hw.physmem,
                  vm.stats.vm.* (memory), kstat.zfs.misc.arcstats.size, kern.boottime, temperatures
                  (dev.cpu.N.temperature, hw.acpi.thermal.tzN.temperature)
      swapinfo -k, zpool list -Hp, mount -p, df -kP / (when / is not ZFS or there is no pool)
      pfctl -si / -sm   states, state limit, counters as rates since the previous run
      dpinger     /var/run/dpinger_<gw>.sock: "<name> <rtt us> <rttsd us> <loss %>"
      /var/log/gateways/latest.log   "ALERT:" lines -> events (incremental, dev/ino/offset marker)
      netstat -ibdn  per link counters (cumulative bytes, drops, errors) + average bit rate since last run
      netstat -m  mbuf cluster usage
      pluginctl -S  services; not running -> metric + one event per service and hour
      ps          RSS / CPU of the watched processes (settings "processes")
      wg show all dump   per peer rx/tx/handshake age (names from config.xml; keys are never stored)
      arp -an     ARP table -> hosts (mac, ip, interface, first/last seen) and the count

    Metric keys keep the opn.py meaning where one existed (see importer.HEALTH_KEYS).
"""

import glob
import json
import os
import re
import socket
import time

from . import common, store

_SYSCTL_RE = re.compile(r'^([a-z0-9_.%-]+):\s*(.*)$', re.I)


def sysctl(ctx, names):
    out = ctx.read(['/sbin/sysctl', '-i'] + list(names))
    result = {}
    for line in out.splitlines():
        match = _SYSCTL_RE.match(line.strip())
        if match:
            result[match.group(1)] = match.group(2).strip()
    return result


def _num(value):
    try:
        return float(str(value).strip().rstrip('C%').replace(',', '.'))
    except (TypeError, ValueError):
        return None


def _ints(value):
    return [int(x) for x in re.findall(r'\d+', value or '')]


# ------------------------------------------------------------------ probes (each returns metrics dict)


def probe_system(ctx, prev, now):
    m = {}
    state = {}
    names = ['kern.cp_time', 'vm.loadavg', 'hw.physmem', 'hw.ncpu', 'vm.stats.vm.v_page_size',
             'vm.stats.vm.v_page_count', 'vm.stats.vm.v_free_count', 'vm.stats.vm.v_inactive_count',
             'vm.stats.vm.v_active_count', 'vm.stats.vm.v_wire_count', 'vm.stats.vm.v_laundry_count',
             'kstat.zfs.misc.arcstats.size', 'kern.boottime']
    s = sysctl(ctx, names)
    cp = _ints(s.get('kern.cp_time'))
    if len(cp) == 5:
        state['cp_time'] = cp
        old = prev.get('cp_time')
        if not old or len(old) != 5 or sum(cp) <= sum(old):
            # first run (or reboot): a one second sample
            time.sleep(0 if ctx.sources.get('no_sleep') else 1)
            again = _ints(sysctl(ctx, ['kern.cp_time']).get('kern.cp_time'))
            old, cp = cp, (again if len(again) == 5 else cp)
            state['cp_time'] = cp
        delta = [b - a for a, b in zip(old, cp)]
        total = sum(delta)
        if total > 0:
            m['cpu_idle_pct'] = round(100.0 * delta[4] / total, 2)
            m['cpu_user_pct'] = round(100.0 * (delta[0] + delta[1]) / total, 2)
            m['cpu_system_pct'] = round(100.0 * delta[2] / total, 2)
            m['cpu_interrupt_pct'] = round(100.0 * delta[3] / total, 2)
    load = re.findall(r'[\d.]+', s.get('vm.loadavg', ''))
    if len(load) >= 3:
        m['load_1m'], m['load_5m'], m['load_15m'] = (float(x) for x in load[:3])
    ncpu = _num(s.get('hw.ncpu'))
    if ncpu:
        m['ncpu'] = ncpu
    page = _num(s.get('vm.stats.vm.v_page_size')) or 4096
    pages = {k.rsplit('.', 1)[-1]: _num(v) or 0 for k, v in s.items() if k.startswith('vm.stats.vm.v_')}
    physmem = _num(s.get('hw.physmem'))
    if physmem:
        m['mem_total_mb'] = round(physmem / 1048576, 1)
    if pages.get('v_page_count'):
        used = pages['v_page_count'] - pages.get('v_free_count', 0) - pages.get('v_inactive_count', 0)
        m['mem_used_mb'] = round(used * page / 1048576, 1)
        m['mem_wired_mb'] = round(pages.get('v_wire_count', 0) * page / 1048576, 1)
        m['mem_free_mb'] = round(pages.get('v_free_count', 0) * page / 1048576, 1)
        m['mem_used_pct'] = round(100.0 * used / pages['v_page_count'], 2)
    arc = _num(s.get('kstat.zfs.misc.arcstats.size'))
    if arc is not None:
        m['zfs_arc_mb'] = round(arc / 1048576, 1)
    boot = re.search(r'sec = (\d+)', s.get('kern.boottime', ''))
    if boot:
        boot_ts = int(boot.group(1))
        m['uptime_s'] = round(now - boot_ts)
        state['boot'] = boot_ts
    # temperatures
    ncores = int(ncpu or 0)
    temps = sysctl(ctx, ['dev.cpu.%d.temperature' % i for i in range(max(ncores, 1))] +
                   ['hw.acpi.thermal.tz%d.temperature' % i for i in range(4)])
    cpu = [_num(v) for k, v in temps.items() if k.startswith('dev.cpu.')]
    cpu = [t for t in cpu if t is not None]
    if cpu:
        m['temp_cpu'] = round(sum(cpu) / len(cpu), 1)
        m['temp_cpu_max'] = max(cpu)
    acpi = [_num(v) for k, v in temps.items() if k.startswith('hw.acpi.')]
    acpi = [t for t in acpi if t is not None]
    if acpi:
        m['temp_acpi'] = max(acpi)
    return m, state


def probe_disk(ctx):
    m = {}
    out = ctx.read(['/usr/sbin/swapinfo', '-k'])
    total = used = 0
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1].isdigit():
            total += int(parts[1])
            used += int(parts[2])
    if total:
        m['swap_total_mb'] = round(total / 1024, 1)
        m['swap_used_mb'] = round(used / 1024, 1)
    pools = ctx.read(['/sbin/zpool', 'list', '-Hp'])
    for line in pools.splitlines():
        f = line.split('\t')
        if len(f) < 10:
            continue
        name = f[0]
        size, alloc, free = _num(f[1]), _num(f[2]), _num(f[3])
        if size:
            m['zpool:%s:size_gb' % name] = round(size / 1e9, 2)
            m['zpool:%s:alloc_gb' % name] = round((alloc or 0) / 1e9, 2)
            m['zpool:%s:free_gb' % name] = round((free or 0) / 1e9, 2)
            m['zpool:%s:cap_pct' % name] = _num(f[7])
            m['zpool:%s:frag_pct' % name] = _num(f[6])
        m['zpool:%s:healthy' % name] = 1.0 if f[9].strip() == 'ONLINE' else 0.0
    # the root file system is measured with df whenever it is not ZFS: on UFS a pool may still exist
    # (the Policy Analyzer file-backed pool for the AI models) without holding /
    root_fs = ''
    for line in ctx.read(['/sbin/mount', '-p']).splitlines():
        f = line.split()
        if len(f) >= 3 and f[1] == '/':
            root_fs = f[2]
    if not pools.strip() or (root_fs and root_fs != 'zfs'):
        df = ctx.read(['/bin/df', '-kP', '/'])
        lines = df.splitlines()
        if len(lines) >= 2:
            f = lines[1].split()
            if len(f) >= 5:
                m['disk_root_used_pct'] = _num(f[4])
                m['disk_root_free_gb'] = round((_num(f[3]) or 0) / 1048576, 2)
    return m


_PF_COUNTERS = ('match', 'state-mismatch', 'memory', 'state-limit', 'proto-cksum', 'bad-offset', 'fragment',
                'short', 'normalize', 'congestion', 'map-failed')


def probe_pf(ctx, prev, now):
    m = {}
    state = {}
    out = ctx.read(['/sbin/pfctl', '-si'])
    totals = {}
    for line in out.splitlines():
        match = re.match(r'^\s+([a-z -]+?)\s+(\d+)\b', line)
        if match:
            totals[match.group(1).strip()] = int(match.group(2))
    if 'current entries' in totals:
        m['pf_states'] = totals['current entries']
    limits = ctx.read(['/sbin/pfctl', '-sm'])
    lim = re.search(r'^states\s+hard limit\s+(\d+)', limits, re.M)
    if lim:
        m['pf_states_limit'] = int(lim.group(1))
        if 'pf_states' in m and m['pf_states_limit']:
            m['pf_states_pct'] = round(100.0 * m['pf_states'] / m['pf_states_limit'], 3)
    keep = {k: totals[k] for k in ('searches', 'inserts', 'removals') + _PF_COUNTERS if k in totals}
    state['pf'] = {'ts': now, 'totals': keep}
    old = prev.get('pf') or {}
    span = now - (old.get('ts') or now)
    if span > 0:
        for k, v in keep.items():
            before = (old.get('totals') or {}).get(k)
            if before is not None and v >= before:
                m['pf:%s_rate' % k.replace('-', '_')] = round((v - before) / span, 3)
    return m, state


def read_dpinger(ctx):
    """ [(name, rtt_us, rttsd_us, loss_pct)] """
    if 'dpinger' in ctx.sources:
        return ctx.sources['dpinger']()
    rows = []
    for path in sorted(glob.glob(ctx.dpinger_glob)):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(path)
            data = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            sock.close()
        except OSError:
            continue
        parts = data.decode('utf-8', 'replace').split()
        if len(parts) >= 4:
            rows.append((parts[0], _num(parts[1]), _num(parts[2]), _num(parts[3])))
    return rows


def probe_gateways(ctx):
    m = {}
    for name, rtt, rttsd, loss in read_dpinger(ctx):
        if rtt is not None:
            m['gw:%s:rtt_ms' % name] = round(rtt / 1000.0, 2)
        if rttsd is not None:
            m['gw:%s:rttsd_ms' % name] = round(rttsd / 1000.0, 2)
        if loss is not None:
            m['gw:%s:loss_pct' % name] = loss
    return m


_ALERT_RE = re.compile(r'ALERT:\s+(\S+)\s+\((.*)\)')


def gateway_events(ctx, marker, now):
    """ ALERT lines of dpinger since the marker -> [(ts, name, text)] """
    from quarantine import sources as qsources            # incremental reader shared with the quarantine
    lines, new_marker, info = qsources.read_new(
        ctx.gateways_log, lambda: sorted(glob.glob(os.path.join(os.path.dirname(os.path.realpath(
            ctx.gateways_log)), 'gateways_*.log')), reverse=True)[:3],
        marker, max_bytes=4 * 1024 * 1024, first_tail=1 << 20, prefilter=b'ALERT:')
    events = []
    for line in lines:
        match = _ALERT_RE.search(line)
        if not match:
            continue
        ts = None
        parts = line.split(' ', 3)
        if len(parts) >= 2 and parts[0].startswith('<'):
            try:
                ts = common.parse_time(parts[1])
            except ValueError:
                ts = None
        events.append((ts or now, match.group(1), line[line.find('ALERT:'):].strip()[:300]))
    return events, new_marker


def probe_interfaces(ctx, prev, now):
    m = {}
    out = ctx.read(['/usr/bin/netstat', '-ibdn'])
    counters = {}
    lines = out.splitlines()
    header = lines[0].split() if lines else []
    for line in lines[1:]:
        f = line.split()
        if len(f) < len(header) - 1 or '<Link' not in line:
            continue
        # Name Mtu Network Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll Drop (Address may be empty)
        if len(f) == len(header) - 1:
            f.insert(3, '')
        row = dict(zip(header, f))
        dev = row.get('Name', '').rstrip('*')
        if not dev or dev.startswith(('lo', 'pflog', 'pfsync', 'enc')):
            continue
        try:
            counters[dev] = {'rx': int(row['Ibytes']), 'tx': int(row['Obytes']),
                             'drops': int(row.get('Idrop', 0) or 0) + int(row.get('Drop', 0) or 0),
                             'errors': int(row.get('Ierrs', 0) or 0) + int(row.get('Oerrs', 0) or 0)}
        except (KeyError, ValueError):
            continue
    old = prev.get('if') or {}
    span = now - (old.get('ts') or now)
    for dev, c in counters.items():
        for k, v in c.items():
            m['if:%s:%s' % (dev, k)] = v
        before = (old.get('counters') or {}).get(dev)
        if before and span > 0:
            for k in ('rx', 'tx'):
                if c[k] >= before.get(k, 0):
                    m['if:%s:%s_bps' % (dev, k)] = round((c[k] - before[k]) * 8 / span, 1)
    mbuf = ctx.read(['/usr/bin/netstat', '-m'])
    match = re.search(r'(\d+)/(\d+)/(\d+)/(\d+) mbuf clusters in use', mbuf)
    if match and int(match.group(4)):
        m['mbuf_clusters_pct'] = round(100.0 * int(match.group(3)) / int(match.group(4)), 3)
    return m, {'if': {'ts': now, 'counters': counters}}


def probe_services(ctx, settings):
    out = ctx.read(['/usr/local/sbin/pluginctl', '-S'], timeout=30)
    try:
        services = json.loads(out) if out.strip() else []
    except ValueError:
        services = []
    stopped = []
    ignore = set(settings.get('ignore_services') or [])
    for svc in services if isinstance(services, list) else []:
        sid = svc.get('name') or ''
        if svc.get('id'):
            sid = '%s/%s' % (sid, svc['id'])
        status = str(svc.get('status') or '')
        if 'is running' in status or sid in ignore or svc.get('name') in ignore:
            continue
        stopped.append((sid, svc.get('description') or sid))
    m = {'services_total': len(services) if isinstance(services, list) else 0, 'services_stopped': len(stopped)}
    return m, stopped


def probe_processes(ctx, settings):
    watch = settings.get('processes') or []
    out = ctx.read(['/bin/ps', '-axww', '-o', 'rss=', '-o', 'pcpu=', '-o', 'comm='])
    m = {}
    for line in out.splitlines():
        f = line.split(None, 2)
        if len(f) < 3:
            continue
        comm = os.path.basename(f[2].strip())
        if comm in watch:
            m['proc:%s:res_mb' % comm] = round(m.get('proc:%s:res_mb' % comm, 0) + int(f[0]) / 1024.0, 1)
            m['proc:%s:cpu' % comm] = round(m.get('proc:%s:cpu' % comm, 0) + (_num(f[1]) or 0), 2)
            m['proc:%s:count' % comm] = m.get('proc:%s:count' % comm, 0) + 1
    return m


def wireguard_names(root):
    names = {}
    if root is None:
        return names
    for peer in root.findall('./OPNsense/wireguard/client/clients/client'):
        if peer.findtext('pubkey'):
            names[peer.findtext('pubkey').strip()] = (peer.findtext('name') or '').strip()
    return names


def probe_wireguard(ctx, root, now):
    out = ctx.read(['/usr/bin/wg', 'show', 'all', 'dump'])
    names = wireguard_names(root)
    m = {}
    for line in out.splitlines():
        f = line.split('\t')
        if len(f) != 9:
            continue        # interface line (holds the private key): never parsed further
        iface, pub, _psk, _endpoint, _allowed, handshake, rx, tx, _ka = f
        name = names.get(pub) or '%s:%s' % (iface, pub[:8])
        name = re.sub(r'[^A-Za-z0-9_.-]', '_', name)[:48]
        m['wg:%s:rx' % name] = _num(rx)
        m['wg:%s:tx' % name] = _num(tx)
        hs = _num(handshake)
        if hs:
            m['wg:%s:handshake_s' % name] = round(now - hs)
    return m


_ARP_RE = re.compile(r'^\S+ \(([0-9a-fA-F:.]+)\) at ([0-9a-f:]{17}) on (\S+)')


def probe_arp(ctx):
    out = ctx.read(['/usr/sbin/arp', '-an'])
    hosts = []
    for line in out.splitlines():
        match = _ARP_RE.match(line.strip())
        if match:
            hosts.append((match.group(2).lower(), match.group(1), match.group(3)))
    return hosts


# ------------------------------------------------------------------ run


def run(ctx, settings, deadline=None):
    con = store.open_db(ctx, 'health')
    now = ctx.clock()
    ts = int(now)
    prev = common.meta_get(con, 'probe_state') or {}
    root = common.load_config(ctx)
    metrics = {}
    state = {}
    errors = []

    def guarded(name, fn, *args):
        try:
            return fn(*args)
        except Exception as exc:          # noqa: BLE001 - one broken probe never loses the others
            errors.append('%s: %s' % (name, exc))
            return None

    for name, fn, args in (('system', probe_system, (ctx, prev, now)), ('pf', probe_pf, (ctx, prev, now)),
                           ('interfaces', probe_interfaces, (ctx, prev, now))):
        res = guarded(name, fn, *args)
        if res:
            metrics.update(res[0])
            state.update(res[1])
    for name, fn, args in (('disk', probe_disk, (ctx,)), ('gateways', probe_gateways, (ctx,)),
                           ('processes', probe_processes, (ctx, settings)),
                           ('wireguard', probe_wireguard, (ctx, root, now))):
        res = guarded(name, fn, *args)
        if res:
            metrics.update(res)
    events = []
    svc = guarded('services', probe_services, ctx, settings)
    if svc:
        metrics.update(svc[0])
        hour = common.hour_of(now)
        for sid, descr in svc[1]:
            events.append((hour, 'service_stopped', sid, '%s stopped' % descr))
    gw = guarded('gateway_log', gateway_events, ctx, common.meta_get(con, 'gateway_marker'), now)
    if gw:
        events.extend((t, 'gateway', name, text) for t, name, text in gw[0])
    if prev.get('boot') and state.get('boot') and state['boot'] != prev['boot']:
        events.append((state['boot'], 'reboot', None, 'firewall booted (%s)' % common.iso(state['boot'])))
    hosts = guarded('arp', probe_arp, ctx) or []
    metrics['hosts_arp'] = len(hosts)
    for kind, db_path in ctx.db.items():
        metrics['collect:%s_mb' % kind] = common.db_size_mb(db_path)

    con.executemany('INSERT OR REPLACE INTO metrics (ts, key, value) VALUES (?,?,?)',
                    [(ts, k, float(v)) for k, v in sorted(metrics.items()) if v is not None])
    con.executemany('INSERT OR IGNORE INTO events (ts, kind, source, text) VALUES (?,?,?,?)', events)
    for mac, ip, iface in hosts:
        con.execute("""INSERT INTO hosts (mac, ip, iface, first_seen, last_seen) VALUES (?,?,?,?,?)
                       ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, iface = excluded.iface,
                       last_seen = excluded.last_seen""", (mac, ip, iface, now, now))
    merged = dict(prev)
    merged.update(state)
    common.meta_set(con, 'probe_state', merged)
    if gw:
        common.meta_set(con, 'gateway_marker', gw[1])
    if not common.meta_get(con, 'local_since'):
        common.meta_set(con, 'local_since', ts)
    con.commit()
    maintenance = store.maintain(ctx, 'health', con, settings, now)
    result = {'status': 'ok', 'kind': 'health', 'ts': common.iso(now), 'metrics': len(metrics),
              'events': len(events), 'hosts': len(hosts), 'errors': errors,
              'sample': {k: metrics.get(k) for k in ('cpu_idle_pct', 'load_1m', 'mem_used_pct', 'pf_states',
                                                      'temp_cpu', 'services_stopped') if k in metrics}}
    if maintenance:
        result['maintenance'] = maintenance
    common.meta_set(con, 'last_run', result)
    con.commit()
    con.close()
    return result
