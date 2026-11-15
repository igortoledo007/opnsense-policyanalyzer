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

    Filter log collector (read only).

    /var/log/filter/latest.log (a link to filter_YYYYMMDD.log) is read from the end towards the beginning
    (and the older daily files when the window asks for it), within a byte, line and time budget, like
    ai/brief.py.  Lines are parsed as the core read_log.py does (filterlog CSV, see
    opnsense/ports filterlog/files/description.txt).  A cheap substring test on the addresses asked for runs
    before the CSV is split, so a focused question over a whole day stays within a few seconds on an N100.

        records, meta = read(paths, since, until, budget, flt)       flt: Filter
        focus(...)      aggregates + a few sample events about one subject (address, port, rule, interface)
        top(...)        who is blocked most, which ports, which rules block (no subject)
        tail(...)       the newest N events for the log viewer of the console
"""

import calendar
import collections
import glob
import ipaddress
import os
import re
import time

from . import fwinfo

MAX_BYTES = 32 * 1024 * 1024
MAX_LINES = 400000
SAMPLES = 8
TOP_N = 8

_RFC5424 = re.compile(r'^<\d+>\d+\s+(\S+)\s+\S+\s+filterlog\b')
_RFC3164 = re.compile(r'^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+filterlog[^:]*:\s*(.*)$')
_TS = re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')


def _ts5424(value):
    m = _TS.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s, tz = m.groups()
    epoch = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s), 0, 0, 0))
    if tz and tz != 'Z':
        sign = 1 if tz[0] == '+' else -1
        tz = tz[1:].replace(':', '')
        epoch -= sign * (int(tz[:2]) * 3600 + int(tz[2:]) * 60)
    elif not tz:
        epoch = time.mktime(time.strptime(value[:19], '%Y-%m-%dT%H:%M:%S'))
    return epoch


def line_time(line, now=None):
    """ :return: (epoch, csv part) or (None, None) for lines that are not filterlog lines """
    m = _RFC5424.match(line)
    if m:
        return _ts5424(m.group(1)), line.rsplit(' ', 1)[-1]
    m = _RFC3164.match(line)
    if not m:
        return None, None
    now = time.time() if now is None else now
    try:
        parsed = time.strptime('%d %s' % (time.localtime(now).tm_year, ' '.join(m.group(1).split())),
                               '%Y %b %d %H:%M:%S')
    except ValueError:
        return None, None
    epoch = time.mktime(parsed)
    if epoch > now + 86400:
        epoch -= 365 * 86400
    return epoch, m.group(2).strip()


def parse_csv(ts, csv):
    """ filterlog CSV -> record dict, None for layouts we do not know """
    f = csv.split(',')
    if len(f) < 9:
        return None
    rec = {'ts': ts, 'rulenr': f[0], 'rid': f[3], 'iface': f[4], 'reason': f[5], 'action': f[6], 'dir': f[7],
           'ipver': f[8], 'proto': '', 'src': '', 'dst': '', 'sport': '', 'dport': '', 'len': '', 'flags': ''}
    if f[8] == '4' and len(f) >= 20:
        rec['proto'], rec['len'], rec['src'], rec['dst'] = f[16].lower(), f[17], f[18], f[19]
        rest = f[20:]
    elif f[8] == '6' and len(f) >= 17:
        rec['proto'], rec['len'], rec['src'], rec['dst'] = f[12].lower(), f[14], f[15], f[16]
        rest = f[17:]
    else:
        return rec if rec['action'] in ('pass', 'block') else None
    if rec['proto'] in ('tcp', 'udp') and len(rest) >= 2:
        rec['sport'], rec['dport'] = rest[0], rest[1]
        if rec['proto'] == 'tcp' and len(rest) >= 4:
            rec['flags'] = rest[3]
    return rec


def parse_line(line, now=None):
    ts, csv = line_time(line.strip(), now)
    if ts is None:
        return None
    return parse_csv(ts, csv)


def log_files(path):
    """ latest.log first, then the older daily files, newest first """
    files = [path]
    try:
        target = os.path.realpath(path)
        rotated = sorted(glob.glob(os.path.join(os.path.dirname(target), 'filter_*.log')), reverse=True)
        if target in rotated:
            files += rotated[rotated.index(target) + 1:]
        elif rotated and target != path:
            files += [r for r in rotated if r != target]
    except OSError:
        pass
    return files


def reverse_lines(path, budget):
    """ lines of one file from the end, within budget['bytes'] """
    try:
        handle = open(path, 'rb')
    except OSError:
        return
    with handle:
        handle.seek(0, os.SEEK_END)
        pos = handle.tell()
        rest = b''
        while pos > 0 and budget['bytes'] > 0:
            size = min(262144, pos, budget['bytes'])
            pos -= size
            handle.seek(pos)
            chunk = handle.read(size) + rest
            budget['bytes'] -= size
            lines = chunk.split(b'\n')
            rest = lines.pop(0)
            for raw in reversed(lines):
                if raw:
                    yield raw.decode('utf-8', 'replace')
        if pos == 0 and rest:
            yield rest.decode('utf-8', 'replace')
        elif pos > 0:
            budget['cut'] = True


class Filter:
    """ what the operator asked about; empty filter = every event """

    def __init__(self, ips=(), ports=(), action=None, devices=(), rids=(), proto=None, direction=None):
        self.nets = []
        self.literals = []
        for value in ips or ():
            try:
                net = ipaddress.ip_network(str(value), strict=False)
            except ValueError:
                continue
            self.nets.append(net)
            if net.num_addresses == 1:
                self.literals.append(str(net.network_address))
        # a substring test is only exact for single addresses
        self.prefilter = self.literals if self.literals and len(self.literals) == len(self.nets) else None
        self.ports = {str(int(p)) for p in ports or () if str(p).isdigit()}
        self.action = action if action in ('pass', 'block') else None
        self.devices = set(devices or ())
        self.rids = set(rids or ())
        self.proto = proto
        self.direction = direction if direction in ('in', 'out') else None

    @property
    def empty(self):
        return not (self.nets or self.ports or self.action or self.devices or self.rids or self.proto or
                    self.direction)

    def raw_ok(self, csv):
        if self.prefilter and not any(lit in csv for lit in self.prefilter):
            return False
        if self.rids and not any(r in csv for r in self.rids):
            return False
        return True

    def ip_ok(self, value):
        if not self.nets:
            return True
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(ip.version == n.version and ip in n for n in self.nets)

    def match(self, rec):
        if self.action and rec['action'] != self.action:
            return False
        if self.devices and rec['iface'] not in self.devices:
            return False
        if self.rids and rec['rid'] not in self.rids:
            return False
        if self.proto and rec['proto'] != self.proto:
            return False
        if self.direction and rec['dir'] != self.direction:
            return False
        if self.ports and rec['dport'] not in self.ports and rec['sport'] not in self.ports:
            return False
        if self.nets and not (self.ip_ok(rec['src']) or self.ip_ok(rec['dst'])):
            return False
        return True

    def describe(self):
        out = {}
        if self.nets:
            out['addresses'] = [str(n) if n.num_addresses > 1 else str(n.network_address) for n in self.nets]
        if self.ports:
            out['ports'] = sorted(self.ports, key=int)
        for key in ('action', 'proto', 'direction'):
            if getattr(self, key):
                out[key] = getattr(self, key)
        if self.devices:
            out['interfaces'] = sorted(self.devices)
        if self.rids:
            out['rules'] = sorted(self.rids)
        return out


def read(path, since, until, budget, flt=None, limit=None, max_bytes=MAX_BYTES, max_lines=MAX_LINES, now=None):
    """
    :return: (records newest first, meta {lines_read, matched, complete, oldest_read, source})
    complete is True when the beginning of the window was reached within the budgets
    """
    flt = flt or Filter()
    now = time.time() if now is None else now
    state = {'bytes': max_bytes, 'cut': False}
    records, lines, reached, oldest = [], 0, False, None
    matched = 0
    for name in log_files(path):
        for line in reverse_lines(name, state):
            lines += 1
            ts, csv = line_time(line, now)
            if ts is not None:
                oldest = ts
                if ts < since:
                    reached = True
                    break
                if ts <= until + 60 and flt.raw_ok(csv):
                    rec = parse_csv(ts, csv)
                    if rec is not None and flt.match(rec):
                        matched += 1
                        if limit is None or len(records) < limit:
                            records.append(rec)
                        if limit is not None and len(records) >= limit:
                            reached = True
                            break
            if lines >= max_lines or (lines % 4000 == 0 and budget.expired()):
                state['cut'] = True
                break
        if reached or state['cut'] or state['bytes'] <= 0:
            break
    if not reached and not state['cut'] and state['bytes'] > 0:
        reached = True          # every file read to its beginning
    return records, {
        'source': 'filter log (%s)' % os.path.basename(path),
        'lines_read': lines,
        'matched': matched,
        'complete': reached and not state['cut'],
        'oldest_read': int(oldest) if oldest else None,
    }


def _port_key(rec):
    return '%s/%s' % (rec['dport'], rec['proto']) if rec['dport'] else (rec['proto'] or '?')


def compact(rec, devices=None, rule_names=None):
    """ one event as the console shows it and the model reads it """
    out = {
        'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rec['ts'])),
        'interface': rec['iface'],
        'action': rec['action'],
        'dir': rec['dir'],
        'proto': rec['proto'] or ('ipv%s' % rec['ipver']),
        'src': rec['src'] + (':%s' % rec['sport'] if rec['sport'] else ''),
        'dst': rec['dst'] + (':%s' % rec['dport'] if rec['dport'] else ''),
    }
    if devices and rec['iface'] in devices:
        info = devices[rec['iface']]
        out['interface_name'] = info['name'] + (' (wan)' if info.get('wan') and info['name'] != 'wan' else '')
    if rec['flags']:
        out['tcp_flags'] = rec['flags']
    if rule_names is not None:
        out['rule'] = rule_names.get(rec['rid'], {}).get('display') or ('label ' + rec['rid'] if rec['rid'] else '')
    return out


def aggregate(records, devices, rule_names, focus_nets=None):
    """ counters of a list of records (no raw lines) """
    by_action = collections.Counter()
    by_dir = collections.Counter()
    by_rule = collections.Counter()
    rule_action = {}
    ports = collections.Counter()
    peers = collections.Counter()
    ifaces = collections.Counter()
    for rec in records:
        action = rec['action'] if rec['action'] in ('pass', 'block') else 'other'
        by_action[action] += 1
        by_dir[rec['dir']] += 1
        by_rule[rec['rid']] += 1
        rule_action[rec['rid']] = action
        ports[_port_key(rec)] += 1
        info = devices.get(rec['iface'])
        ifaces[rec['iface'] + ((' (%s%s)' % (info['name'], ', wan' if info['wan'] else '')) if info else '')] += 1
        if focus_nets is not None:
            for side, other in (('src', 'dst'), ('dst', 'src')):
                if _in(rec[side], focus_nets) and not _in(rec[other], focus_nets):
                    peers[rec[other]] += 1
    rules = []
    for rid, count in by_rule.most_common(TOP_N):
        rules.append({'rule': rule_names.get(rid, {}).get('display') or ('label ' + rid if rid else 'unknown'),
                      'action': rule_action.get(rid), 'events': count})
    data = {
        'events': len(records),
        'by_action': dict(by_action),
        'by_direction': dict(by_dir),
        'by_rule': rules,
        'top_ports': [{'port': k, 'events': v} for k, v in ports.most_common(TOP_N)],
        'interfaces': [{'interface': k, 'events': v} for k, v in ifaces.most_common(4)],
    }
    if focus_nets is not None:
        data['top_peers'] = [{'address': k, 'events': v} for k, v in peers.most_common(TOP_N)]
    if records:
        data['first_seen'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(min(r['ts'] for r in records)))
        data['last_seen'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(max(r['ts'] for r in records)))
    return data


def _in(value, nets):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in nets)


def focus(paths, window, budget, flt, rule_names, now=None, samples=SAMPLES):
    records, meta = read(paths.filter_log, window['since'], window['until'], budget, flt, now=now)
    devices = fwinfo.device_map(paths.config)
    filters = flt.describe()
    if 'rules' in filters:
        # cite rules by name, not by uuid (data minimisation, as explain.py)
        filters['rules'] = [rule_names.get(r, {}).get('display') or r for r in filters['rules']]
    data = {'available': os.path.exists(paths.filter_log), 'filters': filters}
    data.update(meta)
    data.update(aggregate(records, devices, rule_names, flt.nets or None))
    # the newest events, blocked ones first, so the model can quote them
    ordered = [r for r in records if r['action'] == 'block'][:samples]
    ordered += [r for r in records if r['action'] != 'block'][:max(0, samples - len(ordered))]
    ordered.sort(key=lambda r: -r['ts'])
    data['sample_events'] = [compact(r, devices, rule_names) for r in ordered]
    return data


def top(paths, window, budget, rule_names, now=None):
    """ the general picture of a window: blocked sources (external and internal), ports, blocking rules """
    records, meta = read(paths.filter_log, window['since'], window['until'], budget, None, now=now)
    devices = fwinfo.device_map(paths.config)
    wan = fwinfo.wan_devices(paths.config)
    totals = collections.Counter()
    blocked_ext = collections.Counter()
    blocked_int = collections.Counter()
    ext_ports = collections.defaultdict(collections.Counter)
    int_ports = collections.defaultdict(collections.Counter)
    wan_ports = collections.defaultdict(collections.Counter)
    block_rules = collections.Counter()
    hours = collections.Counter()
    for rec in records:
        action = rec['action'] if rec['action'] in ('pass', 'block') else 'other'
        totals[action] += 1
        on_wan = rec['iface'] in wan if wan else rec['dir'] == 'in'
        if rec['dir'] == 'in' and on_wan:
            wan_ports[_port_key(rec)][action] += 1
        if action != 'block' or not rec['src']:
            continue
        block_rules[rec['rid']] += 1
        hours[time.strftime('%H:00', time.localtime(rec['ts']))] += 1
        if rec['dir'] == 'in' and on_wan:
            blocked_ext[rec['src']] += 1
            ext_ports[rec['src']][_port_key(rec)] += 1
        elif rec['dir'] == 'in':
            blocked_int[rec['src']] += 1
            int_ports[rec['src']][_port_key(rec) + ' -> ' + rec['dst']] += 1

    def ranked(counter, ports):
        out = []
        for ip, count in counter.most_common(TOP_N):
            out.append({'address': ip, 'blocked': count, 'distinct_ports': len(ports[ip]),
                        'top': [k for k, _ in ports[ip].most_common(3)]})
        return out

    ports_ranked = sorted(wan_ports.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    data = {'available': os.path.exists(paths.filter_log)}
    data.update(meta)
    data.update({
        'events': sum(totals.values()),
        'pass': totals['pass'],
        'block': totals['block'],
        'other': totals['other'],
        'wan_interfaces': sorted(fwinfo.describe_device(paths.config, d) for d in wan),
        'distinct_blocked_external_sources': len(blocked_ext),
        'top_blocked_external_sources': ranked(blocked_ext, ext_ports),
        'distinct_blocked_internal_sources': len(blocked_int),
        'top_blocked_internal_sources': ranked(blocked_int, int_ports),
        'top_wan_ports': [{'port': k, 'blocked': v['block'], 'passed': v['pass']} for k, v in ports_ranked[:TOP_N]],
        'top_blocking_rules': [{'rule': rule_names.get(rid, {}).get('display') or ('label ' + rid if rid else '?'),
                                'events': n} for rid, n in block_rules.most_common(5)],
        'blocks_per_hour': dict(sorted(hours.items())[-24:]),
    })
    return data


def tail(paths, flt, limit, budget, rule_names=None, window_seconds=7 * 86400, now=None):
    """ newest events first, for the viewer """
    now = time.time() if now is None else now
    records, meta = read(paths.filter_log, now - window_seconds, now, budget, flt, limit=limit,
                         max_bytes=16 * 1024 * 1024, max_lines=200000, now=now)
    devices = fwinfo.device_map(paths.config)
    rows = []
    for rec in records:
        row = compact(rec, devices, rule_names)
        row.update({'ts': int(rec['ts']), 'rid': rec['rid'], 'src_ip': rec['src'], 'dst_ip': rec['dst'],
                    'sport': rec['sport'], 'dport': rec['dport']})
        rows.append(row)
    meta['rows'] = len(rows)
    return rows, meta
