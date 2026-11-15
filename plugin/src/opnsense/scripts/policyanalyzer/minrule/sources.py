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

    Traffic really matched by one rule, read only.

    1. Filter log (exact): the daily files /var/log/filter/filter_YYYYMMDD.log of the window. pf logs the first
       packet of every connection a logging pass rule creates, labelled with the rule (MVC: its uuid). The files
       are scanned with bytes.find() for ",<label>," (a few hundred MB per second), only matching lines are
       split. CSV layout of OPNsense's filterlog (IPv4 / IPv6):
         rulenr,subrulenr,anchor,label,interface,reason,action,dir,4,tos,ecn,ttl,id,offset,flags,protonum,
             protoname,length,src,dst[,srcport,dstport,datalen...]
         rulenr,subrulenr,anchor,label,interface,reason,action,dir,6,class,flowlabel,hoplimit,protoname,
             protonum,length,src,dst[,srcport,dstport,datalen...]
    2. NetFlow (approximate, for rules that do not log): /var/log/flowd.log* through the core's FlowParser,
       flows that entered on the rule's interface and fall inside the rule's match space and are not decided
       earlier by a quick rule that certainly matches them (see analyze.py). Tests use a JSON lines file.
"""

import glob
import json
import os
import re
import sys
import time

HEADER_RE = re.compile(rb'^<\d+>1 (\S+) \S+ filterlog \S+ \S+ (?:\[[^\]]*\] )?(.*)$')
CHUNK = 8 << 20


class Budget:
    def __init__(self, seconds):
        self.started = time.monotonic()
        self.deadline = self.started + seconds

    def expired(self):
        return time.monotonic() > self.deadline


def _ts(text):
    """ 2026-11-08T04:52:51-03:00 -> epoch """
    import calendar
    try:
        base = text[:19]
        epoch = calendar.timegm(time.strptime(base, '%Y-%m-%dT%H:%M:%S'))
        tz = text[19:]
        match = re.match(r'^(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})$', tz)
        if match and match.group(1) != 'Z':
            sign = 1 if match.group(1)[0] == '+' else -1
            digits = match.group(1)[1:].replace(':', '')
            epoch -= sign * (int(digits[:2]) * 3600 + int(digits[2:]) * 60)
        return epoch
    except (ValueError, TypeError):
        return None


def parse_line(line):
    """ :return: dict of one filterlog line or None """
    match = HEADER_RE.match(line)
    if not match:
        return None
    ts = _ts(match.group(1).decode('ascii', 'replace'))
    f = match.group(2).decode('utf-8', 'replace').split(',')
    if len(f) < 10:
        return None
    rec = {'time': ts, 'label': f[3], 'device': f[4], 'action': f[6], 'dir': f[7], 'ipver': f[8]}
    try:
        if f[8] == '4' and len(f) >= 20:
            rec.update(proto=f[16].lower(), protonum=f[15], src=f[18], dst=f[19])
            ports = f[20:22]
        elif f[8] == '6' and len(f) >= 17:
            rec.update(proto=f[12].lower(), protonum=f[13], src=f[15], dst=f[16])
            ports = f[17:19]
        else:
            return None
    except IndexError:
        return None
    if rec['proto'] in ('tcp', 'udp') and len(ports) == 2 and ports[0].isdigit() and ports[1].isdigit():
        rec['sport'], rec['dport'] = int(ports[0]), int(ports[1])
    else:
        rec['sport'] = rec['dport'] = None
    return rec


def log_files(directory, since, until):
    """ daily files that may hold [since, until) (plus latest.log when no daily file exists) """
    files = []
    for path in sorted(glob.glob(os.path.join(directory, 'filter_*.log'))):
        match = re.search(r'filter_(\d{8})\.log$', path)
        if not match:
            continue
        try:
            day = time.mktime(time.strptime(match.group(1), '%Y%m%d'))
        except ValueError:
            continue
        if day + 86400 >= since and day <= until:
            files.append(path)
    if not files and os.path.exists(os.path.join(directory, 'latest.log')):
        files.append(os.path.join(directory, 'latest.log'))
    return files


def scan_label(directory, label, since, until, budget, max_bytes=1 << 30):
    """
    :return: (records, meta) records of the lines labelled with this rule in [since, until)
    """
    needle = (',%s,' % label).encode('ascii')
    records = []
    meta = {'source': 'filterlog', 'files': [], 'bytes': 0, 'lines': 0, 'complete': True, 'first': None,
            'last': None}
    for path in log_files(directory, since, until):
        meta['files'].append(os.path.basename(path))
        try:
            handle = open(path, 'rb')
        except OSError:
            continue
        with handle:
            rest = b''
            while True:
                if budget.expired() or meta['bytes'] >= max_bytes:
                    meta['complete'] = False
                    break
                data = handle.read(CHUNK)
                if not data:
                    break
                meta['bytes'] += len(data)
                block = rest + data
                cut = block.rfind(b'\n')
                if cut < 0:
                    rest = block
                    continue
                rest = block[cut + 1:]
                block = block[:cut]
                pos = block.find(needle)
                while pos >= 0:
                    start = block.rfind(b'\n', 0, pos) + 1
                    end = block.find(b'\n', pos)
                    end = len(block) if end < 0 else end
                    rec = parse_line(block[start:end])
                    pos = block.find(needle, end)
                    if rec is None or rec['label'] != label or rec['time'] is None:
                        continue
                    if not since <= rec['time'] < until:
                        continue
                    meta['lines'] += 1
                    records.append(rec)
            if rest and needle in rest:
                rec = parse_line(rest)
                if rec and rec['label'] == label and rec['time'] is not None and since <= rec['time'] < until:
                    records.append(rec)
        if not meta['complete']:
            break
    if records:
        meta['first'] = min(r['time'] for r in records)
        meta['last'] = max(r['time'] for r in records)
    return records, meta


def flows(paths, since, until, budget, max_records=2000000):
    """
    :return: (iterator of flow dicts {time, src, dst, sport, dport, proto, ifin, octets, packets}, meta)
    """
    meta = {'source': 'netflow', 'files': [], 'records': 0, 'complete': True, 'first': None, 'last': None}
    path = paths.flowd_log
    if path.endswith('.jsonl'):
        def gen_jsonl():
            with open(path) as handle:
                for line in handle:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if since <= rec.get('time', 0) < until:
                        meta['records'] += 1
                        yield rec
        meta['files'].append(os.path.basename(path))
        return gen_jsonl(), meta
    if paths.netflow_lib not in sys.path:
        sys.path.append(paths.netflow_lib)
    try:
        from flowparser import FlowParser  # noqa: E402 - only on the firewall
    except ImportError as exc:
        meta['message'] = 'NetFlow parser not available: %s' % exc
        meta['complete'] = False
        return iter(()), meta
    files = sorted(glob.glob(path + '.*'), reverse=True) + [path]
    files = [f for f in files if os.path.exists(f) and os.path.getmtime(f) >= since]
    meta['files'] = [os.path.basename(f) for f in files]
    protos = {1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp', 41: 'ipv6', 47: 'gre', 50: 'esp', 58: 'ipv6-icmp',
              89: 'ospf', 112: 'carp', 132: 'sctp'}

    def gen():
        for name in files:
            try:
                for rec in FlowParser(name, since):
                    if budget.expired() or meta['records'] >= max_records:
                        meta['complete'] = False
                        return
                    end = rec.get('flow_end') or rec.get('recv_sec')
                    if end is None or end >= until:
                        continue
                    meta['records'] += 1
                    yield {'time': int(rec.get('flow_start') or end), 'src': rec.get('src_addr'),
                           'dst': rec.get('dst_addr'), 'sport': rec.get('src_port'), 'dport': rec.get('dst_port'),
                           'proto': protos.get(rec.get('protocol'), str(rec.get('protocol'))),
                           'ifin': rec.get('if_ndx_in'), 'octets': rec.get('octets', 0),
                           'packets': rec.get('packets', 0)}
            except (OSError, ValueError):
                continue
    return gen(), meta


def interface_indexes(paths):
    """ ifindex -> device name (socket.if_nameindex), tests: <flowd jsonl>.ifindex.json """
    if paths.flowd_log.endswith('.jsonl'):
        try:
            with open(paths.flowd_log[:-len('.jsonl')] + '.ifindex.json') as handle:
                return {int(k): v for k, v in json.load(handle).items()}
        except (OSError, ValueError):
            return {}
    try:
        import socket
        return {idx: name for idx, name in socket.if_nameindex()}
    except (OSError, AttributeError):
        return {}
