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

    Event sources of the quarantine, read forward from a position marker so that no event is lost or
    counted twice between runs (the marker is committed in the same SQLite transaction as the offenses).

      filter log   /var/log/filter/latest.log -> filter_YYYYMMDD.log (daily file, the symlink moves at
                   midnight: the rest of the previous file is read first, found by its inode)
      Suricata     /var/log/suricata/eve.json (EVE JSON, renamed to eve.json.0 at rotation: same inode),
                   only "event_type":"alert" lines are decoded

    Marker: {"dev", "ino", "offset"}; first run (no marker): start a few MiB before the end of the file.
    Only complete lines (ending with a newline) are consumed.
"""

import calendar
import glob
import json
import os
import re
import time

from . import common

# ------------------------------------------------------------------ incremental reader


def _stat(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st


def read_new(current, candidates, marker, max_bytes=common.MAX_READ, deadline=None,
             first_tail=common.FIRST_RUN_TAIL, prefilter=None):
    """
    :param current: path of the live file (may be a symlink)
    :param candidates: callable -> list of paths that may hold the previous (rotated) file
    :param marker: dict or None
    :param prefilter: bytes that a line must contain to be returned (cheap filter before decoding)
    :return: (lines [str], new marker, info {complete, bytes, files, first_run, missing})
    """
    info = {'complete': True, 'bytes': 0, 'files': [], 'first_run': not marker, 'missing': False}
    real = os.path.realpath(current)
    st = _stat(real)
    if st is None:
        info['missing'] = True
        return [], marker, info
    plan = []
    if marker and (marker.get('dev'), marker.get('ino')) != (st.st_dev, st.st_ino):
        for path in candidates():
            cst = _stat(path)
            if cst is not None and (cst.st_dev, cst.st_ino) == (marker.get('dev'), marker.get('ino')) and \
                    os.path.realpath(path) != real:
                plan.append((path, cst, int(marker.get('offset') or 0), False))
                break
        plan.append((real, st, 0, False))
    elif marker:
        offset = int(marker.get('offset') or 0)
        plan.append((real, st, offset if st.st_size >= offset else 0, False))
    else:
        plan.append((real, st, max(0, st.st_size - first_tail), st.st_size > first_tail))
    lines = []
    budget = max_bytes
    new_marker = marker
    for path, fst, offset, skip_partial in plan:
        try:
            handle = open(path, 'rb')
        except OSError:
            continue
        with handle:
            handle.seek(offset)
            pos = offset
            if skip_partial:
                junk = handle.readline()
                pos += len(junk)
            rest = b''
            while True:
                if budget <= 0 or (deadline is not None and time.monotonic() > deadline):
                    info['complete'] = False
                    break
                chunk = handle.read(min(1 << 20, budget))
                if not chunk:
                    break
                budget -= len(chunk)
                info['bytes'] += len(chunk)
                data = rest + chunk
                cut = data.rfind(b'\n')
                if cut < 0:
                    rest = data
                    continue
                body, rest = data[:cut + 1], data[cut + 1:]
                pos += len(body)
                for raw in body.split(b'\n'):
                    if raw and (prefilter is None or prefilter in raw):
                        lines.append(raw.decode('utf-8', 'replace'))
            info['files'].append(os.path.basename(path))
            new_marker = {'dev': fst.st_dev, 'ino': fst.st_ino, 'offset': pos}
        if not info['complete']:
            break
    return lines, new_marker, info


def filter_candidates(current):
    def find():
        directory = os.path.dirname(os.path.realpath(current))
        return sorted(glob.glob(os.path.join(directory, 'filter_*.log')), reverse=True)[:3]
    return find


def eve_candidates(current):
    def find():
        return [current + '.0', current + '.1']
    return find


# ------------------------------------------------------------------ filter log

_RFC5424_RE = re.compile(r'^<\d+>\d+\s+(\S+)\s+\S+\s+filterlog\b')
_RFC3164_RE = re.compile(r'^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+filterlog[^:]*:\s*(.*)$')
_TS_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')


def parse_ts(value):
    """ ISO 8601 with an optional zone (+hh:mm, +hhmm, Z) -> epoch; None when malformed """
    match = _TS_RE.match(value or '')
    if not match:
        return None
    y, mo, d, h, mi, s, tz = match.groups()
    epoch = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s), 0, 0, 0))
    if tz and tz != 'Z':
        sign = 1 if tz[0] == '+' else -1
        tz = tz[1:].replace(':', '')
        epoch -= sign * (int(tz[:2]) * 3600 + int(tz[2:]) * 60)
    elif not tz:
        epoch = time.mktime(time.strptime('%s-%s-%sT%s:%s:%s' % (y, mo, d, h, mi, s), '%Y-%m-%dT%H:%M:%S'))
    return epoch


def _ts3164(value, now):
    try:
        parsed = time.strptime('%d %s' % (time.localtime(now).tm_year, ' '.join(value.split())), '%Y %b %d %H:%M:%S')
    except ValueError:
        return None
    epoch = time.mktime(parsed)
    return epoch - 365 * 86400 if epoch > now + 86400 else epoch


def parse_filter_line(line, now=None):
    """
    one filterlog line -> {ts, rid, iface (device), action, dir, ipver, proto, src, dst, sport, dport, flags}
    or None (not a filterlog line / unknown layout)
    """
    line = line.strip()
    match = _RFC5424_RE.match(line)
    if match:
        ts = parse_ts(match.group(1))
        csv = line.rsplit(' ', 1)[-1]
    else:
        match = _RFC3164_RE.match(line)
        if not match:
            return None
        ts = _ts3164(match.group(1), now if now is not None else time.time())
        csv = match.group(2).strip()
    if ts is None:
        return None
    f = csv.split(',')
    if len(f) < 9:
        return None
    rec = {'ts': ts, 'rid': f[3], 'iface': f[4], 'action': f[6], 'dir': f[7], 'ipver': f[8], 'proto': '',
           'src': '', 'dst': '', 'sport': '', 'dport': '', 'flags': ''}
    if f[8] == '4' and len(f) >= 20:
        rec['proto'], rec['src'], rec['dst'] = f[16].lower(), f[18], f[19]
        rest = f[20:]
    elif f[8] == '6' and len(f) >= 17:
        rec['proto'], rec['src'], rec['dst'] = f[12].lower(), f[15], f[16]
        rest = f[17:]
    else:
        return None
    if rec['proto'] in ('tcp', 'udp') and len(rest) >= 2:
        rec['sport'], rec['dport'] = rest[0], rest[1]
        if rec['proto'] == 'tcp' and len(rest) >= 4:
            rec['flags'] = rest[3]
    return rec


def read_filter(ctx, marker, deadline=None, now=None):
    lines, new_marker, info = read_new(ctx.filter_log, filter_candidates(ctx.filter_log), marker,
                                       deadline=deadline, prefilter=b'filterlog')
    now = ctx.clock() if now is None else now
    records = []
    for line in lines:
        rec = parse_filter_line(line, now)
        if rec is not None:
            records.append(rec)
    info['lines'] = len(lines)
    info['records'] = len(records)
    return records, new_marker, info


# ------------------------------------------------------------------ Suricata EVE


def _eve_ts(value):
    """ "2026-11-01T01:15:01.671613-0300" -> epoch """
    if not isinstance(value, str):
        return None
    return parse_ts(re.sub(r'\.\d+', '', value, count=1))


def parse_eve_line(line):
    """ alert line -> {ts, src, dst, sport, dport, proto, sid, signature, severity, category, action} or None """
    try:
        doc = json.loads(line)
    except ValueError:
        return None
    if not isinstance(doc, dict) or doc.get('event_type') != 'alert' or not isinstance(doc.get('alert'), dict):
        return None
    alert = doc['alert']
    ts = _eve_ts(doc.get('timestamp'))
    if ts is None:
        return None
    try:
        severity = int(alert.get('severity'))
    except (TypeError, ValueError):
        return None
    return {'ts': ts, 'src': str(doc.get('src_ip') or ''), 'dst': str(doc.get('dest_ip') or ''),
            'sport': str(doc.get('src_port') or ''), 'dport': str(doc.get('dest_port') or ''),
            'proto': str(doc.get('proto') or '').lower(), 'sid': alert.get('signature_id'),
            'signature': str(alert.get('signature') or '')[:100], 'severity': severity,
            'category': str(alert.get('category') or '')[:60], 'action': str(alert.get('action') or ''),
            'iface': str(doc.get('in_iface') or '')}


def read_suricata(ctx, marker, deadline=None):
    lines, new_marker, info = read_new(ctx.eve, eve_candidates(ctx.eve), marker, deadline=deadline,
                                       prefilter=b'"event_type":"alert"')
    alerts = [a for a in (parse_eve_line(line) for line in lines) if a is not None]
    info['alerts'] = len(alerts)
    return alerts, new_marker, info
