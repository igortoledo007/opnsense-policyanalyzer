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

    Suricata alerts collector (read only): /var/log/suricata/eve.json (and eve.json.0 after the weekly
    rotation), read from the end within a byte and time budget.  The file is mostly flow/tls/dns records, so
    a substring test for "event_type":"alert" runs before any JSON is decoded.
"""

import collections
import datetime
import ipaddress
import json
import os
import time

from ..common import clean_text
from .filterlog import reverse_lines

MAX_BYTES = 48 * 1024 * 1024
ALERT_MARK = '"event_type":"alert"'


def _epoch(stamp):
    try:
        value = str(stamp)
        if len(value) > 5 and value[-5] in '+-' and value[-3] != ':':
            value = value[:-2] + ':' + value[-2:]
        return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except ValueError:
        return None


def compact(event):
    alert = event.get('alert') or {}
    out = {
        'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_epoch(event.get('timestamp')) or 0)),
        'timestamp': event.get('timestamp'),
        # 64 bit: as text, JavaScript numbers lose digits above 2^53
        'flow_id': str(event.get('flow_id')) if event.get('flow_id') is not None else None,
        'interface': event.get('in_iface'),
        'src': '%s:%s' % (event.get('src_ip'), event.get('src_port')) if event.get('src_port') else event.get('src_ip'),
        'dst': '%s:%s' % (event.get('dest_ip'), event.get('dest_port')) if event.get('dest_port')
        else event.get('dest_ip'),
        'src_ip': event.get('src_ip'),
        'dst_ip': event.get('dest_ip'),
        'proto': event.get('proto'),
        'app_proto': event.get('app_proto'),
        'direction': event.get('direction'),
        'action': alert.get('action'),
        'gid': alert.get('gid'),
        'sid': alert.get('signature_id'),
        'rev': alert.get('rev'),
        'signature': clean_text(alert.get('signature'), 160),
        'classification': clean_text(alert.get('category'), 100),
        'severity': alert.get('severity'),
    }
    meta = alert.get('metadata') or {}
    for key in ('signature_severity', 'confidence', 'attack_target', 'deployment', 'affected_product'):
        if isinstance(meta.get(key), list) and meta[key]:
            out[key] = clean_text(', '.join(str(v) for v in meta[key][:3]), 80)
    http = event.get('http') or {}
    if http.get('hostname'):
        out['hostname'] = clean_text(http.get('hostname'), 80)
    tls = event.get('tls') or {}
    if tls.get('sni'):
        out['hostname'] = clean_text(tls.get('sni'), 80)
    return {k: v for k, v in out.items() if v not in (None, '')}


def read(paths, since, until, budget, severity_max=None, ip=None, sid=None, flow_id=None, limit=None,
         max_bytes=MAX_BYTES):
    target = None
    if ip:
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            target = None
    state = {'bytes': max_bytes, 'cut': False}
    alerts, lines, reached = [], 0, False
    files = [paths.eve, paths.eve + '.0']
    for name in files:
        if not os.path.exists(name):
            continue
        for line in reverse_lines(name, state):
            lines += 1
            if lines % 5000 == 0 and budget.expired():
                state['cut'] = True
                break
            if ALERT_MARK not in line and '"event_type": "alert"' not in line:
                # cheap time check on other records, to stop at the start of the window
                if lines % 200 == 0 and line.startswith('{"timestamp":"'):
                    ts = _epoch(line[14:46].split('"')[0])
                    if ts is not None and ts < since:
                        reached = True
                        break
                continue
            if target is not None and str(target) not in line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            ts = _epoch(event.get('timestamp'))
            if ts is None:
                continue
            if ts < since:
                reached = True
                break
            if ts > until + 60:
                continue
            alert = event.get('alert') or {}
            if severity_max and int(alert.get('severity') or 9) > severity_max:
                continue
            if sid and alert.get('signature_id') != sid:
                continue
            if flow_id and str(event.get('flow_id')) != str(flow_id):
                continue
            alerts.append(event)
            if limit and len(alerts) >= limit:
                reached = True
                break
        if reached or state['cut'] or state['bytes'] <= 0:
            break
    else:
        reached = True
    return alerts, {'source': 'suricata eve.json', 'lines_read': lines,
                    'complete': (reached or not state['cut']) and state['bytes'] > 0,
                    'available': os.path.exists(paths.eve)}


def summary(paths, window, budget, ip=None, severity_max=None, samples=6):
    alerts, meta = read(paths, window['since'], window['until'], budget, severity_max=severity_max, ip=ip)
    by_sev = collections.Counter()
    sigs = collections.Counter()
    sig_info = {}
    sources = collections.Counter()
    actions = collections.Counter()
    for event in alerts:
        alert = event.get('alert') or {}
        by_sev[str(alert.get('severity'))] += 1
        key = alert.get('signature_id')
        sigs[key] += 1
        sig_info[key] = (clean_text(alert.get('signature'), 120), alert.get('severity'),
                         clean_text(alert.get('category'), 80))
        sources[event.get('src_ip')] += 1
        actions[alert.get('action') or '?'] += 1
    data = dict(meta)
    data.update({
        'window': window['label'],
        'filters': {k: v for k, v in (('address', ip), ('max_severity', severity_max)) if v},
        'alerts': len(alerts),
        'by_severity': dict(by_sev),
        'by_action': dict(actions),
        'top_signatures': [{'sid': k, 'signature': sig_info[k][0], 'severity': sig_info[k][1],
                            'classification': sig_info[k][2], 'alerts': n} for k, n in sigs.most_common(6)],
        'top_sources': [{'address': k, 'alerts': n} for k, n in sources.most_common(6)],
        'sample_alerts': [compact(e) for e in alerts[:samples]],
    })
    if not meta['available']:
        data['message'] = 'Suricata (IDS) is not writing eve.json on this firewall'
    return data


def tail(paths, budget, severity_max=None, ip=None, limit=50, days=7, now=None):
    now = time.time() if now is None else now
    alerts, meta = read(paths, now - days * 86400, now, budget, severity_max=severity_max, ip=ip, limit=limit)
    rows = [compact(e) for e in alerts]
    meta['rows'] = len(rows)
    return rows, meta


def find(paths, budget, timestamp, flow_id, sid, now=None):
    """ one alert of the recent files, identified by its timestamp, flow id and signature id """
    now = time.time() if now is None else now
    ts = _epoch(timestamp)
    if ts is None:
        return None
    alerts, _meta = read(paths, ts - 1, ts + 1, budget, sid=sid, flow_id=flow_id, limit=1)
    return alerts[0] if alerts else None
