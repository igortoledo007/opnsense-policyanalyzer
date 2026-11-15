#!/usr/local/bin/python3

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

    AI situational brief for the Max Cyber war room (read only).

        brief.py cached  [language] [focus ip|-]     read the stored brief (fast, never calls the AI)
        brief.py refresh [language] [focus ip|-]     start a background generation when the stored one is
                                                     older than 10 min (or missing), return the current state
        brief.py run     [language] [focus ip|-] [--lock-fd N]
                                                     the generation itself (the detached child of refresh)

    The model only sees aggregates, never log lines: pass/block totals of the last 15 min of the filter log,
    the top blocked sources and the top destination ports on the WAN, the posture of the exposure report and
    the Policy Analyzer finding counts.  They are anonymized by the Assistant like the finding explanations.
    With a focus address the aggregates are those of that one remote address (plus the general totals).

    Result files (JSON, 0640): /var/db/policyanalyzer/ai-brief.json (general) and ai-brief-focus.json (the
    last focus), {status: ok|running|error|disabled, generated_at, text, model, seconds, inputs, ...}.  One
    generation at a time (flock on ai-brief.lock, held by the detached child).  Nothing here changes the
    firewall: no rule, alias or table is touched, the answer is text.
"""

import calendar
import collections
import fcntl
import glob
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ''):
    # run as a script: import the "ai" package from its parent directory, not the modules next to us
    sys.path = [p for p in sys.path if os.path.abspath(p or '.') != _HERE]
    sys.path.insert(0, os.path.dirname(_HERE))

from ai import AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task  # noqa: E402

MOUNT = 'OPNsense/policyanalyzer'
DB_DIR = '/var/db/policyanalyzer'
CONFIG_XML = os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')
REPORT = os.environ.get('POLICYANALYZER_REPORT', DB_DIR + '/last.json')
EXPOSURE = os.environ.get('POLICYANALYZER_EXPOSURE', DB_DIR + '/exposure.json')
FILTER_LOG = os.environ.get('POLICYANALYZER_FILTERLOG', '/var/log/filter/latest.log')
BRIEF = os.environ.get('POLICYANALYZER_BRIEF', DB_DIR + '/ai-brief.json')
BRIEF_FOCUS = os.environ.get('POLICYANALYZER_BRIEF_FOCUS', DB_DIR + '/ai-brief-focus.json')
LOCK = os.environ.get('POLICYANALYZER_BRIEF_LOCK', DB_DIR + '/ai-brief.lock')
AUDIT_LOG = os.environ.get('POLICYANALYZER_AILOG', '/var/log/policyanalyzer/ai.log')

WINDOW_S = 15 * 60                # log window
MIN_AGE_OK = 600                  # a good brief is reused for 10 min
MIN_AGE_ERROR = 120               # a failed one may be retried after 2 min
STALE_RUNNING = 900               # "running" without the lock, or longer than this: interrupted
MAX_BYTES = 16 * 1024 * 1024      # log budget (read backwards from the end)
MAX_LINES = 200000
MAX_SECONDS = 8.0
TOP_N = 5
MAX_TEXT = 1200
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')
USAGE = 'usage: brief.py cached|refresh|run [language] [focus ip|-]'

BRIEF_INSTRUCTIONS = """You write the situational brief shown on the war-room screen of the firewall (OPNsense
Max Cyber). The DATA block holds aggregates only: the firewall log of the last minutes (pass/block totals, top
blocked sources, top destination ports on the WAN), the exposure report of the firewall's own services and the
Policy Analyzer finding counts.
Write at most 4 short sentences of plain text: no lists, no headings, no markdown. Cover, in this order:
the overall picture (how much is blocked and whether it looks like ordinary background scanning of the internet
or something focused); the most notable source or port, if one stands out; whether an internet reachable
service of the firewall is being targeted, and the exposure posture; at most one thing a human could look at
next, phrased as a suggestion (nothing is blocked or changed automatically).
Use the numbers of the data, keep guesses tentative ("likely"), and if the log window has no events say so."""

FOCUS_INSTRUCTIONS = """You write a short note for the war-room screen of the firewall (OPNsense Max Cyber)
about ONE remote address chosen by the administrator. The DATA block holds aggregates only: what this address
did in the firewall log of the last minutes (counts by action and direction, destination ports, interfaces,
seconds since first and last seen), whether it touched an internet reachable service of the firewall, and the
general totals of the same window for context.
Write at most 4 short sentences of plain text: no lists, no headings, no markdown. Say what the address did,
what it most likely is (for example a port scan, a brute force attempt on one service, or ordinary traffic;
keep it tentative), whether it reached an exposed service, and what a human could check next. Never say that
it was or will be blocked or quarantined: nothing is changed automatically."""


# ---------------------------------------------------------------------------------------------- helpers

def emit(data):
    sys.stdout.write(json.dumps(data, ensure_ascii=False) + '\n')
    sys.stdout.flush()


def iso(epoch):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(epoch))


def parse_iso(value):
    """ "2026-11-08T03:10:51Z" (what we write) -> epoch, None when absent or malformed """
    try:
        return calendar.timegm(time.strptime(str(value), '%Y-%m-%dT%H:%M:%SZ'))
    except (TypeError, ValueError):
        return None


def load_json(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_json(path, data):
    """ atomic replace, 0640 (the directory belongs to root:wheel) """
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, mode=0o750, exist_ok=True)
    tmp = '%s.%d.tmp' % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def valid_focus(value):
    """ :return: normalized address or None ("-" and "" mean no focus); ValueError when invalid """
    if value in (None, '', '-'):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValueError('invalid focus address')


def ai_enabled(config_path=None):
    config = AIConfig.from_opnsense(MOUNT, path=config_path or CONFIG_XML)
    return config.enabled, config


# ---------------------------------------------------------------------------------------------- filter log

# https://github.com/opnsense/ports/blob/master/opnsense/filterlog/files/description.txt (as read_log.py)
_GENERAL = 9          # rulenr,subrulenr,anchorname,rid,interface,reason,action,dir,ipversion
_RFC5424_RE = re.compile(r'^<\d+>\d+\s+(\S+)\s+\S+\s+filterlog\b')
_RFC3164_RE = re.compile(r'^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+filterlog[^:]*:\s*(.*)$')
_TS_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')


def _ts5424(value):
    match = _TS_RE.match(value)
    if not match:
        return None
    y, mo, d, h, mi, s, tz = match.groups()
    epoch = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s), 0, 0, 0))
    if tz and tz != 'Z':
        sign = 1 if tz[0] == '+' else -1
        tz = tz[1:].replace(':', '')
        epoch -= sign * (int(tz[:2]) * 3600 + int(tz[2:]) * 60)
    return epoch


def _ts3164(value, now):
    try:
        parsed = time.strptime('%d %s' % (time.localtime(now).tm_year, ' '.join(value.split())), '%Y %b %d %H:%M:%S')
    except ValueError:
        return None
    epoch = time.mktime(parsed)
    return epoch - 365 * 86400 if epoch > now + 86400 else epoch      # December lines read in January


def parse_line(line, now=None):
    """
    one filterlog line -> {ts, iface, action, dir, ipver, proto, src, dst, sport, dport} or None
    (not a filterlog line, or a layout we do not know)
    """
    line = line.strip()
    match = _RFC5424_RE.match(line)
    if match:
        ts = _ts5424(match.group(1))
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
    if len(f) < _GENERAL:
        return None
    rec = {'ts': ts, 'iface': f[4], 'action': f[6], 'dir': f[7], 'ipver': f[8], 'proto': '', 'src': '', 'dst': '',
           'sport': '', 'dport': ''}
    if f[8] == '4' and len(f) >= 20:
        # tos,ecn,ttl,id,offset,ipflags,protonum,protoname,length,src,dst[,srcport,dstport]
        rec['proto'], rec['src'], rec['dst'] = f[16].lower(), f[18], f[19]
        ports = f[20:22]
    elif f[8] == '6' and len(f) >= 17:
        # class,flow,hoplimit,protoname,protonum,length,src,dst[,srcport,dstport]
        rec['proto'], rec['src'], rec['dst'] = f[12].lower(), f[15], f[16]
        ports = f[17:19]
    else:
        return rec if rec['action'] in ('pass', 'block') else None
    if rec['proto'] in ('tcp', 'udp') and len(ports) == 2:
        rec['sport'], rec['dport'] = ports[0], ports[1]
    return rec


def _reverse_lines(path, budget):
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
            size = min(65536, pos, budget['bytes'])
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


def log_files(path):
    """ latest.log first, then the rotated file before it (the window may cross midnight) """
    files = [path]
    try:
        target = os.path.realpath(path)
        rotated = sorted(glob.glob(os.path.join(os.path.dirname(target), 'filter_*.log')))
        if target in rotated:
            idx = rotated.index(target)
            if idx > 0:
                files.append(rotated[idx - 1])
    except OSError:
        pass
    return files


def read_window(path=None, now=None, window=WINDOW_S, max_bytes=MAX_BYTES, max_lines=MAX_LINES,
                max_seconds=MAX_SECONDS):
    """
    :return: (records newer than now - window, meta) reading backwards within the budgets;
             meta = {lines, complete, source}
    """
    now = time.time() if now is None else now
    cutoff = now - window
    started = time.monotonic()
    budget = {'bytes': max_bytes, 'cut': False}
    records, lines, reached = [], 0, False
    for name in log_files(path or FILTER_LOG):
        for line in _reverse_lines(name, budget):
            lines += 1
            rec = parse_line(line, now)
            if rec is not None:
                if rec['ts'] < cutoff:
                    reached = True
                    break
                if rec['ts'] <= now + 120:
                    records.append(rec)
            if lines >= max_lines or (lines % 2000 == 0 and time.monotonic() - started > max_seconds):
                budget['cut'] = True
                break
        if reached or budget['cut'] or budget['bytes'] <= 0:
            break
    return records, {'lines_read': lines, 'complete': reached or not budget['cut'], 'source': 'filter log'}


def wan_interfaces(config_path=None):
    """ device names of the WAN side: the "wan" interface and every interface with a gateway or a dynamic uplink """
    try:
        root = ET.parse(config_path or CONFIG_XML).getroot()
    except (OSError, ET.ParseError):
        return set()
    result = set()
    for node in root.findall('./interfaces/*'):
        dev = (node.findtext('if') or '').strip()
        if not dev:
            continue
        ipaddr = (node.findtext('ipaddr') or '').strip()
        gateway = (node.findtext('gateway') or '').strip() or (node.findtext('gatewayv6') or '').strip()
        if node.tag == 'wan' or gateway or ipaddr in ('dhcp', 'pppoe', 'pptp', 'l2tp'):
            result.add(dev)
    return result


def _port_key(rec):
    return '%s/%s' % (rec['dport'], rec['proto']) if rec['dport'] else rec['proto'] or '?'


def aggregate(records, wan, now, window=WINDOW_S, focus=None):
    """ the numbers sent to the model (no log lines, no own addresses) """
    totals = collections.Counter()
    blocked_src = collections.Counter()
    src_ports = collections.defaultdict(collections.Counter)
    wan_ports = collections.defaultdict(collections.Counter)
    inbound_wan = 0
    for rec in records:
        action = rec['action'] if rec['action'] in ('pass', 'block') else 'other'
        totals[action] += 1
        on_wan = rec['dir'] == 'in' and (rec['iface'] in wan if wan else True)
        if not on_wan:
            continue
        inbound_wan += 1
        wan_ports[_port_key(rec)][action] += 1
        if action == 'block' and rec['src']:
            blocked_src[rec['src']] += 1
            src_ports[rec['src']][_port_key(rec)] += 1
    top_sources = []
    for ip, count in blocked_src.most_common(TOP_N):
        ports = src_ports[ip]
        top_sources.append({'ip': ip, 'blocked': count, 'distinct_ports': len(ports),
                            'ports': [k for k, _ in ports.most_common(3)]})
    ranked = sorted(wan_ports.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    top_ports = [{'port': k, 'blocked': v['block'], 'passed': v['pass']} for k, v in ranked[:TOP_N]]
    data = {
        'window_minutes': int(window // 60),
        'events': sum(totals.values()),
        'pass': totals['pass'],
        'block': totals['block'],
        'other': totals['other'],
        'inbound_on_wan': inbound_wan,
        'distinct_blocked_sources': len(blocked_src),
        'top_blocked_sources': top_sources,
        'top_wan_ports': top_ports,
    }
    if focus:
        data['focus'] = focus_aggregate(records, focus, wan, now)
    return data, {k: dict(v) for k, v in wan_ports.items()}


def focus_aggregate(records, focus, wan, now):
    mine = [r for r in records if focus in (r['src'], r['dst'])]
    actions = collections.Counter()
    ports = collections.Counter()
    ifaces = collections.Counter()
    for rec in mine:
        direction = 'inbound' if rec['src'] == focus else 'outbound'
        actions['%s_%s' % (direction, rec['action'] if rec['action'] in ('pass', 'block') else 'other')] += 1
        ports[_port_key(rec)] += 1
        ifaces['%s%s' % (rec['iface'], ' (wan)' if rec['iface'] in wan else '')] += 1
    result = {'address': focus, 'events': len(mine), 'by_action': dict(actions),
              'distinct_ports': len(ports), 'top_ports': [{'port': k, 'events': v} for k, v in ports.most_common(TOP_N)],
              'interfaces': [k for k, _ in ifaces.most_common(3)]}
    if mine:
        result['first_seen_seconds_ago'] = max(0, int(now - min(r['ts'] for r in mine)))
        result['last_seen_seconds_ago'] = max(0, int(now - max(r['ts'] for r in mine)))
    return result


# ---------------------------------------------------------------------------------------------- reports

def exposure_inputs(report, wan_ports=None):
    """ posture + reachable services of the exposure report; crossed with the WAN ports of the window """
    if not report or not isinstance(report.get('summary'), dict):
        return {'available': False}
    sm = report['summary']
    keep = ('posture', 'posture_confidence', 'services', 'reachable', 'maybe_reachable', 'admin_reachable',
            'vulnerable_packages', 'cves_total', 'kev', 'findings', 'by_severity')
    data = {'available': True, 'report_age_minutes': None}
    data.update({k: sm[k] for k in keep if k in sm})
    generated = report.get('generated')
    if isinstance(generated, str):
        ts = _ts5424(generated.replace('+00:00', 'Z'))
        if ts is not None:
            data['report_age_minutes'] = max(0, int((time.time() - ts) // 60))
    surface = []
    for sv in sm.get('attack_surface') or report.get('services') or []:
        if not isinstance(sv, dict) or sv.get('internet_reachable') not in ('yes', 'maybe'):
            continue
        surface.append({'service': str(sv.get('label') or sv.get('service') or '?'), 'port': sv.get('port'),
                        'proto': sv.get('proto'), 'internet_reachable': sv.get('internet_reachable'),
                        'admin': bool(sv.get('admin')), 'cves': sv.get('cves', 0), 'kev': sv.get('kev', 0)})
    data['internet_reachable_services'] = surface[:8]
    if wan_ports is not None:
        targeted = []
        for sv in surface:
            key = '%s/%s' % (sv['port'], str(sv['proto'] or '').lower())
            hits = wan_ports.get(key)
            if hits:
                targeted.append({'service': sv['service'], 'port': key, 'attempts': sum(hits.values()),
                                 'blocked': hits.get('block', 0), 'passed': hits.get('pass', 0)})
        data['reachable_services_targeted'] = targeted
    return data


def findings_inputs(report):
    if not report or not isinstance(report.get('summary'), dict):
        return {'available': False}
    sm = report['summary']
    return {'available': True, 'rules': sm.get('rules'), 'findings': sm.get('findings'),
            'by_severity': sm.get('by_severity') or {}}


def build_inputs(now=None, focus=None, log_path=None, config_path=None, report_path=None, exposure_path=None):
    now = time.time() if now is None else now
    wan = wan_interfaces(config_path)
    records, meta = read_window(log_path, now)
    log, wan_ports = aggregate(records, wan, now, focus=focus)
    log.update(meta)
    log['wan_interfaces'] = sorted(wan)
    return {
        'firewall_log': log,
        'exposure': exposure_inputs(load_json(exposure_path or EXPOSURE), wan_ports),
        'policy_analyzer': findings_inputs(load_json(report_path or REPORT)),
    }


# ---------------------------------------------------------------------------------------------- state

class Lock:
    """ non-blocking flock on the brief lock file; the fd may be handed to the detached child """

    def __init__(self, path=None, fd=None):
        self.path = path or LOCK
        self.fd = fd

    def acquire(self):
        if self.fd is None:
            os.makedirs(os.path.dirname(self.path) or '.', mode=0o750, exist_ok=True)
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            os.close(self.fd)
            self.fd = None
            return False

    def release(self):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None

    def held_elsewhere(self):
        probe = Lock(self.path)
        if probe.acquire():
            probe.release()
            return False
        return True


def brief_path(focus):
    return BRIEF_FOCUS if focus else BRIEF


def current(focus, now, lock):
    """ the stored record as the API returns it: age, refresh hint, interrupted runs detected """
    rec = load_json(brief_path(focus))
    if rec is None or (focus and rec.get('focus') != focus):
        rec = {'status': 'none', 'focus': focus, 'message': 'no brief generated yet'}
    rec = dict(rec)
    if rec.get('status') == 'running':
        started = parse_iso(rec.get('started_at')) or 0
        if not lock.held_elsewhere() or now - started > STALE_RUNNING:
            rec['status'] = 'error'
            rec['message'] = 'the last generation was interrupted'
    generated = parse_iso(rec.get('generated_at'))
    rec['age_seconds'] = int(max(0, now - generated)) if generated else None
    rec['refresh_interval'] = MIN_AGE_OK
    rec['window_minutes'] = WINDOW_S // 60
    return rec


def is_fresh(rec, now):
    status = rec.get('status')
    if status not in ('ok', 'error'):
        return False
    ref = parse_iso(rec.get('generated_at') if status == 'ok' else (rec.get('failed_at') or rec.get('generated_at')))
    if ref is None:
        return False
    return now - ref < (MIN_AGE_OK if status == 'ok' else MIN_AGE_ERROR)


def spawn_worker(language, focus, lock_fd):
    """ detached child that inherits the locked fd (the lock stays held until it exits) """
    cmd = [sys.executable, os.path.abspath(__file__), 'run', language or 'en_US', focus or '-', '--lock-fd', str(lock_fd)]
    subprocess.Popen(cmd, pass_fds=(lock_fd,), start_new_session=True, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------------------------------------- commands

def cmd_cached(language, focus, now=None, config_path=None):
    now = time.time() if now is None else now
    enabled, config = ai_enabled(config_path)
    if not enabled:
        return {'status': 'disabled', 'focus': focus, 'message': 'AI assistance is disabled in the settings'}
    rec = current(focus, now, Lock())
    rec.setdefault('model', config.options.get('model'))
    return rec


def cmd_refresh(language, focus, now=None, config_path=None, spawn=None):
    now = time.time() if now is None else now
    enabled, config = ai_enabled(config_path)
    if not enabled:
        return {'status': 'disabled', 'focus': focus, 'message': 'AI assistance is disabled in the settings'}
    lock = Lock()
    if not lock.acquire():
        rec = current(focus, now, lock)
        if rec.get('status') != 'running':
            rec['busy'] = True          # another brief (general or focus) is being generated
        return rec
    try:
        rec = current(focus, now, lock)
        if is_fresh(rec, now):
            rec['throttled'] = True
            lock.release()
            return rec
        running = {
            'version': 1, 'kind': 'brief', 'status': 'running', 'focus': focus, 'started_at': iso(now),
            'language': language, 'model': config.options.get('model'), 'provider': config.provider,
            # the previous answer stays visible while the new one is generated
            'text': rec.get('text') if rec.get('status') in ('ok', 'running', 'error') else None,
            'generated_at': rec.get('generated_at'), 'inputs': rec.get('inputs'),
        }
        write_json(brief_path(focus), running)
        (spawn or spawn_worker)(language, focus, lock.fd)
    except Exception as exc:                        # noqa: BLE001
        failed = {'version': 1, 'kind': 'brief', 'status': 'error', 'focus': focus, 'failed_at': iso(now),
                  'message': 'cannot start the generation: %s' % exc}
        try:
            write_json(brief_path(focus), failed)
        except OSError:
            pass
        lock.release()
        return failed
    # the child holds the lock from now on (same open file description); closing our copy keeps it held
    os.close(lock.fd)
    lock.fd = None
    out = current(focus, now, Lock())
    out['status'] = 'running'
    return out


def clean_text(text):
    text = re.sub(r'[*_`#]{1,3}', '', str(text or '')).strip()
    text = re.sub(r'\s*\n\s*', ' ', text)
    text = re.sub(r'\s{2,}', ' ', text)
    if len(text) > MAX_TEXT:
        cut = text[:MAX_TEXT]
        text = cut[:cut.rfind('. ') + 1] if '. ' in cut else cut.rstrip() + '…'
    return text


def generate(language, focus, now=None, assistant=None, inputs=None):
    """ :return: the record to store (ok, error or disabled) """
    now = time.time() if now is None else now
    if assistant is None:
        config = AIConfig.from_opnsense(MOUNT, path=CONFIG_XML)
        # this already runs in the detached child: never queued, the route of the scenario still applies
        assistant = Assistant(config, app='policyanalyzer', audit=AuditLog(AUDIT_LOG), inline=True)
    base = {'version': 1, 'kind': 'brief', 'focus': focus, 'language': language,
            'provider': assistant.config.provider, 'model': assistant.config.options.get('model')}
    started = time.monotonic()
    try:
        if inputs is None:
            inputs = build_inputs(now, focus)
        if focus:
            task = Task('war_room_focus', FOCUS_INSTRUCTIONS, 'Write the note about the focus address.')
        else:
            task = Task('war_room_brief', BRIEF_INSTRUCTIONS, 'Write the situational brief.')
        # the whole generation (both routes) fits before the record looks interrupted (STALE_RUNNING)
        result = assistant.ask(task, inputs, language=language, subject='brief:%s' % (focus or 'general'),
                               max_seconds=STALE_RUNNING - 60)
    except AIDisabled as exc:
        return dict(base, status='disabled', message=str(exc))
    except (ProviderRefusal, ProviderError) as exc:
        return dict(base, status='error', failed_at=iso(time.time()), message=str(exc), inputs=inputs,
                    seconds=round(time.monotonic() - started, 1))
    except Exception as exc:                        # noqa: BLE001
        return dict(base, status='error', failed_at=iso(time.time()), message='brief failed: %s' % exc,
                    inputs=inputs, seconds=round(time.monotonic() - started, 1))
    return dict(base, status='ok', generated_at=iso(time.time()), text=clean_text(result.get('text')),
                model=result.get('model') or base['model'], provider=result.get('provider') or base['provider'],
                fallback=result.get('fallback') or None, seconds=round(time.monotonic() - started, 1),
                anonymized=result.get('anonymized'), truncated=result.get('truncated'), inputs=inputs)


def cmd_run(language, focus, lock_fd=None, assistant=None, inputs=None):
    lock = Lock(fd=lock_fd) if lock_fd is not None else Lock()
    if lock_fd is None and not lock.acquire():
        return {'status': 'running', 'message': 'another brief is being generated'}
    try:
        rec = generate(language, focus, assistant=assistant, inputs=inputs)
        if rec.get('status') == 'error':
            # keep the last good text visible next to the error
            prev = load_json(brief_path(focus)) or {}
            if prev.get('text') and (not focus or prev.get('focus') == focus):
                rec.setdefault('text', prev.get('text'))
                rec.setdefault('generated_at', prev.get('generated_at'))
        write_json(brief_path(focus), rec)
        return rec
    finally:
        lock.release()


def main(argv):
    args = list(argv[1:])
    lock_fd = None
    if '--lock-fd' in args:
        idx = args.index('--lock-fd')
        try:
            lock_fd = int(args[idx + 1])
        except (IndexError, ValueError):
            emit({'status': 'error', 'message': USAGE})
            return 1
        del args[idx:idx + 2]
    if not args or args[0] not in ('cached', 'refresh', 'run'):
        emit({'status': 'error', 'message': USAGE})
        return 1
    language = args[1] if len(args) > 1 and LANG_RE.match(args[1]) else 'en_US'
    try:
        focus = valid_focus(args[2] if len(args) > 2 else None)
    except ValueError as exc:
        emit({'status': 'error', 'message': str(exc)})
        return 1
    if args[0] == 'cached':
        emit(cmd_cached(language, focus))
    elif args[0] == 'refresh':
        emit(cmd_refresh(language, focus))
    else:
        rec = cmd_run(language, focus, lock_fd=lock_fd)
        emit({'status': rec.get('status'), 'message': rec.get('message')})
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
