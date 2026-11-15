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

    Quarantine engine.

    run (cron, every 5 min, at most `budget` seconds, one at a time by flock):
      1. read the filter log and the Suricata alerts since the position markers;
      2. remember allowed inbound connections to a WireGuard port (24 h guard);
      3. per external source address (guards first, then the scenarios):
           base      >= 1 blocked inbound connection on a WAN interface        level >= 1 (30 min)
           scan      >= scan_ports distinct destination ports in scan_window s  level >= 2 (2 h)
           bait      a blocked connection to a bait port                        level >= 2 (2 h)
           suricata  alert with severity <= suricata_severity, source external  level >= 3 (2 days)
         level = max(scenario minimum, previous level + 1) for a repeat offense (a new offense after the
         previous quarantine ended); back to 1 after reset_days without offenses; 5 (30 days) is the top.
         Events while a quarantine is in force are hits, not offenses (a stronger scenario upgrades it);
      4. expire, release entries that became protected, and make the pf table equal to the ledger.
    The markers are committed with the offenses (no event lost or counted twice).
"""

import collections
import csv
import fcntl
import io
import ipaddress
import os
import subprocess
import sys
import time

from . import common, fwconfig, guards as guards_mod, lookup as lookup_mod, pf, sources, store as store_mod

REASON_ORDER = ('suricata', 'scan', 'bait', 'base')


# ------------------------------------------------------------------ pure decisions (unit tested)


def counts_as_connection(rec, syn_only):
    """ a blocked packet that is a connection attempt (TCP SYN without ACK when syn_only) """
    if rec.get('proto') != 'tcp' or not syn_only:
        return True
    flags = rec.get('flags') or ''
    if not flags:
        return True
    return 'S' in flags and 'A' not in flags


def max_distinct_ports(events, window):
    """ largest number of distinct destination ports seen within any `window` seconds """
    items = sorted((e['ts'], '%s/%s' % (e['dport'], e['proto'])) for e in events if e.get('dport'))
    best, left = 0, 0
    counter = collections.Counter()
    for right, (ts, port) in enumerate(items):
        counter[port] += 1
        while items[left][0] < ts - window:
            old = items[left][1]
            counter[old] -= 1
            if not counter[old]:
                del counter[old]
            left += 1
        best = max(best, len(counter))
    return best


def detect(blocks, alerts, settings):
    """
    :param blocks: blocked inbound WAN records of one source (already filtered: not covered, connections)
    :param alerts: Suricata alerts of the same source (already filtered by severity)
    :return: None or {"reasons": [...], "primary", "min_level", "events", "ports", "detail", "iface", "ts"}
    """
    reasons = []
    detail = None
    if alerts:
        reasons.append('suricata')
        first = sorted(alerts, key=lambda a: a['ts'])[0]
        detail = 'sid %s sev %s: %s' % (first.get('sid'), first.get('severity'), first.get('signature'))
    if blocks:
        distinct = max_distinct_ports(blocks, settings['scan_window'])
        if distinct >= settings['scan_ports']:
            reasons.append('scan')
            detail = detail or '%d ports in %d s' % (distinct, settings['scan_window'])
        bait = sorted({int(b['dport']) for b in blocks if b.get('dport', '').isdigit() and
                       int(b['dport']) in settings['bait_ports_list']})
        if bait:
            reasons.append('bait')
            detail = detail or 'bait port %s' % ','.join(str(p) for p in bait[:5])
        reasons.append('base')
    if not reasons:
        return None
    primary = next(r for r in REASON_ORDER if r in reasons)
    ports = collections.Counter('%s/%s' % (b['dport'], b['proto']) if b.get('dport') else b.get('proto') or '?'
                                for b in blocks)
    for a in alerts:
        ports['%s/%s' % (a.get('dport'), a.get('proto'))] += 0
    ifaces = collections.Counter(b.get('iface') for b in blocks if b.get('iface'))
    times = [b['ts'] for b in blocks] + [a['ts'] for a in alerts]
    return {'reasons': [r for r in REASON_ORDER if r in reasons], 'primary': primary,
            'min_level': max(common.MIN_LEVEL[r] for r in reasons), 'events': len(blocks) + len(alerts),
            'ports': ','.join(p for p, _n in ports.most_common(8)), 'distinct_ports': len(ports),
            'detail': detail, 'iface': ifaces.most_common(1)[0][0] if ifaces else None, 'ts': min(times)}


def next_level(entry, t0, settings, scenario_min):
    """ level of a new offense at t0 for an entry (None: first offense) """
    prev = int(entry.get('level') or 0) if entry else 0
    if prev >= common.PERMANENT:
        return common.PERMANENT
    last = entry.get('last_offense') if entry else None
    if prev and last is not None and t0 - last > settings['reset_days'] * 86400:
        prev = 0
    base = min(prev + 1, 5) if prev else 1
    return max(base, int(scenario_min))


def covers(entry, ts):
    """ was the quarantine of the entry in force at ts """
    if entry['state'] == 'permanent':
        return True
    start = entry.get('last_offense') if entry.get('last_offense') is not None else entry.get('since')
    return entry.get('until') is not None and start is not None and start <= ts < entry['until']


def next_run(now, minutes=5):
    return (int(now) // (minutes * 60) + 1) * minutes * 60


# ------------------------------------------------------------------ helpers


class Coverage:
    """ entries in force during the window: by address and by network (net/asn entries) """

    def __init__(self, entries, store):
        self.by_addr = {}
        self.nets = common.IntervalSet()
        self.by_id = {}
        for e in entries:
            self.by_id[e['id']] = e
            if e['kind'] == 'ip':
                self.by_addr[e['addr']] = e
            elif e['kind'] == 'net':
                self.nets.add(e['addr'], e['id'])
            else:
                for prefix in store.asn_prefixes(e['id']):
                    self.nets.add(prefix, e['id'])

    def find(self, ip_text, ip):
        entry = self.by_addr.get(ip_text)
        if entry is not None:
            return entry
        entry_id = self.nets.lookup(ip) if len(self.nets) else None
        return self.by_id.get(entry_id) if entry_id is not None else None


def entry_nets(store, entry):
    if entry['kind'] == 'asn':
        return [ipaddress.ip_network(p) for p in store.asn_prefixes(entry['id'])]
    return [ipaddress.ip_network(entry['addr'], strict=False)]


def desired_table(store, guards):
    """ pf spellings for every entry in force, with "!addr" holes for protected addresses inside networks """
    desired = set()
    for entry in store.active_entries():
        for net in entry_nets(store, entry):
            if net.prefixlen == net.max_prefixlen:
                if guards is None or guards.check(net.network_address) is None:
                    desired.add(common.pf_text(net))
                continue
            holes = guards.overlapping(net) if guards is not None else []
            if any(sub == net for _label, sub in holes):
                continue
            desired.add(common.pf_text(net))
            for _label, sub in holes:
                desired.add('!' + common.pf_text(sub))
    return desired


def pf_count(store):
    count = 0
    for entry in store.active_entries():
        count += len(store.asn_prefixes(entry['id'])) if entry['kind'] == 'asn' else 1
    return count


class Lock:
    def __init__(self, path):
        self.path = path
        self.handle = None

    def acquire(self, wait=0.0):
        os.makedirs(os.path.dirname(self.path), mode=0o750, exist_ok=True)
        self.handle = open(self.path, 'a+')
        end = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= end:
                    self.handle.close()
                    self.handle = None
                    raise common.BusyError('another quarantine run is in progress, try again in a moment')
                time.sleep(0.2)

    def release(self):
        if self.handle is not None:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None


def _syslog(message):
    try:
        import syslog
        syslog.openlog('policyanalyzer-quarantine')
        syslog.syslog(syslog.LOG_WARNING, message)
    except Exception:  # noqa: BLE001
        pass


# ------------------------------------------------------------------ engine


class Engine:
    def __init__(self, ctx=None, runtime_guards=True, resolver=None):
        self.ctx = ctx or common.Context()
        self.runtime_guards = runtime_guards
        self.resolver = resolver

    def now(self):
        return self.ctx.clock()

    def installed(self):
        return os.path.exists(self.ctx.db)

    def open(self, create=False):
        return store_mod.Store(self.ctx.db, create=create)

    def config(self):
        return fwconfig.FirewallConfig(self.ctx.config_xml)

    def guards(self, cfg, store, now):
        return guards_mod.build(self.ctx, cfg, store, now, runtime=self.runtime_guards, resolver=self.resolver)

    # ---------------------------------------------------------- the 5 minute run

    def run(self):
        started = time.monotonic()
        if not self.installed():
            return {'status': 'not_installed', 'message': 'the quarantine is not installed'}
        lock = Lock(self.ctx.lock_file)
        try:
            lock.acquire()
        except common.BusyError as exc:
            return {'status': 'busy', 'message': str(exc)}
        st = self.open()
        try:
            return self._run(st, started)
        finally:
            st.close()
            lock.release()

    def _run(self, st, started):
        now = self.now()
        settings = st.settings()
        deadline = started + settings['budget']
        cfg = self.config()
        wan = cfg.wan_interfaces()
        wan_devs = {w['dev'] for w in wan}
        dev_key = cfg.device_to_key()
        wg_ports = set(cfg.wireguard()['ports'])
        rule = (cfg.quarantine_rules() or [None])[0]
        rule_uuid = rule['uuid'] if rule else None
        stats = collections.Counter()
        guard_skips = collections.Counter()

        f_marker = st.meta_json('marker_filter')
        records, new_f_marker, f_info = sources.read_filter(self.ctx, f_marker, deadline=deadline, now=now)
        alerts, new_e_marker, e_info = [], st.meta_json('marker_eve'), {'skipped': True}
        if settings['suricata']:
            alerts, new_e_marker, e_info = sources.read_suricata(self.ctx, st.meta_json('marker_eve'),
                                                                 deadline=deadline)
        oldest = now - common.MAX_BACKLOG

        g = self.guards(cfg, st, now)
        wg_rows = {}
        blocks = collections.defaultdict(list)
        for rec in records:
            if rec['ts'] < oldest or rec['dir'] != 'in' or rec['iface'] not in wan_devs:
                continue
            ip = common.addr(rec['src'])
            if ip is None:
                continue
            if rec['action'] == 'pass':
                if rec['proto'] == 'udp' and rec['dport'].isdigit() and int(rec['dport']) in wg_ports:
                    text = str(ip)
                    wg_rows[text] = max(wg_rows.get(text, 0), int(rec['ts']))
            elif rec['action'] == 'block' and common.is_external(ip):
                blocks[str(ip)].append(rec)
        for text in wg_rows:
            g.add('wireguard_allowed', text, 'allowed inbound to a WireGuard port in the last 24 h')
        by_alert = collections.defaultdict(list)
        for alert in alerts:
            ip = common.addr(alert['src'])
            if alert['ts'] >= oldest and alert['severity'] <= settings['suricata_severity'] and common.is_external(ip):
                by_alert[str(ip)].append(alert)

        lk = lookup_mod.Lookup(self.ctx)
        new_entries = []
        limit_hit = False
        st.begin()
        try:
            if wg_rows:
                st.wg_seen(sorted(wg_rows.items()))
            st.wg_prune(now - 86400)
            first_ts = min([r['ts'] for v in blocks.values() for r in v] +
                           [a['ts'] for v in by_alert.values() for a in v] + [now])
            coverage = Coverage(st.entries_covering_since(first_ts - 1), st)
            active_pf = pf_count(st)
            sources_ips = sorted(set(blocks) | set(by_alert),
                                 key=lambda k: (min([r['ts'] for r in blocks.get(k, [])] +
                                                    [a['ts'] for a in by_alert.get(k, [])]),
                                                ipaddress.ip_address(k).version, ipaddress.ip_address(k)))
            for text in sources_ips:
                ip = ipaddress.ip_address(text)
                why = g.check(ip)
                if why is not None:
                    guard_skips[why] += 1
                    continue
                stats['sources'] += 1
                covered, open_blocks, open_alerts, covered_alerts = [], [], [], []
                cov_entry = coverage.find(text, ip)
                for rec in sorted(blocks.get(text, []), key=lambda r: r['ts']):
                    if (rule_uuid and rec['rid'] == rule_uuid) or (cov_entry is not None and covers(cov_entry, rec['ts'])):
                        covered.append(rec)
                    elif counts_as_connection(rec, settings['syn_only']):
                        open_blocks.append(rec)
                for alert in by_alert.get(text, []):
                    if cov_entry is not None and covers(cov_entry, alert['ts']):
                        covered_alerts.append(alert)
                    else:
                        open_alerts.append(alert)
                if covered and cov_entry is not None:
                    st.add_hits(cov_entry['id'], len(covered))
                    stats['hits'] += len(covered)
                found = detect(open_blocks, open_alerts, settings)
                if found is None:
                    # stronger scenario while already in quarantine: upgrade (own address entries only)
                    up = detect([r for r in covered if counts_as_connection(r, settings['syn_only'])],
                                covered_alerts, settings) if cov_entry is not None else None
                    if up is not None and cov_entry['kind'] == 'ip' and cov_entry['state'] == 'active' and \
                            up['min_level'] > int(cov_entry['level'] or 0):
                        self._offend(st, cov_entry, up, up['min_level'], now, dev_key, upgrade=True)
                        stats['upgrades'] += 1
                        new_entries.append((text, up['primary']))
                    continue
                entry = st.entry_by_addr(text)
                level = next_level(entry, found['ts'], settings, found['min_level'])
                if entry is None:
                    country, asn = lk.lookup(ip)
                    entry = st.create_entry(text, 'ip', found['ts'], country=country, asn=asn, state='expired',
                                            level=0, origin='auto')
                elif entry.get('country') is None or entry.get('asn') is None:
                    country, asn = lk.lookup(ip)
                    st.update_entry(entry['id'], country=entry.get('country') or country,
                                    asn=entry.get('asn') or asn)
                    entry = st.entry(entry['id'])
                if active_pf >= settings['max_active']:
                    limit_hit = True
                    st.add_offense(entry['id'], found['ts'], found['primary'], found['reasons'], level, None, 'auto',
                                   events=found['events'], ports=found['ports'], detail=found['detail'],
                                   iface=dev_key.get(found['iface'], found['iface']), country=entry.get('country'),
                                   limited=True)
                    st.add_event(entry['id'], now, 'limit', level=level, origin='auto',
                                 note='max_active %d reached' % settings['max_active'])
                    stats['limited'] += 1
                    continue
                self._offend(st, entry, found, level, now, dev_key)
                active_pf += 1
                stats['offenses'] += 1
                stats['reason_' + found['primary']] += 1
                new_entries.append((text, found['primary']))

            expired = self._expire(st, now)
            released = self._guard_release(st, g, now)
            st.set_meta('marker_filter', new_f_marker)
            if settings['suricata']:
                st.set_meta('marker_eve', new_e_marker)
            if limit_hit:
                st.set_meta('limit_alert', {'ts': int(now), 'max_active': settings['max_active']})
            elif active_pf < settings['max_active'] * 0.9:
                st.del_meta('limit_alert')
            st.commit()
        except Exception:
            st.rollback()
            raise
        finally:
            lk.close()
        if limit_hit:
            _syslog('quarantine limit of %d active entries reached, new offenders are only recorded' %
                    settings['max_active'])
        sync = self._sync_table(st, g)
        killed = 0
        if sync.get('status') == 'ok':
            fresh = set(sync.get('new') or [])
            for text, reason in new_entries:
                if text in fresh and reason in ('suricata', 'manual'):
                    pf.Table(self.ctx).kill_states(text)
                    killed += 1
        result = {
            'status': 'ok', 'ts': common.iso(now), 'duration_ms': int((time.monotonic() - started) * 1000),
            'filter_log': {k: f_info.get(k) for k in ('records', 'bytes', 'complete', 'first_run', 'missing', 'files')},
            'suricata': {k: e_info.get(k) for k in ('alerts', 'bytes', 'complete', 'first_run', 'missing', 'skipped')},
            'sources': stats['sources'], 'offenses': stats['offenses'], 'upgrades': stats['upgrades'],
            'hits': stats['hits'], 'limited': stats['limited'], 'expired': expired, 'released': released,
            'by_reason': {r: stats['reason_' + r] for r in REASON_ORDER if stats['reason_' + r]},
            'guarded': dict(guard_skips), 'wireguard_allowed_seen': len(wg_rows),
            'table': {k: sync.get(k) for k in ('status', 'added', 'deleted', 'size')}, 'states_killed': killed,
            'limit_hit': limit_hit,
        }
        st.begin()
        st.set_meta('last_run', result)
        st.commit()
        self._maybe_index(st, now, deadline)
        return result

    def _offend(self, st, entry, found, level, now, dev_key, upgrade=False, origin='auto', note=None):
        duration = common.ttl(level)
        until = None if duration is None else int(now) + duration
        state = 'permanent' if level >= common.PERMANENT else 'active'
        if not upgrade and entry.get('state') == 'active' and entry.get('until') and entry['until'] <= now:
            # the previous quarantine ended before this run noticed it: record its end first
            st.add_event(entry['id'], entry['until'], 'expire', level=entry.get('level'))
        iface = dev_key.get(found.get('iface'), found.get('iface')) if found.get('iface') else entry.get('iface')
        st.update_entry(entry['id'], level=level, state=state, origin=origin, reason=common.REASONS[found['primary']],
                        last_offense=int(found['ts']), since=int(now) if not upgrade else entry.get('since'),
                        until=until, offenses=int(entry.get('offenses') or 0) + 1, iface=iface)
        st.add_offense(entry['id'], found['ts'], found['primary'], found['reasons'], level, until, origin,
                       events=found.get('events'), ports=found.get('ports'), detail=found.get('detail'),
                       iface=iface, country=entry.get('country'))
        st.add_event(entry['id'], now, 'upgrade' if upgrade else 'enter', level=level, until=until, origin=origin,
                     note=note)

    def _expire(self, st, now):
        rows = st.db.execute("SELECT id, level FROM entries WHERE state = 'active' AND until IS NOT NULL AND until <= ?",
                             (int(now),)).fetchall()
        for row in rows:
            st.update_entry(row['id'], state='expired')
            st.add_event(row['id'], now, 'expire', level=row['level'])
        return len(rows)

    def _guard_release(self, st, g, now):
        released = 0
        for entry in st.active_entries():
            if entry['kind'] != 'ip':
                continue
            why = g.check(common.addr(entry['addr']))
            if why is not None:
                st.update_entry(entry['id'], state='released', until=int(now))
                st.add_event(entry['id'], now, 'guard_release', level=entry['level'], note=why)
                released += 1
        return released

    def _sync_table(self, st, g):
        try:
            return pf.Table(self.ctx).sync(desired_table(st, g))
        except common.QuarantineError as exc:
            return {'status': 'error', 'message': str(exc)}

    def _maybe_index(self, st, now, deadline):
        try:
            if not lookup_mod.needs_build(self.ctx):
                return
            last = st.meta_json('index_started') or 0
            if now - last < 3600:
                return
            st.begin()
            st.set_meta('index_started', int(now))
            st.commit()
            argv = ['/usr/bin/nice', '-n', '20', sys.executable, '-I', self.ctx.manage_py, 'quarantine', 'index']
            if self.ctx.spawn is not None:
                self.ctx.spawn(argv)
            else:
                subprocess.Popen(argv, start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
        except (OSError, common.QuarantineError):
            pass

    # ---------------------------------------------------------- boot / sync

    def sync(self):
        """ boot hook and after changes: expire, then pf table = ledger """
        if not self.installed():
            return {'status': 'not_installed'}
        lock = Lock(self.ctx.lock_file)
        try:
            lock.acquire(wait=25)
        except common.BusyError as exc:
            return {'status': 'busy', 'message': str(exc)}
        st = self.open()
        try:
            now = self.now()
            cfg = self.config()
            g = self.guards(cfg, st, now)
            st.begin()
            expired = self._expire(st, now)
            st.commit()
            result = self._sync_table(st, g)
            result['expired'] = expired
            return result
        finally:
            st.close()
            lock.release()

    def index(self):
        lock = Lock(self.ctx.index_lock)
        try:
            lock.acquire()
        except common.BusyError as exc:
            return {'status': 'busy', 'message': str(exc)}
        try:
            return lookup_mod.build(self.ctx)
        finally:
            lock.release()

    # ---------------------------------------------------------- read only views

    def status(self):
        now = self.now()
        result = {'status': 'ok', 'installed': False, 'now': common.iso(now), 'warnings': [], 'warning_actions': []}
        try:
            cfg = self.config()
        except common.QuarantineError as exc:
            return {'status': 'error', 'message': str(exc)}
        rules = cfg.quarantine_rules()
        aliases = cfg.aliases()
        crons = cfg.quarantine_cron()
        rule = rules[0] if rules else None
        result['rule'] = {'present': bool(rule), 'enabled': bool(rule and rule['enabled']),
                          'uuid': rule['uuid'] if rule else None, 'sequence': rule['sequence'] if rule else None,
                          'interfaces': rule['interfaces'] if rule else [], 'description': common.RULE_DESCR,
                          'count': len(rules)}
        result['aliases'] = {
            'quarantine': {'present': common.ALIAS in aliases,
                           'type': aliases.get(common.ALIAS, {}).get('type')},
            'never_block': {'present': common.NEVER_ALIAS in aliases,
                            'entries': len(aliases.get(common.NEVER_ALIAS, {}).get('content', []))}}
        result['cron'] = {'present': bool(crons), 'enabled': bool(crons and crons[0]['enabled']),
                          'minutes': crons[0]['minutes'] if crons else None}
        result['syshook'] = os.path.islink(self.ctx.syshook) or os.path.exists(self.ctx.syshook)
        result['wan_interfaces'] = cfg.wan_interfaces()
        result['next_run'] = common.iso(next_run(now)) if crons and crons[0]['enabled'] else None
        result['sources'] = {'filter_log': os.path.exists(self.ctx.filter_log), 'eve': os.path.exists(self.ctx.eve)}
        lsrc = lookup_mod.sources(self.ctx)
        result['lookup'] = {'geoip': lsrc['geoip'] is not None, 'asn': lsrc['asn'] is not None,
                            'index': os.path.exists(self.ctx.lookup_db)}
        if not self.installed():
            result['warning_actions'].append({'warning': 'The quarantine is not installed.',
                                              'action': {'id': 'install_quarantine', 'label': 'Install', 'args': []}})
            result['settings'] = common.effective_settings({})
            result['settings'].pop('bait_ports_list', None)
            return result
        st = self.open()
        try:
            settings = st.settings()
            settings.pop('bait_ports_list', None)
            result.update({'installed': True, 'paused': st.meta('paused') == '1', 'settings': settings,
                           'last_run': st.meta_json('last_run'), 'counts': st.counts(now),
                           'latest_offenses': [self._row(r, now) for r in st.latest_offenses(10)],
                           'db': {'path': self.ctx.db, 'bytes': st.size(), 'schema': st.meta('schema')},
                           'years': st.years()})
            active_pf = pf_count(st)
            result['limit'] = {'max_active': settings['max_active'], 'pf_entries': active_pf,
                               'alert': st.meta_json('limit_alert')}
            missing = [n for n, ok in (('rule', bool(rule)), ('alias', common.ALIAS in aliases),
                                       ('cron', bool(crons)), ('boot hook', result['syshook'])) if not ok]
            if missing:
                result['warning_actions'].append({
                    'warning': 'Parts of the quarantine are missing: %s.' % ', '.join(missing),
                    'action': {'id': 'install_quarantine', 'label': 'Repair (simulate first)', 'args': []}})
            if rule and not rule['enabled'] and not result['paused']:
                result['warning_actions'].append({
                    'warning': 'The rule "%s" is disabled but the quarantine is not paused.' % common.RULE_DESCR,
                    'action': {'id': 'quarantine_resume', 'label': 'Enable the rule', 'args': []}})
            if result['paused']:
                result['warning_actions'].append({
                    'warning': 'Paused: offenders are recorded, the rule "%s" does not block.' % common.RULE_DESCR,
                    'action': {'id': 'quarantine_resume', 'label': 'Resume', 'args': []}})
            if result['limit']['alert'] or active_pf >= settings['max_active']:
                new_max = min(1000000, settings['max_active'] * 2)
                result['warning_actions'].append({
                    'warning': 'The limit of %d active entries was reached: new offenders are only recorded.' %
                               settings['max_active'],
                    'action': {'id': 'quarantine_settings', 'label': 'Raise the limit to %d' % new_max,
                               'args': ['max_active', str(new_max)]}})
            if settings['suricata'] and not result['sources']['eve']:
                result['warning_actions'].append({
                    'warning': 'Suricata alerts are enabled but %s does not exist.' % self.ctx.eve,
                    'link': {'label': 'Intrusion Detection', 'url': '/ui/ids'}})
            if not result['lookup']['asn']:
                result['warning_actions'].append({
                    'warning': 'No local ASN database: ASN entries and the ASN column are not available.',
                    'action': {'id': 'update_asn_db', 'label': 'Download the ASN database', 'args': []}})
            last = result['last_run'] or {}
            if last.get('table', {}).get('status') == 'missing':
                result['warning_actions'].append({
                    'warning': 'The pf table %s is not loaded.' % common.ALIAS,
                    'action': {'id': 'install_quarantine', 'label': 'Repair (simulate first)', 'args': []}})
            from . import wizard                       # late: wizard imports this module
            for r in wizard.wireguard_unlogged(cfg):
                result['warning_actions'].append(wizard.wireguard_warning(r))
            return result
        finally:
            st.close()

    def summary(self, limit=20):
        """ light: for the Max Cyber widget """
        now = self.now()
        if not self.installed():
            return {'status': 'ok', 'installed': False}
        st = self.open()
        try:
            counts = st.counts(now)
            cfg_rule = None
            try:
                rules = self.config().quarantine_rules()
                cfg_rule = rules[0] if rules else None
            except common.QuarantineError:
                pass
            return {'status': 'ok', 'installed': True, 'paused': st.meta('paused') == '1',
                    'rule_enabled': bool(cfg_rule and cfg_rule['enabled']), 'generated': common.iso(now),
                    'active': counts['active'], 'by_level': counts['active_by_level'],
                    'offenses_24h': counts['offenses_24h'], 'new_24h': counts['new_24h'],
                    'by_reason_24h': counts['offenses_24h_by_reason'],
                    'last_run': (st.meta_json('last_run') or {}).get('ts'),
                    'latest': [{'addr': e['addr'], 'kind': e['kind'], 'level': e['level'],
                                'reason': common.REASON_NAMES.get(e['reason']), 'country': e['country'],
                                'since': common.iso(e['since']), 'until': common.iso(e['until']),
                                'expires_in': (int(e['until'] - now) if e['until'] else None)}
                               for e in st.latest_active(limit)]}
        finally:
            st.close()

    @staticmethod
    def _row(row, now):
        out = dict(row)
        out['reason'] = common.REASON_NAMES.get(row.get('reason'), row.get('reason'))
        if 'reasons' in row and isinstance(row['reasons'], int):
            out['reasons'] = store_mod.reasons_from_mask(row['reasons'])
        for key in ('ts', 'first_seen', 'last_offense', 'since', 'until', 'resolved_at'):
            if key in row:
                out[key + '_iso'] = common.iso(row[key])
        if 'state' in row:
            out['remaining'] = int(row['until'] - now) if row.get('until') and row['state'] == 'active' and \
                row['until'] > now else (None if row['state'] == 'permanent' else 0)
            out['duration'] = int(row['until'] - row['since']) if row.get('until') and row.get('since') else None
            out['level_label'] = common.LEVEL_LABELS.get(row.get('level'), '-')
        return out

    def search(self, filters, sort, page, rows):
        now = self.now()
        st = self.open()
        try:
            total, items = st.search(filters, sort, page, rows, now)
            result = []
            for item in items:
                out = self._row(item, now)
                if item['kind'] == 'asn':
                    out['prefixes'] = len(st.asn_prefixes(item['id']))
                result.append(out)
            return {'status': 'ok', 'total': total, 'rowCount': len(result), 'current': page, 'rows': result}
        finally:
            st.close()

    def entry_detail(self, key):
        now = self.now()
        st = self.open()
        try:
            entry = st.entry(int(key)) if str(key).isdigit() else st.entry_by_addr(key)
            if entry is None:
                raise ValueError('entry not found')
            _t, offenses = st.offenses(entry_id=entry['id'], rows=0)
            _t, events = st.events(entry_id=entry['id'], rows=0)
            yearly = [dict(r) for r in st.db.execute('SELECT * FROM yearly WHERE entry_id = ? ORDER BY year DESC',
                                                     (entry['id'],))]
            for y in yearly:
                y['reasons'] = store_mod.reasons_from_mask(y['reasons'] or 0)
            return {'status': 'ok', 'entry': self._row(entry, now), 'prefixes': st.asn_prefixes(entry['id']),
                    'offenses': [self._row(o, now) for o in offenses],
                    'events': [self._row(e, now) for e in events], 'yearly': yearly}
        finally:
            st.close()

    def history(self, kind, address, period, page, rows):
        start, end = period_bounds(period)
        st = self.open()
        now = self.now()
        try:
            if kind == 'yearly':
                year = int(period) if period and period.isdigit() else time.localtime(now).tm_year
                total, items = st.yearly(year, address, page, rows)
                for item in items:
                    item['reasons'] = store_mod.reasons_from_mask(item['reasons'] or 0)
                return {'status': 'ok', 'kind': kind, 'total': total, 'rows': items, 'years': st.years()}
            fetch = st.events if kind == 'events' else st.offenses
            total, items = fetch(address=address, start=start, end=end, page=page, rows=rows)
            return {'status': 'ok', 'kind': kind, 'total': total, 'rows': [self._row(i, now) for i in items],
                    'years': st.years()}
        finally:
            st.close()

    def export_csv(self, period, address=None):
        start, end = period_bounds(period)
        st = self.open()
        try:
            _total, items = st.offenses(address=address, start=start, end=end, rows=0)
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(['time', 'address', 'kind', 'asn', 'country', 'reason', 'reasons', 'level', 'until',
                             'origin', 'events', 'ports', 'detail', 'interface', 'limited'])
            for o in reversed(items):
                writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(o['ts'])), o['addr'], o['kind'],
                                 o.get('asn') or '', o.get('country') or '', common.REASON_NAMES.get(o['reason']),
                                 ' '.join(store_mod.reasons_from_mask(o['reasons'])), o['level'],
                                 time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(o['until'])) if o['until'] else '',
                                 o['origin'], o.get('events') or '', o.get('ports') or '', o.get('detail') or '',
                                 o.get('iface') or '', o.get('limited') or 0])
            return buf.getvalue()
        finally:
            st.close()

    def guards_report(self):
        now = self.now()
        st = self.open() if self.installed() else None
        try:
            g = self.guards(self.config(), st, now)
            result = g.describe()
            result['status'] = 'ok'
            return result
        finally:
            if st is not None:
                st.close()


def period_bounds(period):
    """ "-"/None, "YYYY", "YYYYMMDD-YYYYMMDD" -> (start, end) epochs (local time), end exclusive """
    if not period or period == '-':
        return None, None
    if period.isdigit() and len(period) == 4:
        return store_mod.year_bounds(int(period))
    if len(period) == 17 and period[8] == '-' and period[:8].isdigit() and period[9:].isdigit():
        start = time.mktime(time.strptime(period[:8], '%Y%m%d'))
        end = time.mktime(time.strptime(period[9:], '%Y%m%d')) + 86400
        if end <= start:
            raise ValueError('invalid period')
        return int(start), int(end)
    raise ValueError('invalid period (YYYY or YYYYMMDD-YYYYMMDD)')
