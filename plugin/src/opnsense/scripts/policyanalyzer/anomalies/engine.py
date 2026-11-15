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

    The periodic run (every 15 minutes, cron "pa_anomalies run") and the read only views.

    run():  flock -> CPU limit (RLIMIT_CPU) and wall clock budget -> read every source from its marker ->
            update the baselines -> run the detectors -> exceptions -> findings/occurrences -> prune.
            One SQLite transaction per run: a crash leaves the markers where they were, nothing is counted
            twice.  Nothing outside anomalies.db (and the optional country/ASN index) is ever written.
"""

import fcntl
import ipaddress
import json
import os
import resource
import time

from . import common, detectors, dnsfeat, netcfg as netcfg_mod, sources, store as store_mod

FAIL_FLAGS_ACK = 0x10
BEACON_SKIP_PORTS = frozenset((53, 123, 853))     # NTP; DNS/DoT are the dns_bypass detector's
MAX_TIMES = 500
LOOKUP_REBUILD_S = 86400


class Lock:
    def __init__(self, path):
        self.path = path
        self.fd = None

    def acquire(self):
        os.makedirs(os.path.dirname(self.path), mode=0o750, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd)
            self.fd = None
            raise common.BusyError('another anomaly run is in progress')

    def release(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class IpCache:
    def __init__(self, cfg):
        self.cfg = cfg
        self._cache = {}

    def kind(self, text):
        """ 'int' (internal host), 'fw' (firewall), 'ext' (internet), 'bcast', '' (other) """
        value = self._cache.get(text)
        if value is not None:
            return value
        ip = netcfg_mod.parse_ip(text)
        if ip is None:
            value = ''
        elif ip.is_multicast or (ip.version == 4 and str(ip) == '255.255.255.255'):
            value = 'bcast'
        elif self.cfg.is_firewall(ip):
            value = 'fw'
        elif self.cfg.is_internal(ip):
            value = 'bcast' if any(ip == n.broadcast_address for n in self.cfg.internal
                                   if n.version == 4 and n.prefixlen < 31) else 'int'
        elif self.cfg.is_external(ip):
            value = 'ext'
        else:
            value = ''
        self._cache[text] = value
        return value


class Engine:
    def __init__(self, ctx):
        self.ctx = ctx

    # ================================================================== helpers
    def _lookup(self):
        """ (callable ip_text -> (country, asn), source name) """
        if 'lookup' in self.ctx.sources:
            return self.ctx.sources['lookup'], 'test'
        try:
            from quarantine import lookup as qlookup
        except ImportError:
            return None, None
        for path, name in ((self.ctx.quarantine_lookup_db, 'quarantine'), (self.ctx.lookup_db, 'anomalies')):
            if os.path.exists(path):
                class _C:
                    lookup_db = path
                lk = qlookup.Lookup(_C)
                if lk.db is not None:
                    def find(text, _lk=lk):
                        try:
                            return _lk.lookup(ipaddress.ip_address(text))
                        except ValueError:
                            return None, None
                    return find, name
        return None, None

    def _spawn_index(self, st, now):
        """ build anomalies-lookup.db in the background (nice) when no index exists, at most once a day """
        last = st.get_meta('index_spawned') or 0
        if now - last < LOOKUP_REBUILD_S or 'lookup' in self.ctx.sources or self.ctx.root:
            return False
        if not (os.path.exists(self.ctx.asn_csv) or os.path.isdir(self.ctx.geoip_dir)):
            return False
        st.set_meta('index_spawned', int(now))
        try:
            import subprocess
            subprocess.Popen([self.ctx.nice, '-n', '20', '/usr/local/bin/python3', self.ctx.cli_py, 'index'],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, close_fds=True)
        except OSError:
            return False
        return True

    @staticmethod
    def _limit_cpu(seconds):
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
            used = int(resource.getrusage(resource.RUSAGE_SELF).ru_utime +
                       resource.getrusage(resource.RUSAGE_SELF).ru_stime)
            want = used + int(seconds)
            if hard == resource.RLIM_INFINITY or want < hard:
                resource.setrlimit(resource.RLIMIT_CPU, (want, hard))
        except (ValueError, OSError):
            pass

    # ================================================================== run
    def run(self, now=None):
        ctx = self.ctx
        now = ctx.clock() if now is None else now
        started = time.monotonic()
        cpu0 = time.process_time()
        lock = Lock(ctx.lock_file)
        try:
            lock.acquire()
        except common.BusyError as exc:
            return {'status': 'busy', 'message': str(exc)}
        try:
            st = store_mod.Store(ctx.db)
            try:
                settings = common.effective_settings(st.settings())
                if not ctx.root and 'flows' not in ctx.sources:
                    self._limit_cpu(settings['cpu_s'])
                deadline = started + settings['budget_s']
                result = self._run(st, settings, now, deadline)
            finally:
                st.close()
        finally:
            lock.release()
        result['duration_ms'] = int((time.monotonic() - started) * 1000)
        result['cpu_ms'] = int((time.process_time() - cpu0) * 1000)
        try:
            st = store_mod.Store(ctx.db)
            st.db.execute('UPDATE runs SET duration_ms = ?, cpu_ms = ? WHERE id = ?',
                          (result['duration_ms'], result['cpu_ms'], result.get('run_id')))
            last = st.get_meta('last_run') or {}
            last.update({'duration_ms': result['duration_ms'], 'cpu_ms': result['cpu_ms']})
            st.set_meta('last_run', last)
            st.close()
        except Exception:      # noqa: BLE001  cost bookkeeping never fails a run
            pass
        return result

    def _run(self, st, settings, now, deadline):
        ctx = self.ctx
        cfg = netcfg_mod.NetConfig(ctx.config_xml)
        ips = IpCache(cfg)
        info = {'sources': {}, 'counts': {}}
        cands = []
        st.begin()
        try:
            lookup, lookup_src = self._lookup()
            info['lookup'] = lookup_src
            if lookup is None:
                info['lookup_spawned'] = self._spawn_index(st, now)
            if not st.get_meta('installed_at'):
                st.set_meta('installed_at', int(now))
            # ---------------------------------------------------------- seeds (first run only)
            if not st.get_meta('insight_seeded'):
                info['insight_seed'] = self._seed_insight(st, ips, lookup, now, deadline)
                st.set_meta('insight_seeded', int(now))
            # ---------------------------------------------------------- NetFlow
            flows, fmarker, finfo = sources.read_flows(ctx, st.get_meta('flow_marker'), now, settings, deadline)
            info['sources']['netflow'] = finfo
            if fmarker:
                st.set_meta('flow_marker', fmarker)
            agg = self._aggregate_flows(flows, ips, cfg)
            info['counts'].update({'flows': len(flows), 'flows_used': agg['used'], 'hosts': len(agg['active'])})
            for host, first, last in agg['active_times']:
                st.db.execute('INSERT INTO hosts_seen VALUES (?, ?, ?) ON CONFLICT(host) DO UPDATE SET '
                              'first_seen = min(first_seen, excluded.first_seen), '
                              'last_seen = max(last_seen, excluded.last_seen)', (host, int(first), int(last)))
            cands += self._beacons(st, agg['pairs'], settings, now, lookup)
            cands += self._volume(st, agg['hours'], settings, now)
            cands += self._rare(st, agg['dests'], settings, now, lookup)
            # ---------------------------------------------------------- filter log (blocked internal attempts)
            blocked = {}
            if time.monotonic() < deadline:
                frecs, fm, finfo2 = sources.read_filter(ctx, st.get_meta('filter_marker'), now, deadline)
                info['sources']['filter'] = {k: v for k, v in finfo2.items() if k in ('records', 'complete',
                                                                                      'missing', 'bytes')}
                if fm:
                    st.set_meta('filter_marker', fm)
                for rec in frecs:
                    if rec['dir'] == 'in' and ips.kind(rec['src']) == 'int' and ips.kind(rec['dst']) in ('int', 'fw'):
                        blocked[rec['src']] = blocked.get(rec['src'], 0) + 1
            cands += self._scans(st, agg['scan'], blocked, settings, now)
            # ---------------------------------------------------------- Unbound
            doh_lookups = {}
            if time.monotonic() < deadline:
                dns_c, doh_lookups, dinfo = self._dns(st, ips, cfg, settings, now, deadline)
                cands += dns_c
                info['sources']['unbound'] = dinfo
            cands += self._bypass(agg['bypass'], doh_lookups, cfg, settings, now)
            # ---------------------------------------------------------- devices
            hosts, hinfo = sources.read_hosts(ctx)
            info['sources']['hosts'] = hinfo
            cands += self._devices(st, hosts, ips, cfg, settings, now)
            # ---------------------------------------------------------- TLS
            if settings['tls_enabled'] and time.monotonic() < deadline:
                tls_c, tinfo = self._tls(st, ips, settings, now, deadline)
                cands += tls_c
                info['sources']['suricata_tls'] = tinfo
            # ---------------------------------------------------------- findings
            self._corroborate(st, cands, now)
            enrich = self._device_index(st)
            counts = {'new': 0, 'update': 0, 'reoccur': 0, 'expected': 0}
            exceptions = st.exceptions()
            for cand in cands:
                dev = enrich.get(cand['host'])
                if dev:
                    cand.setdefault('mac', dev.get('mac'))
                    cand.setdefault('hostname', dev.get('hostname'))
                exc = match_exception(cand, exceptions)
                status = 'expected' if exc else 'open'
                if exc:
                    counts['expected'] += 1
                kind = st.upsert_finding(cand, now, status, exc['id'] if exc else None, settings['reoccur_s'])
                counts[kind] += 1
            info['findings'] = counts
            info['pruned'] = st.prune(now, settings['beacon_window_h'] * 3600)
            info['complete'] = all(s.get('complete', True) for s in info['sources'].values() if isinstance(s, dict))
            info['deadline_hit'] = time.monotonic() > deadline
            cur = st.db.execute('INSERT INTO runs (ts, status, findings, info) VALUES (?, ?, ?, ?)',
                                (int(now), 'ok', len(cands), json.dumps(info, default=str)))
            run_id = cur.lastrowid
            st.set_meta('last_run', {'ts': int(now), 'status': 'ok', 'candidates': len(cands), 'counts': counts,
                                     'complete': info['complete'], 'sources': _source_states(info['sources'])})
            st.commit()
        except Exception:
            st.rollback()
            raise
        return {'status': 'ok', 'run_id': run_id, 'candidates': len(cands), 'findings': counts, 'info': info}

    # ================================================================== NetFlow aggregation
    def _aggregate_flows(self, flows, ips, cfg):
        ifaces = cfg.internal_ifaces
        seen = set()
        pairs, hours, dests, scan, bypass = {}, {}, {}, {}, {}
        active = {}
        used = 0
        for f in flows:
            key = (f['src'], f['sport'], f['dst'], f['dport'], f['proto'], int(f['ts']))
            if key in seen:
                continue
            seen.add(key)
            sk, dk = ips.kind(f['src']), ips.kind(f['dst'])
            if sk == 'int' and dk == 'ext':
                if ifaces and f['if_in'] not in ifaces:
                    continue
                host = f['src']
                used += 1
                self._active(active, host, f['ts'])
                hour = int(f['ts'] // 3600 * 3600)
                h = hours.setdefault((host, hour), {'out': 0, 'in': 0, 'flows': 0, 'dsts': {}})
                h['out'] += f['octets']
                h['flows'] += 1
                h['dsts'][f['dst']] = h['dsts'].get(f['dst'], 0) + f['octets']
                d = dests.setdefault(host, {}).setdefault(f['dst'], [0, 0, f['ts']])
                d[0] += f['octets']
                d[1] += 1
                if f['proto'] in (6, 17) and f['dport'] not in BEACON_SKIP_PORTS:
                    # one session = one 5-tuple: NetFlow expires an idle persistent connection after the inactive
                    # timeout (15 s) and starts a new record with the same ports on the next keepalive
                    pk = (host, f['dst'], f['dport'], f['proto'])
                    p = pairs.setdefault(pk, {'times': [], 'sizes': [], 'durs': [], 'sports': {}})
                    idx = p['sports'].get(f['sport'])
                    if idx is not None:
                        p['sizes'][idx] += f['octets']
                        p['durs'][idx] = max(p['durs'][idx], f['end'] - p['times'][idx])
                    else:
                        p['sports'][f['sport']] = len(p['times'])
                        p['times'].append(f['ts'])
                        p['sizes'].append(f['octets'])
                        p['durs'].append(max(0.0, f['end'] - f['ts']))
                if f['proto'] in (6, 17):
                    kind = None
                    if f['dport'] == 53:
                        kind = 'dns'
                    elif f['dport'] == 853:
                        kind = 'dot'
                    elif f['dport'] == 443 and f['dst'] in netcfg_mod.DOH_ADDRESSES:
                        kind = 'doh'
                    if kind:
                        b = bypass.setdefault(host, {}).setdefault(
                            (f['dst'], f['dport'], 'tcp' if f['proto'] == 6 else 'udp'),
                            {'flows': 0, 'bytes': 0, 'kind': kind, 'iface': f['if_in']})
                        b['flows'] += 1
                        b['bytes'] += f['octets']
            elif sk == 'ext' and dk == 'int':
                if ifaces and f['if_out'] not in ifaces:
                    continue
                used += 1
                host = f['dst']
                hour = int(f['ts'] // 3600 * 3600)
                h = hours.setdefault((host, hour), {'out': 0, 'in': 0, 'flows': 0, 'dsts': {}})
                h['in'] += f['octets']
                d = dests.setdefault(host, {}).setdefault(f['src'], [0, 0, f['ts']])
                d[0] += f['octets']
            elif sk == 'int' and dk in ('int', 'fw') and f['src'] != f['dst']:
                if ifaces and f['if_in'] not in ifaces:
                    continue
                used += 1
                self._active(active, f['src'], f['ts'])
                failed = f['proto'] == 6 and f['packets'] <= detectors.SCAN_FAIL_PACKETS and \
                    not (f['flags'] & FAIL_FLAGS_ACK)
                scan.setdefault(f['src'], []).append((f['ts'], f['dst'], f['dport'], f['proto'], failed))
        return {'pairs': pairs, 'hours': hours, 'dests': dests, 'scan': scan, 'bypass': bypass, 'used': used,
                'active': active, 'active_times': [(h, v[0], v[1]) for h, v in active.items()]}

    @staticmethod
    def _active(active, host, ts):
        v = active.get(host)
        if v is None:
            active[host] = [ts, ts]
        else:
            v[0] = min(v[0], ts)
            v[1] = max(v[1], ts)

    def _host_age(self, st, host, now):
        row = st.db.execute('SELECT first_seen FROM hosts_seen WHERE host = ?', (host,)).fetchone()
        return now - row[0] if row else 0

    def _learn_age(self, st, kind, now):
        """ time since this kind of data is learned (first run that processed it) """
        first = st.get_meta('learn_' + kind)
        if first is None:
            st.set_meta('learn_' + kind, int(now))
            return 0
        return now - first

    # ================================================================== (a) beaconing
    def _beacons(self, st, pairs, settings, now, lookup):
        out = []
        window = settings['beacon_window_h'] * 3600
        for (host, dst, dport, proto), new in pairs.items():
            row = st.db.execute('SELECT first_seen, times, sizes, durs, sports FROM pairs WHERE host = ? AND '
                                'dst = ? AND dport = ? AND proto = ?', (host, dst, dport, proto)).fetchone()
            times, sizes, durs, sports = [], [], [], []
            first = new['times'][0]
            if row is not None:
                times, sizes, durs = json.loads(row[1]), json.loads(row[2]), json.loads(row[3])
                sports = json.loads(row[4] or '[]')
                first = row[0]
            last_known = times[-1] if times else None
            known_ports = set(sports)
            by_index = {i: sp for sp, i in new['sports'].items()}
            for i, (t, s, d) in enumerate(zip(new['times'], new['sizes'], new['durs'])):
                if (last_known is not None and t <= last_known) or by_index.get(i) in known_ports:
                    continue                    # already counted, or the session of the previous run goes on
                times.append(int(t))
                sizes.append(int(s))
                durs.append(round(d, 1))
                sports.append(by_index.get(i))
            sports = sports[-16:]
            keep = [i for i, t in enumerate(times) if t >= now - window][-MAX_TIMES:]
            times = [times[i] for i in keep]
            sizes = [sizes[i] for i in keep]
            durs = [durs[i] for i in keep]
            if not times:
                continue
            st.db.execute('INSERT OR REPLACE INTO pairs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                          (host, dst, dport, proto, int(first), int(times[-1]), json.dumps(times),
                           json.dumps(sizes), json.dumps(durs), json.dumps(sports)))
            if len(times) >= settings['beacon_min_conn']:
                dst_info = {}
                if lookup is not None:
                    cc, asn = lookup(dst)
                    dst_info = {'country': cc, 'asn': asn}
                cand = detectors.beaconing(host, dst, dport, proto, times, sizes, durs, settings, dst_info,
                                           ts=times[-1])
                if cand:
                    out.append(cand)
        return self._group_beacons(st, out, now)

    def _group_beacons(self, st, cands, now):
        """
        one finding per host and service, keyed by protocol + port family (a camera that keeps 6 UDP ports
        open to 3 cloud servers is one finding, not 18, and a port that drops below the threshold does not
        fork the finding); "high" needs corroboration, see _corroborate
        """
        groups = {}
        for c in cands:
            groups.setdefault((c['host'], c['evidence']['proto'], _port_family(c['evidence']['port'])), []).append(c)
        out = []
        for (host, proto, family), items in groups.items():
            items.sort(key=lambda c: -c['score'])
            best = dict(items[0])
            dsts = sorted({c['evidence']['destination'] for c in items})
            ports = tuple(sorted({c['evidence']['port'] for c in items}))
            sig = '%s/%s' % (proto, family)
            best['key'] = sig
            best['id'] = common.finding_id('beaconing', host, sig)
            ev = dict(best['evidence'])
            ev['destinations'] = [{'destination': c['evidence']['destination'], 'port': c['evidence']['port'],
                                   'connections': c['evidence']['connections'],
                                   'median_interval_s': c['evidence']['median_interval_s'], 'score': c['score'],
                                   'dst_info': c['evidence'].get('dst_info')} for c in items[:20]]
            ev['ports'] = list(ports)
            best['evidence'] = ev
            if len(items) > 1:
                best['detail'] = best['detail'].rstrip('.') + '; the same pattern on %d port(s) to %d destination(s) ' \
                    '(%s).' % (len(ports), len(dsts), ', '.join(dsts[:4]) + (' ...' if len(dsts) > 4 else ''))
            out.append(best)
        return out

    CORROBORATING = ('dga', 'dns_tunnel', 'rare_destination', 'tls', 'new_domain', 'volume')

    def _corroborate(self, st, cands, now):
        """ a beacon is "high" only with another kind of finding of the same host (this run or open, 24 h) """
        this_run = {}
        for c in cands:
            if c['type'] in self.CORROBORATING:
                this_run.setdefault(c['host'], set()).add(c['type'])
        for c in cands:
            if c['type'] != 'beaconing':
                continue
            others = set(this_run.get(c['host'], ()))
            others |= {r[0] for r in st.db.execute(
                "SELECT DISTINCT type FROM findings WHERE host = ? AND status = 'open' AND last_seen >= ? AND type IN "
                "(%s)" % ','.join('?' * len(self.CORROBORATING)), (c['host'], int(now - 86400)) + self.CORROBORATING)}
            c['factors'] = list(c['factors']) + [common.factor(
                'corroboration', ', '.join(sorted(others)) or 'none', None, bool(others), None,
                'other kinds of findings of this host in the last 24 h (a beacon alone stays medium)')]
            if c['severity'] == 'high' and not others:
                c['severity'] = 'medium'

    # ================================================================== (d) volume
    @staticmethod
    def _slot(hour):
        return time.localtime(hour).tm_hour

    def _base(self, st, host, slot):
        row = st.db.execute('SELECT n, mean, var FROM vol_base WHERE host = ? AND slot = ?', (host, slot)).fetchone()
        return tuple(row) if row else None

    def _volume(self, st, hours, settings, now):
        out = []
        for (host, hour), h in hours.items():
            top = sorted(h['dsts'].items(), key=lambda kv: -kv[1])[:5]
            st.db.execute(
                'INSERT INTO host_hour (host, hour, bytes_out, bytes_in, flows, dsts, top) VALUES (?, ?, ?, ?, ?, ?, ?) '
                'ON CONFLICT(host, hour) DO UPDATE SET bytes_out = bytes_out + excluded.bytes_out, '
                'bytes_in = bytes_in + excluded.bytes_in, flows = flows + excluded.flows, '
                'dsts = max(dsts, excluded.dsts), top = excluded.top',
                (host, hour, h['out'], h['in'], h['flows'], len(h['dsts']), json.dumps(top)))
        alpha = settings['vol_alpha_pct'] / 100.0
        current = int(now // 3600 * 3600)
        rows = st.db.execute('SELECT host, hour, bytes_out, bytes_in, top FROM host_hour WHERE evaluated = 0 AND '
                             'hour < ? ORDER BY hour', (current,)).fetchall()
        for host, hour, b_out, b_in, top in rows:
            cand = None
            if self._host_age(st, host, now) >= settings['learning_days'] * 86400:
                cand = detectors.volume(host, hour, b_out, b_in, self._base(st, host, self._slot(hour)),
                                        self._base(st, host, -1), settings, _top(top), ts=hour + 3599)
            if cand:
                out.append(cand)
            else:                       # an anomalous hour does not become the new normal
                for slot in (self._slot(hour), -1):
                    n, mean, var = detectors.ewma_update(self._base(st, host, slot), b_out, alpha)
                    st.db.execute('INSERT OR REPLACE INTO vol_base VALUES (?, ?, ?, ?, ?, ?)',
                                  (host, slot, n, mean, var, int(now)))
            st.db.execute('UPDATE host_hour SET evaluated = 1 WHERE host = ? AND hour = ?', (host, hour))
        # the hour in progress: report early when it already crossed the thresholds
        for host, hour, b_out, b_in, top in st.db.execute(
                'SELECT host, hour, bytes_out, bytes_in, top FROM host_hour WHERE hour = ? AND bytes_out >= ?',
                (current, settings['vol_min_mb'] * 1048576)).fetchall():
            if self._host_age(st, host, now) >= settings['learning_days'] * 86400:
                cand = detectors.volume(host, hour, b_out, b_in, self._base(st, host, self._slot(hour)),
                                        self._base(st, host, -1), settings, _top(top), partial=True, ts=now)
                if cand:
                    out.append(cand)
        return out

    # ================================================================== (e) rare destination
    def _rare(self, st, dests, settings, now, lookup):
        if lookup is None:
            return []
        out = []
        learn = self._learn_age(st, 'dest', now)
        for host, items in dests.items():
            agg = {}
            for dst, (octets, conns, _ts) in items.items():
                cc, asn = lookup(dst)
                for kind, value in (('country', cc), ('asn', asn)):
                    if value in (None, ''):
                        continue
                    a = agg.setdefault((kind, str(value)), {'bytes': 0, 'conns': 0, 'sample': dst})
                    a['bytes'] += octets
                    a['conns'] += conns
            new_items = []
            for (kind, value), a in agg.items():
                known = st.db.execute('SELECT 1 FROM host_dest WHERE host = ? AND kind = ? AND value = ?',
                                      (host, kind, value)).fetchone()
                if not known:
                    others = st.db.execute('SELECT count(DISTINCT host) FROM host_dest WHERE kind = ? AND value = ? '
                                           'AND host != ? AND last_seen >= ?',
                                           (kind, value, host, int(now - 30 * 86400))).fetchone()[0]
                    new_items.append({'kind': kind, 'value': value, 'hosts': others, 'bytes': a['bytes'],
                                      'conns': a['conns'], 'sample': a['sample']})
                st.db.execute('INSERT INTO host_dest VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(host, kind, value) '
                              'DO UPDATE SET last_seen = excluded.last_seen, conns = conns + excluded.conns, '
                              'bytes = bytes + excluded.bytes', (host, kind, value, int(now), int(now), a['conns'],
                                                                 a['bytes']))
            if new_items:
                age = min(self._host_age(st, host, now), learn)
                cand = detectors.rare_destination(host, new_items, settings, age, ts=now)
                if cand:
                    out.append(cand)
        return out

    def _seed_insight(self, st, ips, lookup, now, deadline):
        """ first run: the destinations each host already talks to (Insight daily totals), so that the rare
        destination detector does not wait for the learning period """
        rows = sources.read_insight_pairs(self.ctx)
        seeded = 0
        hosts = {}
        for src, dst, octets, first, last in rows:
            if time.monotonic() > deadline - 10:
                break
            sk, dk = ips.kind(src), ips.kind(dst)
            if sk == 'int' and dk == 'ext':
                host, remote = src, dst
            elif sk == 'ext' and dk == 'int':
                host, remote = dst, src
            else:
                continue
            first_ts = _ts(first) or int(now)
            h = hosts.setdefault(host, first_ts)
            hosts[host] = min(h, first_ts)
            if lookup is None:
                continue
            cc, asn = lookup(remote)
            for kind, value in (('country', cc), ('asn', asn)):
                if value in (None, ''):
                    continue
                st.db.execute('INSERT INTO host_dest VALUES (?, ?, ?, ?, ?, 0, ?) ON CONFLICT(host, kind, value) '
                              'DO UPDATE SET first_seen = min(first_seen, excluded.first_seen), '
                              'bytes = bytes + excluded.bytes', (host, kind, str(value), first_ts,
                                                                 int(_ts(last) or now), int(octets or 0)))
                seeded += 1
        for host, first in hosts.items():
            st.db.execute('INSERT INTO hosts_seen VALUES (?, ?, ?) ON CONFLICT(host) DO UPDATE SET '
                          'first_seen = min(first_seen, excluded.first_seen)', (host, first, int(now)))
        if seeded:
            oldest = min(hosts.values())
            st.set_meta('learn_dest', oldest)
        return {'rows': len(rows), 'seeded': seeded, 'hosts': len(hosts)}

    # ================================================================== (g) internal scan
    def _scans(self, st, scan, blocked, settings, now):
        out = []
        for host, events in scan.items():
            events.sort(key=lambda e: e[0])
            base = st.get_meta('scan_base:' + host)
            cand = detectors.internal_scan(host, events, settings, base, blocked.get(host, 0), ts=events[-1][0])
            # EWMA of the distinct internal addresses per run window (the usual reach of this host)
            reach = len({e[1] for e in events})
            if cand:
                out.append(cand)
            else:
                st.set_meta('scan_base:' + host, round(reach if base is None else base * 0.9 + reach * 0.1, 2))
        return out

    # ================================================================== (h) DNS bypass
    def _bypass(self, bypass, doh_lookups, cfg, settings, now):
        out = []
        for host in set(bypass) | set(doh_lookups):
            items = bypass.get(host, {})
            redirect = None
            for v in items.values():
                if v['kind'] == 'dns':
                    redirect = redirect or cfg.redirect_for(v.get('iface'))
            cand = detectors.dns_bypass(host, items, settings, redirect, doh_lookups.get(host), ts=now)
            if cand:
                out.append(cand)
        return out

    # ================================================================== Unbound: DGA, tunnel, new domain
    def _dns(self, st, ips, cfg, settings, now, deadline):
        out = []
        try:
            rows, hours, marker, dinfo = sources.read_dns(self.ctx, st.get_meta('dns_marker'), now, settings,
                                                          deadline)
        except Exception as exc:   # noqa: BLE001  duckdb errors: report, do not fail the run
            return [], {}, {'error': str(exc)[:200], 'complete': False}
        if marker:
            st.set_meta('dns_marker', marker)
        for client, hour, queries, nx, txt in hours:
            if ips.kind(client) == 'int':
                st.db.execute('INSERT OR REPLACE INTO host_dns_hour VALUES (?, ?, ?, ?, ?)',
                              (client, int(hour), int(queries), int(nx or 0), int(txt or 0)))
        if not st.get_meta('dns_seeded'):
            seed = sources.read_dns_seed(self.ctx)
            dinfo['seed'] = self._seed_domains(st, seed, ips, now)
            st.set_meta('dns_seeded', int(now))
        prepared = detectors.dns_prepare(rows, cfg)
        # hosts of this window asking for each registrable domain: a popular new domain is not "never seen"
        in_window = {}
        for client, h in prepared.items():
            if ips.kind(client) == 'int':
                for reg in h['regs']:
                    in_window[reg] = in_window.get(reg, 0) + 1
        doh = {}
        learn = self._learn_age(st, 'dns', now)
        week = int(now - 7 * 86400)
        for host, h in prepared.items():
            if ips.kind(host) != 'int':
                continue
            if h['doh']:
                doh[host] = sorted(h['doh'])
            base = st.db.execute('SELECT count(*), avg(nx), avg(nx * nx) FROM host_dns_hour WHERE host = ? AND '
                                 'hour >= ?', (host, week)).fetchone()
            baseline = None
            if base and base[0] >= 24:
                mean = base[1] or 0.0
                std = max(0.0, (base[2] or 0.0) - mean * mean) ** 0.5
                baseline = (mean, max(std, 1.0))
            cand = detectors.dga(host, h, settings, baseline, ts=now)
            if cand:
                out.append(cand)
            out += detectors.dns_tunnel(host, h, settings, ts=now)
            new_regs = []
            for reg, first in h['regs'].items():
                known = st.db.execute('SELECT 1 FROM host_domain WHERE host = ? AND domain = ?',
                                      (host, reg)).fetchone()
                if not known:
                    others = st.db.execute('SELECT count(*) FROM host_domain WHERE domain = ? AND host != ?',
                                           (reg, host)).fetchone()[0] + in_window.get(reg, 1) - 1
                    label = dnsfeat.registrable(reg)[2]
                    new_regs.append({'domain': reg, 'hosts': others, 'label_score': dnsfeat.name_score(label)[0],
                                     'first': int(first)})
                    st.db.execute('INSERT INTO host_domain VALUES (?, ?, ?, ?, 1)', (host, reg, int(first), int(now)))
                else:
                    st.db.execute('UPDATE host_domain SET last_seen = ?, queries = queries + 1 WHERE host = ? AND '
                                  'domain = ?', (int(now), host, reg))
            if new_regs:
                # accumulate the never seen domains of the day: one finding per host and day
                day_key = 'newdom:%s:%d' % (host, int(now // 86400))
                acc = st.get_meta(day_key) or []
                acc += [d for d in new_regs if d['hosts'] == 0 and not dnsfeat.is_random_by_design(d['domain'])]
                st.set_meta(day_key, acc[-200:])
                age = min(self._host_age(st, host, now) or learn, learn)
                cand = detectors.new_domain(host, acc, settings, age, ts=now, min_new=settings['newdom_min'])
                if cand:
                    out.append(cand)
        st.db.execute("DELETE FROM meta WHERE key LIKE 'newdom:%' AND key NOT LIKE ?",
                      ('newdom:%%:%d' % int(now // 86400),))
        dinfo['hosts'] = len(prepared)
        return out, doh, dinfo

    def _seed_domains(self, st, seed, ips, now):
        """ first run: every (host, registrable domain) of the Unbound history (7 days) is already known """
        count = 0
        oldest = None
        for client, domain, first, last, queries in seed:
            if ips.kind(client) != 'int' or not domain:
                continue
            name = domain.lower().rstrip('.')
            if dnsfeat.skip_name(name):
                continue
            reg = dnsfeat.registrable(name)[0]
            st.db.execute('INSERT INTO host_domain VALUES (?, ?, ?, ?, ?) ON CONFLICT(host, domain) DO UPDATE SET '
                          'first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, '
                          'excluded.last_seen), queries = queries + excluded.queries',
                          (client, reg, int(first), int(last), int(queries)))
            oldest = first if oldest is None else min(oldest, first)
            count += 1
        if oldest is not None:
            st.set_meta('learn_dns', int(oldest))
        return {'pairs': count}

    # ================================================================== (f) devices
    def _devices(self, st, hosts, ips, cfg, settings, now):
        out = []
        learned = st.get_meta('devices_learned')
        merged = {}
        for h in hosts:
            mac = h['mac']
            if not mac or mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
                continue
            internal_iface = h.get('iface') and h['iface'] in cfg.internal_ifaces
            ip_kind = ips.kind(h['ip']) if h.get('ip') else ''
            if not internal_iface and ip_kind != 'int' and not (h.get('ip', '').startswith('fe80') and
                                                                 h.get('iface') in cfg.internal_ifaces):
                continue
            m = merged.setdefault(mac, {'mac': mac, 'ip': None, 'hostname': None, 'vendor': None, 'iface': None,
                                        'source': h['source'], 'first_seen': h.get('first_seen'),
                                        'last_seen': h.get('last_seen')})
            if h.get('ip') and ip_kind == 'int' and (m['ip'] is None or ':' in m['ip']):
                m['ip'] = h['ip']
            for k in ('hostname', 'vendor', 'iface'):
                m[k] = m[k] or h.get(k)
            if h.get('last_seen') and (m['last_seen'] or 0) < h['last_seen']:
                m['last_seen'] = h['last_seen']
        for mac, m in merged.items():
            row = st.db.execute('SELECT mac FROM devices WHERE mac = ?', (mac,)).fetchone()
            if row is None:
                st.db.execute('INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                              (mac, int(now), m['last_seen'], m['ip'], m['hostname'], m['vendor'], m['iface'],
                               m['source'], 0 if learned else 1))
                if learned:
                    cand = detectors.new_device(m, settings, ts=now)
                    out.append(cand)
            else:
                st.db.execute('UPDATE devices SET last_seen = coalesce(?, last_seen), ip = coalesce(?, ip), '
                              'hostname = coalesce(?, hostname), vendor = coalesce(?, vendor), '
                              'iface = coalesce(?, iface) WHERE mac = ?',
                              (m['last_seen'], m['ip'], m['hostname'], m['vendor'], m['iface'], mac))
        if not learned and merged:
            st.set_meta('devices_learned', int(now))
        return out

    def _device_index(self, st):
        return {r[0]: {'mac': r[1], 'hostname': r[2]} for r in
                st.db.execute('SELECT ip, mac, hostname FROM devices WHERE ip IS NOT NULL')}

    # ================================================================== (j) TLS
    def _tls(self, st, ips, settings, now, deadline):
        marker = st.get_meta('tls_marker')
        events, new_marker, info = sources.read_tls(self.ctx, marker, now, deadline)
        if new_marker:
            st.set_meta('tls_marker', new_marker)
        out = []
        first_run = not marker
        learn = 0 if first_run else self._learn_age(st, 'tls', now)
        if first_run:
            st.set_meta('learn_tls', int(min([e['ts'] for e in events] or [now])))
        for e in events:
            if ips.kind(e['src']) != 'int':
                continue
            if e.get('ja4'):
                row = st.db.execute('SELECT 1 FROM host_ja4 WHERE host = ? AND ja4 = ?', (e['src'], e['ja4'])).fetchone()
                if row is None:
                    others = st.db.execute('SELECT count(*) FROM host_ja4 WHERE ja4 = ? AND host != ?',
                                           (e['ja4'], e['src'])).fetchone()[0]
                    st.db.execute('INSERT INTO host_ja4 VALUES (?, ?, ?, ?, 1, ?)',
                                  (e['src'], e['ja4'], int(e['ts']), int(e['ts']), e['sni'] or None))
                    if not first_run:
                        age = min(self._host_age(st, e['src'], now) or learn, learn)
                        cand = detectors.new_ja4(e['src'], e['ja4'], others, e['sni'], settings, age, ts=e['ts'])
                        if cand:
                            out.append(cand)
                else:
                    st.db.execute('UPDATE host_ja4 SET last_seen = ?, count = count + 1 WHERE host = ? AND ja4 = ?',
                                  (int(e['ts']), e['src'], e['ja4']))
            if e.get('issuerdn'):
                row = st.db.execute('SELECT count FROM tls_issuer WHERE issuer = ?', (e['issuerdn'],)).fetchone()
                seen = row[0] if row else None
                st.db.execute('INSERT INTO tls_issuer VALUES (?, ?, ?, 1) ON CONFLICT(issuer) DO UPDATE SET '
                              'last_seen = excluded.last_seen, count = count + 1',
                              (e['issuerdn'], int(e['ts']), int(e['ts'])))
                if not first_run:
                    cand = detectors.tls_certificate(e['src'], e['dst'], e,
                                                     detectors.cert_issues(e, e['ts'], seen), ts=e['ts'])
                    if cand:
                        out.append(cand)
        info = {k: v for k, v in info.items() if k in ('events', 'complete', 'missing', 'bytes', 'first_run')}
        return out, info

    # ================================================================== views
    def _ro(self):
        return store_mod.Store(self.ctx.db, readonly=True)

    def summary(self, now=None):
        """ light: for the Max Cyber widget (/api/policyanalyzer/anomalies/summary) """
        now = self.ctx.clock() if now is None else now
        try:
            st = self._ro()
        except Exception:      # noqa: BLE001
            return {'status': 'ok', 'installed': self.installed(), 'ready': False, 'open': 0,
                    'by_severity': {s: 0 for s in common.SEVERITIES}, 'by_type': {}, 'latest': [],
                    'generated': common.iso(now)}
        try:
            by_sev = {s: 0 for s in common.SEVERITIES}
            by_type = {}
            for sev, kind, n in st.db.execute("SELECT severity, type, count(*) FROM findings WHERE status = 'open' "
                                              "AND last_seen >= ? GROUP BY 1, 2", (int(now - 7 * 86400),)):
                by_sev[sev] = by_sev.get(sev, 0) + n
                by_type[kind] = by_type.get(kind, 0) + n
            new24 = st.db.execute("SELECT count(*) FROM findings WHERE first_seen >= ? AND status = 'open'",
                                  (int(now - 86400),)).fetchone()[0]
            hosts = [{'host': h, 'findings': n, 'max_severity': _sev_name(m)} for h, n, m in st.db.execute(
                "SELECT host, count(*), max(CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 "
                "ELSE 0 END) FROM findings WHERE status = 'open' AND last_seen >= ? GROUP BY host ORDER BY 3 DESC, "
                "2 DESC LIMIT 5", (int(now - 7 * 86400),))]
            latest = [_brief(dict(r), now) for r in st.db.execute(
                "SELECT id, type, host, severity, score, title, detail, last_seen, hostname FROM findings "
                "WHERE status = 'open' ORDER BY last_seen DESC LIMIT 10")]
            last = st.get_meta('last_run') or {}
            return {'status': 'ok', 'installed': self.installed(), 'ready': True, 'generated': common.iso(now),
                    'open': sum(by_sev.values()), 'by_severity': by_sev, 'by_type': by_type, 'new_24h': new24,
                    'top_hosts': hosts, 'latest': latest, 'last_run': common.iso(last.get('ts')),
                    'last_run_status': last.get('status')}
        finally:
            st.close()

    def installed(self):
        try:
            import xml.etree.ElementTree as ET
            root = ET.parse(self.ctx.config_xml).getroot()
        except (OSError, ET.ParseError):
            return False
        return any((j.findtext('command') or '').strip() == common.CRON_COMMAND
                   for j in root.findall('OPNsense/cron/jobs/job'))

    def cron_jobs(self):
        try:
            import xml.etree.ElementTree as ET
            root = ET.parse(self.ctx.config_xml).getroot()
        except (OSError, ET.ParseError):
            return []
        return [{'uuid': j.get('uuid'), 'minutes': j.findtext('minutes'), 'enabled': j.findtext('enabled')}
                for j in root.findall('OPNsense/cron/jobs/job')
                if (j.findtext('command') or '').strip() == common.CRON_COMMAND]

    def status(self, now=None):
        now = self.ctx.clock() if now is None else now
        out = {'status': 'ok', 'installed': self.installed(), 'cron': self.cron_jobs(), 'db': self.ctx.db,
               'db_bytes': _size(self.ctx.db) + _size(self.ctx.db + '-wal'), 'sources': self.source_files(),
               'settings': [], 'runs': [], 'last_run': None, 'exceptions': []}
        stored = {}
        try:
            st = self._ro()
            try:
                stored = st.settings()
                out['last_run'] = st.get_meta('last_run')
                out['runs'] = [{'ts': common.iso(r[0]), 'duration_ms': r[1], 'cpu_ms': r[2], 'status': r[3],
                                'candidates': r[4]} for r in
                               st.db.execute('SELECT ts, duration_ms, cpu_ms, status, findings FROM runs '
                                             'ORDER BY id DESC LIMIT 12')]
                out['exceptions'] = st.exceptions()
                out['counts'] = {t: st.db.execute('SELECT count(*) FROM %s' % t).fetchone()[0] for t in
                                 ('findings', 'occurrences', 'devices', 'pairs', 'host_hour', 'host_domain',
                                  'host_ja4', 'host_dest')}
                out['installed_at'] = common.iso(st.get_meta('installed_at'))
            finally:
                st.close()
        except Exception:      # noqa: BLE001
            out['ready'] = False
        eff = common.effective_settings(stored)
        out['settings'] = [{'key': k, 'value': eff[k], 'default': v[0], 'min': v[1], 'max': v[2],
                            'description': v[3]} for k, v in common.PARAMS.items()]
        out['network'] = netcfg_mod.NetConfig(self.ctx.config_xml).describe()
        return out

    def source_files(self):
        c = self.ctx
        return {'netflow': bool(_glob(c.flowd_log + '*')), 'unbound': os.path.exists(c.unbound_db),
                'hostwatch': os.path.exists(c.hostwatch_db), 'kea': bool(_glob(c.kea_leases + '*')),
                'filter': os.path.exists(c.filter_log), 'suricata': os.path.exists(c.eve),
                'lookup': os.path.exists(c.quarantine_lookup_db) or os.path.exists(c.lookup_db)}

    def search(self, filters, sort, page, rows, now=None):
        now = self.ctx.clock() if now is None else now
        try:
            st = self._ro()
        except Exception:      # noqa: BLE001
            return {'status': 'ok', 'rows': [], 'rowCount': 0, 'total': 0, 'current': page}
        try:
            where, args = [], []
            if filters.get('status'):
                where.append('status = ?')
                args.append(filters['status'])
            if filters.get('severity'):
                where.append('severity = ?')
                args.append(filters['severity'])
            if filters.get('type'):
                where.append('type = ?')
                args.append(filters['type'])
            if filters.get('host'):
                where.append('host = ?')
                args.append(filters['host'])
            if filters.get('days'):
                where.append('last_seen >= ?')
                args.append(int(now - int(filters['days']) * 86400))
            if filters.get('search'):
                where.append('(host LIKE ? OR key LIKE ? OR hostname LIKE ? OR detail LIKE ?)')
                like = '%' + filters['search'] + '%'
                args += [like] * 4
            sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
            total = st.db.execute('SELECT count(*) FROM findings' + sql_where, args).fetchone()[0]
            field, direction = sort
            order = {'severity': "CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END",
                     'score': 'score', 'last_seen': 'last_seen', 'first_seen': 'first_seen', 'host': 'host',
                     'type': 'type', 'occurrences': 'occurrences', 'status': 'status'}.get(field)
            if order is None:
                order_sql = "CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END " \
                            "DESC, last_seen DESC"
            else:
                order_sql = '%s %s, last_seen DESC' % (order, 'ASC' if direction == 'asc' else 'DESC')
            limit = '' if rows == -1 else ' LIMIT %d OFFSET %d' % (rows, (page - 1) * rows)
            items = [_brief(dict(r), now) for r in st.db.execute(
                'SELECT id, type, host, key, severity, score, status, title, detail, first_seen, last_seen, '
                'occurrences, mac, hostname FROM findings' + sql_where + ' ORDER BY ' + order_sql + limit, args)]
            return {'status': 'ok', 'rows': items, 'rowCount': len(items), 'total': total, 'current': page}
        finally:
            st.close()

    def finding(self, fid, now=None):
        now = self.ctx.clock() if now is None else now
        st = self._ro()
        try:
            f = st.finding(fid)
            if f is None:
                return {'status': 'error', 'message': 'finding not found'}
            f['occurrence_list'] = [dict(r) for r in st.db.execute(
                'SELECT ts, last_ts, severity, score, status FROM occurrences WHERE finding_id = ? ORDER BY ts DESC '
                'LIMIT 50', (fid,))]
            f['series'] = self._series(st, f, now)
            f['actions'] = suggested_actions(f)
            f['exception'] = None
            if f.get('exception_id'):
                row = st.db.execute('SELECT * FROM exceptions WHERE id = ?', (f['exception_id'],)).fetchone()
                f['exception'] = dict(row) if row else None
            f['type_title'] = common.TYPE_TITLES.get(f['type'], f['type'])
            for key in ('first_seen', 'last_seen'):
                f[key + '_iso'] = common.iso(f[key])
            return {'status': 'ok', 'finding': f}
        finally:
            st.close()

    def _series(self, st, f, now):
        """ data for the sparkline of the detail: {label, unit, points: [{t, v, b}]} (b = baseline) """
        host = f['host']
        if f['type'] == 'beaconing':
            times = (f.get('evidence') or {}).get('recent') or []
            med = (f.get('evidence') or {}).get('median_interval_s')
            return {'label': 'interval between connections', 'unit': 's',
                    'points': [{'t': b, 'v': b - a, 'b': med} for a, b in zip(times, times[1:])]}
        if f['type'] in ('dga', 'dns_tunnel', 'new_domain'):
            rows = st.db.execute('SELECT hour, nx, queries FROM host_dns_hour WHERE host = ? AND hour >= ? ORDER BY '
                                 'hour', (host, int(now - 48 * 3600))).fetchall()
            mean = st.db.execute('SELECT avg(nx) FROM host_dns_hour WHERE host = ? AND hour >= ?',
                                 (host, int(now - 7 * 86400))).fetchone()[0]
            return {'label': 'NXDOMAIN per hour', 'unit': '',
                    'points': [{'t': r[0], 'v': r[1], 'b': round(mean or 0, 1)} for r in rows]}
        return self._bytes_series(st, host, now, 48)

    def _bytes_series(self, st, host, now, hours):
        rows = st.db.execute('SELECT hour, bytes_out FROM host_hour WHERE host = ? AND hour >= ? ORDER BY hour',
                             (host, int(now - hours * 3600))).fetchall()
        base = {r[0]: r[1] for r in st.db.execute('SELECT slot, mean FROM vol_base WHERE host = ?', (host,))}
        return {'label': 'outbound bytes per hour', 'unit': 'B',
                'points': [{'t': r[0], 'v': r[1], 'b': round(base.get(self._slot(r[0]), base.get(-1, 0)) or 0)}
                           for r in rows]}

    def host(self, ip, now=None):
        """ profile: what is normal for this host vs. now (Explain host, host panel) """
        now = self.ctx.clock() if now is None else now
        st = self._ro()
        try:
            dev = st.db.execute('SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1', (ip,)).fetchone()
            seen = st.db.execute('SELECT first_seen, last_seen FROM hosts_seen WHERE host = ?', (ip,)).fetchone()
            series = self._bytes_series(st, ip, now, 7 * 24)
            current = int(now // 3600 * 3600)
            now_row = st.db.execute('SELECT bytes_out, bytes_in, flows, dsts FROM host_hour WHERE host = ? AND '
                                    'hour = ?', (ip, current)).fetchone()
            prev_row = st.db.execute('SELECT bytes_out, bytes_in, flows, dsts FROM host_hour WHERE host = ? AND '
                                     'hour = ?', (ip, current - 3600)).fetchone()
            slot = st.db.execute('SELECT n, mean, var FROM vol_base WHERE host = ? AND slot = ?',
                                 (ip, self._slot(current))).fetchone()
            all_ = st.db.execute('SELECT n, mean, var FROM vol_base WHERE host = ? AND slot = -1', (ip,)).fetchone()
            dns = st.db.execute('SELECT count(*), avg(queries), avg(nx), max(nx) FROM host_dns_hour WHERE host = ? '
                                'AND hour >= ?', (ip, int(now - 7 * 86400))).fetchone()
            dns_last = st.db.execute('SELECT queries, nx, txt FROM host_dns_hour WHERE host = ? ORDER BY hour DESC '
                                     'LIMIT 1', (ip,)).fetchone()
            countries = [{'country': r[0], 'bytes': r[1], 'first_seen': common.iso(r[2])} for r in st.db.execute(
                "SELECT value, bytes, first_seen FROM host_dest WHERE host = ? AND kind = 'country' ORDER BY bytes "
                "DESC LIMIT 10", (ip,))]
            asns = [{'asn': r[0], 'bytes': r[1]} for r in st.db.execute(
                "SELECT value, bytes FROM host_dest WHERE host = ? AND kind = 'asn' ORDER BY bytes DESC LIMIT 10",
                (ip,))]
            ports = {}
            for (top,) in st.db.execute('SELECT top FROM host_hour WHERE host = ? AND hour >= ?',
                                        (ip, int(now - 86400))):
                for dst, b in _top(top):
                    ports[dst] = ports.get(dst, 0) + b
            findings = [_brief(dict(r), now) for r in st.db.execute(
                'SELECT id, type, host, key, severity, score, status, title, detail, first_seen, last_seen, '
                'occurrences, mac, hostname FROM findings WHERE host = ? ORDER BY last_seen DESC LIMIT 30', (ip,))]
            counts = {
                'domains': st.db.execute('SELECT count(*) FROM host_domain WHERE host = ?', (ip,)).fetchone()[0],
                'ja4': st.db.execute('SELECT count(*) FROM host_ja4 WHERE host = ?', (ip,)).fetchone()[0],
                'pairs': st.db.execute('SELECT count(*) FROM pairs WHERE host = ?', (ip,)).fetchone()[0],
            }

            def stats(row):
                if not row:
                    return None
                return {'samples': row[0], 'mean': int(row[1]), 'std': int(max(row[2], 0) ** 0.5)}
            return {'status': 'ok', 'host': ip, 'generated': common.iso(now),
                    'device': dict(dev) if dev else None,
                    'first_seen': common.iso(seen[0]) if seen else None,
                    'last_seen': common.iso(seen[1]) if seen else None,
                    'normal': {'bytes_out_this_hour_of_day': stats(slot), 'bytes_out_any_hour': stats(all_),
                               'dns_hours': dns[0] if dns else 0,
                               'dns_queries_per_hour': round(dns[1] or 0, 1) if dns else 0,
                               'nxdomain_per_hour': round(dns[2] or 0, 1) if dns else 0,
                               'nxdomain_max_hour': dns[3] if dns else 0,
                               'countries': countries, 'asns': asns, **counts},
                    'now': {'hour': common.iso(current),
                            'bytes_out': now_row[0] if now_row else 0, 'bytes_in': now_row[1] if now_row else 0,
                            'flows': now_row[2] if now_row else 0, 'destinations': now_row[3] if now_row else 0,
                            'previous_hour_bytes_out': prev_row[0] if prev_row else 0,
                            'dns_last_hour': {'queries': dns_last[0], 'nx': dns_last[1], 'txt': dns_last[2]}
                            if dns_last else None,
                            'top_destinations_24h': sorted(({'address': k, 'bytes': v} for k, v in ports.items()),
                                                           key=lambda x: -x['bytes'])[:8]},
                    'series': series, 'findings': findings,
                    'actions': host_actions(ip)}
        finally:
            st.close()


# ---------------------------------------------------------------------------------------------- helpers


def match_exception(cand, exceptions):
    for exc in exceptions:
        if exc['type'] not in ('*', cand['type']):
            continue
        if exc['host'] not in ('*', cand['host'], cand.get('mac') or '\0'):
            continue
        if exc['key'] not in ('*', cand.get('key') or ''):
            continue
        return exc
    return None


def suggested_actions(f):
    """ deterministic buttons of a finding (the AI only explains; nothing runs by itself) """
    host = f['host']
    actions = [{'id': 'live_view', 'label': 'Open in Live View',
                'url': '/ui/diagnostics/firewall/log#field=src&operator==&value=%s' % host}]
    actions.append({'id': 'console', 'label': 'Ask the AI Console about this host',
                    'url': '/ui/policyanalyzer/console#host=%s' % host})
    ev = f.get('evidence') or {}
    external = None
    if f['type'] == 'beaconing':
        external = ev.get('destination')
    elif f['type'] == 'tls':
        external = ev.get('destination')
    elif f['type'] == 'volume' and ev.get('top'):
        external = ev['top'][0][0] if isinstance(ev['top'][0], (list, tuple)) else None
    elif f['type'] == 'rare_destination' and ev.get('items'):
        external = ev['items'][0].get('sample')
    if external and NetCfgPublic.is_public(external):
        actions.append({'id': 'quarantine', 'label': 'Quarantine %s (simulate first)' % external,
                        'target': external, 'change': {'action': 'quarantine_add', 'args': [external, 'auto']}})
    if f['type'] == 'internal_scan':
        actions.append({'id': 'live_view_dst', 'label': 'Blocked attempts of this host',
                        'url': '/ui/diagnostics/firewall/log#field=src&operator==&value=%s' % host})
    if f['status'] != 'expected':
        actions.append({'id': 'expect', 'label': 'Mark as expected'})
    actions.append({'id': 'host', 'label': 'Host profile', 'host': host})
    return actions


def host_actions(ip):
    return [{'id': 'live_view', 'label': 'Open in Live View',
             'url': '/ui/diagnostics/firewall/log#field=src&operator==&value=%s' % ip},
            {'id': 'console', 'label': 'Ask the AI Console about this host',
             'url': '/ui/policyanalyzer/console#host=%s' % ip}]


class NetCfgPublic:
    @staticmethod
    def is_public(text):
        ip = netcfg_mod.parse_ip(text)
        return netcfg_mod.NetConfig.is_external(ip)


def _port_family(port):
    """ the stable key of a beaconing service: the port below 1024, the hundred above (8810-8815 -> 88xx) """
    port = int(port or 0)
    return str(port) if port < 1024 else '%dxx' % (port // 100)


def _top(value):
    try:
        data = json.loads(value) if isinstance(value, str) else (value or [])
    except ValueError:
        return []
    return [tuple(x) for x in data if isinstance(x, (list, tuple)) and len(x) == 2]


def _ts(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    return sources._sqlite_ts(value)


def _brief(row, now):
    row['type_title'] = common.TYPE_TITLES.get(row.get('type'), row.get('type'))
    for key in ('first_seen', 'last_seen'):
        if key in row:
            row[key + '_iso'] = common.iso(row[key])
    if 'last_seen' in row:
        row['age_s'] = int(now - row['last_seen'])
    return row


def _sev_name(rank):
    return {3: 'high', 2: 'medium', 1: 'low'}.get(rank, 'info')


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _glob(pattern):
    import glob
    return glob.glob(pattern)


def _source_states(src):
    out = {}
    for name, value in src.items():
        if isinstance(value, dict):
            out[name] = 'missing' if value.get('missing') else ('error' if value.get('error') else
                                                                ('partial' if value.get('complete') is False else 'ok'))
    return out
