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

    The scan: merges the passive sources per MAC address, classifies, assesses the risk and records the history
    in devices.db. Only LAN side interfaces count (WAN devices are skipped). Reads the firewall, writes only the
    plugin database. Reverse DNS goes to the local resolver only, at most DNS_PER_SCAN lookups per scan, cached
    for 24 h.
"""

import ipaddress
import json
import os
import time

from . import classify, common, oui, risk, sources, store

DNS_PER_SCAN = 40
DNS_TTL = 86400
PRESENT_S = 900
FRESH_S = 600


def _kev_counts():
    data = common.load_json(common.paths()['kev']) or {}
    return risk.kev_vendor_counts(data.get('items') if isinstance(data, dict) else {})


def _iface_for_ip(ip, ifaces):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for dev, info in ifaces.items():
        for net in info['networks']:
            if addr in ipaddress.ip_network(net):
                return dev
    return None


def collect(run=None, now=None, dns=True):
    """ :return: (devices {mac: merged record}, sources state) without touching the database """
    run = run or common.Runner()
    now = common.now() if now is None else now
    root = sources.load_config()
    ifaces = sources.interfaces(root)
    wan_devs = {d for d, i in ifaces.items() if i['wan']}
    hw, hw_state = sources.hostwatch()
    leases, kea_state = sources.kea_leases()
    reservations = sources.kea_reservations(root)
    dmq = sources.dnsmasq_leases()
    arp = sources.arp(run)
    merged = {}

    def slot(mac):
        return merged.setdefault(mac, {'mac': mac, 'ips': set(), 'first_seen': None, 'last_seen': None,
                                       'dev': None, 'vendor_hw': None, 'hostname': None, 'hostname_source': None,
                                       'present': False, 'sources': set()})

    for rec in hw:
        if rec['dev'] in wan_devs:
            continue
        d = slot(rec['mac'])
        d['ips'].add(rec['ip'])
        d['sources'].add('hostwatch')
        if rec['first_seen'] and (d['first_seen'] is None or rec['first_seen'] < d['first_seen']):
            d['first_seen'] = rec['first_seen']
        if rec['last_seen'] and (d['last_seen'] is None or rec['last_seen'] > d['last_seen']):
            d['last_seen'], d['dev'] = rec['last_seen'], rec['dev']
        d['vendor_hw'] = d['vendor_hw'] or rec['vendor']
    for mac, rec in arp.items():
        if rec['dev'] in wan_devs:
            continue
        d = slot(mac)
        d['ips'].add(rec['ip'])
        d['present'] = True
        d['sources'].add('arp')
        d['dev'] = d['dev'] or rec['dev']
        d['last_seen'] = max(d['last_seen'] or 0, int(now))
        d['first_seen'] = d['first_seen'] or int(now)
    for table, name in ((leases, 'kea'), (dmq, 'dnsmasq')):
        for mac, rec in table.items():
            if mac not in merged:
                continue                  # a lease alone (device gone) does not create a device
            d = merged[mac]
            d['sources'].add(name)
            if rec.get('hostname') and not d['hostname']:
                d['hostname'], d['hostname_source'] = rec['hostname'], 'dhcp lease'
    for mac, rec in reservations.items():
        if mac in merged and rec.get('hostname'):
            merged[mac]['hostname'], merged[mac]['hostname_source'] = rec['hostname'], 'dhcp reservation'
            merged[mac]['sources'].add('reservation')
    overrides = sources.host_overrides(root)
    for d in merged.values():
        if d['dev'] is None:
            d['dev'] = next((x for x in (_iface_for_ip(ip, ifaces) for ip in d['ips']) if x), None)
        if not d['hostname']:
            name = next((overrides[ip] for ip in sorted(d['ips']) if ip in overrides), None)
            if name:
                d['hostname'], d['hostname_source'] = name, 'dns override'
        if d['last_seen'] and now - d['last_seen'] < PRESENT_S:
            d['present'] = True
    state = {'hostwatch': hw_state, 'kea': kea_state, 'arp': {'available': bool(arp), 'entries': len(arp)},
             'reservations': len(reservations), 'dnsmasq': len(dmq), 'interfaces': ifaces, 'dns': dns,
             'forwards': sources.port_forwards(root)}
    return merged, state


def scan(run=None, now=None, dns=True, db=None):
    run = run or common.Runner()
    now = int(common.now() if now is None else now)
    started = time.monotonic()
    merged, state = collect(run, now, dns)
    vendors = oui.OUI()
    kev = _kev_counts()
    own_db = db is None
    db = db or store.connect()
    counts = {'devices': 0, 'new': 0, 'changed': 0, 'dns_lookups': 0}
    try:
        cache = {r[0]: (r[1], r[2]) for r in db.execute('SELECT ip, name, resolved_at FROM dns')}
        for mac, d in sorted(merged.items()):
            row = db.execute('SELECT %s FROM devices WHERE mac = ?' % ', '.join(store.COLUMNS), (mac,)).fetchone()
            old = store.row_dict(row) if row else None
            if not d['hostname'] and dns:
                for ip in sorted(d['ips']):
                    name, ts = cache.get(ip, (None, None))
                    if (ts is None or now - ts > DNS_TTL) and counts['dns_lookups'] < DNS_PER_SCAN:
                        name = sources.reverse_dns(run, ip)
                        counts['dns_lookups'] += 1
                        db.execute('INSERT OR REPLACE INTO dns (ip, name, resolved_at) VALUES (?, ?, ?)',
                                   (ip, name, now))
                    if name:
                        d['hostname'], d['hostname_source'] = name, 'reverse dns'
                        break
            vendor = vendors.vendor(mac) or d['vendor_hw']
            rnd = common.randomized(mac)
            if rnd and not vendor:
                vendor = None
            auto = classify.classify(vendor, d['hostname'], rnd)
            ip4 = sorted((ip for ip in d['ips'] if ':' not in ip), key=lambda x: ipaddress.ip_address(x))
            ip6 = sorted(ip for ip in d['ips'] if ':' in ip)
            seen = [x for x in (d['first_seen'], old and old['first_seen']) if x]
            first = min(seen) if seen else now
            known = bool(old and old['known'])
            eff_type = (old and old['user_type']) or auto['type']
            assessed = risk.assess({'vendor': vendor, 'type': eff_type, 'known': known, 'first_seen': first,
                                    'ips': list(d['ips'])}, kev, state['forwards'], now)
            iface = state['interfaces'].get(d['dev'] or '', {})
            values = {'mac': mac, 'first_seen': first, 'last_seen': d['last_seen'] or (old and old['last_seen']) or now,
                      'hostname': d['hostname'] or (old and old['hostname']),
                      'hostname_source': d['hostname_source'] or (old and old['hostname_source']),
                      'vendor': vendor, 'randomized': int(rnd), 'iface': d['dev'],
                      'iface_descr': iface.get('descr') or d['dev'], 'ip4': ','.join(ip4), 'ip6': ','.join(ip6[:8]),
                      'auto_type': auto['type'], 'auto_confidence': auto['confidence'],
                      'auto_why': json.dumps(auto['why']), 'risk': assessed['level'],
                      'risk_reasons': json.dumps(assessed['reasons']), 'present': int(d['present']), 'updated': now}
            if old is None:
                cols = ', '.join(values)
                cur = db.execute('INSERT INTO devices (%s) VALUES (%s)' % (cols, ', '.join('?' * len(values))),
                                 tuple(values.values()))
                dev_id = cur.lastrowid
                store.event(db, now, dev_id, 'new', None, ', '.join(ip4 + ip6[:1]),
                            'first seen %s via %s' % (common.iso(first), '+'.join(sorted(d['sources']))))
                counts['new'] += 1
            else:
                dev_id = old['id']
                if set(old['ip4']) != set(ip4):
                    store.event(db, now, dev_id, 'ip', ','.join(old['ip4']), ','.join(ip4))
                if values['hostname'] != old['hostname']:
                    store.event(db, now, dev_id, 'hostname', old['hostname'], values['hostname'])
                if vendor != old['vendor']:
                    store.event(db, now, dev_id, 'vendor', old['vendor'], vendor)
                if any(values[k] != (','.join(old[k]) if k in ('ip4', 'ip6') else old[k])
                       for k in ('hostname', 'vendor', 'ip4', 'risk', 'auto_type')):
                    counts['changed'] += 1
                sets = ', '.join('%s = ?' % k for k in values if k != 'mac')
                db.execute('UPDATE devices SET %s WHERE id = ?' % sets,
                           tuple(v for k, v in values.items() if k != 'mac') + (dev_id,))
            for ip in d['ips']:
                db.execute('INSERT INTO ips (device_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?) '
                           'ON CONFLICT (device_id, ip) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen)',
                           (dev_id, ip, first, values['last_seen']))
            counts['devices'] += 1
        db.execute('UPDATE devices SET present = 0 WHERE mac NOT IN (%s)' % ','.join('?' * len(merged)) if merged
                   else 'UPDATE devices SET present = 0', tuple(merged))
        sources_state = {k: v for k, v in state.items() if k not in ('interfaces', 'forwards')}
        sources_state['oui'] = vendors.status()
        store.meta_set(db, 'last_scan', now)
        store.meta_set(db, 'sources', json.dumps(sources_state))
        db.commit()
    finally:
        if own_db:
            db.close()
    counts['duration_ms'] = int((time.monotonic() - started) * 1000)
    return dict(counts, status='ok', scanned_at=common.iso(now))


def ensure_fresh(run=None, max_age=FRESH_S, now=None):
    """ scan when the last one is older than max_age (the list and the reports call this) """
    now = common.now() if now is None else now
    path = common.paths()['devices_db']
    last = None
    if os.path.exists(path):
        db = store.connect(readonly=True)
        try:
            last = int(store.meta_get(db, 'last_scan', 0) or 0)
        except Exception:                 # noqa: BLE001 - an old or broken file: scan again
            last = None
        finally:
            db.close()
    if last and now - last < max_age:
        return None
    return scan(run, now)
