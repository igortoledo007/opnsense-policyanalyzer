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

    Local threat intelligence cache: CISA KEV (known exploited vulnerabilities) and FIRST EPSS (probability of
    exploitation in the next 30 days), each stored with the date it was collected.

      <db>/vulns/kev.json   {"version": 1, "fetched": ISO, "source": url, "catalog_version", "date_released",
                             "count", "items": {cve: {vendor, product, name, date_added, due, action,
                                                      ransomware, description}}}
      <db>/vulns/epss.json  {"version": 1, "fetched": ISO, "source": url, "items": {cve: {epss, percentile,
                                                                                         date, fetched}}}

    The network is used only by the change action "vulns_intel_update" (explicit button with simulation).
    Without the files, the cache of the exposure feeds (vuln-cache/, written when the exposure report ran
    online) is used read only. Privacy: KEV is one public file (nothing about the firewall is sent); EPSS
    receives only the CVE ids of the inventory, in batches of 100. HTTPS, verified TLS, no proxy, no redirect,
    size cap (exposure/feeds.py http_get).
"""

import hashlib
import os
import shutil

from . import common

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://api.first.org/data/v1/epss?cve={cves}'
EPSS_BATCH = 100
EPSS_MAX_REQUESTS = 10
STALE_DAYS = 7


def _http_get(url, timeout=45):
    from exposure import feeds          # same rules as the exposure feeds (https, no redirect, verified TLS)
    return feeds.http_get(url, timeout=timeout)


# ------------------------------------------------------------------ read

def _feed_cache(feed_id, key):
    path = os.path.join(common.paths()['feed_cache'], feed_id,
                        hashlib.sha1(key.encode()).hexdigest()[:24] + '.json')
    entry = common.load_json(path)
    if not isinstance(entry, dict) or entry.get('key') != key:
        return None, None
    return entry.get('data'), entry.get('fetched')


def load_kev():
    """ :return: (items {cve: info}, meta) """
    doc = common.load_json(common.paths()['kev'])
    if isinstance(doc, dict) and isinstance(doc.get('items'), dict):
        return doc['items'], {'available': True, 'source': 'local', 'fetched': doc.get('fetched'),
                              'count': len(doc['items']), 'catalog_version': doc.get('catalog_version'),
                              'date_released': doc.get('date_released'), 'url': doc.get('source')}
    data, fetched = _feed_cache('cisa_kev', 'all')
    if isinstance(data, dict) and data:
        items = {cve: {'name': v.get('kev_name'), 'date_added': v.get('kev_date_added'), 'due': v.get('kev_due'),
                       'action': v.get('kev_action'), 'ransomware': bool(v.get('kev_ransomware')),
                       'vendor': None, 'product': None, 'description': None}
                 for cve, v in data.items() if common.CVE_RE.match(cve)}
        return items, {'available': True, 'source': 'exposure_cache', 'fetched': common.iso(float(fetched))
                       if fetched else None, 'count': len(items), 'catalog_version': None,
                       'date_released': None, 'url': KEV_URL}
    return {}, {'available': False, 'source': None, 'fetched': None, 'count': 0, 'url': KEV_URL}


def load_epss(cves=()):
    """ :return: (items {cve: info}, meta) ; exposure feed cache fills the CVEs the local file lacks """
    doc = common.load_json(common.paths()['epss']) or {}
    items = dict(doc.get('items') or {}) if isinstance(doc, dict) else {}
    source = 'local' if items else None
    for cve in cves:
        if cve in items:
            continue
        data, fetched = _feed_cache('first_epss', cve)
        if isinstance(data, dict) and data.get('epss') is not None:
            items[cve] = {'epss': data.get('epss'), 'percentile': data.get('epss_percentile'),
                          'date': data.get('epss_date'),
                          'fetched': common.iso(float(fetched)) if fetched else None}
            source = source or 'exposure_cache'
    return items, {'available': bool(items), 'source': source, 'fetched': doc.get('fetched') if doc else None,
                   'count': len(items), 'url': EPSS_URL.split('?')[0]}


def _age_days(fetched):
    ts = common.parse_iso(fetched)
    return None if ts is None else round((common.now() - ts) / 86400.0, 1)


def status(cves=()):
    _kev, kev_meta = load_kev()
    epss, epss_meta = load_epss(cves)
    out = {}
    for name, meta in (('kev', kev_meta), ('epss', epss_meta)):
        meta = dict(meta)
        meta['age_days'] = _age_days(meta.get('fetched'))
        meta['stale'] = meta['age_days'] is not None and meta['age_days'] > STALE_DAYS
        out[name] = meta
    out['epss']['covered'] = sum(1 for c in cves if c in epss)
    out['epss']['missing'] = sorted(c for c in cves if c not in epss)
    out['network'] = 'only through "Update KEV/EPSS" (explicit action with simulation)'
    return out


# ------------------------------------------------------------------ download (change action only)

def parse_kev_full(doc):
    items = {}
    for item in (doc or {}).get('vulnerabilities') or []:
        cve = (item.get('cveID') or '').strip()
        if not common.CVE_RE.match(cve):
            continue
        items[cve] = {'vendor': (item.get('vendorProject') or '')[:80] or None,
                      'product': (item.get('product') or '')[:80] or None,
                      'name': (item.get('vulnerabilityName') or '')[:200] or None,
                      'date_added': item.get('dateAdded'), 'due': item.get('dueDate'),
                      'action': (item.get('requiredAction') or '')[:300] or None,
                      'ransomware': (item.get('knownRansomwareCampaignUse') or '').lower() == 'known',
                      'description': (item.get('shortDescription') or '')[:500] or None}
    if not items:
        raise ValueError('the KEV catalogue is empty or not in the expected format')
    return {'version': 1, 'fetched': common.iso(), 'source': KEV_URL,
            'catalog_version': (doc or {}).get('catalogVersion'), 'date_released': (doc or {}).get('dateReleased'),
            'count': len(items), 'items': items}


def _f(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def fetch_epss(cves, get=None):
    """ :return: ({cve: info}, errors, requests) for the given CVE ids only """
    get = get or _http_get
    cves = sorted({c for c in cves if common.CVE_RE.match(c)})
    items, errors, requests = {}, [], 0
    for idx in range(0, len(cves), EPSS_BATCH):
        if requests >= EPSS_MAX_REQUESTS:
            errors.append('%d CVEs left for the next update (request limit)' % (len(cves) - idx))
            break
        group = cves[idx:idx + EPSS_BATCH]
        requests += 1
        try:
            doc = get(EPSS_URL.replace('{cves}', ','.join(group)))
        except Exception as exc:            # noqa: BLE001 - FeedError and anything from the transport
            errors.append(str(exc)[:200])
            continue
        for row in (doc or {}).get('data') or []:
            cve = row.get('cve')
            if cve in group:
                items[cve] = {'epss': _f(row.get('epss')), 'percentile': _f(row.get('percentile')),
                              'date': row.get('date'), 'fetched': common.iso()}
    return items, errors, requests


def _backup(path):
    """ keep the previous file for the revert; returns the backup path or None """
    if not os.path.exists(path):
        return None
    backup = path + '.previous'
    shutil.copy2(path, backup)
    os.chmod(backup, 0o640)
    return backup


def plan_update(which, cves):
    kev_items, kev_meta = load_kev()
    epss, epss_meta = load_epss(cves)
    steps, info = [], []
    p = common.paths()
    if which in ('kev', 'all'):
        steps.append({'description': 'Download the CISA KEV catalogue (one public JSON file, ~1-2 MB)',
                      'command': 'GET %s' % KEV_URL,
                      'effect': 'stored in %s (current: %s)' % (p['kev'], kev_meta.get('fetched') or 'none')})
        info.append('KEV: nothing about this firewall is sent, the whole catalogue is downloaded.')
    if which in ('epss', 'all'):
        if cves:
            batches = (len(cves) + EPSS_BATCH - 1) // EPSS_BATCH
            steps.append({'description': 'Ask FIRST EPSS for the %d CVE id(s) of the inventory (%d request(s))'
                                         % (len(cves), min(batches, EPSS_MAX_REQUESTS)),
                          'command': 'GET %s' % EPSS_URL.replace('{cves}', ','.join(sorted(cves)[:5]) +
                                                                 (',...' if len(cves) > 5 else '')),
                          'effect': 'stored in %s (%d of %d CVEs cached now)'
                                    % (p['epss'], sum(1 for c in cves if c in epss), len(cves))})
            info.append('EPSS: only these CVE ids leave the firewall: %s.' % ', '.join(sorted(cves)[:40]) +
                        (' ...' if len(cves) > 40 else ''))
        else:
            info.append('EPSS: the inventory has no CVE, nothing to ask.')
    return {'status': 'ok', 'steps': steps, 'risk': 'low' if steps else 'none',
            'warnings': ['Uses the internet: HTTPS with verified certificates, no proxy, no redirect, 32 MiB cap.'],
            'revert': ['Undo restores the previous cache files (or removes them when there were none).'],
            'info': [{'title': 'What leaves the firewall', 'items': info}],
            'kev_count_now': len(kev_items), 'epss_count_now': len(epss)}


def apply_update(which, cves, get=None):
    get = get or _http_get
    p = common.paths()
    completed, errors, state = [], [], {'files': {}}
    if which in ('kev', 'all'):
        try:
            doc = parse_kev_full(get(KEV_URL))
            state['files'][p['kev']] = _backup(p['kev'])
            common.write_json(p['kev'], doc)
            completed.append('KEV catalogue stored (%d entries, catalogue %s)' % (doc['count'],
                                                                                 doc.get('catalog_version') or '?'))
        except Exception as exc:            # noqa: BLE001
            errors.append('KEV: %s' % str(exc)[:200])
    if which in ('epss', 'all') and cves:
        items, errs, requests = fetch_epss(cves, get)
        errors.extend('EPSS: %s' % e for e in errs)
        if items:
            current = common.load_json(p['epss']) or {}
            merged = dict(current.get('items') or {})
            merged.update(items)
            state['files'][p['epss']] = _backup(p['epss'])
            common.write_json(p['epss'], {'version': 1, 'fetched': common.iso(), 'source': EPSS_URL.split('?')[0],
                                          'items': merged})
            completed.append('EPSS stored for %d CVE(s) in %d request(s)' % (len(items), requests))
    return {'status': 'ok' if completed else 'error', 'done': bool(completed) and not errors,
            'completed': completed, 'warnings': errors, 'state': state,
            'message': '; '.join(errors) if errors and not completed else None, 'steps': []}


def revert_update(entry):
    completed = []
    for path, backup in ((entry.get('state') or {}).get('files') or {}).items():
        if not path.startswith(common.paths()['intel']):
            continue
        if backup and os.path.exists(backup):
            os.replace(backup, path)
            completed.append('restored %s' % path)
        elif not backup and os.path.exists(path):
            os.unlink(path)
            completed.append('removed %s' % path)
    return {'status': 'ok', 'done': True, 'completed': completed, 'steps': []}
