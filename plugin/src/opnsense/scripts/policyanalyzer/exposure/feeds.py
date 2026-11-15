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

    Registry of online vulnerability sources, fetching with a cache, and one parser per source type.

    Registry (merged by "id", later sources win):
      1. DEFAULT_FEEDS below;
      2. config.xml //OPNsense/policyanalyzer/exposure/feeds/feed (model to be added by the GUI side):
         <feed><id/><name/><url/><type/><enabled/><ttl/><max_requests/><interval/></feed>;
      3. /var/db/policyanalyzer/feeds.json  {"feeds": [{...same keys...}]}  (handy for tests and lab use).
    Each feed: id, name, url, type (parser), enabled, ttl (s), mode (bulk | batch | per_cve), batch,
    max_requests per run, interval between requests (s).

    Privacy: bulk feeds are fetched from a fixed URL; batch / per_cve URLs may only contain the {cve} / {cves}
    placeholders, filled with validated CVE ids. Nothing else about the firewall is ever sent. HTTPS only,
    certificates verified (system store /usr/local/etc/ssl/cert.pem), no proxy, no redirects, size cap.
    The network is used only when the caller asks for it (online=1); offline runs read the cache only.
"""

import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from . import common, cvss

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
ID_RE = re.compile(r'^[a-z][a-z0-9_]{1,31}$')
USER_AGENT = 'os-policyanalyzer-exposure/1'
MAX_BYTES = 32 * 1024 * 1024
TTL_MIN, TTL_MAX = 3600, 30 * 86400
DAY = 86400

DEFAULT_FEEDS = [
    {'id': 'cisa_kev', 'name': 'CISA Known Exploited Vulnerabilities', 'type': 'kev', 'mode': 'bulk',
     'url': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
     'enabled': True, 'ttl': DAY},
    {'id': 'first_epss', 'name': 'FIRST EPSS', 'type': 'epss', 'mode': 'batch', 'batch': 100,
     'url': 'https://api.first.org/data/v1/epss?cve={cves}', 'enabled': True, 'ttl': DAY, 'max_requests': 10},
    {'id': 'nvd', 'name': 'NIST NVD 2.0', 'type': 'nvd', 'mode': 'per_cve',
     'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}', 'enabled': True, 'ttl': DAY,
     # public rate limit without an API key: 5 requests per rolling 30 s window
     'max_requests': 20, 'interval': 6.5},
    {'id': 'osv', 'name': 'OSV.dev', 'type': 'osv', 'mode': 'per_cve',
     'url': 'https://api.osv.dev/v1/vulns/{cve}', 'enabled': True, 'ttl': DAY, 'max_requests': 100},
    {'id': 'opnsense_ghsa', 'name': 'OPNsense core security advisories (GitHub)', 'type': 'ghsa_opnsense',
     'mode': 'bulk', 'url': 'https://api.github.com/repos/opnsense/core/security-advisories?per_page=100',
     'enabled': True, 'ttl': DAY},
]


class FeedError(Exception):
    pass


class NotFound(FeedError):
    pass


# ------------------------------------------------------------------ registry

def _bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('1', 'yes', 'true', 'on')


def validate(feed):
    """ normalized copy of a feed definition; raises ValueError """
    out = dict(feed)
    if not ID_RE.match(str(out.get('id', ''))):
        raise ValueError('invalid feed id')
    if out.get('type') not in PARSERS:
        raise ValueError('unknown feed type "%s"' % out.get('type'))
    out.setdefault('mode', PARSER_MODE[out['type']])
    if out['mode'] != PARSER_MODE[out['type']]:
        raise ValueError('feed type %s needs mode %s' % (out['type'], PARSER_MODE[out['type']]))
    url = str(out.get('url', ''))
    if not url.startswith('https://') or any(c in url for c in ' \r\n'):
        raise ValueError('feed url must be https')
    placeholders = set(re.findall(r'\{[^}]*\}', url))
    allowed = {'bulk': set(), 'batch': {'{cves}'}, 'per_cve': {'{cve}'}}[out['mode']]
    if placeholders != allowed:
        raise ValueError('feed url placeholders must be %s' % (sorted(allowed) or 'none'))
    out['url'] = url
    out['name'] = str(out.get('name') or out['id'])[:120]
    out['enabled'] = _bool(out.get('enabled', True))
    try:
        out['ttl'] = max(TTL_MIN, min(TTL_MAX, int(out.get('ttl') or DAY)))
        out['max_requests'] = max(1, min(1000, int(out.get('max_requests') or 50)))
        out['interval'] = max(0.0, min(60.0, float(out.get('interval') or 0)))
        out['batch'] = max(1, min(200, int(out.get('batch') or 100)))
    except (TypeError, ValueError):
        raise ValueError('invalid numeric field')
    return out


def _config_feeds(config_path):
    try:
        root = ET.parse(config_path).getroot()
    except (OSError, ET.ParseError, TypeError, AttributeError):
        return []
    feeds = []
    for node in root.findall('./OPNsense/policyanalyzer/exposure/feeds/feed'):
        feeds.append({child.tag: (child.text or '').strip() for child in node})
    return feeds


def _file_feeds(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    items = data.get('feeds') if isinstance(data, dict) else data
    return [f for f in items or [] if isinstance(f, dict)]


def registry(config_path=None, file_path=None):
    """ :return: (feeds by id in order, errors) """
    config_path = config_path or common.CONFIG_XML
    file_path = file_path or os.path.join(common.DB_DIR, 'feeds.json')
    merged = {}
    order = []
    errors = []
    for origin, items in (('default', DEFAULT_FEEDS), ('config', _config_feeds(config_path)),
                          ('file', _file_feeds(file_path))):
        for item in items:
            base = dict(merged.get(item.get('id'), {}))
            base.update({k: v for k, v in item.items() if v not in ('', None)})
            try:
                feed = validate(base)
            except ValueError as exc:
                errors.append({'id': item.get('id'), 'origin': origin, 'error': str(exc)})
                continue
            feed['origin'] = origin
            if feed['id'] not in merged:
                order.append(feed['id'])
            merged[feed['id']] = feed
    return [merged[i] for i in order], errors


# ------------------------------------------------------------------ http + cache

def ssl_context():
    ctx = ssl.create_default_context()
    if not ctx.get_ca_certs():
        for cafile in common.CA_FILES:
            if os.path.isfile(cafile):
                try:
                    ctx.load_verify_locations(cafile=cafile)
                    break
                except (OSError, ssl.SSLError):
                    continue
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'redirect refused', headers, fp)


def http_get(url, timeout=10):
    """ GET url -> parsed JSON """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ssl_context()), _NoRedirect())
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/json'})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise NotFound('not found')
        raise FeedError('HTTP %s' % exc.code)
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        raise FeedError(str(getattr(exc, 'reason', exc))[:200])
    if len(body) > MAX_BYTES:
        raise FeedError('response too large')
    try:
        return json.loads(body.decode('utf-8'))
    except ValueError:
        raise FeedError('invalid JSON')


class Fetcher(object):
    """ cache in <cache_dir>/<feed id>/<key hash>.json = {"fetched": ts, "key": ..., "data": ...} """

    def __init__(self, cache_dir=None, online=False, write_cache=True, get=None, clock=time.time,
                 sleep=time.sleep, timeout=10):
        self.cache_dir = cache_dir or os.path.join(common.DB_DIR, 'vuln-cache')
        self.online = online
        self.write_cache = write_cache
        self.get = get or http_get
        self.clock = clock
        self.sleep = sleep
        self.timeout = timeout

    def _path(self, feed, key):
        return os.path.join(self.cache_dir, feed['id'], hashlib.sha1(key.encode()).hexdigest()[:24] + '.json')

    def cached(self, feed, key):
        """ (data, fresh) or (None, False) """
        try:
            with open(self._path(feed, key)) as handle:
                entry = json.load(handle)
        except (OSError, ValueError):
            return None, False
        if entry.get('key') != key:
            return None, False
        return entry.get('data'), (self.clock() - float(entry.get('fetched', 0))) < feed['ttl']

    def store(self, feed, key, data):
        if not self.write_cache:
            return
        path = self._path(feed, key)
        directory = os.path.dirname(path)
        try:
            os.makedirs(directory, mode=0o750, exist_ok=True)
            tmp = path + '.tmp'
            with open(tmp, 'w') as handle:
                json.dump({'fetched': self.clock(), 'key': key, 'data': data}, handle)
            os.chmod(tmp, 0o640)
            os.replace(tmp, path)
        except OSError:
            pass

    def fetch(self, url):
        return self.get(url, timeout=self.timeout)


# ------------------------------------------------------------------ parsers (raw JSON -> {cve: partial})

def _f(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_kev(doc):
    out = {}
    for item in (doc or {}).get('vulnerabilities') or []:
        cve = item.get('cveID')
        if not cve or not CVE_RE.match(cve):
            continue
        out[cve] = {'kev': True, 'kev_date_added': item.get('dateAdded'), 'kev_due': item.get('dueDate'),
                    'kev_name': item.get('vulnerabilityName'), 'kev_action': (item.get('requiredAction') or '')[:300] or None,
                    'kev_ransomware': (item.get('knownRansomwareCampaignUse') or '').lower() == 'known'}
    return out


def parse_epss(doc):
    out = {}
    for item in (doc or {}).get('data') or []:
        cve = item.get('cve')
        if cve and CVE_RE.match(cve):
            out[cve] = {'epss': _f(item.get('epss')), 'epss_percentile': _f(item.get('percentile')),
                        'epss_date': item.get('date')}
    return out


NVD_METRICS = ('cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2')


def parse_nvd(doc):
    out = {}
    for wrapper in (doc or {}).get('vulnerabilities') or []:
        cve = (wrapper or {}).get('cve') or {}
        cid = cve.get('id')
        if not cid or not CVE_RE.match(cid):
            continue
        rec = {}
        metrics = cve.get('metrics') or {}
        for key in NVD_METRICS:
            entries = metrics.get(key) or []
            if not entries:
                continue
            entry = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
            data = entry.get('cvssData') or {}
            score = _f(data.get('baseScore'))
            if score is None:
                continue
            rec.update(cvss=score, cvss_version=data.get('version'), cvss_vector=data.get('vectorString'),
                       severity=(data.get('baseSeverity') or entry.get('baseSeverity') or
                                 cvss.severity(score) or '').lower() or None)
            break
        text = next((d.get('value') for d in cve.get('descriptions') or [] if d.get('lang') == 'en'), None)
        if text:
            rec['summary'] = text.strip()[:600]
        refs = [r.get('url') for r in cve.get('references') or [] if r.get('url')]
        if refs:
            rec['refs'] = refs[:8]
        if cve.get('published'):
            rec['published'] = cve.get('published')
        weak = [d.get('value') for w in cve.get('weaknesses') or [] for d in w.get('description') or []
                if d.get('value', '').startswith('CWE-')]
        if weak:
            rec['cwe'] = sorted(set(weak))
        out[cid] = rec
    return out


def parse_osv(doc):
    doc = doc or {}
    ids = [doc.get('id')] + list(doc.get('aliases') or [])
    cid = next((i for i in ids if i and CVE_RE.match(i)), None)
    if cid is None:
        return {}
    rec = {}
    for sev in doc.get('severity') or []:
        vector = sev.get('score') or ''
        if sev.get('type') == 'CVSS_V3':
            score = cvss.v3_base_score(vector)
            if score is not None:
                rec.update(cvss=score, cvss_version=vector.split('/')[0].split(':')[1], cvss_vector=vector,
                           severity=cvss.severity(score))
                break
        elif sev.get('type') == 'CVSS_V4' and 'cvss_vector' not in rec:
            rec.update(cvss_vector=vector, cvss_version='4.0')
    summary = doc.get('summary') or (doc.get('details') or '').strip().split('\n')[0]
    if summary:
        rec['summary'] = summary.strip()[:600]
    refs = [r.get('url') for r in doc.get('references') or [] if r.get('url')]
    if refs:
        rec['refs'] = refs[:8]
    if doc.get('published'):
        rec['published'] = doc.get('published')
    return {cid: rec}


def parse_ghsa_opnsense(doc):
    """ list of advisories (not keyed by CVE: many OPNsense advisories have no CVE id) """
    out = []
    for adv in doc if isinstance(doc, list) else []:
        if not isinstance(adv, dict) or not adv.get('ghsa_id'):
            continue
        ranges = [(v.get('vulnerable_version_range') or '', v.get('patched_versions') or '')
                  for v in adv.get('vulnerabilities') or [] if isinstance(v, dict)]
        cve = adv.get('cve_id') if adv.get('cve_id') and CVE_RE.match(adv.get('cve_id')) else None
        score = _f((adv.get('cvss') or {}).get('score'))
        out.append({'id': adv['ghsa_id'], 'cve': cve, 'severity': (adv.get('severity') or '').lower() or None,
                    'cvss': score, 'summary': (adv.get('summary') or '')[:300], 'url': adv.get('html_url'),
                    'published': adv.get('published_at'), 'ranges': ranges})
    return out


PARSERS = {'kev': parse_kev, 'epss': parse_epss, 'nvd': parse_nvd, 'osv': parse_osv,
           'ghsa_opnsense': parse_ghsa_opnsense}
PARSER_MODE = {'kev': 'bulk', 'epss': 'batch', 'nvd': 'per_cve', 'osv': 'per_cve', 'ghsa_opnsense': 'bulk'}


# ------------------------------------------------------------------ OPNsense version matching

def _vtuple(text):
    """ '26.7.8_2' -> (26, 7, 8, 0, 0) ; '26.4.2p5' -> (26, 4, 2, 0, 5) ; None when not a version """
    match = re.search(r'(\d+(?:\.\d+)*)(?:p(\d+))?', text or '')
    if not match:
        return None
    nums = [int(x) for x in match.group(1).split('.')][:4]
    nums += [0] * (4 - len(nums))
    return tuple(nums) + (int(match.group(2) or 0),)


def opnsense_affected(advisory, version):
    """ True / False / None (can not tell). Ranges are interpreted per release series (26.7, 26.4...):
        GitHub advisories of opnsense/core list one constraint per series separated by commas. """
    current = _vtuple(version)
    if current is None:
        return None
    series = current[:2]
    decided = None
    seen_series = set()
    for vulnerable, patched in advisory.get('ranges') or []:
        for token in [t.strip() for t in patched.split(',') if t.strip()]:
            pv = _vtuple(token)
            if pv:
                seen_series.add(pv[:2])
            if pv and pv[:2] == series:
                return current < pv
        for token in [t.strip() for t in vulnerable.split(',') if t.strip()]:
            match = re.match(r'^(<=|<|>=|>|=)?\s*(.*)$', token)
            op, ver = match.group(1) or '=', match.group(2)
            vv = _vtuple(ver)
            if vv is not None:
                seen_series.add(vv[:2])
            if vv is None or vv[:2] != series:
                continue
            if op == '<=':
                hit = current <= vv
            elif op == '<':
                hit = current < vv
            elif op == '=':
                hit = current[:4] == vv[:4] and current[4] == vv[4]
            else:
                continue
            decided = hit or bool(decided)
    if decided is None and seen_series and all(x < series for x in seen_series):
        return False            # only older release series are listed: fixed before this series
    return decided


# ------------------------------------------------------------------ enrichment

def _chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def run_feed(feed, cves, fetcher):
    """ :return: (data, status). data: {cve: partial} (or list of advisories for ghsa) """
    status = {'id': feed['id'], 'name': feed['name'], 'type': feed['type'], 'enabled': feed['enabled'],
              'origin': feed.get('origin', 'default'), 'requests': 0, 'cache_hits': 0, 'stale': 0,
              'errors': [], 'deferred': 0, 'items': 0}
    if not feed['enabled']:
        status['state'] = 'disabled'
        return ({} if feed['mode'] != 'bulk' or feed['type'] != 'ghsa_opnsense' else []), status
    parser = PARSERS[feed['type']]
    if feed['mode'] == 'bulk':
        data, fresh = fetcher.cached(feed, 'all')
        if data is not None and (fresh or not fetcher.online):
            status['cache_hits'] += 1
            status['stale'] += 0 if fresh else 1
        elif fetcher.online:
            try:
                status['requests'] += 1
                data = parser(fetcher.fetch(feed['url']))
                fetcher.store(feed, 'all', data)
            except FeedError as exc:
                status['errors'].append(str(exc))
                stale, _fresh = fetcher.cached(feed, 'all')
                data = stale
                if stale is not None:
                    status['stale'] += 1
        if data is None:
            data = [] if feed['type'] == 'ghsa_opnsense' else {}
        if isinstance(data, dict):
            data = {c: data[c] for c in cves if c in data}
        status['items'] = len(data)
        status['state'] = _state(status, fetcher)
        return data, status
    # per CVE / batch: cache per CVE, fetch only what is missing or expired
    result = {}
    missing = []
    for cve in cves:
        data, fresh = fetcher.cached(feed, cve)
        if data is not None and (fresh or not fetcher.online):
            status['cache_hits'] += 1
            status['stale'] += 0 if fresh else 1
            if data:
                result[cve] = data
        else:
            missing.append(cve)
    if fetcher.online and missing:
        groups = list(_chunks(missing, feed['batch'])) if feed['mode'] == 'batch' else [[c] for c in missing]
        for index, group in enumerate(groups):
            if status['requests'] >= feed['max_requests']:
                status['deferred'] += sum(len(g) for g in groups[index:])
                break
            if status['requests'] and feed['interval']:
                fetcher.sleep(feed['interval'])
            url = feed['url'].replace('{cves}', ','.join(group)).replace('{cve}', group[0])
            status['requests'] += 1
            try:
                parsed = parser(fetcher.fetch(url))
            except NotFound:
                parsed = {}
            except FeedError as exc:
                status['errors'].append('%s: %s' % (group[0] if len(group) == 1 else '%d CVEs' % len(group), exc))
                for cve in group:
                    stale, _fresh = fetcher.cached(feed, cve)
                    if stale:
                        result[cve] = stale
                        status['stale'] += 1
                if len(status['errors']) >= 3:
                    status['deferred'] += sum(len(g) for g in groups[index + 1:])
                    break
                continue
            for cve in group:
                rec = parsed.get(cve) or {}
                fetcher.store(feed, cve, rec)          # negative results are cached too
                if rec:
                    result[cve] = rec
    elif missing:
        status['deferred'] = len(missing)
    status['items'] = len(result)
    status['state'] = _state(status, fetcher)
    return result, status


def _state(status, fetcher):
    if status['errors'] and not status['items']:
        return 'error'
    if not fetcher.online:
        return 'offline_cache' if status['cache_hits'] else 'offline'
    return 'partial' if status['errors'] or status['deferred'] else 'ok'


def enrich(cves, feeds, fetcher, opnsense_version=None):
    """ :return: {'by_feed': {feed id: {cve: partial}}, 'advisories': [...], 'status': [...]}
        OPNsense advisories run first: the CVE ids of those that affect this version are enriched too. """
    cves = set(c for c in cves if CVE_RE.match(c))
    by_feed = {}
    advisories = []
    status = []
    ordered = [f for f in feeds if f['type'] == 'ghsa_opnsense'] + [f for f in feeds if f['type'] != 'ghsa_opnsense']
    for feed in ordered:
        if feed['type'] == 'ghsa_opnsense':
            data, st = run_feed(feed, [], fetcher)
            for adv in data or []:
                if not isinstance(adv, dict):
                    continue
                adv = dict(adv, source=feed['id'], affected=opnsense_affected(adv, opnsense_version),
                           version_unknown=opnsense_version is None)
                advisories.append(adv)
                if adv['affected'] is True and adv.get('cve'):
                    cves.add(adv['cve'])
            st['items'] = sum(1 for a in advisories if a['source'] == feed['id'] and a['affected'] is True)
        else:
            data, st = run_feed(feed, sorted(cves), fetcher)
            by_feed[feed['id']] = data
        status.append(st)
    return {'by_feed': by_feed, 'advisories': advisories, 'status': status}
