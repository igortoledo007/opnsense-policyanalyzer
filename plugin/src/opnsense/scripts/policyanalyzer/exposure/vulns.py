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

    Known vulnerabilities of the installed packages:
      * pkg audit (FreeBSD VuXML, /var/db/pkg/vuln.xml): always, offline; "refresh" adds -F (downloads VuXML);
      * optional enrichment from the feed registry (feeds.py): KEV, EPSS, NVD, OSV, OPNsense advisories,
        merged and deduplicated per CVE, every field keeps the source it came from ("provenance");
      * pkg version -U -vRl '<' (local repository catalogue, no download): packages with a newer version;
      * local Suricata rules that reference a CVE (suggestion only).
"""

import json
import os
import re
import time

from . import common, feeds as feedmod

URL_VID_RE = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.html')
TEXT_HEAD_RE = re.compile(r'^(\S+) is vulnerable:\s*$')
OUTDATED_RE = re.compile(r'^(\S+)\s+<\s+needs updating \(remote has (\S+)\)')
SURICATA_CVE_RE = re.compile(r'reference\s*:\s*cve\s*,\s*(?:CVE-)?(\d{4}-\d{4,7})', re.I)
SURICATA_SID_RE = re.compile(r'\bsid\s*:\s*(\d+)')
SURICATA_MSG_RE = re.compile(r'msg\s*:\s*"([^"]*)"')
# field -> feed type precedence (first wins); "vuxml"/"ghsa" are the local / advisory sources
PRECEDENCE = {
    'cvss': ('nvd', 'osv', 'ghsa_opnsense'),
    'summary': ('nvd', 'osv', 'ghsa_opnsense', 'vuxml'),
    'published': ('nvd', 'osv', 'ghsa_opnsense'),
    'cwe': ('nvd',),
}
CVSS_FIELDS = ('cvss', 'cvss_version', 'cvss_vector', 'severity')
KEV_FIELDS = ('kev_date_added', 'kev_due', 'kev_name', 'kev_action', 'kev_ransomware')


# ------------------------------------------------------------------ pkg audit

def _fixed_from_affected(ranges):
    """ VuXML "Affected versions" (e.g. ['< 3.53.5,1'] or ['>= 0']) -> fixed versions ([] = no fix yet) """
    fixed = []
    for item in ranges or []:
        for match in re.finditer(r'<=?\s*(\S+)', item):
            if match.group(0).startswith('<='):
                continue
            fixed.append(match.group(1).rstrip(','))
    return sorted(set(fixed))


def parse_audit_json(text):
    data = json.loads(text)
    out = []
    for name, info in sorted((data.get('packages') or {}).items()):
        advisories = []
        fixed = []
        unbounded = False
        for issue in info.get('issues') or []:
            ranges = issue.get('Affected versions') or []
            fixes = _fixed_from_affected(ranges)
            if not fixes:
                unbounded = True
            fixed.extend(fixes)
            url = issue.get('url') or ''
            vid = URL_VID_RE.search(url)
            advisories.append({'description': (issue.get('description') or '').strip(),
                               'cves': [c for c in issue.get('cve') or [] if c],
                               'url': url or None, 'vid': vid.group(1) if vid else None,
                               'affected_versions': ranges, 'fixed_in': fixes})
        out.append({'name': name, 'version': info.get('version'), 'advisories': advisories,
                    'fixed_in': sorted(set(fixed)), 'fix_available': bool(fixed) and not unbounded,
                    'reverse_deps': list(info.get('reverse dependencies') or []), 'source': 'vuxml'})
    return out


def parse_audit_text(text):
    """ plain "pkg audit" output (fallback) """
    out = []
    current = None
    advisory = None
    for raw in text.splitlines():
        line = raw.rstrip()
        head = TEXT_HEAD_RE.match(line)
        if head:
            name, version = common.split_pkg_version(head.group(1))
            current = {'name': name, 'version': version, 'advisories': [], 'fixed_in': [],
                       'fix_available': None, 'reverse_deps': [], 'source': 'vuxml'}
            out.append(current)
            advisory = None
            continue
        if current is None or not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith('CVE:') and advisory is not None:
            advisory['cves'].append(stripped[4:].strip())
        elif stripped.startswith('WWW:') and advisory is not None:
            advisory['url'] = stripped[4:].strip()
            vid = URL_VID_RE.search(advisory['url'])
            advisory['vid'] = vid.group(1) if vid else None
        elif re.match(r'^\d+ problem\(s\)', stripped):
            current = None
        else:
            advisory = {'description': stripped, 'cves': [], 'url': None, 'vid': None,
                        'affected_versions': [], 'fixed_in': []}
            current['advisories'].append(advisory)
    return out


def audit(run, refresh=False):
    """ :return: (packages, meta) ; meta has the VuXML database age and how it was read """
    meta = {'database': common.VULN_XML, 'refreshed': False, 'error': None, 'format': None}
    try:
        st = os.stat(common.VULN_XML)
        meta['database_mtime'] = common.now_iso(st.st_mtime)
        meta['database_age_days'] = None
    except OSError:
        meta['database_mtime'] = None
        st = None
    argv = ['pkg', 'audit'] + (['-F'] if refresh else []) + ['-q', '--raw=json-compact']
    rc, out, err = run(argv, timeout=300)
    meta['refreshed'] = bool(refresh and rc in (0, 1))
    packages = None
    if rc is not None and out.strip().startswith('{'):
        try:
            packages = parse_audit_json(out)
            meta['format'] = 'json'
        except ValueError:
            packages = None
    if packages is None and rc is not None:
        rc2, out2, err2 = run(['pkg', 'audit'] + (['-F'] if refresh and not meta['refreshed'] else []), timeout=300)
        if rc2 in (0, 1) and (out2.strip() or rc2 == 0):
            packages = parse_audit_text(out2)
            meta['format'] = 'text'
        else:
            meta['error'] = (err2 or err).strip()[:300] or 'pkg audit failed'
    elif rc is None:
        meta['error'] = err.strip()[:300] or 'pkg not available'
    if st is not None:
        meta['database_age_days'] = round((time.time() - st.st_mtime) / 86400.0, 1)
    return packages, meta


def outdated(run):
    """ packages with a newer version in the (already downloaded) repository catalogue """
    rc, out, err = run(['pkg', 'version', '-U', '-vRl', '<'], timeout=120)
    if rc is None or (rc != 0 and not out.strip()):
        return None, (err.strip()[:200] or 'pkg version failed')
    result = []
    for line in out.splitlines():
        match = OUTDATED_RE.match(line.strip())
        if match:
            name, version = common.split_pkg_version(match.group(1))
            result.append({'name': name, 'version': version, 'available': match.group(2)})
    return result, None


# ------------------------------------------------------------------ suricata

def suricata_rules(cves, rules_dir=None, limit=5):
    """ cve -> [{sid, msg, file, enabled}] from the local rule files (read only) """
    rules_dir = rules_dir or common.SURICATA_RULES
    wanted = {c[4:] for c in cves if c.startswith('CVE-')}
    found = {}
    if not wanted:
        return found
    try:
        names = sorted(n for n in os.listdir(rules_dir) if n.endswith('.rules'))
    except OSError:
        return found
    for name in names:
        try:
            with open(os.path.join(rules_dir, name), errors='replace') as handle:
                for line in handle:
                    if 'cve' not in line.lower():
                        continue
                    for match in SURICATA_CVE_RE.finditer(line):
                        if match.group(1) not in wanted:
                            continue
                        cve = 'CVE-' + match.group(1)
                        sid = SURICATA_SID_RE.search(line)
                        msg = SURICATA_MSG_RE.search(line)
                        entries = found.setdefault(cve, [])
                        if len(entries) < limit and sid:
                            entries.append({'sid': int(sid.group(1)), 'msg': msg.group(1) if msg else '',
                                            'file': name, 'enabled': not line.lstrip().startswith('#')})
        except OSError:
            continue
    return found


# ------------------------------------------------------------------ merge

def merge_cve(cve, local, enrichment, feed_types):
    """ one CVE record from the local advisory data and every feed, with provenance per field """
    rec = {'id': cve, 'cvss': None, 'cvss_version': None, 'cvss_vector': None, 'severity': None,
           'kev': False, 'epss': None, 'epss_percentile': None, 'summary': None, 'refs': [],
           'sources': [], 'provenance': {}}
    for src in local.get('sources', []):
        if src not in rec['sources']:
            rec['sources'].append(src)
    partials = {}       # feed type -> (feed id, partial)
    for feed_id, data in (enrichment or {}).items():
        part = (data or {}).get(cve)
        if part:
            partials.setdefault(feed_types.get(feed_id, feed_id), (feed_id, part))
            if feed_id not in rec['sources']:
                rec['sources'].append(feed_id)
    if local.get('ghsa'):
        partials.setdefault('ghsa_opnsense', (local['ghsa']['source'], local['ghsa']))
    if local.get('summary'):
        partials.setdefault('vuxml', ('vuxml', {'summary': local['summary']}))
    for ftype in PRECEDENCE['cvss']:
        if ftype in partials and partials[ftype][1].get('cvss') is not None:
            feed_id, part = partials[ftype]
            for key in CVSS_FIELDS:
                rec[key] = part.get(key)
            rec['provenance']['cvss'] = feed_id
            break
    if rec['cvss'] is None:
        # a vector without a score (OSV with CVSS v4 only) is still useful context
        for ftype in PRECEDENCE['cvss']:
            if ftype in partials and partials[ftype][1].get('cvss_vector'):
                feed_id, part = partials[ftype]
                rec['cvss_vector'], rec['cvss_version'] = part.get('cvss_vector'), part.get('cvss_version')
                rec['provenance']['cvss_vector'] = feed_id
                break
    for field in ('summary', 'published', 'cwe'):
        for ftype in PRECEDENCE[field]:
            if ftype in partials and partials[ftype][1].get(field):
                rec[field] = partials[ftype][1][field]
                rec['provenance'][field] = partials[ftype][0]
                break
    if 'kev' in partials:
        feed_id, part = partials['kev']
        rec['kev'] = True
        for key in KEV_FIELDS:
            rec[key] = part.get(key)
        rec['provenance']['kev'] = feed_id
    if 'epss' in partials:
        feed_id, part = partials['epss']
        rec['epss'], rec['epss_percentile'] = part.get('epss'), part.get('epss_percentile')
        rec['provenance']['epss'] = feed_id
    refs = list(local.get('refs', []))
    for ftype in ('nvd', 'osv', 'ghsa_opnsense'):
        if ftype in partials:
            refs.extend(partials[ftype][1].get('refs') or [])
    seen = []
    for ref in refs:
        if ref and ref not in seen:
            seen.append(ref)
    rec['refs'] = seen[:10]
    return rec


def collect(run, online=False, refresh=False, fetcher=None, feed_list=None, opnsense_version=None,
            config_path=None):
    """ :return: dict with packages (per package CVE records), meta, feeds status, advisories """
    packages, meta = audit(run, refresh=refresh and online)
    packages = packages or []
    feed_list, registry_errors = (feed_list, []) if feed_list is not None else feedmod.registry(config_path)
    feed_types = {f['id']: f['type'] for f in feed_list}
    fetcher = fetcher or feedmod.Fetcher(online=online)
    all_cves = sorted({c for p in packages for a in p['advisories'] for c in a['cves']})
    enrichment = feedmod.enrich(all_cves, feed_list, fetcher, opnsense_version=opnsense_version)
    by_feed = enrichment['by_feed']

    out_packages = []
    for pkg in packages:
        local = {}
        for adv in pkg['advisories']:
            for cve in adv['cves']:
                entry = local.setdefault(cve, {'sources': ['vuxml'], 'refs': [], 'summary': adv['description']})
                if adv['url'] and adv['url'] not in entry['refs']:
                    entry['refs'].append(adv['url'])
        records = [merge_cve(cve, local[cve], by_feed, feed_types) for cve in sorted(local)]
        no_cve = [a for a in pkg['advisories'] if not a['cves']]
        out_packages.append(dict(pkg, cves=records, advisories_without_cve=len(no_cve)))

    # OPNsense core advisories that affect (or may affect) this version become an "opnsense" entry
    # True, or None when the version is known but the advisory ranges could not be compared (needs_review)
    affecting = [a for a in enrichment['advisories'] if a.get('affected') is True or
                 (a.get('affected') is None and not a.get('version_unknown'))]
    if affecting:
        records = []
        for adv in affecting:
            key = adv.get('cve') or adv['id']
            local = {'sources': [adv['source']], 'refs': [adv['url']] if adv.get('url') else [],
                     'summary': adv.get('summary'),
                     'ghsa': {'source': adv['source'], 'cvss': adv.get('cvss'), 'severity': adv.get('severity'),
                              'summary': adv.get('summary'), 'published': adv.get('published'),
                              'cvss_version': None, 'cvss_vector': None}}
            rec = merge_cve(key, local, by_feed if adv.get('cve') else {}, feed_types)
            rec['ghsa'] = adv['id']
            rec['affected'] = adv['affected']          # True or None (could not compare the version)
            if rec['severity'] is None and adv.get('severity'):
                rec['severity'] = adv['severity']
            records.append(rec)
        existing = next((p for p in out_packages if p['name'] == 'opnsense'), None)
        if existing is None:
            out_packages.append({'name': 'opnsense', 'version': opnsense_version, 'advisories': [],
                                 'fixed_in': [], 'fix_available': None, 'reverse_deps': [],
                                 'source': 'opnsense_ghsa', 'cves': records, 'advisories_without_cve': 0})
        else:
            known = {r['id'] for r in existing['cves']}
            existing['cves'].extend(r for r in records if r['id'] not in known)
    unique = {r['id'] for p in out_packages for r in p['cves']}
    return {'packages': out_packages, 'meta': meta, 'feeds': enrichment['status'],
            'feed_errors': registry_errors, 'online': bool(online), 'cves_total': len(unique),
            'kev_total': len({r['id'] for p in out_packages for r in p['cves'] if r['kev']})}
