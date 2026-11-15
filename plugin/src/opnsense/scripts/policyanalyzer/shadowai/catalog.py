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

    AI service catalogue: shipped data file (data/ai-services.json, versioned) merged with the optional local
    file (/usr/local/etc/policyanalyzer/ai-services.local.json): services with the same id are extended
    (domains added, other fields replaced), new ids are added, "known" entries are appended, and
    "disabled": ["id", ...] removes services.

    Matching is a suffix match on labels: "claude.ai" matches claude.ai and *.claude.ai, never
    "notclaude.ai"; the longest matching domain wins (gemini.google.com before a hypothetical google.com).
"""

import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SHIPPED = os.path.join(HERE, 'data', 'ai-services.json')
ID_RE = re.compile(r'^[a-z][a-z0-9_]{0,31}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$')


def _read(path):
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def normalize_domain(name):
    name = (name or '').strip().lower().rstrip('.')
    return name if DOMAIN_RE.match(name) else None


class Catalog:
    def __init__(self, shipped=None, local=None, shipped_data=None):
        data = shipped_data if shipped_data is not None else _read(shipped or SHIPPED)
        if data is None:
            raise ValueError('AI service catalogue not readable: %s' % (shipped or SHIPPED))
        self.version = data.get('version')
        self.categories = dict(data.get('categories') or {})
        self.services = {}
        self.known = []
        self.local_version = None
        self.errors = []
        self._merge(data, shipped=True)
        if local:
            extra = _read(local)
            if extra is not None:
                self.local_version = extra.get('version') or 'local'
                self._merge(extra, shipped=False)
            elif os.path.exists(local):
                self.errors.append('local catalogue is not valid JSON: %s' % local)
        for sid in (data.get('disabled') or []):
            self.services.pop(sid, None)
        self._index()

    def _merge(self, data, shipped):
        self.categories.update(data.get('categories') or {})
        for item in data.get('services') or []:
            sid = str(item.get('id', ''))
            if not ID_RE.match(sid):
                self.errors.append('invalid service id: %r' % sid)
                continue
            domains = [d for d in (normalize_domain(x) for x in item.get('domains') or []) if d]
            current = self.services.get(sid)
            if current is None:
                current = {'id': sid, 'name': sid, 'vendor': '', 'category': 'assistant', 'risk': 'standard',
                           'note': '', 'domains': []}
                self.services[sid] = current
            for key in ('name', 'vendor', 'category', 'risk', 'note'):
                if item.get(key):
                    current[key] = str(item[key])[:120]
            current['domains'] = sorted(set(current['domains']) | set(domains))
            current['local'] = current.get('local', False) or not shipped
        for sid in data.get('disabled') or []:
            self.services.pop(sid, None)
        for entry in data.get('known') or []:
            if entry.get('example'):
                continue
            match = entry.get('match') or {}
            if not any(match.get(k) for k in ('ip', 'net', 'hostname', 'mac')):
                continue
            self.known.append({'match': {k: str(v).lower() for k, v in match.items() if v},
                               'services': [s for s in entry.get('services') or [] if ID_RE.match(str(s))] or ['*'],
                               'reason': str(entry.get('description') or 'listed as expected')[:160],
                               'source': 'catalog'})

    def _index(self):
        self.suffix = {}
        for sid, svc in self.services.items():
            for domain in svc['domains']:
                # the more specific (longer) domain wins on conflicts
                if domain not in self.suffix or len(domain) > len(self.suffix[domain][1]):
                    self.suffix[domain] = (sid, domain)
        self.max_labels = max((d.count('.') + 1 for d in self.suffix), default=0)

    def match(self, name):
        """ :return: (service id, matched catalogue domain) or None """
        name = (name or '').strip().lower().rstrip('.')
        if not name:
            return None
        labels = name.split('.')
        for start in range(max(0, len(labels) - self.max_labels), len(labels)):
            candidate = '.'.join(labels[start:])
            hit = self.suffix.get(candidate)
            if hit:
                return hit
        return None

    def all_domains(self):
        return sorted(self.suffix)

    def regex(self):
        """ one regular expression for a coarse pre-filter in SQL (exact matching is done by match()) """
        parts = sorted((re.escape(d) for d in self.suffix), key=len, reverse=True)
        return r'(^|\.)(%s)\.?$' % '|'.join(parts)

    def public(self):
        return {'version': self.version, 'local_version': self.local_version, 'categories': self.categories,
                'services': [{k: v for k, v in s.items()} for s in sorted(self.services.values(),
                                                                          key=lambda x: x['name'].lower())],
                'errors': self.errors}
