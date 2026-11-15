"""
    Copyright (c) 2026 Igor Toledo
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

    Report assembly (JSON contract version 1, see CONTRACT.md, "Report format").
"""

import datetime
import hashlib
import os
import time

from .config import FirewallConfig
from .resolve import Resolver
from .rules import RuleNormalizer, evaluation_order
from .detectors import Context, run_all

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}


def finding_id(finding):
    uuids = [r.uuid for r in finding.rules]
    if finding.type in ('shadowed', 'redundant', 'duplicate'):
        # keep the pair order (affected rule first, covering rule second)
        material = '|'.join(uuids)
    else:
        material = '|'.join(sorted(uuids))
    raw = '%s:%s:%s:%s' % (finding.type, material, ','.join(finding.aliases), finding.key)
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]


LEGACY_RULES_PAGE = '/usr/local/www/firewall_rules.php'


def priority_group(rule):
    if rule.priority < 300000:
        return 'floating'
    if rule.priority < 400000:
        return 'group'
    return 'interface'


def rule_ref(rule, legacy_page=None):
    """ edit link. MVC: the rules page filters its grid by '#search=<text>' (the search includes the uuid);
        legacy: same value filter_core_rules_user stores in '#ref' """
    if rule.source == 'mvc':
        return 'ui/firewall/filter#search=%s' % rule.uuid
    if legacy_page is None:
        legacy_page = os.path.isfile(LEGACY_RULES_PAGE)
    if not legacy_page:
        return 'ui/firewall/migration'
    intf = 'FloatingRules' if rule.fields.get('floating') == '1' else rule.fields.get('interface', '')
    return 'firewall_rules_edit.php?if=%s&id=%d' % (intf, rule.index)


def rule_entry(rule, legacy_page=None):
    if rule.ifset.all:
        interface = ''
    else:
        interface = ('!' if rule.ifset.neg else '') + ','.join(rule.interfaces_raw)
    return {
        'uuid': rule.uuid,
        'source': rule.source,
        'interface': interface,
        'direction': rule.direction_raw,
        'action': rule.action,
        'sequence': rule.sequence,
        'description': rule.description,
        'summary': rule.summary,
        'quick': rule.quick,
        'enabled': rule.enabled,
        'priority_group': priority_group(rule),
        'ref': rule_ref(rule, legacy_page),
    }


def stats_block(cfg, stats, meta):
    """ top level "stats" object (contract revisions 1 and 2) """
    keep = bool(cfg.keepcounters)
    available = stats is not None
    since = None
    if available:
        since = meta.get('boot_time') if keep else meta.get('ruleset_loaded')
    return {
        'source': meta.get('source') if available else None,
        'ruleset_loaded': meta.get('ruleset_loaded') if available else None,
        'boot_time': meta.get('boot_time') if available else None,
        'keepcounters': keep,
        'keepcounters_source': cfg.keepcounters_source,
        'counters_since': since,
        'settings_page': cfg.settings_page,
    }


def build_report(config_path, stats, stats_meta, now=None):
    started = time.monotonic()
    cfg = FirewallConfig(config_path)
    resolver = Resolver(cfg)
    normalizer = RuleNormalizer(cfg, resolver)
    rules = evaluation_order([normalizer.normalize(raw) for raw in cfg.rules])
    ctx = Context(cfg, resolver, rules, stats, stats_meta, now=now)
    findings = run_all(ctx)
    legacy_page = os.path.isfile(LEGACY_RULES_PAGE) if any(r.source == 'legacy' for r in rules) else False

    output = []
    seen = set()
    for finding in findings:
        fid = finding_id(finding)
        if fid in seen:
            continue
        seen.add(fid)
        evidence = dict(finding.evidence)
        output.append({
            'id': fid,
            'type': finding.type,
            'severity': finding.severity,
            'title': finding.title,
            'detail': finding.detail,
            'recommendation': finding.recommendation,
            'rules': [rule_entry(r, legacy_page) for r in finding.rules],
            'aliases': list(finding.aliases),
            'evidence': evidence,
        })
    order_index = {r.uuid: idx for idx, r in enumerate(rules)}
    output.sort(key=lambda f: (SEVERITY_ORDER.get(f['severity'], 9), f['type'],
                               order_index.get(f['rules'][0]['uuid'], 0) if f['rules'] else 0, f['id']))
    by_severity = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for item in output:
        by_severity[item['severity']] = by_severity.get(item['severity'], 0) + 1
    generated = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) if now is None else \
        datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    return {
        'version': 1,
        'generated': generated.isoformat(),
        'duration_ms': int((time.monotonic() - started) * 1000),
        'summary': {
            'rules': len(rules),
            'enabled': sum(1 for r in rules if r.enabled),
            'findings': len(output),
            'by_severity': by_severity,
        },
        'stats_available': stats is not None,
        'stats': stats_block(cfg, stats, stats_meta),
        'findings': output,
    }
