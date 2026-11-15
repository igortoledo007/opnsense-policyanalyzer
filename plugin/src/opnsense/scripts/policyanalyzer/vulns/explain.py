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

    AI help for the vulnerabilities (text only, nothing is applied):
      explain_cve   impact on THIS firewall (how it is reached, which service), mitigation now, virtual
                    patching suggested as text (Suricata rule, block/restrict rule, GeoIP, rate limit), update
      suggest       for an item of the review queue: which listening service (if any) runs the vulnerable code,
                    with the evidence; the owner confirms with vulns_review_decide

    Modes: "cached" (stored answer only), "refresh" (ask the AI), "preview" (exactly what would be sent, nothing
    leaves the firewall). Only aggregates go to the AI: no addresses, no rule ids, no hostnames. The Assistant
    anonymizes and audits like every other AI call of the plugin (/var/log/policyanalyzer/ai.log).
"""

import os
import re

from . import common, prioritize, review

MAX_TEXT = 6000

EXPLAIN_INSTRUCTIONS = """You explain ONE vulnerability (CVE) to the administrator of this OPNsense firewall.
Structure the answer with these short sections, plain text, each starting with its title on its own line:
Impact here - what an attacker could do on THIS firewall, given the exposure in the data (internet, internal only,
  or no listening service). Say clearly when the component is only a library without a network path.
Why this priority - restate the priority (P1-P4) and the factors from the data (KEV, EPSS, CVSS, exposure).
Mitigate now - concrete steps the administrator can take in the GUI before a patch exists.
Virtual patching - suggested as text only: Suricata rules listed in the data (enable in IPS mode), restricting the
  source of the rule that exposes the service, GeoIP or VPN only access, rate limiting. Never say it was applied.
Fix - the update path (System > Firmware > Updates) and the fixed version when the data has it.
Keep it under 250 words. Do not invent versions, rules, ports or advisories that are not in the data."""

SUGGEST_INSTRUCTIONS = """You help map a vulnerable component of this OPNsense firewall to the listening service that
runs it, so its priority can be computed. Use only the data. Answer in at most 120 words, plain text:
first line exactly "MAPPING: <service id from candidates>" or "MAPPING: none" (no network path, library only)
or "MAPPING: unsure"; then the reasoning (does that daemon load this library or interpreter at runtime, or is it
only used by helper scripts?) and what the administrator should check to confirm. The administrator decides."""

MAPPING_RE = re.compile(r'^\s*MAPPING:\s*([0-9a-f]{6,32}|none|unsure)\b', re.I | re.M)


def _ai():
    from ai import AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task
    return AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task


def mapping_schema(ids):
    """ Ollama structured output of the mapping suggestion; rendered back to "MAPPING: <id>" + text """
    return {'type': 'object',
            'properties': {'mapping': {'type': 'string', 'enum': list(ids) + ['none', 'unsure']},
                           'explanation': {'type': 'string'}},
            'required': ['mapping', 'explanation']}


def render_mapping(doc):
    return 'MAPPING: %s\n%s' % (doc.get('mapping') or 'unsure', str(doc.get('explanation') or '').strip())


def assistant_factory():
    AIConfig, _d, Assistant, AuditLog, _e, _r, _t = _ai()
    config = AIConfig.from_opnsense(common.MOUNT, path=common.CONFIG_XML)
    return Assistant(config, app='policyanalyzer', audit=AuditLog(common.AUDIT_LOG))


def run_task(name, instructions, question, data, language, subject, mode, assistant=None, **task_options):
    _c, AIDisabled, _a, _l, ProviderError, ProviderRefusal, Task = _ai()
    assistant = assistant or assistant_factory()
    task = Task(name, instructions, question, **task_options)
    if mode == 'preview':
        result = assistant.preview(task, data, language)
        result['ai_enabled'] = bool(assistant.config.enabled)
        return result
    if not assistant.config.enabled:
        return {'status': 'disabled', 'message': 'AI assistance is disabled in the settings'}
    try:
        result = assistant.ask(task, data, language=language, subject=subject)
    except AIDisabled as exc:
        return {'status': 'disabled', 'message': str(exc)}
    except (ProviderRefusal, ProviderError) as exc:
        return {'status': 'error', 'message': str(exc)}
    if result.get('status') == 'queued':
        return result
    text = (result.get('text') or '').strip()
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT].rstrip() + '…'
    return {'status': 'ok', 'text': text, 'model': result.get('model'), 'provider': result.get('provider'),
            'anonymized': result.get('anonymized'), 'duration_ms': result.get('duration_ms'),
            'language': result.get('language'), 'generated_at': common.iso()}


def cve_data(item):
    """ the aggregate sent to the AI for one prioritised CVE (no addresses, no rule ids) """
    return {
        'cve': item['cve'], 'package': item['package'], 'installed_version': item['version'],
        'fixed_in': item['fixed_in'], 'fix_available': item['fix_available'], 'summary': item['summary'],
        'cvss': item['cvss'], 'cvss_vector': item['cvss_vector'], 'epss': item['epss'],
        'epss_percentile': item['epss_percentile'],
        'kev': None if not item['kev'] else {k: item['kev'].get(k) for k in ('date_added', 'due', 'action',
                                                                             'ransomware', 'name')},
        'priority': item['priority'], 'priority_rule': item['rule'],
        'factors': [f['text'] for f in item['factors']],
        'exposure': item['exposure']['class'],
        'services': [{'service': s['service'], 'service_name': s['name'], 'proto': s['proto'], 'port': s['port'],
                      'internet_reachable': s['internet_reachable'], 'management': s['admin'], 'link': s['link']}
                     for s in item['exposure']['services']],
        'suricata_rules': [{'sid': s.get('sid'), 'enabled': s.get('enabled'), 'message': s.get('msg')}
                           for s in item['suricata']],
    }


def _cache_path(key):
    return os.path.join(common.paths()['explain'], re.sub(r'[^A-Za-z0-9_.-]', '_', key) + '.json')


def explain_cve(cve, language='en_US', mode='cached', assistant=None, result=None):
    cve = common.valid_cve(cve)
    language = common.valid_language(language)
    result = result or prioritize.build()
    item = next((i for i in result.get('items') or [] if i['cve'] == cve), None)
    if item is None:
        return {'status': 'error', 'message': '%s is not in the inventory' % cve}
    path = _cache_path('cve-%s-%s' % (cve, language))
    if mode == 'cached':
        stored = common.load_json(path)
        return dict(stored, cached=True) if stored else {'status': 'none', 'cve': cve, 'item': item}
    data = cve_data(item)
    answer = run_task('explain_cve', EXPLAIN_INSTRUCTIONS, 'Explain this vulnerability for this firewall.', data,
                      language, 'cve:%s' % cve, mode, assistant)
    answer.update(cve=cve, item=item)
    if mode == 'refresh' and answer.get('status') == 'ok':
        common.write_json(path, answer)
    return answer


def suggest(item_id, language='en_US', mode='refresh', assistant=None, result=None):
    if not common.REVIEW_ID_RE.match(item_id or ''):
        raise ValueError('invalid review item id')
    language = common.valid_language(language)
    result = result or prioritize.build()
    item = next((q for q in result.get('review') or [] if q['id'] == item_id), None)
    if item is None:
        return {'status': 'error', 'message': 'review item not found'}
    data = {'kind': item['kind'], 'component': item['package'] or item['subject'], 'version': item['version'],
            'cves': item['cves'][:20], 'why_in_review': item['reason'],
            'candidates': [{'id': c['id'], 'service': c['service'], 'service_name': c.get('name'),
                            'proto': c.get('proto'), 'port': c.get('port'),
                            'internet_reachable': c.get('internet_reachable'), 'package': c.get('package')}
                           for c in item['candidates']]}
    ids = [c['id'] for c in item['candidates']]
    answer = run_task('vuln_review_suggest', SUGGEST_INSTRUCTIONS, 'Suggest the mapping of this component.', data,
                      language, 'vuln-review:%s' % item_id, mode, assistant, schema=mapping_schema(ids),
                      render=render_mapping, check_ctx={'first_values': ids + ['none', 'unsure']})
    if mode != 'preview' and answer.get('status') == 'ok':
        match = MAPPING_RE.search(answer['text'])
        mapping = match.group(1).lower() if match else 'unsure'
        valid = {c['id'] for c in item['candidates']}
        if mapping not in ('none', 'unsure') and mapping not in valid:
            mapping = 'unsure'
        answer['mapping'] = mapping
        # a suggestion is advice stored next to the item; it never changes a decision
        state = review.load_state()
        state['suggestions'][item_id] = {'mapping': mapping, 'text': answer['text'], 'model': answer.get('model'),
                                         'generated_at': answer.get('generated_at')}
        review.save_state(state)
    answer['item_id'] = item_id
    return answer
