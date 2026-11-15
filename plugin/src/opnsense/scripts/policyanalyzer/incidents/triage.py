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

    AI on the incident cases (read only: the model summarizes, classifies and recommends, it never applies).

      summarize(case)   summary, hypothesis, impact, confidence, next steps and suggested actions of one case
      digest(day)       plain language digest of the cases active on one local day

    Suggested actions are never free text from the model: the backend builds the list of candidate actions of
    the case (quarantine an external address, open the Live View, review a rule, open the IDS alerts or the DNS
    report, change the state of the case) with ids, the model may only pick ids from it (and, for a quarantine,
    a duration of the ladder).  The GUI shows the picked ones as buttons that open the existing simulated
    actions (quarantine_add through the simulation dialog) or links; nothing runs automatically.
    Data goes through the Assistant: anonymized (addresses, host names, rule descriptions), audited in
    /var/log/policyanalyzer/ai.log as incident_summary / incident_digest.
"""

import json
import re
import time

from ai import AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task, is_queued
from ai import brief as ai_brief

from . import common

MOUNT = 'OPNsense/policyanalyzer'
DURATIONS = ('l1', 'l2', 'l3', 'l4', 'l5')
DURATION_LABELS = {'l1': '30 min', 'l2': '2 h', 'l3': '2 days', 'l4': '10 days', 'l5': '30 days'}
MAX_EVIDENCE = 40
MAX_FIELD = 900
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

SUMMARY_INSTRUCTIONS = """You triage ONE security case of the firewall (OPNsense Policy Analyzer, Incidents).
The DATA block holds the case: its title, the correlation rules that matched, the score factors, the entities
(external addresses, internal hosts, ports, firewall rules) with their quarantine state, a timeline of
summarized evidence, and "candidate_actions": the only actions the interface can offer for this case.
Answer with ONE JSON object and nothing else (no markdown fence, no text before or after):
{"summary": "2-4 sentences in plain language for a non specialist",
 "hypothesis": "what most likely happened, tentative",
 "impact": "what could be affected and how serious it looks",
 "confidence": "low" | "medium" | "high",
 "next_steps": ["short steps a human could take", "... at most 5"],
 "actions": [{"id": "<id from candidate_actions>", "duration": "l1|l2|l3|l4|l5 (quarantine only)",
              "why": "one short reason"}]}
Rules: pick actions ONLY by the ids of candidate_actions (at most 4); never invent ids, addresses or rules.
Suggest a quarantine only when the evidence supports it, choosing the duration from the ladder (l1 30 min,
l2 2 h, l3 2 days, l4 10 days, l5 30 days); prefer short durations when unsure. If it looks like ordinary
background scanning of the internet or a benign service, say so and suggest the false_positive or resolve
action. Nothing is applied automatically: every action is reviewed and simulated by a human first."""

DIGEST_INSTRUCTIONS = """You write the daily digest of the security cases of the firewall (OPNsense Policy
Analyzer, Incidents) for its administrator. The DATA block holds the totals of the day (cases by severity,
state and correlation rule) and the most relevant cases with their title, score, state and entities.
Write plain text, no markdown, at most 8 short sentences: the overall picture of the day; the cases that
deserve attention first and why; what looks like ordinary background noise; and at most three suggestions
for a human (phrased as suggestions: nothing is changed automatically). If there were no cases, say so."""


def _assistant(assistant=None, config_path=None):
    if assistant is not None:
        return assistant
    config = AIConfig.from_opnsense(MOUNT, path=config_path or ai_brief.CONFIG_XML)
    return Assistant(config, app='policyanalyzer', audit=AuditLog(ai_brief.AUDIT_LOG))


# ------------------------------------------------------------------ candidate actions


def live_view_url(field, value):
    return '/ui/diagnostics/firewall/log#field=%s&operator=%%3D&value=%s' % (field, value)


def candidates(case):
    """ the closed list of actions the GUI can offer for this case (ids are stable within the case) """
    out = []
    ents = case.get('entities') or []
    ext = [e for e in ents if e['kind'] == 'ext'][:4]
    for idx, e in enumerate(ext, 1):
        q = (e.get('info') or {}).get('quarantine') or {}
        out.append({'id': 'quarantine_%d' % idx, 'kind': 'quarantine', 'target': e['value'],
                    'label': 'Put %s in quarantine' % e['value'],
                    'note': ('already in quarantine (level %s)' % q.get('level')) if q.get('active') else None,
                    'durations': list(DURATIONS)})
        out.append({'id': 'live_view_%d' % idx, 'kind': 'link', 'target': e['value'],
                    'label': 'Open %s in the Live View' % e['value'], 'url': live_view_url('src', e['value'])})
    for idx, e in enumerate([e for e in ents if e['kind'] == 'int'][:3], 1):
        out.append({'id': 'live_view_host_%d' % idx, 'kind': 'link', 'target': e['value'],
                    'label': 'Open %s in the Live View' % e['value'], 'url': live_view_url('src', e['value'])})
    for idx, e in enumerate([e for e in ents if e['kind'] == 'rule'][:3], 1):
        name = (e.get('info') or {}).get('description') or e['value']
        item = {'id': 'review_rule_%d' % idx, 'kind': 'link', 'target': e['value'],
                'label': 'Review the rule "%s"' % name}
        if UUID_RE.match(e['value']):
            item['url'] = '/ui/firewall/filter#%s' % e['value']
        else:
            item['url'] = '/ui/firewall/filter'
        out.append(item)
    sources = {ev.get('source') for ev in case.get('evidence') or []}
    if 'suricata' in sources:
        out.append({'id': 'ids_alerts', 'kind': 'link', 'label': 'Open the IDS alerts', 'url': '/ui/ids#alerts'})
    if 'dns' in sources:
        out.append({'id': 'dns_report', 'kind': 'link', 'label': 'Open the Unbound DNS report',
                    'url': '/ui/unbound/overview'})
    if 'quarantine' in sources or any((e.get('info') or {}).get('quarantine') for e in ext):
        out.append({'id': 'quarantine_tab', 'kind': 'link', 'label': 'Open the quarantine',
                    'url': '/ui/policyanalyzer/#quarantine'})
    if case.get('state') != 'investigating':
        out.append({'id': 'investigating', 'kind': 'state', 'state': 'investigating', 'label': 'Mark as in analysis'})
    out.append({'id': 'resolve', 'kind': 'state', 'state': 'resolved', 'label': 'Mark as resolved'})
    out.append({'id': 'false_positive', 'kind': 'state', 'state': 'false_positive', 'label': 'Mark as false positive'})
    return out


# ------------------------------------------------------------------ payloads


def case_payload(case, cands):
    """ what the model sees (before anonymization): no ids of other cases, no raw lines """
    ents = []
    for e in case.get('entities') or []:
        item = {'kind': e['kind'], 'role': e['role']}
        if e['kind'] == 'rule':
            item['description'] = (e.get('info') or {}).get('description') or 'rule'
        else:
            item['value'] = e['value']
        info = e.get('info') or {}
        if info.get('quarantine'):
            q = info['quarantine']
            item['quarantine'] = {'level': q.get('level'), 'active': q.get('active'), 'reason': q.get('reason')}
        for k in ('connections', 'events'):
            if k in info:
                item[k] = info[k]
        ents.append(item)
    evidence = sorted(case.get('evidence') or [], key=lambda ev: ev.get('last') or ev.get('ts') or 0)[-MAX_EVIDENCE:]
    timeline = []
    domains = []
    for ev in evidence:
        timeline.append({'time': common.iso(ev.get('first') or ev.get('ts')), 'last': common.iso(ev.get('last')),
                         'source': ev['source'], 'rule': ev.get('rule'), 'count': ev.get('count'), 'text': ev['text']})
        domains.extend(((ev.get('data') or {}).get('domains') or [])[:4])
    data = {
        'case': {'title': case['title'], 'severity': case['severity'], 'score': case['score'], 'state': case['state'],
                 'first_seen': common.iso(case['first_seen']), 'last_activity': common.iso(case['last_activity']),
                 'matches': case.get('matches'), 'rules': [r['rule'] if isinstance(r, dict) else r
                                                           for r in case.get('rules') or []],
                 'score_factors': [{'factor': f['label'], 'points': f['points'], 'detail': f.get('detail')}
                                   for f in case.get('factors') or []]},
        'entities': ents,
        'timeline': timeline,
        'evidence_rows_total': case.get('evidence_total'),
        # "label" would be anonymized as a description: the text of the action goes as "action"
        'candidate_actions': [{'id': c['id'], 'action': c['label'], 'note': c.get('note')} for c in cands],
        'quarantine_ladder': DURATION_LABELS,
    }
    if domains:
        data['domain'] = sorted(set(domains))[:12]      # "domain": anonymized as host names
    return data


def summary_schema(cands):
    """ JSON Schema of the answer for Ollama structured output: actions only from the closed list """
    return {
        'type': 'object',
        'properties': {
            'summary': {'type': 'string'},
            'hypothesis': {'type': 'string'},
            'impact': {'type': 'string'},
            'confidence': {'type': 'string', 'enum': ['low', 'medium', 'high']},
            'next_steps': {'type': 'array', 'items': {'type': 'string'}, 'maxItems': 5},
            'actions': {'type': 'array', 'maxItems': 4, 'items': {
                'type': 'object',
                'properties': {'id': {'type': 'string', 'enum': [c['id'] for c in cands]},
                               'duration': {'type': 'string', 'enum': list(DURATIONS)},
                               'why': {'type': 'string'}},
                'required': ['id', 'why']}},
        },
        'required': ['summary', 'hypothesis', 'impact', 'confidence', 'next_steps', 'actions'],
    }


def parse_answer(text, cands):
    """ the model's JSON (tolerant: fences, text around it); actions validated against the candidates """
    raw = str(text or '').strip()
    doc = None
    start, end = raw.find('{'), raw.rfind('}')
    if start >= 0 and end > start:
        try:
            doc = json.loads(raw[start:end + 1])
        except ValueError:
            doc = None
    if not isinstance(doc, dict):
        return {'parsed': False, 'summary': common.clean_text(raw, 2000), 'hypothesis': None, 'impact': None,
                'confidence': None, 'next_steps': [], 'actions': []}
    by_id = {c['id']: c for c in cands}

    def field(name):
        value = doc.get(name)
        return common.clean_text(value, MAX_FIELD) if isinstance(value, str) and value.strip() else None

    steps = [common.clean_text(s, 240) for s in (doc.get('next_steps') or []) if isinstance(s, str) and s.strip()][:5]
    actions, seen = [], set()
    for item in doc.get('actions') or []:
        if not isinstance(item, dict):
            continue
        cid = str(item.get('id') or '')
        if cid not in by_id or cid in seen:
            continue
        seen.add(cid)
        action = dict(by_id[cid])
        action['why'] = common.clean_text(item.get('why'), 240) if isinstance(item.get('why'), str) else None
        if action['kind'] == 'quarantine':
            duration = str(item.get('duration') or '')
            action['duration'] = duration if duration in DURATIONS else 'l1'
            action['duration_label'] = DURATION_LABELS[action['duration']]
            action.pop('durations', None)
        actions.append(action)
        if len(actions) >= 4:
            break
    confidence = doc.get('confidence') if doc.get('confidence') in ('low', 'medium', 'high') else None
    return {'parsed': True, 'summary': field('summary'), 'hypothesis': field('hypothesis'), 'impact': field('impact'),
            'confidence': confidence, 'next_steps': steps, 'actions': actions}


# ------------------------------------------------------------------ commands


def summarize(engine, case_id, language='en_US', preview=False, assistant=None):
    detail = engine.case_detail(case_id)
    if detail.get('status') != 'ok':
        return detail
    case = detail['case']
    cands = candidates(case)
    data = case_payload(case, cands)
    task = Task('incident_summary', SUMMARY_INSTRUCTIONS, 'Triage this case and answer with the JSON object.',
                schema=summary_schema(cands), check_ctx={'valid_ids': [c['id'] for c in cands]})
    helper = _assistant(assistant)
    if preview:
        return helper.preview(task, data, language)
    started = time.monotonic()
    try:
        result = helper.ask(task, data, language=language, subject='incident:%d' % case_id)
    except AIDisabled as exc:
        return {'status': 'disabled', 'message': str(exc)}
    except (ProviderRefusal, ProviderError) as exc:
        return {'status': 'error', 'message': str(exc)}
    if is_queued(result):
        return dict(result, case_id=case_id)
    parsed = parse_answer(result.get('text'), cands)
    record = dict(parsed, candidates=cands, model=result.get('model'), provider=result.get('provider'),
                  anonymized=result.get('anonymized'), language=result.get('language'),
                  seconds=round(time.monotonic() - started, 1), truncated=result.get('truncated'))
    now = engine.now()
    st = engine.open()
    try:
        st.begin()
        st.add_summary(case_id, now, record, language=language, provider=record['provider'], model=record['model'])
        st.log(case_id, now, 'summary', note='AI summary (%s)' % (record.get('model') or record.get('provider')))
        st.commit()
    except Exception:
        st.rollback()
        raise
    finally:
        st.close()
    return {'status': 'ok', 'case_id': case_id, 'ts': common.iso(now), 'summary': record}


def digest_payload(engine, day):
    start, end = common.local_day_bounds(day)
    st = engine.open(readonly=True)
    try:
        total, cases = st.search({'since': start, 'until': end}, ('score', 'desc'), 1, 500)
        by_sev, by_state, by_rule = {}, {}, {}
        for c in cases:
            by_sev[c['severity']] = by_sev.get(c['severity'], 0) + 1
            by_state[c['state']] = by_state.get(c['state'], 0) + 1
            for r in st.case_rules(c['id']):
                by_rule[r['rule']] = by_rule.get(r['rule'], 0) + 1
        top = []
        for c in cases[:12]:
            ents = st.entities(c['id'])
            top.append({'title': c['title'], 'severity': c['severity'], 'score': c['score'], 'state': c['state'],
                        'new_today': start <= c['created'] < end, 'rules': [r['rule'] for r in st.case_rules(c['id'])],
                        'entities': [{'kind': e['kind'], 'value': e['value']} if e['kind'] != 'rule' else
                                     {'kind': 'rule', 'description': (e['info'] or {}).get('description') or 'rule'}
                                     for e in ents[:5]],
                        'evidence_rows': st.evidence_count(c['id'])[0]})
        created = sum(1 for c in cases if start <= c['created'] < end)
        return {'day': day, 'cases': total, 'new_cases': created, 'by_severity': by_sev, 'by_state': by_state,
                'by_rule': by_rule, 'top_cases': top}
    finally:
        st.close()


def digest(engine, day, language='en_US', mode='cached', assistant=None):
    """ mode cached: the stored digest (plus the totals computed now); generate: ask the AI and store it """
    data = digest_payload(engine, day)
    if mode != 'generate':
        st = engine.open(readonly=True)
        try:
            stored = st.digest(day)
        finally:
            st.close()
        return {'status': 'ok', 'day': day, 'totals': data, 'digest': stored}
    task = Task('incident_digest', DIGEST_INSTRUCTIONS, 'Write the daily digest.')
    helper = _assistant(assistant)
    started = time.monotonic()
    try:
        result = helper.ask(task, data, language=language, subject='incident_digest:%s' % day)
    except AIDisabled as exc:
        return {'status': 'disabled', 'message': str(exc), 'day': day, 'totals': data}
    except (ProviderRefusal, ProviderError) as exc:
        return {'status': 'error', 'message': str(exc), 'day': day, 'totals': data}
    if is_queued(result):
        return dict(result, day=day, totals=data)
    text = common.clean_text(re.sub(r'[*_`#]{1,3}', '', result.get('text') or ''), 3000)
    record = {'text': text, 'model': result.get('model'), 'provider': result.get('provider'),
              'anonymized': result.get('anonymized'), 'seconds': round(time.monotonic() - started, 1),
              'cases': data['cases']}
    now = engine.now()
    st = engine.open()
    try:
        st.begin()
        st.set_digest(day, now, record, language=language, provider=record['provider'], model=record['model'])
        st.commit()
    except Exception:
        st.rollback()
        raise
    finally:
        st.close()
    return {'status': 'ok', 'day': day, 'totals': data, 'digest': {'day': day, 'ts': int(now), 'data': record}}
