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

    Short texts written by the AI for the e-mails, always with a fixed fallback text when the AI is off or fails:
      executive(data)    "AI executive summary": 3-5 sentences over the aggregates of the report
      notification(ev)   1-3 sentences for one notification (or a digest of several)
    Only aggregates are sent: counts, ports, countries, CVE ids, device types. Top source addresses of the report
    are dropped before the call (the Assistant would anonymise them anyway). The answer is text; the AI cannot
    change anything.

    Never published: an answer in another language than the report or made of the model's reasoning (a thinking
    model such as qwen3 leaks "Okay, let's tackle this. The user wants ..." when it ignores think=false). The
    Assistant cuts leaked reasoning when a final answer follows it, retries once and rejects the rest
    (AnswerRejected); _ask checks the final text again (publishable) and the caller then uses the fixed text.
    Every call is bounded (AI_SECONDS): a report from cron never waits more than that for the AI.
"""

import copy
import re
import time

import i18n

from . import common

EXEC_INSTRUCTIONS = """You write the executive summary at the top of a periodic security report of an OPNsense
firewall, for its owner. 3 to 5 short sentences, plain text, no lists, no markdown. Start with the overall state
(calm, attention, critical), then the 1-2 most important facts of the period (attacks blocked, quarantine,
vulnerabilities with priority P1/P2 or in KEV, new devices, posture changes) and end with the single most useful
next step, phrased as a suggestion. Use only the numbers in the data; when a section is unavailable, ignore it."""

NOTIFY_INSTRUCTIONS = """You write the first lines of an alert e-mail of an OPNsense firewall. 1 to 3 short
sentences, plain text: what happened, why it matters, and the suggested next step (a human decides; nothing was
changed by you). Use only the data. When several events are listed, summarise them together."""

# seconds the AI may take for one text (all attempts and the fallback route included); the report waits that much
AI_SECONDS = {'6h': 900, 'daily': 1200, 'weekly': 1500, 'manual': 900, 'notification': 300}
MIN_RETRY_SECONDS = 120


def strings(language):
    """ fixed texts (section "aisum" of i18n/<language>.json) used when the AI is off or its answer is rejected """
    return i18n.section(language, 'aisum')


def _assistant():
    from ai import AIConfig, Assistant, AuditLog
    config = AIConfig.from_opnsense(common.MOUNT, path=common.paths()['config'])
    # reports and notifications run from cron or the report preview: never queued
    return Assistant(config, app='policyanalyzer', audit=AuditLog(common.paths()['ai_log']), inline=True)


def publishable(text, language):
    """ :return: list of reasons why the text must not go to an e-mail/PDF (empty: fine) """
    from ai import validate
    text = str(text or '').strip()
    if not text:
        return ['the answer is empty']
    out = []
    if validate.leaked_reasoning(text):
        out.append(validate.REASONING_PROBLEM)
    out += validate.check_language(text, language, strict=True)
    return out


def clean(text, language):
    """ the text that goes to the e-mail: think blocks and leaked reasoning cut, no markdown """
    from ai import validate
    text, _leaked = validate.strip_reasoning(validate.strip_think(text), language)
    return re.sub(r'[*_`#]{1,3}', '', text or '').strip()


def _ask(name, instructions, question, data, language, subject, assistant=None, max_seconds=None):
    """ :return: (text or None, info); None = use the fixed text """
    try:
        from ai import AIDisabled, AnswerRejected, ProviderError, ProviderRefusal, Task
    except ImportError:
        return None, {'status': 'unavailable'}
    started = time.monotonic()
    info = {'status': 'error'}
    for attempt in (1, 2):
        left = None if not max_seconds else max_seconds - (time.monotonic() - started)
        if attempt == 2 and left is not None and left < MIN_RETRY_SECONDS:
            break
        try:
            assistant = assistant or _assistant()
            if not assistant.config.enabled:
                return None, {'status': 'disabled'}
            result = assistant.ask(Task(name, instructions, question), data, language=language, subject=subject,
                                   max_seconds=left)
        except AIDisabled:
            return None, {'status': 'disabled'}
        except AnswerRejected as exc:
            info = {'status': 'rejected', 'message': str(exc)[:200]}
            if str(exc).startswith('answer rejected after 1 attempt'):
                continue                    # one route, no retry and no fallback: one new attempt here
            break
        except (ProviderError, ProviderRefusal) as exc:
            return None, {'status': 'error', 'message': str(exc)[:200]}
        except Exception as exc:            # noqa: BLE001 - a broken AI never blocks an e-mail
            return None, {'status': 'error', 'message': str(exc)[:200]}
        text = clean(result.get('text'), language)[:1500]
        problems = publishable(text, language)
        if not problems:
            return text, {'status': 'ok', 'model': result.get('model'), 'provider': result.get('provider'),
                          'attempts': attempt}
        info = {'status': 'rejected', 'message': '; '.join(problems)[:200], 'model': result.get('model')}
    return None, info


def report_inputs(data):
    """ aggregates only: drop the addresses of the top lists; the chart series become totals vs previous period """
    data = copy.deepcopy(data)
    metrics = data.pop('metrics', None) or {}
    trend = {}
    for key, cur, prev in (('blocked', ('traffic', 'blocked'), ('traffic', 'previous')),
                           ('quarantine_new', ('quarantine', 'new'), ('quarantine', 'previous_new')),
                           ('incidents_opened', ('incidents', 'opened_series'), ('incidents', 'previous')),
                           ('ai_requests', ('ai', 'requests'), ('ai', 'previous'))):
        part = metrics.get(cur[0]) or {}
        if isinstance(part.get(cur[1]), list):
            trend[key] = {'period': sum(part[cur[1]]), 'previous_period': part.get(prev[1])}
    if trend:
        data['trend'] = trend
    if isinstance(data.get('traffic'), dict):
        data['traffic'].pop('timeline', None)
    for section, key in (('quarantine', 'top_period'), ('quarantine', 'top_repeat'), ('traffic', 'top_sources')):
        items = (data.get(section) or {}).get(key)
        if items:
            data[section][key] = [{k: v for k, v in i.items() if k != 'addr'} for i in items]
    devices = data.get('devices') or {}
    if devices.get('new'):
        devices['new'] = [{k: v for k, v in d.items() if k in ('type', 'vendor', 'risk', 'interface')}
                          for d in devices['new']]
    devices.pop('top_risk', None)
    return data


def fallback_executive(data, language):
    s = strings(language)
    t = data.get('traffic') or {}
    q = data.get('quarantine') or {}
    c = data.get('cves') or {}
    d = data.get('devices') or {}
    p = data.get('posture') or {}
    p1 = (c.get('counts') or {}).get('P1', 0)
    level = 'critical' if p1 or p.get('posture') == 'critical' else (
        'attention' if (c.get('counts') or {}).get('P2') or d.get('new_count') or q.get('new') else 'calm')
    parts = [s[level]]
    if t.get('blocked_in'):
        parts.append(s['blocked'] % t['blocked_in'])
    if q.get('new'):
        parts.append(s['quarantine'] % q['new'])
    if p1:
        parts.append(s['p1'] % p1)
    if c.get('kev'):
        parts.append(s['kev'] % c['kev'])
    if d.get('new_count'):
        parts.append(s['devices'] % d['new_count'])
    if p.get('posture'):
        parts.append(s['posture'] % p['posture'])
    parts.append(s['next'])
    return ' '.join(parts)


def executive(data, language, enabled=True, assistant=None):
    """ :return: {text, ai: bool, info} """
    if enabled:
        text, info = _ask('report_summary', EXEC_INSTRUCTIONS, 'Write the executive summary of this report.',
                          report_inputs(data), language, 'report:%s' % data.get('kind'), assistant,
                          max_seconds=AI_SECONDS.get(data.get('kind'), AI_SECONDS['manual']))
        if text:
            return {'text': text, 'ai': True, 'info': info}
    else:
        info = {'status': 'off'}
    note = None
    if enabled:
        note = strings(language)['rejected_note' if info.get('status') == 'rejected' else 'fallback_note']
    return {'text': fallback_executive(data, language), 'ai': False, 'info': info, 'note': note}


def notification(events, language, enabled=True, assistant=None):
    data = [{'type': e['type'], 'severity': e['severity'], 'title': e['title'], 'detail': e.get('detail'),
             'facts': e.get('data')} for e in events[:20]]
    if enabled:
        text, info = _ask('notification_summary', NOTIFY_INSTRUCTIONS, 'Write the alert summary.', {'events': data},
                          language, 'notify:%s' % events[0]['type'], assistant, max_seconds=AI_SECONDS['notification'])
        if text:
            return {'text': text, 'ai': True, 'info': info}
    else:
        info = {'status': 'off'}
    first = events[0]
    base = first['title'] if len(events) == 1 else '%d: %s' % (len(events), '; '.join(e['title'] for e in events[:3]))
    return {'text': strings(language)['event_fallback'] % base, 'ai': False, 'info': info}
