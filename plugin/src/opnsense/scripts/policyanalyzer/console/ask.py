#!/usr/local/bin/python3

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

    AI Console of the Policy Analyzer: configd entry point (configctl pa_console <action> ...).

        ask.py status                                  AI state, which local sources exist
        ask.py suggest  <gui language>                 ready made questions
        ask.py ask      <payload> <gui language> <send|preview|route>
                        payload (base64 JSON): {"q": "...", "history": [{"q", "a"}], "lang": "auto|pt_BR|en_US"}
        ask.py explain  <log|rule|alert> <payload> <gui language> <send|preview>
                        log:   {"ts", "iface", "action", "dir", "proto", "src", "sport", "dst", "dport", "rid"}
                        rule:  {"uuid"} or {"label"}
                        alert: {"timestamp", "flow_id", "sid"}
        ask.py log      <payload>     {"ip", "port", "action", "iface", "dir", "limit"}   filter log viewer
        ask.py rules    <payload>     {"search", "iface", "unused", "action"}            rules with counters
        ask.py alerts   <payload>     {"severity", "ip", "limit", "days"}                Suricata alerts

    The model never gets tools.  A deterministic router (console/router.py) picks read-only collectors, the
    evidence is assembled within a token budget (console/context.py), anonymized and audited by the shared
    Assistant (ai/assistant.py), and the answer is text.  Proposals in an answer are text only: nothing in
    this program changes the firewall.  Output is always one JSON document on stdout.
"""

import ipaddress
import os
import re
import socket
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ''):
    sys.path = [p for p in sys.path if os.path.abspath(p or '.') != _HERE]
    sys.path.insert(0, os.path.dirname(_HERE))

from ai import AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task  # noqa: E402
from ai import mapreduce  # noqa: E402
from ai.anonymizer import Anonymizer  # noqa: E402
from ai.prompts import build_system, build_user  # noqa: E402
from console import context, router  # noqa: E402
from console.collectors import (  # noqa: E402
    aliases, changes, filterlog, fwinfo, hosts, quarantine, reports, rules, suricata,
)
from console.common import (  # noqa: E402
    IFACE_RE, LABEL_RE, LANG_RE, Budget, Paths, clean_text, clip, decode_payload, emit, ip_or_none, is_public,
    valid_port,
)

MOUNT = 'OPNsense/policyanalyzer'
MAX_QUESTION = 600
MAX_HISTORY = 3
MAX_HISTORY_Q = 300
MAX_HISTORY_A = 900
COLLECT_SECONDS = 20.0
LANG_CHOICES = ('auto', 'pt_BR', 'en_US')
CLOCK = time.time            # tests replace it with a fixed clock

FORMAT_RULES = """Formatting (this overrides the plain text rule above): write light Markdown: short ### headings,
bullet lists, **bold** for the key fact, `inline code` for rule fields, addresses and ports. No tables, no HTML,
no links. A proposed change goes in a fenced ```diff block that shows the rule fields before (-) and after (+),
headed "Proposal (not applied)"; it is a suggestion for a human to review in the GUI, never something you did."""

EVIDENCE_RULES = """Evidence rules:
- Every factual claim needs evidence from the DATA block. Cite it inline in square brackets naming the section
  and the item, for example [filterlog: 14 blocks, last 10:15, rule lan #3 block "Block IoT"] or
  [rules: lan #12 pass "Allow DNS", 0 packets since 2026-11-08 04:50] or [changes: 09:12 by USER_1].
- question_analysis tells how the question was understood (intents, entities, time window) and
  evidence_order lists the sections collected. A section with "available": false or "omitted" has no data;
  "complete": false means the log was only partly read inside the time budget.
- If the evidence does not answer the question, or covers another time window, say so plainly ("I do not have
  enough data to ...") and say which page or data the administrator could check next. Never guess and never
  fill gaps with general knowledge presented as fact.
- The path section is a static, approximate evaluation of the configured rules; automatic rules (anti-lockout,
  bogons, default deny, plugins) are outside it. Say "likely" when you rely on it."""

ASK_INSTRUCTIONS = """You answer an administrator's question about this OPNsense firewall in the AI Console.
The DATA block holds the read-only evidence collected for this question (filter log aggregates and a few sample
events, rules with their counters, aliases, quarantine ledger, Policy Analyzer findings, exposure report, local
host names, configuration changes, Suricata alerts). Earlier turns of the conversation, if any, came before.
Start with a direct answer in one or two sentences, then the supporting evidence, then (only if useful) what to
check next. Keep it under about 250 words unless the question asks for a list.
""" + EVIDENCE_RULES + '\n' + FORMAT_RULES

EXPLAIN_LOG = """You explain ONE event of the OPNsense filter log to the administrator. The DATA block holds the
event, the rule that logged it (rid), the local host names, the recent activity of the same source, the quarantine
record of a public source and a static evaluation of the rules on the path.
Structure: ### What happened (the event in plain words: who talked to whom, on which interface, which rule
decided and why), ### Is this expected? (normal background traffic, misconfiguration, attack attempt; keep it
tentative), ### What to check (concrete steps in the GUI), and, only when a rule looks wrong, a proposal.
""" + EVIDENCE_RULES + '\n' + FORMAT_RULES

EXPLAIN_RULE = """You review ONE firewall rule of OPNsense for the administrator. The DATA block holds the rule
(fields, summary, position in the evaluation order), its pf counters, the Policy Analyzer findings that involve it,
its neighbours on the same interface, and how often the filter log saw it recently.
Structure: ### What it does (in plain words, including direction, quick and logging), ### Risks (too broad source,
destination or ports, any/any, WAN exposure, missing description, logging), ### Usage (counters and log hits;
say if it looks unused, shadowed or redundant and why, using the findings), ### Suggestion (or "none" when it looks
intentional), with a ```diff proposal of the changed fields when you suggest narrowing it.
""" + EVIDENCE_RULES + '\n' + FORMAT_RULES

EXPLAIN_ALERT = """You explain ONE Suricata (IDS/IPS) alert to the administrator. The DATA block holds the alert
(signature, category, severity, action taken, addresses, ports, protocol), what the filter log saw from the same
source, the quarantine record of a public source and local host names.
Structure: ### What the signature means, ### What happened here (who, which direction, was it blocked or only
alerted), ### Likely a real threat or a false positive? (tentative, with reasons from the data), ### What to check
(and, only if useful, a proposal such as a rule or a suppression, as text).
""" + EVIDENCE_RULES + '\n' + FORMAT_RULES

SUGGESTIONS = {
    'pt': [
        'Quem mais foi bloqueado hoje?',
        'O que mudou na configuração desde ontem?',
        'Algum serviço do firewall está exposto à internet?',
        'Quais achados do Policy Analyzer devo revisar primeiro?',
        'Como está a quarentena agora?',
        'Houve alertas do Suricata de severidade 1 hoje?',
    ],
    'en': [
        'Who else was blocked today?',
        'What changed in the configuration since yesterday?',
        'Is any firewall service exposed to the internet?',
        'Which Policy Analyzer findings should I review first?',
        'How is the quarantine doing right now?',
        'Were there severity 1 Suricata alerts today?',
    ],
}


# ------------------------------------------------------------------------------------------------ assistant

# values that are public knowledge (IDS signature names and classes): the FQDN pattern of the anonymizer would
# otherwise hide "ET MALWARE Banker.Delf" as a host name; restored only when they hold no address
PUBLIC_KEYS = ('signature', 'classification')
_ADDRESS_RE = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}')


def keep_public(original, safe):
    if isinstance(original, dict) and isinstance(safe, dict):
        for key, value in original.items():
            if key in PUBLIC_KEYS and isinstance(value, str) and not _ADDRESS_RE.search(value):
                safe[key] = value
            elif key in safe:
                keep_public(value, safe[key])
    elif isinstance(original, list) and isinstance(safe, list):
        for a, b in zip(original, safe):
            keep_public(a, b)
    return safe


class ConsoleAssistant(Assistant):
    """
    The shared Assistant with two additions: the page language choice (auto follows the setting, then the
    GUI) and the earlier turns of the conversation, anonymized with the same placeholders as the data.  The
    question itself is anonymized too (Assistant.prepare only anonymizes the data block).
    """

    def __init__(self, config, language_choice='auto', history=None, question=None, **kwargs):
        super().__init__(config, **kwargs)
        self.language_choice = language_choice if language_choice in LANG_CHOICES else 'auto'
        self.history = history or []
        self.question = question
        self.last_messages = None

    def resolve_language(self, requested=None):
        if self.language_choice != 'auto':
            return self.language_choice
        return super().resolve_language(requested)

    def prepare(self, task, data, language=None):
        """ same steps as Assistant.prepare, plus the anonymized question and earlier turns """
        anonymizer = Anonymizer(enabled=self.config.anonymize, sensitive_keys=self.sensitive_keys)
        safe_data = keep_public(data, anonymizer.anonymize(data))
        question = self.question if self.question is not None else task.question
        messages = [{'role': 'system', 'content': build_system(task.instructions, self.resolve_language(language))}]
        for turn in self.history:
            messages.append({'role': 'user', 'content': anonymizer.anonymize_text(turn['q'])})
            messages.append({'role': 'assistant', 'content': anonymizer.anonymize_text(turn['a'])})
        messages.append({'role': 'user', 'content': build_user(anonymizer.anonymize_text(question), safe_data)})
        self.last_messages = messages
        return anonymizer, messages


def make_assistant(paths, choice='auto', history=None, question=None, config=None):
    config = config or AIConfig.from_opnsense(MOUNT, path=paths.config)
    return ConsoleAssistant(config, language_choice=choice, history=history, question=question, app='policyanalyzer',
                            audit=AuditLog(paths.audit_log))


# ------------------------------------------------------------------------------------------------ helpers

def resolve_domains(names, timeout=2.0):
    """ A/AAAA of the domains named in a question, through the firewall's own resolver, within timeout """
    result = {}

    def work(name):
        try:
            infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            return
        addrs = []
        for info in infos:
            addr = info[4][0]
            if addr not in addrs:
                addrs.append(addr)
        result[name] = addrs[:4]
    threads = [threading.Thread(target=work, args=(n,), daemon=True) for n in names[:3]]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    return {n: result.get(n, []) for n in names[:3]}


def devices_for(paths, names):
    """ interface names as typed (lan, IoT, igc0) -> devices of the log """
    out = []
    for item in fwinfo.interfaces(paths.config):
        for name in names:
            if router.normalize(name) in (router.normalize(item['name']), router.normalize(item['descr']),
                                          router.normalize(item['device'])) and item['device'] not in out:
                out.append(item['device'])
    return out


def source_line(name, data):
    """ chip shown under the answer: which sources were used """
    if not isinstance(data, dict):
        return {'name': name, 'available': False}
    return {'name': name, 'available': bool(data.get('available', True)) and not data.get('omitted'),
            'complete': data.get('complete'), 'message': data.get('message')}


def sanitize_history(raw):
    out = []
    for turn in (raw or [])[-MAX_HISTORY:]:
        if not isinstance(turn, dict):
            continue
        q = clip(clean_text(turn.get('q'), MAX_HISTORY_Q), MAX_HISTORY_Q)
        a = clip(str(turn.get('a') or '').replace('\x00', ''), MAX_HISTORY_A)
        if q and a:
            out.append({'q': q, 'a': a})
    return out


def is_local(ip):
    return ip_or_none(ip) is not None and not is_public(ip)


# ------------------------------------------------------------------------------------------------ collection

def collect(plan, paths, budget, question=''):
    """ run the collectors of the plan; :return: (analysis, sections) """
    ents = plan['entities']
    window = plan['window']
    known = hosts.known_names(paths)
    host_ips = {}
    for name in ents['hosts']:
        host_ips[name] = known.get(name, [])[:3]
    ips = list(ents['ips'])
    for values in host_ips.values():
        ips += [v for v in values if v not in ips]
    resolved = resolve_domains(ents['domains'], timeout=min(2.0, budget.left())) if ents['domains'] else {}
    dst_ips = [ip for values in resolved.values() for ip in values]
    singles = [ip for ip in ips if '/' not in ip]
    rule_names = rules.index(paths)
    devices = devices_for(paths, ents['interfaces'])
    matched_rules = []
    sections = []
    results = {}
    for name in plan['collectors']:
        if budget.expired():
            sections.append((name, {'available': False, 'message': 'time budget exhausted before this source'}))
            continue
        data = None
        if name == 'rules':
            data = rules.evidence(paths, budget.slice(20), ents['rules'])
            matched_rules = list(data.pop('matched_uuids', []))
            matched_rules += [r['label'] for r in data.get('automatic_rules') or []]
        elif name == 'filterlog':
            rids = matched_rules if 'rule_usage' in plan['intents'] and matched_rules else ()
            if rids:
                flt = filterlog.Filter(rids=rids)
            else:
                flt = filterlog.Filter(ips=ips or dst_ips, ports=ents['ports'],
                                       action=ents['action'] if 'why_blocked' not in plan['intents'] else None,
                                       devices=devices,
                                       proto=ents['protocols'][0] if len(ents['protocols']) == 1 else None)
            if flt.empty:
                data = {'available': False, 'message': 'no address, port, interface or rule to look for in the log'}
            else:
                data = filterlog.focus(paths, window, budget.slice(10), flt, rule_names)
        elif name == 'filterlog_top':
            data = filterlog.top(paths, window, budget.slice(10), rule_names)
        elif name == 'path_rules':
            local = [ip for ip in singles if is_local(ip)]
            others = [ip for ip in singles if ip not in local[:1]]
            src = local[0] if local else (singles[0] if singles else None)
            dst = (others[0] if others and others[0] != src else None) or (dst_ips[0] if dst_ips else None)
            if src and dst and ':' in src and ':' not in dst:
                v6 = [d for d in dst_ips if ':' in d]
                dst = v6[0] if v6 else None
            elif src and dst and ':' not in src and ':' in dst:
                v4 = [d for d in dst_ips if ':' not in d]
                dst = v4[0] if v4 else None
            proto = ents['protocols'][0] if ents['protocols'] else None
            assumed = []
            if ents['ports'] and not proto:
                proto = 'tcp'
                assumed.append('protocol assumed tcp because only a port was given')
            if not dst and ents['domains']:
                assumed.append('the domain could not be resolved: destination unknown')
            data = rules.path(paths, src=src, dst=dst, dport=ents['ports'][0] if ents['ports'] else None,
                              proto=proto, assumed=assumed)
        elif name == 'hosts':
            wanted = [ip for ip in singles if is_local(ip)]
            top = results.get('filterlog_top') or {}
            wanted += [s['address'] for s in top.get('top_blocked_internal_sources') or []][:6]
            focus = results.get('filterlog') or {}
            wanted += [p['address'] for p in focus.get('top_peers') or [] if is_local(p['address'])][:3]
            wanted = list(dict.fromkeys(wanted))
            data = hosts.lookup(paths, wanted) if wanted else {'available': False, 'message': 'no local address'}
        elif name == 'aliases':
            members = [aliases.member_of(paths, ip, budget.slice(4)) for ip in (singles + dst_ips)[:2]]
            named = aliases.describe(paths, [w for w in re.findall(r'[A-Za-z0-9_]{2,64}', question)
                                             if w in set(aliases.alias_names(paths))][:3])
            data = {'available': True, 'source': 'config.xml aliases + pf tables', 'addresses': members,
                    'named_aliases': named}
        elif name == 'quarantine':
            public = [ip for ip in singles + dst_ips if not is_local(ip)][:2]
            data = {'available': True}
            if public:
                data['entries'] = [quarantine.entry(paths, ip, now=CLOCK()) for ip in public]
            if not public or set(plan['intents']) & {'quarantine', 'top_blocked', 'overview'}:
                data['summary'] = quarantine.summary(paths, now=CLOCK())
            data['available'] = any(v.get('available') for v in [data.get('summary') or {}] +
                                    data.get('entries', []))
        elif name == 'suricata':
            data = suricata.summary(paths, window, budget.slice(8), ip=singles[0] if singles else None,
                                    severity_max=ents['severity'])
        elif name == 'findings':
            data = reports.findings(paths, rule_uuids=set(matched_rules) or None)
        elif name == 'exposure':
            data = reports.exposure(paths)
        elif name == 'changes':
            data = changes.collect(paths, window, budget.slice(8), now=CLOCK())
        results[name] = data
        sections.append((name, data))
    analysis = {
        'intents': plan['intents'],
        'time_window': router.window_text(window),
        'window_given_in_question': window['explicit'],
        'now': time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime(window['until'])),
        'entities': {
            'addresses': ents['ips'], 'ports': ents['ports'], 'protocols': ents['protocols'],
            'action': ents['action'], 'interfaces': ents['interfaces'],
            'host_names': [{'hostname': n, 'addresses': v} for n, v in host_ips.items()],
            'domains': [{'domain': d, 'resolved': v} for d, v in resolved.items()],
            'rule_references': {k: v for k, v in ents['rules'].items() if v},
            'suricata_severity': ents['severity'],
        },
        'carried_from_previous_question': plan['carried_from_history'],
        'collectors': plan['collectors'],
    }
    analysis['entities'] = {k: v for k, v in analysis['entities'].items() if v}
    return analysis, sections


def known_for_router(paths):
    return {'interfaces': fwinfo.interface_names(paths.config), 'hosts': list(hosts.known_names(paths))}


# ------------------------------------------------------------------------------------------------ commands

def _send(assistant, task, data, gui_lang, mode, subject, extra, mr=None):
    """ :param mr: map/reduce callable -> (result, data) or (None, None) when the evidence fits the budget """
    if mode == 'preview':
        result = assistant.preview(task, data, gui_lang)
        result.update(extra)
        return result
    try:
        result = None
        if mr is not None:
            result, mr_data = mr()
            if mr_data is not None:
                extra['context'] = mr_data['context_limits']
        if result is None:
            result = assistant.ask(task, data, language=gui_lang, subject=subject)
    except AIDisabled as exc:
        return dict(extra, status='disabled', message=str(exc))
    except ProviderRefusal as exc:
        return dict(extra, status='refusal', message=str(exc))
    except ProviderError as exc:
        return dict(extra, status='error', message=str(exc))
    messages = assistant.last_messages or []
    result.update(extra)
    result['sent'] = {'messages': messages, 'bytes': sum(len(m['content'].encode()) for m in messages)}
    return result


def cmd_ask(payload, gui_lang, mode, paths=None, config=None, provider=None, now=None):
    paths = paths or Paths()
    question = clean_text(payload.get('q'), MAX_QUESTION)
    if len(question) < 2:
        return {'status': 'error', 'message': 'empty question'}
    history = sanitize_history(payload.get('history'))
    choice = payload.get('lang') if payload.get('lang') in LANG_CHOICES else 'auto'
    plan = router.route(question, known=known_for_router(paths), now=CLOCK() if now is None else now,
                        history=[t['q'] for t in history])
    if mode == 'route':
        return {'status': 'ok', 'plan': plan}
    budget = Budget(COLLECT_SECONDS)
    analysis, sections = collect(plan, paths, budget, question)
    assistant = make_assistant(paths, choice, history, question, config)
    if provider is not None:
        assistant._provider = provider
    task = Task('console_ask', ASK_INSTRUCTIONS, question)
    route = assistant.route_for(task)
    tokens = context.token_budget(assistant.config, route)
    data = context.build(analysis, sections, tokens)
    extra = {
        'plan': {'intents': plan['intents'], 'window': plan['window']['label'], 'collectors': plan['collectors'],
                 'carried': plan['carried_from_history']},
        'sources': [source_line(n, d) for n, d in sections],
        'context': data['context_limits'],
        'collect_ms': budget.elapsed_ms(),
    }
    subject = 'console:%s' % '+'.join(plan['intents'])
    return _send(assistant, task, data, gui_lang, mode, subject, extra, _map_reduce(assistant, task, route, analysis,
                                                                                    sections, tokens, gui_lang,
                                                                                    subject))


def _map_reduce(assistant, task, route, analysis, sections, tokens, gui_lang, subject):
    """ local model with evidence above the budget: parts + consolidation instead of cutting (ai/mapreduce.py) """
    if not route.local:
        return None
    return lambda: mapreduce.console(assistant, task, analysis, sections, tokens, gui_lang, subject, context.build)


def _log_item(payload):
    """ validated filter log event from the browser (structured fields only) """
    item = {}
    for key in ('src', 'dst'):
        try:
            item[key] = str(ipaddress.ip_address(str(payload.get(key) or '').strip()))
        except ValueError:
            raise ValueError('invalid %s address' % key)
    for key in ('sport', 'dport'):
        value = str(payload.get(key) or '').strip()
        item[key] = str(valid_port(value)) if value and valid_port(value) else ''
    iface = str(payload.get('iface') or '')
    item['iface'] = iface if IFACE_RE.match(iface) else ''
    item['action'] = payload.get('action') if payload.get('action') in ('pass', 'block', 'rdr', 'nat',
                                                                          'binat') else 'other'
    item['dir'] = payload.get('dir') if payload.get('dir') in ('in', 'out') else ''
    proto = str(payload.get('proto') or '').lower()
    item['proto'] = proto if re.match(r'^[a-z0-9-]{1,16}$', proto) else ''
    rid = str(payload.get('rid') or '').lower()
    item['rid'] = rid if LABEL_RE.match(rid) else ''
    try:
        item['ts'] = int(payload.get('ts') or 0)
    except (TypeError, ValueError):
        item['ts'] = 0
    return item


def explain_log(paths, payload, budget):
    item = _log_item(payload)
    names = rules.index(paths)
    rec = {'ts': item['ts'] or CLOCK(), 'iface': item['iface'], 'action': item['action'], 'dir': item['dir'],
           'proto': item['proto'], 'ipver': '6' if ':' in item['src'] else '4', 'src': item['src'],
           'dst': item['dst'], 'sport': item['sport'], 'dport': item['dport'], 'flags': '', 'rid': item['rid']}
    event = filterlog.compact(rec, fwinfo.device_map(paths.config), names)
    sections = [('event', dict(event, available=True, source='filter log line selected by the administrator'))]
    refs = {'uuids': [item['rid']] if item['rid'] else [], 'labels': [item['rid']] if item['rid'] else []}
    rule_ev = rules.evidence(paths, budget.slice(15), refs) if item['rid'] else \
        {'available': False, 'message': 'the log line has no rule label'}
    rule_ev.pop('matched_uuids', None)
    sections.append(('rule', rule_ev))
    local = [ip for ip in (item['src'], item['dst']) if is_local(ip)]
    if local:
        sections.append(('hosts', hosts.lookup(paths, local)))
    window = {'since': int(rec['ts'] - 3600), 'until': int(rec['ts'] + 300), 'label': 'the hour before the event',
              'explicit': False}
    sections.append(('source_activity', filterlog.focus(paths, window, budget.slice(8),
                                                        filterlog.Filter(ips=[item['src']]), names, samples=4)))
    if not is_local(item['src']):
        sections.append(('quarantine', quarantine.entry(paths, item['src'], now=CLOCK())))
    if item['dir'] == 'in' or item['action'] == 'block':
        sections.append(('path', rules.path(paths, src=item['src'], dst=item['dst'],
                                            dport=valid_port(item['dport']), proto=item['proto'] or None)))
    analysis = {'explain': 'filter log event', 'event_time': event['time']}
    return Task('console_explain_log', EXPLAIN_LOG, 'Explain this filter log event.'), analysis, sections, \
        'log:%s' % (item['rid'] or '-')


def explain_rule(paths, payload, budget):
    uuid = str(payload.get('uuid') or payload.get('label') or '').lower()
    if not LABEL_RE.match(uuid):
        raise ValueError('invalid rule id')
    refs = {'uuids': [uuid], 'labels': [uuid]}
    ev = rules.evidence(paths, budget.slice(15), refs)
    ev.pop('matched_uuids', None)
    sections = [('rule', ev)]
    _cfg, all_rules = rules.load(paths)
    target = None
    for pos, rule in enumerate(all_rules, 1):
        if rule.uuid == uuid:
            target = (pos, rule)
            break
    if target:
        pos, rule = target
        names = rule.interfaces_raw or []
        near = []
        for p2, other in enumerate(all_rules, 1):
            if other is rule or abs(p2 - pos) > 6:
                continue
            if rule.ifset.all or other.ifset.all or other.ifset.touches(names):
                near.append(dict(rules.entry(other, p2, None, {}, brief=True),
                                 relation='before' if p2 < pos else 'after'))
        sections.append(('neighbours', {'available': True, 'source': 'rules evaluated just before and after it',
                                        'rules': near[:8]}))
    sections.append(('findings', reports.findings(paths, rule_uuids={uuid})))
    now = CLOCK()
    window = {'since': int(now - 86400), 'until': int(now), 'label': 'last 24 h', 'explicit': False}
    sections.append(('log_hits', filterlog.focus(paths, window, budget.slice(8), filterlog.Filter(rids=[uuid]),
                                                 rules.index(paths), samples=4)))
    analysis = {'explain': 'firewall rule',
                'rule': rules.display(target[1], target[0]) if target else 'not found in the configuration'}
    return Task('console_explain_rule', EXPLAIN_RULE, 'Review this firewall rule.'), analysis, sections, \
        'rule:%s' % uuid


def explain_alert(paths, payload, budget):
    sid = str(payload.get('sid') or '')
    flow = str(payload.get('flow_id') or '')
    stamp = str(payload.get('timestamp') or '')
    if not sid.isdigit() or not flow.isdigit() or len(flow) > 20 or not re.match(r'^[0-9T:.+-]{19,40}$', stamp):
        raise ValueError('invalid alert reference')
    sid, flow = int(sid), int(flow)
    event = suricata.find(paths, budget.slice(10), stamp, flow, sid, now=CLOCK())
    if event is None:
        raise ValueError('the alert is no longer in the recent Suricata log')
    alert = suricata.compact(event)
    sections = [('alert', dict(alert, available=True, source='suricata eve.json'))]
    src = alert.get('src_ip')
    ts = suricata._epoch(stamp) or CLOCK()
    window = {'since': int(ts - 3600), 'until': int(ts + 600), 'label': 'around the alert', 'explicit': False}
    if src:
        sections.append(('source_activity', filterlog.focus(paths, window, budget.slice(8),
                                                            filterlog.Filter(ips=[src]), rules.index(paths),
                                                            samples=4)))
        if not is_local(src):
            sections.append(('quarantine', quarantine.entry(paths, src, now=CLOCK())))
    local = [ip for ip in (src, alert.get('dst_ip')) if ip and is_local(ip)]
    if local:
        sections.append(('hosts', hosts.lookup(paths, local)))
    analysis = {'explain': 'suricata alert', 'sid': sid}
    return Task('console_explain_alert', EXPLAIN_ALERT, 'Explain this Suricata alert.'), analysis, sections, \
        'alert:%s' % sid


EXPLAINERS = {'log': explain_log, 'rule': explain_rule, 'alert': explain_alert}


def cmd_explain(kind, payload, gui_lang, mode, paths=None, config=None, provider=None):
    paths = paths or Paths()
    if kind not in EXPLAINERS:
        return {'status': 'error', 'message': 'unknown item kind'}
    budget = Budget(COLLECT_SECONDS)
    try:
        task, analysis, sections, subject = EXPLAINERS[kind](paths, payload, budget)
    except ValueError as exc:
        return {'status': 'error', 'message': str(exc)}
    choice = payload.get('lang') if payload.get('lang') in LANG_CHOICES else 'auto'
    assistant = make_assistant(paths, choice, config=config)
    if provider is not None:
        assistant._provider = provider
    route = assistant.route_for(task)
    tokens = context.token_budget(assistant.config, route)
    data = context.build(analysis, sections, tokens)
    extra = {'kind': kind, 'sources': [source_line(n, d) for n, d in sections], 'context': data['context_limits'],
             'collect_ms': budget.elapsed_ms()}
    return _send(assistant, task, data, gui_lang, mode, subject, extra,
                 _map_reduce(assistant, task, route, analysis, sections, tokens, gui_lang, subject))


def cmd_log(payload, paths=None):
    paths = paths or Paths()
    ips = []
    if payload.get('ip'):
        value = str(payload['ip']).strip()
        try:
            ips = [str(ipaddress.ip_network(value, strict=False))]
        except ValueError:
            return {'status': 'error', 'message': 'invalid address'}
    port = valid_port(payload.get('port')) if payload.get('port') not in (None, '') else None
    if payload.get('port') not in (None, '') and port is None:
        return {'status': 'error', 'message': 'invalid port'}
    action = payload.get('action') if payload.get('action') in ('pass', 'block') else None
    direction = payload.get('dir') if payload.get('dir') in ('in', 'out') else None
    iface = str(payload.get('iface') or '')
    devices = devices_for(paths, [iface]) if iface and IFACE_RE.match(iface) else []
    try:
        limit = max(10, min(200, int(payload.get('limit') or 50)))
    except (TypeError, ValueError):
        limit = 50
    flt = filterlog.Filter(ips=ips, ports=[port] if port else [], action=action, devices=devices,
                           direction=direction)
    rows, meta = filterlog.tail(paths, flt, limit, Budget(8.0), rules.index(paths), now=CLOCK())
    return {'status': 'ok', 'rows': rows, 'meta': meta, 'filters': flt.describe(),
            'interfaces': [{'name': i['name'], 'descr': i['descr'], 'device': i['device'], 'wan': i['wan']}
                           for i in fwinfo.interfaces(paths.config) if i['device']]}


def cmd_rules(payload, paths=None):
    paths = paths or Paths()
    search = clean_text(payload.get('search'), 80)
    iface = str(payload.get('iface') or '')
    iface = iface if IFACE_RE.match(iface) else ''
    action = payload.get('action') if payload.get('action') in ('pass', 'block', 'reject', 'match') else ''
    return rules.table(paths, Budget(25.0), search=search, interface=iface, unused=bool(payload.get('unused')),
                       action=action)


def cmd_alerts(payload, paths=None):
    paths = paths or Paths()
    try:
        severity = int(payload.get('severity') or 0) or None
        limit = max(10, min(200, int(payload.get('limit') or 50)))
        days = max(1, min(14, int(payload.get('days') or 7)))
    except (TypeError, ValueError):
        return {'status': 'error', 'message': 'invalid filter'}
    ip = None
    if payload.get('ip'):
        try:
            ip = str(ipaddress.ip_address(str(payload['ip']).strip()))
        except ValueError:
            return {'status': 'error', 'message': 'invalid address'}
    rows, meta = suricata.tail(paths, Budget(10.0), severity_max=severity, ip=ip, limit=limit, days=days,
                               now=CLOCK())
    return {'status': 'ok', 'rows': rows, 'meta': meta}


def cmd_status(paths=None, config=None):
    paths = paths or Paths()
    config = config or AIConfig.from_opnsense(MOUNT, path=paths.config)
    return {
        'status': 'ok',
        'ai': {'enabled': config.enabled, 'provider': config.provider, 'model': config.options.get('model'),
               'route': _route_info(config),
               'anonymize': config.anonymize, 'language_setting': config.language,
               'context_tokens': context.token_budget(config)},
        'sources': {
            'filter_log': os.path.exists(paths.filter_log),
            'suricata': os.path.exists(paths.eve),
            'quarantine': os.path.exists(paths.quarantine_db),
            'host_discovery': os.path.exists(paths.hostwatch_db),
            'kea_leases': os.path.exists(paths.kea_leases),
            'config_backups': len(changes.backups(paths.backups)),
            'findings_report': os.path.exists(paths.report),
            'exposure_report': os.path.exists(paths.exposure),
        },
        'limits': {'question': MAX_QUESTION, 'history_turns': MAX_HISTORY},
    }


def _route_info(config):
    """ provider/model/mode of the console_ask scenario (the page tells when it goes to the local queue) """
    try:
        from ai import scenarios
        return scenarios.resolve('console_ask', config).as_dict()
    except Exception:                           # noqa: BLE001
        return None


def cmd_suggest(gui_lang, paths=None):
    paths = paths or Paths()
    lang = 'pt' if str(gui_lang).startswith('pt') else 'en'
    items = list(SUGGESTIONS[lang])
    # two questions built from local data (never sent anywhere): an unused rule and a known host
    report = reports.findings(paths, types={'unused'}, limit=1)
    for f in report.get('findings') or []:
        if f.get('type') == 'unused' and f.get('rules') and f['rules'][0].get('description'):
            desc = clean_text(f['rules'][0]['description'], 50)
            items.insert(2, ('A regra "%s" está sendo usada?' if lang == 'pt' else 'Is the rule "%s" being used?')
                         % desc)
    names = sorted(hosts.known_names(paths))
    if names:
        items.insert(1, ('O que o %s fez na última hora?' if lang == 'pt' else 'What did %s do in the last hour?')
                     % names[0])
    return {'status': 'ok', 'language': lang, 'suggestions': items[:8]}


def main(argv):
    args = [a for a in argv[1:]]
    cmd = args[0] if args else ''
    try:
        if cmd == 'status':
            emit(cmd_status())
        elif cmd == 'suggest':
            emit(cmd_suggest(args[1] if len(args) > 1 and LANG_RE.match(args[1]) else 'en_US'))
        elif cmd == 'ask':
            payload = decode_payload(args[1] if len(args) > 1 else '')
            gui_lang = args[2] if len(args) > 2 and LANG_RE.match(args[2]) else 'en_US'
            mode = args[3] if len(args) > 3 and args[3] in ('send', 'preview', 'route') else 'send'
            emit(cmd_ask(payload, gui_lang, mode))
        elif cmd == 'explain':
            kind = args[1] if len(args) > 1 else ''
            payload = decode_payload(args[2] if len(args) > 2 else '')
            gui_lang = args[3] if len(args) > 3 and LANG_RE.match(args[3]) else 'en_US'
            mode = args[4] if len(args) > 4 and args[4] in ('send', 'preview') else 'send'
            emit(cmd_explain(kind, payload, gui_lang, mode))
        elif cmd == 'log':
            emit(cmd_log(decode_payload(args[1] if len(args) > 1 else '')))
        elif cmd == 'rules':
            emit(cmd_rules(decode_payload(args[1] if len(args) > 1 else '')))
        elif cmd == 'alerts':
            emit(cmd_alerts(decode_payload(args[1] if len(args) > 1 else '')))
        else:
            emit({'status': 'error', 'message': 'usage: ask.py status|suggest|ask|explain|log|rules|alerts ...'})
            return 1
    except ValueError as exc:
        emit({'status': 'error', 'message': str(exc)})
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
