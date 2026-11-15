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

    Map/reduce for data above the context budget of a route (local models).

    The local runtime reads a prompt at 13-27 tokens/s and loses format, language and citations above ~3k tokens
    (docs/bench-ia-local.md).  Instead of cutting the data, the scenario is split:

        map     each batch (findings, or evidence sections of the AI Console) goes in its own short call that
                only extracts notes (no validation, same route as the scenario);
        reduce  the original task runs once over the notes, with its usual validation and correction.

    Used only when the route is the Ollama of this firewall: the notes come back with the real values (they
    are restored by the Assistant) and are anonymized again only by pattern, so they never go to a provider
    outside the firewall.
"""

import json

from .assistant import Task, is_queued

CHARS_PER_TOKEN = 3.2
MAX_PARTS = 8

MAP_SET = """You read ONE BATCH of the findings of the OPNsense Policy Analyzer (a deterministic, read-only review of
the firewall rule set); the other batches are read separately and a final step writes the summary.
Write notes, not the final summary: one short bullet per finding with its severity, title, the rule involved
(interface, sequence, action, summary exactly as in the data) and in a few words why it matters. Group duplicates.
At most 120 words. Only facts present in the data."""

MAP_SET_REDUCE = """The DATA block holds the summary counters of the report and "batch_notes": notes written from each
batch of findings (the findings themselves were too many for one request). Base the answer only on the counters
and on those notes."""

MAP_CONSOLE = """You read PART of the evidence collected for the administrator's question below; the other parts are
read separately and a final step writes the answer. Extract only the facts of this part that help to answer the
question, as short bullets, each with its citation in square brackets naming the section and the item exactly as
the final answer must cite it, for example [filterlog: 14 blocks, last 10:15, rule lan #3 block "Block IoT"].
Say "nothing relevant" when the part does not help. At most 150 words. Do not answer the question yet."""

MAP_CONSOLE_REDUCE = """The evidence was too large for one request: "evidence_notes" holds the facts extracted from each
part of it, with their citations. Cite those bracketed citations as given; question_analysis and evidence_order
still describe what was collected."""


def size_tokens(data):
    text = data if isinstance(data, str) else json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False)
    return int(len(text) / CHARS_PER_TOKEN) + 1


def pack(items, budget, base=None, limit=MAX_PARTS):
    """ greedy batches whose JSON (with the common part) stays within budget; never more than limit batches """
    base_size = size_tokens(base) if base is not None else 0
    room = max(200, budget - base_size)
    batches, current, used = [], [], 0
    for item in items:
        cost = int(size_tokens(item) * 1.15) + 2        # nesting adds indentation and separators
        if current and used + cost > room:
            batches.append(current)
            current, used = [], 0
        current.append(item)
        used += cost
    if current:
        batches.append(current)
    while len(batches) > limit:
        # merge the two smallest neighbours (the parts get bigger, the count stays bounded)
        idx = min(range(len(batches) - 1), key=lambda i: len(batches[i]) + len(batches[i + 1]))
        batches[idx:idx + 2] = [batches[idx] + batches[idx + 1]]
    return batches


def needed(route, data, budget=None):
    budget = budget or route.budget
    return bool(route.local and budget and size_tokens(data) > budget)


def explain_set(assistant, task, data, language, subject, budget):
    """ :return: Assistant result of the reduce step (or the queued result of the first part) """
    findings = list(data.get('findings') or [])
    common = {k: v for k, v in data.items() if k != 'findings'}
    parts = pack(findings, budget, common)
    notes = []
    for idx, part in enumerate(parts, 1):
        sub = Task('explain_set_part', MAP_SET, 'Write the notes of batch %d of %d.' % (idx, len(parts)),
                   scenario=task.scenario, validate=False)
        res = assistant.ask(sub, dict(common, batch=idx, batches=len(parts), findings=part), language=language,
                            subject='%s:part%d' % (subject, idx))
        if is_queued(res):
            return res
        notes.append({'batch': idx, 'findings': len(part), 'notes': res.get('text') or ''})
    reduce_task = Task(task.name, task.instructions + '\n' + MAP_SET_REDUCE, task.question, scenario=task.scenario,
                       schema=task.schema, render=task.render, check_ctx=task.check_ctx)
    result = assistant.ask(reduce_task, dict(common, batch_notes=notes), language=language, subject=subject)
    if not is_queued(result):
        result['map_reduce'] = {'parts': len(parts), 'items': len(findings)}
    return result


def console(assistant, task, analysis, sections, budget, language, subject, build):
    """
    :param build: console.context.build (analysis, sections, max_tokens) -> data
    :return: (result, data_sent) or (None, None) when the evidence fits the budget
    """
    full = build(analysis, sections, budget * 4)
    if size_tokens(full) <= budget:
        return None, None
    named = [(n, d) for n, d in sections if d is not None]
    room = max(300, budget - size_tokens({'question_analysis': analysis}))
    groups, current, used = [], [], 0
    for name, value in named:
        cost = min(size_tokens({name: value}), room)     # a bigger section is trimmed by build() in its part
        if current and used + cost > room:
            groups.append(current)
            current, used = [], 0
        current.append({'name': name, 'value': value})
        used += cost
    if current:
        groups.append(current)
    groups = groups[:MAX_PARTS]
    notes = []
    for idx, group in enumerate(groups, 1):
        part = build(analysis, [(p['name'], p['value']) for p in group], budget)
        sub = Task('%s_part' % task.name, MAP_CONSOLE, task.question, scenario=task.scenario, validate=False)
        res = assistant.ask(sub, part, language=language, subject='%s:part%d' % (subject, idx))
        if is_queued(res):
            return res, None
        notes.append({'sections': [p['name'] for p in group], 'notes': res.get('text') or ''})
    data = {'question_analysis': analysis, 'evidence_order': [n for n, _ in named], 'evidence_notes': notes,
            'context_limits': {'max_tokens': budget, 'map_reduce': len(groups),
                               'estimated_tokens': size_tokens(full), 'trimmed': []}}
    reduce_task = Task(task.name, task.instructions + '\n' + MAP_CONSOLE_REDUCE, task.question,
                       scenario=task.scenario)
    result = assistant.ask(reduce_task, data, language=language, subject=subject)
    if not is_queued(result):
        result['map_reduce'] = {'parts': len(groups), 'sections': len(named)}
    return result, data
