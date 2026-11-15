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

    Compact context for the model, within a token budget.

    The evidence sections arrive in priority order (the router's order).  When the JSON is larger than the
    budget the longest lists of the least important sections are halved first, then long strings are cut,
    and as a last resort whole low priority sections are replaced by a note.  Every cut is listed in
    "context_limits.trimmed", so the model (and the operator in the preview) know the data is partial.
"""

import copy
import json

CHARS_PER_TOKEN = 3.2        # JSON with addresses and numbers tokenizes worse than prose
DEFAULT_TOKENS = 6000
SMALL_TOKENS = 2500          # Ollama on the firewall: num_ctx 8192 shared with the answer
NEVER_TRIM = ('question_analysis',)


def size_tokens(data):
    text = json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False)
    return int(len(text) / CHARS_PER_TOKEN) + 1


def token_budget(config, route=None):
    """
    the budget of the scenario route when it sets one (ai/scenarios.py), else a smaller budget for the local
    Ollama runtime and the default for LAN/API providers
    """
    if route is not None:
        if route.budget:
            return int(route.budget)
        return SMALL_TOKENS if route.local else DEFAULT_TOKENS
    if config is None:
        return DEFAULT_TOKENS
    if config.provider == 'ollama' and config.options.get('location', 'local') != 'lan':
        return SMALL_TOKENS
    return DEFAULT_TOKENS


def _longest_list(node, path=()):
    """ (length, parent, key, path) of the longest list inside node """
    best = (0, None, None, path)
    if isinstance(node, dict):
        items = node.items()
    elif isinstance(node, list):
        items = enumerate(node)
    else:
        return best
    for key, value in items:
        if isinstance(value, list) and len(value) > best[0]:
            best = (len(value), node, key, path + (key,))
        if isinstance(value, (dict, list)):
            sub = _longest_list(value, path + (key,))
            if sub[0] > best[0]:
                best = sub
    return best


def _cut_strings(node, limit):
    changed = False
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and len(value) > limit:
                node[key] = value[:limit - 1] + '…'
                changed = True
            elif isinstance(value, (dict, list)):
                changed = _cut_strings(value, limit) or changed
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            if isinstance(value, str) and len(value) > limit:
                node[idx] = value[:limit - 1] + '…'
                changed = True
            elif isinstance(value, (dict, list)):
                changed = _cut_strings(value, limit) or changed
    return changed


def build(analysis, sections, max_tokens=DEFAULT_TOKENS):
    """
    :param analysis: router output shown to the model (intents, entities, window)
    :param sections: [(name, dict)] in priority order
    :return: data dict for the prompt
    """
    evidence = {}
    order = []
    for name, value in sections:
        if value is None:
            continue
        evidence[name] = copy.deepcopy(value)
        order.append(name)
    data = {'question_analysis': analysis, 'evidence': evidence, 'evidence_order': order}
    cuts = {}               # path -> [original length, current length]
    notes = []

    def limits():
        trimmed = ['%s: %d -> %d items' % (k, v[0], v[1]) for k, v in cuts.items()] + notes
        return {'max_tokens': max_tokens, 'estimated_tokens': 0, 'trimmed': trimmed}

    data['context_limits'] = limits()
    guard = 0
    while size_tokens(data) > max_tokens and guard < 400:
        guard += 1
        done = False
        # 1. halve the longest list of the lowest priority section that has one
        for name in reversed(order):
            if name in NEVER_TRIM or not isinstance(evidence.get(name), dict):
                continue
            length, parent, key, path = _longest_list(evidence[name])
            if length > 1:
                keep = length // 2
                parent[key] = parent[key][:keep]
                label = '%s.%s' % (name, '.'.join(str(p) for p in path))
                cuts.setdefault(label, [length, keep])[1] = keep
                done = True
                break
        if not done:
            # 2. shorten long strings everywhere
            if any(_cut_strings(evidence[n], 120) for n in order if isinstance(evidence.get(n), dict)):
                notes.append('long texts shortened to 120 characters')
                done = True
        if not done:
            # 3. drop the lowest priority section that is still there
            for name in reversed(order[1:]):
                if not evidence[name].get('omitted'):
                    evidence[name] = {'omitted': 'left out to fit the context limit'}
                    notes.append('%s: left out' % name)
                    done = True
                    break
        data['context_limits'] = limits()
        if not done:
            break
    data['context_limits']['estimated_tokens'] = size_tokens(data)
    return data
