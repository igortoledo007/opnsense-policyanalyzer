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

    Answer checks for the AI scenarios (format, number of sentences, sections,
    citations, language) and the helpers that make small local models usable:

        strip_think(text)                remove <think>...</think> (qwen3, deepseek-r1), also the reasoning before a
                                         lone </think> (Qwen3 "Thinking-2507": the template opens <think> itself)
        strip_reasoning(text, language)  (text, leaked): reasoning that leaked WITHOUT tags ("Okay, let's tackle
                                         this. The user wants ...") is cut when a final answer follows it
        leaked_reasoning(text)           True when the text reads like the model's planning notes
        ThinkFilter().feed(piece)        the same for a streamed answer
        detect_language(text)            'pt' | 'en' | None (simple marker heuristic)
        check(scenario, text, language, ctx)  -> list of problems (empty: the answer is fine)
        correction(problems, language)   the user message of the one correction attempt

    The checks are deliberately tolerant (the numbers of the bench of 2026-11-08 with a margin): their purpose
    is to catch a wrong format or language, not to grade the text.
"""

import json
import re

from .prompts import language_name

THINK_RE = re.compile(r'<think>.*?</think>', re.S | re.I)
PT_RE = re.compile(r'\b(não|que|para|com|uma|são|está|regra|porta|endereço|tráfego|você|também|isso|pelo|pela|'
                   r'como|mais|seu|sua|nos|das|dos|ao|à|é|foi|há|então|pode|deve)\b', re.I)
EN_RE = re.compile(r'\b(the|and|is|are|this|that|with|from|which|rule|traffic|should|would|you|your|of|it|was|'
                   r'has|have|can|there)\b', re.I)
# strict check only (published texts): short Portuguese function words and accented words, absent from English
PT_EXTRA_RE = re.compile(r'\b(e|o|a|os|as|de|do|da|em|no|na|um|por|sem|nenhum|nenhuma|foram|foi|houve|última|'
                         r'últimas|hora|horas|período|conexões|origens|bloqueios|sugiro|recomendo)\b|'
                         r'\b\w*[ãõçáéíóúâêô]\w*\b', re.I)
CJK_RE = re.compile(r'[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]')
CITATION_RE = re.compile(r'\[[A-Za-z_]+:[^\]]+\]')
HEADING_RE = re.compile(r'(^|\n)\s*#{2,4}\s')
MARKDOWN_RE = re.compile(r'(^|\n)\s*([-*•]|\d+\.)\s|\*\*|(^|\n)#')
SENTENCE_SPLIT_RE = re.compile(r'(?<=[.!?])\s+(?=[A-ZÁÉÍÓÚÂÊÔÃÕÇ0-9"(])')


def strip_think(text):
    """
    drop reasoning blocks; an unterminated <think> (cut by num_predict) drops everything after it; a lone
    </think> (the chat template already opened <think>, e.g. Qwen3-30B-A3B-Thinking-2507) drops everything before it
    """
    text = THINK_RE.sub('', str(text or ''))
    low = text.lower()
    if '</think>' in low and '<think>' not in low[:low.rindex('</think>')]:
        text = text[low.rindex('</think>') + 8:]
        low = text.lower()
    if '<think>' in low:
        text = text[:low.index('<think>')]
    return text.replace('</think>', '').strip()


# planning notes of a thinking model that leaked into the answer without <think> tags (qwen3 with think=false,
# deepseek-r1 distills): English, first person, talks about "the user" and the instructions
REASONING_START_RE = re.compile(
    r"^\W*(okay|ok|alright|all right|hmm+|so,|well,|first,|let me|let's|let us|i need|i will|i'll|i should|"
    r"i must|i have to|the user|we need|we have|looking at|to (?:write|answer|summari[sz]e)|now,)\b", re.I)
STRONG_START_RE = re.compile(r"^\W*(okay|ok,|alright|all right|hmm+|let me|let's|let us|i need|i'll|i will|i must|"
                             r"i have to|the user|we need)\b", re.I)
REASONING_RE = re.compile(
    r"(?i)(\bokay,? (?:so|let'?s|let me)\b|\blet me (?:think|check|start|see|look|recall|make sure|count|draft|"
    r"structure|verify|confirm|go|try|put|write|rephrase|read|re-?read|parse|analy[sz]e|figure|focus)\b|"
    r"\bthe user (?:wants|want|asked|asks|is asking|said|says|mentioned|needs|provided|wrote|specified|requested)\b|"
    r"\bfirst,? i (?:need|should|will|must|have)\b|\bi need to\b|\bwait,|\bhmm+\b|"
    r"\blet'?s (?:tackle|see|start|break|look|check|draft|count|go|make|put|think|structure|verify)\b|"
    r"\bthe instructions (?:say|said|ask|are)\b|"
    r"\bin brazilian portuguese\b|\bthe (?:answer|summary|response) (?:should|must|needs)\b|"
    r"\bso the (?:summary|answer|response)\b|\bnext step(?: is|:)? (?:to )?(?:suggest|mention)\b|"
    r"\bi'?ll (?:start|write|mention|need|go|check|draft)\b)")
ANSWER_LABEL_RE = re.compile(r'(?im)^\W*(final answer|answer|resposta final|resposta|resumo(?: executivo)?|'
                             r'summary|executive summary)\W*:\W*$')


def reasoning_markers(text):
    return len(REASONING_RE.findall(_plain(text)))


def leaked_reasoning(text):
    """ True when the text (or its start) reads like the planning notes of a thinking model """
    body = _plain(text).strip()
    if not body:
        return False
    head = body[:400]
    hits = reasoning_markers(body)
    if STRONG_START_RE.search(head) or (REASONING_START_RE.search(head) and hits >= 1):
        return True
    return hits >= 2


def strip_reasoning(text, language=None):
    """
    :return: (text, leaked). When the planning notes leaked without tags and a final answer in the expected
             language follows them (last paragraphs, or after a "Final answer:" label), only that answer is
             kept. Otherwise the text is returned unchanged and leaked=True (the check then rejects it).
    """
    text = str(text or '').strip()
    if not leaked_reasoning(text):
        return text, False
    want = expected_language(language)
    label = None
    for match in ANSWER_LABEL_RE.finditer(text):
        label = match
    if label is not None:
        tail = text[label.end():].strip()
        if _acceptable_answer(tail, language):
            return tail, True
    paras = [p.strip() for p in re.split(r'\n\s*\n', text) if p.strip()]
    keep = []
    for para in reversed(paras):
        if REASONING_RE.search(para) or REASONING_START_RE.search(para) or \
                (want is not None and detect_language(para) not in (None, want)):
            break
        keep.insert(0, para)
    tail = '\n\n'.join(keep)
    if keep and len(keep) < len(paras) and _acceptable_answer(tail, language):
        return tail, True
    return text, True


def _acceptable_answer(text, language):
    if not text or words(text) < 5 or reasoning_markers(text) or REASONING_START_RE.search(text[:200]):
        return False
    return not check_language(text, language, strict=True)


class ThinkFilter:
    """ streaming version of strip_think: feed() returns only the visible part """

    def __init__(self):
        self.buffer = ''
        self.inside = False

    def feed(self, piece):
        self.buffer += piece or ''
        out = []
        while self.buffer:
            if self.inside:
                end = self.buffer.lower().find('</think>')
                if end < 0:
                    # keep a possible partial closing tag
                    self.buffer = self.buffer[-8:]
                    return ''.join(out)
                self.buffer = self.buffer[end + 8:]
                self.inside = False
                continue
            start = self.buffer.lower().find('<think>')
            if start < 0:
                # a "<" near the end may start a tag: hold it back
                cut = self.buffer.rfind('<')
                if cut >= 0 and len(self.buffer) - cut < 7:
                    out.append(self.buffer[:cut])
                    self.buffer = self.buffer[cut:]
                else:
                    out.append(self.buffer)
                    self.buffer = ''
                return ''.join(out)
            out.append(self.buffer[:start])
            self.buffer = self.buffer[start + 7:]
            self.inside = True
        return ''.join(out)

    def flush(self):
        rest = '' if self.inside else self.buffer
        self.buffer = ''
        return rest


def _plain(text):
    text = re.sub(r'```.*?```', ' ', str(text or ''), flags=re.S)
    return re.sub(r'`[^`]*`', ' ', text)


def detect_language(text):
    """ 'pt', 'en' or None when the text is too short or mixed """
    body = _plain(text)
    pt, en = len(PT_RE.findall(body)), len(EN_RE.findall(body))
    if pt >= 3 and pt > 1.5 * en:
        return 'pt'
    if en >= 3 and en > 1.5 * pt:
        return 'en'
    return None


def expected_language(code):
    """ OPNsense locale -> 'pt' | 'en' | None (other languages are not checked) """
    code = str(code or '').lower()
    if code.startswith('pt'):
        return 'pt'
    if code.startswith('en'):
        return 'en'
    return None


def sentences(text):
    plain = re.sub(r'\s+', ' ', str(text or '')).strip()
    return len([p for p in SENTENCE_SPLIT_RE.split(plain) if p.strip()]) if plain else 0


def words(text):
    return len(re.findall(r'\w+', str(text or '')))


def _json_doc(text):
    raw = str(text or '').strip()
    start, end = raw.find('{'), raw.rfind('}')
    if start < 0 or end <= start:
        return None
    try:
        doc = json.loads(raw[start:end + 1])
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _json_text(doc):
    parts = []

    def walk(node):
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                if key not in ('id', 'duration', 'confidence'):
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(doc)
    return ' '.join(parts)


REASONING_PROBLEM = ('the answer contains your reasoning (planning notes in English) instead of the final text; '
                     'write only the final answer, no notes about the task or the user')
LANGUAGE_PROBLEM = 'the answer is not in %s'


def check_reasoning(text):
    if _json_doc(text) is not None and str(text or '').lstrip().startswith('{'):
        return []
    return [REASONING_PROBLEM] if leaked_reasoning(text) else []


def language_share(text):
    """ (pt markers, en markers) of the text, the broad Portuguese list of the strict check """
    body = _plain(text)
    return len(PT_EXTRA_RE.findall(body)), len(EN_RE.findall(body))


def check_language(text, language, strict=False):
    """ strict (texts published in e-mails, PDFs and the dashboard): mixed text with a large share of English
    (or of Portuguese, for an English target) is also rejected """
    want = expected_language(language)
    if want is None:
        return []
    body = text
    doc = _json_doc(text) if str(text or '').lstrip().startswith('{') else None
    if doc is not None:
        body = _json_text(doc)
    if CJK_RE.search(_plain(body)):
        return ['the answer contains Chinese/Japanese/Korean characters; it must be written only in %s'
                % language_name(language)]
    got = detect_language(body)
    if got is not None and got != want:
        return [LANGUAGE_PROBLEM % language_name(language)]
    if strict:
        pt, en = language_share(body)
        mine, other = (pt, en) if want == 'pt' else (en, pt)
        if (mine + other >= 4 and other > 0.35 * (mine + other)) or (words(body) >= 12 and mine < 2):
            return [LANGUAGE_PROBLEM % language_name(language)]
    return []


def hard_problems(problems):
    """ the problems that make a published text unusable: empty, wrong language, leaked reasoning """
    return [p for p in problems or [] if p == 'the answer is empty' or p.startswith('the answer is not in') or
            'characters' in p or p == REASONING_PROBLEM]


def check_format(checks, text, ctx=None):
    """ :param checks: catalog spec; :param ctx: {"valid_ids": [...], "first_values": [...]} """
    ctx = ctx or {}
    problems = []
    text = str(text or '')
    if not text.strip():
        return ['the answer is empty']
    low = text.lower()
    if checks.get('sections'):
        keys = checks['sections']
        found = [k for k in keys if any(alt in low for alt in k.split('|'))]
        if len(found) < len(keys) - 1:
            missing = [k.split('|')[1] if '|' in k else k for k in keys if k not in found]
            problems.append('missing sections: %s (use these section titles, each on its own line)'
                            % ', '.join(missing))
    if checks.get('sentences'):
        lo, hi = checks['sentences']
        n = sentences(text)
        if n < lo or n > hi + 1:
            problems.append('it has %d sentences; write %d to %d sentences' % (n, lo, hi))
    if checks.get('plain') and MARKDOWN_RE.search(text):
        problems.append('use plain text: no lists, no headings, no bold')
    if checks.get('words'):
        lo, hi = checks['words']
        n = words(text)
        if n > hi or (lo and n < lo):
            problems.append('it has %d words; keep it between %d and %d words' % (n, lo, hi))
    if checks.get('citations'):
        n = len(CITATION_RE.findall(text))
        if n < checks['citations']:
            problems.append('cite the evidence inline in square brackets with the section name, e.g. '
                            '[filterlog: 14 blocks, last 10:15]')
    if checks.get('headings'):
        n = len(HEADING_RE.findall(text))
        if n < checks['headings']:
            problems.append('structure the answer with the ### headings given in the instructions')
    if checks.get('first_line'):
        tag = checks['first_line']
        first = text.strip().splitlines()[0].strip() if text.strip() else ''
        match = re.match(r'^%s:\s*([A-Za-z0-9_.-]+)' % tag, first, re.I)
        values = ctx.get('first_values')
        if not match:
            problems.append('the first line must be exactly "%s: <value>"' % tag)
        elif values and match.group(1).lower() not in values:
            problems.append('"%s: %s" is not one of: %s' % (tag, match.group(1), ', '.join(values)))
    if checks.get('json'):
        doc = _json_doc(text)
        if doc is None:
            problems.append('answer with ONE JSON object and nothing else')
        else:
            for key in checks['json']:
                if not isinstance(doc.get(key), str) or not doc.get(key).strip():
                    problems.append('the JSON object needs a non empty "%s"' % key)
            valid = ctx.get('valid_ids')
            if checks.get('actions') and valid is not None:
                bad = [str(a.get('id')) for a in doc.get('actions') or [] if isinstance(a, dict) and
                       str(a.get('id')) not in valid]
                if bad:
                    problems.append('actions may only use ids of candidate_actions; invalid: %s' % ', '.join(bad))
    return problems


def check(scenario, text, language=None, ctx=None, checks=None):
    """ :return: list of problems (format first, then language) """
    if checks is None:
        from .scenarios import CATALOG
        checks = (CATALOG.get(scenario) or {}).get('checks') or {}
    problems = check_format(checks, text, ctx)
    if not checks.get('json') and not checks.get('first_line'):
        problems += check_reasoning(text)
    return problems + check_language(text, language, strict=bool(checks.get('publish')))


def correction(problems, language):
    """ user message of the correction attempt """
    return ('Your previous answer does not follow the instructions: %s. Rewrite the COMPLETE answer, following '
            'the task instructions and the format exactly, in %s. Reply only with the corrected answer.'
            % ('; '.join(problems), language_name(language)))


def no_reasoning_note(language):
    """ appended to the user message of the new attempt after leaked reasoning (the reasoning is NOT sent back) """
    return ('IMPORTANT: reply directly with the final text only, in %s. Do not write any reasoning, plan, draft or '
            'notes about the task.' % language_name(language))


def language_reminder(language):
    """ appended to the last user message for the local models (the system prompt alone is not enough) """
    return 'Write the whole answer in %s.' % language_name(language)
