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

    Posture health check (configd: actions_pa_posture.conf). Read only.

        cli.py run                         run every check, store posture.json + a history row, print the report
        cli.py last                        the stored report (runs once when there is none)
        cli.py summary                     light document for widgets
        cli.py history [days]              score history (default 90 days)
        cli.py explain <check id|summary> [language] [send|preview]
                                           AI text for one check, or the executive summary of the posture
        cli.py checks                      the catalogue (id, category, title, severity, references)

    Output is always one JSON document.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posture import checks as checks_mod  # noqa: E402
from posture import engine  # noqa: E402
from posture.common import CHECK_ID_RE, Paths, ai_explain, emit, valid_language  # noqa: E402

EXPLAIN_CHECK = """You explain one result of a deterministic firewall health check (benchmark style).
- Say in one sentence what was checked and the result (pass, warn, fail or na).
- Explain the practical risk for this firewall using only the evidence given.
- If the result is warn or fail, give the fix as numbered GUI steps based on the "fix" and "recommendation"
  fields (keep the menu path as written). Mention any trade-off given in fix.note.
- Never claim the fix was applied; the administrator applies it in the GUI.
- 120 to 220 words. Markdown allowed: short paragraphs, bullet or numbered lists, **bold**; no tables."""

EXECUTIVE = """You write the executive summary of a firewall security posture assessment for a manager.
- Start with the score and grade and what they mean in one sentence.
- Then the three most important problems (fail first, then high severity), each with its impact in plain
  words and the action to take; refer to checks by id (e.g. PA-ACC-01).
- Mention what improved or got worse since the previous run when "changes" has entries.
- End with one sentence on what is already in good shape (categories with a high score).
- 180 to 300 words. Markdown allowed: a short title line, bullets, **bold**; no tables."""

# keys whose list values identify people or accounts: only their number goes to the AI
COUNT_ONLY = ('administrators', 'without_otp', 'ssh_key_only', 'accounts_with_api_keys',
              'administrators_with_api_keys', 'admins_with_shell')


def ai_view(item):
    evidence = {}
    names = set()
    for key, value in (item.get('evidence') or {}).items():
        if key in COUNT_ONLY and isinstance(value, list):
            evidence[key + '_count'] = len(value)
            names.update(str(v) for v in value if v)
        else:
            evidence[key] = value
    for row in (item.get('evidence') or {}).get('weak') or []:
        if isinstance(row, dict) and row.get('user'):
            names.add(str(row['user']))
    tokens = {name: 'ACCOUNT_%d' % (idx + 1) for idx, name in enumerate(sorted(names, key=len, reverse=True))}

    def scrub(value):
        if isinstance(value, str):
            for name, token in tokens.items():
                value = re.sub(r'(?<![\w.-])%s(?![\w.-])' % re.escape(name), token, value)
            return value
        if isinstance(value, list):
            return [scrub(v) for v in value]
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        return value
    out = {k: item.get(k) for k in ('id', 'category_label', 'title', 'severity', 'result', 'summary',
                                     'recommendation')}
    out['evidence'] = evidence
    out['references'] = [r.get('label') for r in item.get('references') or []]
    if item.get('fix'):
        out['fix'] = {k: v for k, v in item['fix'].items() if k in ('path', 'diff', 'note')}
    return scrub(out)


def executive_view(report):
    return {
        'score': report.get('score'), 'grade': report.get('grade'), 'counts': report.get('counts'),
        'categories': {v['label']: {'score': v['score'], 'fail': v['fail'], 'warn': v['warn']}
                       for v in (report.get('by_category') or {}).values()},
        'failing': [{'id': c['id'], 'title': c['title'], 'severity': c['severity'], 'summary': c['summary']}
                    for c in report.get('checks', []) if c['result'] == 'fail'],
        'warnings': [{'id': c['id'], 'title': c['title'], 'severity': c['severity']}
                     for c in report.get('checks', []) if c['result'] == 'warn'][:15],
        'changes': {k: v for k, v in (report.get('changes') or {}).items()
                    if k in ('delta', 'new_failures', 'fixed', 'previous_score')},
        'firmware_version': (report.get('system') or {}).get('version'),
    }


def cmd_explain(paths, args, assistant=None):
    target = args[0] if args else ''
    language = valid_language(args[1]) if len(args) > 1 else None
    mode = args[2] if len(args) > 2 and args[2] in ('send', 'preview') else 'send'
    report = engine.last(paths)
    if report.get('status') != 'ok':
        return report
    if target == 'summary':
        data = executive_view(report)
        result = ai_explain(paths, 'posture-ai.json', 'posture_summary', EXECUTIVE,
                            'Write the executive summary of this posture assessment.', data, language, mode,
                            subject='posture:summary', assistant=assistant)
    else:
        if not CHECK_ID_RE.match(target):
            return {'status': 'error', 'message': 'invalid check id'}
        item = next((c for c in report['checks'] if c['id'] == target), None)
        if item is None:
            return {'status': 'error', 'message': 'check not found in the last report'}
        result = ai_explain(paths, 'posture-ai.json', 'posture_check', EXPLAIN_CHECK,
                            'Explain this health check result.', ai_view(item), language, mode,
                            subject='posture:%s' % target, assistant=assistant)
    result['target'] = target
    result['report_generated'] = report.get('generated')
    return result


def catalogue():
    return {'status': 'ok', 'categories': checks_mod.CATEGORIES,
            'checks': [{'id': c.id, 'category': c.category, 'title': c.title, 'severity': c.severity,
                        'references': c.references, 'page': c.page, 'recommendation': c.recommendation}
                       for c in checks_mod.CHECKS]}


def main(argv, paths=None, runner=None, assistant=None):
    paths = paths or Paths()
    cmd = argv[0] if argv else 'last'
    args = argv[1:]
    if cmd == 'run':
        return engine.run(paths, runner, write='--no-write' not in args)
    if cmd == 'last':
        return engine.last(paths, runner)
    if cmd == 'summary':
        return engine.summary(engine.last(paths, runner))
    if cmd == 'history':
        days = int(args[0]) if args and args[0].isdigit() and 0 < int(args[0]) <= 400 else 90
        store = engine.Store(paths.db('posture.db'))
        try:
            return {'status': 'ok', 'days': days, 'history': store.history(days)}
        finally:
            store.close()
    if cmd == 'explain':
        return cmd_explain(paths, args, assistant)
    if cmd == 'checks':
        return catalogue()
    return {'status': 'error', 'message': 'unknown command'}


if __name__ == '__main__':
    try:
        emit(main(sys.argv[1:]))
    except Exception as exc:  # noqa: BLE001 - configd expects JSON, never a traceback
        emit({'status': 'error', 'message': '%s: %s' % (exc.__class__.__name__, exc)})
