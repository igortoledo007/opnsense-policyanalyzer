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

    Explain Policy Analyzer findings with the configured AI provider.

    Usage (via configd, arguments are validated here as well):
        explain.py explain <finding id|all> [language] [send|preview] [--stream]
        explain.py test
        explain.py models
        explain.py providers             provider registry (choices, fields, privacy) for the GUI
        explain.py routing               AI per scenario: catalog, presets, routing file and resolved routes

    Changes to the system (storage, ...) are not done here, see manage.py.

    Output is always one JSON document on stdout, except with --stream
    (command line only) where the answer is printed as it arrives.
    Read only: findings come from the last analysis report, the answer is
    text and nothing is ever applied to the configuration.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai import AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task, is_queued  # noqa: E402
from ai import mapreduce, providers  # noqa: E402

MOUNT = 'OPNsense/policyanalyzer'
CONFIG_XML = os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')
REPORT = os.environ.get('POLICYANALYZER_REPORT', '/var/db/policyanalyzer/last.json')
AUDIT_LOG = os.environ.get('POLICYANALYZER_AILOG', '/var/log/policyanalyzer/ai.log')

ID_RE = re.compile(r'^[0-9a-f]{6,64}$')
LANG_RE = re.compile(r'^[a-z]{2,3}(_[A-Z]{2})?$')
SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
MAX_FINDINGS_ALL = 40
USAGE = 'usage: explain.py explain <id|all> [lang] [send|preview] | test | models | providers | routing'

FINDING_INSTRUCTIONS = """You explain one finding of the OPNsense Policy Analyzer, a deterministic, read-only
review of the firewall rule set. The finding (type, severity, deterministic detail, recommendation, the
rules involved and the evidence) is in the DATA block.
Structure the answer as:
- What it means: the finding in plain words, citing the rules involved.
- Why it matters: the security or maintenance impact, consistent with the severity given.
- What I would check: concrete steps in Firewall > Rules for a human to verify before changing anything.
- Suggested change: in words only, or "none" if the rule set looks intentional. Mention that rule order and
  floating/group rules may change the picture when the evidence is incomplete.
Do not contradict the deterministic detail; if you think it may be a false positive, say why using the data."""

SET_INSTRUCTIONS = """You summarise the findings of the OPNsense Policy Analyzer, a deterministic, read-only
review of the firewall rule set. The DATA block holds the summary counters and the most important findings.
Structure the answer as:
- Overview: the overall state of the rule set in two or three sentences.
- Priorities: the findings to look at first and why, citing their titles and rules.
- Clean-up plan: a short ordered list of review steps for a human; nothing is applied automatically.
Only mention findings present in the data."""

RULE_FIELDS = ('source', 'interface', 'direction', 'action', 'sequence', 'description', 'summary', 'disabled')
FINDING_FIELDS = ('id', 'type', 'severity', 'title', 'detail', 'recommendation', 'aliases', 'evidence')


def emit(data):
    sys.stdout.write(json.dumps(data) + '\n')
    sys.stdout.flush()


def load_report():
    try:
        with open(REPORT) as handle:
            report = json.load(handle)
    except (OSError, ValueError):
        return None
    return report if isinstance(report, dict) else None


def compact_rule(rule):
    return {k: rule[k] for k in RULE_FIELDS if isinstance(rule, dict) and k in rule}


def compact_finding(finding, with_evidence=True):
    """ data minimisation: only the fields the model needs, uuids are left out """
    result = {k: finding[k] for k in FINDING_FIELDS if k in finding and (with_evidence or k != 'evidence')}
    result['rules'] = [compact_rule(r) for r in finding.get('rules') or []]
    return result


def subject_data(report, finding_id):
    findings = [f for f in report.get('findings') or [] if isinstance(f, dict)]
    if finding_id == 'all':
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get('severity'), 9))
        data = {
            'summary': report.get('summary', {}),
            'stats_available': report.get('stats_available'),
            'generated': report.get('generated'),
            'findings_total': len(findings),
            'findings_included': min(len(findings), MAX_FINDINGS_ALL),
            'findings': [compact_finding(f, with_evidence=False) for f in findings[:MAX_FINDINGS_ALL]],
        }
        task = Task('explain_set', SET_INSTRUCTIONS, 'Summarise these policy analysis findings.')
        return task, data
    for finding in findings:
        if finding.get('id') == finding_id:
            data = compact_finding(finding)
            data['stats_available'] = report.get('stats_available')
            task = Task('explain_finding', FINDING_INSTRUCTIONS, 'Explain this policy analysis finding.')
            return task, data
    return None, None


def make_assistant():
    config = AIConfig.from_opnsense(MOUNT, path=CONFIG_XML)
    return Assistant(config, app='policyanalyzer', audit=AuditLog(AUDIT_LOG))


def cmd_explain(args):
    stream = '--stream' in args
    args = [a for a in args if a != '--stream']
    finding_id = args[0] if len(args) > 0 else ''
    language = args[1] if len(args) > 1 and LANG_RE.match(args[1]) else None
    mode = args[2] if len(args) > 2 and args[2] in ('send', 'preview') else 'send'
    if finding_id != 'all' and not ID_RE.match(finding_id):
        return emit({'status': 'error', 'message': 'invalid finding id'})
    report = load_report()
    if report is None:
        return emit({'status': 'error', 'message': 'no analysis report found, run an analysis first'})
    task, data = subject_data(report, finding_id)
    if task is None:
        return emit({'status': 'error', 'message': 'finding not found in the last report, run the analysis again'})
    assistant = make_assistant()
    if mode == 'preview':
        result = assistant.preview(task, data, language)
        result['finding'] = finding_id
        return emit(result)
    on_chunk = None
    if stream:
        def on_chunk(text):
            sys.stdout.write(text)
            sys.stdout.flush()
    try:
        route = assistant.route_for(task)
        if finding_id == 'all' and mapreduce.needed(route, data):
            # local model: batches of findings, then one consolidation (ai/mapreduce.py)
            result = mapreduce.explain_set(assistant, task, data, language, 'finding:all', route.budget)
        else:
            result = assistant.ask(task, data, language=language, subject='finding:%s' % finding_id,
                                   stream=stream, on_chunk=on_chunk)
    except AIDisabled as exc:
        return emit({'status': 'disabled', 'message': str(exc)})
    except ProviderRefusal as exc:
        return emit({'status': 'refusal', 'message': str(exc)})
    except ProviderError as exc:
        return emit({'status': 'error', 'message': str(exc)})
    if stream:
        sys.stdout.write('\n')
        return
    result['finding'] = finding_id
    if is_queued(result):
        return emit(result)
    result['report_generated'] = report.get('generated')
    emit(result)


def cmd_test(_args):
    try:
        emit(make_assistant().test())
    except ProviderError as exc:
        emit({'status': 'error', 'message': str(exc)})


def cmd_models(_args):
    try:
        emit(make_assistant().list_models())
    except ProviderError as exc:
        emit({'status': 'error', 'message': str(exc)})


def cmd_providers(_args):
    emit(providers.describe())


def cmd_routing(_args):
    from ai import scenarios
    emit(scenarios.describe(AIConfig.from_opnsense(MOUNT, path=CONFIG_XML)))


def main(argv):
    commands = {'explain': cmd_explain, 'test': cmd_test, 'models': cmd_models, 'providers': cmd_providers,
                'routing': cmd_routing}
    if len(argv) < 2 or argv[1] not in commands:
        emit({'status': 'error', 'message': USAGE})
        return 1
    commands[argv[1]](argv[2:])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
