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

    "Explain anomaly" and "Explain host" with the configured AI provider (Assistant of the ai package:
    anonymization, guardrails, audit in /var/log/policyanalyzer/ai.log).  The detectors decided; the model
    only explains the factors and suggests what a human could check.  The buttons of the GUI come from the
    finding (engine.suggested_actions), never from the answer: nothing is applied.
"""

import os

from ai import AIConfig, AIDisabled, Assistant, AuditLog, ProviderError, ProviderRefusal, Task

MOUNT = 'OPNsense/policyanalyzer'
AUDIT_LOG = os.environ.get('POLICYANALYZER_AILOG', '/var/log/policyanalyzer/ai.log')

FINDING_INSTRUCTIONS = """You explain one finding of the anomaly detection of the firewall (OPNsense Policy
Analyzer, a lightweight NDR). A deterministic detector produced it; the DATA block holds the detector type, the
severity, the factors it measured (value, threshold, whether each factor counted), the evidence, the parameters
and the history of occurrences.
Structure the answer as:
- What was detected: the behaviour in plain words, citing the factors that counted and their values.
- Likely explanations: the benign ones (software updates, backups, monitoring agents, smart TVs, VPN clients,
  CDNs, inventory tools...) and the malicious one, with what in the data supports or weakens each.
- What I would check: concrete steps a human can take (which device it is, Live View, the AI Console, the
  owner of the device), in order.
- Suggested actions: choose only among the "available_actions" of the data (they are buttons a human may press
  after a simulation; nothing happens automatically). Recommend "Mark as expected" when it looks legitimate.
Do not contradict the factors; if you think it is a false positive, say which factor misleads and why."""

HOST_INSTRUCTIONS = """You describe one internal host of the network for the administrator of the firewall
(OPNsense Policy Analyzer anomaly detection). The DATA block holds its profile: what is normal for it (hourly
outbound bytes baseline, DNS queries and NXDOMAIN per hour, countries and ASNs it talks to, number of domains
and TLS fingerprints learned), what it is doing now (this hour, top destinations of the last 24 h, last DNS
hour) and its anomaly findings.
Structure the answer as:
- Who it looks like: the kind of device suggested by the data (vendor, host name, traffic pattern), tentative.
- Normal vs. now: compare the current values with the baseline using the numbers.
- Findings: the open findings in order of importance and whether they fit the profile.
- What I would check: concrete next steps; choose actions only among "available_actions" (buttons a human
  may press; nothing is applied automatically)."""

FINDING_FIELDS = ('type', 'type_title', 'severity', 'score', 'max_score', 'status', 'title', 'detail', 'key',
                  'host', 'mac', 'hostname', 'first_seen_iso', 'last_seen_iso', 'occurrences', 'factors', 'params')


def compact_finding(f):
    data = {k: f.get(k) for k in FINDING_FIELDS if f.get(k) not in (None, '', [])}
    ev = dict(f.get('evidence') or {})
    for key in ('recent', 'targets'):
        if isinstance(ev.get(key), list):
            ev[key] = ev[key][:12]
    data['evidence'] = ev
    data['occurrence_history'] = [{'severity': o['severity'], 'score': o['score'], 'status': o['status']}
                                  for o in (f.get('occurrence_list') or [])[:10]]
    data['available_actions'] = [a['label'] for a in f.get('actions') or []]
    return data


def compact_host(profile):
    data = {k: profile.get(k) for k in ('host', 'device', 'first_seen', 'last_seen', 'normal', 'now')}
    data['findings'] = [{k: f.get(k) for k in ('type', 'severity', 'score', 'status', 'detail', 'last_seen_iso',
                                               'occurrences')} for f in profile.get('findings') or []][:15]
    points = (profile.get('series') or {}).get('points') or []
    data['hourly_outbound_last_48h'] = [{'hour': p['t'], 'bytes': p['v'], 'baseline': p['b']} for p in points[-48:]]
    data['available_actions'] = [a['label'] for a in profile.get('actions') or []]
    return data


def make_assistant(config_path):
    config = AIConfig.from_opnsense(MOUNT, path=config_path)
    return Assistant(config, app='policyanalyzer', audit=AuditLog(AUDIT_LOG))


def ask(kind, subject_id, data, language, mode, config_path, assistant=None):
    if kind == 'finding':
        task = Task('anomaly_explain', FINDING_INSTRUCTIONS, 'Explain this anomaly finding.')
    else:
        task = Task('anomaly_host', HOST_INSTRUCTIONS, 'Describe this host: what is normal for it and what is '
                                                         'happening now.')
    assistant = assistant or make_assistant(config_path)
    if mode == 'preview':
        result = assistant.preview(task, data, language)
        result['subject'] = subject_id
        return result
    try:
        result = assistant.ask(task, data, language=language, subject='anomaly-%s:%s' % (kind, subject_id))
    except AIDisabled as exc:
        return {'status': 'disabled', 'message': str(exc)}
    except ProviderRefusal as exc:
        return {'status': 'refusal', 'message': str(exc)}
    except ProviderError as exc:
        return {'status': 'error', 'message': str(exc)}
    result['subject'] = subject_id
    return result
