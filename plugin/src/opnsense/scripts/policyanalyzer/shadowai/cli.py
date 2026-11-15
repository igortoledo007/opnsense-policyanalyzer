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

    AI usage on the network ("shadow AI") — configd: actions_pa_shadowai.conf. Read only.

        cli.py run [days]                   build the report (DNS + TLS SNI, default 7 days), store
                                            shadowai.json and the history, print it
        cli.py last [days]                  stored report (rebuilt when missing, older than 15 min or for
                                            another window)
        cli.py summary                      light document for widgets
        cli.py propose <payload>            blocking proposal + replay; payload = base64 JSON
                                            {"services": [ids], "scope": "all|host|net", "value": "ip/cidr",
                                             "method": "unbound|alias"}
        cli.py explain <payload> [language] [send|preview]
                                            AI text; payload {"target": "overview"} or {"target": "host", "ip"}
        cli.py catalog                      the merged service catalogue

    Output is always one JSON document.
"""

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posture.common import Paths, ai_explain, decode_payload, emit, load_json, now, valid_language, write_json  # noqa
from shadowai import report as report_mod  # noqa: E402
from shadowai.catalog import Catalog  # noqa: E402

MAX_AGE = 900

OVERVIEW = """You explain the use of AI services on a home or small office network, measured by the firewall
from DNS queries and TLS server names (SNI). Counts are queries/connections, not data volume, and say nothing
about what was typed.
- Summarise which services are used, by how many hosts, and what is new.
- Separate expected usage (known: true, e.g. the firewall's own AI bridge) from unexpected usage.
- Point out services with risk "elevated" (data residency, companion apps) and hosts with many services.
- Suggest proportionate next steps (talk to the user, an acceptable use policy, or a DNS block proposal for a
  host); never recommend blocking expected usage.
- 150 to 250 words. Markdown allowed: short paragraphs, bullets, **bold**; no tables."""

HOST = """You explain the AI service usage of ONE host of the network, measured by the firewall from DNS queries
and TLS server names (SNI) with JA4 client fingerprints. Counts are queries/connections, not content.
- Say which services the host uses, since when, and how intensively compared with the window.
- If several JA4 fingerprints appear, say it suggests several applications (browser, desktop app, CLI).
- Mark expected usage (known: true) as such and do not treat it as a problem.
- Suggest what to verify with the owner of the host. 100 to 180 words. Markdown allowed; no tables."""


def ai_overview(report):
    return {
        'window_days': report['window_days'], 'totals': report['totals'],
        'services': [{k: s[k] for k in ('name', 'category', 'risk', 'hosts', 'unexpected_hosts', 'total', 'new_hosts')}
                     for s in report['services']],
        'hosts': [{'host': h.get('name') or h['ip'], 'firewall': h['firewall'], 'total': h['total'],
                   'services': [{'service': s['name'], 'total': s['total'], 'known': s['known'], 'new': s['new']}
                                for s in h['services']]} for h in report['hosts'][:25]],
        'new': [{'host': n.get('name') or n['host'], 'service': n['service_name']} for n in report['new_items']],
    }


def ai_host(report, ip):
    host = next((h for h in report['hosts'] if h['ip'] == ip), None)
    if host is None:
        return None
    return {
        'window_days': report['window_days'],
        'host': {'address': host['ip'], 'name': host.get('name'), 'vendor': host.get('vendor'),
                 'firewall': host['firewall']},
        'services': [{k: s[k] for k in ('name', 'category', 'risk', 'dns', 'tls', 'first', 'last', 'new', 'known',
                                        'known_reason')} | {'ja4_fingerprints': len(s['ja4'])}
                     for s in host['services']],
    }


def load(paths, days=7, force=False):
    stored = load_json(paths.db('shadowai.json'))
    if not force and isinstance(stored, dict) and stored.get('kind') == 'shadowai' and \
            stored.get('window_days') == days:
        age = now() - _epoch(stored.get('generated'))
        if age < MAX_AGE:
            stored['age_seconds'] = int(age)
            return stored
    report = report_mod.build(paths, days=days, write=True)
    write_json(paths.db('shadowai.json'), report)
    report['age_seconds'] = 0
    return report


def _epoch(text):
    import calendar
    import time
    try:
        return calendar.timegm(time.strptime(text, '%Y-%m-%dT%H:%M:%SZ'))
    except (TypeError, ValueError):
        return 0


def _days(args, idx=0):
    if len(args) > idx and args[idx].isdigit() and 1 <= int(args[idx]) <= 30:
        return int(args[idx])
    return 7


def main(argv, paths=None, assistant=None):
    paths = paths or Paths()
    cmd = argv[0] if argv else 'last'
    args = argv[1:]
    if cmd == 'run':
        return load(paths, _days(args), force=True)
    if cmd == 'last':
        return load(paths, _days(args))
    if cmd == 'summary':
        # light: the stored report whatever its age (built only when there is none yet)
        stored = load_json(paths.db('shadowai.json'))
        if isinstance(stored, dict) and stored.get('kind') == 'shadowai':
            stored['age_seconds'] = int(now() - _epoch(stored.get('generated')))
            return report_mod.summary(stored)
        return report_mod.summary(load(paths, 7))
    if cmd == 'catalog':
        return dict(Catalog(local=paths.local_catalog).public(), status='ok')
    if cmd in ('propose', 'explain'):
        try:
            payload = decode_payload(args[0] if args else '')
        except ValueError as exc:
            return {'status': 'error', 'message': str(exc)}
        days = payload.get('days') if isinstance(payload.get('days'), int) and 1 <= payload['days'] <= 30 else 7
        report = load(paths, days)
        if cmd == 'propose':
            services = [str(s) for s in payload.get('services') or [] if isinstance(s, str)][:40]
            return report_mod.propose(report, Catalog(local=paths.local_catalog), services,
                                      str(payload.get('scope') or 'all'), payload.get('value'),
                                      str(payload.get('method') or 'unbound'))
        language = valid_language(args[1]) if len(args) > 1 else None
        mode = args[2] if len(args) > 2 and args[2] in ('send', 'preview') else 'send'
        target = payload.get('target') or 'overview'
        if target == 'host':
            try:
                ip = str(ipaddress.ip_address(str(payload.get('ip'))))
            except ValueError:
                return {'status': 'error', 'message': 'invalid address'}
            data = ai_host(report, ip)
            if data is None:
                return {'status': 'error', 'message': 'host not in the report'}
            result = ai_explain(paths, 'shadowai-ai.json', 'shadowai_host', HOST,
                                'Explain the AI usage of this host.', data, language, mode,
                                subject='shadowai:host', assistant=assistant)
        else:
            result = ai_explain(paths, 'shadowai-ai.json', 'shadowai_overview', OVERVIEW,
                                'Explain the AI usage on this network.', ai_overview(report), language, mode,
                                subject='shadowai:overview', assistant=assistant)
        result['target'] = target
        result['report_generated'] = report.get('generated')
        return result
    return {'status': 'error', 'message': 'unknown command'}


if __name__ == '__main__':
    try:
        emit(main(sys.argv[1:]))
    except Exception as exc:  # noqa: BLE001 - configd expects JSON
        emit({'status': 'error', 'message': '%s: %s' % (exc.__class__.__name__, exc)})
