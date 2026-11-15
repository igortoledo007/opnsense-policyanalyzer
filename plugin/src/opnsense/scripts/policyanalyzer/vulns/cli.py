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

    configd entry point of the vulnerabilities (actions_pa_vulns.conf). One JSON document on stdout.

      cli.py summary                                 light counts for the Max Cyber / reports
      cli.py list [P1+P2+...|all]                    prioritised CVEs (with factors), review queue, intel state
      cli.py cve <CVE id>                            one item
      cli.py intel                                   KEV / EPSS cache state (dates, coverage)
      cli.py explain <CVE id> <language> <cached|refresh|preview>
      cli.py suggest <item id> <language> <refresh|preview>
      cli.py plan|apply <vulns_intel_update|vulns_review_decide|revert> [args...]
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ''):
    sys.path = [p for p in sys.path if os.path.abspath(p or '.') != _HERE]
    sys.path.insert(0, os.path.dirname(_HERE))

from vulns import common, explain, intel, prioritize  # noqa: E402

USAGE = 'usage: cli.py summary|list|cve|intel|explain|suggest|plan|apply ...'
OWN_ACTIONS = ('vulns_intel_update', 'vulns_review_decide', 'revert')


def change(mode, args):
    from ai import changes
    from vulns import actions  # noqa: F401  (registers the actions even when ai/changes.py does not list us)
    if not args or args[0] not in OWN_ACTIONS:
        raise ValueError('unknown action')
    return changes.run(mode, args[0], args[1:])


def run(argv):
    args = [a for a in argv if a != '']
    if not args:
        raise ValueError(USAGE)
    cmd, rest = args[0], args[1:]
    if cmd == 'summary':
        return prioritize.summary()
    if cmd == 'list':
        result = prioritize.build()
        wanted = (rest[0] if rest else 'all').split('+')
        if 'all' not in wanted:
            result['items'] = [i for i in result['items'] if i['priority'] in wanted]
        return result
    if cmd == 'cve':
        cve = common.valid_cve(rest[0] if rest else '')
        result = prioritize.build()
        item = next((i for i in result['items'] if i['cve'] == cve), None)
        return {'status': 'ok', 'item': item} if item else {'status': 'error', 'message': 'not in the inventory'}
    if cmd == 'intel':
        doc = prioritize.load_exposure() or {}
        cves = sorted({c['id'] for p in (doc.get('vulns') or {}).get('packages') or [] for c in p.get('cves') or []})
        return dict(intel.status(cves), status='ok')
    if cmd == 'explain':
        rest = rest + ['', '', '']
        mode = rest[2] if rest[2] in ('cached', 'refresh', 'preview') else 'cached'
        return explain.explain_cve(rest[0], rest[1], mode)
    if cmd == 'suggest':
        rest = rest + ['', '', '']
        mode = 'preview' if rest[2] == 'preview' else 'refresh'
        return explain.suggest(rest[0], rest[1], mode)
    if cmd in ('plan', 'apply'):
        return change(cmd, rest)
    raise ValueError(USAGE)


def main(argv=None):
    try:
        result = run(sys.argv[1:] if argv is None else argv)
    except ValueError as exc:
        result = {'status': 'error', 'message': str(exc)}
    except OSError as exc:
        result = {'status': 'error', 'message': 'unable to read the state: %s' % exc}
    sys.stdout.write(json.dumps(result) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
