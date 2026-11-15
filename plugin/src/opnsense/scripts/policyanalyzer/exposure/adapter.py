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

    Probes for manage.py ("status" sub commands) and a small CLI.

    manage.py merges STATUS_PROBES the same way as setup.adapter.STATUS_PROBES:

        try:
            from exposure import adapter as _exposure_adapter
            STATUS.update(_exposure_adapter.STATUS_PROBES)
        except (ImportError, AttributeError):
            pass

    Probes (each takes the list of configd tokens and returns one JSON document):
        inventory                       packages, versions, listening services, interfaces
        exposure                        listening services + internet reachability (rule engine)
        vulns [online] [refresh]        pkg audit + optional feed enrichment
        exposure_report [online] [refresh] [no-write]
                                        everything + findings + summary; stores /var/db/policyanalyzer/exposure.json
    Tokens: "online" or "online=1" (use the network for the feeds), "refresh" (with online: pkg audit -F),
    "no-write" (do not store exposure.json, and do not write the feed cache).

    CLI (tests, lab):  python3 -m exposure.adapter <probe> [tokens] [--config PATH] [--sudo-read] [--pretty]
"""

import json
import os
import sys
import time

if __package__ in (None, ''):                    # pragma: no cover - executed as a script
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = 'exposure'

from . import common, feeds, inventory, reach, report, vulns  # noqa: E402

RUNNER_FACTORY = common.Runner                   # replaced by the tests
FETCHER_FACTORY = feeds.Fetcher


def _flags(args):
    tokens = set()
    options = {}
    for arg in args or []:
        arg = (arg or '').strip().lstrip('-')
        if not arg:
            continue
        if '=' in arg:
            key, value = arg.split('=', 1)
            if value in ('1', 'yes', 'true', 'on'):
                tokens.add(key)
            elif value not in ('0', 'no', 'false', 'off'):
                options[key] = value
        else:
            tokens.add(arg)
    return tokens, options


class Run(object):
    """ one probe execution: runner, configuration, engine view """

    def __init__(self, args, config_path=None, runner=None):
        self.tokens, self.options = _flags(args)
        self.online = 'online' in self.tokens
        self.refresh = 'refresh' in self.tokens
        self.write = 'no-write' not in self.tokens and 'nowrite' not in self.tokens
        self.config_path = config_path or common.CONFIG_XML
        self.run = runner or RUNNER_FACTORY(sudo_read='sudo-read' in self.tokens or
                                            os.environ.get('POLICYANALYZER_SUDO_READ') == '1')
        self._rules = None

    @property
    def rules(self):
        if self._rules is None:
            self._rules = reach.RuleSet(self.config_path)
        return self._rules

    def fetcher(self):
        return FETCHER_FACTORY(online=self.online, write_cache=self.write)


def _inventory(r, with_packages=True):
    return inventory.collect(r.run, r.rules.cfg, with_packages=with_packages)


def _exposure(r, inv=None):
    inv = inv or _inventory(r, with_packages=False)
    for svc in inv['services']:
        reach.assess(r.rules, svc, inv['interfaces'])
    return inv


def probe_inventory(args, runner=None, config_path=None):
    r = Run(args, config_path, runner)
    return dict(_inventory(r), status='ok')


def probe_exposure(args, runner=None, config_path=None):
    r = Run(args, config_path, runner)
    inv = _exposure(r)
    return {'status': 'ok', 'wan': r.rules.wan, 'services': inv['services'],
            'services_complete': inv['services_complete'], 'limitations': inv['limitations'],
            'summary': {'services': len(inv['services']),
                        'reachable': sum(1 for s in inv['services'] if s['internet_reachable'] == 'yes'),
                        'maybe_reachable': sum(1 for s in inv['services'] if s['internet_reachable'] == 'maybe')}}


def probe_vulns(args, runner=None, config_path=None, fetcher=None):
    r = Run(args, config_path, runner)
    version = inventory.opnsense_version(r.run).get('version')
    result = vulns.collect(r.run, online=r.online, refresh=r.refresh, fetcher=fetcher or r.fetcher(),
                           opnsense_version=version, config_path=r.config_path)
    return dict(result, status='ok')


def probe_exposure_report(args, runner=None, config_path=None, fetcher=None, output=None):
    started = time.monotonic()
    r = Run(args, config_path, runner)
    inv = _exposure(r, _inventory(r))
    version = (inv.get('opnsense') or {}).get('version')
    vul = vulns.collect(r.run, online=r.online, refresh=r.refresh, fetcher=fetcher or r.fetcher(),
                        opnsense_version=version, config_path=r.config_path)
    outdated, reason = vulns.outdated(r.run)
    all_cves = [c['id'] for p in vul['packages'] for c in p['cves']]
    sids = vulns.suricata_rules(all_cves)
    doc = report.build(inv, vul, outdated, reason, sids, wan=r.rules.wan, started=started)
    doc['status'] = 'ok'
    if r.write:
        report.write(doc, output)
        doc['stored'] = output or report.OUTPUT_FILE
    return doc


def _safe(func):
    """ manage.py only catches ValueError/OSError: an unreadable config.xml must still give one JSON document """
    def wrapper(args, **kw):
        try:
            return func(args, **kw)
        except SyntaxError as exc:              # xml.etree.ElementTree.ParseError
            return {'status': 'error', 'message': 'unable to read configuration: %s' % exc.__class__.__name__}
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


STATUS_PROBES = {
    'inventory': _safe(probe_inventory),
    'exposure': _safe(probe_exposure),
    'vulns': _safe(probe_vulns),
    'exposure_report': _safe(probe_exposure_report),
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    pretty = '--pretty' in argv
    config_path = None
    if '--config' in argv:
        idx = argv.index('--config')
        config_path = argv[idx + 1] if idx + 1 < len(argv) else None
        del argv[idx:idx + 2]
    argv = [a for a in argv if a != '--pretty']
    if not argv or argv[0] not in STATUS_PROBES:
        print(json.dumps({'status': 'error', 'message': 'usage: adapter.py %s [tokens]' % '|'.join(STATUS_PROBES)}))
        return 1
    try:
        result = STATUS_PROBES[argv[0]](argv[1:], config_path=config_path)
    except (OSError, SyntaxError) as exc:          # ParseError is a SyntaxError
        result = {'status': 'error', 'message': 'unable to read configuration or state: %s' % exc.__class__.__name__}
    print(json.dumps(result, indent=2 if pretty else None))
    return 0 if result.get('status') == 'ok' else 1


if __name__ == '__main__':                       # pragma: no cover
    sys.exit(main())
