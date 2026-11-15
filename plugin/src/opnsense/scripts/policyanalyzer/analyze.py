#!/usr/local/bin/python3

"""
    Copyright (c) 2026 Igor Toledo
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

    --------------------------------------------------------------------------------------
    Policy Analyzer: read-only, deterministic analysis of the firewall policy.

    Reads /conf/config.xml and the pf rule counters, prints the findings as JSON (contract version 1) and
    stores the same document in /var/db/policyanalyzer/last.json. Never changes rules or configuration.
"""

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.report import build_report  # noqa: E402
from engine.stats import load_stats  # noqa: E402

DEFAULT_CONFIG = '/conf/config.xml'
OUTPUT_DIR = '/var/db/policyanalyzer'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'last.json')


def write_result(document, path=OUTPUT_FILE):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    os.chmod(directory, 0o750)
    fd, tmp = tempfile.mkstemp(prefix='.last.', dir=directory)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(document)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description='OPNsense firewall policy analyzer (read-only)')
    parser.add_argument('--config', default=DEFAULT_CONFIG, help='config.xml to analyze')
    parser.add_argument('--stats', default=None, help='JSON file with pf rule counters (rule_stats.py format)')
    parser.add_argument('--no-stats', action='store_true', help='do not read pf rule counters')
    parser.add_argument('--no-write', action='store_true', help='only print, do not store last.json')
    parser.add_argument('--output', default=OUTPUT_FILE, help=argparse.SUPPRESS)
    parser.add_argument('--pretty', action='store_true', help='indent the JSON output')
    args = parser.parse_args(argv)

    if args.no_stats:
        stats, meta = None, {'source': None}
    else:
        stats, meta = load_stats(args.stats)
    try:
        result = build_report(args.config, stats, meta)
    except (OSError, SyntaxError) as exc:
        # xml.etree.ElementTree.ParseError is a SyntaxError subclass
        print(json.dumps({'version': 1, 'error': 'unable to read configuration: %s' % exc.__class__.__name__}))
        return 1
    document = json.dumps(result, indent=2 if args.pretty else None, sort_keys=False)
    if not args.no_write:
        write_result(document, args.output)
    print(document)
    return 0


if __name__ == '__main__':
    sys.exit(main())
