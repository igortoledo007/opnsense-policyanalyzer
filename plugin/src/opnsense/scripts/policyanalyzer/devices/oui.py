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

    Manufacturer of a MAC address (IEEE OUI, MA-L 24 bit prefixes), from local files only:
      1. <db>/oui.csv     downloaded by the change action devices_oui_update (explicit, with simulation)
      2. /usr/local/opnsense/contrib/ieee/oui.csv   shipped and updated by the OPNsense core (firmware)
      3. the "oui" table of the Host discovery database (hostwatch), already joined by sources.hostwatch
    Same CSV layout for 1 and 2: Registry,Assignment,Organization Name,Organization Address.
"""

import csv
import io
import os

from . import common

IEEE_URL = 'https://standards-oui.ieee.org/oui/oui.csv'
MAX_BYTES = 16 * 1024 * 1024


def parse(handle):
    db = {}
    for idx, row in enumerate(csv.reader(handle)):
        if idx == 0 or len(row) < 3:
            continue
        key = row[1].strip().upper()
        if len(key) == 6:
            db[key] = row[2].strip()
    return db


class OUI(object):
    def __init__(self, files=None):
        p = common.paths()
        self.db = {}
        self.source = None
        self.mtime = None
        for path in files or (p['local_oui'], p['core_oui']):
            try:
                with open(path, newline='', encoding='utf-8', errors='replace') as handle:
                    db = parse(handle)
            except OSError:
                continue
            if db:
                self.db, self.source, self.mtime = db, path, os.stat(path).st_mtime
                break

    def vendor(self, mac):
        if not mac:
            return None
        return self.db.get(mac.replace(':', '')[:6].upper())

    def status(self):
        return {'source': self.source, 'entries': len(self.db),
                'updated': common.iso(self.mtime) if self.mtime else None, 'download_url': IEEE_URL}


def fetch(get=None):
    """ download the IEEE registry (raw CSV); same transport rules as the exposure feeds """
    if get is None:
        import ssl
        import urllib.request
        from exposure import feeds
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=feeds.ssl_context()),
                                             feeds._NoRedirect())
        request = urllib.request.Request(IEEE_URL, headers={'User-Agent': 'os-policyanalyzer-devices/1'})
        try:
            with opener.open(request, timeout=60) as response:
                body = response.read(MAX_BYTES + 1)
        except (OSError, ssl.SSLError) as exc:
            raise ValueError('download failed: %s' % str(getattr(exc, 'reason', exc))[:200])
    else:
        body = get(IEEE_URL)
    if len(body) > MAX_BYTES:
        raise ValueError('the registry is larger than expected')
    count = len(parse(io.StringIO(body.decode('utf-8', 'replace'))))
    if count < 10000:
        raise ValueError('the file does not look like the IEEE OUI registry (%d entries)' % count)
    return body, count
