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

    Audit trail of everything sent to an AI provider, one JSON object per line.

    Every record holds the SHA-256 and size of the prompt and answer, the
    provider, endpoint, model and duration.  The prompt itself is only kept
    when it was anonymized (it then is exactly what left the firewall);
    without anonymization only the hash is written, never raw data.
"""

import hashlib
import json
import os
import time

DEFAULT_LOG = '/var/log/policyanalyzer/ai.log'


def sha256(text):
    return hashlib.sha256((text or '').encode('utf-8', errors='replace')).hexdigest()


class AuditLog:
    def __init__(self, path=DEFAULT_LOG, max_bytes=1024 * 1024, backups=3):
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups

    def _rotate(self):
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        for idx in range(self.backups - 1, 0, -1):
            src = '%s.%d' % (self.path, idx)
            if os.path.exists(src):
                os.replace(src, '%s.%d' % (self.path, idx + 1))
        os.replace(self.path, self.path + '.1')

    def record(self, **event):
        """ append an event, failures to log never break the caller """
        entry = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
        entry.update({k: v for k, v in event.items() if v is not None})
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o750, exist_ok=True)
            self._rotate()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            with os.fdopen(fd, 'a') as handle:
                handle.write(json.dumps(entry, sort_keys=True) + '\n')
        except OSError:
            return False
        return True


class NullAuditLog(AuditLog):
    def __init__(self):
        super().__init__(path='')
        self.records = []

    def record(self, **event):
        self.records.append(event)
        return True
