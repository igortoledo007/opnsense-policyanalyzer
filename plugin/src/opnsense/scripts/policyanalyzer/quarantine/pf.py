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

    The pf table behind the External (advanced) alias pa_quarantine.

    filter.inc declares an external alias as "table <pa_quarantine> persist" without addresses, so a
    "filter reload" keeps its content (pf only replaces a table's addresses when the ruleset lists some);
    update_tables.py never touches it (no parser for the "external" type).  The content is lost on reboot,
    so it is rebuilt from the ledger by the boot hook (rc.syshook.d/start) and checked again every run:
    table = entries with an active quarantine in SQLite (sync()).  Negated entries ("!addr") keep protected
    addresses out of a quarantined network.
"""

from . import common

CHUNK = 200


class Table:
    def __init__(self, ctx, name=common.ALIAS):
        self.ctx = ctx
        self.name = name

    def _pfctl(self, args, timeout=30):
        return self.ctx.runner.run([self.ctx.pfctl] + list(args), timeout=timeout)

    def exists(self):
        rc, out, _err = self._pfctl(['-s', 'Tables'])
        return rc == 0 and self.name in [line.strip() for line in out.splitlines()]

    def show(self):
        rc, out, err = self._pfctl(['-t', self.name, '-T', 'show'])
        if rc != 0:
            raise common.QuarantineError('pfctl show %s: %s' % (self.name, err.strip() or rc))
        return {line.strip() for line in out.splitlines() if line.strip()}

    def _chunked(self, op, entries):
        done = 0
        entries = sorted(entries)
        for i in range(0, len(entries), CHUNK):
            part = entries[i:i + CHUNK]
            rc, _out, err = self._pfctl(['-t', self.name, '-T', op] + part)
            if rc != 0:
                raise common.QuarantineError('pfctl %s %s: %s' % (op, self.name, err.strip() or rc))
            done += len(part)
        return done

    def add(self, entries):
        return self._chunked('add', entries)

    def delete(self, entries):
        return self._chunked('delete', entries)

    def flush(self):
        rc, _out, err = self._pfctl(['-t', self.name, '-T', 'flush'])
        if rc != 0:
            raise common.QuarantineError('pfctl flush %s: %s' % (self.name, err.strip() or rc))

    def kill(self):
        self._pfctl(['-t', self.name, '-T', 'kill'])

    def kill_states(self, address):
        """ drop the states created from the address (inbound connections it opened) """
        self._pfctl(['-k', address], timeout=10)

    def sync(self, desired):
        """ make the table equal to `desired` (set of pf spellings); :return: {"added", "deleted", "size"} """
        if not self.exists():
            return {'status': 'missing', 'added': 0, 'deleted': 0, 'size': 0}
        current = self.show()
        to_add = desired - current
        to_del = current - desired
        deleted = self.delete(to_del) if to_del else 0
        added = self.add(to_add) if to_add else 0
        return {'status': 'ok', 'added': added, 'deleted': deleted, 'size': len(desired),
                'new': sorted(to_add)}
