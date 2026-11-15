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

    Local collectors (port of the remote opn.py routines; everything runs on the firewall, no API, no token):
    config (config.xml history), health (hourly metrics), flows (blocks and DNS every 5 minutes), the read
    interface query.py, the one-time importer of the old history and the change actions collect_schedule /
    collect_settings.  See CONTRACT.md ("Local collectors").

    Modules: common, sanitize, store, config, health, flows, query, importer, actions, cli, model.php.
"""

_REGISTERED = None

try:                                        # register the change actions when the plugin dispatcher exists
    from ai import changes as _changes      # noqa: F401
    from . import actions as _actions
    if not getattr(_changes, '_collect_registered', False):
        _REGISTERED = _actions.register(_changes)
        _changes._collect_registered = True
except ImportError:                         # pragma: no cover - standalone
    pass
