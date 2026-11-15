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

    Periodic security reports (every 6 h / daily) and the notification center, delivered by e-mail through the
    SMTP settings of Monit (by reference, or imported into the plugin). History and queue in
    /var/db/policyanalyzer/reports.db. See CONTRACT.md ("Reports and notifications").

    Modules: common, settings, monit, collect, aisum, render, pdf (pure Python PDF writer), ttf (TrueType subset
    for the alphabets outside WinAnsi), pdfreport (the report as a PDF attachment), mailer, store, deliver, notify,
    actions, cli, model.php (cron jobs through the core model). Texts: the catalogs of ../i18n (one JSON per
    language).
"""

try:                                        # register the change actions when the plugin dispatcher exists
    from ai import changes as _changes      # noqa: F401
    from . import actions as _actions       # noqa: F401
except ImportError:                         # pragma: no cover
    pass
