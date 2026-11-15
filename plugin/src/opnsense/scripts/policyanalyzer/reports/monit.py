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

    E-mail settings of the Monit service of the core (//OPNsense/monit), read only.

    Monit (Services > Monit > Settings) renders "set mailserver <host[,host]> port <p> username <u> password <p>
    using ssl with options { version: <v> verify: enable|disable }". Monit itself uses implicit TLS on port 465
    and STARTTLS otherwise when "ssl" is on; the plugin does the same. The sender is the "from:" line of the
    mail format of the first enabled alert (fallback monit@<hostname>), the recipients are the enabled alerts.

    public() never returns the password: only whether one is set. password() is called by the mailer at send
    time only (mode "monit": by reference, nothing is copied) or by the import action (mode "own").
"""

import re

from . import common

FROM_RE = re.compile(r'^\s*from:\s*(\S+@\S+)\s*$', re.I | re.M)
EMAIL_RE = re.compile(r'^[^@\s<>"]{1,64}@[A-Za-z0-9.-]{1,253}$')


def _node(root):
    return None if root is None else root.find('./OPNsense/monit')


def read(root=None):
    """ :return: dict (no password) or None when Monit has no mail server """
    root = root if root is not None else common.config_root()
    monit = _node(root)
    if monit is None:
        return None
    general = monit.find('general')
    if general is None:
        return None
    hosts = [h.strip() for h in (general.findtext('mailserver') or '').split(',') if h.strip()]
    if not hosts:
        return None
    try:
        port = int((general.findtext('port') or '25').strip())
    except ValueError:
        port = 25
    ssl_on = (general.findtext('ssl') or '0').strip() == '1'
    security = ('ssl' if port == 465 else 'starttls') if ssl_on else 'none'
    sslversion = (general.findtext('sslversion') or 'auto').strip().lower()
    recipients, sender = [], None
    for alert in monit.findall('alert'):
        if (alert.findtext('enabled') or '0').strip() != '1':
            continue
        rcpt = (alert.findtext('recipient') or '').strip()
        if EMAIL_RE.match(rcpt) and rcpt not in recipients:
            recipients.append(rcpt)
        if sender is None:
            match = FROM_RE.search(alert.findtext('format') or '')
            if match and EMAIL_RE.match(match.group(1)):
                sender = match.group(1)
    hostname = (root.findtext('./system/hostname') or 'firewall').strip()
    domain = (root.findtext('./system/domain') or 'localdomain').strip()
    username = (general.findtext('username') or '').strip()
    return {'host': hosts[0], 'hosts': hosts, 'port': port, 'security': security,
            'verify': (general.findtext('sslverify') or '1').strip() == '1',
            'min_tls': sslversion if sslversion in ('tlsv12', 'tlsv13') else 'auto',
            'username': username, 'password_set': bool((general.findtext('password') or '').strip()),
            'sender': sender or ('monit@%s.%s' % (hostname, domain)),
            'sender_source': 'alert mail format' if sender else 'default (monit@hostname)',
            'recipients': recipients, 'enabled': (general.findtext('enabled') or '0').strip() == '1'}


def password(root=None):
    """ the Monit SMTP password, for the mailer only; never logged, journaled or returned by the API """
    root = root if root is not None else common.config_root()
    monit = _node(root)
    if monit is None:
        return ''
    return (monit.findtext('general/password') or '').strip()


def public(root=None):
    data = read(root)
    if data is None:
        return {'available': False, 'message': 'Monit has no mail server configured (Services > Monit > Settings)'}
    return dict(data, available=True)
