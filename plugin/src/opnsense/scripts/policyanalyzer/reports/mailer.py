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

    SMTP delivery (smtplib, stdlib only): multipart/alternative (text + HTML), or multipart/mixed with that
    alternative part first and the attachments after it (the report PDF, base64), implicit TLS ("ssl", port 465) or
    STARTTLS (required: no fallback to plain text when the server does not offer it), certificates verified with
    the system store unless the channel says otherwise (Monit "sslverify"). The password is used for the login
    only: it never goes to an error message, a log or the database.
"""

import email.utils
import os
import smtplib
import socket
import ssl
from email.message import EmailMessage

CA_FILES = ('/usr/local/etc/ssl/cert.pem', '/etc/ssl/cert.pem')
TIMEOUT = 30


def build(subject, sender, recipients, text, html_body, hostname=None, attachments=None):
    """ :param attachments: [(filename, bytes, 'type/subtype')] -> multipart/mixed (alternative + attachments) """
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Message-ID'] = email.utils.make_msgid('policyanalyzer', domain=hostname or None)
    msg['X-Mailer'] = 'OPNsense Policy Analyzer'
    msg['Auto-Submitted'] = 'auto-generated'
    msg.set_content(text)
    msg.add_alternative(html_body, subtype='html')
    for name, data, mime in attachments or []:
        maintype, _sep, subtype = (mime or 'application/octet-stream').partition('/')
        msg.add_attachment(data, maintype=maintype, subtype=subtype or 'octet-stream', filename=name)
    return msg


def context(verify=True, min_tls='auto'):
    ctx = ssl.create_default_context()
    if not ctx.get_ca_certs():
        for cafile in CA_FILES:
            if os.path.isfile(cafile):
                try:
                    ctx.load_verify_locations(cafile=cafile)
                    break
                except (OSError, ssl.SSLError):
                    continue
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if min_tls == 'tlsv13':
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    elif min_tls == 'tlsv12':
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class MailError(Exception):
    pass


def _clean(text, secret):
    text = str(text)
    if secret:
        text = text.replace(secret, '****')
    return text[:300]


def send(msg, channel, smtp_factory=None, ssl_factory=None):
    """
    :param channel: {host, port, security, verify, min_tls, username, password, sender, recipients}
    :param smtp_factory: (cls_name, host, port, timeout, context) -> SMTP-like object (tests)
    """
    secret = channel.get('password') or ''
    host, port, security = channel['host'], int(channel['port']), channel.get('security', 'starttls')
    ctx = (ssl_factory or context)(channel.get('verify', True), channel.get('min_tls', 'auto')) \
        if security != 'none' else None
    try:
        if smtp_factory is not None:
            server = smtp_factory('SMTP_SSL' if security == 'ssl' else 'SMTP', host, port, TIMEOUT, ctx)
        elif security == 'ssl':
            server = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=ctx)
        else:
            server = smtplib.SMTP(host, port, timeout=TIMEOUT)
        try:
            server.ehlo()
            if security == 'starttls':
                if not server.has_extn('starttls'):
                    raise MailError('the server does not offer STARTTLS (refusing to send in plain text)')
                server.starttls(context=ctx)
                server.ehlo()
            if channel.get('username'):
                server.login(channel['username'], secret)
            refused = server.send_message(msg, from_addr=channel['sender'], to_addrs=channel['recipients'])
        finally:
            try:
                server.quit()
            except (smtplib.SMTPException, OSError):
                pass
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError('authentication failed (%s)' % _clean(exc.smtp_code, secret))
    except (smtplib.SMTPException, ssl.SSLError, socket.error, OSError) as exc:
        raise MailError(_clean('%s: %s' % (exc.__class__.__name__, exc), secret))
    if refused:
        raise MailError('refused recipients: %s' % ', '.join(sorted(refused)))
    return {'status': 'sent', 'recipients': channel['recipients'], 'message_id': msg['Message-ID']}
