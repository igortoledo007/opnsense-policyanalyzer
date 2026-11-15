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

    Deterministic posture checks (benchmark style, inspired by the CIS Controls v8 safeguards and NIST SP
    800-41r1 / 800-53r5; there is no official CIS benchmark for OPNsense). Every check is a function of the
    Context (config.xml + read-only probes) and returns one result:

        pass   the setting matches the recommendation
        warn   partly, or acceptable with a documented trade-off
        fail   the setting contradicts the recommendation
        na     not applicable here (feature not installed / probe unavailable)

    A "fix" is a proposal only: a textual diff with the GUI path and the page link; "action" names an
    existing change action (simulate first, see ai/changes.py) when one is safe to offer. Nothing here
    changes the system.
"""

import re

from .common import now
from .sources import certificate_info, ssh_key_info

CHECKS = []

SEVERITIES = ('high', 'medium', 'low', 'info')
RESULTS = ('pass', 'warn', 'fail', 'na')
CATEGORIES = {
    'access': 'Management access',
    'accounts': 'Accounts and authentication',
    'system': 'Firmware and system hardening',
    'firewall': 'Firewall policy',
    'logging': 'Logging and monitoring',
    'dns_ntp': 'DNS and time',
    'ids': 'Intrusion detection / prevention',
    'backup': 'Backup and recovery',
    'crypto': 'Certificates and keys',
}


# ------------------------------------------------------------------------------------------ references

def cis(safeguard, title):
    return {'label': 'CIS Controls v8 %s' % safeguard, 'title': title,
            'url': 'https://www.cisecurity.org/controls/v8'}


def nist53(control):
    return {'label': 'NIST SP 800-53r5 %s' % control,
            'url': 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'}


NIST41 = {'label': 'NIST SP 800-41r1 (firewall policy)', 'url': 'https://csrc.nist.gov/pubs/sp/800/41/r1/final'}


def doc(path, label):
    return {'label': 'OPNsense docs: %s' % label, 'url': 'https://docs.opnsense.org/%s' % path}


DOC_ADMIN = doc('manual/settingsmenu.html#administration', 'Settings, Administration')
DOC_2FA = doc('manual/two_factor.html', 'Two-factor authentication')
DOC_USERS = doc('manual/users.html', 'User management')
DOC_FIRMWARE = doc('manual/updates.html', 'Updates')
DOC_RULES = doc('manual/firewall.html', 'Rules')
DOC_FW_SETTINGS = doc('manual/firewall_settings.html', 'Firewall settings')
DOC_INTERFACES = doc('manual/interfaces.html', 'Interfaces')
DOC_LOGGING = doc('manual/logging.html', 'Logging')
DOC_UNBOUND = doc('manual/unbound.html', 'Unbound DNS')
DOC_NTP = doc('manual/ntpd.html', 'Network Time')
DOC_IDS = doc('manual/ips.html', 'Intrusion Prevention System')
DOC_BACKUP = doc('manual/backups.html', 'Backups')
DOC_CERTS = doc('manual/certificates.html', 'Trust (certificates)')
DOC_TUNABLES = doc('troubleshooting/hardening.html', 'Security hardening')
DOC_MONIT = doc('manual/monit.html', 'Monit')
DOC_UPNP = doc('manual/upnp.html', 'UPnP')

PAGE_ADMIN = 'system_advanced_admin.php'
PAGE_USERS = 'system_usermanager.php'
PAGE_FW_ADV = 'system_advanced_firewall.php'
PAGE_RULES = 'ui/firewall/filter'
PAGE_FIRMWARE = 'ui/core/firmware#status'
PAGE_TUNABLES = 'ui/core/tunables'
PAGE_SYSLOG = 'ui/syslog/'
PAGE_UNBOUND = 'ui/unbound/general'
PAGE_UNBOUND_DOT = 'ui/unbound/dot'
PAGE_UNBOUND_ADV = 'ui/unbound/advanced'
PAGE_IDS = 'ui/ids'
PAGE_CRON = 'ui/cron'
PAGE_BACKUP = 'diag_backup.php'
PAGE_CERTS = 'ui/trust/cert'
PAGE_MONIT = 'ui/monit'

# path shown with every fix ("where to change it")
GUI_ADMIN = 'System › Settings › Administration'


class Check:
    def __init__(self, cid, category, title, severity, references, page, recommendation, func):
        self.id = cid
        self.category = category
        self.title = title
        self.severity = severity
        self.references = references
        self.page = page
        self.recommendation = recommendation
        self.func = func


def check(cid, category, title, severity, references, page, recommendation):
    def wrap(func):
        CHECKS.append(Check(cid, category, title, severity, references, page, recommendation, func))
        return func
    return wrap


def res(result, summary, evidence=None, fix=None, severity=None, recommendation=None):
    out = {'result': result, 'summary': summary, 'evidence': evidence or {}}
    if fix:
        out['fix'] = fix
    if severity:
        out['severity'] = severity
    if recommendation:
        out['recommendation'] = recommendation
    return out


def fix(path, before, after, page, action=None, note=None):
    """ proposal: textual diff of the GUI setting(s); action = existing safe change action to simulate """
    lines = ['# %s' % path]
    for item in (before if isinstance(before, list) else [before]):
        lines.append('- %s' % item)
    for item in (after if isinstance(after, list) else [after]):
        lines.append('+ %s' % item)
    out = {'path': path, 'diff': '\n'.join(lines), 'page': page}
    if action:
        out['action'] = action
    if note:
        out['note'] = note
    return out


def na(summary, evidence=None):
    return res('na', summary, evidence)


def _report_findings(ctx, ftype):
    report = ctx.report
    if not isinstance(report, dict):
        return None
    return [f for f in report.get('findings', []) if f.get('type') == ftype]


def _gui_port(ctx):
    port = ctx.text('system/webgui/port')
    if port.isdigit():
        return int(port)
    return 80 if ctx.text('system/webgui/protocol', 'https') == 'http' else 443


def _ssh_port(ctx):
    port = ctx.text('system/ssh/port')
    return int(port) if port.isdigit() else 22


def _ssh_enabled(ctx):
    return ctx.text('system/ssh/enabled') == 'enabled' or ctx.has('system/ssh/enabled') and \
        ctx.text('system/ssh/enabled') not in ('', '0', 'disabled')


def _wan_rules_to_self(ctx, port):
    """ Policy Analyzer wan_exposed findings that pass the given port to the firewall itself """
    findings = _report_findings(ctx, 'wan_exposed')
    if findings is None:
        return None
    hits = []
    for finding in findings:
        ev = finding.get('evidence') or {}
        if port in (ev.get('admin_ports') or []):
            hits.append({'id': finding.get('id'), 'severity': finding.get('severity'),
                         'rule': (finding.get('rules') or [{}])[0].get('summary')})
    return hits


def _wan_label(ctx):
    return ', '.join(ctx.interface_label(n) for n in ctx.wan_interfaces) or 'wan'


# ========================================================================================== management access

@check('PA-ACC-01', 'access', 'Web GUI not reachable from the WAN', 'high',
       [cis('4.6', 'Securely manage enterprise assets and software'), nist53('AC-17'), NIST41, DOC_ADMIN],
       PAGE_ADMIN, 'Bind the web GUI to internal interfaces only and never pass the GUI port to "This Firewall" '
                   'on a WAN; reach it from outside through a VPN.')
def gui_wan(ctx):
    listen = ctx.csv('system/webgui/interfaces')
    wans = ctx.wan_interfaces
    exposed_rules = _wan_rules_to_self(ctx, _gui_port(ctx))
    evidence = {'listen_interfaces': listen or ['all'], 'wan_interfaces': wans, 'gui_port': _gui_port(ctx),
                'wan_pass_rules': exposed_rules}
    bound_wan = [n for n in listen if n in wans]
    the_fix = fix(GUI_ADMIN + ' › Web GUI › Listen Interfaces', 'Listen Interfaces: %s' % (', '.join(listen) or 'All'),
                  'Listen Interfaces: LAN (and the VPN interface used for administration)', PAGE_ADMIN)
    if exposed_rules:
        return res('fail', '%d WAN rule(s) pass the GUI port to the firewall itself' % len(exposed_rules),
                   evidence, fix(PAGE_RULES, 'pass in on WAN to This Firewall port %d' % _gui_port(ctx),
                                 'remove the rule, or restrict its source to a VPN / admin alias', PAGE_RULES))
    if bound_wan:
        return res('fail', 'the GUI listens on WAN interface(s) %s' % ', '.join(bound_wan), evidence, the_fix)
    if not listen:
        return res('warn', 'the GUI listens on all interfaces (only the rule set keeps it off the WAN)', evidence,
                   the_fix, severity='medium')
    return res('pass', 'the GUI listens only on %s' % ', '.join(ctx.interface_label(n) for n in listen), evidence)


@check('PA-ACC-02', 'access', 'Web GUI served over HTTPS with HSTS', 'medium',
       [cis('3.10', 'Encrypt sensitive data in transit'), nist53('SC-8'), DOC_ADMIN],
       PAGE_ADMIN, 'Use HTTPS for the GUI and enable HTTP Strict Transport Security.')
def gui_https(ctx):
    proto = ctx.text('system/webgui/protocol', 'https') or 'https'
    hsts = ctx.flag('system/webgui/ssl-hsts') or ctx.has('system/webgui/ssl-hsts') and \
        ctx.text('system/webgui/ssl-hsts') not in ('', '0')
    evidence = {'protocol': proto, 'hsts': hsts, 'http_redirect': not ctx.has('system/webgui/disablehttpredirect')}
    if proto != 'https':
        return res('fail', 'the GUI is served over plain HTTP', evidence,
                   fix(GUI_ADMIN + ' › Web GUI', 'Protocol: HTTP', ['Protocol: HTTPS',
                       'HTTP Strict Transport Security: enabled'], PAGE_ADMIN), severity='high')
    if not hsts:
        return res('warn', 'HTTPS is used but HSTS is off', evidence,
                   fix(GUI_ADMIN + ' › Web GUI', 'HTTP Strict Transport Security: disabled',
                       'HTTP Strict Transport Security: enabled', PAGE_ADMIN))
    return res('pass', 'HTTPS with HSTS', evidence)


@check('PA-ACC-03', 'access', 'Web GUI certificate trusted and not expiring', 'medium',
       [cis('3.10', 'Encrypt sensitive data in transit'), nist53('SC-17'), DOC_CERTS],
       PAGE_CERTS, 'Use a certificate from a trusted CA (e.g. ACME) for the GUI and renew it before it expires.')
def gui_certificate(ctx):
    if ctx.text('system/webgui/protocol', 'https') != 'https':
        return na('the GUI does not use HTTPS (see PA-ACC-02)')
    refid = ctx.text('system/webgui/ssl-certref')
    cert = ctx.certificate(refid)
    if cert is None:
        return res('warn', 'the GUI certificate reference is not in the configuration', {'certref': refid})
    info = certificate_info(cert.findtext('crt') or '')
    descr = (cert.findtext('descr') or '').strip()
    if info is None:
        return na('the certificate could not be parsed', {'certificate': descr})
    days = int((info['not_after'] - now()) // 86400)
    evidence = {'certificate': descr, 'issuer': info['issuer'], 'expires_in_days': days,
                'self_signed': info['self_signed'], 'key': '%s %s' % (info['key_type'], info['key_bits'] or '')}
    renew = fix('System › Trust › Certificates', 'Web GUI certificate: %s' % descr,
                'Web GUI certificate: one issued by a trusted CA (Services › ACME Client), renewed automatically',
                PAGE_CERTS)
    if days < 0:
        return res('fail', 'the GUI certificate expired %d day(s) ago' % -days, evidence, renew, severity='high')
    if info['staging']:
        return res('fail', 'the GUI certificate comes from a staging (test) CA', evidence, renew)
    if days < 14:
        return res('fail', 'the GUI certificate expires in %d day(s)' % days, evidence, renew)
    if info['self_signed'] or days < 30:
        return res('warn', 'self-signed certificate' if info['self_signed'] else
                   'the GUI certificate expires in %d days' % days, evidence, renew, severity='low')
    return res('pass', 'trusted certificate, %d days left' % days, evidence)


@check('PA-ACC-04', 'access', 'GUI session timeout and request checks', 'low',
       [cis('4.3', 'Configure automatic session locking'), nist53('AC-12'), DOC_ADMIN],
       PAGE_ADMIN, 'Keep the GUI session timeout at 30 minutes or less and the DNS rebind / HTTP referer '
                   'checks enabled.')
def gui_session(ctx):
    timeout = ctx.text('system/webgui/session_timeout')
    minutes = int(timeout) if timeout.isdigit() else 240
    rebind_off = ctx.has('system/webgui/nodnsrebindcheck')
    referer_off = ctx.has('system/webgui/nohttpreferercheck')
    evidence = {'session_timeout_minutes': minutes, 'dns_rebind_check': not rebind_off,
                'http_referer_check': not referer_off}
    before, after = [], []
    if minutes > 30:
        before.append('Session Timeout: %d' % minutes)
        after.append('Session Timeout: 30')
    if rebind_off:
        before.append('Disable DNS Rebinding Checks: checked')
        after.append('Disable DNS Rebinding Checks: unchecked')
    if referer_off:
        before.append('Disable HTTP_REFERER enforcement check: checked')
        after.append('Disable HTTP_REFERER enforcement check: unchecked')
    if not before:
        return res('pass', 'session timeout %d min, rebind and referer checks on' % minutes, evidence)
    result = 'fail' if (rebind_off or referer_off) else 'warn'
    return res(result, '; '.join(before), evidence, fix(GUI_ADMIN + ' › Web GUI', before, after, PAGE_ADMIN))


@check('PA-ACC-05', 'access', 'SSH not reachable from the WAN', 'high',
       [cis('4.6', 'Securely manage enterprise assets and software'), nist53('AC-17'), DOC_ADMIN],
       PAGE_ADMIN, 'Disable SSH or bind it to internal interfaces; never pass port 22 to the firewall on a WAN.')
def ssh_wan(ctx):
    if not _ssh_enabled(ctx):
        return res('pass', 'SSH is disabled', {'enabled': False})
    listen = ctx.csv('system/ssh/interfaces')
    wans = ctx.wan_interfaces
    rules = _wan_rules_to_self(ctx, _ssh_port(ctx))
    evidence = {'enabled': True, 'listen_interfaces': listen or ['all'], 'port': _ssh_port(ctx),
                'wan_pass_rules': rules}
    the_fix = fix(GUI_ADMIN + ' › Secure Shell › Listen Interfaces', 'Listen Interfaces: %s' %
                  (', '.join(listen) or 'All'), 'Listen Interfaces: LAN', PAGE_ADMIN)
    if rules:
        return res('fail', '%d WAN rule(s) pass SSH to the firewall itself' % len(rules), evidence,
                   fix(PAGE_RULES, 'pass in on WAN to This Firewall port %d' % _ssh_port(ctx),
                       'remove the rule (use a VPN)', PAGE_RULES))
    if any(n in wans for n in listen):
        return res('fail', 'SSH listens on a WAN interface', evidence, the_fix)
    if not listen:
        return res('warn', 'SSH listens on all interfaces', evidence, the_fix, severity='medium')
    return res('pass', 'SSH only on %s' % ', '.join(ctx.interface_label(n) for n in listen), evidence)


@check('PA-ACC-06', 'access', 'SSH: no password logins', 'high',
       [cis('6.5', 'Require MFA for administrative access'), nist53('IA-2'), DOC_ADMIN],
       PAGE_ADMIN, 'Use key based SSH logins only: uncheck "Permit password login".')
def ssh_password(ctx):
    if not _ssh_enabled(ctx):
        return na('SSH is disabled')
    password = ctx.flag('system/ssh/passwordauth') or ctx.text('system/ssh/passwordauth') == 'enabled'
    root = ctx.flag('system/ssh/permitrootlogin') or ctx.text('system/ssh/permitrootlogin') == 'enabled'
    evidence = {'password_auth': password, 'permit_root_login': root}
    if password:
        return res('fail', 'password logins are allowed%s' % (' (root included)' if root else ''), evidence,
                   fix(GUI_ADMIN + ' › Secure Shell', 'Permit password login: checked',
                       'Permit password login: unchecked (add an authorized key to the users first)', PAGE_ADMIN))
    return res('pass', 'key based logins only', evidence)


@check('PA-ACC-07', 'access', 'SSH: root login', 'medium',
       [cis('5.4', 'Restrict administrator privileges to dedicated administrator accounts'), nist53('AC-6(2)'),
        DOC_ADMIN],
       PAGE_ADMIN, 'Log in with a named administrator account and sudo; uncheck "Permit root user login".')
def ssh_root(ctx):
    if not _ssh_enabled(ctx):
        return na('SSH is disabled')
    root = ctx.flag('system/ssh/permitrootlogin') or ctx.text('system/ssh/permitrootlogin') == 'enabled'
    if not root:
        return res('pass', 'root can not log in over SSH', {'permit_root_login': False})
    password = ctx.flag('system/ssh/passwordauth')
    return res('warn' if not password else 'fail', 'root may log in over SSH', {'permit_root_login': True,
               'password_auth': password},
               fix(GUI_ADMIN + ' › Secure Shell', 'Permit root user login: checked',
                   'Permit root user login: unchecked (log in as a named admin, then sudo)', PAGE_ADMIN))


WEAK_SSH = re.compile(r'(cbc|arcfour|3des|hmac-md5|hmac-sha1(?!-etm)|-sha1$|group1-|group14-sha1|'
                      r'diffie-hellman-group-exchange-sha1|ssh-dss)', re.I)


@check('PA-ACC-08', 'access', 'SSH: strong algorithms and host keys', 'medium',
       [cis('3.10', 'Encrypt sensitive data in transit'), nist53('SC-13'), DOC_ADMIN],
       PAGE_ADMIN, 'Keep the default (modern) key exchange, cipher and MAC lists; RSA host keys of 3072 bits or '
                   'more, no DSA.')
def ssh_crypto(ctx):
    if not _ssh_enabled(ctx):
        return na('SSH is disabled')
    configured = {k: ctx.csv('system/ssh/%s' % k) for k in ('kex', 'ciphers', 'macs', 'keysig')}
    weak = sorted({a for items in configured.values() for a in items if WEAK_SSH.search(a)})
    keys = ctx.ssh_host_keys
    weak_keys = [k for k in (keys or []) if k['type'] == 'ssh-dss' or (k['type'] == 'ssh-rsa' and
                                                                        (k['bits'] or 0) < 3072)]
    evidence = {'configured': {k: v for k, v in configured.items() if v} or 'defaults', 'weak_algorithms': weak,
                'host_keys': keys, 'weak_host_keys': weak_keys}
    if weak:
        return res('fail', 'weak algorithms allowed: %s' % ', '.join(weak), evidence,
                   fix(GUI_ADMIN + ' › Secure Shell', 'Key exchange / Ciphers / MACs: %s' % ', '.join(weak),
                       'Key exchange / Ciphers / MACs: empty (system defaults)', PAGE_ADMIN))
    if weak_keys:
        return res('warn', 'weak host key(s): %s' % ', '.join('%s %s' % (k['type'], k['bits']) for k in weak_keys),
                   evidence, fix('shell (console)', 'host key %s' % weak_keys[0]['file'],
                                 'remove the weak host key file and restart SSH so that it is regenerated',
                                 PAGE_ADMIN), severity='low')
    if keys is None:
        return res('pass', 'default algorithms (host keys not readable)', evidence)
    return res('pass', 'default algorithms, %d strong host key(s)' % len(keys), evidence)


@check('PA-ACC-09', 'access', 'Console menu protected', 'low',
       [cis('4.1', 'Establish and maintain a secure configuration process'), nist53('AC-3'), DOC_ADMIN],
       PAGE_ADMIN, 'Enable "Password protect the console menu".')
def console(ctx):
    protected = ctx.has('system/disableconsolemenu')
    if protected:
        return res('pass', 'the console menu asks for a login', {'protected': True})
    return res('warn', 'anyone at the console gets the menu (reset passwords, shell)', {'protected': False},
               fix(GUI_ADMIN + ' › Console', 'Console menu: unprotected', 'Password protect the console menu: checked',
                   PAGE_ADMIN))


# ========================================================================================== accounts

def _totp_servers(ctx):
    return [s.findtext('name') for s in ctx.nodes('system/authserver') if (s.findtext('type') or '') == 'totp']


@check('PA-USR-01', 'accounts', 'GUI login requires a second factor (TOTP)', 'high',
       [cis('6.5', 'Require MFA for administrative access'), nist53('IA-2(1)'), DOC_2FA],
       'system_authservers.php', 'Create a "Local + Timebased One Time Password" server and select it in '
                                 'Administration › Authentication.')
def gui_totp(ctx):
    modes = ctx.csv('system/webgui/authmode')
    totp = _totp_servers(ctx)
    evidence = {'authentication_servers': modes or ['Local Database'], 'totp_servers': totp}
    if any(m in totp for m in modes):
        return res('pass', 'GUI authentication uses %s' % ', '.join(m for m in modes if m in totp), evidence)
    return res('fail', 'the GUI accepts a password alone', evidence,
               fix(GUI_ADMIN + ' › Authentication', 'Server: %s' % (', '.join(modes) or 'Local Database'),
                   'Server: <Local + TOTP server> (System › Access › Servers)', 'system_authservers.php'))


@check('PA-USR-02', 'accounts', 'Administrators have a TOTP seed', 'high',
       [cis('6.5', 'Require MFA for administrative access'), nist53('IA-2(1)'), DOC_2FA],
       PAGE_USERS, 'Generate an OTP seed for every enabled administrator (System › Access › Users).')
def admin_totp(ctx):
    admins = [u for u in ctx.users if u['admin'] and not u['disabled']]
    missing = [u['name'] for u in admins if not u['has_otp']]
    evidence = {'administrators': [u['name'] for u in admins], 'without_otp': missing,
                'gui_totp': any(m in _totp_servers(ctx) for m in ctx.csv('system/webgui/authmode'))}
    if not missing:
        return res('pass', 'all %d administrators have an OTP seed' % len(admins), evidence)
    key_only = [u['name'] for u in admins if not u['has_otp'] and u['authorized_keys']]
    evidence['ssh_key_only'] = key_only
    return res('fail', '%d administrator(s) without OTP seed: %s' % (len(missing), ', '.join(missing)), evidence,
               fix('System › Access › Users › %s' % missing[0], 'OTP seed: empty',
                   'OTP seed: generated (scan the QR code); or remove the account from the admins group', PAGE_USERS),
               severity='high' if not evidence['gui_totp'] else 'medium')


@check('PA-USR-03', 'accounts', 'root: no password login over SSH', 'high',
       [cis('5.4', 'Restrict administrator privileges'), nist53('AC-6(2)'), DOC_USERS],
       PAGE_ADMIN, 'Never combine "Permit root user login" with "Permit password login".')
def root_password_ssh(ctx):
    if not _ssh_enabled(ctx):
        return na('SSH is disabled')
    root = next((u for u in ctx.users if u['uid'] == '0'), None)
    if root is None or root['disabled']:
        return res('pass', 'root is disabled', {})
    password = ctx.flag('system/ssh/passwordauth')
    permit = ctx.flag('system/ssh/permitrootlogin')
    evidence = {'root_has_password': root['has_password'], 'ssh_password_auth': password,
                'ssh_permit_root': permit}
    if root['has_password'] and password and permit:
        return res('fail', 'root can log in over SSH with a password', evidence,
                   fix(GUI_ADMIN + ' › Secure Shell', ['Permit root user login: checked',
                                                        'Permit password login: checked'],
                       ['Permit root user login: unchecked', 'Permit password login: unchecked'], PAGE_ADMIN))
    return res('pass', 'root has no password path over SSH', evidence)


@check('PA-USR-04', 'accounts', 'API keys only on least-privilege accounts', 'medium',
       [cis('5.4', 'Restrict administrator privileges'), nist53('AC-6'), DOC_USERS],
       PAGE_USERS, 'Give API keys to dedicated accounts with only the privileges they need, not to administrators.')
def api_keys(ctx):
    with_keys = [u for u in ctx.users if u['has_apikeys'] and not u['disabled']]
    admin_keys = [u['name'] for u in with_keys if u['admin']]
    evidence = {'accounts_with_api_keys': [u['name'] for u in with_keys], 'administrators_with_api_keys': admin_keys}
    if admin_keys:
        return res('fail', 'administrator account(s) with API keys: %s' % ', '.join(admin_keys), evidence,
                   fix('System › Access › Users › %s' % admin_keys[0], 'API keys on a full administrator',
                       'API keys on a dedicated account with only the needed privileges', PAGE_USERS))
    if not with_keys:
        return res('pass', 'no API keys', evidence)
    return res('pass', '%d API account(s), none with full privileges' % len(with_keys), evidence)


@check('PA-USR-05', 'accounts', 'sudo asks for the password', 'low',
       [cis('5.4', 'Restrict administrator privileges'), nist53('AC-6(1)'), DOC_ADMIN],
       PAGE_ADMIN, 'Set Administration › Authentication › Sudo to "Ask password".')
def sudo_password(ctx):
    value = ctx.text('system/sudo_allow_wheel')
    evidence = {'sudo_allow_wheel': {'': 'disallow', '1': 'ask password', '2': 'no password'}.get(value, value)}
    if value == '2':
        shell_users = [u['name'] for u in ctx.users if u['admin'] and u['shell'] and not u['disabled']
                       and u['uid'] != '0']
        evidence['admins_with_shell'] = shell_users
        return res('warn', 'administrators with a shell get root without a password (%s)' %
                   (', '.join(shell_users) or 'none right now'), evidence,
                   fix(GUI_ADMIN + ' › Authentication', 'Sudo: No password', 'Sudo: Ask password', PAGE_ADMIN),
                   severity='low' if shell_users else 'info')
    return res('pass', evidence['sudo_allow_wheel'], evidence)


# ========================================================================================== firmware / system

@check('PA-SYS-01', 'system', 'Firmware up to date', 'high',
       [cis('7.3', 'Perform automated operating system patch management'), nist53('SI-2'), DOC_FIRMWARE],
       PAGE_FIRMWARE, 'Install pending updates (System › Firmware › Status) and check for updates at least weekly.')
def firmware(ctx):
    data = ctx.firmware
    if not isinstance(data, dict):
        return res('warn', 'no update check result on this system yet', {},
                   fix('System › Firmware › Status', 'last check: never', 'Check for updates', PAGE_FIRMWARE),
                   severity='low')
    age_days = None
    mtime = ctx.file_mtime(ctx.paths.firmware)
    if mtime:
        age_days = int((now() - mtime) // 86400)
    upgrades = data.get('upgrade_packages') or []
    major = data.get('upgrade_major_version') or ''
    evidence = {'product_version': data.get('product_version'), 'last_check': data.get('last_check'),
                'check_age_days': age_days, 'upgrade_packages': len(upgrades),
                'new_packages': len(data.get('new_packages') or []), 'major_available': major or None,
                'connection': data.get('connection'), 'repository': data.get('repository')}
    the_fix = fix('System › Firmware › Status', 'version %s, %d update(s) pending' %
                  (data.get('product_version'), len(upgrades)), 'Update (review the changelog first)', PAGE_FIRMWARE)
    if upgrades:
        core = [p for p in upgrades if isinstance(p, dict) and p.get('name') in ('opnsense', 'base', 'kernel')]
        return res('fail', '%d package update(s) pending%s' % (len(upgrades), ' (core included)' if core else ''),
                   evidence, the_fix, severity='high' if core else 'medium')
    if age_days is not None and age_days > 7:
        return res('warn', 'last update check %d days ago' % age_days, evidence,
                   fix('System › Firmware › Status', 'last check %d days ago' % age_days, 'Check for updates',
                       PAGE_FIRMWARE), severity='low')
    if major:
        return res('warn', 'major release %s available' % major, evidence, the_fix, severity='low')
    return res('pass', '%s, no pending updates' % data.get('product_version'), evidence)


@check('PA-SYS-02', 'system', 'No pending reboot after an update', 'low',
       [cis('7.3', 'Perform automated operating system patch management'), nist53('SI-2'), DOC_FIRMWARE],
       PAGE_FIRMWARE, 'Reboot in a maintenance window when an update asks for it.')
def needs_reboot(ctx):
    data = ctx.firmware
    if not isinstance(data, dict):
        return na('no update check result')
    pending = str(data.get('needs_reboot', '0')) == '1'
    if pending:
        return res('warn', 'an installed update waits for a reboot', {'needs_reboot': True},
                   fix('System › Firmware', 'kernel/base update installed, not active', 'Reboot (maintenance window)',
                       PAGE_FIRMWARE))
    return res('pass', 'nothing waits for a reboot', {'needs_reboot': False})


NET_HARDENING = {
    'net.inet.tcp.blackhole': ('2', 'drop RST on closed TCP ports (no stealth scan answers)'),
    'net.inet.udp.blackhole': ('1', 'no ICMP port unreachable for closed UDP ports'),
    'net.inet.ip.random_id': ('1', 'random IP ID (no idle scan / host counting)'),
    'net.inet.ip.redirect': ('0', 'do not send ICMP redirects'),
    'net.inet.ip.sourceroute': ('0', 'do not forward source routed packets'),
    'net.inet.ip.accept_sourceroute': ('0', 'do not accept source routed packets'),
    'net.inet.tcp.drop_synfin': ('1', 'drop SYN+FIN packets'),
    'net.inet6.ip6.redirect': ('0', 'do not send ICMPv6 redirects'),
    'net.inet.icmp.drop_redirect': ('1', 'ignore ICMP redirects'),
}


@check('PA-SYS-03', 'system', 'Network stack hardening (sysctl)', 'medium',
       [cis('4.1', 'Establish and maintain a secure configuration process'), nist53('CM-6'), DOC_TUNABLES],
       PAGE_TUNABLES, 'Set the recommended network tunables in System › Settings › Tunables.')
def sysctl_network(ctx):
    values = ctx.sysctl(sorted(NET_HARDENING))
    if values is None:
        return na('sysctl not available')
    bad = []
    for name, (wanted, why) in sorted(NET_HARDENING.items()):
        if name not in values:
            continue
        current = values[name]
        if name.endswith('blackhole'):
            ok = current.isdigit() and int(current) >= int(wanted) - (1 if name.endswith('tcp.blackhole') else 0)
        else:
            ok = current == wanted
        if not ok:
            bad.append({'tunable': name, 'current': current, 'recommended': wanted, 'why': why})
    evidence = {'checked': len(values), 'not_hardened': bad}
    if not bad:
        return res('pass', '%d network tunables hardened' % len(values), evidence)
    return res('warn' if len(bad) <= 2 else 'fail', '%d tunable(s) differ: %s' % (
        len(bad), ', '.join(b['tunable'] for b in bad)), evidence,
        fix('System › Settings › Tunables', ['%s = %s' % (b['tunable'], b['current']) for b in bad],
            ['%s = %s' % (b['tunable'], b['recommended']) for b in bad], PAGE_TUNABLES))


@check('PA-SYS-04', 'system', 'Process isolation and CPU mitigations', 'medium',
       [cis('4.1', 'Establish and maintain a secure configuration process'), nist53('SC-39'), DOC_TUNABLES],
       PAGE_TUNABLES, 'Keep CPU side channel mitigations on (vm.pmap.pti=1 on affected Intel CPUs, hw.ibrs_disable=0) '
                      'and hide other users\' processes (security.bsd.see_other_uids=0).')
def sysctl_isolation(ctx):
    names = ['vm.pmap.pti', 'hw.ibrs_disable', 'security.bsd.see_other_uids', 'security.bsd.see_other_gids',
             'kern.randompid', 'hw.mds_disable']
    values = ctx.sysctl(names)
    if values is None:
        return na('sysctl not available')
    bad = []
    if values.get('vm.pmap.pti') == '0':
        bad.append(('vm.pmap.pti', '0', '1', 'Meltdown mitigation (page table isolation) is off'))
    if values.get('hw.ibrs_disable') == '1':
        bad.append(('hw.ibrs_disable', '1', '0', 'Spectre v2 mitigation (IBRS) is off'))
    if values.get('hw.mds_disable') == '1':
        bad.append(('hw.mds_disable', '1', '0', 'MDS mitigation is off'))
    if values.get('security.bsd.see_other_uids') == '1':
        bad.append(('security.bsd.see_other_uids', '1', '0', 'users can see other users\' processes'))
    if values.get('kern.randompid') == '0':
        bad.append(('kern.randompid', '0', '1', 'predictable process ids'))
    evidence = {'values': values, 'not_hardened': [{'tunable': b[0], 'current': b[1], 'recommended': b[2],
                                                     'why': b[3]} for b in bad]}
    if not bad:
        return res('pass', 'mitigations and isolation on', evidence)
    cpu = any(b[0] in ('vm.pmap.pti', 'hw.ibrs_disable', 'hw.mds_disable') for b in bad)
    return res('warn', '; '.join(b[3] for b in bad), evidence,
               fix('System › Settings › Tunables', ['%s = %s' % (b[0], b[1]) for b in bad],
                   ['%s = %s' % (b[0], b[2]) for b in bad], PAGE_TUNABLES,
                   note='CPU mitigations cost some throughput; the firewall runs only trusted code, so this is a '
                        'deliberate trade-off when documented.' if cpu else None))


# listeners every firewall has, or that only the rule set exposes by design
EXPECTED_WILDCARD = {'wireguard', 'wg', 'charon', 'openvpn', 'samplicate', 'flowd', 'dhclient', 'dhcp6c',
                     'dpinger', 'radvd', 'rtsold'}


@check('PA-SYS-05', 'system', 'Services listening on all addresses', 'medium',
       [cis('4.8', 'Uninstall or disable unnecessary services'), nist53('CM-7'), NIST41],
       PAGE_ADMIN, 'Bind services to the interfaces that need them; a service bound to * is one rule away '
                   'from the internet.')
def wildcard_listeners(ctx):
    listeners = ctx.listeners
    if listeners is None:
        return na('sockstat not available')
    wildcard = [lst for lst in listeners if lst['address'] in ('*', '0.0.0.0', '::') and
                lst['command'] not in EXPECTED_WILDCARD and lst['port']]
    # WireGuard is in the kernel: sockets without a command name show as "??"
    wildcard = [w for w in wildcard if w['command'] not in ('??', '?')]
    evidence = {'listening': len(listeners), 'wildcard': sorted(
        {'%s %s/%s' % (w['command'], w['port'], w['proto'].rstrip('46')) for w in wildcard})}
    if not wildcard:
        return res('pass', 'no unexpected service bound to all addresses', evidence)
    return res('warn', 'bound to all addresses: %s' % ', '.join(evidence['wildcard']), evidence,
               fix('the service settings', ['%s listens on *' % w for w in evidence['wildcard']],
                   'listen only on the internal interfaces (e.g. Network Time › Interfaces, Unbound › Network '
                   'Interfaces)', PAGE_ADMIN), severity='low')


@check('PA-SYS-06', 'system', 'UPnP / NAT-PMP disabled or restricted', 'high',
       [cis('4.8', 'Uninstall or disable unnecessary services'), nist53('CM-7'), DOC_UPNP],
       'services_upnp.php', 'Disable UPnP, or allow only listed hosts and ports (deny by default).')
def upnp(ctx):
    node = ctx.node('installedpackages/miniupnpd/config')
    if node is None:
        node = ctx.node('OPNsense/miniupnpd') or ctx.node('miniupnpd')
    if node is None:
        return na('UPnP (os-upnp) is not installed')
    enabled = (node.findtext('enable') or '').strip() not in ('', '0', 'off')
    if not enabled:
        return res('pass', 'UPnP is installed but disabled', {'enabled': False})
    acl = [n.text for n in node.iter() if n.tag.startswith('permuser') and (n.text or '').strip()]
    default_deny = (node.findtext('permdefault') or '').strip() not in ('', '0')
    evidence = {'enabled': True, 'acl_entries': len(acl), 'deny_by_default': default_deny}
    if acl and default_deny:
        return res('warn', 'UPnP on with %d ACL entr(ies), deny by default' % len(acl), evidence, severity='low')
    return res('fail', 'UPnP lets any LAN host open ports on the WAN', evidence,
               fix('Services › Universal Plug and Play', 'Enable: checked, no ACL',
                   ['Enable: unchecked', 'or: Default deny: checked + user specified permissions'],
                   'services_upnp.php'))


OPTIONAL_SERVICES = (
    ('OPNsense/monit/general/httpdEnabled', 'Monit web interface'),
    ('OPNsense/netdata/general/enabled', 'Netdata'),
    ('OPNsense/snmp/general/enabled', 'SNMP (net-snmp)'),
    ('OPNsense/lldpd/general/enabled', 'LLDP'),
    ('OPNsense/ndproxy/general/enabled', 'NDP proxy'),
    ('OPNsense/tftp/general/enabled', 'TFTP'),
)


@check('PA-SYS-07', 'system', 'Optional management services', 'low',
       [cis('4.8', 'Uninstall or disable unnecessary services'), nist53('CM-7'), DOC_ADMIN],
       PAGE_ADMIN, 'Disable management add-ons you do not use (SNMP, Monit httpd, Netdata, TFTP...).')
def optional_services(ctx):
    on = [label for path, label in OPTIONAL_SERVICES if ctx.flag(path)]
    if ctx.has('bsnmpd/enable') or ctx.has('snmpd/enable'):
        on.append('SNMP (bsnmpd)')
    dnsmasq = ctx.has('dnsmasq/enable') and ctx.text('dnsmasq/enable') not in ('0',)
    if dnsmasq and ctx.flag('OPNsense/unboundplus/general/enabled'):
        on.append('Dnsmasq next to Unbound')
    evidence = {'enabled': on}
    if not on:
        return res('pass', 'no optional management service enabled', evidence)
    return res('warn', 'enabled: %s' % ', '.join(on), evidence,
               fix('the service pages', ['%s: enabled' % s for s in on], 'disable what is not used', PAGE_ADMIN),
               severity='low')


# ========================================================================================== firewall policy

@check('PA-FW-01', 'firewall', 'No any-to-any pass rules', 'high',
       [cis('4.4', 'Implement and manage a firewall on servers'), cis('13.4', 'Perform traffic filtering'),
        NIST41, DOC_RULES],
       PAGE_RULES, 'Restrict source, destination and ports; use "Minimal rule" to derive them from the traffic.')
def any_any(ctx):
    findings = _report_findings(ctx, 'permissive')
    if findings is None:
        return na('no Policy Analyzer report yet (run the analysis)')
    hits = [f for f in findings if 'any_any' in ((f.get('evidence') or {}).get('reasons') or [])]
    evidence = {'rules': [{'finding': f.get('id'), 'rule': (f.get('rules') or [{}])[0].get('summary'),
                           'uuid': (f.get('rules') or [{}])[0].get('uuid'), 'severity': f.get('severity')}
                          for f in hits]}
    if not hits:
        return res('pass', 'no rule passes any source to any destination on every protocol', evidence)
    first = evidence['rules'][0]
    the_fix = fix('Firewall › Rules', first['rule'], 'minimal rule from the observed traffic (destinations, ports '
                  'and protocols really used)', PAGE_RULES)
    the_fix['minrule'] = first['uuid']
    return res('fail', '%d any-to-any pass rule(s)' % len(hits), evidence, the_fix,
               severity='high' if any(f.get('severity') == 'high' for f in hits) else 'medium')


@check('PA-FW-02', 'firewall', 'Nothing on the firewall itself exposed to the WAN', 'high',
       [cis('4.4', 'Implement and manage a firewall'), cis('12.2', 'Establish and maintain a secure network '
                                                                  'architecture'), NIST41, DOC_RULES],
       PAGE_RULES, 'Keep only the WAN pass rules you need (VPN listeners) and restrict their sources.')
def wan_exposed(ctx):
    findings = _report_findings(ctx, 'wan_exposed')
    if findings is None:
        return na('no Policy Analyzer report yet (run the analysis)')
    evidence = {'rules': [{'finding': f.get('id'), 'severity': f.get('severity'),
                           'rule': (f.get('rules') or [{}])[0].get('summary'),
                           'uuid': (f.get('rules') or [{}])[0].get('uuid'),
                           'admin_ports': (f.get('evidence') or {}).get('admin_ports')} for f in findings]}
    high = [f for f in findings if f.get('severity') in ('high', 'medium')]
    if not findings:
        return res('pass', 'no WAN pass rule reaches the firewall', evidence)
    first = evidence['rules'][0]
    the_fix = fix('Firewall › Rules', first['rule'], 'restrict the source (VPN peers / alias) or the port; '
                  'see "Minimal rule"', PAGE_RULES)
    the_fix['minrule'] = first['uuid']
    if high:
        return res('fail', '%d WAN rule(s) expose the firewall (management or broad ports)' % len(high), evidence,
                   the_fix)
    return res('warn', '%d WAN rule(s) reach the firewall (e.g. VPN listeners), review their sources' %
               len(findings), evidence, the_fix, severity='low')


def _wan_inbound(rule, wans):
    names = [n for n in rule.get('interface', '').split(',') if n]
    return rule.get('direction', 'in') in ('in', 'any', '') and any(n in wans for n in names)


@check('PA-FW-03', 'firewall', 'Block and reject rules are logged', 'medium',
       [cis('8.2', 'Collect audit logs'), nist53('AU-12'), DOC_RULES],
       PAGE_RULES, 'Enable "Log packets that are handled by this rule" on block/reject rules.')
def block_logging(ctx):
    rules = [r for r in ctx.mvc_rules if r.get('enabled', '1') == '1' and r.get('action') in ('block', 'reject')]
    silent = [r for r in rules if r.get('log') != '1']
    evidence = {'block_rules': len(rules), 'not_logged': [{'uuid': r['uuid'], 'description': r.get('description'),
                                                            'interface': r.get('interface')} for r in silent]}
    if not rules:
        return na('no explicit block/reject rules (the default deny is checked by PA-FW-05)')
    if not silent:
        return res('pass', 'all %d block/reject rules log' % len(rules), evidence)
    ratio = len(silent) / float(len(rules))
    return res('fail' if ratio > 0.5 else 'warn', '%d of %d block/reject rules do not log' % (len(silent), len(rules)),
               evidence, fix('Firewall › Rules › %s' % (silent[0].get('description') or silent[0]['uuid']),
                             'Log: unchecked', 'Log: checked', 'ui/firewall/filter#search=%s' % silent[0]['uuid']),
               severity='medium' if ratio > 0.5 else 'low')


@check('PA-FW-04', 'firewall', 'WAN pass rules are logged', 'medium',
       [cis('8.2', 'Collect audit logs'), nist53('AU-12'), DOC_RULES],
       PAGE_RULES, 'Log the pass rules of the WAN interfaces (connections into the network are evidence).')
def wan_pass_logging(ctx):
    wans = ctx.wan_interfaces
    rules = [r for r in ctx.mvc_rules if r.get('enabled', '1') == '1' and r.get('action') == 'pass' and
             _wan_inbound(r, wans)]
    silent = [r for r in rules if r.get('log') != '1']
    all_pass = [r for r in ctx.mvc_rules if r.get('enabled', '1') == '1' and r.get('action') == 'pass']
    logged = sum(1 for r in all_pass if r.get('log') == '1')
    evidence = {'wan_pass_rules': len(rules), 'not_logged': [{'uuid': r['uuid'], 'description': r.get('description')}
                                                              for r in silent],
                'pass_rules_logged_pct': round(100.0 * logged / len(all_pass), 1) if all_pass else None}
    if not rules:
        return na('no WAN pass rules')
    if not silent:
        return res('pass', 'all %d WAN pass rules log' % len(rules), evidence)
    return res('warn', '%d WAN pass rule(s) without logging' % len(silent), evidence,
               fix('Firewall › Rules › %s' % (silent[0].get('description') or silent[0]['uuid']), 'Log: unchecked',
                   'Log: checked', 'ui/firewall/filter#search=%s' % silent[0]['uuid']))


@check('PA-FW-05', 'firewall', 'Default deny is logged', 'medium',
       [cis('8.2', 'Collect audit logs'), nist53('AU-12'), DOC_FW_SETTINGS],
       'ui/syslog/', 'Keep "Log packets matched from the default block rules" enabled.')
def default_block_log(ctx):
    off = ctx.has('syslog/nologdefaultblock') or ctx.flag('OPNsense/Syslog/general/nologdefaultblock')
    if off:
        return res('fail', 'the default block rule does not log', {'log_default_block': False},
                   fix('System › Settings › Logging', 'Log packets matched from the default block rules: unchecked',
                       'Log packets matched from the default block rules: checked', 'ui/syslog/'))
    return res('pass', 'the default block rule logs', {'log_default_block': True})


def _antilockout_disabled(ctx):
    if ctx.has('system/webgui/noantilockout'):
        return True
    node = ctx.node('OPNsense/Firewall/Filter/settings')
    if node is not None:
        for item in node.iter():
            if 'antilockout' in item.tag.lower() and (item.text or '').strip() == '1':
                return True
    return False


@check('PA-FW-06', 'firewall', 'Anti-lockout replaced by an explicit admin rule', 'low',
       [cis('4.6', 'Securely manage enterprise assets'), nist53('AC-17'), DOC_FW_SETTINGS],
       PAGE_FW_ADV, 'Once an explicit rule lets only the admin hosts reach the GUI/SSH, disable the anti-lockout '
                    'rule (it allows every LAN host).')
def antilockout(ctx):
    disabled = _antilockout_disabled(ctx)
    evidence = {'anti_lockout': not disabled}
    if disabled:
        return res('pass', 'anti-lockout disabled (access is decided by explicit rules)', evidence)
    return res('warn', 'the automatic anti-lockout rule lets every host on the LAN reach the GUI and SSH', evidence,
               fix('Firewall › Settings › Advanced', 'Disable anti-lockout: unchecked',
                   ['1) Firewall › Rules › LAN: pass from <admin hosts alias> to This Firewall port 443, 22',
                    '2) Disable anti-lockout: checked (only after testing rule 1)'], PAGE_FW_ADV),
               severity='low')


@check('PA-FW-07', 'firewall', 'WAN blocks private and bogon networks', 'medium',
       [cis('13.4', 'Perform traffic filtering between network segments'), nist53('SC-7'), NIST41, DOC_INTERFACES],
       'interfaces.php', 'Enable "Block private networks" and "Block bogon networks" on every WAN.')
def bogons(ctx):
    wans = ctx.wan_interfaces
    if not wans:
        return na('no WAN interface')
    missing = []
    detail = {}
    for name in wans:
        info = ctx.interfaces[name]
        detail[name] = {'block_private': info['blockpriv'], 'block_bogons': info['blockbogons'],
                        'address': info['ipaddr']}
        if not info['blockbogons']:
            missing.append('%s: Block bogon networks' % ctx.interface_label(name))
        # behind a modem in a private transit network, blocking private sources would cut the modem off
        private_transit = re.match(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)', info['ipaddr'] or '')
        if not info['blockpriv'] and not private_transit:
            missing.append('%s: Block private networks' % ctx.interface_label(name))
    evidence = {'wan_interfaces': detail}
    if not missing:
        return res('pass', 'bogon/private blocking on %s' % _wan_label(ctx), evidence)
    first = [n for n in wans if n in missing[0]] or wans
    return res('fail' if len(missing) > 1 else 'warn', '; '.join(missing) + ' disabled', evidence,
               fix('Interfaces › [WAN] › Generic configuration', ['%s: unchecked' % m for m in missing],
                   ['%s: checked' % m for m in missing], 'interfaces.php?if=%s' % first[0]))


@check('PA-FW-08', 'firewall', 'IPv6 is filtered when enabled', 'medium',
       [cis('4.4', 'Implement and manage a firewall'), nist53('SC-7'), NIST41, DOC_RULES],
       PAGE_RULES, 'With IPv6 on, add IPv6 (or IPv4+IPv6) rules with the same intent as the IPv4 ones, or disable '
                   'IPv6 (Firewall › Settings › Advanced › Allow IPv6).')
def ipv6(ctx):
    # 26.x: Interfaces › Settings "disableipv6"; older configs: system/ipv6allow (present = allowed)
    if ctx.node('OPNsense/Interfaces/settings/disableipv6') is not None:
        disabled = ctx.flag('OPNsense/Interfaces/settings/disableipv6')
    else:
        disabled = not ctx.has('system/ipv6allow')
    v6_ifaces = [n for n, i in ctx.interfaces.items() if i['ipaddrv6'] and i['enabled'] and n != 'lo0']
    v6_rules = [r for r in ctx.mvc_rules if r.get('enabled', '1') == '1' and r.get('ipprotocol') in ('inet6', 'inet46')]
    evidence = {'ipv6_allowed': not disabled, 'interfaces_with_ipv6': v6_ifaces, 'ipv6_rules': len(v6_rules)}
    if disabled and not v6_ifaces:
        return res('pass', 'IPv6 is disabled', evidence)
    if v6_ifaces and not v6_rules:
        return res('fail', 'IPv6 configured on %s but no IPv6 rules' % ', '.join(v6_ifaces), evidence,
                   fix('Firewall › Rules', 'rules: IPv4 only', 'rules: IPv4+IPv6 (TCP/IP Version) where the intent '
                       'is the same, explicit IPv6 blocks elsewhere', PAGE_RULES))
    return res('pass', '%d IPv6 rule(s) for %s' % (len(v6_rules), ', '.join(v6_ifaces) or 'no IPv6 interface'),
               evidence)


@check('PA-FW-09', 'firewall', 'State table has headroom', 'medium',
       [cis('4.1', 'Establish and maintain a secure configuration'), nist53('SC-5'), DOC_FW_SETTINGS],
       PAGE_FW_ADV, 'Keep the state table limit at the default (10% of RAM) or higher than the peak; under 80% use.')
def states(ctx):
    pf = ctx.pf_limits
    configured = ctx.text('system/maximumstates')
    if pf is None or not pf.get('states_limit'):
        return na('pfctl not available', {'configured_limit': configured or 'default'})
    used = (pf['states_current'] or 0) / float(pf['states_limit'])
    evidence = {'configured_limit': configured or 'default', 'limit': pf['states_limit'],
                'current': pf['states_current'], 'used_pct': round(100 * used, 2)}
    if used > 0.8:
        return res('fail', 'state table %.0f%% full' % (100 * used), evidence,
                   fix('Firewall › Settings › Advanced', 'Firewall Maximum States: %s' % (configured or 'default'),
                       'Firewall Maximum States: higher, or find the source of the states (Diagnostics › States)',
                       PAGE_FW_ADV))
    if configured.isdigit() and int(configured) < 100000:
        return res('warn', 'state limit set low (%s)' % configured, evidence, severity='low')
    return res('pass', '%d of %d states in use (%.2f%%)' % (pf['states_current'] or 0, pf['states_limit'],
                                                             100 * used), evidence)


@check('PA-FW-10', 'firewall', 'Rule counters kept across reloads', 'low',
       [cis('8.2', 'Collect audit logs'), nist53('AU-6'), DOC_FW_SETTINGS],
       PAGE_FW_ADV, 'Enable "Keep counters" so unused-rule analysis covers the time since boot.')
def keep_counters(ctx):
    keep = ctx.has('system/keepcounters') or ctx.flag('OPNsense/Firewall/Filter/settings/filter/keep_counters')
    if keep:
        return res('pass', 'counters survive filter reloads', {'keep_counters': True})
    return res('warn', 'counters restart at every filter reload', {'keep_counters': False},
               fix('Firewall › Settings › Advanced', 'Keep counters: unchecked', 'Keep counters: checked', PAGE_FW_ADV),
               severity='info')


@check('PA-FW-11', 'firewall', 'Automatic quarantine of WAN scanners', 'low',
       [cis('13.3', 'Deploy a network intrusion detection solution'), nist53('SI-4'), DOC_RULES],
       'ui/policyanalyzer/#quarantine', 'Install the Policy Analyzer quarantine (rule "Max Cyber IA"), simulated '
                                        'step by step.')
def quarantine(ctx):
    rules = [r for r in ctx.mvc_rules if r.get('description') == 'Max Cyber IA']
    enabled = [r for r in rules if r.get('enabled', '1') == '1']
    evidence = {'rule_present': bool(rules), 'rule_enabled': bool(enabled)}
    if enabled:
        return res('pass', 'quarantine rule "Max Cyber IA" active', evidence)
    return res('warn', 'repeat scanners are only blocked by the default deny, never quarantined', evidence,
               fix('Firewall › Policy Analyzer › Quarantine', 'quarantine: not installed',
                   'quarantine: installed (alias pa_quarantine + rule "Max Cyber IA" + schedule)',
                   'ui/policyanalyzer/#quarantine', action={'name': 'install_quarantine', 'args': []}),
               severity='info')


# ========================================================================================== logging

@check('PA-LOG-01', 'logging', 'Logs sent to a remote syslog', 'medium',
       [cis('8.9', 'Centralize audit logs'), nist53('AU-9(2)'), DOC_LOGGING],
       PAGE_SYSLOG, 'Add a remote destination (System › Settings › Logging › Remote), TLS when possible.')
def remote_syslog(ctx):
    dests = []
    for dest in ctx.nodes('OPNsense/Syslog/destinations/destination'):
        if (dest.findtext('enabled') or '1').strip() == '1':
            dests.append({'transport': (dest.findtext('transport') or '').strip(),
                          'port': (dest.findtext('port') or '').strip()})
    legacy = ctx.has('syslog/remoteserver') and ctx.has('syslog/enable')
    evidence = {'destinations': dests, 'legacy_remote': legacy}
    if not dests and not legacy:
        return res('fail', 'logs only on this firewall (lost if it is compromised or the disk fails)', evidence,
                   fix('System › Settings › Logging › Remote', 'destinations: none',
                       '+ destination: tls4 <log server>:6514, all applications, level info', PAGE_SYSLOG))
    if dests and all(not d['transport'].startswith('tls') for d in dests):
        return res('warn', '%d remote destination(s), none over TLS' % len(dests), evidence, severity='low')
    return res('pass', '%d remote destination(s)' % (len(dests) or 1), evidence)


@check('PA-LOG-02', 'logging', 'Log retention', 'low',
       [cis('8.10', 'Retain audit logs'), nist53('AU-11'), DOC_LOGGING],
       PAGE_SYSLOG, 'Keep at least 90 days of local logs (CIS 8.10).')
def retention(ctx):
    days = ctx.text('OPNsense/Syslog/general/maxpreserve')
    days = int(days) if days.isdigit() else 31
    evidence = {'preserve_days': days, 'local_logging': ctx.text('OPNsense/Syslog/general/loglocal', '1') != '0'}
    if not evidence['local_logging']:
        return res('fail', 'local logging is disabled', evidence)
    if days < 90:
        return res('warn', '%d days kept' % days, evidence,
                   fix('System › Settings › Logging', 'Preserve logs (Days): %d' % days, 'Preserve logs (Days): 90',
                       PAGE_SYSLOG))
    return res('pass', '%d days kept' % days, evidence)


@check('PA-LOG-03', 'logging', 'Alerts reach an administrator', 'low',
       [cis('8.11', 'Conduct audit log reviews'), nist53('SI-4(5)'), DOC_MONIT],
       PAGE_MONIT, 'Enable Monit with a mail server and an alert recipient.')
def monit(ctx):
    enabled = ctx.flag('OPNsense/monit/general/enabled')
    mail = ctx.text('OPNsense/monit/general/mailserver')
    alerts = [a for a in ctx.nodes('OPNsense/monit/alert') if (a.findtext('enabled') or '') == '1']
    evidence = {'monit': enabled, 'mail_server': bool(mail), 'alert_recipients': len(alerts)}
    if enabled and mail and alerts:
        return res('pass', 'Monit mails %d recipient(s)' % len(alerts), evidence)
    return res('warn', 'no e-mail alerting configured', evidence,
               fix('Services › Monit', 'alerts: none', ['Mail server: <smtp>', '+ Alert settings: recipient'],
                   PAGE_MONIT))


# ========================================================================================== DNS / NTP

@check('PA-DNS-01', 'dns_ntp', 'DNSSEC validation', 'medium',
       [cis('9.2', 'Use DNS filtering services'), nist53('SC-21'), DOC_UNBOUND],
       PAGE_UNBOUND, 'Enable DNSSEC support in Unbound (Services › Unbound DNS › General).')
def dnssec(ctx):
    if not ctx.flag('OPNsense/unboundplus/general/enabled'):
        return na('Unbound is disabled')
    local = ctx.flag('OPNsense/unboundplus/general/dnssec')
    crypt = ctx.flag('OPNsense/dnscryptproxy/general/enabled') and \
        ctx.flag('OPNsense/dnscryptproxy/general/require_dnssec')
    forwarders = ctx.unbound_forwarders() or []
    via_crypt = crypt and any('@5353' in f or f.startswith('127.0.0.1') for f in forwarders)
    evidence = {'unbound_dnssec': local, 'dnscrypt_require_dnssec': crypt, 'forwarders': forwarders}
    if local:
        return res('pass', 'Unbound validates DNSSEC', evidence)
    the_fix = fix('Services › Unbound DNS › General', 'DNSSEC: unchecked', 'DNSSEC: checked', PAGE_UNBOUND)
    if via_crypt:
        return res('warn', 'validation delegated to the dnscrypt-proxy upstream servers (not validated locally)',
                   evidence, the_fix, severity='low')
    return res('fail', 'answers are not DNSSEC validated', evidence, the_fix)


@check('PA-DNS-02', 'dns_ntp', 'Encrypted upstream DNS (DoT / DNSCrypt / DoH)', 'medium',
       [cis('3.10', 'Encrypt sensitive data in transit'), nist53('SC-8'), DOC_UNBOUND],
       PAGE_UNBOUND_DOT, 'Forward the queries over DNS over TLS (Unbound › DNS over TLS) or through dnscrypt-proxy.')
def dns_encrypted(ctx):
    if not ctx.flag('OPNsense/unboundplus/general/enabled'):
        return na('Unbound is disabled')
    dots = [d for d in ctx.nodes('OPNsense/unboundplus/dots/dot') if (d.findtext('enabled') or '') == '1']
    dot_tls = [d for d in dots if (d.findtext('type') or 'dot') == 'dot' and (d.findtext('port') or '853') == '853']
    crypt = ctx.flag('OPNsense/dnscryptproxy/general/enabled')
    forwarders = ctx.unbound_forwarders() or []
    via_crypt = crypt and any('@5353' in f or f.startswith('127.0.0.1@') for f in forwarders)
    evidence = {'dot_servers': len(dot_tls), 'forwarders': forwarders, 'dnscrypt_proxy': crypt,
                'forwarding_mode': ctx.flag('OPNsense/unboundplus/forwarding/enabled')}
    if dot_tls:
        return res('pass', 'DNS over TLS to %d server(s)' % len(dot_tls), evidence)
    if via_crypt:
        return res('pass', 'Unbound forwards to dnscrypt-proxy (DNSCrypt/DoH upstream)', evidence)
    return res('warn', 'queries leave in clear text (full recursion or plain forwarding)', evidence,
               fix('Services › Unbound DNS › DNS over TLS', 'servers: none', '+ 9.9.9.9 port 853, verify '
                   'dns.quad9.net (and a second provider)', PAGE_UNBOUND_DOT))


@check('PA-DNS-03', 'dns_ntp', 'DNS resolver not open to the WAN', 'high',
       [cis('4.8', 'Disable unnecessary services'), nist53('SC-7'), DOC_UNBOUND],
       PAGE_UNBOUND, 'Bind Unbound to the internal interfaces (Network Interfaces) and keep the ACL default.')
def dns_open(ctx):
    if not ctx.flag('OPNsense/unboundplus/general/enabled'):
        return na('Unbound is disabled')
    active = ctx.csv('OPNsense/unboundplus/general/active_interface')
    wans = ctx.wan_interfaces
    evidence = {'interfaces': active or ['all'], 'acl_default': ctx.text('OPNsense/unboundplus/acls/default_action',
                                                                        'allow')}
    bound_wan = [n for n in active if n in wans]
    the_fix = fix('Services › Unbound DNS › General', 'Network Interfaces: %s' % (', '.join(active) or 'All'),
                  'Network Interfaces: LAN (and the internal VLANs/VPN)', PAGE_UNBOUND)
    if bound_wan:
        return res('fail', 'Unbound listens on WAN interface(s) %s' % ', '.join(bound_wan), evidence, the_fix)
    if not active:
        return res('warn', 'Unbound listens on all interfaces (the ACL and the rule set protect it)', evidence,
                   the_fix, severity='low')
    return res('pass', 'listens on %s' % ', '.join(active), evidence)


@check('PA-DNS-04', 'dns_ntp', 'Resolver hides identity and blocks rebinding', 'low',
       [cis('4.1', 'Secure configuration'), nist53('SC-20'), DOC_UNBOUND],
       PAGE_UNBOUND_ADV, 'Enable "Hide Identity", "Hide Version" and the private address (rebind) protection.')
def dns_hardening(ctx):
    if not ctx.flag('OPNsense/unboundplus/general/enabled'):
        return na('Unbound is disabled')
    items = {
        'Hide Identity': ctx.flag('OPNsense/unboundplus/advanced/hideidentity'),
        'Hide Version': ctx.flag('OPNsense/unboundplus/advanced/hideversion'),
        'Rebind protection (Private Address)': bool(ctx.text('OPNsense/unboundplus/advanced/privateaddress')),
    }
    off = [k for k, v in items.items() if not v]
    if not off:
        return res('pass', 'identity/version hidden, rebind protection on', items)
    return res('warn', 'off: %s' % ', '.join(off), items,
               fix('Services › Unbound DNS › Advanced', ['%s: off' % k for k in off], ['%s: on' % k for k in off],
                   PAGE_UNBOUND_ADV))


@check('PA-NTP-01', 'dns_ntp', 'Reliable, authenticated time', 'low',
       [cis('8.4', 'Standardize time synchronization'), nist53('AU-8'), DOC_NTP],
       'services_ntpd.php', 'Use at least three time sources, NTS-authenticated when available (os-chrony).')
def ntp(ctx):
    if ctx.flag('OPNsense/chrony/enabled') or ctx.flag('OPNsense/chrony/general/enabled'):
        base = 'OPNsense/chrony' if ctx.node('OPNsense/chrony/peers') is not None else 'OPNsense/chrony/general'
        peers = ctx.csv(base + '/peers')
        nts = ctx.flag(base + '/ntsclient')
        evidence = {'daemon': 'chrony', 'servers': len(peers), 'nts': nts,
                    'allowed_networks': ctx.csv(base + '/allowednetworks')}
        page = 'ui/chrony/general'
    else:
        servers = [s for s in ctx.text('system/timeservers').split() if s]
        evidence = {'daemon': 'ntpd', 'servers': len(servers), 'nts': False}
        peers, nts, page = servers, False, 'services_ntpd.php'
    if len(peers) < 3:
        return res('warn', '%d time source(s)' % len(peers), evidence,
                   fix('Services › Network Time', 'servers: %d' % len(peers), 'servers: 3 or more (NTS when the '
                       'daemon supports it)', page))
    if not nts:
        return res('pass', '%d time sources (unauthenticated)' % len(peers), evidence)
    return res('pass', '%d time sources, NTS authenticated' % len(peers), evidence)


# ========================================================================================== IDS / IPS

@check('PA-IDS-01', 'ids', 'Intrusion detection enabled', 'medium',
       [cis('13.3', 'Deploy a network intrusion detection solution'), nist53('SI-4'), DOC_IDS],
       PAGE_IDS, 'Enable Suricata on the internal and/or WAN interfaces with maintained rule sets.')
def ids_enabled(ctx):
    if ctx.node('OPNsense/IDS') is None:
        return na('the IDS is not configured')
    enabled = ctx.flag('OPNsense/IDS/general/enabled')
    files = [f for f in ctx.nodes('OPNsense/IDS/files/file') if (f.findtext('enabled') or '') == '1']
    evidence = {'enabled': enabled, 'interfaces': ctx.csv('OPNsense/IDS/general/interfaces'),
                'rule_sets': len(files)}
    if not enabled:
        return res('fail', 'Suricata is disabled', evidence,
                   fix('Services › Intrusion Detection › Administration', 'Enabled: unchecked',
                       ['Enabled: checked', 'Download: enable rule sets (abuse.ch, ET open)'], PAGE_IDS))
    if not files:
        return res('warn', 'enabled without rule sets', evidence)
    return res('pass', 'enabled on %s with %d rule set(s)' % (', '.join(evidence['interfaces']) or '?', len(files)),
               evidence)


@check('PA-IDS-02', 'ids', 'Inline prevention (IPS) instead of detection only', 'medium',
       [cis('13.8', 'Deploy a network intrusion prevention solution'), nist53('SI-4(4)'), DOC_IDS],
       PAGE_IDS, 'Run Suricata in IPS mode (netmap or divert) with a drop policy for high-confidence rules.')
def ids_mode(ctx):
    if not ctx.flag('OPNsense/IDS/general/enabled'):
        return na('Suricata is disabled (see PA-IDS-01)')
    mode = ctx.text('OPNsense/IDS/general/mode') or ('ips' if ctx.flag('OPNsense/IDS/general/ips') else 'ids')
    ips = ctx.flag('OPNsense/IDS/general/ips') or mode in ('divert', 'netmap', 'ips')
    drop_policies = [p for p in ctx.nodes('OPNsense/IDS/policies/policy') if (p.findtext('enabled') or '') == '1'
                     and (p.findtext('new_action') or '') in ('drop', 'reject')]
    evidence = {'mode': mode, 'inline': ips, 'drop_policies': len(drop_policies)}
    if ips and drop_policies:
        return res('pass', 'inline (%s) with %d drop policy(ies)' % (mode, len(drop_policies)), evidence)
    if ips:
        return res('warn', 'inline mode but no policy changes alerts to drops', evidence, severity='low')
    return res('warn', 'detection only: alerts are logged, attacks are not stopped', evidence,
               fix('Services › Intrusion Detection › Administration', 'IPS mode: unchecked',
                   ['IPS mode: checked (disable hardware offloading first)', 'Policies: drop high confidence'],
                   PAGE_IDS, note='IPS on a small CPU costs throughput; measure first.'))


@check('PA-IDS-03', 'ids', 'IDS rules updated automatically', 'medium',
       [cis('13.3', 'Deploy a network intrusion detection solution'), nist53('SI-3(2)'), DOC_IDS],
       PAGE_IDS, 'Enable the rule update schedule (Intrusion Detection › Schedule, cron "ids update").')
def ids_updates(ctx):
    if not ctx.flag('OPNsense/IDS/general/enabled'):
        return na('Suricata is disabled')
    ref = ctx.text('OPNsense/IDS/general/UpdateCron')
    jobs = ctx.nodes('OPNsense/cron/jobs/job')
    job = None
    for item in jobs:
        if ref and item.get('uuid') == ref:
            job = item
    if job is None:
        job = next((j for j in jobs if (j.findtext('command') or '').strip() == 'ids update'), None)
    if job is None:
        return res('fail', 'no rule update schedule', {'cron': None},
                   fix('Services › Intrusion Detection › Schedule', 'schedule: none',
                       'schedule: daily "ids update"', PAGE_IDS))
    enabled = (job.findtext('enabled') or '') == '1'
    evidence = {'cron_enabled': enabled, 'when': '%s %s' % ((job.findtext('minutes') or '').strip(),
                                                           (job.findtext('hours') or '').strip())}
    if not enabled:
        return res('fail', 'the update job exists but is disabled: signatures age every day', evidence,
                   fix('Services › Intrusion Detection › Schedule', 'ids rule updates: disabled',
                       'ids rule updates: enabled (daily)', PAGE_CRON))
    return res('pass', 'rules updated by cron (%s)' % evidence['when'], evidence)


# ========================================================================================== backup

@check('PA-BAK-01', 'backup', 'Automatic off-box configuration backup', 'medium',
       [cis('11.2', 'Perform automated backups'), nist53('CP-9'), DOC_BACKUP],
       PAGE_BACKUP, 'Enable Google Drive, Nextcloud or Git backup (System › Configuration › Backups) on a schedule.')
def backups(ctx):
    targets = []
    if ctx.text('system/remotebackup/GDriveEnabled') in ('on', '1', 'yes'):
        targets.append('Google Drive')
    if ctx.flag('system/backup/git/enabled') or ctx.flag('OPNsense/backup/git/enabled'):
        targets.append('Git')
    if ctx.flag('system/backup/nextcloud/enabled') or ctx.flag('OPNsense/backup/nextcloud/enabled'):
        targets.append('Nextcloud')
    cron = [j for j in ctx.nodes('OPNsense/cron/jobs/job') if (j.findtext('command') or '').strip() ==
            'system remote backup' and (j.findtext('enabled') or '') == '1']
    evidence = {'targets': targets, 'scheduled': bool(cron)}
    if not targets:
        return res('fail', 'the configuration exists only on this box', evidence,
                   fix('System › Configuration › Backups', 'remote backup: none',
                       'remote backup: Git / Nextcloud / Google Drive, encrypted', PAGE_BACKUP))
    return res('pass', 'backup to %s%s' % (', '.join(targets), ', scheduled' if cron else ''), evidence)


@check('PA-BAK-02', 'backup', 'Off-box backups are encrypted', 'medium',
       [cis('3.11', 'Encrypt sensitive data at rest'), nist53('CP-9(8)'), DOC_BACKUP],
       PAGE_BACKUP, 'Set the backup encryption password (the configuration contains password hashes and keys).')
def backup_encrypted(ctx):
    gdrive = ctx.text('system/remotebackup/GDriveEnabled') in ('on', '1', 'yes')
    if not gdrive and not ctx.flag('system/backup/git/enabled') and not ctx.flag('system/backup/nextcloud/enabled'):
        return na('no remote backup (see PA-BAK-01)')
    encrypted = []
    plain = []
    if gdrive:
        (encrypted if ctx.text('system/remotebackup/GDrivePassword') else plain).append('Google Drive')
    if ctx.flag('system/backup/nextcloud/enabled'):
        (encrypted if ctx.text('system/backup/nextcloud/password_encryption') else plain).append('Nextcloud')
    if ctx.flag('system/backup/git/enabled'):
        plain.append('Git (stored as is, keep the repository private)')
    evidence = {'encrypted': encrypted, 'not_encrypted': plain}
    if plain:
        return res('warn', 'not encrypted: %s' % ', '.join(plain), evidence,
                   fix('System › Configuration › Backups', 'encryption password: empty', 'encryption password: set',
                       PAGE_BACKUP))
    return res('pass', 'encrypted: %s' % ', '.join(encrypted), evidence)


@check('PA-BAK-03', 'backup', 'Local configuration history', 'low',
       [cis('11.2', 'Perform automated backups'), nist53('CM-3'), DOC_BACKUP],
       'ui/core/backup/history/this', 'Keep at least 30 local configuration revisions.')
def backup_history(ctx):
    count = ctx.text('system/backupcount')
    count = int(count) if count.isdigit() else 60
    if count < 30:
        return res('warn', '%d revisions kept' % count, {'backupcount': count},
                   fix('System › Configuration › History', 'Backup Count: %d' % count, 'Backup Count: 60',
                       'diag_backup.php'))
    return res('pass', '%d revisions kept' % count, {'backupcount': count})


# ========================================================================================== certificates

@check('PA-CRT-01', 'crypto', 'No certificate expired or about to expire', 'medium',
       [cis('3.10', 'Encrypt sensitive data in transit'), nist53('SC-17'), DOC_CERTS],
       PAGE_CERTS, 'Renew (or remove) certificates that expire within 30 days.')
def certificates(ctx):
    items = []
    for cert in ctx.nodes('cert'):
        info = certificate_info(cert.findtext('crt') or '')
        if info is None:
            continue
        days = int((info['not_after'] - now()) // 86400)
        items.append({'certificate': (cert.findtext('descr') or '').strip(), 'expires_in_days': days,
                      'refid': (cert.findtext('refid') or '').strip()})
    if not items:
        return na('no parseable certificates')
    expired = [i for i in items if i['expires_in_days'] < 0]
    soon = [i for i in items if 0 <= i['expires_in_days'] < 30]
    evidence = {'certificates': len(items), 'expired': expired, 'expiring_30d': soon}
    if expired or soon:
        what = expired + soon
        return res('fail' if expired else 'warn', '%d expired, %d expiring in 30 days' % (len(expired), len(soon)),
                   evidence, fix('System › Trust › Certificates', ['%s (%d days)' % (i['certificate'],
                                                                                    i['expires_in_days'])
                                                                    for i in what],
                                 'renew or remove', PAGE_CERTS), severity='medium' if expired else 'low')
    return res('pass', '%d certificates, all valid for 30+ days' % len(items), evidence)


@check('PA-CRT-02', 'crypto', 'Strong certificate keys and signatures', 'medium',
       [cis('3.10', 'Encrypt sensitive data in transit'), nist53('SC-13'), DOC_CERTS],
       PAGE_CERTS, 'Use RSA 2048+ (3072+ preferred) or EC P-256+ keys and SHA-256+ signatures.')
def cert_strength(ctx):
    weak = []
    count = 0
    for cert in ctx.nodes('cert') + ctx.nodes('ca'):
        info = certificate_info(cert.findtext('crt') or '')
        if info is None:
            continue
        count += 1
        reasons = []
        if info['key_type'] == 'RSA' and (info['key_bits'] or 0) < 2048:
            reasons.append('RSA %s' % info['key_bits'])
        if info['key_type'] == 'DSA':
            reasons.append('DSA')
        if info['signature_hash'] in ('md5', 'sha1'):
            reasons.append(info['signature_hash'].upper())
        if reasons:
            weak.append({'certificate': (cert.findtext('descr') or '').strip(), 'weak': reasons})
    if not count:
        return na('no parseable certificates')
    if weak:
        return res('fail', '%d weak certificate(s)' % len(weak), {'weak': weak},
                   fix('System › Trust', ['%s: %s' % (w['certificate'], ', '.join(w['weak'])) for w in weak],
                       'reissue with RSA 3072 / EC P-256 and SHA-256', PAGE_CERTS))
    return res('pass', '%d certificates/CAs with strong keys' % count, {'checked': count})


@check('PA-CRT-03', 'crypto', 'Authorized SSH keys are strong', 'medium',
       [cis('5.2', 'Use unique passwords'), nist53('IA-5(2)'), DOC_USERS],
       PAGE_USERS, 'Replace DSA and RSA < 3072 bit keys by Ed25519 keys.')
def authorized_keys(ctx):
    weak = []
    total = 0
    for user in ctx.users:
        for line in user['authorized_keys']:
            info = ssh_key_info(line)
            if info is None:
                continue
            total += 1
            if info['type'] == 'ssh-dss' or (info['type'] == 'ssh-rsa' and (info['bits'] or 0) < 3072):
                weak.append({'user': user['name'], 'type': info['type'], 'bits': info['bits']})
    if not total:
        return na('no authorized keys')
    if weak:
        return res('warn' if all(w['type'] == 'ssh-rsa' and (w['bits'] or 0) >= 2048 for w in weak) else 'fail',
                   '%d weak key(s): %s' % (len(weak), ', '.join('%s %s %s' % (w['user'], w['type'], w['bits'])
                                                               for w in weak)),
                   {'keys': total, 'weak': weak},
                   fix('System › Access › Users › %s › Authorized keys' % weak[0]['user'],
                       '%s %s' % (weak[0]['type'], weak[0]['bits']), 'ssh-ed25519 (ssh-keygen -t ed25519)',
                       PAGE_USERS))
    return res('pass', '%d strong authorized key(s)' % total, {'keys': total})
