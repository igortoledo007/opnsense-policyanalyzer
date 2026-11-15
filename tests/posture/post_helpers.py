"""
Helpers of the posture tests: import path, a temporary root (config, firmware status, SSH host keys, report),
a fake command runner (sysctl, sockstat, pfctl) and a fake AI provider (nothing leaves the machine).
Only fictional data and documentation addresses.
"""

import base64
import datetime
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
sys.dont_write_bytecode = True

from posture.common import Paths  # noqa: E402

NOW = 1793000000

SYSCTL_GOOD = {
    'net.inet.tcp.blackhole': '2', 'net.inet.udp.blackhole': '1', 'net.inet.ip.random_id': '1',
    'net.inet.ip.redirect': '0', 'net.inet.ip.sourceroute': '0', 'net.inet.ip.accept_sourceroute': '0',
    'net.inet.tcp.drop_synfin': '1', 'net.inet6.ip6.redirect': '0', 'net.inet.icmp.drop_redirect': '1',
    'vm.pmap.pti': '1', 'hw.ibrs_disable': '0', 'security.bsd.see_other_uids': '0', 'kern.randompid': '1',
}
SOCKSTAT_GOOD = ('root sshd 100 3 tcp4 192.0.2.1:22 *:*\n'
                 'root lighttpd 101 4 tcp4 192.0.2.1:443 *:*\n'
                 '?? ?? ?? ?? udp4 *:51820 *:*\n'
                 'root suricata 102 5 div4 *:8000 *:*\n')
SOCKSTAT_WEAK = SOCKSTAT_GOOD + 'root chronyd 103 6 udp4 *:123 *:*\nroot snmpd 104 7 udp4 *:161 *:*\n'


class FakeRunner:
    def __init__(self, sysctl=None, sockstat=SOCKSTAT_GOOD, states=(500, 100000), broken=()):
        self.sysctl = dict(SYSCTL_GOOD if sysctl is None else sysctl)
        self.sockstat = sockstat
        self.states = states
        self.broken = broken
        self.calls = []

    def __call__(self, argv, timeout=10):
        self.calls.append(argv)
        name = os.path.basename(argv[0])
        if name in self.broken:
            return None
        if name == 'sysctl':
            return ''.join('%s=%s\n' % (k, self.sysctl[k]) for k in argv[2:] if k in self.sysctl)
        if name == 'sockstat':
            return self.sockstat
        if name == 'pfctl' and argv[1] == '-sm':
            return 'states        hard limit %d\nsrc-nodes     hard limit 1000\n' % self.states[1]
        if name == 'pfctl' and argv[1] == '-si':
            return 'State Table                          Total             Rate\n  current entries %d\n' % self.states[0]
        return None


def make_cert(days_valid, cn='fw.example.test', key_size=2048, issuer_cn=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    start = datetime.datetime.fromtimestamp(NOW - 86400 * 30, datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(1000).not_valid_before(start)
            .not_valid_after(datetime.datetime.fromtimestamp(NOW + 86400 * days_valid, datetime.timezone.utc))
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return base64.b64encode(pem).decode()


ED25519_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@example'


class Root:
    """ temporary directory laid out like the firewall """

    def __init__(self, fixture, cert_days=200, cert_issuer='Example Trusted CA', firmware=None, report=None,
                 hostkeys=(('ssh_host_ed25519_key.pub', ED25519_KEY),)):
        self.dir = tempfile.mkdtemp(prefix='pa-posture-')
        os.makedirs(os.path.join(self.dir, 'db'))
        os.makedirs(os.path.join(self.dir, 'sshd'))
        with open(os.path.join(HERE, 'fixtures', fixture)) as handle:
            text = handle.read()
        text = text.replace('@@CRT@@', make_cert(cert_days, issuer_cn=cert_issuer) if '@@CRT@@' in text else '')
        text = text.replace('@@KEY@@', base64.b64encode(ED25519_KEY.encode()).decode())
        with open(os.path.join(self.dir, 'config.xml'), 'w') as handle:
            handle.write(text)
        for name, line in hostkeys:
            with open(os.path.join(self.dir, 'sshd', name), 'w') as handle:
                handle.write(line + '\n')
        fw_path = os.path.join(self.dir, 'pkg_upgrade.json')
        if firmware is not False:
            with open(fw_path, 'w') as handle:
                json.dump(firmware or {'product_version': '26.7.8', 'upgrade_packages': [], 'needs_reboot': '0',
                                       'connection': 'ok', 'repository': 'ok', 'last_check': 'today'}, handle)
            os.utime(fw_path, (NOW - 3600, NOW - 3600))
        if report is not None:
            with open(os.path.join(self.dir, 'last.json'), 'w') as handle:
                json.dump(report, handle)
        self.paths = Paths(config=os.path.join(self.dir, 'config.xml'), db_dir=os.path.join(self.dir, 'db'),
                           firmware=fw_path, sshd_dir=os.path.join(self.dir, 'sshd'),
                           report=os.path.join(self.dir, 'last.json'),
                           unbound_conf_dir=os.path.join(self.dir, 'unbound'),
                           audit_log=os.path.join(self.dir, 'ai.log'))

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class FakeProvider:
    """ stands in for the AI provider: records the messages, answers a fixed text """

    def __init__(self, answer='**Fine.** Nothing to add.'):
        self.answer = answer
        self.messages = []

    def endpoint(self):
        return 'fake://test'

    def chat(self, messages, stream=False, on_chunk=None):
        from ai.providers.base import GenerateResult
        self.messages.append(messages)
        return GenerateResult(self.answer, 'fake-model', 12)


def fake_assistant(enabled=True, anonymize=True):
    from ai import AIConfig, Assistant, AuditLog
    config = AIConfig(enabled=enabled, provider='ollama' if enabled else 'none', anonymize=anonymize,
                      options={'model': 'fake-model'})
    provider = FakeProvider()
    audit = AuditLog(os.path.join(tempfile.mkdtemp(prefix='pa-audit-'), 'ai.log'))
    return Assistant(config, app='test', audit=audit, provider=provider), provider


REPORT_WEAK = {
    'generated': '2026-10-26T00:00:00+00:00',
    'findings': [
        {'id': 'aaaa000000000001', 'type': 'permissive', 'severity': 'high',
         'rules': [{'uuid': '11111111-1111-4111-8111-111111111111', 'summary': 'pass in quick on lan from any to any'}],
         'evidence': {'reasons': ['any_any']}},
        {'id': 'aaaa000000000002', 'type': 'wan_exposed', 'severity': 'high',
         'rules': [{'uuid': '33333333-3333-4333-8333-333333333333', 'summary': 'pass in on wan to wanip port 22'}],
         'evidence': {'admin_ports': [22]}},
    ],
}
REPORT_CLEAN = {'generated': '2026-10-26T00:00:00+00:00', 'findings': []}
