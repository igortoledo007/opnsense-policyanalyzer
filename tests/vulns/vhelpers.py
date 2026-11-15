"""
Fixtures of the vulnerability prioritisation tests: a synthetic exposure.json (fictitious CVE ids CVE-2099-*,
documentation addresses only), a KEV cache and a fake AI provider. Every test runs in its own temporary
POLICYANALYZER_DB directory; nothing touches the network or /var/db.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)


def svc(sid, service, label, proto, port, reach, components, package=None, admin=False):
    return {'id': sid, 'service': service, 'label': label, 'kind': service, 'admin': admin, 'proto': proto,
            'port': port, 'internet_reachable': reach, 'components': components, 'package_name': package or service,
            'scope': 'address', 'needs_review': None, 'rules': []}


def cve(cid, cvss=None, kev=False, epss=None, summary='fictitious vulnerability'):
    return {'id': cid, 'cvss': cvss, 'cvss_vector': None, 'severity': None, 'kev': kev, 'epss': epss,
            'epss_percentile': None, 'summary': summary, 'refs': ['https://example.org/%s' % cid], 'sources': ['vuxml'],
            'provenance': {}}


def pkg(name, version, cves, reverse_deps=(), fixed_in=()):
    return {'name': name, 'version': version, 'cves': cves, 'reverse_deps': list(reverse_deps),
            'fixed_in': list(fixed_in), 'fix_available': bool(fixed_in), 'advisories': []}


def exposure_doc():
    services = [
        svc('aaaa000000000001', 'openvpn', 'OpenVPN server', 'udp', 1194, 'yes', ['openvpn', 'openssl']),
        svc('aaaa000000000002', 'unbound', 'Unbound DNS', 'udp', 53, 'no', ['unbound']),
        svc('aaaa000000000003', 'kea', 'Kea DHCPv4', 'udp', 67, 'no', ['kea']),
        svc('aaaa000000000004', 'webgui', 'Web GUI (lighttpd)', 'tcp', 443, 'maybe', ['lighttpd'], admin=True),
    ]
    packages = [
        pkg('openvpn', '2.6.0', [cve('CVE-2099-1000', cvss=6.5)], fixed_in=['2.6.1']),
        pkg('openssl', '3.0.0', [cve('CVE-2099-2000', cvss=7.5)]),
        pkg('unbound', '1.20.0', [cve('CVE-2099-3000', cvss=8.1)]),
        pkg('python313', '3.13.16', [cve('CVE-2099-4000', cvss=7.2)], reverse_deps=['kea', 'syslog-ng']),
        pkg('sqlite3', '3.53.4,1', [cve('CVE-2099-5000', cvss=5.0)]),
        pkg('lighttpd', '1.4.0', [cve('CVE-2099-6000', cvss=5.3, epss=0.62)]),
    ]
    findings = [{'id': 'f1', 'type': 'needs_review', 'severity': 'info', 'title': 'Unknown listening service',
                 'detail': 'A socket on tcp/9999 is not mapped to a known service', 'evidence': {
                     'reason': 'unknown process', 'process': 'mystery', 'binary': '/usr/home/x/mystery',
                     'port': 9999, 'proto': 'tcp'}},
                {'id': 'f2', 'type': 'exposed_vulnerable_service', 'severity': 'high', 'title': 'x', 'detail': 'x',
                 'evidence': {'suricata': {'CVE-2099-1000': [{'sid': 2099001, 'msg': 'ET EXPLOIT test',
                                                              'file': 'emerging-exploit.rules', 'enabled': False}]}}}]
    return {'version': 1, 'kind': 'exposure', 'generated': '2026-11-08T03:00:00+00:00',
            'summary': {'posture': 'exposed'}, 'services': services, 'findings': findings,
            'vulns': {'packages': packages, 'cves_total': 6, 'kev_total': 0}}


KEV = {'version': 1, 'fetched': '2026-11-08T01:00:00Z', 'source': 'https://example.invalid/kev.json',
       'catalog_version': '2026.11.07', 'count': 2,
       'items': {'CVE-2099-1000': {'vendor': 'OpenVPN', 'product': 'OpenVPN', 'name': 'OpenVPN test flaw',
                                   'date_added': '2026-11-01', 'due': '2026-11-22', 'action': 'Apply updates.',
                                   'ransomware': False, 'description': 'fictitious'},
                 'CVE-2099-7777': {'vendor': 'Hikvision', 'product': 'Cameras', 'name': 'camera flaw',
                                   'date_added': '2026-01-01', 'due': None, 'action': None, 'ransomware': True,
                                   'description': 'fictitious'}}}


class FakeProvider(object):
    def __init__(self, text):
        self.text = text
        self.calls = []

    def endpoint(self):
        return 'fake://provider'

    def chat(self, messages, stream=False, on_chunk=None):
        from ai.providers.base import GenerateResult
        self.calls.append(messages)
        return GenerateResult(self.text, 'fake-model', 5)


def assistant(text, enabled=True, tmp=None):
    from ai import AIConfig, Assistant, AuditLog
    config = AIConfig(enabled=enabled, provider='ollama', options={'model': 'fake-model'})
    return Assistant(config, app='test', audit=AuditLog(os.path.join(tmp or tempfile.gettempdir(), 'ai.log')),
                     provider=FakeProvider(text))


class VulnsCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-vulns-')
        self.env = {k: os.environ.get(k) for k in ('POLICYANALYZER_DB', 'POLICYANALYZER_EXPOSURE',
                                                    'POLICYANALYZER_UNDO')}
        os.environ['POLICYANALYZER_DB'] = self.tmp
        os.environ.pop('POLICYANALYZER_EXPOSURE', None)
        from ai import journal
        self._undo = journal.UNDO_DIR
        journal.UNDO_DIR = os.path.join(self.tmp, 'undo')
        self.write('exposure.json', exposure_doc())

    def tearDown(self):
        from ai import journal
        journal.UNDO_DIR = self._undo
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, data):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as handle:
            json.dump(data, handle)
        return path
