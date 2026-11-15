"""
Fixtures and fakes for the exposure tests: synthetic sockstat / procstat / pkg outputs, a fake command runner,
a fake HTTP getter (no network) and config.xml files written to a temporary directory.

Only documentation addresses are used (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
for path in (TESTS,):
    if path not in sys.path:
        sys.path.insert(0, path)

import helpers  # noqa: E402  (tests/helpers.py: synthetic config builder, adds the scripts dir to sys.path)
from helpers import alias, rule  # noqa: E402,F401

from exposure import adapter, common, feeds, inventory, reach, report, vulns  # noqa: E402,F401

WG_XML = ('<wireguard><server><servers><server uuid="wg-1"><enabled>1</enabled><name>wg</name>'
          '<port>51820</port></server></servers></server></wireguard>')

SOCKSTAT = """USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
root     lighttpd   100   5   tcp4   *:8443                *:*
root     lighttpd   100   6   tcp4   *:80                  *:*
root     sshd       200   3   tcp4   *:22                  *:*
root     sshd       200   4   tcp6   *:22                  *:*
unbound  unbound    300   4   udp4   192.0.2.1:53          *:*
unbound  unbound    300   5   tcp4   127.0.0.1:953         *:*
unbound  unbound    300   6   tcp6   [::1]:953             *:*
root     kea-dhcp4  400   7   udp4   192.0.2.1:67          *:*
??       ??         ??    ??  udp4   *:51820               *:*
??       ??         ??    ??  udp6   *:51820               *:*
nobody   mystery    500   3   tcp4   *:9999                *:*
"""

SOCKSTAT_LOCAL_ONLY = """USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
root     lighttpd   100   5   tcp4   192.0.2.1:8443        *:*
root     sshd       200   3   tcp4   192.0.2.1:22          *:*
unbound  unbound    300   5   tcp4   127.0.0.1:953         *:*
"""

PROCSTAT = """  PID COMM                OSREL PATH
  100 lighttpd          1501000 /usr/local/sbin/lighttpd
  200 sshd              1501000 /usr/local/sbin/sshd
  300 unbound           1501000 /usr/local/sbin/unbound
  400 kea-dhcp4         1501000 /usr/local/sbin/kea-dhcp4
  500 mystery           1501000 /usr/home/someone/mystery
"""

PKG_WHICH = """/usr/local/sbin/lighttpd was installed by package lighttpd-1.4.85
/usr/local/sbin/sshd was installed by package openssh-portable-10.0.p1,1
/usr/local/sbin/unbound was installed by package unbound-1.26.2
/usr/local/sbin/kea-dhcp4 was installed by package kea-3.0.1
/usr/home/someone/mystery was not found in the database
"""

PKG_QUERY = '\n'.join('\t'.join(x) for x in [
    ('lighttpd', '1.4.85', 'www/lighttpd', '1', 'Secure, fast, compliant, and flexible web server'),
    ('openssh-portable', '10.0.p1,1', 'security/openssh-portable', '1', 'The portable version of OpenSSH'),
    ('php85', '8.5.12_2', 'lang/php85', '1', 'PHP Scripting Language'),
    ('php85-sqlite3', '8.5.12_2', 'databases/php85-sqlite3', '1', 'The sqlite3 shared extension for php'),
    ('python313', '3.13.16', 'lang/python313', '1', 'Interpreted object-oriented programming language'),
    ('sqlite3', '3.53.4,1', 'databases/sqlite3', '1', 'SQLite database library'),
    ('unbound', '1.26.2', 'dns/unbound', '1', 'Validating, recursive, and caching DNS resolver'),
]) + '\n'

AUDIT_VULN = {
    'pkg_count': 3,
    'packages': {
        'openssh-portable': {'version': '10.0.p1,1', 'issue_count': 1, 'issues': [
            {'Affected versions': ['< 10.1.p1,1'], 'description': 'OpenSSH -- pre-auth memory corruption',
             'cve': ['CVE-2026-0001'],
             'url': 'https://vuxml.FreeBSD.org/freebsd/11111111-2222-3333-4444-555555555555.html'}],
            'reverse dependencies': []},
        'sqlite3': {'version': '3.53.4,1', 'issue_count': 1, 'issues': [
            {'Affected versions': ['< 3.53.5,1'], 'description': 'sqlite3 -- multiple vulnerabilities',
             'cve': ['CVE-2026-0002', 'CVE-2026-0003'],
             'url': 'https://vuxml.FreeBSD.org/freebsd/22222222-2222-3333-4444-555555555555.html'}],
            'reverse dependencies': ['php85-sqlite3', 'opnsense']},
        'python313': {'version': '3.13.16', 'issue_count': 1, 'issues': [
            {'Affected versions': ['>= 0'], 'description': 'Python -- poplib command injection',
             'cve': ['CVE-2025-15367'],
             'url': 'https://vuxml.FreeBSD.org/freebsd/6d3488ae-2e0f-11f1-88c7-00a098b42aeb.html'}],
            'reverse dependencies': ['opnsense', 'py313-requests', 'unbound']},
    },
}
AUDIT_CLEAN = {'pkg_count': 0, 'packages': {}}

AUDIT_TEXT = """python313-3.13.16 is vulnerable:
  Python -- poplib module, when passed a user-controlled command, can have additional commands injected
  CVE: CVE-2025-15367
  WWW: https://vuxml.FreeBSD.org/freebsd/6d3488ae-2e0f-11f1-88c7-00a098b42aeb.html

sqlite3-3.53.4,1 is vulnerable:
  sqlite3 -- multiple vulnerabilities
  CVE: CVE-2026-0002
  CVE: CVE-2026-0003
  WWW: https://vuxml.FreeBSD.org/freebsd/22222222-2222-3333-4444-555555555555.html

2 problem(s) in 2 package(s) found.
"""

PKG_VERSION = """openssh-portable-10.0.p1,1          <   needs updating (remote has 10.1.p1,1)
beep-1.0_2                          <   needs updating (remote has 1.0_3)
"""

IFCONFIG = {
    'vtnet0': {'flags': ['up'], 'ipv4': [{'ipaddr': '198.51.100.2', 'subnetbits': 24}],
               'ipv6': [{'ipaddr': 'fe80::1%vtnet0'}]},
    'vtnet1': {'flags': ['up'], 'ipv4': [{'ipaddr': '192.0.2.1', 'subnetbits': 25}],
               'ipv6': [{'ipaddr': '2001:db8:10::1'}]},
}

# ------------------------------------------------------------------ feeds

KEV_DOC = {'vulnerabilities': [
    {'cveID': 'CVE-2026-0001', 'vendorProject': 'OpenBSD', 'product': 'OpenSSH', 'vulnerabilityName': 'sshd RCE',
     'dateAdded': '2026-10-01', 'dueDate': '2026-10-22', 'requiredAction': 'Apply updates per vendor instructions.',
     'knownRansomwareCampaignUse': 'Known'},
    {'cveID': 'CVE-2020-9999', 'dateAdded': '2020-01-01'}]}


def epss_doc(cves):
    return {'status': 'OK', 'data': [{'cve': c, 'epss': '0.9%d' % (i % 10), 'percentile': '0.99',
                                      'date': '2026-11-07'} for i, c in enumerate(cves)]}


def nvd_doc(cve, score=9.8, version='3.1'):
    return {'vulnerabilities': [{'cve': {
        'id': cve, 'published': '2026-09-01T00:00:00.000',
        'descriptions': [{'lang': 'en', 'value': 'NVD description of %s' % cve}],
        'metrics': {'cvssMetricV31': [{'type': 'Primary', 'cvssData': {
            'version': version, 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'baseScore': score, 'baseSeverity': 'CRITICAL' if score >= 9 else 'HIGH'}}]},
        'references': [{'url': 'https://example.org/%s' % cve}],
        'weaknesses': [{'description': [{'lang': 'en', 'value': 'CWE-787'}]}]}}]}


def osv_doc(cve, vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'):
    return {'id': cve, 'summary': 'OSV summary of %s' % cve, 'aliases': [],
            'severity': [{'type': 'CVSS_V3', 'score': vector}], 'references': [{'url': 'https://osv.dev/%s' % cve}]}


GHSA_DOC = [
    {'ghsa_id': 'GHSA-aaaa-bbbb-cccc', 'cve_id': None, 'severity': 'high', 'summary': 'Authenticated command injection',
     'html_url': 'https://github.com/opnsense/core/security/advisories/GHSA-aaaa-bbbb-cccc',
     'published_at': '2026-10-28T09:16:24Z', 'cvss': {'score': 7.2},
     'vulnerabilities': [{'package': {'name': 'opnsense'}, 'vulnerable_version_range': '<= 26.7.7, <= 26.4.2p5',
                          'patched_versions': '26.7.8, 26.10'}]},
    {'ghsa_id': 'GHSA-dddd-eeee-ffff', 'cve_id': 'CVE-2026-0100', 'severity': 'low', 'summary': 'old XSS',
     'html_url': 'https://github.com/opnsense/core/security/advisories/GHSA-dddd-eeee-ffff',
     'published_at': '2026-01-01T00:00:00Z', 'cvss': {'score': 3.1},
     'vulnerabilities': [{'package': {'name': ''}, 'vulnerable_version_range': '<= 26.1.2',
                          'patched_versions': '26.1.3'}]},
]


class FakeHTTP(object):
    """ url -> JSON document, from the feed templates; records every request """

    def __init__(self, fail=(), not_found=(), ghsa=None):
        self.requests = []
        self.fail = set(fail)
        self.not_found = set(not_found)
        self.ghsa = GHSA_DOC if ghsa is None else ghsa

    def __call__(self, url, timeout=10):
        self.requests.append(url)
        if any(f in url for f in self.fail):
            raise feeds.FeedError('HTTP 503')
        if any(n in url for n in self.not_found):
            raise feeds.NotFound('not found')
        if 'known_exploited' in url:
            return KEV_DOC
        if 'api.first.org' in url:
            return epss_doc(url.split('cve=')[1].split(','))
        if 'services.nvd.nist.gov' in url:
            return nvd_doc(url.split('cveId=')[1])
        if 'api.osv.dev' in url:
            return osv_doc(url.rsplit('/', 1)[1])
        if 'security-advisories' in url:
            return self.ghsa
        raise feeds.FeedError('unexpected url %s' % url)


class FakeRunner(object):
    """ answers commands from fixtures; records calls """

    def __init__(self, sockstat=SOCKSTAT, audit=AUDIT_VULN, audit_text=None, version='26.7.5', privileged=True,
                 pkg_version=PKG_VERSION, ifconfig=IFCONFIG):
        self.sockstat = sockstat
        self.audit = audit
        self.audit_text = audit_text
        self.version = version
        self.privileged = privileged
        self.pkg_version = pkg_version
        self.ifconfig = ifconfig
        self.calls = []

    def __call__(self, argv, timeout=None):
        argv = list(argv)
        self.calls.append(argv)
        cmd = argv[0]
        if cmd == 'opnsense-version':
            if argv[1] == '-v':
                return 0, self.version + '\n', ''
            return 0, json.dumps({'CORE_ABI': '26.7', 'CORE_ARCH': 'amd64', 'CORE_VERSION': self.version,
                                  'CORE_NAME': 'opnsense', 'product_email': 'x'}), ''
        if cmd == 'freebsd-version':
            return 0, '15.1-RELEASE-p6\n15.1-RELEASE-p6\n', ''
        if cmd == 'sockstat':
            return 0, self.sockstat, ''
        if cmd == 'procstat':
            return 0, PROCSTAT, ''
        if cmd == 'pkg' and argv[1] == 'which':
            return 1, PKG_WHICH, ''
        if cmd == 'pkg' and argv[1] == 'query':
            return 0, PKG_QUERY, ''
        if cmd == 'pkg' and argv[1] == 'audit':
            if '--raw=json-compact' in argv:
                if self.audit is None:
                    return 1, '', 'pkg: vulnxml file /var/db/pkg/vuln.xml does not exist'
                return (1 if self.audit['packages'] else 0), json.dumps(self.audit), ''
            if self.audit_text is not None:
                return 1, self.audit_text, ''
            return 1, '', 'pkg: vulnxml file /var/db/pkg/vuln.xml does not exist'
        if cmd == 'pkg' and argv[1] == 'version':
            return 0, self.pkg_version, ''
        if cmd.endswith('configctl'):
            if self.ifconfig is None:
                return None, '', 'no configd'
            return 0, json.dumps(self.ifconfig), ''
        return None, '', 'unknown command %s' % cmd


WAN_RULES = [
    rule('wan ssh open', interface='wan', protocol='TCP', destination_net='(self)', destination_port='22'),
    rule('wan wireguard', interface='wan', protocol='UDP', destination_net='wanip', destination_port='51820'),
    rule('wan gui from geoip', interface='wan', protocol='TCP', source_net='countries',
         destination_net='any', destination_port='8443'),
    rule('wan block 9999', interface='wan', action='block', protocol='TCP', destination_port='9999'),
    rule('wan pass 9999', interface='wan', protocol='TCP', destination_port='9999'),
    rule('lan any', interface='lan', source_net='lan'),
]
WAN_ALIASES = [alias('countries', 'geoip', 'BR')]
CLOSED_RULES = [rule('lan any closed', interface='lan', source_net='lan')]


class ExposureCase(unittest.TestCase):
    """ temporary directory for config.xml, cache and output (TMPDIR decides where) """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-exposure-test-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cache = os.path.join(self.tmp, 'cache')
        # never look at the host's VuXML database or Suricata rules
        for name, value in (('VULN_XML', os.path.join(self.tmp, 'vuln.xml')),
                            ('SURICATA_RULES', os.path.join(self.tmp, 'rules')),
                            ('DB_DIR', os.path.join(self.tmp, 'db'))):
            patcher = mock.patch.object(common, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write_config(self, rules=WAN_RULES, aliases=WAN_ALIASES, wireguard=True, feeds_xml=''):
        data = helpers.build_config(rules, aliases).getvalue().decode('utf-8')
        inner = (WG_XML if wireguard else '') + (
            '<policyanalyzer><exposure><feeds>%s</feeds></exposure></policyanalyzer>' % feeds_xml if feeds_xml else '')
        data = data.replace('<OPNsense>', '<OPNsense>' + inner, 1)
        path = os.path.join(self.tmp, 'config.xml')
        with open(path, 'w') as handle:
            handle.write(data)
        return path

    def fetcher(self, http=None, online=True, write_cache=True, clock=None):
        self.sleeps = []
        kwargs = {}
        if clock is not None:
            kwargs['clock'] = clock
        return feeds.Fetcher(cache_dir=self.cache, online=online, write_cache=write_cache, get=http or FakeHTTP(),
                             sleep=self.sleeps.append, **kwargs)

    def feed_list(self, config_path=None, file_path=None):
        items, errors = feeds.registry(config_path or os.path.join(self.tmp, 'none.xml'),
                                       file_path or os.path.join(self.tmp, 'none.json'))
        self.assertEqual(errors, [])
        return items

    def report(self, runner=None, config=None, tokens=('no-write',), http=None, online=False, **kw):
        config = config or self.write_config()
        fetch = self.fetcher(http=http, online=online)
        with _patched_registry(self):
            return adapter.probe_exposure_report(list(tokens), runner=runner or FakeRunner(), config_path=config,
                                                 fetcher=fetch, **kw)


class _patched_registry(object):
    """ keep the tests away from /var/db/policyanalyzer/feeds.json """

    def __init__(self, case):
        self.case = case

    def __enter__(self):
        self.orig = feeds.registry
        none = os.path.join(self.case.tmp, 'none.json')
        feeds.registry = lambda config_path=None, file_path=None: self.orig(config_path, file_path or none)
        vulns.feedmod.registry = feeds.registry
        return self

    def __exit__(self, *exc):
        feeds.registry = self.orig
        vulns.feedmod.registry = self.orig
        return False


def by_type(doc, ftype):
    return [f for f in doc['findings'] if f['type'] == ftype]


def service(doc_or_list, name, port=None):
    items = doc_or_list['services'] if isinstance(doc_or_list, dict) else doc_or_list
    for item in items:
        if item['service'] == name and (port is None or item['port'] == port):
            return item
    raise AssertionError('service %s/%s not found in %s' % (name, port, [(s['service'], s['port']) for s in items]))
