"""
inventory: sockstat / procstat / pkg parsing, service mapping, interfaces, partial results without root.
"""

import unittest

from exposure_helpers import (ExposureCase, FakeRunner, SOCKSTAT_LOCAL_ONLY, adapter, inventory, service)

from exposure import services


class TestParsers(unittest.TestCase):
    def test_endpoints(self):
        self.assertEqual(inventory.parse_endpoint('*:22'), ('*', 22))
        self.assertEqual(inventory.parse_endpoint('192.0.2.1:443'), ('192.0.2.1', 443))
        self.assertEqual(inventory.parse_endpoint('[::1]:953'), ('::1', 953))
        self.assertEqual(inventory.parse_endpoint('[fe80::1%lo0]:80'), ('fe80::1%lo0', 80))
        self.assertEqual(inventory.parse_endpoint('*:*'), (None, None))

    def test_scopes(self):
        self.assertEqual(inventory.bind_scope('*'), 'any')
        self.assertEqual(inventory.bind_scope('::'), 'any')
        self.assertEqual(inventory.bind_scope('127.0.0.1'), 'loopback')
        self.assertEqual(inventory.bind_scope('fe80::1%lo0'), 'loopback')
        self.assertEqual(inventory.bind_scope('192.0.2.1'), 'address')

    def test_sockstat(self):
        socks, reason = inventory.sockets(FakeRunner())
        self.assertIsNone(reason)
        kernel = [s for s in socks if s['kernel']]
        self.assertEqual(len(kernel), 2)
        self.assertTrue(all(s['process'] is None and s['pid'] is None for s in kernel))
        ssh6 = [s for s in socks if s['process'] == 'sshd' and s['family'] == 6]
        self.assertEqual(ssh6[0]['scope'], 'any')

    def test_component_match(self):
        self.assertTrue(services.component_match('php85-sqlite3', ['php']))
        self.assertTrue(services.component_match('php85', ['php']))
        self.assertFalse(services.component_match('pkgconf', ['pkg']))
        self.assertTrue(services.component_match('FreeBSD-runtime', ['FreeBSD-']))
        self.assertFalse(services.component_match('phpmyadmin', ['php']))


class TestInventory(ExposureCase):
    def test_full_inventory(self):
        inv = adapter.probe_inventory([], runner=FakeRunner(), config_path=self.write_config())
        self.assertEqual(inv['status'], 'ok')
        self.assertEqual(inv['opnsense']['version'], '26.7.5')
        self.assertNotIn('product_email', inv['opnsense']['details'])
        self.assertEqual(inv['freebsd']['kernel'], '15.1-RELEASE-p6')
        self.assertEqual(inv['packages']['count'], 7)
        self.assertTrue(inv['services_complete'])
        gui = service(inv, 'webgui', 8443)
        self.assertTrue(gui['admin'])
        self.assertEqual(gui['package'], 'lighttpd-1.4.85')
        self.assertEqual(service(inv, 'webgui', 80)['label'], 'Web GUI redirect (lighttpd)')
        ssh = service(inv, 'ssh', 22)
        self.assertEqual(ssh['package_name'], 'openssh-portable')
        self.assertEqual(sorted(ssh['families']), [4, 6])
        self.assertEqual(ssh['scope'], 'any')
        ctl = service(inv, 'unbound-control', 953)
        self.assertTrue(ctl['admin'])
        self.assertEqual(ctl['scope'], 'loopback')
        self.assertEqual(service(inv, 'wireguard', 51820)['kind'], 'vpn_wireguard')
        unknown = service(inv, 'unknown:mystery', 9999)
        self.assertIn('unknown process', unknown['needs_review'])
        self.assertIsNone(unknown['package'])
        wan = [i for i in inv['interfaces'] if i['name'] == 'wan'][0]
        self.assertTrue(wan['wan'])
        self.assertEqual(wan['ipv4'], ['198.51.100.2'])
        self.assertIn('192.0.2.1', inv['local_addresses'])
        self.assertEqual(inv['admin_ports'], {'22': 'ssh', '8443': 'webgui'})

    def test_partial_without_root(self):
        inv = adapter.probe_inventory([], runner=FakeRunner(privileged=False), config_path=self.write_config())
        self.assertFalse(inv['services_complete'])
        self.assertTrue(any('not running as root' in x for x in inv['limitations']))

    def test_unknown_kernel_socket(self):
        inv = adapter.probe_inventory([], runner=FakeRunner(), config_path=self.write_config(wireguard=False))
        self.assertIn('kernel socket', service(inv, 'unknown:kernel', 51820)['needs_review'])

    def test_static_addresses_without_configd(self):
        inv = adapter.probe_inventory([], runner=FakeRunner(ifconfig=None, sockstat=SOCKSTAT_LOCAL_ONLY),
                                      config_path=self.write_config())
        wan = [i for i in inv['interfaces'] if i['name'] == 'wan'][0]
        self.assertEqual(wan['ipv4'], ['198.51.100.2'])          # from config.xml
        self.assertTrue(any('configctl' in x for x in inv['limitations']))

    def test_unreadable_config(self):
        bad = self.tmp + '/bad.xml'
        with open(bad, 'w') as handle:
            handle.write('<opnsense>')
        res = adapter.STATUS_PROBES['inventory']([], runner=FakeRunner(), config_path=bad)
        self.assertEqual(res['status'], 'error')


if __name__ == '__main__':
    unittest.main()
