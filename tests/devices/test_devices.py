"""
Passive device inventory: merge of Host discovery + Kea + ARP + DNS, manufacturer (OUI), type heuristic, risk,
permanent history, change actions (known / type / name / OUI download) with revert, Explain device (fake AI).
Run: cd tests/devices && TMPDIR=<scratch> /usr/bin/python3 -m unittest discover -s . -v
"""

import base64
import os
import sys
import unittest

import dhelpers
from dhelpers import NOW, DevicesCase

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vulns'))
import vhelpers  # noqa: E402  (fake AI provider)

from devices import classify, common, explain, inventory, oui, risk, view  # noqa: E402
from ai import changes  # noqa: E402


class ScanTest(DevicesCase):
    def scan(self, now=NOW):
        return inventory.scan(self.run_, now=now)

    def devices(self):
        return {d['mac']: d for d in view.listing(now=NOW)['rows']}

    def test_merge_and_classify(self):
        result = self.scan()
        self.assertEqual(result['devices'], 5)                       # the WAN neighbour is not inventoried
        d = self.devices()
        pc = d['02:00:00:00:00:01']
        self.assertEqual(pc['hostname'], 'desktop-igor')
        self.assertEqual(pc['hostname_source'], 'dhcp reservation')
        self.assertEqual(pc['type'], 'pc')
        cam = d['a4:14:37:00:00:02']
        self.assertIn('Hikvision', cam['vendor'])
        self.assertEqual(cam['type'], 'camera')
        self.assertEqual(cam['iface_descr'], 'IOT')
        self.assertEqual(cam['risk'], 'high')                         # port forward from the WAN
        self.assertTrue(any(r['code'] == 'port_forward' for r in cam['risk_reasons']))
        printer = d['3c:2a:f4:00:00:03']
        self.assertEqual(printer['type'], 'printer')
        self.assertEqual(printer['hostname'], 'printer.example.test')  # Unbound host override
        phone = d['ba:aa:00:00:00:04']
        self.assertTrue(phone['randomized'])
        self.assertEqual(phone['type'], 'phone')                      # Galaxy hostname + random MAC
        self.assertTrue(phone['present'])
        rpi = d['b8:27:eb:00:00:05']
        self.assertEqual(rpi['hostname'], 'rpi-garagem.example.test')  # reverse DNS at 127.0.0.1
        self.assertEqual(sorted(rpi['ip4'] + rpi['ip6']), ['192.0.2.50', '2001:db8::50'])
        self.assertTrue(all(c[-1] == '@127.0.0.1' for c in self.run_.calls if c[0] == 'drill'))

    def test_kev_vendor_and_new(self):
        self.write_kev()
        self.scan()
        cam = self.devices()['a4:14:37:00:00:02']
        codes = {r['code'] for r in cam['risk_reasons']}
        self.assertIn('vendor_kev', codes)
        self.assertIn('new_device', codes)
        pc = self.devices()['02:00:00:00:00:01']
        self.assertNotIn('new_device', {r['code'] for r in pc['risk_reasons']})

    def test_history_is_permanent(self):
        self.scan()
        later = NOW + 3600
        with open(os.path.join(self.root, 'var/db/kea/kea-leases4.csv'), 'a') as h:
            h.write('192.0.2.41,ba:aa:00:00:00:04,,3600,1794120000,1,0,0,Galaxy-S24,0,,0\n')
        import sqlite3
        hw = sqlite3.connect(os.path.join(self.root, 'var/db/hostwatch/hosts.db'))
        hw.execute("UPDATE hosts SET ip_address = '192.0.2.41', last_seen = '2026-11-08 04:00:00' "
                   "WHERE ether_address = 'ba:aa:00:00:00:04'")
        hw.commit()
        hw.close()
        inventory.scan(self.run_, now=later)
        phone = self.devices()['ba:aa:00:00:00:04']
        detail = view.device(phone['id'], now=later)['device']
        kinds = [h['kind'] for h in detail['history']]
        self.assertIn('new', kinds)
        self.assertIn('ip', kinds)
        self.assertEqual({a['ip'] for a in detail['addresses']}, {'192.0.2.40', '192.0.2.41'})

    def test_summary(self):
        self.scan()
        s = view.summary(now=NOW)
        self.assertEqual(s['total'], 5)
        self.assertEqual(s['by_risk']['high'], 1)
        self.assertEqual(s['top_risk'][0]['type'], 'camera')
        self.assertGreaterEqual(s['new_7d'], 3)

    def test_filters(self):
        self.scan()
        rows = view.listing('type=camera', now=NOW)['rows']
        self.assertEqual([r['mac'] for r in rows], ['a4:14:37:00:00:02'])
        self.assertEqual(view.listing('search=galaxy', now=NOW)['total'], 1)


class ActionsTest(DevicesCase):
    def setUp(self):
        super().setUp()
        inventory.scan(self.run_, now=NOW)
        self.rows = {d['mac']: d for d in view.listing(now=NOW)['rows']}

    def test_mark_known_revert(self):
        cam = self.rows['a4:14:37:00:00:02']
        plan = changes.run('plan', 'devices_mark_known', [str(cam['id']), '1'])
        self.assertEqual(len(plan['steps']), 1)
        res = changes.run('apply', 'devices_mark_known', [str(cam['id']), '1'])
        self.assertTrue(res['done'], res)
        d = view.device(cam['id'])['device']
        self.assertTrue(d['known'])
        self.assertNotIn('new_device', {r['code'] for r in d['risk_reasons']})
        changes.run('apply', 'revert', [res['journal_id']])
        self.assertFalse(view.device(cam['id'])['device']['known'])

    def test_set_type_and_name(self):
        rpi = self.rows['b8:27:eb:00:00:05']
        name = base64.urlsafe_b64encode('Sensor da garagem'.encode()).decode()
        res = changes.run('apply', 'devices_set', [str(rpi['id']), 'iot', name])
        self.assertTrue(res['done'], res)
        d = view.device(rpi['id'])['device']
        self.assertEqual((d['type'], d['type_source'], d['name']), ('iot', 'owner', 'Sensor da garagem'))
        inventory.scan(self.run_, now=NOW + 60)                      # a new scan keeps the owner's choice
        self.assertEqual(view.device(rpi['id'])['device']['type'], 'iot')
        changes.run('apply', 'revert', [res['journal_id']])
        self.assertEqual(view.device(rpi['id'])['device']['type_source'], 'heuristic')
        self.assertEqual(changes.run('plan', 'devices_set', [str(rpi['id']), 'toaster', '-'])['status'], 'error')

    def test_oui_update_fake(self):
        body = ('Registry,Assignment,Organization Name,Organization Address\n' +
                ''.join('MA-L,%06X,Vendor %d,"X"\n' % (i, i) for i in range(12000))).encode()
        from devices import actions
        res = actions.DevicesOuiUpdate().apply(get=lambda url: body)
        self.assertTrue(res['done'])
        self.assertEqual(oui.OUI().source, common.paths()['local_oui'])
        with self.assertRaises(ValueError):
            actions.DevicesOuiUpdate().apply(get=lambda url: b'not,a,registry\n')

    def test_explain(self):
        cam = self.rows['a4:14:37:00:00:02']
        a = vhelpers.assistant('TYPE: camera\nIt is probably an IP camera.', tmp=self.tmp)
        prev = explain.explain(cam['id'], 'pt_BR', 'preview', assistant=a)
        self.assertNotIn('a4:14:37:00:00:02', prev['messages'][1]['content'])
        self.assertNotIn('198.51.100.20', prev['messages'][1]['content'])
        res = explain.explain(cam['id'], 'pt_BR', 'refresh', assistant=a)
        self.assertEqual(res['suggested_type'], 'camera')
        d = view.device(cam['id'])['device']
        self.assertEqual(d['ai']['type'], 'camera')
        self.assertEqual(d['type_source'], 'heuristic')               # a suggestion never sets the type


class UnitTest(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify.classify('Espressif Inc.', 'ESP_12AB34')['type'], 'iot')
        self.assertEqual(classify.classify(None, None)['type'], 'unknown')
        self.assertEqual(classify.classify('Ubiquiti Inc', 'U6-Lite')['type'], 'ap')

    def test_mac(self):
        self.assertEqual(common.norm_mac('A4-14-37-0-0-2'), 'a4:14:37:00:00:02')
        self.assertIsNone(common.norm_mac('00:00:00:00:00:00'))
        self.assertTrue(common.randomized('ba:aa:00:00:00:04'))
        self.assertFalse(common.randomized('a4:14:37:00:00:02'))

    def test_risk_big_vendor_ignored(self):
        r = risk.assess({'vendor': 'Apple, Inc.', 'type': 'phone', 'known': True}, {'apple': 300})
        self.assertEqual(r['level'], 'info')


if __name__ == '__main__':
    unittest.main()
