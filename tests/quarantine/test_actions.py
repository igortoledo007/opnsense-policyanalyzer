"""
change actions through the plugin dispatcher (ai/changes.py + journal): install (plan shows the steps,
the rule position, the cron and the guards; apply; revert), remove (keeps the ledger unless purge_db=yes,
with double confirmation), manual entries (address, CIDR, range, ASN; guards; sizes), batch release /
extend / permanent, never block, pause / resume, settings, ASN database download.
"""

import base64
import gzip
import io
import os
import unittest

from qhelpers import RULE_UUID, T0, QuarantineCase, actions, common, filter_line, lookup

from ai import changes, journal

changes.load_extensions()


def b64(text):
    return base64.b64encode(text.encode()).decode()


class ActionCase(QuarantineCase):
    def setUp(self):
        super().setUp()
        journal.UNDO_DIR = os.path.join(self.tmp, 'undo')

    def plan(self, name, *args):
        return changes.run('plan', name, list(args))

    def apply(self, name, *args):
        return changes.run('apply', name, list(args))

    def revert(self, journal_id, mode='apply'):
        return changes.run(mode, 'revert', [journal_id])


class TestInstall(ActionCase):
    installed = False

    def test_registered(self):
        names = {a['name'] for a in changes.describe()['actions']}
        self.assertTrue({'install_quarantine', 'remove_quarantine', 'quarantine_add', 'quarantine_release',
                         'quarantine_extend', 'quarantine_permanent', 'never_block_add', 'quarantine_pause',
                         'quarantine_resume', 'quarantine_settings', 'update_asn_db'} <= names)

    def test_plan_shows_every_step_and_the_guards(self):
        plan = self.plan('install_quarantine')
        self.assertEqual(plan['status'], 'ok')
        text = '\n'.join('%s | %s | %s' % (s['description'], s['command'], s['effect']) for s in plan['steps'])
        for expected in ('quarantine.db', 'pa_quarantine, type External (advanced)', 'pa_never_block',
                         '"Max Cyber IA": block in quick, log, IPv4+IPv6', 'floating, sequence 99',
                         'before "BL GeoIP" (100)', 'configctl filter reload', 'minutes */5',
                         'configctl cron restart', '90-policyanalyzer-quarantine'):
            self.assertIn(expected, text)
        self.assertTrue(plan['requires_confirmation'])
        info = {block['title']: block['items'] for block in plan['info']}
        guards_text = ' '.join(info['Guards: never put in quarantine'])
        for addr in ('198.51.100.53', '198.51.100.123', '198.51.100.124', '198.51.100.77', '198.51.100.1'):
            self.assertIn(addr, guards_text)
        self.assertIn('"VPN Remote access" (1731)', ' '.join(info['Rule position']))
        self.assertEqual(self.runner.calls and [c for c in self.runner.calls if 'model.php' in ' '.join(c)], [])

    def test_apply_and_revert(self):
        self.log(filter_line(T0 - 30, '203.0.113.5'))
        result = self.apply('install_quarantine')
        self.assertEqual(result['status'], 'ok', result)
        self.assertTrue(result['done'])
        self.assertTrue(os.path.exists(self.ctx.db))
        self.assertEqual(self.rule['sequence'], '99')
        self.assertEqual(self.rule['interfaces'], 'wan,opt6')
        self.assertTrue(self.cron)
        self.assertIn(common.ALIAS, self.aliases)
        self.assertIn(common.NEVER_ALIAS, self.aliases)
        with open(self.ctx.syshook) as handle:
            self.assertIn('quarantine_sync', handle.read())
        cmds = [' '.join(c[1:]) for c in self.runner.calls if c[0].endswith('configctl')]
        self.assertEqual(cmds, ['filter reload', 'cron restart'])
        # starts at the end of the log: what happened before the install is not counted
        self.assertEqual(self.engine().run()['offenses'], 0)
        # idempotent
        self.assertEqual(self.plan('install_quarantine')['steps'], [])
        plan = self.revert(result['journal_id'], 'plan')
        self.assertIn('the ledger', ' '.join(plan['warnings']))
        reverted = self.revert(result['journal_id'])
        self.assertEqual(reverted['status'], 'ok', reverted)
        self.assertIsNone(self.rule)
        self.assertFalse(self.cron)
        self.assertEqual(self.aliases, {})
        self.assertFalse(os.path.exists(self.ctx.syshook))
        self.assertTrue(os.path.exists(self.ctx.db))                # the history stays

    def test_failure_rolls_back(self):
        self.runner.fail.add('configctl')
        result = self.apply('install_quarantine')
        self.assertEqual(result['status'], 'error')
        self.assertIn('rolled back', result['message'])
        self.assertIsNone(self.rule)
        self.assertEqual(self.aliases, {})
        self.assertNotIn('journal_id', result)

    def test_single_wan_warns_about_floating_pass_rules(self):
        from quarantine import fwconfig
        cfg = fwconfig.FirewallConfig(self.ctx.config_xml)
        pos = fwconfig.rule_position(cfg, ['wan'])
        self.assertFalse(pos['floating'])
        self.assertTrue(any('floating pass rule' in w for w in pos['warnings']))


class TestRemove(ActionCase):
    def test_remove_keeps_the_ledger(self):
        self.log(filter_line(T0 - 30, '203.0.113.5'))
        self.engine().run()
        self.aliases[common.NEVER_ALIAS] = '203.0.113.200'
        self.write_config()
        plan = self.plan('remove_quarantine')
        self.assertFalse(plan['requires_double_confirmation'])
        self.assertTrue(any('are kept' in w for w in plan['warnings']))
        self.assertIn('1 entries saved', ' '.join(s['effect'] for s in plan['steps']))
        result = self.apply('remove_quarantine')
        self.assertEqual(result['status'], 'ok', result)
        self.assertTrue(os.path.exists(self.ctx.db))
        self.assertIsNone(self.rule)
        self.assertIsNone(self.runner.table)
        self.assertEqual(self.entry('203.0.113.5')['state'], 'expired')
        # revert = install again, with pa_never_block content and the still valid quarantines
        reverted = self.revert(result['journal_id'])
        self.assertEqual(reverted['status'], 'ok', reverted)
        self.assertEqual(self.aliases[common.NEVER_ALIAS], '203.0.113.200')
        self.assertEqual(self.entry('203.0.113.5')['state'], 'active')
        self.assertEqual(self.runner.table, {'203.0.113.5'})

    def test_purge_needs_double_confirmation(self):
        plan = self.plan('remove_quarantine', 'purge_db=yes')
        self.assertTrue(plan['requires_double_confirmation'])
        self.assertTrue(plan['irreversible'])
        self.assertEqual(plan['risk'], 'high')
        self.assertEqual(self.apply('remove_quarantine', 'purge_db=yes')['status'], 'ok')
        self.assertFalse(os.path.exists(self.ctx.db))
        self.assertEqual(self.plan('remove_quarantine', 'bogus')['status'], 'error')


class TestManual(ActionCase):
    def test_add_address_with_comment_and_revert(self):
        plan = self.plan('quarantine_add', '203.0.113.9', 'l3', b64('from the honeypot'))
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertIn('level 3 (2 days)', plan['steps'][0]['description'])
        result = self.apply('quarantine_add', '203.0.113.9', 'l3', b64('from the honeypot'))
        self.assertEqual(result['status'], 'ok', result)
        entry = self.entry('203.0.113.9')
        self.assertEqual((entry['origin'], entry['level'], entry['comment']), ('manual', 3, 'from the honeypot'))
        self.assertEqual(self.offenses('203.0.113.9')[0]['reason'], common.REASONS['manual'])
        self.assertEqual(self.runner.table, {'203.0.113.9'})
        self.assertIn('203.0.113.9', self.runner.killed)
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertEqual(self.entry('203.0.113.9')['state'], 'released')
        self.assertEqual(self.runner.table, set())
        self.assertEqual(len(self.offenses('203.0.113.9')), 1)          # the history keeps the record

    def test_auto_duration_follows_the_ladder(self):
        self.apply('quarantine_add', '203.0.113.9', 'auto')
        self.assertEqual(self.entry('203.0.113.9')['level'], 1)

    def test_guards_apply_to_manual_entries(self):
        for target, message in (('198.51.100.53', 'protected (dns)'), ('192.168.1.10', 'protected'),
                                ('198.51.100.1', 'protected (firewall)'), ('10.0.0.0/8', 'not public'),
                                ('192.0.0.0/7', 'not public')):
            plan = self.plan('quarantine_add', target, 'l1')
            self.assertEqual(plan['status'], 'error', target)
            self.assertIn(message, plan['message'])

    def test_network_covering_a_protected_address(self):
        plan = self.plan('quarantine_add', '198.51.100.0/24', 'l2')
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertTrue(any('198.51.100.53' in w for w in plan['warnings']))
        self.apply('quarantine_add', '198.51.100.0/24', 'l2')
        self.assertIn('!198.51.100.53', self.runner.table)
        self.assertEqual(self.entry('198.51.100.0/24')['kind'], 'net')

    def test_big_network_and_permanent_need_double_confirmation(self):
        common.TEST_EXTERNAL = common.TEST_EXTERNAL + (__import__('ipaddress').ip_network('203.0.0.0/15'),)
        try:
            self.assertTrue(self.plan('quarantine_add', '203.0.0.0/15', 'l1')['requires_double_confirmation'])
        finally:
            common.TEST_EXTERNAL = common.TEST_EXTERNAL[:-1]
        common.TEST_EXTERNAL = common.TEST_EXTERNAL + (__import__('ipaddress').ip_network('202.0.0.0/7'),)
        try:
            self.assertIn('too big', self.plan('quarantine_add', '202.0.0.0/7', 'l1')['message'])
        finally:
            common.TEST_EXTERNAL = common.TEST_EXTERNAL[:-1]
        self.assertFalse(self.plan('quarantine_add', '203.0.113.0/24', 'l1')['requires_double_confirmation'])
        self.assertTrue(self.plan('quarantine_add', '203.0.113.9', 'permanent')['requires_double_confirmation'])

    def test_range(self):
        result = self.apply('quarantine_add', '203.0.113.0-203.0.113.9', 'l1')
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(self.runner.table, {'203.0.113.0/29', '203.0.113.8/31'})

    def test_asn(self):
        plan = self.plan('quarantine_add', 'AS64500', 'l2')
        self.assertEqual(plan['status'], 'error')
        self.assertIn('ASN database', plan['message'])
        with open(self.ctx.asn_csv, 'w') as handle:
            handle.write('203.0.113.0/25,64500\n203.0.113.128/25,64500\n198.51.100.0/24,64501\n10.0.0.0/8,64500\n')
        plan = self.plan('quarantine_add', 'AS64500', 'l2')
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertTrue(any('not public' in w for w in plan['warnings']))
        self.apply('quarantine_add', 'AS64500', 'l2')
        self.assertEqual(self.runner.table, {'203.0.113.0/24'})
        st = self.db()
        try:
            entry = st.entry_by_addr('AS64500')
            self.assertEqual((entry['kind'], entry['asn']), ('asn', 64500))
            self.assertEqual(st.asn_prefixes(entry['id']), ['203.0.113.0/24'])
            self.assertIsNotNone(entry['resolved_at'])
        finally:
            st.close()
        # an address of the ASN is a hit, not a new offense
        self.log(filter_line(T0 + 10, '203.0.113.77'))
        self.assertEqual(self.engine().run()['hits'], 1)

    def test_limit_refuses_manual_entries(self):
        self.set_setting('max_active', 100)
        st = self.db()
        st.begin()
        for i in range(100):
            st.create_entry('192.0.2.%d' % i, 'ip', T0, state='active', level=1, since=T0, last_offense=T0,
                            until=T0 + 1800)
        st.commit()
        st.close()
        plan = self.plan('quarantine_add', '203.0.113.9', 'l1')
        self.assertEqual(plan['status'], 'error')
        self.assertIn('limit', plan['message'])


class TestBatch(ActionCase):
    def setUp(self):
        super().setUp()
        self.log(filter_line(T0 - 30, '203.0.113.5'), filter_line(T0 - 30, '203.0.113.6'))
        self.engine().run()
        self.ids = '+'.join(str(self.entry(a)['id']) for a in ('203.0.113.5', '203.0.113.6'))

    def test_release_and_revert(self):
        result = self.apply('quarantine_release', self.ids)
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(self.runner.table, set())
        self.assertEqual(self.entry('203.0.113.5')['state'], 'released')
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertEqual(self.runner.table, {'203.0.113.5', '203.0.113.6'})

    def test_extend(self):
        self.apply('quarantine_extend', self.ids, 'next')
        entry = self.entry('203.0.113.5')
        self.assertEqual((entry['level'], entry['until']), (2, T0 + 7200))
        self.apply('quarantine_extend', self.ids, 'l4')
        self.assertEqual(self.entry('203.0.113.6')['until'], T0 + 7200 + 864000)
        self.assertEqual(self.plan('quarantine_extend', self.ids, 'forever')['status'], 'error')

    def test_permanent(self):
        plan = self.plan('quarantine_permanent', self.ids)
        self.assertTrue(plan['requires_double_confirmation'])
        self.apply('quarantine_permanent', self.ids)
        entry = self.entry('203.0.113.5')
        self.assertEqual((entry['state'], entry['level'], entry['until']), ('permanent', 6, None))
        self.clock.now += 400 * 86400
        self.engine().run()
        self.assertEqual(self.entry('203.0.113.5')['state'], 'permanent')
        self.assertIn('203.0.113.5', self.runner.table)

    def test_never_block(self):
        one = str(self.entry('203.0.113.5')['id'])
        result = self.apply('never_block_add', one)
        self.assertEqual(result['status'], 'ok', result)
        self.assertEqual(self.aliases[common.NEVER_ALIAS], '203.0.113.5')
        self.assertEqual(self.entry('203.0.113.5')['state'], 'released')
        self.assertEqual(self.plan('never_block_add', self.ids)['status'], 'error')
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertEqual(self.aliases[common.NEVER_ALIAS], '')

    def test_invalid_selection(self):
        for bad in ('', 'a', '1,2', '+'.join(['1'] * 31)):
            self.assertEqual(self.plan('quarantine_release', bad)['status'], 'error')
        self.assertEqual(self.plan('quarantine_release', '99999')['status'], 'error')


class TestPauseSettings(ActionCase):
    def test_pause_resume(self):
        plan = self.plan('quarantine_pause')
        self.assertIn('Disable the rule "Max Cyber IA"', plan['steps'][0]['description'])
        result = self.apply('quarantine_pause')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(self.rule['enabled'], '0')
        status = self.engine().status()
        self.assertTrue(status['paused'])
        self.assertTrue(any(w['action']['id'] == 'quarantine_resume' for w in status['warning_actions']
                            if 'action' in w))
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertEqual(self.rule['enabled'], '1')
        self.assertEqual(self.plan('quarantine_resume')['steps'], [])

    def test_settings(self):
        result = self.apply('quarantine_settings', 'reset_days', '30')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(self.engine().status()['settings']['reset_days'], 30)
        self.assertEqual(self.plan('quarantine_settings', 'reset_days', '0')['status'], 'error')
        self.assertEqual(self.plan('quarantine_settings', 'bait_ports', '22+23')['status'], 'ok')
        self.revert(result['journal_id'])
        self.assertEqual(self.engine().status()['settings']['reset_days'], 90)


class TestAsnDb(ActionCase):
    def test_download(self):
        data = gzip.compress(''.join('203.0.%d.0/24 64500\n' % (i % 256) for i in range(1200)).encode())
        actions.UpdateAsnDb.OPENER = staticmethod(lambda url, timeout: io.BytesIO(data))
        try:
            plan = self.plan('update_asn_db')
            self.assertIn('rulesets.opnsense.org', plan['steps'][0]['command'])
            result = self.apply('update_asn_db')
            self.assertEqual(result['status'], 'ok', result)
            with open(self.ctx.asn_csv) as handle:
                self.assertEqual(handle.readline(), '203.0.0.0/24,64500\n')
            self.assertTrue(self.spawned)                                  # index built in the background
            self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
            self.assertFalse(os.path.exists(self.ctx.asn_csv))
        finally:
            actions.UpdateAsnDb.OPENER = staticmethod(__import__('urllib.request').request.urlopen)

    def test_index_and_lookup(self):
        os.makedirs(self.ctx.geoip_dir, exist_ok=True)
        with open(os.path.join(self.ctx.geoip_dir, 'BR-IPv4'), 'w') as handle:
            handle.write('203.0.113.0/25\n')
        with open(os.path.join(self.ctx.geoip_dir, 'NL-IPv6'), 'w') as handle:
            handle.write('2001:db8::/48\n')
        with open(self.ctx.asn_csv, 'w') as handle:
            handle.write(''.join('192.0.2.%d/32,%d\n' % (i, 65000 + i) for i in range(200)) +
                         '203.0.113.0/24,64500\n203.0.113.0/26,64501\n')
        self.assertTrue(lookup.needs_build(self.ctx))
        self.assertEqual(self.engine().index()['status'], 'ok')
        self.assertFalse(lookup.needs_build(self.ctx))
        lk = lookup.Lookup(self.ctx)
        try:
            self.assertEqual(lk.lookup(common.addr('203.0.113.5')), ('BR', 64501))
            self.assertEqual(lk.lookup(common.addr('203.0.113.100')), ('BR', 64500))
            self.assertEqual(lk.lookup(common.addr('203.0.113.200')), (None, 64500))
            self.assertEqual(lk.lookup(common.addr('2001:db8::1')), ('NL', None))
        finally:
            lk.close()
        self.log(filter_line(T0 - 30, '203.0.113.5'))
        self.engine().run()
        entry = self.entry('203.0.113.5')
        self.assertEqual((entry['country'], entry['asn']), ('BR', 64501))
        self.assertEqual(self.offenses('203.0.113.5')[0]['country'], 'BR')


class TestRuleUuidConstant(unittest.TestCase):
    def test_description(self):
        self.assertEqual(common.RULE_DESCR, 'Max Cyber IA')
        self.assertTrue(RULE_UUID)


if __name__ == '__main__':
    unittest.main()
