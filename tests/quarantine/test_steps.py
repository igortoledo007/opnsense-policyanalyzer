"""
the installation as steps of the assistant (steps.py, wizard.py): every step action through the plugin
dispatcher (plan -> apply -> revert with its own journal entry), idempotency, the undo of the ledger with and
without history (disconnect, connect again, delete with double confirmation), the rule created disabled ->
activate -> pause, the scenarios with their preview, the schedule, pa_never_block, the logging of the
WireGuard rule, the detected state of every step and the composites install/remove chaining the steps.
"""

import os
import unittest

from qhelpers import RULE_UUID, T0, WG_RULE_UUID, QuarantineCase, common, filter_line, store

from ai import changes, journal
from quarantine import cli, steps, wizard

changes.load_extensions()


class StepCase(QuarantineCase):
    installed = False

    def setUp(self):
        super().setUp()
        journal.UNDO_DIR = os.path.join(self.tmp, 'undo')

    def plan(self, name, *args):
        return changes.run('plan', name, list(args))

    def apply(self, name, *args):
        result = changes.run('apply', name, list(args))
        self.assertEqual(result['status'], 'ok', result)
        return result

    def revert(self, journal_id, *flags, mode='apply'):
        return changes.run(mode, 'revert', [journal_id] + list(flags))

    def state(self):
        return wizard.state(self.ctx, engine_options={'runtime_guards': True, 'resolver': self.resolver})

    def history_of(self, name):
        return [e for e in journal.entries() if e['action'] == name]

    def install_until_rule(self, rule='on'):
        self.apply('qsetup_ledger', 'create')
        self.apply('qsetup_aliases', 'create')
        return self.apply('qsetup_rule', 'create', rule)


class TestRegistry(StepCase):
    def test_every_step_is_registered(self):
        names = {a['name'] for a in changes.describe()['actions']}
        self.assertTrue({'qsetup_rule_log', 'qsetup_ledger', 'qsetup_aliases', 'qsetup_never_block', 'qsetup_rule',
                         'qsetup_scenarios', 'qsetup_schedule', 'qsetup_activate', 'install_quarantine',
                         'remove_quarantine'} <= names)
        for actions in steps.STEP_ACTIONS.values():
            for name in actions:
                self.assertIn(name, names)


class TestCheck(StepCase):
    def test_state_of_a_fresh_firewall(self):
        self.log(filter_line(T0 - 60, '203.0.113.5'), filter_line(T0 - 50, '203.0.113.6', iface='igc2'),
                 filter_line(T0 - 1800, '203.0.113.7'), filter_line(T0 - 40, '198.51.100.53'),
                 filter_line(T0 - 30, '192.168.1.50'))
        data = self.state()
        self.assertEqual(data['status'], 'ok')
        self.assertFalse(data['installed'])
        self.assertEqual({k: v for k, v in data['done'].items() if v}, {'check': True})
        wan = {w['key']: w for w in data['check']['wan']}
        self.assertEqual(set(wan), {'wan', 'opt6'})
        self.assertEqual(wan['wan']['sources_5m'], 2)          # 203.0.113.5 and the DNS server (guard later)
        self.assertEqual(wan['opt6']['sources_5m'], 1)
        self.assertEqual(wan['wan']['sources_1h'], 3)
        self.assertEqual(data['check']['entering_5m'], 2)      # the DNS server is protected
        self.assertEqual(data['check']['entering_1h'], 3)
        self.assertEqual(data['check']['guarded_1h'], {'dns': 1})
        self.assertFalse(data['check']['suricata']['running'])
        self.assertTrue(any('Suricata is not running' in w['warning'] for w in data['check']['warning_actions']))
        self.assertGreater(data['check']['guards']['counts']['dns'], 0)
        self.assertEqual(data['rule']['position']['sequence'], 99)
        self.assertEqual(data['rule']['position']['before'][0]['description'], 'BL GeoIP')

    def test_wireguard_rule_without_log_brings_its_button(self):
        self.wg_log = '0'
        self.write_config()
        warnings = self.state()['check']['warning_actions']
        wa = [w for w in warnings if 'WireGuard' in w['warning']]
        self.assertEqual(wa[0]['action'], {'id': 'qsetup_rule_log', 'label': 'Enable logging of this rule',
                                           'args': [WG_RULE_UUID, 'on']})
        plan = self.plan('qsetup_rule_log', WG_RULE_UUID, 'on')
        self.assertTrue(plan['requires_confirmation'])
        self.assertIn('Enable logging of the rule "VPN Remote access"', plan['steps'][0]['description'])
        result = self.apply('qsetup_rule_log', WG_RULE_UUID, 'on')
        self.assertEqual(self.wg_log, '1')
        self.assertEqual(self.plan('qsetup_rule_log', WG_RULE_UUID, 'on')['steps'], [])      # idempotent
        self.assertFalse(any('WireGuard' in w['warning'] for w in self.state()['check']['warning_actions']))
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertEqual(self.wg_log, '0')
        # only WAN pass rules to a WireGuard port, never the block rules
        self.assertEqual(self.plan('qsetup_rule_log', 'cccccccc-1111-2222-3333-444444444444', 'on')['status'], 'error')
        self.assertEqual(self.plan('qsetup_rule_log', 'r-100', 'on')['status'], 'error')


class TestLedger(StepCase):
    def test_create_is_idempotent_and_undo_deletes_an_empty_ledger(self):
        plan = self.plan('qsetup_ledger', 'create')
        self.assertIn('quarantine.db', plan['steps'][0]['description'])
        result = self.apply('qsetup_ledger')
        self.assertTrue(os.path.exists(self.ctx.db))
        self.assertEqual(self.plan('qsetup_ledger', 'create')['steps'], [])
        self.assertEqual(self.apply('qsetup_ledger', 'create').get('journal_id'), None)  # nothing journaled
        rplan = self.revert(result['journal_id'], mode='plan')
        self.assertIn('Delete the EMPTY ledger', ' '.join(s['description'] for s in rplan['steps']))
        self.assertFalse(rplan['requires_double_confirmation'])
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertFalse(os.path.exists(self.ctx.db))

    def _ledger_with_history(self):
        result = self.apply('qsetup_ledger', 'create')
        st = store.Store(self.ctx.db)
        st.begin()
        entry = st.create_entry('203.0.113.9', 'ip', T0, level=1, state='expired', origin='auto')
        st.add_offense(entry['id'], T0, 'base', ['base'], 1, T0 + 1800, 'auto')
        st.commit()
        st.close()
        return result

    def test_undo_with_history_only_disconnects(self):
        result = self._ledger_with_history()
        rplan = self.revert(result['journal_id'], mode='plan')
        text = ' '.join(s['description'] for s in rplan['steps'])
        self.assertIn('Disconnect the ledger (it holds history: 1 entries, 1 offenses)', text)
        self.assertFalse(rplan['irreversible'])
        self.assertFalse(rplan['requires_double_confirmation'])
        delete = [w for w in rplan.get('warning_actions', []) if w.get('action', {}).get('id') == 'revert']
        self.assertEqual(delete[0]['action']['args'], [result['journal_id'], 'purge'])
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertFalse(os.path.exists(self.ctx.db))
        detached = wizard.detached_ledgers(self.ctx)
        self.assertEqual(len(detached), 1)
        self.assertTrue(detached[0]['name'].startswith(common.DETACHED_PREFIX))
        # the assistant offers to connect it again, and that is a step of its own (with undo)
        plan = self.plan('qsetup_ledger', 'create')
        attach = plan['warning_actions'][0]['action']
        self.assertEqual(attach['args'], ['attach', detached[0]['name']])
        res = self.apply('qsetup_ledger', 'attach', detached[0]['name'])
        self.assertTrue(os.path.exists(self.ctx.db))
        self.assertIsNotNone(self.entry('203.0.113.9'))
        self.assertEqual(self.revert(res['journal_id'])['status'], 'ok')          # disconnects again
        self.assertFalse(os.path.exists(self.ctx.db))
        self.assertEqual(self.plan('qsetup_ledger', 'attach', '../x.db')['status'], 'error')

    def test_delete_needs_the_explicit_option_and_double_confirmation(self):
        result = self._ledger_with_history()
        rplan = self.revert(result['journal_id'], 'purge', mode='plan')
        self.assertTrue(rplan['requires_double_confirmation'])
        self.assertTrue(rplan['irreversible'])
        self.assertEqual(rplan['risk'], 'high')
        self.assertEqual(self.revert(result['journal_id'], 'purge')['status'], 'ok')
        self.assertFalse(os.path.exists(self.ctx.db))
        self.assertEqual(wizard.detached_ledgers(self.ctx), [])

    def test_undo_waits_for_the_rule(self):
        result = self.apply('qsetup_ledger', 'create')
        self.apply('qsetup_aliases', 'create')
        self.apply('qsetup_rule', 'create')
        rplan = self.revert(result['journal_id'], mode='plan')
        self.assertEqual(rplan['steps'], [])
        self.assertEqual(rplan['warning_actions'][0]['action'], {'id': 'qsetup_rule', 'args': ['remove'],
                                                                  'label': 'Remove the rule (simulate first)'})
        self.assertEqual(self.revert(result['journal_id'])['status'], 'error')
        self.assertTrue(os.path.exists(self.ctx.db))

    def test_detach_and_purge_modes(self):
        self._ledger_with_history()
        plan = self.plan('qsetup_ledger', 'purge')
        self.assertTrue(plan['requires_double_confirmation'])
        res = self.apply('qsetup_ledger', 'detach')
        self.assertFalse(os.path.exists(self.ctx.db))
        self.assertEqual(self.revert(res['journal_id'])['status'], 'ok')         # connects it again
        self.assertTrue(os.path.exists(self.ctx.db))
        res = self.apply('qsetup_ledger', 'purge')
        self.assertFalse(os.path.exists(self.ctx.db))
        self.assertEqual(self.revert(res['journal_id'])['status'], 'error')      # deleted is deleted


class TestAliases(StepCase):
    def test_create_edit_and_undo(self):
        plan = self.plan('qsetup_aliases', 'create')
        self.assertEqual(len(plan['steps']), 3)
        result = self.apply('qsetup_aliases', 'create')
        self.assertIn(common.ALIAS, self.aliases)
        self.assertIn(common.NEVER_ALIAS, self.aliases)
        self.assertEqual(self.plan('qsetup_aliases', 'create')['steps'], [])
        # pa_never_block, entry by entry, each undoable
        self.assertEqual(self.plan('qsetup_never_block', 'add', 'not-an-address')['status'], 'error')
        add = self.apply('qsetup_never_block', 'add', '203.0.113.0/28')
        self.assertEqual(self.aliases[common.NEVER_ALIAS], '203.0.113.0/28')
        self.assertEqual(self.plan('qsetup_never_block', 'add', '203.0.113.0/28')['steps'], [])
        priv = self.plan('qsetup_never_block', 'add', '192.168.1.10')
        self.assertTrue(any('not public' in w for w in priv['warnings']))
        self.apply('qsetup_never_block', 'add', '2001:db8::5')
        self.assertEqual(self.revert(add['journal_id'])['status'], 'ok')
        self.assertEqual(self.aliases[common.NEVER_ALIAS], '2001:db8::5')
        # undo of the creation: the entries of pa_never_block are named and need the double confirmation
        rplan = self.revert(result['journal_id'], mode='plan')
        self.assertTrue(rplan['requires_double_confirmation'])
        self.assertIn('2001:db8::5', ' '.join(rplan['warnings']))
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertEqual(self.aliases, {})

    def test_remove_waits_for_the_rule_and_keeps_the_entries(self):
        self.install_until_rule()
        self.apply('qsetup_never_block', 'add', '203.0.113.200')
        plan = self.plan('qsetup_aliases', 'remove')
        self.assertEqual(plan['steps'], [])
        self.assertEqual(plan['warning_actions'][0]['action']['id'], 'qsetup_rule')
        self.apply('qsetup_rule', 'remove')
        res = self.apply('qsetup_aliases', 'remove')
        self.assertEqual(self.aliases, {})
        self.assertIsNone(self.runner.table)
        self.assertEqual(self.revert(res['journal_id'])['status'], 'ok')
        self.assertEqual(self.aliases[common.NEVER_ALIAS], '203.0.113.200')

    def test_never_block_needs_the_alias(self):
        plan = self.plan('qsetup_never_block', 'add', '203.0.113.7')
        self.assertEqual(plan['warning_actions'][0]['action']['id'], 'qsetup_aliases')


class TestRule(StepCase):
    def test_needs_the_alias(self):
        plan = self.plan('qsetup_rule', 'create')
        self.assertEqual(plan['steps'], [])
        self.assertEqual(plan['warning_actions'][0]['action']['args'], ['create'])
        self.assertEqual(changes.run('apply', 'qsetup_rule', ['create'])['status'], 'error')

    def test_position_and_undo(self):
        self.apply('qsetup_ledger', 'create')
        self.apply('qsetup_aliases', 'create')
        plan = self.plan('qsetup_rule', 'create', 'off')
        text = ' '.join(s['description'] + s['command'] + s['effect'] for s in plan['steps'])
        self.assertIn('DISABLED', text)
        self.assertIn('sequence 99', text)
        self.assertIn('before "BL GeoIP" (100)', text)
        info = {b['title']: b['items'] for b in plan['info']}
        self.assertIn('"VPN Remote access" (1731)', ' '.join(info['Rule position']))
        self.runner.calls.clear()
        result = self.apply('qsetup_rule', 'create', 'off')
        self.assertEqual(self.rule['enabled'], '0')
        self.assertEqual([' '.join(c[1:]) for c in self.runner.calls if c[0].endswith('configctl')], ['filter reload'])
        self.assertEqual(self.plan('qsetup_rule', 'create', 'off')['steps'], [])
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertIsNone(self.rule)

    def test_remove_ends_the_quarantines_and_undo_restores_them(self):
        self.install_until_rule()
        self.apply('qsetup_schedule', 'create')
        self.log(filter_line(T0 + 10, '203.0.113.5'))
        self.run_engine(advance=60)
        self.assertEqual(self.runner.table, {'203.0.113.5'})
        res = self.apply('qsetup_rule', 'remove')
        self.assertIsNone(self.rule)
        self.assertEqual(self.entry('203.0.113.5')['state'], 'expired')
        self.assertEqual(self.runner.table, set())
        self.assertEqual(self.revert(res['journal_id'])['status'], 'ok')
        self.assertEqual(self.rule['sequence'], '99')
        self.assertEqual(self.entry('203.0.113.5')['state'], 'active')
        self.assertEqual(self.runner.table, {'203.0.113.5'})

    def test_failed_reload_removes_the_rule_again(self):
        self.apply('qsetup_aliases', 'create')
        self.runner.fail.add('configctl')
        result = changes.run('apply', 'qsetup_rule', ['create'])
        self.assertEqual(result['status'], 'error')
        self.assertIn('removed again', result['message'])
        self.assertIsNone(self.rule)
        self.assertEqual(self.history_of('qsetup_rule'), [])


class TestScenarios(StepCase):
    def test_needs_the_ledger(self):
        plan = self.plan('qsetup_scenarios', 'scan_ports=12')
        self.assertEqual(plan['warning_actions'][0]['action']['id'], 'qsetup_ledger')

    def test_before_after_preview_apply_and_undo(self):
        self.apply('qsetup_ledger', 'create')
        for port in range(1, 9):
            self.log(filter_line(T0 - 100 + port, '203.0.113.20', dport=port))
        self.log(filter_line(T0 - 60, '203.0.113.21', dport=3389), filter_line(T0 - 900, '203.0.113.22'))
        self.assertEqual(self.plan('qsetup_scenarios', 'scan_ports=1')['status'], 'error')        # validated
        self.assertEqual(self.plan('qsetup_scenarios', 'bogus=1')['status'], 'error')
        plan = self.plan('qsetup_scenarios', 'scan_ports=8:bait_ports=3389+23:reset_days=90')
        self.assertEqual([s['description'] for s in plan['steps']], ['Set scan_ports', 'Set bait_ports'])
        self.assertEqual(plan['steps'][0]['effect'], '10 -> 8')
        info = {b['title'].split(':')[0]: b for b in plan['info']}
        self.assertIn('reset_days: 90 (unchanged)', info['Unchanged']['items'])
        self.assertIn('scan_ports: 10 -> 8', info['Before / after']['items'])
        preview = [b for b in plan['info'] if b['title'].startswith('Preview')][0]
        self.assertIn('2 address(es) would enter', preview['title'])         # the old one is outside 5 min
        self.assertTrue(any(i.startswith('203.0.113.20 — scan, level 2') for i in preview['items']))
        self.assertTrue(any(i.startswith('203.0.113.21 — bait') for i in preview['items']))
        before = os.path.getsize(self.ctx.db)
        self.assertEqual(self.entry('203.0.113.20'), None)                   # the preview writes nothing
        self.assertEqual(os.path.getsize(self.ctx.db), before)
        result = self.apply('qsetup_scenarios', 'scan_ports=8:bait_ports=3389+23')
        self.assertEqual(self.engine().status()['settings']['scan_ports'], 8)
        self.assertEqual(self.plan('qsetup_scenarios', 'scan_ports=8:bait_ports=3389+23')['steps'], [])
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        settings = self.engine().status()['settings']
        self.assertEqual((settings['scan_ports'], settings['bait_ports']), (10, common.DEFAULTS['bait_ports']))
        st = self.db()
        self.assertEqual(st.stored_settings(), {})
        st.close()

    def test_preview_from_the_cli(self):
        import io
        self.log(filter_line(T0 - 30, '203.0.113.5'))
        out = io.StringIO()
        cli.main(['preview', 'scan_ports=5'], out=out)
        import json
        data = json.loads(out.getvalue())
        self.assertEqual(data['entering'], 1)
        self.assertEqual(data['settings']['scan_ports'], 5)
        out = io.StringIO()
        cli.main(['wizard'], out=out)
        self.assertEqual(json.loads(out.getvalue())['status'], 'ok')


class TestSchedule(StepCase):
    def test_create_remove_and_undo(self):
        result = self.apply('qsetup_schedule', 'create')
        self.assertTrue(self.cron)
        self.assertTrue(os.path.exists(self.ctx.syshook))
        self.assertEqual(self.plan('qsetup_schedule', 'create')['steps'], [])
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertFalse(self.cron)
        self.assertFalse(os.path.exists(self.ctx.syshook))
        self.apply('qsetup_schedule', 'create')
        res = self.apply('qsetup_schedule', 'remove')
        self.assertFalse(self.cron)
        self.assertEqual(self.plan('qsetup_schedule', 'remove')['steps'], [])
        self.assertEqual(self.revert(res['journal_id'])['status'], 'ok')
        self.assertTrue(self.cron)
        self.assertTrue(os.path.exists(self.ctx.syshook))


class TestActivate(StepCase):
    def test_needs_ledger_alias_and_rule(self):
        plan = self.plan('qsetup_activate')
        ids = [w['action']['id'] for w in plan['warning_actions']]
        self.assertEqual(ids, ['qsetup_ledger', 'qsetup_aliases', 'qsetup_rule'])

    def test_disabled_rule_activate_then_pause(self):
        self.install_until_rule('off')
        self.assertEqual(self.rule['enabled'], '0')
        self.log(filter_line(T0 + 5, '203.0.113.5'), filter_line(T0 + 6, '203.0.113.6', dport=23),
                 filter_line(T0 + 7, '198.51.100.53'))
        self.clock.now = T0 + 60
        plan = self.plan('qsetup_activate')
        effects = ' '.join(s['effect'] for s in plan['steps'])
        self.assertIn('about 2 address(es) enter (bait 1, base 1)', effects)
        self.assertTrue(any('Not scheduled yet' in w['warning'] for w in plan['warning_actions']))
        self.assertEqual(self.entry('203.0.113.5'), None)                    # the preview writes nothing
        result = self.apply('qsetup_activate')
        self.assertEqual(self.rule['enabled'], '1')
        self.assertEqual(result['run']['offenses'], 2)
        self.assertIn('first run: 2 address(es) entered (bait 1, base 1)', ' '.join(result['completed']))
        self.assertEqual(self.runner.table, {'203.0.113.5', '203.0.113.6'})
        self.assertTrue(self.state()['done']['activate'])
        # undo = pause: rule disabled, the ledger keeps recording
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertEqual(self.rule['enabled'], '0')
        self.assertTrue(self.engine().status()['paused'])
        self.assertEqual(self.entry('203.0.113.5')['state'], 'active')
        self.log(filter_line(T0 + 120, '203.0.113.7'))
        self.assertEqual(self.run_engine(advance=120)['offenses'], 1)
        # activate again: resume + run; idempotent rule part
        again = self.apply('qsetup_activate')
        self.assertEqual(self.rule['enabled'], '1')
        self.assertFalse(self.engine().status()['paused'])
        todo = [s['description'] for s in self.plan('qsetup_activate')['steps'] if s['effect'] != 'already done']
        self.assertEqual(todo, ['Run the quarantine now (the first run)'])
        self.assertTrue(again['journal_id'])


class TestComposites(StepCase):
    def test_install_writes_one_journal_entry_per_step(self):
        result = self.apply('install_quarantine')
        names = [e['action'] for e in journal.entries()]
        for name in ('qsetup_ledger', 'qsetup_aliases', 'qsetup_rule', 'qsetup_schedule', 'install_quarantine'):
            self.assertIn(name, names)
        self.assertEqual(len(result['completed']) >= 6, True)
        data = self.state()
        self.assertTrue(data['installed'])
        self.assertTrue(data['rule']['enabled'])
        # a step undone alone is skipped by the revert of the composite
        rule_entry = self.history_of('qsetup_schedule')[0]
        self.assertEqual(self.revert(rule_entry['id'])['status'], 'ok')
        self.assertFalse(self.cron)
        self.assertEqual(self.revert(result['journal_id'])['status'], 'ok')
        self.assertIsNone(self.rule)
        self.assertEqual(self.aliases, {})
        self.assertTrue(os.path.exists(self.ctx.db))
        self.assertTrue(all(e['reverted'] for e in journal.entries() if e['action'] != 'qsetup_ledger'))

    def test_remove_by_inverse_steps(self):
        self.apply('install_quarantine')
        self.apply('qsetup_never_block', 'add', '203.0.113.200')
        res = self.apply('remove_quarantine')
        removal = [e['action'] for e in journal.entries() if (e.get('args') or {}).get('via') == 'remove_quarantine']
        self.assertEqual(sorted(removal), ['qsetup_aliases', 'qsetup_rule', 'qsetup_schedule'])
        self.assertEqual(len(self.history_of('remove_quarantine')), 1)
        self.assertTrue(os.path.exists(self.ctx.db))                         # the ledger stays by default
        # every inverse step is undoable on its own: bring back the aliases only
        alias_remove = [e for e in self.history_of('qsetup_aliases') if e['args'].get('mode') == 'remove'][0]
        self.assertEqual(self.revert(alias_remove['id'])['status'], 'ok')
        self.assertEqual(self.aliases[common.NEVER_ALIAS], '203.0.113.200')
        self.assertIsNone(self.rule)
        self.assertEqual(self.revert(res['journal_id'])['status'], 'ok')     # the rest
        self.assertTrue(self.cron)
        self.assertEqual(self.rule['uuid'], RULE_UUID)


if __name__ == '__main__':
    unittest.main()
