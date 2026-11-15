"""
OPNsense 27.1 (Filter.xml 1.1.7) compatibility: "match" rules, scrub_* options and the migrated firewall
settings (//OPNsense/Firewall/Filter/settings). The 26.7 layout must keep working unchanged.
"""

import unittest

from helpers import analyze, findings_of, rule, alias, uuid_for

S27 = {'keep_counters': '1', 'skip_rules_gw_down': '0'}
V27 = '1.1.7'


def match_rule(name, **fields):
    """ a match rule as the MFP1_0_8 migration writes it (floating, not quick, stateless, both directions) """
    values = {'interface': '', 'action': 'match', 'quick': '0', 'direction': 'any', 'ipprotocol': 'inet46',
              'statetype': 'none'}
    values.update(fields)
    return rule(name, **values)


class TestFilterSettings(unittest.TestCase):
    def test_keep_counters_from_settings(self):
        r = analyze([rule('a')], filter_settings=S27, filter_version=V27)
        self.assertTrue(r['stats']['keepcounters'])
        self.assertEqual(r['stats']['keepcounters_source'], 'mvc')
        self.assertEqual(r['stats']['settings_page'], 'ui/firewall/settings')

    def test_keep_counters_legacy_still_works(self):
        r = analyze([rule('a')], system_extra='<keepcounters>1</keepcounters>')
        self.assertTrue(r['stats']['keepcounters'])
        self.assertEqual(r['stats']['keepcounters_source'], 'legacy')
        self.assertEqual(r['stats']['settings_page'], 'system_advanced_firewall.php')

    def test_settings_win_over_leftover_legacy(self):
        r = analyze([rule('a')], system_extra='<keepcounters>1</keepcounters>',
                    filter_settings={'keep_counters': '0'}, filter_version=V27)
        self.assertFalse(r['stats']['keepcounters'])
        self.assertEqual(r['stats']['keepcounters_source'], 'mvc')

    def test_partial_migration_falls_back_per_key(self):
        # settings node exists but keep_counters is not there yet: the legacy node still counts
        r = analyze([rule('a')], system_extra='<keepcounters>1</keepcounters>',
                    filter_settings={'skip_rules_gw_down': '1'}, filter_version=V27)
        self.assertTrue(r['stats']['keepcounters'])
        self.assertEqual(r['stats']['keepcounters_source'], 'legacy')
        self.assertEqual(r['stats']['settings_page'], 'ui/firewall/settings')

    def test_no_keepcounters_anywhere(self):
        r = analyze([rule('a')])
        self.assertFalse(r['stats']['keepcounters'])
        self.assertIsNone(r['stats']['keepcounters_source'])

    def test_not_loaded_text_mentions_skip_rules_only_when_enabled(self):
        rules = [rule('gw rule', gateway='WAN_GW', source_net='192.0.2.10')]
        stats = {uuid_for('other'): {'packets': 1}}
        r = analyze(rules, stats=stats, filter_settings={'skip_rules_gw_down': '1'}, filter_version=V27)
        self.assertIn('skip rules', findings_of(r, 'inactive', 'gw rule')[0]['detail'])
        r = analyze(rules, stats=stats, filter_settings={'skip_rules_gw_down': '0'}, filter_version=V27)
        self.assertNotIn('skip rules', findings_of(r, 'inactive', 'gw rule')[0]['detail'])


class TestMatchRules(unittest.TestCase):
    def test_match_rule_does_not_override_pass(self):
        rules = [rule('np', interface='', quick='0', direction='any'),
                 match_rule('m', scrub_no_df='1')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        self.assertEqual(findings_of(r, 'shadowed', 'np'), [])
        self.assertEqual(findings_of(r, 'redundant', 'np'), [])

    def test_migrated_scrub_rule_is_silent(self):
        rules = [match_rule('scrub', interface='opt1', sequence='1', scrub_max_mss='1360'),
                 rule('dmz', interface='opt1', source_net='opt1')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        for ftype in ('shadowed', 'redundant', 'duplicate'):
            self.assertEqual(findings_of(r, ftype, 'scrub'), [], ftype)
            self.assertEqual(findings_of(r, ftype, 'dmz'), [], ftype)

    def test_match_after_quick_block_is_not_reported(self):
        # by decision: match rules are never reported as shadowed by pass/block rules
        rules = [rule('block all', action='block'),
                 match_rule('m', interface='lan', direction='in', ipprotocol='inet', scrub_max_mss='1300')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        self.assertEqual(findings_of(r, 'shadowed', 'm'), [])

    def test_match_is_neither_permissive_nor_exposed(self):
        rules = [match_rule('wan match', interface='wan', direction='in', scrub_random_id='1')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        self.assertEqual(findings_of(r, 'permissive'), [])
        self.assertEqual(findings_of(r, 'wan_exposed'), [])

    def test_quick_match_stops_evaluation(self):
        rules = [rule('qm', action='match', protocol='UDP', destination_port='53', statetype='none'),
                 rule('blk', action='block', protocol='UDP', destination_port='53')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        hits = findings_of(r, 'shadowed', 'blk')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['severity'], 'high')
        self.assertEqual(hits[0]['evidence']['mode'], 'quick_match')
        self.assertEqual(hits[0]['rules'][1]['action'], 'match')

    def test_non_quick_match_does_not_stop_evaluation(self):
        rules = [rule('nqm', action='match', quick='0', protocol='UDP', destination_port='53', statetype='none'),
                 rule('blk', action='block', protocol='UDP', destination_port='53')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        self.assertEqual(findings_of(r, 'shadowed', 'blk'), [])

    def test_duplicate_match_rules(self):
        rules = [match_rule('m1', scrub_max_mss='1360'), match_rule('m2', scrub_max_mss='1360'),
                 match_rule('m3', scrub_max_mss='1400')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        found = findings_of(r, 'duplicate', 'm2')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['evidence']['mode'], 'match_duplicate')
        self.assertEqual(found[0]['rules'][1]['description'], 'm1')
        self.assertEqual(findings_of(r, 'duplicate', 'm3'), [])
        self.assertEqual(findings_of(r, 'redundant'), [])

    def test_match_unused_with_stats(self):
        rules = [match_rule('m', scrub_max_mss='1360')]
        stats = {uuid_for('m'): {'packets': 0, 'states': 0, 'evaluations': 10}}
        r = analyze(rules, stats=stats, filter_settings=S27, filter_version=V27)
        self.assertEqual(len(findings_of(r, 'unused', 'm')), 1)


class TestScrubOptions(unittest.TestCase):
    def test_scrub_options_are_an_effect(self):
        rules = [rule('mss', protocol='TCP', destination_port='22', scrub_max_mss='1200'),
                 rule('plain', protocol='TCP', destination_port='22')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        self.assertEqual(findings_of(r, 'duplicate', 'plain'), [])
        self.assertEqual(findings_of(r, 'redundant', 'plain'), [])
        found = findings_of(r, 'shadowed', 'plain')
        self.assertEqual(found[0]['severity'], 'medium')
        self.assertIn('scrub_max_mss', found[0]['evidence']['differences'])

    def test_scrub_defaults_do_not_break_duplicates(self):
        # a 26.7 rule (no scrub_* nodes) and a 27.1 rule with scrub_no_df=0 are still the same effect
        rules = [rule('a', protocol='TCP', destination_port='22'),
                 rule('b', protocol='TCP', destination_port='22', scrub_no_df='0', scrub_random_id='0')]
        r = analyze(rules, filter_settings=S27, filter_version=V27)
        self.assertEqual(len(findings_of(r, 'duplicate', 'b')), 1)


class TestScrubLeftover(unittest.TestCase):
    SCRUB = '<scrub><rule><interface>opt1</interface><src>SCRUB_ONLY</src><srcmask>32</srcmask>' \
            '<dst>any</dst><max-mss>1360</max-mss></rule></scrub>'

    def _config(self, version):
        return analyze(rules=[rule('x')], aliases=[alias('SCRUB_ONLY', 'host', ['192.0.2.77'])],
                       legacy=[self.SCRUB], filter_version=version)

    def test_leftover_scrub_does_not_count_as_alias_use_after_migration(self):
        r = self._config(V27)
        self.assertEqual([f['aliases'][0] for f in findings_of(r, 'unused_alias')], ['SCRUB_ONLY'])

    def test_active_scrub_counts_as_alias_use_on_26_7(self):
        r = self._config('1.0.6')
        self.assertEqual(findings_of(r, 'unused_alias'), [])


if __name__ == '__main__':
    unittest.main()
