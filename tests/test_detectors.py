"""
Policy Analyzer engine tests (stdlib unittest, synthetic configurations only).

    /usr/bin/python3 -m unittest discover -s tests -v
"""

import unittest

from helpers import analyze, rule, alias, legacy_rule, findings_of, uuid_for, FIXED_NOW


class TestShadowed(unittest.TestCase):
    def test_block_before_pass_is_high(self):
        res = analyze(rules=[
            rule('block all lan', action='block'),
            rule('web host', source_net='192.0.2.10', protocol='TCP', destination_port='443'),
        ])
        found = findings_of(res, 'shadowed', 'web host')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['severity'], 'high')
        self.assertEqual(found[0]['rules'][1]['description'], 'block all lan')
        self.assertEqual(found[0]['evidence']['mode'], 'earlier_quick')

    def test_block_vs_reject_is_medium(self):
        res = analyze(rules=[
            rule('reject lan', action='reject'),
            rule('block host', action='block', source_net='192.0.2.10'),
        ])
        found = findings_of(res, 'shadowed', 'block host')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['severity'], 'medium')

    def test_same_action_different_gateway_is_shadowed_medium(self):
        res = analyze(rules=[
            rule('pass lan net', source_net='lan'),
            rule('policy route host', source_net='192.0.2.20', gateway='WAN2_GW'),
        ])
        found = findings_of(res, 'shadowed', 'policy route host')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['severity'], 'medium')
        self.assertIn('gateway', found[0]['evidence']['differences'])

    def test_group_rules_precede_interface_rules(self):
        # the interface rule has a lower sequence but group rules (prio 300000) are evaluated first
        res = analyze(rules=[
            rule('lan host pass', source_net='192.0.2.10'),
            rule('internal block', action='block', interface='INTERNAL'),
        ])
        found = findings_of(res, 'shadowed', 'lan host pass')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['rules'][1]['description'], 'internal block')

    def test_floating_quick_shadows_interface(self):
        res = analyze(rules=[
            rule('floating block', action='block', interface='', destination_net='198.51.100.0/24'),
            rule('lan to doc net', destination_net='198.51.100.7', protocol='UDP', destination_port='53'),
        ])
        self.assertEqual(len(findings_of(res, 'shadowed', 'lan to doc net')), 1)

    def test_non_quick_overridden_by_later_rule(self):
        # floating non-quick block on lan+opt1, followed by a group pass for everything: never decides
        res = analyze(rules=[
            rule('float nonquick', action='block', quick='0', interface='lan,opt1', source_net='192.0.2.10'),
            rule('internal pass all', interface='INTERNAL'),
        ])
        found = findings_of(res, 'shadowed', 'float nonquick')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['evidence']['mode'], 'later_overrides')

    def test_interfacenot(self):
        res = analyze(rules=[
            rule('block not wan', action='block', interface='wan', interfacenot='1'),
            rule('pass dmz', interface='opt1', source_net='opt1'),
        ])
        self.assertEqual(len(findings_of(res, 'shadowed', 'pass dmz')), 1)
        res = analyze(rules=[
            rule('block not wan', action='block', interface='wan', interfacenot='1'),
            rule('pass wan', interface='wan', source_net='203.0.113.5'),
        ])
        self.assertEqual(findings_of(res, 'shadowed', 'pass wan'), [])

    def test_inet46_covers_inet6(self):
        res = analyze(rules=[
            rule('block both', action='block', ipprotocol='inet46'),
            rule('pass v6', ipprotocol='inet6', destination_net='2001:db8:99::/48'),
        ])
        self.assertEqual(len(findings_of(res, 'shadowed', 'pass v6')), 1)

    def test_icmp_type_subset(self):
        res = analyze(rules=[
            rule('block icmp', action='block', protocol='ICMP'),
            rule('pass echo', protocol='ICMP', icmptype='echoreq'),
        ])
        self.assertEqual(len(findings_of(res, 'shadowed', 'pass echo')), 1)
        res = analyze(rules=[
            rule('block echo', action='block', protocol='ICMP', icmptype='echoreq'),
            rule('pass icmp', protocol='ICMP'),
        ])
        self.assertEqual(findings_of(res, 'shadowed', 'pass icmp'), [])

    def test_nested_static_alias_resolves(self):
        res = analyze(
            aliases=[alias('SERVERS', 'host', ['192.0.2.10', '192.0.2.11']),
                     alias('ALLNETS', 'network', ['192.0.2.0/25', 'SERVERS'])],
            rules=[rule('block allnets', action='block', source_net='ALLNETS'),
                   rule('pass servers', source_net='SERVERS', protocol='TCP', destination_port='22')])
        found = findings_of(res, 'shadowed', 'pass servers')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['aliases'], ['ALLNETS', 'SERVERS'])

    def test_port_alias_and_ranges(self):
        res = analyze(
            aliases=[alias('WEB', 'port', ['80', '443', '8000:8080'])],
            rules=[rule('block web', action='block', protocol='TCP', destination_port='WEB'),
                   rule('pass 8001', protocol='TCP', destination_port='8001-8002')])
        self.assertEqual(len(findings_of(res, 'shadowed', 'pass 8001')), 1)

    def test_legacy_rule_shadowed_by_mvc(self):
        res = analyze(
            rules=[rule('mvc block lan', action='block')],
            legacy=[legacy_rule('legacy pass', source='<address>192.0.2.10</address>')])
        found = findings_of(res, 'shadowed', 'legacy pass')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['rules'][0]['source'], 'legacy')


class TestLegacy(unittest.TestCase):
    def test_legacy_floating_defaults_to_non_quick(self):
        res = analyze(legacy=[
            legacy_rule('legacy float block', interface='lan,opt1', rtype='block', extra='<floating>yes</floating>'),
            legacy_rule('legacy lan pass', source='<address>192.0.2.10</address>'),
        ])
        self.assertEqual(findings_of(res, 'shadowed', 'legacy lan pass'), [])

    def test_legacy_quick_floating_shadows(self):
        res = analyze(legacy=[
            legacy_rule('legacy float block', interface='lan,opt1', rtype='block',
                        extra='<floating>yes</floating><quick>yes</quick>'),
            legacy_rule('legacy lan pass', source='<address>192.0.2.10</address>'),
        ])
        self.assertEqual(len(findings_of(res, 'shadowed', 'legacy lan pass')), 1)

    def test_mvc_precedes_legacy_in_same_priority(self):
        res = analyze(rules=[rule('mvc pass host', source_net='192.0.2.10')],
                      legacy=[legacy_rule('legacy block lan', rtype='block')])
        found = findings_of(res, 'shadowed', 'mvc pass host')
        self.assertEqual(found, [])
        self.assertEqual(findings_of(res, 'redundant', 'mvc pass host'), [])


class TestNotShadowed(unittest.TestCase):
    def assertClean(self, res, description):
        for ftype in ('shadowed', 'redundant', 'duplicate'):
            self.assertEqual(findings_of(res, ftype, description), [], ftype)

    def test_opaque_alias_never_shadows(self):
        for atype, content in (('geoip', ['NL']), ('urltable', ['https://example.com/list.txt']),
                               ('host', ['www.example.com']), ('asn', ['64496'])):
            res = analyze(
                aliases=[alias('DYN', atype, content)],
                rules=[rule('block dyn', action='block', source_net='DYN'),
                       rule('pass host', source_net='192.0.2.10')])
            self.assertClean(res, 'pass host')

    def test_same_opaque_alias_on_both_sides_is_shadowing(self):
        res = analyze(
            aliases=[alias('COUNTRIES', 'geoip', ['NL'])],
            rules=[rule('block countries', action='block', interface='wan', source_net='COUNTRIES'),
                   rule('pass countries web', interface='wan', source_net='COUNTRIES', protocol='TCP',
                        destination_port='443')])
        self.assertEqual(len(findings_of(res, 'shadowed', 'pass countries web')), 1)

    def test_partial_port_overlap(self):
        res = analyze(rules=[
            rule('block 80-100', action='block', protocol='TCP', destination_port='80-100'),
            rule('pass 90-110', protocol='TCP', destination_port='90-110'),
        ])
        self.assertClean(res, 'pass 90-110')

    def test_partial_address_overlap(self):
        res = analyze(rules=[
            rule('block half', action='block', source_net='192.0.2.0/26'),
            rule('pass lan net', source_net='lan'),
        ])
        self.assertClean(res, 'pass lan net')

    def test_different_interface(self):
        res = analyze(rules=[
            rule('block lan', action='block', interface='lan'),
            rule('pass dmz', interface='opt1'),
        ])
        self.assertClean(res, 'pass dmz')

    def test_different_direction(self):
        res = analyze(rules=[
            rule('block out', action='block', interface='', direction='out'),
            rule('pass in', interface='lan'),
        ])
        self.assertClean(res, 'pass in')

    def test_floating_non_quick_does_not_shadow(self):
        res = analyze(rules=[
            rule('float block nonquick', action='block', interface='', quick='0'),
            rule('pass lan host', source_net='192.0.2.10'),
        ])
        self.assertClean(res, 'pass lan host')

    def test_protocol_mismatch(self):
        res = analyze(rules=[
            rule('block tcp', action='block', protocol='TCP'),
            rule('pass any proto', source_net='192.0.2.10'),
        ])
        self.assertClean(res, 'pass any proto')

    def test_family_mismatch(self):
        res = analyze(rules=[
            rule('block v4', action='block', ipprotocol='inet'),
            rule('pass v6', ipprotocol='inet6'),
        ])
        self.assertClean(res, 'pass v6')

    def test_schedule_limits_cover(self):
        res = analyze(rules=[
            rule('block office hours', action='block', sched='OfficeHours'),
            rule('pass host', source_net='192.0.2.10'),
        ])
        self.assertClean(res, 'pass host')

    def test_dynamic_wan_net_does_not_cover(self):
        # interface network of an interface without static address is opaque
        res = analyze(rules=[
            rule('block vpn net', action='block', interface='opt3', source_net='opt3'),
            rule('pass vpn host', interface='opt3', source_net='192.0.2.250'),
        ])
        self.assertClean(res, 'pass vpn host')

    def test_alias_exclusion_is_respected(self):
        res = analyze(
            aliases=[alias('LAN_NO_10', 'network', ['192.0.2.0/25', '!192.0.2.10'])],
            rules=[rule('block lan but 10', action='block', source_net='LAN_NO_10'),
                   rule('pass 10', source_net='192.0.2.10'),
                   rule('pass 11', source_net='192.0.2.11')])
        self.assertClean(res, 'pass 10')
        self.assertEqual(len(findings_of(res, 'shadowed', 'pass 11')), 1)

    def test_inverted_source(self):
        res = analyze(rules=[
            rule('block not lan', action='block', source_net='lan', source_not='1'),
            rule('pass lan host', source_net='192.0.2.10'),
            rule('pass outside', source_net='203.0.113.9'),
        ])
        self.assertClean(res, 'pass lan host')
        self.assertEqual(len(findings_of(res, 'shadowed', 'pass outside')), 1)

    def test_disabled_rule_does_not_shadow(self):
        res = analyze(rules=[
            rule('disabled block', action='block', enabled='0'),
            rule('pass host', source_net='192.0.2.10'),
        ])
        self.assertClean(res, 'pass host')


class TestRedundantDuplicate(unittest.TestCase):
    def test_redundant_by_earlier(self):
        res = analyze(rules=[
            rule('pass lan net', source_net='lan'),
            rule('pass host https', source_net='192.0.2.10', protocol='TCP', destination_port='443'),
        ])
        found = findings_of(res, 'redundant', 'pass host https')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['severity'], 'medium')

    def test_duplicate(self):
        res = analyze(rules=[
            rule('dns a', source_net='lan', protocol='TCP/UDP', destination_port='53'),
            rule('dns b', source_net='lan', protocol='TCP/UDP', destination_port='domain'),
        ])
        found = findings_of(res, 'duplicate', 'dns b')
        self.assertEqual(len(found), 1)
        self.assertEqual(findings_of(res, 'redundant', 'dns b'), [])

    def test_redundant_by_later_without_conflict(self):
        res = analyze(rules=[
            rule('pass host first', source_net='192.0.2.10', protocol='TCP', destination_port='443'),
            rule('pass lan net later', source_net='lan'),
        ])
        found = findings_of(res, 'redundant', 'pass host first')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['severity'], 'low')

    def test_not_redundant_when_conflict_in_between(self):
        res = analyze(rules=[
            rule('pass host first', source_net='192.0.2.10', protocol='TCP', destination_port='443'),
            rule('block https', action='block', protocol='TCP', destination_port='443'),
            rule('pass lan net later', source_net='lan'),
        ])
        self.assertEqual(findings_of(res, 'redundant', 'pass host first'), [])


class TestPermissiveAndWan(unittest.TestCase):
    def test_any_any_on_wan_is_high(self):
        res = analyze(rules=[rule('wan allow all', interface='wan')])
        found = findings_of(res, 'permissive', 'wan allow all')
        self.assertEqual(found[0]['severity'], 'high')

    def test_any_any_on_lan_is_medium(self):
        res = analyze(rules=[rule('lan allow all', interface='lan')])
        self.assertEqual(findings_of(res, 'permissive', 'lan allow all')[0]['severity'], 'medium')

    def test_lan_net_to_any_is_not_permissive(self):
        res = analyze(rules=[rule('default lan', source_net='lan')])
        self.assertEqual(findings_of(res, 'permissive'), [])

    def test_wan_port_forward_any_source_is_info(self):
        res = analyze(rules=[rule('wan web dmz', interface='wan', protocol='TCP',
                                  destination_net='192.0.2.140', destination_port='443')])
        self.assertEqual(findings_of(res, 'permissive', 'wan web dmz')[0]['severity'], 'info')
        self.assertEqual(findings_of(res, 'wan_exposed'), [])

    def test_wan_any_port(self):
        res = analyze(rules=[rule('wan dmz all ports', interface='wan', destination_net='192.0.2.140')])
        self.assertEqual(findings_of(res, 'permissive', 'wan dmz all ports')[0]['severity'], 'medium')

    def test_wan_gui_exposed_high(self):
        res = analyze(rules=[rule('wan gui', interface='wan', protocol='TCP', destination_net='wanip',
                                  destination_port='8443')])
        found = findings_of(res, 'wan_exposed', 'wan gui')
        self.assertEqual(found[0]['severity'], 'high')
        self.assertEqual(found[0]['evidence']['admin_ports'], [8443])

    def test_wan_ssh_restricted_source_medium(self):
        res = analyze(rules=[rule('wan ssh admin', interface='wan', protocol='TCP', source_net='203.0.113.4',
                                  destination_net='(self)', destination_port='22')])
        self.assertEqual(findings_of(res, 'wan_exposed', 'wan ssh admin')[0]['severity'], 'medium')

    def test_wan_vpn_port_low(self):
        res = analyze(rules=[rule('wireguard', interface='wan', protocol='UDP', destination_net='wanip',
                                  destination_port='51820')])
        self.assertEqual(findings_of(res, 'wan_exposed', 'wireguard')[0]['severity'], 'low')

    def test_wan_any_destination_admin_port(self):
        res = analyze(rules=[rule('wan https any', interface='wan', protocol='TCP', destination_port='8443')])
        self.assertEqual(findings_of(res, 'wan_exposed', 'wan https any')[0]['severity'], 'high')

    def test_outbound_wan_not_exposed(self):
        res = analyze(rules=[rule('wan out', interface='wan', direction='out', protocol='TCP',
                                  destination_net='wanip', destination_port='22')])
        self.assertEqual(findings_of(res, 'wan_exposed'), [])

    def test_lan_gui_not_wan_exposed(self):
        res = analyze(rules=[rule('lan gui', protocol='TCP', destination_net='lanip', destination_port='8443')])
        self.assertEqual(findings_of(res, 'wan_exposed'), [])


class TestHousekeeping(unittest.TestCase):
    def test_disabled_old_rule_is_low(self):
        res = analyze(rules=[
            rule('old disabled', enabled='0', audit={'updated': {'time': FIXED_NOW - 200 * 86400}}),
            rule('new disabled', enabled='0', audit={'updated': {'time': FIXED_NOW - 2 * 86400}}),
        ])
        self.assertEqual(findings_of(res, 'disabled', 'old disabled')[0]['severity'], 'low')
        self.assertEqual(findings_of(res, 'disabled', 'old disabled')[0]['evidence']['days_since_change'], 200)
        self.assertEqual(findings_of(res, 'disabled', 'new disabled')[0]['severity'], 'info')

    def test_no_description(self):
        res = analyze(rules=[rule('x', description='', source_net='192.0.2.10'), rule('described')])
        found = findings_of(res, 'no_description')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['rules'][0]['uuid'], uuid_for('x'))

    def test_empty_alias_referenced(self):
        res = analyze(aliases=[alias('EMPTY_HOSTS', 'host', ''), alias('EMPTY_PORTS', 'port', '')],
                      rules=[rule('uses empty', source_net='EMPTY_HOSTS'),
                             rule('uses empty ports', protocol='TCP', destination_port='EMPTY_PORTS')])
        found = {f['aliases'][0]: f for f in findings_of(res, 'empty_alias')}
        # host tables may be filled at runtime (alias API): low; port aliases are static macros: medium
        self.assertEqual(found['EMPTY_HOSTS']['severity'], 'low')
        self.assertEqual(found['EMPTY_PORTS']['severity'], 'medium')
        # rules matching nothing are not reported as shadowed/never_matches
        self.assertEqual(findings_of(res, 'never_matches'), [])

    def test_unused_alias(self):
        res = analyze(
            aliases=[alias('ORPHAN', 'host', ['192.0.2.50']), alias('USED', 'host', ['192.0.2.51']),
                     alias('NESTED', 'host', ['192.0.2.52']), alias('PARENT', 'host', ['NESTED']),
                     alias('NAT_ONLY', 'host', ['192.0.2.53'])],
            rules=[rule('uses USED', source_net='USED'), rule('uses PARENT', source_net='PARENT')],
            extra='<nat><rule><destination><address>NAT_ONLY</address></destination><descr>ORPHAN</descr>'
                  '</rule></nat>')
        unused = sorted(f['aliases'][0] for f in findings_of(res, 'unused_alias'))
        self.assertEqual(unused, ['ORPHAN'])

    def test_inactive_unknown_alias(self):
        res = analyze(rules=[rule('broken ref', source_net='DOES_NOT_EXIST')])
        found = findings_of(res, 'inactive', 'broken ref')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['severity'], 'medium')

    def test_dynamic_plugin_alias_is_opaque_not_inactive(self):
        res = analyze(rules=[rule('qfeeds block', action='block', source_net='__qfeeds_malware_ip'),
                             rule('pass host', source_net='192.0.2.10')])
        self.assertEqual(findings_of(res, 'inactive'), [])
        self.assertEqual(findings_of(res, 'shadowed'), [])

    def test_stats_confirm_rule_is_loaded(self):
        stats = {uuid_for('unknown ref'): {'packets': 3}}
        res = analyze(rules=[rule('unknown ref', source_net='SOMETHING_RUNTIME')], stats=stats)
        self.assertEqual(findings_of(res, 'inactive'), [])

    def test_inactive_unknown_interface(self):
        res = analyze(rules=[rule('ghost iface', interface='opt9')])
        self.assertEqual(len(findings_of(res, 'inactive', 'ghost iface')), 1)

    def test_never_matches_family(self):
        res = analyze(rules=[rule('v4 rule v6 dst', destination_net='2001:db8:1::/64')])
        self.assertEqual(len(findings_of(res, 'never_matches', 'v4 rule v6 dst')), 1)


class TestUnused(unittest.TestCase):
    def rules(self):
        return [rule('hit rule', source_net='192.0.2.10'), rule('cold rule', source_net='192.0.2.11')]

    def test_unused_with_stats(self):
        stats = {uuid_for('hit rule'): {'pf_rules': 1, 'evaluations': 10, 'packets': 5, 'bytes': 300, 'states': 1},
                 uuid_for('cold rule'): {'pf_rules': 1, 'evaluations': 10, 'packets': 0, 'bytes': 0, 'states': 0}}
        meta = {'ruleset_loaded': '2026-09-01T00:00:00+00:00'}
        res = analyze(rules=self.rules(), stats=stats, stats_meta=meta)
        self.assertTrue(res['stats_available'])
        found = findings_of(res, 'unused')
        self.assertEqual([f['rules'][0]['description'] for f in found], ['cold rule'])
        self.assertEqual(found[0]['severity'], 'low')
        self.assertEqual(found[0]['evidence']['counters_since'], '2026-09-01T00:00:00+00:00')

    def test_short_window_is_info(self):
        stats = {uuid_for('hit rule'): {'packets': 5}, uuid_for('cold rule'): {'packets': 0}}
        meta = {'ruleset_loaded': '2026-10-25T00:00:00+00:00'}
        res = analyze(rules=self.rules(), stats=stats, stats_meta=meta)
        self.assertEqual(findings_of(res, 'unused')[0]['severity'], 'info')

    def test_keepcounters_window_uses_boot_and_rule_change(self):
        rules = [rule('hit rule', source_net='192.0.2.10'),
                 rule('cold rule', source_net='192.0.2.11', audit={'updated': {'time': FIXED_NOW - 3 * 86400}})]
        stats = {uuid_for('hit rule'): {'packets': 5}, uuid_for('cold rule'): {'packets': 0}}
        meta = {'ruleset_loaded': '2026-10-25T23:00:00+00:00', 'boot_time': '2026-08-01T00:00:00+00:00'}
        res = analyze(rules=rules, stats=stats, stats_meta=meta, system_extra='<keepcounters>1</keepcounters>')
        found = findings_of(res, 'unused')[0]
        self.assertTrue(found['evidence']['keepcounters'])
        self.assertEqual(found['evidence']['window_days'], 3)
        self.assertEqual(found['severity'], 'info')
        rules[1] = rule('cold rule 2', source_net='192.0.2.11')
        stats[uuid_for('cold rule 2')] = {'packets': 0}
        res = analyze(rules=rules, stats=stats, stats_meta=meta, system_extra='<keepcounters>1</keepcounters>')
        found = findings_of(res, 'unused')[0]
        self.assertEqual(found['evidence']['counters_since'], '2026-08-01T00:00:00+00:00')
        self.assertEqual(found['severity'], 'low')

    def test_no_stats_no_unused(self):
        res = analyze(rules=self.rules())
        self.assertFalse(res['stats_available'])
        self.assertEqual(findings_of(res, 'unused'), [])

    def test_rule_missing_from_ruleset(self):
        stats = {uuid_for('hit rule'): {'packets': 5}}
        res = analyze(rules=self.rules(), stats=stats, stats_meta={})
        found = findings_of(res, 'inactive', 'cold rule')
        self.assertEqual(found[0]['severity'], 'low')


class TestContract(unittest.TestCase):
    def test_shape_and_stable_ids(self):
        rules = [rule('block all lan', action='block'), rule('web host', source_net='192.0.2.10'),
                 rule('', description='')]
        a = analyze(rules=rules)
        b = analyze(rules=rules)
        self.assertEqual([f['id'] for f in a['findings']], [f['id'] for f in b['findings']])
        self.assertEqual(set(a), {'version', 'generated', 'duration_ms', 'summary', 'stats_available', 'stats',
                                  'findings'})
        self.assertEqual(set(a['stats']), {'source', 'ruleset_loaded', 'boot_time', 'keepcounters',
                                           'keepcounters_source', 'counters_since', 'settings_page'})
        self.assertEqual(set(a['summary']), {'rules', 'enabled', 'findings', 'by_severity'})
        self.assertEqual(set(a['summary']['by_severity']), {'high', 'medium', 'low', 'info'})
        self.assertEqual(a['summary']['findings'], len(a['findings']))
        for item in a['findings']:
            self.assertEqual(set(item), {'id', 'type', 'severity', 'title', 'detail', 'recommendation', 'rules',
                                         'aliases', 'evidence'})
            self.assertIn(item['severity'], ('high', 'medium', 'low', 'info'))
            for r in item['rules']:
                self.assertEqual(set(r), {'uuid', 'source', 'interface', 'direction', 'action', 'sequence',
                                          'description', 'summary', 'quick', 'enabled', 'priority_group',
                                          'ref'})
        self.assertEqual(len({f['id'] for f in a['findings']}), len(a['findings']))


    def test_pair_order_mode_and_rule_fields(self):
        res = analyze(rules=[rule('group block', action='block', interface='INTERNAL'),
                             rule('float pass', interface='lan,opt1', quick='0', source_net='192.0.2.10'),
                             rule('lan pass', source_net='192.0.2.10')])
        found = findings_of(res, 'shadowed', 'lan pass')[0]
        self.assertEqual(found['evidence']['mode'], 'earlier_quick')
        affected, covering = found['rules']
        self.assertEqual((affected['description'], covering['description']), ('lan pass', 'group block'))
        self.assertEqual(affected['priority_group'], 'interface')
        self.assertEqual(covering['priority_group'], 'group')
        self.assertEqual(affected['ref'], 'ui/firewall/filter#search=%s' % uuid_for('lan pass'))
        self.assertIs(affected['quick'], True)
        self.assertIs(affected['enabled'], True)
        floating = findings_of(res, 'shadowed', 'float pass')
        self.assertEqual(floating[0]['rules'][0]['priority_group'], 'floating')
        self.assertIs(floating[0]['rules'][0]['quick'], False)
        self.assertEqual(floating[0]['evidence']['mode'], 'later_overrides')
        disabled = findings_of(res, 'disabled')
        self.assertEqual(disabled, [])

    def test_legacy_ref_without_legacy_page(self):
        res = analyze(rules=[rule('mvc block lan', action='block')],
                      legacy=[legacy_rule('legacy pass', source='<address>192.0.2.10</address>')])
        entry = findings_of(res, 'shadowed', 'legacy pass')[0]['rules'][0]
        self.assertEqual(entry['source'], 'legacy')
        self.assertEqual(entry['ref'], 'ui/firewall/migration')  # no firewall_rules.php on 26.x

    def test_legacy_ref_with_legacy_page(self):
        from engine.report import rule_ref
        from engine.rules import Rule
        r = Rule()
        r.source, r.index, r.fields = 'legacy', 3, {'interface': 'opt1', 'floating': '0'}
        self.assertEqual(rule_ref(r, legacy_page=True), 'firewall_rules_edit.php?if=opt1&id=3')
        r.fields['floating'] = '1'
        self.assertEqual(rule_ref(r, legacy_page=True), 'firewall_rules_edit.php?if=FloatingRules&id=3')

    def test_stats_block(self):
        meta = {'source': 'file', 'ruleset_loaded': '2026-10-25T00:00:00+00:00',
                'boot_time': '2026-08-01T00:00:00+00:00'}
        res = analyze(rules=[rule('r')], stats={uuid_for('r'): {'packets': 1}}, stats_meta=meta)
        self.assertEqual(res['stats'], {'source': 'file', 'ruleset_loaded': '2026-10-25T00:00:00+00:00',
                                        'boot_time': '2026-08-01T00:00:00+00:00', 'keepcounters': False,
                                        'keepcounters_source': None,
                                        'counters_since': '2026-10-25T00:00:00+00:00',
                                        'settings_page': 'system_advanced_firewall.php'})
        res = analyze(rules=[rule('r')], stats={uuid_for('r'): {'packets': 1}}, stats_meta=meta,
                      system_extra='<keepcounters>1</keepcounters>')
        self.assertEqual(res['stats']['counters_since'], '2026-08-01T00:00:00+00:00')
        self.assertTrue(res['stats']['keepcounters'])
        res = analyze(rules=[rule('r')])
        self.assertEqual(res['stats']['source'], None)
        self.assertEqual(res['stats']['counters_since'], None)


if __name__ == '__main__':
    unittest.main()
