"""
health collector: system / memory / temperature / disk / pf / gateways (dpinger) / interfaces / services /
processes / WireGuard (keys never stored) / ARP, rates and CPU since the previous run, gateway alerts from the
log (incremental), reboot event, broken probe isolation.
"""

import unittest

from chelpers import SECRETS, T0, Sandbox, fixture

from collect import common, health, query


class TestHealth(Sandbox):
    def setUp(self):
        super().setUp()
        self.write('/var/log/gateways/latest.log', fixture('gateways.log'))

    def latest(self):
        return query.Query(self.ctx).health_latest()['metrics']

    def test_first_sample(self):
        result = health.run(self.ctx, self.settings)
        self.assertEqual(result['errors'], [])
        m = self.latest()
        self.assertEqual(m['load_1m'], 0.74)
        self.assertAlmostEqual(m['mem_total_mb'], 34036920320 / 1048576, 0)
        self.assertEqual(m['temp_cpu'], 51.0)
        self.assertEqual(m['temp_cpu_max'], 52.0)
        self.assertEqual(m['temp_acpi'], 27.9)
        self.assertEqual(m['pf_states'], 1415)
        self.assertEqual(m['pf_states_limit'], 3246000)
        self.assertEqual(m['zpool:zroot:cap_pct'], 7)
        self.assertEqual(m['zpool:zroot:healthy'], 1)
        self.assertEqual(m['swap_used_mb'], 1.0)
        self.assertEqual(m['gw:WAN_B:rtt_ms'], 14.43)
        self.assertEqual(m['gw:WAN_C:loss_pct'], 5.0)
        self.assertEqual(m['if:igc0:rx'], 33545458234)
        self.assertEqual(m['if:pppoe1:errors'], 3)
        self.assertNotIn('if:lo0:rx', m)
        self.assertEqual(m['services_stopped'], 2)
        self.assertEqual(m['proc:unbound:res_mb'], 200.0)
        self.assertEqual(m['proc:suricata:cpu'], 12.0)
        self.assertEqual(m['wg:phone:rx'], 1000)
        self.assertEqual(m['wg:phone:handshake_s'], 60)
        self.assertEqual(m['hosts_arp'], 2)
        self.assertIn('mbuf_clusters_pct', m)
        events = query.Query(self.ctx).health_events('2026-10-26', '2026-10-26')
        kinds = sorted((e['kind'], e['source']) for e in events)
        self.assertEqual(kinds, [('gateway', 'WAN_B'), ('gateway', 'WAN_B'),
                                 ('service_stopped', 'dpinger/WAN_C'), ('service_stopped', 'suricata')])

    def test_rates_and_cpu_between_runs(self):
        health.run(self.ctx, self.settings)
        self.clock.now = T0 + 3600
        self.runner.sysctl['kern.cp_time'] = '1300 0 600 100 10000'     # +300 user, +100 sys, +1600 idle
        pf = self.runner.outputs[('/sbin/pfctl', '-si')]
        self.runner.set(('/sbin/pfctl', '-si'), pf.replace('2585985', str(2585985 + 36000)))
        net = self.runner.outputs[('/usr/bin/netstat', '-ibdn')]
        self.runner.set(('/usr/bin/netstat', '-ibdn'), net.replace('   33545458234', '   33545908234'))
        health.run(self.ctx, self.settings)
        m = self.latest()
        self.assertEqual(m['cpu_idle_pct'], 80.0)
        self.assertEqual(m['cpu_user_pct'], 15.0)
        self.assertEqual(m['pf:match_rate'], 10.0)
        self.assertEqual(m['if:igc0:rx_bps'], 1000.0)          # 450000 bytes * 8 / 3600 s
        series = query.Query(self.ctx).health_series('pf_states,gw:*:rtt_ms', '24h', 'now')
        self.assertEqual(len(series['pf_states']), 2)
        self.assertEqual(sorted(series), ['gw:WAN_B:rtt_ms', 'gw:WAN_C:rtt_ms', 'pf_states'])

    def test_gateway_log_incremental_and_reboot(self):
        health.run(self.ctx, self.settings)
        self.clock.now = T0 + 3600
        self.runner.sysctl['kern.boottime'] = '{ sec = %d, usec = 0 } Mon Oct 26 12:30:00 2026' % (T0 + 1800)
        result = health.run(self.ctx, self.settings)
        self.assertEqual(result['events'], 3)                  # 2 stopped services + reboot, no repeated alerts
        events = query.Query(self.ctx).health_events('2026-10-26', '2026-10-26', kind='reboot')
        self.assertEqual(len(events), 1)

    def test_no_wireguard_key_and_ignore_services(self):
        self.settings['ignore_services'] = ['dpinger/WAN_C']
        health.run(self.ctx, self.settings)
        self.assertEqual(self.latest()['services_stopped'], 1)
        with open(self.ctx.db['health'], 'rb') as handle:
            raw = handle.read()
        for secret in SECRETS:
            self.assertNotIn(secret.encode(), raw)
        con = common.connect_ro(self.ctx.db['health'])
        keys = [k for (k,) in con.execute("SELECT key FROM metrics WHERE key LIKE 'wg:%'")]
        con.close()
        self.assertIn('wg:wg0_UNKNOWNP:rx', keys)
        self.assertFalse(any('SECRET' in k for k in keys))

    def test_broken_probe_does_not_lose_the_rest(self):
        self.ctx.sources['dpinger'] = lambda: 1 / 0
        result = health.run(self.ctx, self.settings)
        self.assertTrue(any(e.startswith('gateways:') for e in result['errors']))
        self.assertIn('pf_states', self.latest())


if __name__ == '__main__':
    unittest.main()
