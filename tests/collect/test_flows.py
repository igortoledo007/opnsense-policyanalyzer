"""
flows collector: filterlog parsing and hourly aggregation, incremental marker (append, partial line, daily
rotation found by the inode, truncation), DNS from the Unbound DuckDB (cursor, lag, first run since local
midnight, row limit), from the resolver log and from the dnsmasq log.
"""

import os
import unittest

from chelpers import T0, Sandbox, fixture

from collect import common, flows, query

LINE = ('<134>1 2026-10-26T%s-03:00 fw.example.lan filterlog 570 - [meta sequenceId="9"] '
        '82,,,02f4bab031b57d1e30553ce08e0ec131,pppoe1,match,block,in,4,0x0,,52,1,0,none,6,tcp,44,%s,'
        '198.51.100.1,40000,%s,0,S,1,,1024,,mss\n')


def line(clock, src='203.0.113.9', port=23):
    return (LINE % (clock, src, port)).encode()


class TestBlocks(Sandbox):
    def setUp(self):
        super().setUp()
        self.link_filter(data=fixture('filter.log'))

    def rows(self):
        con = common.connect_ro(self.ctx.db['flows'])
        rows = con.execute('SELECT hour, iface, dir, action, proto, src, dst, dport, rid, n FROM blocks_hourly '
                           'ORDER BY hour, src, dport').fetchall()
        con.close()
        return rows

    def test_first_run_aggregates_blocks_only(self):
        result = flows.run(self.ctx, self.settings)
        self.assertEqual(result['blocks'], 6)                     # pass line, garbage and broken csv ignored
        rows = self.rows()
        ssh = [r for r in rows if r[5] == '203.0.113.5' and r[7] == '22']
        self.assertEqual(ssh[0][9], 2)                            # two SYN to 22 in the same hour
        self.assertEqual(ssh[0][1:5], ('pppoe1', 'in', 'block', 'tcp'))
        v6 = [r for r in rows if r[5] == '2001:db8::bad'][0]
        self.assertEqual((v6[7], v6[4]), ('445', 'tcp'))
        self.assertEqual(sum(r[9] for r in rows), 6)
        con = common.connect_ro(self.ctx.db['flows'])
        self.assertEqual(common.meta_get(con, 'blocks_since'), common.hour_of(common.parse_time(
            '2026-10-26T10:00:01-03:00')))
        con.close()

    def test_incremental_append_and_partial_line(self):
        flows.run(self.ctx, self.settings)
        self.assertEqual(flows.run(self.ctx, self.settings)['blocks'], 0)
        name = '/var/log/filter/filter_20261026.log'
        self.append(name, line('11:30:00') + line('11:31:00')[:40])          # one full line + a partial one
        self.assertEqual(flows.run(self.ctx, self.settings)['blocks'], 1)
        self.append(name, line('11:31:00')[40:])
        self.assertEqual(flows.run(self.ctx, self.settings)['blocks'], 1)   # the partial line, once
        self.assertEqual(sum(r[9] for r in self.rows()), 8)

    def test_rotation_reads_rest_of_previous_file(self):
        flows.run(self.ctx, self.settings)
        self.append('/var/log/filter/filter_20261026.log', line('23:59:59'))
        self.link_filter('20261027', line('00:00:01').replace(b'2026-10-26', b'2026-10-27'))
        self.clock.now = T0 + 86400
        result = flows.run(self.ctx, self.settings)
        self.assertEqual(result['blocks'], 2)
        self.assertEqual(result['filter']['files'], ['filter_20261026.log', 'filter_20261027.log'])

    def test_truncated_file_restarts(self):
        flows.run(self.ctx, self.settings)
        self.write('/var/log/filter/filter_20261026.log', line('11:50:00'))
        self.assertEqual(flows.run(self.ctx, self.settings)['blocks'], 1)

    def test_missing_log_is_not_an_error(self):
        os.unlink(self.path('/var/log/filter/latest.log'))
        result = flows.run(self.ctx, self.settings)
        self.assertEqual((result['status'], result['blocks']), ('ok', 0))
        self.assertTrue(result['filter']['missing'])


class TestDns(Sandbox):
    def setUp(self):
        super().setUp()
        self.calls = []
        self.data = []

        def rows(since, until, limit):
            self.calls.append((since, until, limit))
            return sorted([r for r in self.data if since < r[0] <= until], key=lambda r: r[0])[:limit]
        self.ctx.sources['unbound_rows'] = rows

    def dns(self):
        con = common.connect_ro(self.ctx.db['flows'])
        rows = con.execute('SELECT client, domain, action, n, nx FROM dns_hourly ORDER BY domain').fetchall()
        con.close()
        return rows

    def test_duckdb_cursor_lag_and_first_run(self):
        midnight = int(common.local_midnight(T0))
        self.data = [(midnight - 5, '192.168.1.9', 'old.example.com.', 0, 0),          # yesterday: not read
                     (int(T0) - 3600, '192.168.1.20', 'www.example.com.', 0, 0),
                     (int(T0) - 3599, '192.168.1.20', 'WWW.example.com', 0, 0),
                     (int(T0) - 1000, '192.168.1.21', 'ads.example.net.', 1, 0),
                     (int(T0) - 900, '192.168.1.21', 'nx.example.org.', 0, 3),
                     (int(T0) - 30, '192.168.1.21', 'late.example.org.', 0, 0)]        # inside the lag
        result = flows.run(self.ctx, self.settings)
        self.assertEqual(self.calls[0][:2], (midnight - 1, int(T0) - common.DNS_LAG))
        self.assertEqual(result['dns'], 4)
        self.assertEqual(self.dns(), [('192.168.1.21', 'ads.example.net', 'block', 1, 0),
                                      ('192.168.1.21', 'nx.example.org', 'pass', 1, 1),
                                      ('192.168.1.20', 'www.example.com', 'pass', 2, 0)])
        self.clock.now = T0 + 300
        self.assertEqual(flows.run(self.ctx, self.settings)['dns'], 1)                 # the late one, once
        self.assertEqual(flows.run(self.ctx, self.settings)['dns'], 0)
        con = common.connect_ro(self.ctx.db['flows'])
        self.assertEqual(common.meta_get(con, 'dns_since'), midnight)
        con.close()

    def test_row_limit_keeps_whole_seconds(self):
        common.DNS_MAX_ROWS, saved = 3, common.DNS_MAX_ROWS
        self.addCleanup(setattr, common, 'DNS_MAX_ROWS', saved)
        t = int(T0) - 2000
        self.data = [(t, 'c', 'a.example', 0, 0), (t + 1, 'c', 'b.example', 0, 0), (t + 1, 'c', 'c.example', 0, 0),
                     (t + 1, 'c', 'd.example', 0, 0), (t + 2, 'c', 'e.example', 0, 0)]
        first = flows.run(self.ctx, self.settings)
        self.assertEqual((first['dns'], first['dns_info']['complete']), (1, False))
        common.DNS_MAX_ROWS = 10
        self.assertEqual(flows.run(self.ctx, self.settings)['dns'], 4)
        self.assertEqual(sum(r[3] for r in self.dns()), 5)

    def test_resolver_log_without_duckdb(self):
        self.ctx.sources['unbound_rows'] = lambda since, until, limit: None
        self.write('/var/log/resolver/latest.log', fixture('resolver.log'))
        result = flows.run(self.ctx, self.settings)
        self.assertEqual(result['dns_info']['source'], 'unbound-log')
        rows = self.dns()
        self.assertIn(('192.168.1.20', 'ads.example.net', 'block', 1, 1), rows)
        self.assertIn(('192.168.1.20', 'www.example.com', 'pass', 1, 0), rows)
        self.assertIn(('192.168.1.21', 'mail.example.org', 'pass', 1, 0), rows)
        self.assertEqual(len(rows), 3)

    def test_dnsmasq_log(self):
        with open(self.path('/conf/config.xml')) as handle:
            cfg = handle.read()
        cfg = cfg.replace('<enabled>1</enabled><stats>1</stats>', '<enabled>0</enabled>').replace(
            '<dnsmasq><enable>0</enable></dnsmasq>', '<dnsmasq><enable>1</enable></dnsmasq>')
        self.write('/conf/config.xml', cfg, 'w')
        self.write('/var/log/dnsmasq/latest.log', fixture('dnsmasq.log'))
        result = flows.run(self.ctx, self.settings)
        self.assertEqual(result['dns_info']['source'], 'dnsmasq-log')
        self.assertEqual(self.dns(), [('192.168.1.21', 'nope.example.org', 'pass', 1, 1),
                                      ('192.168.1.21', 'tracker.example.net', 'block', 1, 0),
                                      ('192.168.1.20', 'www.example.com', 'pass', 1, 0)])

    def test_dns_source_none(self):
        self.settings['dns_source'] = 'none'
        self.assertEqual(flows.run(self.ctx, self.settings)['dns_info']['source'], 'none')


class TestQueryFlows(Sandbox):
    def setUp(self):
        super().setUp()
        self.link_filter(data=fixture('filter.log'))
        self.ctx.sources['unbound_rows'] = lambda s, u, l: [
            (int(T0) - 3600, '192.168.1.20', 'www.example.com.', 0, 0),
            (int(T0) - 3500, '192.168.1.20', 'ads.example.net', 1, 3),
            (int(T0) - 3400, '192.168.1.21', 'www.example.com', 0, 0)]
        flows.run(self.ctx, self.settings)
        self.q = query.Query(self.ctx)

    def test_series_filled(self):
        series = self.q.blocks_series('2026-10-26T08:00:00', '2026-10-26T12:00:00')
        self.assertEqual([p['blocks'] for p in series], [0, 0, 4, 2])
        self.assertEqual(series[2]['t'], '2026-10-26T10:00:00-03:00')
        wan_in = self.q.blocks_series('2026-10-26', '2026-10-26', bucket='day', wan_only=True, direction='in')
        self.assertEqual([p['blocks'] for p in wan_in], [5])

    def test_tops(self):
        self.assertEqual(self.q.top_sources('2026-10-26', '2026-10-26', 1)[0],
                         {'ip': '203.0.113.5', 'blocks': 3, 'ports': 2, 'country': None})
        self.assertEqual(self.q.top_ports('2026-10-26', '2026-10-26', 1)[0]['label'], 'SSH')
        self.assertEqual(self.q.top_interfaces('2026-10-26', '2026-10-26')[0]['name'], 'WAN_A')
        self.write('/tmp/rules.debug', b'block in log inet from {any} to {any} label '
                                       b'"02f4bab031b57d1e30553ce08e0ec131" # Default deny / state violation rule\n')
        self.assertEqual(self.q.top_rules('2026-10-26', '2026-10-26', 1)[0]['label'],
                         'Default deny / state violation rule')
        self.assertEqual(self.q.top_countries('2026-10-26', '2026-10-26')[0]['country'], '??')
        doms = self.q.top_domains('2026-10-26', '2026-10-26')
        self.assertEqual(doms[0], {'domain': 'www.example.com', 'queries': 2, 'clients': 2})
        self.assertEqual(self.q.top_domains('2026-10-26', '2026-10-26', action='blocked')[0]['domain'],
                         'ads.example.net')
        self.assertEqual(self.q.top_dns_clients('2026-10-26', '2026-10-26')[0]['client'], '192.168.1.20')

    def test_run_cli_validation(self):
        out = query.run_cli(self.q, 'top_ports', ['2026-10-26', '2026-10-26', '2', '1', 'in'])
        self.assertEqual(len(out['data']), 2)
        with self.assertRaises(ValueError):
            query.run_cli(self.q, 'top_ports', ["2026-10-26'; drop"])
        with self.assertRaises(ValueError):
            query.run_cli(self.q, 'nope', [])


if __name__ == '__main__':
    unittest.main()
