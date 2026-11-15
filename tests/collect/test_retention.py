"""
retention: hourly -> daily compaction after compact_after_days, deletion after retention_days, the size limit
(oldest day first, never today) and the daily maintenance gate.
"""

import unittest

from chelpers import T0, Sandbox

from collect import common, query, store


class TestRetention(Sandbox):
    def fill_flows(self, days, per_hour=1):
        con = store.open_db(self.ctx, 'flows')
        rows = []
        for d in range(days):
            for h in range(0, 24, 6):
                hour = common.hour_of(T0 - d * 86400) - h * 3600
                for i in range(per_hour):
                    rows.append((hour, 'pppoe1', 'in', 'block', 'tcp', '203.0.113.%d' % (i % 250), '198.51.100.1',
                                 str(1000 + i), 'r' * 32, None, 2, hour, hour))
        con.executemany('INSERT OR IGNORE INTO blocks_hourly (hour, iface, dir, action, proto, src, dst, dport, rid,'
                        ' cc, n, first, last) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', rows)
        con.executemany('INSERT OR IGNORE INTO dns_hourly (hour, client, domain, action, n, nx) VALUES (?,?,?,?,?,?)',
                        [(r[0], '192.168.1.20', 'd%s.example.com' % r[7], 'pass', 3, 0) for r in rows])
        con.commit()
        return con, sum(r[10] for r in rows)

    def test_compaction_keeps_totals(self):
        con, total = self.fill_flows(10)
        before = sum(p['blocks'] for p in query.Query(self.ctx).blocks_series('30d', 'now', bucket='day'))
        self.assertEqual(before, total)
        out = store.maintain(self.ctx, 'flows', con, self.settings, T0)
        self.assertGreater(out['compacted']['blocks'], 0)
        self.assertEqual(con.execute('SELECT count(*) FROM blocks_hourly WHERE hour < ?',
                                     (common.local_midnight(T0 - 7 * 86400),)).fetchone()[0], 0)
        con.close()
        q = query.Query(self.ctx)
        self.assertEqual(sum(p['blocks'] for p in q.blocks_series('30d', 'now', bucket='day')), total)
        hourly = q.blocks_series('9d', 'now', bucket='hour')
        self.assertTrue(any(p.get('daily') for p in hourly))
        self.assertEqual(sum(p['blocks'] for p in hourly),
                         sum(p['blocks'] for p in q.blocks_series('9d', 'now', bucket='day')))
        self.assertEqual(q.top_domains('30d', 'now', 1)[0]['queries'], 120)       # 4 slots x 10 days x 3

    def test_retention_and_gate(self):
        con, _ = self.fill_flows(5)
        con.execute("INSERT INTO blocks_daily (day, iface, dir, action, proto, src, dst, dport, rid, n) "
                    "VALUES ('2026-01-01', 'pppoe1', 'in', 'block', 'tcp', '203.0.113.1', '-', '22', '-', 5)")
        con.commit()
        self.assertIsNotNone(store.maintain(self.ctx, 'flows', con, self.settings, T0))
        self.assertIsNone(store.maintain(self.ctx, 'flows', con, self.settings, T0 + 60))    # once a day
        self.assertEqual(con.execute("SELECT count(*) FROM blocks_daily WHERE day = '2026-01-01'").fetchone()[0], 0)
        con.close()

    def test_size_limit_drops_oldest_days(self):
        con, _ = self.fill_flows(20, per_hour=200)
        store.maintain(self.ctx, 'flows', con, self.settings, T0)
        size = common.db_size_mb(self.ctx.db['flows'])
        self.settings['max_mb_flows'] = max(1, int(size * 0.6))
        out = store.maintain(self.ctx, 'flows', con, self.settings, T0, force=True)
        self.assertTrue(out['size_dropped'])
        self.assertLessEqual(common.db_size_mb(self.ctx.db['flows']), self.settings['max_mb_flows'] + 0.5)
        self.assertLess(min(out['size_dropped']), common.day_of(T0 - 10 * 86400))
        self.assertNotIn(common.day_of(T0), out['size_dropped'])
        con.close()

    def test_health_compaction(self):
        con = store.open_db(self.ctx, 'health')
        for d in range(12):
            for h in range(24):
                con.execute('INSERT INTO metrics (ts, key, value) VALUES (?,?,?)',
                            (int(T0 - d * 86400 - h * 3600), 'temp_cpu', 40 + h % 10))
        con.commit()
        store.maintain(self.ctx, 'health', con, self.settings, T0)
        self.assertGreater(con.execute('SELECT count(*) FROM metrics_daily').fetchone()[0], 3)
        con.close()
        series = query.Query(self.ctx).health_series(['temp_cpu'], '12d', 'now', bucket='day', agg='max')
        self.assertTrue(all(p['value'] == 49 for p in series['temp_cpu'][1:-1]))


if __name__ == '__main__':
    unittest.main()
