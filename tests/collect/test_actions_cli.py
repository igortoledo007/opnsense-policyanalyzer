"""
change actions through the plugin dispatcher (ai/changes.py + journal): collect_schedule plan / apply /
revert (the fake model.php edits the sandbox config.xml like the core cron model), collect_settings, and the
command line (run, status, query, errors, busy lock).
"""

import io
import json
import os
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout

from chelpers import Sandbox, fixture

import collect  # noqa: F401  (registers the actions)
from ai import changes, journal
from collect import actions, cli, common


class FakeModel:
    """ php model.php cron_set|cron_del <kind> and configctl cron restart, against the sandbox config.xml """

    def __init__(self, ctx):
        self.ctx = ctx
        self.calls = []

    def __call__(self, argv, timeout=120):
        self.calls.append(argv[1:] if argv[0] == self.ctx.php else argv)
        if argv[0] != self.ctx.php:
            return ''
        op, kind = argv[2], argv[3]
        tree = ET.parse(self.ctx.config_xml)
        jobs = tree.getroot().find('./OPNsense/cron/jobs')
        for job in list(jobs):
            if job.findtext('command') == actions.CRON_COMMAND and job.findtext('parameters') == kind:
                jobs.remove(job)
        if op == 'cron_set':
            job = ET.SubElement(jobs, 'job', uuid='cccccccc-0000-0000-0000-%012d' % len(self.calls))
            for tag, value in (('origin', 'PolicyAnalyzer'), ('enabled', '1'), ('minutes', actions.SCHEDULE[kind][0]),
                               ('hours', actions.SCHEDULE[kind][1]), ('command', actions.CRON_COMMAND),
                               ('parameters', kind)):
                ET.SubElement(job, tag).text = value
        tree.write(self.ctx.config_xml)
        return '{"status": "ok"}'


class ActionCase(Sandbox):
    def setUp(self):
        super().setUp()
        journal.UNDO_DIR = os.path.join(self.tmp, 'undo')
        os.makedirs(journal.UNDO_DIR)
        self.sched = changes.REGISTRY['collect_schedule']
        self.sett = changes.REGISTRY['collect_settings']
        self.model = FakeModel(self.ctx)
        self.sched.CTX, self.sched.RUN = self.ctx, staticmethod(self.model)
        self.sett.CTX = self.ctx

        def restore():
            self.sched.CTX, self.sched.RUN, self.sett.CTX = None, staticmethod(actions._run), None
        self.addCleanup(restore)


class TestSchedule(ActionCase):
    def test_plan_apply_revert(self):
        plan = changes.run('plan', 'collect_schedule', ['create'])
        self.assertEqual(plan['status'], 'ok')
        self.assertEqual(len(plan['steps']), 4)
        self.assertTrue(any('compare' in w for w in plan['warnings']))
        self.assertEqual(actions.cron_jobs(self.ctx), {})                       # plan changes nothing
        done = changes.run('apply', 'collect_schedule', ['create'])
        self.assertTrue(done['done'])
        jobs = actions.cron_jobs(self.ctx)
        self.assertEqual({k: (v['minutes'], v['hours']) for k, v in jobs.items()},
                         {'flows': ('*/5', '*'), 'health': ('7', '*'), 'config': ('3', '*')})
        self.assertIn(['cron', 'restart'], [c[1:] for c in self.model.calls if c[0].endswith('configctl')])
        self.assertEqual(changes.run('plan', 'collect_schedule', ['create'])['steps'], [])   # idempotent
        rev = changes.run('apply', 'revert', [done['journal_id']])
        self.assertEqual(rev['status'], 'ok')
        self.assertEqual(actions.cron_jobs(self.ctx), {})

    def test_revert_only_what_it_created(self):
        self.model([self.ctx.php, self.ctx.model_php, 'cron_set', 'flows'])       # created by hand before
        done = changes.run('apply', 'collect_schedule', ['create'])
        changes.run('apply', 'revert', [done['journal_id']])
        self.assertEqual(sorted(actions.cron_jobs(self.ctx)), ['flows'])

    def test_remove_and_revert(self):
        changes.run('apply', 'collect_schedule', ['create'])
        removed = changes.run('apply', 'collect_schedule', ['remove'])
        self.assertEqual(actions.cron_jobs(self.ctx), {})
        changes.run('apply', 'revert', [removed['journal_id']])
        self.assertEqual(len(actions.cron_jobs(self.ctx)), 3)

    def test_bad_args(self):
        self.assertEqual(changes.run('plan', 'collect_schedule', ['now'])['status'], 'error')


class TestSettings(ActionCase):
    def test_apply_and_revert(self):
        plan = changes.run('plan', 'collect_settings', ['retention_days=30+max_mb_flows=2048'])
        self.assertEqual(len(plan['steps']), 2)
        self.assertTrue(plan['warnings'])                       # shorter retention
        done = changes.run('apply', 'collect_settings', ['retention_days=30+max_mb_flows=2048'])
        self.assertEqual(common.load_settings(self.ctx)['retention_days'], 30)
        changes.run('apply', 'revert', [done['journal_id']])
        self.assertEqual(common.load_settings(self.ctx)['retention_days'], 90)
        self.assertFalse(os.path.exists(self.ctx.settings_file))

    def test_validation(self):
        for spec in ('retention_days=0', 'nope=1', 'dns_source=bind', 'processes=a;b'):
            self.assertEqual(changes.run('plan', 'collect_settings', [spec])['status'], 'error', spec)


class TestCli(ActionCase):
    def call(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli.main(list(args), ctx=self.ctx)
        return json.loads(buf.getvalue())

    def test_run_status_query(self):
        self.link_filter(data=fixture('filter.log'))
        out = self.call('run', 'all')
        self.assertEqual([r['status'] for r in out['runs']], ['ok', 'ok', 'ok'])
        st = self.call('status')
        self.assertTrue(st['collectors']['flows']['available'])
        self.assertEqual(st['cron'], {})
        q = self.call('query', 'top_ports', '2026-10-26', '2026-10-26', '1')
        self.assertEqual(q['data'][0]['port'], '22')
        self.assertEqual(self.call('query', 'compare', '2026-10-26', '2026-10-26')['data']['days']['2026-10-26']
                         ['blocks'], 6)
        self.assertEqual(self.call('nope')['status'], 'error')
        self.assertEqual(self.call('query', 'top_ports', 'bad value!')['status'], 'error')
        self.assertEqual(self.call('import', 'missing.db')['status'], 'error')

    def test_schedule_through_cli_and_revert_scope(self):
        done = self.call('schedule', 'apply', 'create')
        self.assertTrue(done['done'])
        self.assertEqual(self.call('revert', 'plan', done['journal_id'])['status'], 'ok')
        other = journal.create('prepare_storage', {}, {'completed': ['x']})
        self.assertEqual(self.call('revert', 'apply', other['id'])['status'], 'error')

    def test_busy_lock(self):
        self.ctx.ensure_dirs()
        with common.Lock(os.path.join(self.ctx.dir, 'flows.lock')) as lock:
            self.assertTrue(lock.acquired)
            self.assertEqual(self.call('run', 'flows')['status'], 'busy')


if __name__ == '__main__':
    unittest.main()
