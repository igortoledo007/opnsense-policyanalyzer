"""
Runner of ai/bench.py after the night of 2026-11-09: the "noturno" plan looked dead after "round matrix
started" (00:30:38). The runner was alive; its first step (load qwen2.5:3b) waited 20 min behind two weekly
reports that held the only Ollama slot with qwen3 (in their own process, invisible to the queue/brief checks, and
the %CPU check was skipped for 90 s after a step), failed with "TimeoutError: timed out" and no event at all.
Covers: the sockstat parser of the other Ollama clients, the pause for them, contention -> step back to pending,
step errors as events, a loop that survives an exception, the exit event and "start <plan> retry".
No network, no Ollama, no e-mail.
"""

import os
import shutil
import tempfile
import unittest

import ai_helpers  # noqa: F401  (import path)

from ai import bench

SOCKSTAT = """USER   COMMAND      PID FD PROTO LOCAL ADDRESS         FOREIGN ADDRESS
root   python3.13 23317  3 tcp4  127.0.0.1:45058       127.0.0.1:11434
root   python3.13 87020  6 tcp4  127.0.0.1:38125       127.0.0.1:11434
root   python3.13 37729  6 tcp4  127.0.0.1:6427        127.0.0.1:11434
root   python3.13 37729  7 tcp4  127.0.0.1:6428        127.0.0.1:11434
nobody ollama     99726  6 tcp4  127.0.0.1:11434       127.0.0.1:6427
nobody ollama     99726  8 tcp4  127.0.0.1:11434       127.0.0.1:53453
??     ??            ?? ?? tcp4  127.0.0.1:53453       127.0.0.1:11434
"""


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-bench-runner-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, 'ai-bench.db')
        self.saved = {k: getattr(bench, k) for k in ('_sh', 'ollama_clients', 'unload_all', 'SAMPLE_SECONDS',
                                                     'production_busy', 'unsafe', 'ollama_version')}
        self.addCleanup(self.restore)
        bench._sh = lambda cmd, timeout=20: ''
        bench.ollama_version = lambda: None          # the compute profile of a step never asks a real Ollama
        bench.unload_all = lambda: None
        bench.SAMPLE_SECONDS = 0
        bench.unsafe = lambda samples: None
        self.runner = bench.Runner(self.path)
        self.addCleanup(self.runner.db.close)
        self.runner.mailer = bench.Mailer(self.runner.db, sender=lambda *a: None, clock=lambda: 0)
        self.db = self.runner.db
        self.plan = bench.create_plan(self.db, 'matriz')
        self.rid = self.db.execute('SELECT id FROM rounds WHERE plan_id = ?', (self.plan,)).fetchone()[0]
        self.db.execute("UPDATE plans SET status = 'running', started = 1 WHERE id = ?", (self.plan,))
        self.db.execute("UPDATE rounds SET status = 'running', started = 1 WHERE id = ?", (self.rid,))
        bench.add_steps(self.db, self.rid, [{'kind': 'load', 'model': 'qwen2.5:3b'},
                                            {'kind': 'scenario', 'model': 'qwen2.5:3b', 'scenario': 'quicktest'}])

    def restore(self):
        for key, value in self.saved.items():
            setattr(bench, key, value)

    def events(self, kind=None):
        rows = self.db.execute('SELECT kind, message FROM events ORDER BY id').fetchall()
        return [r['message'] for r in rows if kind is None or r['kind'] == kind]

    def steps(self):
        return {r['seq']: dict(r) for r in self.db.execute('SELECT * FROM steps WHERE round_id = ?', (self.rid,))}


class TestClients(unittest.TestCase):
    def test_parse_sockstat(self):
        saved = bench._sh
        bench._sh = lambda cmd, timeout=20: ''
        try:
            clients = bench.ollama_clients(exclude=(23317,), text=SOCKSTAT)
        finally:
            bench._sh = saved
        self.assertEqual([c['pid'] for c in clients], [87020, 37729])      # server side, closed and ours out

    def test_production_busy_names_the_client(self):
        saved = bench.ollama_clients
        bench.ollama_clients = lambda exclude=(), text=None: [
            {'pid': 37729, 'user': 'root', 'command': 'python3 reports/cli.py send weekly'}]
        try:
            reason = bench.production_busy(check_cpu=False)
        finally:
            bench.ollama_clients = saved
        self.assertIn('37729', reason)
        self.assertIn('send weekly', reason)


class TestRunner(RunnerCase):
    def test_waits_while_another_process_uses_ollama(self):
        calls = []

        def busy(check_cpu=True, exclude=None):
            calls.append(check_cpu)
            return 'Ollama in use by another process: pid 1 (cli.py send weekly)' if len(calls) < 3 else None
        bench.production_busy = busy
        self.runner.last_step_end = 10 ** 12        # "just finished a step": the client check still runs
        self.assertTrue(self.runner.wait_ready('load'))
        self.assertEqual(len(calls), 3)
        self.assertIn('send weekly', self.events('pause')[0])
        self.assertTrue(self.events('resume'))

    def test_contention_puts_the_step_back(self):
        def child(step):
            self.runner.contention = 'pid 37729 (cli.py send weekly)'
            return None, 'TimeoutError: timed out'
        self.runner.run_child = child
        step = self.steps()[1]
        self.runner.execute(self.db.execute('SELECT * FROM steps WHERE id = ?', (step['id'],)).fetchone())
        self.assertEqual(self.steps()[1]['status'], 'pending')
        self.assertIn('send weekly', self.events('step_retry')[0])
        # after MAX_STEP_RUNS it is an error, with an event
        self.db.execute('UPDATE steps SET runs = ? WHERE id = ?', (bench.MAX_STEP_RUNS, step['id']))
        self.runner.execute(self.db.execute('SELECT * FROM steps WHERE id = ?', (step['id'],)).fetchone())
        self.assertEqual(self.steps()[1]['status'], 'error')
        self.assertIn('timed out', self.events('step_error')[0])

    def test_step_error_is_an_event(self):
        self.runner.run_child = lambda step: (None, 'ProviderError: model not found')
        self.runner.contention = None
        bench.production_busy = lambda check_cpu=True, exclude=None: None
        self.runner.iterate()
        self.assertEqual(self.steps()[1]['status'], 'error')
        self.assertIn('model not found', self.events('step_error')[0])

    def test_loop_survives_an_exception_and_goes_on(self):
        bench.production_busy = lambda check_cpu=True, exclude=None: None
        done = []

        def child(step):
            if step['seq'] == 1:
                raise RuntimeError('database is locked')
            done.append(step['seq'])
            return {'ok': True}, None
        self.runner.run_child = child
        original = bench.round_summary
        bench.round_summary = lambda db, plan, rnd: ('OK', 'Round finished', 'x')
        self.runner.finish = lambda plan: self.db.execute(
            "UPDATE plans SET status = 'done' WHERE id = ?", (plan['id'],)) and self.db.commit()
        try:
            self.runner.loop()
        finally:
            bench.round_summary = original
        steps = self.steps()
        self.assertEqual(steps[1]['status'], 'error')
        self.assertIn('database is locked', steps[1]['error'])
        self.assertEqual(steps[2]['status'], 'done')
        self.assertEqual(done, [2])
        self.assertIn('database is locked', self.events('runner_error')[0])

    def test_gives_up_after_repeated_errors(self):
        self.runner.iterate = lambda: (_ for _ in ()).throw(RuntimeError('broken'))
        with self.assertRaises(RuntimeError):
            self.runner.loop()
        self.assertEqual(len(self.events('runner_error')), bench.MAX_LOOP_ERRORS)

    def test_start_retry_resets_failed_steps(self):
        self.db.execute("UPDATE steps SET status = 'error', error = 'TimeoutError: timed out' WHERE seq = 1")
        self.db.commit()
        saved = bench.spawn_runner, bench.runner_pid
        bench.spawn_runner, bench.runner_pid = (lambda: True), (lambda: None)
        try:
            res = bench.cmd_start('matriz', db=self.db, retry=True)
        finally:
            bench.spawn_runner, bench.runner_pid = saved
        self.assertEqual(res['retried'], 1)
        self.assertEqual(self.steps()[1]['status'], 'pending')
        self.assertIsNone(self.steps()[1]['error'])


class TestBusyOllama(RunnerCase):
    """ OLLAMA_MAX_QUEUE=2 on the firewall: the 3rd waiting request gets 503 at once; 2026-11-09 01:00-01:02 the
    matrix steps 28-73 were recorded as "done" in 2 s each with that error inside the result """

    BUSY = 'ProviderHTTPError: HTTP 503 from endpoint server busy, please try again.  maximum pending requests exceeded'

    def test_busy_result_is_not_a_measurement(self):
        self.runner.contention = None
        self.runner.run_child = lambda step: ({'scenario': 'quicktest', 'error': self.BUSY, 'wall_s': 0.0}, None)
        step = self.db.execute('SELECT * FROM steps WHERE seq = 2 AND round_id = ?', (self.rid,)).fetchone()
        self.runner.execute(step)
        self.assertEqual(self.steps()[2]['status'], 'pending')
        self.assertIn('503', self.events('step_retry')[0])

    def test_timeout_is_a_result_without_contention(self):
        self.runner.contention = None
        res = {'scenario': 'quicktest', 'error': 'ProviderError: timeout after 600 seconds', 'wall_s': 600.0}
        self.runner.run_child = lambda step: (res, None)
        step = self.db.execute('SELECT * FROM steps WHERE seq = 2 AND round_id = ?', (self.rid,)).fetchone()
        self.runner.execute(step)
        self.assertEqual(self.steps()[2]['status'], 'done')

    def test_retry_resets_busy_done_steps(self):
        import json
        self.db.execute("UPDATE steps SET status = 'done', result = ? WHERE seq = 2",
                        (json.dumps({'error': self.BUSY}),))
        self.db.commit()
        saved = bench.spawn_runner, bench.runner_pid
        bench.spawn_runner, bench.runner_pid = (lambda: True), (lambda: None)
        try:
            res = bench.cmd_start('matriz', db=self.db, retry=True)
        finally:
            bench.spawn_runner, bench.runner_pid = saved
        self.assertEqual(res['retried'], 1)
        self.assertEqual(self.steps()[2]['status'], 'pending')
        self.assertIsNone(self.steps()[2]['result'])

    def test_retry_reopens_a_finished_round(self):
        """ 2026-11-09: rounds matrix and repeat had closed with 106 refused steps and "retry" found none """
        import json
        self.db.execute("UPDATE steps SET status = 'done', result = ? WHERE seq = 2",
                        (json.dumps({'error': self.BUSY}),))
        self.db.execute("UPDATE rounds SET status = 'done', finished = 1 WHERE id = ?", (self.rid,))
        self.db.commit()
        saved = bench.spawn_runner, bench.runner_pid
        bench.spawn_runner, bench.runner_pid = (lambda: True), (lambda: None)
        try:
            res = bench.cmd_start('matriz', db=self.db, retry=True)
        finally:
            bench.spawn_runner, bench.runner_pid = saved
        self.assertEqual(res['retried'], 1)
        rnd = self.db.execute('SELECT status, finished FROM rounds WHERE id = ?', (self.rid,)).fetchone()
        self.assertEqual((rnd['status'], rnd['finished']), ('running', None))


class TestRunnerProcess(RunnerCase):
    def test_exit_is_an_event_and_sighup_is_ignored(self):
        import signal
        saved_dir = (bench.RUN_DIR, bench.PID_FILE, bench.LOCK_FILE)
        bench.RUN_DIR = self.tmp
        bench.PID_FILE = os.path.join(self.tmp, 'bench.pid')
        bench.LOCK_FILE = os.path.join(self.tmp, 'bench.lock')
        old = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        self.runner.sampler = lambda: None
        self.runner.loop = lambda: (_ for _ in ()).throw(KeyboardInterrupt())
        try:
            self.assertEqual(self.runner.run()['status'], 'ok')
            self.assertEqual(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)
            bench.RUN_DIR, bench.PID_FILE, bench.LOCK_FILE = saved_dir
        messages = self.events('runner')
        self.assertTrue(messages[0].startswith('runner started'))
        self.assertIn('KeyboardInterrupt', messages[-1])
        self.assertTrue(self.events('runner_error'))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'bench.pid')))


if __name__ == '__main__':
    unittest.main()
