"""
Background AI queue (ai/jobqueue.py): jobs, merge of duplicates, position/estimate, worker with lock, cache of
answers, cancel, recovery, metrics, and the Assistant side (mode "queue" -> queued, worker -> inline answer).
"""

import fcntl
import json
import os
import sys
import unittest
from unittest import mock

from ai_fakes import Factory, FakeProvider, TempDirCase, config, routing
from ai_helpers import SCRIPTS
from ai import Task, jobqueue
from ai.assistant import is_queued

SCRIPT = os.path.join(SCRIPTS, 'explain.py')


class TestQueue(TempDirCase):
    def enqueue(self, key='k1', scenario='console_ask', argv=None, **kw):
        return jobqueue.enqueue(scenario, key, argv or [SCRIPT, 'explain', 'all'], route={'provider': 'ollama',
                                'model': 'qwen3:30b-a3b', 'label': 'local AI'}, path=self.queue_path, **kw)

    def test_enqueue_merge_position_and_estimate(self):
        j1 = self.enqueue('a', eta=300)
        self.assertEqual((j1['status'], j1['position'], j1['eta_seconds']), ('queued', 1, 300))
        j2 = self.enqueue('b', scenario='incident_summary', eta=480)
        self.assertEqual((j2['position'], j2['ahead'], j2['eta_seconds']), (2, 1, 780))
        dup = self.enqueue('a')
        self.assertTrue(dup['merged'])
        self.assertEqual(dup['id'], j1['id'])
        with self.assertRaises(ValueError):
            self.enqueue('c', argv=['/etc/passwd'])
        with self.assertRaises(ValueError):
            self.enqueue('c', argv=['/usr/bin/env', 'rm'])

    def test_worker_runs_in_order_and_stores_results(self):
        self.enqueue('a')
        self.enqueue('b', scenario='posture_summary')
        seen = []

        def runner(argv, env, timeout, on_start=None):
            seen.append((argv, env['PA_AI_JOB'], env['PA_AI_INLINE']))
            on_start(4242)
            jobqueue.add_metrics(int(env['PA_AI_JOB']), path=self.queue_path, provider='ollama', model='qwen3:30b-a3b',
                                 prompt_tokens=900, completion_tokens=300, duration_ms=60000, attempts=2,
                                 format_ok=True, lang_ok=False)
            if env['PA_AI_JOB'] == '2':
                return 1, b'', b'Traceback: boom'
            return 0, b'progress line\n{"status": "ok", "text": "answer", "finding": "all"}\n', b''
        res = jobqueue.work(path=self.queue_path, runner=runner)
        self.assertEqual(res['ran'], 2)
        self.assertEqual([s[1] for s in seen], ['1', '2'])
        self.assertEqual(seen[0][0][0], SCRIPT)
        one = jobqueue.get(1, self.queue_path)
        self.assertEqual(one['job']['status'], 'done')
        self.assertEqual(one['result'], {'status': 'ok', 'text': 'answer', 'finding': 'all'})
        self.assertEqual((one['job']['prompt_tokens'], one['job']['completion_tokens']), (900, 300))
        self.assertEqual((one['job']['format_ok'], one['job']['lang_ok'], one['job']['pid']), (1, 0, 4242))
        two = jobqueue.get(2, self.queue_path)
        self.assertEqual(two['job']['status'], 'error')
        self.assertIn('boom', two['job']['error'])
        listing = jobqueue.listing(path=self.queue_path)
        self.assertEqual(listing['counts']['done'], 1)
        stat = [s for s in listing['stats'] if s['scenario'] == 'console_ask'][0]
        self.assertEqual((stat['jobs'], stat['ok'], stat['model']), (1, 1, 'qwen3:30b-a3b'))
        self.assertEqual(stat['attempts'], 2.0)

    def test_module_answering_queued_again_is_an_error(self):
        self.enqueue('a')
        jobqueue.work(path=self.queue_path, runner=lambda *a: (0, b'{"status": "queued", "job": {}}', b''))
        self.assertIn('queued again', jobqueue.get(1, self.queue_path)['job']['error'])

    def test_lock_cancel_and_recovery(self):
        self.enqueue('a')
        fd = os.open(jobqueue.lock_path(self.queue_path), os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            self.assertEqual(jobqueue.work(path=self.queue_path, runner=None)['status'], 'busy')
            self.assertTrue(jobqueue.worker_state(self.queue_path)['running'])
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertFalse(jobqueue.worker_state(self.queue_path)['running'])
        self.assertTrue(jobqueue.cancel(1, self.queue_path)['cancelled'])
        self.assertEqual(jobqueue.work(path=self.queue_path, runner=lambda *a: 1 / 0)['ran'], 0)
        # a job left "running" by a dead worker is queued again once, then fails
        self.enqueue('b')
        db = jobqueue.connect(self.queue_path)
        db.execute("UPDATE jobs SET status = 'running', runs = 1 WHERE id = 2")
        db.commit()
        db.close()
        ran = jobqueue.work(path=self.queue_path, runner=lambda argv, env, t, s=None: (0, b'{"status":"ok"}', b''))
        self.assertEqual(ran['jobs'], [{'id': 2, 'status': 'done'}])
        self.enqueue('c')
        db = jobqueue.connect(self.queue_path)
        db.execute("UPDATE jobs SET status = 'running', runs = 2 WHERE id = 3")
        db.commit()
        db.close()
        jobqueue.work(path=self.queue_path, runner=lambda *a: (0, b'{"status":"ok"}', b''))
        self.assertIn('interrupted', jobqueue.get(3, self.queue_path)['job']['error'])

    def test_timeout_kills_the_command(self):
        jobqueue.MAX_JOB_SECONDS, old = 1, jobqueue.MAX_JOB_SECONDS
        self.addCleanup(setattr, jobqueue, 'MAX_JOB_SECONDS', old)
        script = os.path.join(self.tmp, 'slow.py')
        with open(script, 'w') as handle:
            handle.write('import time\ntime.sleep(30)\n')
        rc, out, err = jobqueue._run_command([script], dict(os.environ), 1)
        self.assertEqual(rc, 124)

    def test_cache(self):
        self.assertIsNone(jobqueue.cache_get('x', self.queue_path))
        jobqueue.cache_put('x', 'console_ask', 'texto', 'ollama', 'm', {'attempts': 1}, ttl=60, path=self.queue_path)
        hit = jobqueue.cache_get('x', self.queue_path)
        self.assertEqual((hit['text'], hit['meta']), ('texto', {'attempts': 1}))
        jobqueue.cache_put('y', 'console_ask', 'old', 'ollama', 'm', ttl=-1, path=self.queue_path)
        self.assertIsNone(jobqueue.cache_get('y', self.queue_path))

    def test_main_cli(self):
        out = []
        with mock.patch.object(jobqueue, 'DB_PATH', self.queue_path), \
                mock.patch.object(jobqueue, 'emit', out.append):
            jobqueue.main(['jobqueue.py', 'list', '5'])
            jobqueue.main(['jobqueue.py', 'job', '99'])
            self.assertEqual(jobqueue.main(['jobqueue.py', 'rm', '-rf']), 1)
        self.assertEqual(out[0]['status'], 'ok')
        self.assertEqual(out[1]['status'], 'error')


class TestAssistantQueue(TempDirCase):
    def setUp(self):
        super().setUp()
        self.runtime(False)
        self.local = FakeProvider('ollama', ['A resposta da IA local, com [filterlog: 3 bloqueios].'])
        self.route = routing({'console_ask': {'provider': 'ollama', 'model': 'qwen3:30b-a3b', 'mode': 'queue',
                                              'retries': 0}})

    def make(self):
        return self.assistant(config('claudecode', 'fable'), self.route, Factory(ollama=self.local))

    def test_queue_then_worker_answers_then_cache(self):
        a = self.make()
        task = Task('console_ask', 'x', 'q')
        with mock.patch.object(jobqueue, 'current_argv', return_value=[SCRIPT, 'explain', 'all']), \
                mock.patch.object(jobqueue, 'spawn_worker', return_value=True) as spawn:
            res = a.ask(task, {'a': 1}, language='pt_BR', subject='console:test')
            self.assertTrue(is_queued(res))
            self.assertEqual(res['label'], 'local AI')
            self.assertEqual(res['job']['position'], 1)
            self.assertEqual(spawn.call_count, 1)
            again = a.ask(task, {'a': 1}, language='pt_BR')
            self.assertTrue(again['job']['merged'])
            self.assertEqual(spawn.call_count, 1)
        self.assertEqual(self.local.calls, [])
        # the worker runs the same command with PA_AI_JOB: the Assistant answers inline and fills the cache
        os.environ['PA_AI_JOB'] = str(res['job']['id'])
        try:
            inline = self.make().ask(task, {'a': 1}, language='pt_BR')
        finally:
            os.environ.pop('PA_AI_JOB')
        self.assertEqual(inline['status'], 'ok')
        self.assertEqual(len(self.local.calls), 1)
        job = jobqueue.get(res['job']['id'], self.queue_path)['job']
        self.assertEqual((job['calls'], job['provider_used'], job['format_ok']), (1, 'ollama', 1))
        # same input later: answered from the cache, synchronously, without the model
        with mock.patch.object(jobqueue, 'current_argv', return_value=[SCRIPT, 'explain', 'all']):
            cached = self.make().ask(task, {'a': 1}, language='pt_BR')
        self.assertEqual(cached['status'], 'ok')
        self.assertTrue(cached['cached'])
        self.assertEqual(len(self.local.calls), 1)
        # other input: queued again
        with mock.patch.object(jobqueue, 'current_argv', return_value=[SCRIPT, 'explain', 'all']), \
                mock.patch.object(jobqueue, 'spawn_worker', return_value=True):
            self.assertTrue(is_queued(self.make().ask(task, {'a': 2}, language='pt_BR')))

    def test_not_queueable_command_answers_synchronously(self):
        res = self.make().ask(Task('console_ask', 'x', 'q'), {'a': 1}, language='pt_BR')
        self.assertEqual(res['status'], 'ok')                       # sys.argv is the test runner
        self.assertEqual(len(self.local.calls), 1)

    def test_inline_flag(self):
        a = self.assistant(config('claudecode', 'fable'), self.route, Factory(ollama=self.local), inline=True)
        with mock.patch.object(jobqueue, 'current_argv', return_value=[SCRIPT, 'explain', 'all']):
            self.assertEqual(a.ask(Task('console_ask', 'x', 'q'), {'a': 1})['status'], 'ok')

    def test_end_to_end_worker_subprocess(self):
        """ a real worker subprocess runs a real plugin command (explain.py providers: no AI, prints JSON) """
        argv = [os.path.join(SCRIPTS, 'explain.py'), 'providers']
        job = jobqueue.enqueue('quicktest', 'e2e', argv, path=self.queue_path)
        env = dict(os.environ, POLICYANALYZER_AI_QUEUE=self.queue_path)
        import subprocess
        out = subprocess.run([sys.executable, os.path.join(SCRIPTS, 'ai', 'jobqueue.py'), 'work'], env=env,
                             stdout=subprocess.PIPE, timeout=120)
        self.assertEqual(json.loads(out.stdout)['ran'], 1)
        got = jobqueue.get(job['id'], self.queue_path)
        self.assertEqual(got['job']['status'], 'done')
        self.assertEqual(got['result']['status'], 'ok')
        self.assertIn('providers', got['result'])


if __name__ == '__main__':
    unittest.main()
