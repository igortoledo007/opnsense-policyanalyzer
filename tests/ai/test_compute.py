"""
Compute profile of a measurement (ai/compute.py): the machine + the share of it given to the model, recorded per
step of ai/bench.py and per evaluation of ai/evaluate.py, so a time or a tokens/s figure can be compared with
another configuration (3 threads instead of 2) or another hardware later.
Covers: the probes with a fake firewall (sysctl, dmesg.boot, dmidecode), the key (what makes two measurements
comparable), one row per distinct profile, the migration of an older database, the stamp of the runner, the
retroactive stamp (backfill) and what it leaves alone, the reference throughput per profile and model, the section
of the catalog, the line of the round e-mail, the hardware line / mixed shares of the evaluation and what follows
the share of the jail (options of the direct calls, load guard, load score).
No network, no Ollama, no e-mail, nothing read from the machine running the tests.
"""

import json
import os
import shutil
import sqlite3
import tempfile
import unittest

import ai_helpers  # noqa: F401  (import path)

from ai import bench, compute, evaluate

N100 = {'hostname': 'fw-teste', 'os': 'FreeBSD', 'os_release': '14.3', 'cpu': 'Intel(R) N100', 'cores': 4,
        'physical_cores': 4, 'simd': 'AVX2 + VNNI', 'ram_gib': 31.7, 'mem_modules': ['32 GB DDR5-4800'],
        'mem_type': 'DDR5', 'mem_speed': 4800, 'mem_channels': 1, 'mem_bandwidth_gbs': 38.4, 'mem_how': 'dmidecode'}
TWO = {'cpus': '2-3', 'threads': 2, 'ctx': 8192, 'nice': 20, 'mem_gb': 12, 'num_parallel': 1}
THREE = dict(TWO, cpus='1-3', threads=3)

DMESG = """CPU: Intel(R) N100 (806.40-MHz K8-class CPU)
  Features=0xbfebfbff<FPU,VME,DE,PSE,TSC,MSR,PAE,MCE,CX8,APIC,SEP,MTRR,PGE,MCA,CMOV,PAT,PSE36,CLFLUSH,DTS,ACPI,MMX,FXSR,SSE,SSE2,SS,HTT,TM,PBE>
  Features2=0x7ffafbbf<SSE3,PCLMULQDQ,DTES64,MON,DS_CPL,VMX,EST,TM2,SSSE3,SDBG,FMA,CX16,xTPR,PDCM,PCID,SSE4.1,SSE4.2,x2APIC,MOVBE,POPCNT,TSCDLT,AESNI,XSAVE,OSXSAVE,AVX,F16C,RDRAND>
  Structured Extended Features=0x239ca7eb<FSGSBASE,TSCADJ,BMI1,AVX2,SMEP,BMI2,ERMS,INVPCID,NFPUSG,PQE,RDSEED,ADX,SMAP,CLFLUSHOPT,CLWB,PROCTRACE,SHA>
  Structured Extended Features4=0x10<AVX_VNNI>
"""
DMIDECODE = """# dmidecode 3.6

Handle 0x0020, DMI type 17, 92 bytes
Memory Device
	Size: 32 GB
	Locator: Controller0-ChannelA-DIMM0
	Type: DDR5
	Speed: 4800 MT/s
	Configured Memory Speed: 4800 MT/s

Handle 0x0021, DMI type 17, 92 bytes
Memory Device
	Size: No Module Installed
	Locator: Controller1-ChannelA-DIMM0
"""


class FakeRunner:
    def read(self, argv, timeout=None):
        if argv[0].endswith('sysctl'):
            return {'hw.model': 'Intel(R) N100\n', 'hw.ncpu': '4\n', 'kern.smp.cores': '4\n',
                    'hw.physmem': '34036920320\n'}.get(argv[-1], '')
        if argv[0].endswith('dmidecode'):
            return DMIDECODE
        return ''


class FakeCtx:
    def __init__(self, root, is_root=True):
        self.root, self.is_root, self.runner = root, is_root, FakeRunner()


def prof(limits=TWO, version='0.34.3'):
    return compute.profile(ollama_version=version, limits=limits, static=N100, ollama_url='http://127.0.0.1:11434')


class ProbeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-compute-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.makedirs(os.path.join(self.tmp, 'var/run'))
        with open(os.path.join(self.tmp, 'var/run/dmesg.boot'), 'w') as handle:
            handle.write(DMESG)

    def test_machine_from_the_firewall_probes(self):
        hw = compute.static_profile(FakeCtx(self.tmp))
        self.assertEqual(hw['cpu'], 'Intel(R) N100')
        self.assertEqual((hw['cores'], hw['physical_cores']), (4, 4))
        self.assertEqual(hw['simd'], 'AVX2 + VNNI')
        self.assertEqual(hw['ram_gib'], 31.7)
        self.assertEqual(hw['mem_modules'], ['32 GB DDR5-4800'])
        self.assertEqual((hw['mem_type'], hw['mem_speed'], hw['mem_channels']), ('DDR5', 4800, 1))
        self.assertEqual(hw['mem_bandwidth_gbs'], 38.4)

    def test_without_root_the_memory_modules_stay_unknown(self):
        hw = compute.static_profile(FakeCtx(self.tmp, is_root=False))
        self.assertEqual(hw['cpu'], 'Intel(R) N100')
        self.assertIsNone(hw['mem_modules'])
        self.assertIsNone(hw['mem_channels'])

    def test_cpuset(self):
        self.assertEqual(compute.cpuset_cores('2-3'), 2)
        self.assertEqual(compute.cpuset_cores('1-3'), 3)
        self.assertEqual(compute.cpuset_cores('0,2'), 2)
        self.assertEqual(compute.cpuset_cores('0-1,3'), 3)
        self.assertIsNone(compute.cpuset_cores('x'))

    def test_limits_file(self):
        path = os.path.join(self.tmp, 'limits.json')
        self.assertEqual(compute.read_limits(path), {})
        with open(path, 'w') as handle:
            json.dump(THREE, handle)
        doc = compute.profile(ollama_version='0.34.3', limits=compute.read_limits(path), static=N100)
        self.assertEqual((doc['jail_cpus'], doc['jail_cores'], doc['jail_threads'], doc['num_ctx']), ('1-3', 3, 3, 8192))


class KeyTest(unittest.TestCase):
    def test_key_follows_what_changes_the_speed(self):
        base = prof()
        self.assertEqual(base['key'], prof()['key'])
        self.assertNotEqual(base['key'], prof(THREE)['key'])
        self.assertNotEqual(base['key'], prof(dict(TWO, ctx=16384))['key'])
        self.assertNotEqual(base['key'], prof(version='0.35.0')['key'])
        other = compute.profile(ollama_version='0.34.3', limits=TWO, static=dict(N100, cpu='AMD Ryzen 7 8845HS'))
        self.assertNotEqual(base['key'], other['key'])
        # information only: not a new profile
        self.assertEqual(base['key'], prof(dict(TWO, nice=10))['key'])
        self.assertEqual(base['key'], compute.profile(ollama_version='0.34.3', limits=TWO,
                                                      static=dict(N100, hostname='outro-nome'))['key'])

    def test_text(self):
        doc = prof()
        self.assertEqual(compute.short(doc), '2 threads on 2 cores (cpus 2-3)')
        self.assertEqual(compute.memory_text(doc), '31.7 GiB, 1 × DDR5-4800 in a single channel (38.4 GB/s theoretical)')
        label = compute.label(doc)
        for piece in ('Intel(R) N100, 4 cores (AVX2 + VNNI)', 'jail with 2 threads on 2 cores (cpus 2-3)',
                      'num_ctx 8192', 'Ollama 0.34.3'):
            self.assertIn(piece, label)
        self.assertEqual(compute.memory_text({'ram_gib': 15.5}), '15.5 GiB')


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-compute-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, 'ai-bench.db')
        self.db = bench.connect(self.path)
        self.addCleanup(self.db.close)
        self.plan = bench.create_plan(self.db, 'matriz')
        self.rid = self.db.execute('SELECT id FROM rounds WHERE plan_id = ?', (self.plan,)).fetchone()[0]

    def step(self, model='m:1b', result=None, started=100, status='done', params=None, rid=None):
        cur = self.db.execute('INSERT INTO steps (round_id, seq, kind, model, scenario, variant, params, status, runs, '
                              "started, finished, result) VALUES (?, 0, 'scenario', ?, 'quicktest', 0, ?, ?, 1, ?, ?, ?)",
                              (rid or self.rid, model, json.dumps(params or {}), status, started,
                               started + 10 if started else None, json.dumps(result) if result is not None else None))
        self.db.commit()
        return cur.lastrowid

    def compute_id(self, step_id):
        return self.db.execute('SELECT compute_id FROM steps WHERE id = ?', (step_id,)).fetchone()[0]


class StoreTest(StoreCase):
    def test_one_row_per_distinct_profile(self):
        first = compute.record(self.db, prof())
        self.assertEqual(compute.record(self.db, prof()), first)
        second = compute.record(self.db, prof(THREE))
        self.assertNotEqual(first, second)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM compute_profiles').fetchone()[0], 2)
        self.assertEqual(compute.get(self.db, second)['jail_threads'], 3)
        self.assertIsNone(compute.get(self.db, 999))
        self.assertIsNone(compute.get(self.db, None))

    def test_older_database_gains_the_column(self):
        path = os.path.join(self.tmp, 'old.db')
        old = sqlite3.connect(path)
        old.executescript(bench.SCHEMA)
        self.assertNotIn('compute_id', {r[1] for r in old.execute('PRAGMA table_info(steps)')})
        old.execute("INSERT INTO plans (name, status, created) VALUES ('noturno', 'done', 1)")
        old.commit()
        old.close()
        db = bench.connect(path)
        self.addCleanup(db.close)
        self.assertIn('compute_id', {r[1] for r in db.execute('PRAGMA table_info(steps)')})
        self.assertEqual(db.execute('SELECT COUNT(*) FROM plans').fetchone()[0], 1)
        bench.connect(path).close()          # a second time: nothing to do, no error

    def test_backfill_stamps_only_what_was_measured_here(self):
        measured = self.step(result={'gen_tps': 4.0})
        pending = self.step(started=None, status='pending')
        already = self.step(result={'gen_tps': 4.0})
        compute.stamp(self.db, already, compute.record(self.db, prof(THREE)))
        self.db.execute("INSERT INTO plans (name, status, created, imported) VALUES ('importado', 'done', 1, 1)")
        imported_plan = self.db.execute('SELECT MAX(id) FROM plans').fetchone()[0]
        self.db.execute("INSERT INTO rounds (plan_id, idx, name, status) VALUES (?, 0, 'matrix', 'done')", (imported_plan,))
        imported_round = self.db.execute('SELECT MAX(id) FROM rounds').fetchone()[0]
        elsewhere = self.step(result={'gen_tps': 9.0}, rid=imported_round)

        self.assertEqual(compute.backfill(self.db, prof()), 1)
        two = compute.record(self.db, prof())
        self.assertEqual(self.compute_id(measured), two)
        self.assertIsNone(self.compute_id(pending))
        self.assertIsNone(self.compute_id(elsewhere))
        self.assertNotEqual(self.compute_id(already), two)
        note = json.loads(self.db.execute("SELECT v FROM meta WHERE k = 'compute_backfill'").fetchone()[0])
        self.assertEqual((note[0]['steps'], note[0]['profile_id']), (1, two))
        event = self.db.execute("SELECT message FROM events WHERE kind = 'compute'").fetchone()[0]
        self.assertIn('retroactively on 1 step', event)
        self.assertIn('2 threads on 2 cores', event)
        # nothing left: no second note
        self.assertEqual(compute.backfill(self.db, prof()), 0)
        self.assertEqual(len(json.loads(self.db.execute("SELECT v FROM meta WHERE k = 'compute_backfill'").fetchone()[0])), 1)

    def test_throughput_is_the_median_per_profile_and_model(self):
        two, three = compute.record(self.db, prof()), compute.record(self.db, prof(THREE))
        for pid, values in ((two, (4.0, 5.0, 6.0)), (three, (6.5, 7.5))):
            for value in values:
                compute.stamp(self.db, self.step(result={'gen_tps': value, 'prompt_tps': value * 10}), pid)
        compute.stamp(self.db, self.step(model='big:30b', result={'gen_tps': 1.2}), two)
        # out: an error, a timeout, a step that overrides the threads or the context, one without a profile
        compute.stamp(self.db, self.step(result={'gen_tps': 99.0, 'error': 'boom'}), two)
        compute.stamp(self.db, self.step(result={'gen_tps': 99.0, 'timeout': True}), two)
        compute.stamp(self.db, self.step(result={'gen_tps': 99.0}, params={'tag': 'threads', 'num_thread': 4}), two)
        compute.stamp(self.db, self.step(result={'gen_tps': 99.0}, params={'num_ctx': 16384}), two)
        self.step(result={'gen_tps': 99.0})
        rows = {(r['profile_id'], r['model']): r for r in compute.throughput(self.db)}
        self.assertEqual(rows[(two, 'm:1b')], {'profile_id': two, 'model': 'm:1b', 'n': 3, 'prompt_tps': 50.0,
                                               'gen_tps': 5.0})
        self.assertEqual((rows[(three, 'm:1b')]['n'], rows[(three, 'm:1b')]['gen_tps']), (2, 7.0))
        self.assertEqual((rows[(two, 'big:30b')]['gen_tps'], rows[(two, 'big:30b')]['prompt_tps']), (1.2, None))
        self.assertEqual(len(rows), 3)

    def test_catalog_section(self):
        lines = compute.report_lines(self.db)
        self.assertIn('No measurement with a recorded profile yet.', lines)
        self.step(result={'gen_tps': 4.0, 'prompt_tps': 40.0})
        compute.backfill(self.db, prof())
        compute.stamp(self.db, self.step(result={'gen_tps': 6.0, 'prompt_tps': 55.0}), compute.record(self.db, prof(THREE)))
        text = '\n'.join(compute.report_lines(self.db))
        self.assertIn('| #1 | Intel(R) N100 | 4 | AVX2 + VNNI | 2 cores (2-3) | 2 | 8192 |', text)
        self.assertIn('| #2 | Intel(R) N100 | 4 | AVX2 + VNNI | 3 cores (1-3) | 3 | 8192 |', text)
        self.assertIn('Profile #1 recorded retroactively on 1 step(s)', text)
        self.assertIn('| #1 | m:1b | 1 | 40.0 | 4.0 |', text)
        self.assertIn('| #2 | m:1b | 1 | 55.0 | 6.0 |', text)
        self.assertIn('## Compute profile', bench.report_md(self.db))

    def test_command(self):
        saved = bench.compute_now
        self.addCleanup(setattr, bench, 'compute_now', saved)
        bench.compute_now = lambda version=None: prof()
        self.step(result={'gen_tps': 4.0})
        out = bench.cmd_compute(self.db, backfill=True)
        self.assertEqual((out['status'], out['backfilled']), ('ok', 1))
        self.assertEqual(out['profiles'][0]['steps'], 1)
        self.assertEqual(out['throughput'][0]['gen_tps'], 4.0)
        self.assertEqual(bench.cmd_compute(self.db)['profiles'][0]['jail_cpus'], '2-3')
        self.assertNotIn('backfilled', bench.cmd_compute(self.db))


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-compute-runner-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.saved = {k: getattr(bench, k) for k in ('_sh', 'unload_all', 'compute_now', 'ollama_version')}
        self.addCleanup(lambda: [setattr(bench, k, v) for k, v in self.saved.items()])
        bench._sh = lambda cmd, timeout=20: ''
        bench.unload_all = lambda: None
        bench.ollama_version = lambda: '0.34.3'
        self.limits = dict(TWO)
        bench.compute_now = lambda version=None: prof(self.limits, version or '0.34.3')
        self.runner = bench.Runner(os.path.join(self.tmp, 'ai-bench.db'))
        self.addCleanup(self.runner.db.close)
        self.db = self.runner.db
        self.plan = bench.create_plan(self.db, 'matriz')
        self.rid = self.db.execute('SELECT id FROM rounds WHERE plan_id = ?', (self.plan,)).fetchone()[0]
        bench.add_steps(self.db, self.rid, [{'kind': 'scenario', 'model': 'm:1b', 'scenario': 'quicktest'},
                                            {'kind': 'scenario', 'model': 'm:1b', 'scenario': 'quicktest'}])
        self.runner.run_child = lambda step: ({'wall_s': 10.0, 'gen_tps': 5.0, 'scenario': 'quicktest'}, None)

    def steps(self):
        return self.db.execute('SELECT * FROM steps WHERE round_id = ? ORDER BY id', (self.rid,)).fetchall()

    def test_every_step_carries_its_profile_and_a_set_limits_opens_another(self):
        first, second = self.steps()
        self.runner.execute(first)
        self.limits.update(THREE)                    # set_limits between two steps
        self.runner.execute(second)
        first, second = self.steps()
        self.assertEqual(first['status'], 'done')
        self.assertEqual(compute.get(self.db, first['compute_id'])['jail_threads'], 2)
        self.assertEqual(compute.get(self.db, second['compute_id'])['jail_threads'], 3)
        self.assertNotEqual(first['compute_id'], second['compute_id'])

    def test_a_failing_probe_does_not_stop_the_step(self):
        def boom(version=None):
            raise RuntimeError('broken probe')
        bench.compute_now = boom
        first = self.steps()[0]
        self.runner.execute(first)
        row = self.steps()[0]
        self.assertEqual(row['status'], 'done')
        self.assertIsNone(row['compute_id'])
        self.assertIn('without a compute profile: broken probe',
                      self.db.execute("SELECT message FROM events WHERE kind = 'compute'").fetchone()[0])

    def test_round_mail_says_where_it_ran(self):
        plan = self.db.execute('SELECT * FROM plans WHERE id = ?', (self.plan,)).fetchone()
        rnd = self.db.execute('SELECT * FROM rounds WHERE id = ?', (self.rid,)).fetchone()
        self.assertNotIn('Compute', bench.round_summary(self.db, plan, rnd)[2])
        first, second = self.steps()
        self.runner.execute(first)
        text = bench.round_summary(self.db, plan, rnd)[2]
        self.assertIn('Compute (profile #1): Intel(R) N100, 4 cores (AVX2 + VNNI); jail with 2 threads on 2 cores '
                      '(cpus 2-3), num_ctx 8192', text)
        self.limits.update(THREE)
        self.runner.execute(second)
        text = bench.round_summary(self.db, plan, rnd)[2]
        self.assertIn('the round ran on 2 profiles', text)
        self.assertIn('#2 3 threads on 3 cores (cpus 1-3), num_ctx 8192', text)


class EvaluationTest(unittest.TestCase):
    OLD = {'hostname': 'fw', 'os': 'FreeBSD', 'cpu': 'Intel(R) N100', 'cores': 4, 'ram_gib': 31.7,
           'ollama_url': 'http://127.0.0.1:11434', 'ollama_version': '0.34.3', 'source': 'firewall'}

    def test_hardware_line(self):
        line = evaluate.hardware_line(dict(self.OLD, jail_threads=2, jail_cpus='2-3'))
        self.assertIn('Intel(R) N100, 4 cores, 31.7 GiB, jail with 2 threads on 2 cores (cpus 2-3), Ollama 0.34.3', line)
        full = dict(self.OLD, **{k: prof(THREE).get(k) for k in evaluate.COMPUTE_FIELDS}, jail_threads=3, jail_cpus='1-3')
        line = evaluate.hardware_line(full)
        self.assertIn('4 cores (AVX2 + VNNI), 31.7 GiB, 1 × DDR5-4800 in a single channel (38.4 GB/s theoretical), jail '
                      'with 3 threads on 3 cores (cpus 1-3), num_ctx 8192, Ollama 0.34.3', line)
        # recorded before the profile existed: as before
        self.assertIn('Intel(R) N100, 4 cores, 31.7 GiB, Ollama 0.34.3, host fw', evaluate.hardware_line(self.OLD))

    def test_mixed_shares_are_pointed_out(self):
        two = dict(self.OLD, jail_threads=2, jail_cpus='2-3', num_ctx=8192)
        three = dict(self.OLD, jail_threads=3, jail_cpus='1-3', num_ctx=8192)
        self.assertEqual(evaluate.mixed_shares([{'model': 'a', 'hardware': two}, {'model': 'b', 'hardware': two}]), {})
        self.assertEqual(evaluate.mixed_shares([{'model': 'a', 'hardware': self.OLD}, {'model': 'b', 'hardware': two}]), {})
        mixed = evaluate.mixed_shares([{'model': 'a', 'hardware': two}, {'model': 'b', 'hardware': three},
                                       {'model': 'c', 'hardware': three}])
        self.assertEqual(mixed, {'2 threads on 2 cores (cpus 2-3), num_ctx 8192': ['a'],
                                 '3 threads on 3 cores (cpus 1-3), num_ctx 8192': ['b', 'c']})


class ShareTest(unittest.TestCase):
    """ what follows the share of the jail: the options of the direct calls, the load guard, the load score """

    def setUp(self):
        self.saved = compute.read_limits
        self.addCleanup(lambda: setattr(compute, 'read_limits', self.saved))

    def limits(self, doc):
        compute.read_limits = lambda path=None: doc

    def test_share_comes_from_the_limits_file(self):
        self.limits({})
        self.assertEqual(bench.share(), (2, 8192))
        self.limits(THREE)
        self.assertEqual(bench.share(), (3, 8192))
        self.limits({'threads': 'x', 'ctx': 16384})
        self.assertEqual(bench.share(), (2, 16384))

    def test_load_guard_follows_the_threads_and_stops_at_the_cores(self):
        self.assertEqual(bench.load_max(2, 4), 3.5)
        self.assertEqual(bench.load_max(3, 4), 4.0)
        self.assertEqual(bench.load_max(4, 4), 4.0)
        self.assertEqual(bench.load_max(6, 16), 7.5)
        sample = lambda load: {'load': [load, 0, 0], 'wan': {}}
        self.limits(TWO)
        self.assertEqual(bench.load_max(cores=4), 3.5)
        self.assertEqual(bench.unsafe([sample(3.8)] * bench.SUSTAIN), 'load average > 3.5')
        self.limits(THREE)
        orig = os.cpu_count
        os.cpu_count = lambda: 4
        try:
            self.assertIsNone(bench.unsafe([sample(3.8)] * bench.SUSTAIN))
            self.assertEqual(bench.unsafe([sample(4.2)] * bench.SUSTAIN), 'load average > 4.0')
        finally:
            os.cpu_count = orig

    def test_load_score_is_relative_to_the_share(self):
        self.assertEqual(evaluate.load_bounds(None), (2.0, 3.5))
        self.assertEqual(evaluate.load_bounds({'jail_threads': 2, 'cores': 4}), (2.0, 3.5))
        self.assertEqual(evaluate.load_bounds({'jail_threads': 3, 'cores': 4}), (3.0, 4.0))
        two = evaluate.perf_components('explain', 60, 90, 5, 20, 8, 2.3, {'jail_threads': 2, 'cores': 4})
        three = evaluate.perf_components('explain', 60, 90, 5, 20, 8, 3.3, {'jail_threads': 3, 'cores': 4})
        self.assertAlmostEqual(two['carga'], 0.8)
        self.assertAlmostEqual(three['carga'], 0.7)
        self.assertEqual(evaluate.perf_components('explain', 60, 90, 5, 20, 8, 3.3)['carga'],
                         evaluate.perf_components('explain', 60, 90, 5, 20, 8, 3.3, {})['carga'])


if __name__ == '__main__':
    unittest.main()
