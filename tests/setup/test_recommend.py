"""
Hardware profile (read only probes) and model recommendation on synthetic profiles.
"""

import copy
import json
import os
import unittest
import unittest.mock

from setup_helpers import SetupTestCase, common

from setup import actions, adapter, models, recommend

GB = 1000 ** 3
FLAGS_AVX2 = {'avx2': True, 'fma': True, 'f16c': True, 'avx512': False, 'avx_vnni': False, 'amx': False}
NO_SERVICES = {'suricata': {'running': False, 'installed': False, 'enabled': None, 'ips': None},
               'zenarmor': {'running': False, 'installed': False},
               'crowdsec': {'running': False, 'installed': False, 'enabled': None}}


def profile(model, threads, total_gb, avail_gb, gpus=(), flags=FLAGS_AVX2, modules=None, vulkan_jail=None,
            tpc=1, services=None, cpus='2-3', load=(0.3, 0.3, 0.3)):
    return {
        'cpu': {'model': model, 'threads': threads, 'cores': threads // tpc, 'threads_per_core': tpc,
                'flags': dict(flags)},
        'memory': {'total_bytes': int(total_gb * GB), 'available_bytes': int(avail_gb * GB), 'modules': modules},
        'gpus': list(gpus),
        'vulkan': {'host': {'loader': False, 'icds': []}, 'jail': vulkan_jail or {'loader': False, 'icds': []}},
        'load': list(load),
        'services': copy.deepcopy(services or NO_SERVICES),
        'models_free_bytes': 400 * GB,
        'limits': {'cpus': cpus, 'threads': 2, 'ctx': 8192, 'nice': 20},
    }


N100 = profile('Intel(R) N100', 4, 34.0, 28.0,
               gpus=[{'vendor': 'intel', 'name': 'Alder Lake-N [UHD Graphics]', 'integrated': True,
                      'driver_loaded': False}])
I5 = profile('13th Gen Intel(R) Core(TM) i5-1335U', 12, 16.0, 11.0, tpc=2, cpus='4-7',
             gpus=[{'vendor': 'intel', 'name': 'Raptor Lake-P [Iris Xe Graphics]', 'integrated': True,
                    'driver_loaded': True}],
             modules=[{'size': '8 GB', 'type': 'DDR5', 'speed': 5200}, {'size': '8 GB', 'type': 'DDR5', 'speed': 5200}])
NVIDIA = {'vendor': 'nvidia', 'name': 'GA106 [GeForce RTX 3060]', 'integrated': False, 'driver_loaded': True}
RYZEN = profile('AMD Ryzen 7 5700G with Radeon Graphics', 16, 64.0, 55.0, tpc=2, cpus='8-15', gpus=[NVIDIA],
                vulkan_jail={'loader': True, 'icds': ['nvidia_icd.json']})
SMALL = profile('Intel(R) Celeron(R) J4125 CPU @ 2.00GHz', 4, 8.0, 5.0)


def by_name(result):
    return {c['model']: c for c in result['candidates']}


class TestRecommend(unittest.TestCase):
    def check_shape(self, result):
        self.assertEqual(set(result) >= {'profile', 'backend', 'candidates', 'recommended', 'alternatives',
                                         'notes'}, True)
        for cand in [c for c in result['candidates'] if c['local']]:
            for key in ('model', 'size_gb', 'ram_gb', 'est_gen_tps', 'est_prompt_tps', 'est_seconds_per_finding',
                        'verdict', 'reasons'):
                self.assertIn(key, cand)
            self.assertIn(cand['verdict'], ('recommended', 'possible', 'not_recommended'))
            self.assertTrue(cand['reasons'])
        json.dumps(result)          # stable, serialisable output
        if result['recommended']:
            self.assertIn(result['recommended'], models.ALLOWED_MODELS)   # pull_model accepts it directly

    def test_n100_32gb_no_gpu(self):
        res = recommend.recommend(N100)
        self.check_shape(res)
        self.assertEqual(res['backend'], 'cpu')
        self.assertEqual(res['bandwidth_gbs']['theoretical'], 25.6)
        self.assertEqual(res['settings']['num_thread'], 2)
        self.assertEqual(res['settings']['num_ctx'], 8192)
        cands = by_name(res)
        # docs/ollama-local-n100.md 3.3: 3B with 2 threads, tg 6-8, pp 14-18, about 75-80 s per finding
        self.assertTrue(6 <= cands['qwen2.5:3b']['est_gen_tps'] <= 8.5)
        self.assertTrue(12 <= cands['qwen2.5:3b']['est_prompt_tps'] <= 18)
        self.assertTrue(60 <= cands['qwen2.5:3b']['est_seconds_per_finding'] <= 95)
        self.assertIn(res['recommended'], ('qwen2.5:3b', 'llama3.2:3b'))
        for big in ('qwen3:8b', 'qwen2.5:7b', 'llama3.1:8b'):
            self.assertEqual(cands[big]['verdict'], 'not_recommended')
        self.assertNotEqual(cands['qwen3:30b-a3b']['verdict'], 'recommended')
        self.assertTrue(any('Integrated GPU' in n for n in res['notes']))

    def test_budget_pct(self):
        default = recommend.recommend(N100)
        self.assertEqual(default['settings']['ram_budget_pct'], 40)
        self.assertEqual(by_name(default)['qwen3:30b-a3b']['verdict'], 'possible')
        wide = recommend.recommend(N100, budget_pct=70)
        self.check_shape(wide)
        self.assertEqual(wide['settings']['ram_budget_pct'], 70)
        moe = by_name(wide)['qwen3:30b-a3b']
        self.assertEqual(moe['verdict'], 'recommended', moe['reasons'])
        self.assertEqual(wide['recommended'], 'qwen3:30b-a3b')
        self.assertTrue(any('+large' in r for r in moe['reasons']))
        # the firewall reserve still applies: little free RAM keeps the MoE out even at 75%
        tight = copy.deepcopy(N100)
        tight['memory']['available_bytes'] = int(22 * GB)
        self.assertEqual(by_name(recommend.recommend(tight, budget_pct=75))['qwen3:30b-a3b']['verdict'],
                         'not_recommended')
        # and so does the time limit (a single slow core set)
        slow = copy.deepcopy(N100)
        slow['limits']['cpus'] = '3'
        self.assertNotEqual(by_name(recommend.recommend(slow, budget_pct=70))['qwen3:30b-a3b']['verdict'],
                            'recommended')
        for bad in (5, 80, 'x'):
            with self.assertRaises(ValueError):
                recommend.recommend(N100, budget_pct=bad)

    def test_chinese_models(self):
        res = recommend.recommend(N100, budget_pct=70)
        cands = by_name(res)
        for name in ('kimi-k2.6:cloud', 'kimi-k3:cloud'):
            self.assertEqual(cands[name]['verdict'], 'not_recommended')
            self.assertFalse(cands[name]['local'])
            self.assertTrue(any('cloud' in r for r in cands[name]['reasons']))
            self.assertNotIn(name, models.ALLOWED_MODELS)
            self.assertEqual(cands[name]['origin'], 'Moonshot AI (China)')
        self.assertEqual(cands['qwen3:4b']['origin'], 'Alibaba (China)')
        self.assertEqual(cands['deepseek-r1:8b']['origin'], 'DeepSeek (China)')
        self.assertNotEqual(cands['deepseek-r1:7b']['verdict'], 'recommended')     # long thinking
        self.assertTrue(any('Kimi' in n for n in res['notes']))

    def test_n100_with_suricata_ips(self):
        prof = copy.deepcopy(N100)
        prof['services']['suricata'] = {'running': True, 'installed': True, 'enabled': True, 'ips': True}
        res = recommend.recommend(prof)
        self.assertTrue(any('IPS' in n for n in res['notes']))
        rec = by_name(res)[res['recommended']]
        self.assertLessEqual(rec['est_seconds_per_finding'], 60)

    def test_i5_with_igpu(self):
        res = recommend.recommend(I5)
        self.check_shape(res)
        self.assertEqual(res['backend'], 'cpu')                 # iGPU never used
        self.assertIn('dmidecode', res['bandwidth_gbs']['source'])
        self.assertEqual(res['bandwidth_gbs']['theoretical'], 83.2)  # 2 x DDR5-5200
        self.assertEqual(res['settings']['num_thread'], 2)          # 4 cpus in the set, SMT counted once
        cands = by_name(res)
        self.assertGreater(cands['qwen2.5:3b']['est_gen_tps'], by_name(recommend.recommend(N100))['qwen2.5:3b']
                           ['est_gen_tps'])

    def test_ryzen_with_nvidia(self):
        res = recommend.recommend(RYZEN)
        self.check_shape(res)
        self.assertEqual(res['backend'], 'gpu')
        self.assertTrue(any('Vulkan backend usable' in n for n in res['notes']))
        # same box without the driver: honest cpu fallback with an explanation
        prof = copy.deepcopy(RYZEN)
        prof['gpus'][0]['driver_loaded'] = False
        res = recommend.recommend(prof)
        self.assertEqual(res['backend'], 'cpu')
        self.assertTrue(any('not usable' in n and 'CUDA' in n for n in res['notes']))

    def test_small_ram(self):
        res = recommend.recommend(SMALL)
        self.check_shape(res)
        cands = by_name(res)
        self.assertEqual(res['settings']['num_ctx'], 4096)
        for name in ('qwen3:8b', 'qwen2.5:7b', 'qwen3:30b-a3b', 'gemma3:4b'):
            self.assertEqual(cands[name]['verdict'], 'not_recommended', name)
        self.assertTrue(any('RAM' in r for r in cands['qwen3:8b']['reasons']))
        self.assertIsNotNone(res['recommended'])
        self.assertLess(cands[res['recommended']]['ram_gb'], 3.5)

    def test_no_avx2(self):
        prof = copy.deepcopy(N100)
        prof['cpu']['flags'] = {k: False for k in FLAGS_AVX2}
        res = recommend.recommend(prof)
        self.assertTrue(any('AVX2' in n for n in res['notes']))
        self.assertLess(by_name(res)['qwen2.5:3b']['est_prompt_tps'], by_name(recommend.recommend(N100))
                        ['qwen2.5:3b']['est_prompt_tps'])


class TestHwProfile(SetupTestCase):
    def setUp(self):
        super().setUp()
        self.system.sysctl.update({'hw.model': 'Intel(R) N100', 'kern.smp.cores': '4',
                                   'kern.smp.threads_per_core': '1', 'hw.pagesize': '4096',
                                   'hw.physmem': '34036920320', 'vm.stats.vm.v_free_count': '6291587',
                                   'vm.stats.vm.v_inactive_count': '970635', 'vm.stats.vm.v_laundry_count': '0',
                                   'kstat.zfs.misc.arcstats.size': '1332440200',
                                   'kstat.zfs.misc.arcstats.c_min': '1000000000', 'vm.loadavg': '{ 0.13 0.18 0.22 }'})
        os.makedirs(self.root + '/var/run', exist_ok=True)
        with open(self.root + '/var/run/dmesg.boot', 'w') as handle:
            handle.write('  Features2=0x7ffafbbf<SSE3,FMA,AVX,F16C>\n'
                         '  Structured Extended Features=0x239ca7eb<FSGSBASE,BMI1,AVX2,SHA>\n')
        with open(self.root + '/var/run/suricata.pid', 'w') as handle:
            handle.write('999999\n')
        os.makedirs(self.root + '/conf')
        with open(self.root + '/conf/config.xml', 'w') as handle:
            handle.write('<opnsense><OPNsense><IDS><general><enabled>1</enabled><ips>1</ips></general></IDS>'
                         '</OPNsense></opnsense>')
        pci = ('vgapci0@pci0:0:2:0:\tclass=0x030000 rev=0x00 hdr=0x00 vendor=0x8086 device=0x46d1 subvendor=0x8086 '
               'subdevice=0x7270\n    vendor     = \'Intel Corporation\'\n    device     = \'Alder Lake-N [UHD Graphics]\'\n'
               'xhci0@pci0:0:20:0:\tclass=0x0c0330 rev=0x00 hdr=0x00 vendor=0x8086 device=0x54ed\n')
        base_run = self.system.run

        def run(argv, timeout=600, env=None, cancel=None):
            if argv[0] == '/usr/sbin/pciconf':
                self.system.calls.append(list(argv))
                return 0, pci, ''
            if argv[0] == '/sbin/kldstat':
                self.system.calls.append(list(argv))
                return 1, '', ''
            if argv[0] == '/usr/local/sbin/dmidecode':
                self.system.calls.append(list(argv))
                return 0, ('Memory Device\n\tSize: 32 GB\n\tType: DDR4\n\tSpeed: 3200 MT/s\n'
                           '\tConfigured Memory Speed: 3200 MT/s\n\nMemory Device\n\tSize: No Module Installed\n'), ''
            return base_run(argv, timeout, env, cancel)
        self.system.run = run

    def test_profile_is_read_only_and_parsed(self):
        before = self.tree()
        prof = recommend.hw_profile(self.ctx)
        self.assertEqual(self.tree(), before)
        self.assertEqual(self.system.writes(), [])
        self.assertEqual(prof['cpu']['model'], 'Intel(R) N100')
        self.assertTrue(prof['cpu']['flags']['avx2'])
        self.assertFalse(prof['cpu']['flags']['avx512'])
        self.assertEqual(prof['gpus'], [{'vendor': 'intel', 'device_id': '0x46d1', 'name': 'Alder Lake-N [UHD Graphics]',
                                          'driver_loaded': False, 'integrated': True}])
        self.assertEqual(prof['memory']['modules'], [{'size': '32 GB', 'type': 'DDR4', 'speed': 3200}])
        self.assertEqual(prof['services']['suricata']['ips'], True)
        self.assertFalse(prof['services']['suricata']['running'])          # stale pid file
        self.assertEqual(prof['load'], [0.13, 0.18, 0.22])
        res = recommend.recommend(prof)
        self.assertIn('dmidecode: 1 module', res['bandwidth_gbs']['source'])
        self.assertEqual(res['bandwidth_gbs']['theoretical'], 25.6)

    def test_probes_and_plan_actions(self):
        self.assertEqual(set(adapter.STATUS_PROBES), {'runtime', 'setup_job', 'hw_profile', 'recommend'})
        with unittest.mock.patch.object(adapter, 'CONTEXT_FACTORY', lambda: self.ctx):
            self.assertEqual(adapter.status_recommend(['60'])['settings']['ram_budget_pct'], 60)
            self.assertEqual(adapter.status_recommend(['90'])['status'], 'error')
        self.assertEqual(actions.plan('recommend', {'budget_pct': '70'}, self.ctx)['result']['settings']
                         ['ram_budget_pct'], 70)
        prof = actions.plan('hw_profile', {}, self.ctx)['result']
        self.assertGreater(prof['ram']['used_pct'], 0)
        self.assertLess(prof['ram']['used_pct'], 100)
        res = actions.plan('recommend', {}, self.ctx)
        self.assertEqual(res['status'], 'ok')
        self.assertIn(res['result']['recommended'], models.ALLOWED_MODELS)
        plan = actions.plan('pull_model', {'model': res['result']['recommended']}, self.ctx)
        self.assertNotEqual(plan['status'], 'error', plan)            # accepted without +custom
        self.assertEqual(actions.plan('hw_profile', {}, self.ctx)['result']['cpu']['threads'], 4)


if __name__ == '__main__':
    unittest.main()
