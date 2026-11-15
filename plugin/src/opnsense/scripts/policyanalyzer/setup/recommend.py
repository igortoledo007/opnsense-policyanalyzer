"""
    Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

    Hardware profile and model recommendation for the local runtime.  Read
    only, no journal: hw_profile(ctx) probes the machine, recommend(profile)
    is a pure function (the tests feed it synthetic profiles).

    Estimates (docs/ollama-local-n100.md, section 3):
      generation (memory bound)  tg ~= effective bandwidth / bytes read per token * 0.9
                                 (bytes per token = Q4_K_M weights actually used per token; MoE: active part)
      prompt (compute bound)     pp ~= 23 * threads * core_factor * simd_factor / active params (billions)
                                 (23 calibrated on the N100: gemma3 4B, 4 threads, pp 23.8 t/s)
      one finding                600 tokens in / 250 out;  summary of 30 findings: 5000 in (pp at 75%) / 600 out
    They are estimates; the benchmark action measures the real numbers.

    GPU: the FreeBSD port misc/ollama has the backends CPU, VULKAN and MLX (no CUDA/ROCm on FreeBSD).
    Vulkan needs a GPU driver (drm-kmod amdgpu/i915kms or nvidia-driver), the vulkan ICD and the device
    nodes visible inside the jail; OPNsense ships none of them.  An integrated GPU shares the single
    memory channel, so it can not make generation faster.
"""

import os
import re
import xml.etree.ElementTree as ET

from . import common

GB = 1000 ** 3

# name: (file bytes Q4_K_M from registry.ollama.ai on 2026-11-07, params B, active params B,
#        kv bytes per token f16 (approx.), pt-BR quality 1 weak .. 4 very good, notes)
CANDIDATES = {
    'qwen2.5:1.5b': (986048512, 1.5, 1.5, 28672, 2, 'fast, weaker reasoning'),
    'gemma2:2b': (1629509152, 2.6, 2.6, 106496, 2, ''),
    'granite3.3:2b': (1545303328, 2.5, 2.5, 81920, 2, 'Portuguese officially supported'),
    'llama3.2:3b': (2019377376, 3.2, 3.2, 114688, 3, 'Portuguese officially supported'),
    'qwen2.5:3b': (1929903008, 3.1, 3.1, 36864, 3, 'small KV cache'),
    'phi3.5:3.8b': (2176177152, 3.8, 3.8, 393216, 1, 'large KV cache (no GQA), weak in pt-BR'),
    'phi4-mini:3.8b': (2491874624, 3.8, 3.8, 131072, 2, ''),
    'qwen3:4b': (2497280480, 4.0, 4.0, 147456, 3, 'use think=false'),
    'gemma3:4b': (2499012288 + 851251104, 4.3, 3.9, 139264, 4, 'includes a vision projector (0.85 GB, not read per token)'),
    'qwen2.5:7b': (4683073952, 7.6, 7.6, 57344, 4, ''),
    'qwen3:8b': (5225374496, 8.2, 8.2, 147456, 4, 'use think=false'),
    'llama3.1:8b': (4920738944, 8.0, 8.0, 131072, 3, ''),
    'granite3.3:8b': (4942873344, 8.2, 8.2, 163840, 3, ''),
    'qwen3:30b-a3b': (18556685856, 30.5, 3.3, 98304, 4, 'MoE, 3.3B active per token; hypothesis to measure'),
    'deepseek-r1:7b': (4683073184, 7.6, 7.6, 57344, 3, 'reasoning model (Qwen2.5 distill): long hidden thinking'),
    'deepseek-r1:8b': (5225373760, 8.2, 8.2, 147456, 3, 'reasoning model (Qwen3 distill): long hidden thinking'),
}
# origin shown to the user (who trains the model)
ORIGIN = {'qwen': 'Alibaba (China)', 'deepseek': 'DeepSeek (China)', 'kimi': 'Moonshot AI (China)',
          'llama': 'Meta', 'gemma': 'Google', 'phi': 'Microsoft', 'granite': 'IBM'}

# Not runnable locally, listed as an honest reference.  Checked on ollama.com/library on 2026-11-07:
# the Kimi family only has ":cloud" tags (manifest without layers: inference on Ollama's servers, the
# data leaves the firewall, and the jail has no egress anyway).  Kimi K2 is a ~1T parameter MoE with
# ~32B active; at Q4 the weights alone are about 550-600 GB.
REFERENCE_ONLY = {
    'kimi-k2.6:cloud': (1000, 32, '~1T-parameter MoE (~32B active), ~570 GB at Q4'),
    'kimi-k2.7-code:cloud': (1000, 32, '~1T-parameter MoE (~32B active), ~570 GB at Q4, coding model'),
    'kimi-k3:cloud': (None, None, 'Kimi K3, large MoE successor of K2 (size not published on ollama.com)'),
    'kimi-k3.1-pro:cloud': (None, None, 'Kimi K3.1 Pro, large MoE (size not published on ollama.com)'),
}
BUDGET_PCT_DEFAULT = 40
BUDGET_PCT_RANGE = (10, 75)
# bytes read per generated token, when it differs from the file (projector, MoE experts)
ACTIVE_BYTES = {
    'gemma3:4b': 2499012288,
    'qwen3:30b-a3b': int(18556685856 * 3.3 / 30.5 * 1.15),     # active experts + shared layers
}

# CPU families: (regex on hw.model, memory channels, default type/speed, core factor vs an E-core)
CPU_FAMILIES = [
    (r'\bN(50|95|97|100|150|200|250|300|305|350|355)\b|Atom x7', 1, ('DDR4', 3200), 1.0, 'Alder/Twin Lake-N, 1 channel'),
    (r'Celeron|Pentium (Silver|Gold)|Atom', 2, ('DDR4', 2400), 0.8, 'low power, assumed 2 channels'),
    (r'EPYC|Xeon|Threadripper', 4, ('DDR4', 2933), 1.6, 'server, assumed 4 channels'),
    (r'Ryzen|Core\(TM\)|Core Ultra|Intel\(R\) Core', 2, ('DDR4', 3200), 1.8, 'desktop/laptop, assumed 2 channels'),
]
BANDWIDTH_EFFICIENCY = 0.70
HEAVY_SERVICES = {
    'suricata': ('/var/run/suricata.pid',),
    'zenarmor': ('/var/run/eastpect.pid', '/usr/local/sensei'),
    'crowdsec': ('/var/run/crowdsec.pid', '/usr/local/etc/crowdsec'),
}
GPU_VENDORS = {'0x10de': 'nvidia', '0x1002': 'amd', '0x8086': 'intel'}
GPU_DRIVERS = {'nvidia': ('nvidia', 'nvidia-modeset'), 'amd': ('amdgpu',), 'intel': ('i915kms',)}


# ------------------------------------------------------------------ probes (read only)


def _sysctl(ctx, name):
    return common.sysctl(ctx, name)


def _int(text, default=None):
    return int(text) if re.match(r'^[0-9]+$', text or '') else default


def cpu_flags(ctx):
    """ instruction set flags from dmesg.boot (world readable) """
    text = common.read_text(ctx.root + '/var/run/dmesg.boot', limit=512 * 1024) or ''
    flags = set()
    for line in text.splitlines():
        if 'Features' in line and '<' in line:
            flags.update(f.strip().upper() for f in line.split('<', 1)[1].rstrip('>').split(','))
    return {
        'avx2': 'AVX2' in flags,
        'fma': 'FMA' in flags,
        'f16c': 'F16C' in flags,
        'avx512': any(f.startswith('AVX512') for f in flags),
        'avx_vnni': 'AVX_VNNI' in flags or 'AVXVNNI' in flags,
        'amx': any(f.startswith('AMX') for f in flags),
        'source': 'dmesg.boot' if flags else None,
    }


def dmidecode_memory(ctx):
    """ populated modules, type and speed; needs root (configd) """
    if not ctx.is_root:
        return None
    out = ctx.runner.read(['/usr/local/sbin/dmidecode', '-t', 'memory'], timeout=20)
    modules = []
    for block in out.split('\n\n'):
        if 'Memory Device' not in block:
            continue
        size = re.search(r'^\s*Size:\s*(.+)$', block, re.M)
        if not size or 'No Module' in size.group(1):
            continue
        mtype = re.search(r'^\s*Type:\s*(\S+)', block, re.M)
        speed = re.search(r'^\s*Configured (?:Memory|Clock) Speed:\s*([0-9]+)', block, re.M) or \
            re.search(r'^\s*Speed:\s*([0-9]+)', block, re.M)
        modules.append({'size': size.group(1).strip(), 'type': mtype.group(1) if mtype else None,
                        'speed': int(speed.group(1)) if speed else None})
    return modules or None


def gpus(ctx):
    out = ctx.runner.read(['/usr/sbin/pciconf', '-lv'], timeout=15)
    result = []
    current = None
    for line in out.splitlines():
        if not line.startswith(' ') and '@pci' in line:
            current = None
            match = re.search(r'class=0x(03[0-9a-f]{4}).*?\svendor=(0x[0-9a-f]{4}).*?\sdevice=(0x[0-9a-f]{4})', line)
            if match:
                current = {'vendor': GPU_VENDORS.get(match.group(2), match.group(2)), 'device_id': match.group(3),
                           'name': None, 'driver_loaded': False}
                result.append(current)
        elif current is not None and line.strip().startswith('device'):
            current['name'] = line.split('=', 1)[1].strip().strip("'")
    for gpu in result:
        for module in GPU_DRIVERS.get(gpu['vendor'], ()):
            if ctx.runner.run(['/sbin/kldstat', '-q', '-n', module], timeout=10)[0] == 0:
                gpu['driver_loaded'] = True
        gpu['integrated'] = gpu['vendor'] == 'intel'
    return result


def vulkan(ctx):
    def has(root):
        lib = any(os.path.exists(root + p) for p in ('/usr/local/lib/libvulkan.so.1', '/usr/local/lib/libvulkan.so'))
        icd_dir = root + '/usr/local/share/vulkan/icd.d'
        icds = sorted(os.listdir(icd_dir)) if os.path.isdir(icd_dir) else []
        return {'loader': lib, 'icds': icds}
    return {'host': has(ctx.root), 'jail': has(ctx.jail_dir)}


def _alive(ctx, pidfile):
    text = common.read_text(ctx.root + pidfile)
    pid = _int((text or '').split()[0] if text and text.split() else '')
    if pid is None:
        return False
    if not ctx.is_root:
        return 'unknown'           # security.bsd.see_other_uids=0 hides other users' processes
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def services(ctx):
    cfg = None
    try:
        cfg = ET.parse(ctx.root + '/conf/config.xml').getroot()
    except (OSError, ET.ParseError):
        pass

    def flag(path):
        node = cfg.find(path) if cfg is not None else None
        return (node.text or '').strip() == '1' if node is not None else None
    result = {}
    for name, paths in HEAVY_SERVICES.items():
        states = [_alive(ctx, p) for p in paths if p.endswith('.pid')]
        running = True if True in states else ('unknown' if 'unknown' in states else False)
        present = any(os.path.exists(ctx.root + p) for p in paths)
        result[name] = {'running': running, 'installed': present}
    result['suricata']['enabled'] = flag('OPNsense/IDS/general/enabled')
    result['suricata']['ips'] = flag('OPNsense/IDS/general/ips')
    result['crowdsec']['enabled'] = flag('OPNsense/crowdsec/general/agent_enabled')
    return result


def ram_usage(total, free_bytes_, arc):
    """ current use without the ZFS ARC (the ARC shrinks when a model needs the memory) """
    if not total:
        return {'total_bytes': None, 'used_bytes': None, 'used_pct': None, 'arc_bytes': arc or None}
    used = max(0, total - free_bytes_ - (arc or 0))
    return {'total_bytes': total, 'used_bytes': used, 'used_pct': round(100.0 * used / total, 1),
            'arc_bytes': arc or None}


def validate_budget(value):
    if value in (None, ''):
        return BUDGET_PCT_DEFAULT
    return common.as_int(value, BUDGET_PCT_RANGE[0], BUDGET_PCT_RANGE[1], 'budget_pct')


def hw_profile(ctx=None):
    ctx = ctx or common.Context()
    model = _sysctl(ctx, 'hw.model')
    ncpu = _int(_sysctl(ctx, 'hw.ncpu'), ctx.ncpu)
    cores = _int(_sysctl(ctx, 'kern.smp.cores'), ncpu)
    tpc = _int(_sysctl(ctx, 'kern.smp.threads_per_core'), 1)
    pagesize = _int(_sysctl(ctx, 'hw.pagesize'), 4096)
    physmem = _int(_sysctl(ctx, 'hw.physmem'))
    free_pages = sum(_int(_sysctl(ctx, n), 0) for n in ('vm.stats.vm.v_free_count', 'vm.stats.vm.v_inactive_count',
                                                       'vm.stats.vm.v_laundry_count'))
    arc = _int(_sysctl(ctx, 'kstat.zfs.misc.arcstats.size'), 0)
    arc_min = _int(_sysctl(ctx, 'kstat.zfs.misc.arcstats.c_min'), 0)
    load = re.findall(r'[0-9.]+', _sysctl(ctx, 'vm.loadavg'))
    from .runtime import current_limits
    limits = dict(common.DEFAULT_LIMITS)
    limits.update(current_limits(ctx))
    return {
        'cpu': {'model': model or None, 'threads': ncpu, 'cores': cores, 'threads_per_core': tpc,
                'flags': cpu_flags(ctx)},
        'memory': {'total_bytes': physmem,
                   'available_bytes': free_pages * pagesize + max(0, arc - arc_min) if physmem else None,
                   'arc_bytes': arc or None, 'modules': dmidecode_memory(ctx)},
        'ram': ram_usage(physmem, free_pages * pagesize, arc),
        'gpus': gpus(ctx),
        'vulkan': vulkan(ctx),
        'load': [float(v) for v in load[:3]] if load else None,
        'services': services(ctx),
        'models_free_bytes': common.free_bytes(ctx.models_dir),
        'limits': {k: limits[k] for k in ('cpus', 'threads', 'ctx', 'nice')},
        'root': ctx.is_root,
    }


# ------------------------------------------------------------------ estimation (pure)


def memory_bandwidth(profile):
    """ :return: (theoretical GB/s, effective GB/s, how it was obtained) """
    model = (profile.get('cpu') or {}).get('model') or ''
    family = next((f for f in CPU_FAMILIES if re.search(f[0], model)), None)
    max_channels = family[1] if family else 2
    mtype, speed = family[2] if family else ('DDR4', 3200)
    modules = (profile.get('memory') or {}).get('modules')
    if modules:
        speeds = [m['speed'] for m in modules if m.get('speed')]
        if speeds:
            speed = min(speeds)
        mtype = next((m['type'] for m in modules if m.get('type')), mtype)
        channels = min(len(modules), max_channels)
        how = 'dmidecode: %d module(s) %s-%d, %d channel(s) used' % (len(modules), mtype, speed, channels)
    else:
        channels = max_channels
        how = 'estimated from the CPU family (%s, %s-%d)' % (family[4] if family else 'unknown CPU, 2 channels assumed',
                                                             mtype, speed)
    theoretical = channels * speed * 8 / 1000.0
    return round(theoretical, 1), round(theoretical * BANDWIDTH_EFFICIENCY, 1), how


def core_factor(profile):
    model = (profile.get('cpu') or {}).get('model') or ''
    family = next((f for f in CPU_FAMILIES if re.search(f[0], model)), None)
    return family[3] if family else 1.5


def simd_factor(flags):
    if not flags.get('avx2'):
        return 0.4
    factor = 1.0
    if flags.get('avx512'):
        factor = 1.35
    elif flags.get('avx_vnni'):
        factor = 1.1
    return factor


def cpuset_size(cpus, ncpu):
    try:
        return len(common.parse_cpuset(cpus, max(ncpu, 1)))
    except ValueError:
        return max(1, ncpu // 2)


def estimate(name, profile, threads, bw_eff, gpu=None):
    size, params, active, kv, quality, note = CANDIDATES[name]
    ctx_tokens = 8192
    ram = size + kv * ctx_tokens + int(0.6 * GB)
    active_bytes = ACTIVE_BYTES.get(name, size)
    flags = (profile.get('cpu') or {}).get('flags') or {}
    thread_factor = min(1.0, 0.55 + 0.15 * threads)          # generation saturates the channel at 3-4 threads
    tg = bw_eff * GB / active_bytes * 0.9 * thread_factor
    pp = 23.0 * threads * core_factor(profile) * simd_factor(flags) / active
    if gpu:
        tg = gpu['bandwidth'] * GB / active_bytes * 0.6
        pp = pp * 8
    finding = 600 / pp + 250 / tg
    summary = 5000 / (pp * 0.75) + 600 / tg
    return {
        'model': name, 'size_gb': round(size / GB, 2), 'ram_gb': round(ram / GB, 2),
        'est_gen_tps': round(tg, 1), 'est_prompt_tps': round(pp, 1),
        'est_seconds_per_finding': int(round(finding)), 'est_seconds_summary_30': int(round(summary)),
        'pt_br': quality, 'note': note, 'params_b': params, 'active_params_b': active,
    }


def _usable_gpu(profile):
    """ a discrete GPU Ollama could really use through Vulkan inside the jail, else None """
    vk = (profile.get('vulkan') or {}).get('jail') or {}
    for gpu in profile.get('gpus') or []:
        if gpu.get('integrated') or gpu.get('vendor') not in ('nvidia', 'amd'):
            continue
        if gpu.get('driver_loaded') and vk.get('loader') and vk.get('icds'):
            return dict(gpu, bandwidth=gpu.get('bandwidth_gbs') or 200)
    return None


def recommend(profile, limits=None, budget_pct=None):
    """ :param budget_pct: share of the total RAM the model may use (10-75, default 40) """
    budget_pct = validate_budget(budget_pct)
    limits = dict(limits or profile.get('limits') or common.DEFAULT_LIMITS)
    cpu = profile.get('cpu') or {}
    ncpu = cpu.get('threads') or 1
    set_size = cpuset_size(limits.get('cpus', '2-3'), ncpu)
    tpc = cpu.get('threads_per_core') or 1
    threads = max(1, set_size // tpc) if tpc > 1 and set_size >= tpc else set_size
    theo, bw_eff, bw_how = memory_bandwidth(profile)
    mem = profile.get('memory') or {}
    total = mem.get('total_bytes') or 0
    avail = mem.get('available_bytes') or total
    reserve = max(2 * GB, 0.15 * total)                     # kept free for the firewall itself
    budget = min(total * budget_pct / 100.0, max(0, avail - reserve))
    services = profile.get('services') or {}
    suricata = services.get('suricata') or {}
    ips = bool(suricata.get('ips')) and suricata.get('running') in (True, 'unknown') and suricata.get('enabled') is not False
    heavy = [n for n, s in services.items() if s.get('running') is True or (s.get('running') == 'unknown' and s.get('enabled'))]
    target = 60 if ips else 90
    load1 = (profile.get('load') or [0])[0]
    notes = []
    gpu = _usable_gpu(profile)
    backend = 'gpu' if gpu else 'cpu'

    for g in profile.get('gpus') or []:
        if g.get('integrated'):
            notes.append('Integrated GPU %s: not used. It shares the same memory channel(s) as the CPU, so it can '
                         'not speed up generation, and OPNsense ships no i915kms/Vulkan driver.' % (g.get('name') or ''))
        elif not gpu:
            notes.append('GPU %s (%s) found but not usable: Ollama on FreeBSD has no CUDA/ROCm, only Vulkan, which '
                         'needs the %s driver loaded, a Vulkan ICD and the device nodes exposed in the jail '
                         '(devfs ruleset).' % (g.get('name') or g.get('device_id'), g.get('vendor'),
                                               'nvidia-driver' if g.get('vendor') == 'nvidia' else 'drm-kmod amdgpu'))
    if gpu:
        notes.append('Vulkan backend usable on %s: set ollama_use_vulkan=1 in the jail; GPU numbers are rough '
                     '(VRAM size and bandwidth not measured)' % (gpu.get('name') or gpu.get('vendor')))
    flags = cpu.get('flags') or {}
    if not flags.get('avx2'):
        notes.append('CPU without AVX2: prompt processing is several times slower')
    notes.append('Memory bandwidth %s GB/s theoretical, about %s GB/s effective (%s); generation speed is '
                 'bandwidth / model size' % (theo, bw_eff, bw_how))
    if ips:
        notes.append('Suricata in IPS mode: inference competes with inline inspection; target %ds per finding and '
                     'prefer running outside peak hours' % target)
    if load1 and load1 > 1.5:
        notes.append('current load %.2f: start explanations only when load1 < 1.5' % load1)
    if heavy:
        notes.append('services competing for CPU/memory: %s' % ', '.join(sorted(heavy)))

    candidates = []
    for name in CANDIDATES:
        cand = estimate(name, profile, threads, bw_eff, gpu)
        reasons = []
        verdict = 'recommended'
        ram = cand['ram_gb'] * GB
        size = CANDIDATES[name][0]
        if not total:
            verdict = 'possible'
            reasons.append('RAM size unknown')
        elif ram > max(0, avail - reserve):
            verdict = 'not_recommended'
            reasons.append('needs %.1f GB of RAM, %.1f GB available after keeping %.1f GB free for the firewall'
                           % (cand['ram_gb'], max(0, avail - reserve) / GB, reserve / GB))
        elif ram > budget:
            verdict = 'possible'
            reasons.append('uses %.1f GB of RAM, above the %.1f GB budget (%d%% of the RAM)'
                           % (cand['ram_gb'], budget / GB, budget_pct))
        secs = cand['est_seconds_per_finding']
        if secs > 180:
            verdict = 'not_recommended'
            reasons.append('about %ds per finding' % secs)
        elif secs > target:
            if verdict == 'recommended':
                verdict = 'possible'
            reasons.append('about %ds per finding (target %ds)' % (secs, target))
        if cand['pt_br'] <= 1:
            verdict = 'not_recommended' if verdict != 'recommended' else 'possible'
            reasons.append('weak in Brazilian Portuguese')
        elif cand['pt_br'] == 2 and verdict == 'recommended':
            reasons.append('acceptable pt-BR, less precise')
        if size > 6 * common.GIB:
            reasons.append('larger than 6 GiB: pull with +large')
        if 'reasoning model' in cand['note']:
            if verdict == 'recommended':
                verdict = 'possible'
            reasons.append('reasoning model: hundreds of thinking tokens before the answer, real time per '
                           'finding several times the estimate')
        if 'MoE' in cand['note']:
            reasons.append('MoE estimate not measured yet')
        if ips and cand['size_gb'] > 3 and verdict == 'recommended':
            verdict = 'possible'
            reasons.append('heavier memory traffic while Suricata inspects inline')
        if verdict == 'recommended' and not [r for r in reasons if not r.startswith(('larger than', 'MoE'))]:
            reasons.append('fits the RAM budget, about %ds per finding, pt-BR quality %d/4' % (secs, cand['pt_br']))
        if models_free(profile) is not None and size > models_free(profile):
            verdict = 'not_recommended'
            reasons.append('not enough disk space in the models directory')
        cand['verdict'] = verdict
        cand['reasons'] = reasons
        cand['origin'] = origin(name)
        cand['local'] = True
        # ready-made arguments of the pull_model button (dispatcher tokens)
        cand['action'] = {'id': 'pull_model', 'args': [name] + (['+large'] if size > 6 * common.GIB else []),
                          'label': 'Download %s' % name}
        candidates.append(cand)
    reference = [reference_candidate(name) for name in REFERENCE_ONLY]

    order = {'recommended': 0, 'possible': 1, 'not_recommended': 2}
    good = [c for c in candidates if c['verdict'] == 'recommended']
    pool = good or [c for c in candidates if c['verdict'] == 'possible']
    pool.sort(key=lambda c: (-c['pt_br'], c['est_seconds_per_finding']))
    recommended = pool[0]['model'] if pool else None
    alternatives = [c['model'] for c in sorted(candidates, key=lambda c: (order[c['verdict']], -c['pt_br'],
                                                                         c['est_seconds_per_finding']))
                    if c['model'] != recommended and c['verdict'] != 'not_recommended'][:3]
    if not recommended:
        notes.append('no model fits this hardware as a local runtime: use a model server on the network')
    small_ram = total and total < 12 * GB
    num_ctx = 4096 if small_ram else min(int(limits.get('ctx') or 8192), 8192)
    candidates.sort(key=lambda c: (order[c['verdict']], -c['pt_br'], c['est_seconds_per_finding']))
    candidates += reference
    notes.append('Kimi (Moonshot AI) is only offered as ":cloud" on Ollama: ~1T-parameter MoE models, about '
                 '570 GB at Q4, impossible on %.0f GB; listed for reference, never pulled' % (total / GB if total else 0))
    return {
        'profile': profile,
        'backend': backend,
        'bandwidth_gbs': {'theoretical': theo, 'effective': bw_eff, 'source': bw_how},
        'settings': {'num_thread': threads, 'num_ctx': num_ctx, 'cpus': limits.get('cpus'),
                     'ram_budget_pct': budget_pct, 'ram_budget_bytes': int(budget),
                     'ram_reserve_bytes': int(reserve),
                     'reason': '%d cpu(s) in the jail cpuset%s; num_ctx %d' % (
                         set_size, ' (SMT siblings counted once)' if tpc > 1 else '', num_ctx)},
        'candidates': candidates,
        'recommended': recommended,
        'alternatives': alternatives,
        'notes': notes,
        'estimates': 'rough, from bandwidth and core count; run the benchmark action for real numbers',
    }


def origin(name):
    return next((v for k, v in ORIGIN.items() if name.startswith(k)), None)


def reference_candidate(name):
    params, active, what = REFERENCE_ONLY[name]
    reasons = ['only available as a cloud model on Ollama (no local weights): the data would leave the firewall',
               what + ': far beyond the RAM and bandwidth of this host']
    return {'model': name, 'size_gb': round(params * 0.57) if params else None, 'ram_gb': None,
            'est_gen_tps': None, 'est_prompt_tps': None, 'est_seconds_per_finding': None,
            'est_seconds_summary_30': None, 'pt_br': None, 'note': what, 'params_b': params,
            'active_params_b': active, 'verdict': 'not_recommended', 'reasons': reasons,
            'origin': origin(name), 'local': False}


def models_free(profile):
    return profile.get('models_free_bytes')


def recommended_model(ctx=None, budget_pct=None):
    return recommend(hw_profile(ctx), budget_pct=budget_pct).get('recommended')
