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

    AI scenarios: the catalog of every place of the plugin that calls the AI,
    and the per scenario routing (provider, model, limits, sync or queue).

        route = resolve('incident_summary', config)     -> Route
        route.provider, route.options, route.timeout, route.mode, route.fallback, ...

    The routing lives in /var/db/policyanalyzer/ai-routing.json, written only by
    the change action "ai_routing" (plan/apply/revert, see routing_actions.py):

        {"version": 1, "preset": "local_only"|"hybrid"|"custom"|null,
         "fallback": {"provider": "auto"|"none"|"ollama"|"claudecode"|"claude", "model": ""},
         "scenarios": {"<id>": {"provider": "default"|"ollama"|..., "model": "", "mode": "sync"|"queue"|"auto",
                                "timeout": 600, "num_ctx": 8192, "num_predict": 600, "keep_alive": "30m",
                                "budget": 1500, "retries": 1}},
         "effective": {"<id>": {"provider", "model", "mode", "php_timeout"}},     derived, read by the PHP API
         "updated": "ISO"}

    Without the file every scenario follows the global provider of the settings,
    synchronously, exactly like before (the only addition is the automatic
    fallback to the local Ollama when the AI setup installed it).
"""

import copy
import json
import os
import re
import time

from .config import CONFIG_XML

ROUTING_FILE = os.environ.get('POLICYANALYZER_AI_ROUTING', '/var/db/policyanalyzer/ai-routing.json')
LIMITS_FILE = os.environ.get('POLICYANALYZER_LIMITS', '/var/db/policyanalyzer/runtime-limits.json')

PROVIDERS = ('default', 'ollama', 'claudecode', 'claude')
MODES = ('sync', 'queue', 'auto')
FALLBACK_PROVIDERS = ('auto', 'none', 'ollama', 'claudecode', 'claude')
MAX_TIMEOUT = 1800                      # 30 min, local CPU models on long prompts
MAX_BUDGET = 32000
MODEL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$')
KEEP_ALIVE_RE = re.compile(r'^([0-9]{1,4}[smh]|0|-1)$')
FIELDS = ('provider', 'model', 'mode', 'timeout', 'num_ctx', 'num_predict', 'keep_alive', 'budget', 'retries', 'think',
          'think_budget')
# reasoning of thinking models on Ollama: off (default, think=false), on (think=true, extra num_predict for the reasoning)
# or a level (low/medium/high: gpt-oss); models without the thinking capability always get think=false
THINK_VALUES = ('off', 'on', 'low', 'medium', 'high')
THINK_ALIASES = {'false': 'off', 'no': 'off', '0': 'off', 'true': 'on', 'yes': 'on', '1': 'on'}
INT_FIELDS = {'timeout': (10, MAX_TIMEOUT), 'num_ctx': (1024, 131072), 'num_predict': (32, 8192),
              'budget': (300, MAX_BUDGET), 'retries': (0, 2), 'think_budget': (512, 16384)}

LOCAL_SHORT = 'qwen2.5:3b'
LOCAL_LONG = 'qwen3:30b-a3b'
BRIDGE_MODEL = 'fable'

# ------------------------------------------------------------------ catalog
#
# kind        short: prompt up to ~900 tokens (25-75 s on the N100 with qwen2.5:3b)
#             long:  1.5k-5k tokens (2-7 min or more): background or queue on the local runtime
# background  the caller already runs in the background (brief child, cron, report): "queue" is not used,
#             the call is made in that process
# eta         seconds measured with qwen2.5:3b on the N100 (docs/bench-ia-local.md), the default estimate of
#             the queue before the history has its own numbers
# checks      validation of the answer (ai/validate.py), one correction attempt when it fails;
#             "publish": the text goes to an e-mail, a PDF or the dashboard: strict language check, and an answer
#             that is still in the wrong language / leaked reasoning after the retries is REJECTED (AnswerRejected,
#             a ProviderError: the fallback route, then the deterministic text of the caller)
# structured  JSON Schema output on Ollama (Task.schema), converted back to the format the module expects
# mapreduce   batches + consolidation when the data is above the budget of the route

SECTIONS_FINDING = ['o que significa|what it means', 'por que importa|why it matters|por que é importante',
                    'o que eu verificaria|what i would check|o que verificar|verificaria',
                    'mudança sugerida|suggested change|alteração sugerida']
SECTIONS_SET = ['visão geral|overview|panorama', 'prioridades|priorities', 'plano de limpeza|clean-up|limpeza|plano']
SECTIONS_ANOMALY = ['detectado|what was detected|foi detectado', 'explicações|likely explanations|explicacoes',
                    'verificaria|what i would check|verificar', 'ações sugeridas|suggested actions|ações']
SECTIONS_HOST = ['parece|who it looks like|looks like', 'normal', 'achados|findings',
                 'verificaria|what i would check|verificar']
SECTIONS_CVE = ['impact|impacto', 'priority|prioridade', 'mitig', 'virtual', 'fix|correção|correcao|atualiza']

CATALOG = {
    'explain_finding': {'label': 'Policy Analyzer: explain a finding', 'module': 'findings', 'kind': 'short',
                        'eta': 105, 'checks': {'sections': SECTIONS_FINDING}},
    'explain_set': {'label': 'Policy Analyzer: explain the whole report', 'module': 'findings', 'kind': 'long',
                    'eta': 900, 'mapreduce': True, 'checks': {'sections': SECTIONS_SET}},
    'war_room_brief': {'label': 'Max Cyber AI ANALYST (general brief)', 'module': 'brief', 'kind': 'long',
                       'background': True, 'eta': 125, 'checks': {'sentences': [1, 4], 'plain': True, 'publish': True}},
    'war_room_focus': {'label': 'Max Cyber AI ANALYST (focus on an address)', 'module': 'brief', 'kind': 'long',
                       'background': True, 'eta': 130, 'checks': {'sentences': [1, 4], 'plain': True, 'publish': True}},
    'console_ask': {'label': 'AI Console: question', 'module': 'console', 'kind': 'long', 'eta': 360,
                    'mapreduce': True, 'checks': {'citations': 1}},
    'console_explain_log': {'label': 'AI Console: explain a log line', 'module': 'console', 'kind': 'long',
                            'eta': 360, 'mapreduce': True, 'checks': {'citations': 1, 'headings': 2}},
    'console_explain_rule': {'label': 'AI Console: explain a rule', 'module': 'console', 'kind': 'long',
                             'eta': 320, 'mapreduce': True, 'checks': {'citations': 1, 'headings': 2}},
    'console_explain_alert': {'label': 'AI Console: explain a Suricata alert', 'module': 'console', 'kind': 'long',
                              'eta': 340, 'mapreduce': True, 'checks': {'citations': 1, 'headings': 2}},
    'incident_summary': {'label': 'Incidents: summarize a case', 'module': 'incidents', 'kind': 'long',
                         'eta': 480, 'structured': True, 'checks': {'json': ['summary'], 'actions': True}},
    'incident_digest': {'label': 'Incidents: daily digest', 'module': 'incidents', 'kind': 'long', 'eta': 220,
                        'checks': {'sentences': [2, 8], 'plain': True, 'publish': True}},
    'anomaly_explain': {'label': 'Anomalies: explain an anomaly', 'module': 'anomalies', 'kind': 'long',
                        'eta': 175, 'checks': {'sections': SECTIONS_ANOMALY}},
    'anomaly_host': {'label': 'Anomalies: explain a host', 'module': 'anomalies', 'kind': 'long', 'eta': 320,
                     'checks': {'sections': SECTIONS_HOST}},
    'explain_cve': {'label': 'Vulnerabilities: explain a CVE', 'module': 'vulns', 'kind': 'short', 'eta': 65,
                    'checks': {'sections': SECTIONS_CVE}},
    'vuln_review_suggest': {'label': 'Vulnerabilities: mapping suggestion', 'module': 'vulns', 'kind': 'short',
                            'eta': 50, 'structured': True, 'checks': {'first_line': 'MAPPING'}},
    'explain_device': {'label': 'Devices: explain a device', 'module': 'devices', 'kind': 'short', 'eta': 70,
                       'structured': True, 'checks': {'first_line': 'TYPE', 'words': [0, 260]}},
    'posture_check': {'label': 'Posture: explain a check', 'module': 'posture', 'kind': 'short', 'eta': 60,
                      'checks': {'words': [96, 264]}},
    'posture_summary': {'label': 'Posture: executive summary', 'module': 'posture', 'kind': 'long', 'eta': 150,
                        'checks': {'words': [144, 360], 'publish': True}},
    'shadowai_overview': {'label': 'AI usage (shadow AI): overview', 'module': 'shadowai', 'kind': 'long',
                          'eta': 310, 'checks': {'words': [120, 300]}},
    'minrule_explain': {'label': 'Minimal rule: risk explanation', 'module': 'minrule', 'kind': 'short', 'eta': 75,
                        'checks': {'words': [120, 300]}},
    'report_summary': {'label': 'Reports: executive summary of the report', 'module': 'reports', 'kind': 'long',
                       'background': True, 'eta': 255, 'checks': {'sentences': [3, 5], 'plain': True, 'publish': True}},
    'notification_summary': {'label': 'Reports: notification summary', 'module': 'reports', 'kind': 'short',
                             'background': True, 'eta': 30, 'checks': {'sentences': [1, 3], 'plain': True, 'publish': True}},
    'quicktest': {'label': 'AI setup: quick test', 'module': 'setup', 'kind': 'short', 'eta': 25, 'checks': {}},
}
SCENARIOS = tuple(CATALOG)
# task names that use the route of another scenario (map/reduce parts pass Task(scenario=...) instead)
ALIASES = {'shadowai_host': 'shadowai_overview'}

# local defaults: one num_ctx per model (a different num_ctx reloads the model in Ollama)
LOCAL_SHORT_ROUTE = {'provider': 'ollama', 'model': LOCAL_SHORT, 'mode': 'sync', 'timeout': 600, 'num_ctx': 8192,
                     'num_predict': 600, 'keep_alive': '30m', 'budget': 1500, 'retries': 1}
LOCAL_LONG_ROUTE = {'provider': 'ollama', 'model': LOCAL_LONG, 'mode': 'queue', 'timeout': 1800, 'num_ctx': 8192,
                    'num_predict': 1200, 'keep_alive': '30m', 'budget': 4000, 'retries': 1}
BRIDGE_ROUTE = {'provider': 'claudecode', 'model': BRIDGE_MODEL, 'mode': 'sync', 'timeout': 300, 'retries': 1}

# hybrid: the bench of 2026-11-08 (docs/bench-ia-local.md): local where qwen2.5:3b answered well in < 75 s,
# local in the background where minutes are fine, the bridge (Fable) for the interactive long ones
HYBRID_LOCAL = ('quicktest', 'notification_summary', 'explain_cve', 'explain_device', 'posture_check',
                'minrule_explain', 'explain_finding', 'vuln_review_suggest')
HYBRID_BACKGROUND = ('war_room_brief', 'posture_summary', 'report_summary')
PRESETS = {
    'local_only': {'label': 'Local only', 'help': 'Everything on the Ollama of this firewall: qwen2.5:3b for the '
                   'short scenarios (synchronous), qwen3:30b-a3b for the long ones (background queue). Nothing '
                   'leaves the firewall; long answers take minutes.'},
    'hybrid': {'label': 'Hybrid', 'help': 'Short scenarios and background summaries on the local Ollama, the '
               'interactive long ones (AI Console, Incidents, Anomalies, AI usage, whole report, focus brief) on '
               'Claude Code (LAN) with Fable; the local runtime is the fallback when the bridge is down.'},
    'global': {'label': 'Follow the global provider', 'help': 'Removes every per scenario setting: all scenarios '
               'use the provider of the settings above, synchronously, as before.'},
}


def preset_scenarios(name):
    """ :return: {scenario: entry} of a preset ("global" -> {}) """
    if name not in PRESETS:
        raise ValueError('unknown preset "%s"' % name)
    out = {}
    if name == 'global':
        return out
    for sid, meta in CATALOG.items():
        if name == 'local_only' or sid in HYBRID_LOCAL or sid in HYBRID_BACKGROUND:
            base = LOCAL_SHORT_ROUTE if meta['kind'] == 'short' else LOCAL_LONG_ROUTE
            if name == 'hybrid' and sid in HYBRID_BACKGROUND:
                base = LOCAL_LONG_ROUTE
        else:
            base = BRIDGE_ROUTE
        entry = dict(base)
        if meta.get('background') and entry.get('mode') == 'queue':
            # already in the background (brief child, cron): same process; the brief marks a run older than
            # 15 min as interrupted, so it gets at most 14 min
            entry['mode'] = 'sync'
            if meta['module'] == 'brief':
                entry['timeout'] = min(entry['timeout'], 840)
        if sid == 'quicktest':
            entry.update(mode='sync', timeout=300)
        out[sid] = entry
    return out


# ------------------------------------------------------------------ file


def empty_routing():
    return {'version': 1, 'preset': None, 'fallback': {'provider': 'auto', 'model': ''}, 'scenarios': {},
            'effective': {}, 'updated': None}


def load_routing(path=None):
    """ :return: routing dict (empty routing when absent or broken) """
    try:
        with open(path or ROUTING_FILE) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return empty_routing()
    if not isinstance(data, dict):
        return empty_routing()
    out = empty_routing()
    out['preset'] = data.get('preset') if data.get('preset') in tuple(PRESETS) + ('custom',) else None
    try:
        out['fallback'] = validate_fallback(data.get('fallback') or {})
    except ValueError:
        pass
    for sid, entry in (data.get('scenarios') or {}).items():
        if sid in CATALOG and isinstance(entry, dict):
            try:
                out['scenarios'][sid] = validate_entry(entry)
            except ValueError:
                continue
    out['effective'] = data.get('effective') if isinstance(data.get('effective'), dict) else {}
    out['updated'] = data.get('updated')
    return out


def write_routing(routing, path=None, config=None):
    """ atomic write (0640); recomputes "effective" for the PHP API """
    path = path or ROUTING_FILE
    data = copy.deepcopy(routing)
    data['version'] = 1
    data['updated'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    data['effective'] = effective(data, config)
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=1, sort_keys=True)
    os.replace(tmp, path)
    return data


def raw_file(path=None):
    """ exact file content (for the undo journal) or None """
    try:
        with open(path or ROUTING_FILE) as handle:
            return handle.read()
    except OSError:
        return None


# ------------------------------------------------------------------ validation


def validate_entry(entry):
    out = {}
    for key, value in (entry or {}).items():
        if key not in FIELDS or value in (None, ''):
            continue
        if key == 'provider':
            if value not in PROVIDERS:
                raise ValueError('invalid provider "%s"' % value)
        elif key == 'mode':
            if value not in MODES:
                raise ValueError('invalid mode "%s"' % value)
        elif key == 'model':
            value = str(value)
            if not MODEL_RE.match(value):
                raise ValueError('invalid model name')
        elif key == 'keep_alive':
            value = str(value)
            if not KEEP_ALIVE_RE.match(value):
                raise ValueError('keep_alive must be like 30m, 2h, 0 or -1')
        elif key == 'think':
            value = str(value).strip().lower()
            value = THINK_ALIASES.get(value, value)
            if value not in THINK_VALUES:
                raise ValueError('think must be one of %s' % ', '.join(THINK_VALUES))
        else:
            low, high = INT_FIELDS[key]
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError('%s must be a number' % key)
            if not low <= value <= high:
                raise ValueError('%s must be between %d and %d' % (key, low, high))
        out[key] = value
    if out.get('provider') == 'default':
        out.pop('provider')
    return out


def validate_fallback(value):
    value = dict(value or {})
    provider = value.get('provider') or 'auto'
    if provider not in FALLBACK_PROVIDERS:
        raise ValueError('invalid fallback provider "%s"' % provider)
    model = str(value.get('model') or '')
    if model and not MODEL_RE.match(model):
        raise ValueError('invalid fallback model')
    return {'provider': provider, 'model': model}


def parse_spec(token):
    """ "provider=ollama+model=qwen2.5:3b+mode=queue+timeout=1800" -> dict (validated) """
    if not token:
        raise ValueError('empty specification')
    entry = {}
    for part in token.split('+'):
        if '=' not in part:
            raise ValueError('expected key=value, got "%s"' % part)
        key, value = part.split('=', 1)
        if key not in FIELDS:
            raise ValueError('unknown field "%s"' % key)
        entry[key] = value
    return validate_entry(entry)


def format_spec(entry):
    return '+'.join('%s=%s' % (k, entry[k]) for k in FIELDS if k in entry)


# ------------------------------------------------------------------ resolution


class Route:
    """ everything the Assistant needs for one scenario """

    def __init__(self, scenario, provider, options, timeout=None, mode='sync', budget=None, retries=0,
                 num_ctx=None, num_predict=None, keep_alive=None, source='global', kind='short', fallback=None,
                 role='primary', php_timeout=None, think=None, think_budget=None):
        self.scenario = scenario
        self.provider = provider
        self.options = dict(options or {})
        self.timeout = timeout
        self.mode = mode
        self.budget = budget
        self.retries = retries
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.keep_alive = keep_alive
        self.source = source
        self.kind = kind
        self.fallback = fallback
        self.role = role
        self.php_timeout = php_timeout
        self.think = think
        self.think_budget = think_budget

    @property
    def thinking(self):
        """ reasoning asked for this route (think on or a level) """
        return self.think in ('on', 'low', 'medium', 'high')

    @property
    def model(self):
        return self.options.get('model')

    @property
    def local(self):
        """ Ollama on this firewall (127.0.0.1) """
        return self.provider == 'ollama' and _location(self.options) == 'local'

    @property
    def ollama(self):
        return self.provider == 'ollama'

    def provider_options(self):
        """ provider options with the per route Ollama limits """
        opts = dict(self.options)
        if self.provider == 'ollama':
            for key in ('num_ctx', 'num_predict', 'keep_alive'):
                value = getattr(self, key)
                if value not in (None, ''):
                    opts[key] = value
            if self.thinking:
                opts['think'] = True if self.think == 'on' else self.think
                if self.think_budget:
                    opts['think_budget'] = int(self.think_budget)
        return opts

    def label(self):
        if self.local:
            return 'local AI'
        return {'ollama': 'Ollama (LAN)', 'claudecode': 'Claude Code (LAN)', 'claude': 'Claude'}.get(
            self.provider, self.provider)

    def as_dict(self):
        out = {'scenario': self.scenario, 'provider': self.provider, 'model': self.model, 'mode': self.mode,
               'timeout': self.timeout, 'budget': self.budget, 'retries': self.retries, 'num_ctx': self.num_ctx,
               'num_predict': self.num_predict, 'keep_alive': self.keep_alive, 'source': self.source,
               'kind': self.kind, 'local': self.local, 'role': self.role, 'label': self.label(),
               'think': self.think or 'off', 'think_budget': self.think_budget}
        if self.fallback is not None:
            out['fallback'] = self.fallback.as_dict()
        return out


def _location(options):
    location = options.get('location') or ('lan' if options.get('mode') == 'network' else 'local')
    return 'lan' if location in ('lan', 'network') else 'local'


def provider_options(config, name):
    """ options of any provider from the same config.xml read (not only the global one) """
    raw = getattr(config, 'raw', None)
    if name == config.provider or not isinstance(raw, dict):
        options = dict(config.options) if name == config.provider else {}
    else:
        options = dict(raw.get(name) or {})
    if name == 'ollama':
        if 'mode' in options and 'location' not in options:
            options['location'] = 'lan' if options['mode'] == 'network' else 'local'
        if options.get('location', 'local') == 'local':
            options['url'] = 'http://127.0.0.1:11434'
    return options


def runtime_installed(path=None):
    """ the AI setup wrote the runtime limits: the local Ollama exists (fallback "auto") """
    return os.path.isfile(path or LIMITS_FILE)


def default_local_model(config, kind='short'):
    """ fallback "auto" model: the configured Ollama model, else the preset model of the kind """
    opts = provider_options(config, 'ollama')
    if opts.get('model') and _location(opts) == 'local':
        return opts['model']
    return LOCAL_SHORT if kind == 'short' else LOCAL_LONG


def resolve(scenario, config, routing=None, path=None, limits_path=None):
    """
    :param scenario: catalog id (unknown ids follow the global provider, synchronously)
    :param config: AIConfig
    :param routing: routing dict override (tests), default: the file
    :return: Route with .fallback (Route or None)
    """
    routing = routing if routing is not None else load_routing(path)
    meta = CATALOG.get(scenario) or {'kind': 'short'}
    entry = (routing.get('scenarios') or {}).get(scenario) or {}
    provider = entry.get('provider') or config.provider
    options = provider_options(config, provider)
    if entry.get('model'):
        options['model'] = entry['model']
    timeout = entry.get('timeout')
    if timeout is None and provider == config.provider:
        timeout = config.timeout
    mode = entry.get('mode') or 'sync'
    probe = Route(scenario, provider, options)
    if mode == 'auto':
        mode = 'queue' if probe.local and meta['kind'] == 'long' else 'sync'
    if meta.get('background'):
        mode = 'sync'
    route = Route(scenario, provider, options, timeout=timeout, mode=mode, budget=entry.get('budget'),
                  retries=entry.get('retries', 1 if (entry and probe.ollama) else 0), num_ctx=entry.get('num_ctx'),
                  num_predict=entry.get('num_predict'), keep_alive=entry.get('keep_alive'),
                  source='scenario' if entry else 'global', kind=meta['kind'], think=entry.get('think'),
                  think_budget=entry.get('think_budget'))
    route.fallback = _fallback(route, meta, config, routing, limits_path)
    eff = (routing.get('effective') or {}).get(scenario) or {}
    route.php_timeout = eff.get('php_timeout')
    return route


def _fallback(route, meta, config, routing, limits_path=None):
    spec = routing.get('fallback') or {'provider': 'auto', 'model': ''}
    provider = spec.get('provider') or 'auto'
    if provider == 'none':
        return None
    if provider == 'auto':
        if not runtime_installed(limits_path):
            return None
        provider = 'ollama'
        options = provider_options(config, 'ollama')
        options['location'] = 'local'
        options['url'] = 'http://127.0.0.1:11434'
        options['model'] = spec.get('model') or default_local_model(config, meta['kind'])
    else:
        options = provider_options(config, provider)
        if spec.get('model'):
            options['model'] = spec['model']
    if provider == route.provider and options.get('model') == route.model and \
            options.get('url') == route.options.get('url'):
        return None
    fb = Route(route.scenario, provider, options, role='fallback', kind=meta['kind'], source='fallback')
    if fb.local:
        base = LOCAL_SHORT_ROUTE if meta['kind'] == 'short' else LOCAL_LONG_ROUTE
        fb.timeout = base['timeout']
        fb.num_ctx = base['num_ctx']
        fb.num_predict = base['num_predict']
        fb.keep_alive = base['keep_alive']
        fb.budget = base['budget']
        fb.retries = 1
        fb.mode = 'queue' if meta['kind'] == 'long' and not meta.get('background') else 'sync'
    else:
        fb.timeout = BRIDGE_ROUTE['timeout'] if provider == 'claudecode' else None
        fb.retries = 0
        fb.mode = 'sync'
    return fb


def effective(routing, config=None):
    """ per scenario summary for the PHP API: the seconds a synchronous request may take """
    if config is None:
        try:
            from .config import AIConfig
            config = AIConfig.from_opnsense('OPNsense/policyanalyzer', path=CONFIG_XML)
        except Exception:                       # noqa: BLE001
            config = None
    out = {}
    for sid in CATALOG:
        if config is None:
            break
        route = resolve(sid, config, routing=routing)
        primary = route.timeout or _default_timeout(route)
        total = primary * (1 + min(route.retries, 1))
        if route.fallback is not None and route.fallback.mode == 'sync':
            total += (route.fallback.timeout or _default_timeout(route.fallback))
        out[sid] = {'provider': route.provider, 'model': route.model, 'mode': route.mode,
                    'php_timeout': int(min(total, 2 * MAX_TIMEOUT) + 45)}
    return out


def _default_timeout(route):
    if route.local:
        return 360
    return {'claude': 180, 'claudecode': 300}.get(route.provider, 120)


def _queue_cron():
    try:
        from .routing_actions import cron_jobs
        return cron_jobs()
    except Exception:                           # noqa: BLE001
        return []


def describe(config, routing=None):
    """ configd "ai_routing": catalog, presets, the file and every resolved route """
    routing = routing if routing is not None else load_routing()
    items = []
    for sid, meta in CATALOG.items():
        route = resolve(sid, config, routing=routing)
        items.append({'id': sid, 'label': meta['label'], 'module': meta['module'], 'kind': meta['kind'],
                      'background': bool(meta.get('background')), 'structured': bool(meta.get('structured')),
                      'mapreduce': bool(meta.get('mapreduce')), 'eta': meta['eta'],
                      'entry': (routing.get('scenarios') or {}).get(sid) or {}, 'route': route.as_dict()})
    return {'status': 'ok', 'preset': routing.get('preset'), 'fallback': routing.get('fallback'),
            'updated': routing.get('updated'), 'scenarios': items,
            'presets': [{'id': k, 'label': v['label'], 'help': v['help']} for k, v in PRESETS.items()],
            'global': {'provider': config.provider, 'model': config.options.get('model'), 'enabled': config.enabled},
            'runtime_installed': runtime_installed(),
            'queue_cron': _queue_cron(),
            'fields': {'providers': list(PROVIDERS), 'modes': list(MODES), 'fallback': list(FALLBACK_PROVIDERS),
                       'think': list(THINK_VALUES),
                       'limits': {k: list(v) for k, v in INT_FIELDS.items()}}}
