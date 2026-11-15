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

    Read only side of the quarantine assistant (WIZARD.md, "Quarantine wizard"): the state of every step,
    detected again on every call (never cached in the browser), and the preview of the scenarios.

      state(ctx)                    {check, ledger, aliases, rule, scenarios, schedule, activate, done}
      preview(ctx, settings, ...)   what a run would do with the recent logs, nothing is written
      parse_scenarios(token)        "reset_days=90:scan_ports=10:bait_ports=23+3389" -> {key: value}

    "manage.py quarantine wizard" and "manage.py quarantine preview <token|->" (cli.py) print them.
"""

import collections
import ipaddress
import os
import time

from . import common, engine as engine_mod, fwconfig, sources, store as store_mod

TAIL_BYTES = 6 * 1024 * 1024        # recent filter log read for the estimates (~1 MB per hour on the firewall)
EVE_TAIL_BYTES = 4 * 1024 * 1024
PREVIEW_DEADLINE = 5.0              # seconds of reading per preview
FIRST_RUN_BYTES = 16 * 1024 * 1024  # preview of the first run (Activate): at most this much since the marker
SHORT_LIST = 12
SCENARIO_KEYS = ('reset_days', 'scan_ports', 'scan_window', 'bait_ports', 'suricata', 'suricata_severity',
                 'max_active', 'syn_only', 'budget')
FIXED = {'base_min_blocks': 1, 'ladder': [common.LEVEL_LABELS[i] for i in range(1, 6)]}


def parse_scenarios(token):
    """ "key=value:key=value" (bait ports joined by "+") or "defaults" -> {key: value|None}; None = default """
    token = (token or '').strip()
    if token in ('defaults', 'default'):
        return {key: None for key in SCENARIO_KEYS}
    if not token or token == '-':
        raise ValueError('no settings given')
    result = {}
    for part in token.split(':'):
        key, sep, value = part.partition('=')
        if not sep or key not in SCENARIO_KEYS:
            raise ValueError('unknown setting: %s' % key)
        if key in result:
            raise ValueError('setting given twice: %s' % key)
        result[key] = common.validate_setting(key, value)
    return result


def scenarios_token(values):
    return ':'.join('%s=%s' % (k, values[k]) for k in SCENARIO_KEYS if k in values and values[k] is not None)


def _tail(ctx, path, max_bytes, prefilter, deadline):
    lines, _marker, info = sources.read_new(path, lambda: [], None, max_bytes=max_bytes, first_tail=max_bytes,
                                            prefilter=prefilter, deadline=deadline)
    return lines, info


def recent(ctx, now, filter_bytes=TAIL_BYTES, eve_bytes=EVE_TAIL_BYTES, suricata=True):
    """ the end of the filter log and of eve.json: (records, alerts, info) """
    deadline = time.monotonic() + PREVIEW_DEADLINE
    lines, finfo = _tail(ctx, ctx.filter_log, filter_bytes, b'filterlog', deadline)
    records = [r for r in (sources.parse_filter_line(line, now) for line in lines) if r is not None]
    alerts, einfo = [], {'missing': not os.path.exists(ctx.eve), 'skipped': not suricata}
    if suricata and not einfo['missing']:
        elines, einfo = _tail(ctx, ctx.eve, eve_bytes, b'"event_type":"alert"', deadline)
        alerts = [a for a in (sources.parse_eve_line(line) for line in elines) if a is not None]
    oldest = min([r['ts'] for r in records] or [now])
    return records, alerts, {'filter_missing': finfo.get('missing', False), 'filter_bytes': finfo.get('bytes', 0),
                             'covers_seconds': int(max(0, now - oldest)) if records else 0,
                             'eve_missing': einfo.get('missing', False)}


def evaluate(cfg, settings, records, alerts, guards, now, window, entries=None):
    """
    what the scenarios would decide for the events of the last `window` seconds (no history, no ledger write)
    :param entries: {addr: entry} of the ledger (optional): addresses already in quarantine are only "hits"
    :return: {"candidates": [{addr, reason, reasons, level, events, ports, iface, already}], "by_reason",
              "guarded", "per_wan": {key: {blocks, sources}}, "sources"}
    """
    wan = cfg.wan_interfaces()
    dev_key = {w['dev']: w['key'] for w in wan}
    since = now - window
    blocks = collections.defaultdict(list)
    per_wan = {w['key']: {'blocks': 0, 'sources': set(), 'descr': w['descr'], 'dev': w['dev']} for w in wan}
    for rec in records:
        if rec['ts'] < since or rec['dir'] != 'in' or rec['iface'] not in dev_key or rec['action'] != 'block':
            continue
        ip = common.addr(rec['src'])
        if not common.is_external(ip):
            continue
        if not engine_mod.counts_as_connection(rec, settings['syn_only']):
            continue
        blocks[str(ip)].append(rec)
        slot = per_wan[dev_key[rec['iface']]]
        slot['blocks'] += 1
        slot['sources'].add(str(ip))
    by_alert = collections.defaultdict(list)
    if settings['suricata']:
        for alert in alerts:
            ip = common.addr(alert['src'])
            if alert['ts'] >= since and alert['severity'] <= settings['suricata_severity'] and common.is_external(ip):
                by_alert[str(ip)].append(alert)
    candidates, guarded = [], collections.Counter()
    by_reason = collections.Counter()
    for text in sorted(set(blocks) | set(by_alert), key=lambda a: (ipaddress.ip_address(a).version,
                                                                   ipaddress.ip_address(a))):
        why = guards.check(ipaddress.ip_address(text)) if guards is not None else None
        if why is not None:
            guarded[why] += 1
            continue
        found = engine_mod.detect(blocks.get(text, []), by_alert.get(text, []), settings)
        if found is None:
            continue
        entry = (entries or {}).get(text)
        level = engine_mod.next_level(entry, found['ts'], settings, found['min_level'])
        already = bool(entry and entry['state'] in ('active', 'permanent'))
        if not already:
            by_reason[found['primary']] += 1
        candidates.append({'addr': text, 'reason': found['primary'], 'reasons': found['reasons'], 'level': level,
                           'level_label': common.LEVEL_LABELS.get(level), 'events': found['events'],
                           'ports': found['ports'], 'iface': dev_key.get(found['iface'], found['iface']),
                           'already': already})
    candidates.sort(key=lambda c: (c['already'], -c['level'], -c['events'], c['addr']))
    fresh = [c for c in candidates if not c['already']]
    return {'candidates': candidates, 'entering': len(fresh), 'by_reason': dict(by_reason),
            'guarded': dict(guarded), 'sources': len(candidates),
            'per_wan': {k: {'blocks': v['blocks'], 'sources': len(v['sources']), 'descr': v['descr'],
                            'dev': v['dev']} for k, v in per_wan.items()}}


def _open_store(ctx):
    return store_mod.Store(ctx.db) if os.path.exists(ctx.db) else None


def _entries_by_addr(st, addrs):
    if st is None or not addrs:
        return {}
    result = {}
    for addr in addrs:
        entry = st.entry_by_addr(addr)
        if entry is not None:
            result[addr] = entry
    return result


def preview(ctx, settings=None, window=300, engine_options=None):
    """ :param settings: {key: value|None} overriding the stored/effective ones; :return: dict (short list) """
    now = ctx.clock()
    eng = engine_mod.Engine(ctx, **(engine_options or {}))
    cfg = eng.config()
    st = _open_store(ctx)
    try:
        stored = st.stored_settings() if st is not None else {}
        merged = dict(stored)
        for key, value in (settings or {}).items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        effective = common.effective_settings(merged)
        records, alerts, info = recent(ctx, now, suricata=bool(effective['suricata']))
        g = eng.guards(cfg, st, now)
        addrs = {str(common.addr(r['src'])) for r in records
                 if common.addr(r['src']) is not None and r['ts'] >= now - window}
        res = evaluate(cfg, effective, records, alerts, g, now, window, _entries_by_addr(st, sorted(addrs)[:5000]))
    finally:
        if st is not None:
            st.close()
    res['candidates'] = res['candidates'][:SHORT_LIST]
    effective.pop('bait_ports_list', None)
    res.update({'status': 'ok', 'window': window, 'settings': effective, 'log': info,
                'complete': info['covers_seconds'] >= window})
    return res


def first_run_preview(ctx, engine_options=None):
    """ Activate: what the first run would read (from the markers of the ledger) and decide, nothing written """
    now = ctx.clock()
    if not os.path.exists(ctx.db):
        return {'status': 'error', 'message': 'no ledger'}
    eng = engine_mod.Engine(ctx, **(engine_options or {}))
    cfg = eng.config()
    st = store_mod.Store(ctx.db)
    try:
        settings = st.settings()
        marker = st.meta_json('marker_filter')
        lines, _m, finfo = sources.read_new(ctx.filter_log, sources.filter_candidates(ctx.filter_log), marker,
                                            max_bytes=FIRST_RUN_BYTES, prefilter=b'filterlog',
                                            deadline=time.monotonic() + PREVIEW_DEADLINE)
        records = [r for r in (sources.parse_filter_line(line, now) for line in lines) if r is not None]
        alerts = []
        if settings['suricata']:
            elines, _m, _e = sources.read_new(ctx.eve, sources.eve_candidates(ctx.eve), st.meta_json('marker_eve'),
                                              max_bytes=FIRST_RUN_BYTES, prefilter=b'"event_type":"alert"',
                                              deadline=time.monotonic() + PREVIEW_DEADLINE)
            alerts = [a for a in (sources.parse_eve_line(line) for line in elines) if a is not None]
        g = eng.guards(cfg, st, now)
        addrs = sorted({str(common.addr(r['src'])) for r in records if common.addr(r['src']) is not None})[:5000]
        res = evaluate(cfg, settings, records, alerts, g, now, common.MAX_BACKLOG, _entries_by_addr(st, addrs))
        installed = st.meta_json('installed')
    finally:
        st.close()
    res['candidates'] = res['candidates'][:SHORT_LIST]
    res.update({'status': 'ok', 'records': len(records), 'since': common.iso(installed) if installed else None,
                'complete': finfo.get('complete', True), 'bytes': finfo.get('bytes', 0)})
    return res


def suricata_running(ctx):
    rc, _out, _err = ctx.runner.run([ctx.pgrep, '-x', 'suricata'], timeout=5)
    return rc == 0


def detached_ledgers(ctx):
    result = []
    try:
        names = sorted(os.listdir(ctx.state_dir))
    except OSError:
        return result
    for name in names:
        if name.startswith(common.DETACHED_PREFIX) and name.endswith('.db'):
            path = os.path.join(ctx.state_dir, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            result.append({'name': name, 'path': path, 'bytes': st.st_size, 'mtime': common.iso(st.st_mtime)})
    return result


def ledger_usage(st, now):
    counts = st.counts(now)
    entries = sum(counts['by_state'].values())
    return {'entries': entries, 'offenses': counts['offenses_total'], 'history_since': common.iso(counts['history_since']),
            'active': counts['active'], 'used': bool(entries or counts['offenses_total'])}


def wireguard_unlogged(cfg):
    """ enabled WAN pass rules to a WireGuard listen port without logging (the 24 h guard can not see them) """
    wg_ports = set(cfg.wireguard()['ports'])
    wan_keys = {w['key'] for w in cfg.wan_interfaces()}
    result = []
    for r in cfg.rules():
        if r['action'] == 'pass' and r['enabled'] and not r['log'] and r['direction'] in ('in', 'any') and \
                set(r['interfaces']) & wan_keys and r['destination_port'].isdigit() and \
                int(r['destination_port']) in wg_ports:
            result.append(r)
    return result


def wireguard_warning(rule):
    return {'warning': 'The WireGuard rule "%s" does not log: the 24 h guard of allowed WireGuard clients only sees '
                       'the current endpoints.' % (rule['description'] or rule['uuid']),
            'action': {'id': 'qsetup_rule_log', 'label': 'Enable logging of this rule', 'args': [rule['uuid'], 'on']}}


def _rule_brief(rule):
    return {'uuid': rule['uuid'], 'description': rule['description'], 'sequence': rule['sequence'],
            'action': rule['action'], 'interfaces': rule['interfaces'], 'floating': rule['floating']}


def state(ctx, engine_options=None):
    now = ctx.clock()
    eng = engine_mod.Engine(ctx, **(engine_options or {}))
    try:
        cfg = eng.config()
    except common.QuarantineError as exc:
        return {'status': 'error', 'message': str(exc)}
    wan = cfg.wan_interfaces()
    keys = [w['key'] for w in wan]
    aliases = cfg.aliases()
    rules = cfg.quarantine_rules()
    crons = cfg.quarantine_cron()
    rule = rules[0] if rules else None
    st = _open_store(ctx)
    try:
        stored = st.stored_settings() if st is not None else {}
        settings = common.effective_settings(stored)
        g = eng.guards(cfg, st, now)
        desc = g.describe()
        records, alerts, loginfo = recent(ctx, now, suricata=bool(settings['suricata']))
        win5 = evaluate(cfg, settings, records, alerts, g, now, 300)
        win60 = evaluate(cfg, settings, records, alerts, g, now, 3600)
        ledger = {'exists': st is not None, 'path': ctx.db, 'detached': detached_ledgers(ctx),
                  'lookup_db': os.path.exists(ctx.lookup_db)}
        activate = {'paused': None, 'last_run': None, 'installed': None}
        pf_entries = 0
        if st is not None:
            ledger.update(ledger_usage(st, now))
            ledger.update({'bytes': st.size(), 'schema': st.meta('schema'), 'installed': common.iso(
                st.meta_json('installed'))})
            activate = {'paused': st.meta('paused') == '1', 'last_run': st.meta_json('last_run'),
                        'installed': ledger['installed']}
            pf_entries = engine_mod.pf_count(st)
    finally:
        if st is not None:
            st.close()
    warnings = []
    if not wan:
        warnings.append({'warning': 'No WAN interface was found in the configuration: the rule has nowhere to go.',
                         'link': {'label': 'Interfaces: Assignments', 'url': '/ui/interfaces/assign'}})
    if loginfo['filter_missing']:
        warnings.append({'warning': 'The filter log %s does not exist: nothing can be detected.' % ctx.filter_log,
                         'link': {'label': 'Firewall: Log Files', 'url': '/ui/diagnostics/firewall/log'}})
    running = suricata_running(ctx)
    eve = os.path.exists(ctx.eve)
    if settings['suricata'] and not running:
        warnings.append({'warning': 'Suricata is not running: the Suricata scenario stays idle (the others work).',
                         'link': {'label': 'Services: Intrusion Detection', 'url': '/ui/ids'}})
    elif settings['suricata'] and not eve:
        warnings.append({'warning': 'Suricata runs but %s does not exist (EVE log off?).' % ctx.eve,
                         'link': {'label': 'Services: Intrusion Detection', 'url': '/ui/ids'}})
    for r in wireguard_unlogged(cfg):
        warnings.append(wireguard_warning(r))
    estimate = win60['entering']
    if estimate > settings['max_active'] * 0.8:
        warnings.append({'warning': 'About %d addresses would enter per hour, close to the limit of %d active '
                                    'entries.' % (estimate, settings['max_active']),
                         'step': 'scenarios'})
    pos = fwconfig.rule_position(cfg, keys) if keys else None
    settings.pop('bait_ports_list', None)
    result = {
        'status': 'ok', 'now': common.iso(now),
        'check': {
            'wan': [dict(w, blocks_5m=win5['per_wan'][w['key']]['blocks'], sources_5m=win5['per_wan'][w['key']]['sources'],
                         blocks_1h=win60['per_wan'][w['key']]['blocks'], sources_1h=win60['per_wan'][w['key']]['sources'])
                    for w in wan],
            'entering_5m': win5['entering'], 'entering_1h': win60['entering'],
            'by_reason_5m': win5['by_reason'], 'by_reason_1h': win60['by_reason'],
            'guarded_1h': win60['guarded'], 'log': loginfo,
            'filter_log': {'path': ctx.filter_log, 'exists': not loginfo['filter_missing']},
            'suricata': {'running': running, 'eve': eve, 'path': ctx.eve, 'enabled': bool(settings['suricata'])},
            'limit': {'max_active': settings['max_active'], 'pf_entries': pf_entries},
            'guards': {'counts': desc['counts'], 'total': sum(desc['counts'].values()), 'implicit': desc['implicit'],
                       'sample': {k: [i['addr'] for i in v[:6]] for k, v in desc['labels'].items() if v},
                       'notes': desc['notes']},
            'warning_actions': warnings,
        },
        'ledger': ledger,
        'aliases': {
            'quarantine': {'present': common.ALIAS in aliases, 'uuid': aliases.get(common.ALIAS, {}).get('uuid'),
                           'type': aliases.get(common.ALIAS, {}).get('type')},
            'never_block': {'present': common.NEVER_ALIAS in aliases,
                            'uuid': aliases.get(common.NEVER_ALIAS, {}).get('uuid'),
                            'content': aliases.get(common.NEVER_ALIAS, {}).get('content', [])}},
        'rule': {'present': bool(rule), 'enabled': bool(rule and rule['enabled']), 'uuid': rule['uuid'] if rule else None,
                 'sequence': rule['sequence'] if rule else None, 'interfaces': rule['interfaces'] if rule else keys,
                 'count': len(rules), 'description': common.RULE_DESCR,
                 'position': {'sequence': pos['sequence'], 'floating': pos['floating'],
                              'group_size': pos['group_size'], 'warnings': pos['warnings'],
                              'before': [_rule_brief(r) for r in pos['before']],
                              'wan_pass_rules': [_rule_brief(r) for r in pos['wan_pass_rules'][:8]],
                              'wan_pass_total': len(pos['wan_pass_rules'])} if pos else None},
        'scenarios': {'settings': settings, 'stored': stored, 'defaults': dict(common.DEFAULTS), 'fixed': FIXED,
                      'rules': {k: list(v) for k, v in common.SETTING_RULES.items()}},
        'schedule': {'cron': {'present': bool(crons), 'enabled': bool(crons and crons[0]['enabled']),
                              'minutes': crons[0]['minutes'] if crons else None,
                              'uuid': crons[0]['uuid'] if crons else None},
                     'syshook': os.path.exists(ctx.syshook), 'syshook_path': ctx.syshook,
                     'next_run': common.iso(engine_mod.next_run(now)) if crons and crons[0]['enabled'] else None},
        'activate': activate,
    }
    result['done'] = {
        'check': True,
        'ledger': ledger['exists'],
        'aliases': result['aliases']['quarantine']['present'] and result['aliases']['never_block']['present'],
        'rule': bool(rule),
        'scenarios': ledger['exists'],          # the defaults are a valid choice; custom values are optional
        'schedule': bool(crons) and result['schedule']['syshook'],
        'activate': bool(rule and rule['enabled']) and ledger['exists'] and not activate['paused'] and
        bool(activate['last_run']),
    }
    result['installed'] = all(result['done'][k] for k in ('ledger', 'aliases', 'rule', 'schedule'))
    return result
