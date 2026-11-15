"""
Fictitious local bases for the chart tests and the sample PDFs (never real data): documentation addresses
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), private ASN 64496-64511, example.test names, CVE-2099-* ids.

    build_all(directory, now, span)   writes quarantine.db, incidents.db, anomalies.db, devices.db, posture.db,
                                      ai-queue.db, shadowai.db, ai.log (+ ai.log.1) and collect/flows.db
                                      with a deterministic pseudo random series over [now - span, now)
"""

import json
import math
import os
import random
import sqlite3
import time

QUARANTINE = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE entries (id INTEGER PRIMARY KEY, addr TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, asn INTEGER,
    country TEXT, level INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'expired',
    origin TEXT NOT NULL DEFAULT 'auto', reason INTEGER, first_seen INTEGER NOT NULL, last_offense INTEGER,
    since INTEGER, until INTEGER, offenses INTEGER NOT NULL DEFAULT 0, hits INTEGER NOT NULL DEFAULT 0, iface TEXT,
    comment TEXT, resolved_at INTEGER);
CREATE TABLE offenses (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, entry_id INTEGER NOT NULL, reason INTEGER NOT NULL,
    reasons INTEGER NOT NULL, level INTEGER NOT NULL, until INTEGER, origin TEXT NOT NULL, events INTEGER, ports TEXT,
    detail TEXT, iface TEXT, country TEXT, limited INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, entry_id INTEGER, kind TEXT NOT NULL, level INTEGER,
    until INTEGER, origin TEXT, note TEXT);
"""
INCIDENTS = """
CREATE TABLE port_hourly (hour INTEGER NOT NULL, port TEXT NOT NULL, events INTEGER NOT NULL, blocked INTEGER NOT NULL,
    passed INTEGER NOT NULL, sources INTEGER NOT NULL, PRIMARY KEY (port, hour)) WITHOUT ROWID;
CREATE TABLE cases (id INTEGER PRIMARY KEY, title TEXT NOT NULL, rule TEXT NOT NULL, primary_kind TEXT NOT NULL,
    primary_value TEXT NOT NULL, severity TEXT NOT NULL, score INTEGER NOT NULL, factors TEXT,
    state TEXT NOT NULL DEFAULT 'new', created INTEGER NOT NULL, first_seen INTEGER NOT NULL,
    last_activity INTEGER NOT NULL, updated INTEGER NOT NULL, matches INTEGER NOT NULL DEFAULT 0,
    suppressed INTEGER NOT NULL DEFAULT 0, previous_id INTEGER, summary_ts INTEGER);
CREATE TABLE case_log (id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, ts INTEGER NOT NULL, kind TEXT NOT NULL,
    from_state TEXT, to_state TEXT, note TEXT, journal_id TEXT);
"""
ANOMALIES = """
CREATE TABLE findings (id TEXT PRIMARY KEY, type TEXT NOT NULL, host TEXT NOT NULL, key TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL, score INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', title TEXT, detail TEXT,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1);
CREATE TABLE occurrences (id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL, ts INTEGER NOT NULL,
    last_ts INTEGER NOT NULL, severity TEXT NOT NULL, score INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open',
    factors TEXT);
CREATE TABLE host_hour (host TEXT NOT NULL, hour INTEGER NOT NULL, bytes_out INTEGER NOT NULL DEFAULT 0,
    bytes_in INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0, dsts INTEGER NOT NULL DEFAULT 0, top TEXT,
    evaluated INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (host, hour)) WITHOUT ROWID;
"""
DEVICES = """
CREATE TABLE devices (id INTEGER PRIMARY KEY, mac TEXT NOT NULL UNIQUE, first_seen INTEGER, last_seen INTEGER,
    hostname TEXT, vendor TEXT, auto_type TEXT, user_type TEXT, user_name TEXT, known INTEGER NOT NULL DEFAULT 0,
    risk TEXT, present INTEGER NOT NULL DEFAULT 0);
"""
POSTURE = """
CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, score REAL, grade TEXT, pass INTEGER,
    warn INTEGER, fail INTEGER, na INTEGER, version TEXT);
"""
AI_QUEUE = """
CREATE TABLE jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, scenario TEXT NOT NULL, subject TEXT,
    status TEXT NOT NULL, created INTEGER NOT NULL, started INTEGER, finished INTEGER, provider TEXT, model TEXT,
    label TEXT, route TEXT, argv TEXT NOT NULL, language TEXT, timeout INTEGER, eta INTEGER, pid INTEGER,
    runs INTEGER NOT NULL DEFAULT 0, calls INTEGER NOT NULL DEFAULT 0, cached_calls INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER, completion_tokens INTEGER, model_seconds REAL, attempts INTEGER, format_ok INTEGER,
    lang_ok INTEGER, fallback INTEGER NOT NULL DEFAULT 0, provider_used TEXT, model_used TEXT, result TEXT, error TEXT);
"""
SHADOWAI = """
CREATE TABLE daily (host TEXT, service TEXT, day TEXT, dns INTEGER, tls INTEGER, blocked INTEGER,
    PRIMARY KEY (host, service, day));
"""
COLLECT = "CREATE TABLE report_series (ts INTEGER NOT NULL, series TEXT NOT NULL, value REAL NOT NULL);"

SEVERITIES = ('critical', 'high', 'medium', 'low')
SCENARIOS = (('report_summary', 'ollama', 'qwen3:30b-a3b', 95.0), ('notification_summary', 'ollama', 'qwen2.5:3b', 9.0),
             ('explain_cve', 'ollama', 'qwen2.5:3b', 14.0), ('incident_summary', 'claudecode', 'fable', 11.0),
             ('console_ask', 'claudecode', 'fable', 7.0), ('posture_summary', 'ollama', 'qwen3:30b-a3b', 140.0))


def _db(path, schema):
    if os.path.exists(path):
        os.unlink(path)
    db = sqlite3.connect(path)
    db.executescript(schema)
    return db


def _diurnal(ts):
    """ more scans at night (local), a smooth wave between 0.4 and 1.6 """
    hour = time.localtime(ts).tm_hour
    return 1.0 + 0.6 * math.cos((hour - 3) / 24.0 * 2 * math.pi)


def build_all(directory, now, span=86400, seed=7):
    rnd = random.Random(seed)
    os.makedirs(directory, exist_ok=True)
    since = now - span
    prev = since - span
    hours = list(range(prev // 3600 * 3600, now, 3600))

    # quarantine: entries, enter / upgrade / expire events, offenses with ASN
    db = _db(os.path.join(directory, 'quarantine.db'), QUARANTINE)
    asns = [(64496 + i, c) for i, c in enumerate(['NL', 'CN', 'RU', 'US', 'BR', 'DE', 'VN', 'IN'])]
    entry_id = 0
    event_rows, offense_rows, entries = [], [], []
    for hour in hours:
        for _ in range(int(rnd.randint(0, 4) * _diurnal(hour))):
            ts = hour + rnd.randint(0, 3599)
            if ts >= now:
                continue
            repeat = entries and rnd.random() < 0.3
            if repeat:
                eid, asn, cc = rnd.choice(entries)
            else:
                entry_id += 1
                asn, cc = asns[min(int(rnd.expovariate(0.45)), len(asns) - 1)]
                eid = entry_id
                entries.append((eid, asn, cc))
            level = min(6, 1 + (2 if repeat else 0) + rnd.choice([0, 0, 0, 1, 2]))
            event_rows.append((ts, eid, 'enter', level, 'auto'))
            offense_rows.append((ts, eid, rnd.choice([1, 2, 2, 3]), 2, level, 'auto', cc))
            if rnd.random() < 0.15:
                event_rows.append((ts + 60, eid, 'upgrade', min(6, level + 1), 'auto'))
            if rnd.random() < 0.6 and ts + 1800 < now:
                event_rows.append((ts + rnd.choice([1800, 7200, 172800]), eid, 'expire', level, 'auto'))
    db.executemany("INSERT INTO entries (id, addr, kind, asn, country, level, state, first_seen, offenses) VALUES "
                   "(?, ?, 'ip', ?, ?, 1, 'active', ?, 1)",
                   [(eid, '203.0.113.%d' % (eid % 250 + 1) if eid < 250 else '198.51.100.%d' % (eid % 250 + 1),
                     asn, cc, since) for eid, asn, cc in entries])
    db.executemany('INSERT INTO events (ts, entry_id, kind, level, origin) VALUES (?, ?, ?, ?, ?)',
                   sorted(e for e in event_rows if e[0] < now))
    db.executemany('INSERT INTO offenses (ts, entry_id, reason, reasons, level, origin, country) VALUES '
                   '(?, ?, ?, ?, ?, ?, ?)', offense_rows)
    db.commit()
    db.close()

    # incidents: hourly totals of the filter ('*') and cases
    db = _db(os.path.join(directory, 'incidents.db'), INCIDENTS)
    db.executemany("INSERT INTO port_hourly (hour, port, events, blocked, passed, sources) VALUES (?, '*', ?, ?, ?, ?)",
                   [(h, 0, int(rnd.randint(300, 700) * _diurnal(h)), rnd.randint(2000, 4000), rnd.randint(40, 90))
                    for h in hours])
    cid = 0
    for hour in hours:
        for _ in range(rnd.choice([0, 0, 0, 1, 1, 2])):
            cid += 1
            ts = hour + rnd.randint(0, 3599)
            sev = ('low', 'medium', 'high', 'critical')[min(3, int(rnd.expovariate(1.1)))]
            closed = rnd.random() < 0.55
            db.execute("INSERT INTO cases (id, title, rule, primary_kind, primary_value, severity, score, state, "
                       "created, first_seen, last_activity, updated) VALUES (?, ?, 'scan', 'ip', ?, ?, 40, ?, ?, ?, ?, ?)",
                       (cid, 'Port scan (fictitious)', '203.0.113.%d' % (cid % 200 + 1), sev,
                        'resolved' if closed else 'new', ts, ts, ts, ts + 900))
            db.execute("INSERT INTO case_log (case_id, ts, kind, to_state) VALUES (?, ?, 'created', 'new')", (cid, ts))
            if closed and ts + 1800 < now:
                db.execute("INSERT INTO case_log (case_id, ts, kind, from_state, to_state) VALUES "
                           "(?, ?, 'state', 'new', 'resolved')", (cid, ts + 1800))
    db.commit()
    db.close()

    # anomalies: outbound volume per host and hour, a few spikes with occurrences
    db = _db(os.path.join(directory, 'anomalies.db'), ANOMALIES)
    spikes = set(rnd.sample(range(len(hours)), 3))
    for i, hour in enumerate(hours):
        for host in ('192.0.2.10', '192.0.2.11', '192.0.2.12'):
            base = rnd.randint(40, 120) * 1024 * 1024 * (0.4 + 0.6 * (1.0 if 8 <= time.localtime(hour).tm_hour <= 23 else 0.3))
            if i in spikes and host == '192.0.2.11':
                base *= 9
            db.execute('INSERT INTO host_hour (host, hour, bytes_out) VALUES (?, ?, ?)', (host, hour, int(base)))
        if i in spikes:
            db.execute("INSERT INTO occurrences (finding_id, ts, last_ts, severity, score) VALUES ('vol-1', ?, ?, ?, 70)",
                       (hour + 1200, hour + 1800, rnd.choice(['high', 'medium'])))
        elif rnd.random() < 0.08:
            db.execute("INSERT INTO occurrences (finding_id, ts, last_ts, severity, score) VALUES ('dns-1', ?, ?, 'low', 20)",
                       (hour + 600, hour + 700))
    db.commit()
    db.close()

    # devices
    db = _db(os.path.join(directory, 'devices.db'), DEVICES)
    types = ['phone'] * 12 + ['pc'] * 4 + ['tv'] * 3 + ['camera'] * 3 + ['ap'] * 2 + ['unknown'] * 4
    for i, kind in enumerate(types):
        first = since - 30 * 86400 if i < len(types) - 5 else since + rnd.randint(0, span - 1)
        db.execute('INSERT INTO devices (id, mac, first_seen, last_seen, hostname, vendor, auto_type, present) '
                   "VALUES (?, ?, ?, ?, ?, 'Exemplo', ?, 1)",
                   (i + 1, '02:00:00:00:00:%02x' % i, first, now, 'host-%d.example.test' % i, kind))
    db.commit()
    db.close()

    # posture: one run per day for 3 weeks
    db = _db(os.path.join(directory, 'posture.db'), POSTURE)
    score = 71.0
    for day in range(21, 0, -1):
        score = max(40.0, min(95.0, score + rnd.uniform(-4, 5)))
        db.execute("INSERT INTO runs (ts, score, grade, pass, warn, fail, na) VALUES (?, ?, ?, ?, ?, ?, 2)",
                   (now - day * 86400 + 3600, round(score, 1), 'B' if score >= 80 else 'C', 30, 6, 4))
    db.commit()
    db.close()

    # AI: audit log (ok / error with duration) and the local queue
    lines = []
    for hour in hours:
        for _ in range(rnd.randint(0, 5)):
            name, provider, model, mean = rnd.choice(SCENARIOS)
            ts = hour + rnd.randint(0, 3599)
            if ts >= now:
                continue
            status = 'error' if rnd.random() < 0.07 else 'ok'
            rec = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(ts)), 'app': 'policyanalyzer',
                   'action': name, 'scenario': name, 'provider': provider, 'model': model, 'status': status,
                   'prompt': 'FICTITIOUS', 'subject': 'fictitious'}
            if status == 'ok':
                rec['duration_ms'] = int(rnd.lognormvariate(math.log(mean * 1000), 0.35))
                if rnd.random() < 0.1:
                    rec['problems'] = ['too many sentences']
            else:
                rec['error'] = 'timeout (fictitious)'
            lines.append((ts, json.dumps(rec)))
    lines.sort()
    half = len(lines) // 3
    with open(os.path.join(directory, 'ai.log.1'), 'w') as handle:
        handle.write(''.join(l + '\n' for _t, l in lines[:half]))
    with open(os.path.join(directory, 'ai.log'), 'w') as handle:
        handle.write(''.join(l + '\n' for _t, l in lines[half:]))
    db = _db(os.path.join(directory, 'ai-queue.db'), AI_QUEUE)
    for i in range(18):
        name, provider, model, mean = rnd.choice(SCENARIOS[:3] + SCENARIOS[5:])
        created = since + rnd.randint(0, span - 600)
        started = created + rnd.randint(2, 240)
        status = 'error' if i % 9 == 4 else 'done'
        db.execute("INSERT INTO jobs (key, scenario, status, created, started, finished, provider, model, argv, "
                   "format_ok, provider_used, model_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?)",
                   ('k%d' % i, name, status, created, started, started + int(mean), provider, model,
                    1 if rnd.random() > 0.1 else 0, provider, model))
    db.commit()
    db.close()

    # shadow AI
    db = _db(os.path.join(directory, 'shadowai.db'), SHADOWAI)
    day_first = time.strftime('%Y-%m-%d', time.localtime(since))
    day_last = time.strftime('%Y-%m-%d', time.localtime(now - 1))
    for day in sorted({day_first, day_last}):
        for service, weight in (('ChatGPT', 90), ('Gemini', 40), ('Claude', 35), ('Copilot', 22), ('Perplexity', 8)):
            for host in ('192.0.2.10', '192.0.2.11'):
                db.execute('INSERT OR REPLACE INTO daily VALUES (?, ?, ?, ?, ?, 0)',
                           (host, service, day, rnd.randint(weight // 2, weight), rnd.randint(weight // 3, weight)))
    db.commit()
    db.close()

    # a local collector exposing report_series
    os.makedirs(os.path.join(directory, 'collect'), exist_ok=True)
    db = _db(os.path.join(directory, 'collect', 'dns.db'), COLLECT)
    for hour in hours:
        if hour >= since:
            db.execute("INSERT INTO report_series VALUES (?, 'consultas', ?)", (hour, rnd.randint(800, 2400)))
            db.execute("INSERT INTO report_series VALUES (?, 'bloqueadas (DNSBL)', ?)", (hour, rnd.randint(40, 300)))
    db.commit()
    db.close()
