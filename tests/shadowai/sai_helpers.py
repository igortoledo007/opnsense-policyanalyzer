"""
Helpers of the AI usage tests: a temporary root with fictional DNS queries (JSON lines instead of the Unbound
DuckDB), Suricata eve.json TLS events, Kea leases, a hostwatch SQLite file and the fictional config.xml.
Internal hosts use 192.0.2.0/24 (documentation prefix, declared internal through POLICYANALYZER_TEST_INTERNAL).

    192.0.2.10  laptop-01   ChatGPT every day, DeepSeek new (last day)
    192.0.2.20  bridge       Claude (the Claude Code bridge of the AI provider: expected)
    192.0.2.30  dev-ws       GitHub Copilot (known in the local catalogue), Claude
    127.0.0.1   firewall     Ollama model downloads (expected)
    192.0.2.40  phone        Midjourney (disabled in the local catalogue: not counted), "notclaude.ai" (no match)
"""

import csv
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
sys.dont_write_bytecode = True
os.environ['TZ'] = 'UTC'
time.tzset()
os.environ['POLICYANALYZER_TEST_INTERNAL'] = '192.0.2.0/24'

from posture.common import Paths  # noqa: E402

NOW = 1793000000
DAY = 86400


def eve_line(ts, src, sni, ja4='t13d1516h2_8daaf6152771_e5627efa2ab1'):
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts)) + '.000000+0000'
    return json.dumps({'timestamp': stamp, 'flow_id': 1, 'event_type': 'tls', 'src_ip': src, 'src_port': 50000,
                       'dest_ip': '198.51.100.7', 'dest_port': 443, 'proto': 'TCP',
                       'tls': {'sni': sni, 'version': 'TLS 1.3', 'ja4': ja4}}, separators=(',', ':'))


class Root:
    def __init__(self, with_eve=True, with_local=True, dns_extra=()):
        self.dir = tempfile.mkdtemp(prefix='pa-shadowai-')
        os.makedirs(os.path.join(self.dir, 'db'))
        shutil.copy(os.path.join(HERE, 'fixtures', 'config.xml'), os.path.join(self.dir, 'config.xml'))
        queries = []
        for day in range(7):
            t = NOW - (6 - day) * DAY - 3600
            queries += [{'time': t + i * 60, 'client': '192.0.2.10', 'domain': 'chatgpt.com.', 'action': 0}
                        for i in range(5)]
            queries.append({'time': t, 'client': '192.0.2.20', 'domain': 'api.anthropic.com.', 'action': 0})
        queries += [{'time': NOW - 7200, 'client': '192.0.2.10', 'domain': 'chat.deepseek.com.', 'action': 0},
                    {'time': NOW - 7100, 'client': '192.0.2.10', 'domain': 'chat.deepseek.com.', 'action': 1},
                    {'time': NOW - 5000, 'client': '192.0.2.30', 'domain': 'api.githubcopilot.com.', 'action': 0},
                    {'time': NOW - 4000, 'client': '192.0.2.30', 'domain': 'claude.ai.', 'action': 0},
                    {'time': NOW - 3000, 'client': '127.0.0.1', 'domain': 'registry.ollama.ai.', 'action': 0},
                    {'time': NOW - 2000, 'client': '192.0.2.40', 'domain': 'www.midjourney.com.', 'action': 0},
                    {'time': NOW - 1900, 'client': '192.0.2.40', 'domain': 'notclaude.ai.', 'action': 0},
                    {'time': NOW - 1800, 'client': '192.0.2.40', 'domain': 'example.org.', 'action': 0},
                    {'time': NOW - 1700, 'client': '100.200.0.9', 'domain': 'chatgpt.com.', 'action': 0},
                    {'time': NOW - 30 * DAY, 'client': '192.0.2.10', 'domain': 'gemini.google.com.', 'action': 0}]
        queries += list(dns_extra)
        with open(os.path.join(self.dir, 'unbound.jsonl'), 'w') as handle:
            for q in queries:
                handle.write(json.dumps(q) + '\n')
        with open(os.path.join(self.dir, 'unbound.clients.json'), 'w') as handle:
            json.dump({'192.0.2.10': 'laptop-01.example.test'}, handle)
        eve = os.path.join(self.dir, 'eve.json')
        if with_eve:
            lines = [eve_line(NOW - 20 * DAY, '192.0.2.10', 'chatgpt.com')]
            lines += [eve_line(NOW - 3 * DAY + i, '192.0.2.10', 'chatgpt.com') for i in range(3)]
            lines += [eve_line(NOW - 2 * DAY, '192.0.2.20', 'api.anthropic.com', ja4='t13d1312h2_aaaaaaaaaaaa_bbbbbbbbbbbb')]
            lines += [eve_line(NOW - DAY, '192.0.2.20', 'api.anthropic.com')]
            lines += ['{"timestamp":"x","event_type":"alert","src_ip":"192.0.2.10"}']
            with open(eve, 'w') as handle:
                handle.write('\n'.join(lines) + '\n')
        with open(os.path.join(self.dir, 'leases.csv'), 'w', newline='') as handle:
            w = csv.writer(handle)
            w.writerow(['address', 'hwaddr', 'client_id', 'valid_lifetime', 'expire', 'subnet_id', 'fqdn_fwd',
                        'fqdn_rev', 'hostname', 'state', 'user_context', 'pool_id'])
            w.writerow(['192.0.2.20', '02:00:00:00:00:20', '', '86400', '0', '1', '0', '0', 'bridge', '0', '', '0'])
        hw = os.path.join(self.dir, 'hosts.db')
        db = sqlite3.connect(hw)
        db.executescript('''CREATE TABLE hosts (ip_address text, ether_address text, last_seen text);
            CREATE TABLE oui (assignment TEXT PRIMARY KEY, organization_name TEXT);
            CREATE VIEW v_hosts AS SELECT hosts.*, oui.organization_name FROM hosts LEFT JOIN oui
                ON oui.assignment = upper(replace(substr(hosts.ether_address,0,9),':',''));
            INSERT INTO oui VALUES ('020000', 'Example Devices Inc');
            INSERT INTO hosts VALUES ('192.0.2.10', '02:00:00:00:00:10', '2026-10-26');
            INSERT INTO hosts VALUES ('192.0.2.40', '02:00:00:00:00:40', '2026-10-26');''')
        db.commit()
        db.close()
        self.paths = Paths(config=os.path.join(self.dir, 'config.xml'), db_dir=os.path.join(self.dir, 'db'),
                           unbound_db=os.path.join(self.dir, 'unbound.jsonl'), eve=eve,
                           kea_leases=os.path.join(self.dir, 'leases.csv'), hostwatch_db=hw,
                           local_catalog=os.path.join(HERE, 'fixtures', 'ai-services.local.json') if with_local
                           else os.path.join(self.dir, 'none.json'),
                           audit_log=os.path.join(self.dir, 'ai.log'))

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)
