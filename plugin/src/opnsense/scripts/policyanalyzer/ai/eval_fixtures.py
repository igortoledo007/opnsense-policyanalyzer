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

    Fixed, SYNTHETIC inputs of the per scenario evaluation (ai/evaluate.py): one or more samples per scenario of the
    catalog, with the real instructions of each module (the same Task the module builds) and data shaped like the
    module's DATA block.  Every address, host name, rule and number is invented: documentation ranges
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), a private 10.20.30.0/24 LAN and "*.home.lan" names.  Public
    knowledge (a CVE id, an IDS signature name, a vendor) is used where the scenario needs it.

    Evaluation data in Portuguese, on purpose: the models are tested answering in Brazilian Portuguese
    (LANGUAGE below, evaluate.LANG), so the quicktest question, the console question, some rule descriptions of
    the synthetic data ("Libera NAS", "LAN para qualquer") and the regexes of facts / forbidden (matched against
    the Portuguese answers, without accents) stay in Portuguese.  Changing them changes what is measured: bump
    FIXTURES_VERSION if you do.

    Each fixture: id, scenario, subject, build() -> (Task, data), and what a good answer must contain:
        facts      list of regex alternatives ("a|b"), matched without accents and case; one point each
        expect     structured checks: first_value (MAPPING/TYPE value in a list), actions_any (an incident action
                   id among these), confidence_in
        forbidden  claims that must not appear (e.g. "it was blocked automatically")
        max_words  size limit when the catalog has none

    FIXTURES_VERSION changes whenever a fixture changes: results of different versions are not compared.
"""

FIXTURES_VERSION = 1
LANGUAGE = 'pt_BR'


def _task(*args, **kwargs):
    from ai import Task
    return Task(*args, **kwargs)


# ------------------------------------------------------------------ Policy Analyzer findings


def _explain_finding():
    import explain
    data = {
        'finding': {'id': 'f3a9c1d2e4', 'type': 'wan_exposed', 'severity': 'high',
                    'title': 'NAS file sharing reachable from the internet',
                    'detail': 'Rule "Libera NAS" on WAN passes any source to 10.20.30.15 port 445/tcp (SMB). '
                              'The destination is the NAS nas-sala.home.lan; 1.284 states in the last 7 days.',
                    'recommendation': 'Restrict the source to a VPN or remove the rule; SMB must not face the '
                                      'internet.',
                    'aliases': [], 'evidence': {'states_7d': 1284, 'port_forward': 'WAN tcp/445 -> 10.20.30.15:445'}},
        'rules': [{'source': 'filter', 'interface': 'wan', 'direction': 'in', 'action': 'pass', 'sequence': 4,
                   'description': 'Libera NAS', 'summary': 'pass in on wan proto tcp from any to 10.20.30.15 port 445',
                   'disabled': False}],
    }
    return _task('explain_finding', explain.FINDING_INSTRUCTIONS, 'Explain this finding.'), data


def _explain_set():
    import explain
    data = {
        'summary': {'rules': 38, 'findings': 4, 'by_severity': {'high': 1, 'medium': 2, 'low': 1}},
        'findings': [
            {'type': 'wan_exposed', 'severity': 'high', 'title': 'NAS file sharing reachable from the internet',
             'detail': 'WAN rule "Libera NAS" passes any to 10.20.30.15 port 445/tcp.',
             'rules': ['wan #4 pass "Libera NAS"']},
            {'type': 'shadowed', 'severity': 'medium', 'title': 'Rule never matches (shadowed)',
             'detail': 'LAN rule #9 "Bloqueia IoT para internet" comes after LAN rule #2 "LAN para qualquer", which '
                       'already passes the same traffic.', 'rules': ['lan #2 pass', 'lan #9 block']},
            {'type': 'permissive', 'severity': 'medium', 'title': 'Pass rule with any source, destination and port',
             'detail': 'LAN rule #2 "LAN para qualquer" passes any to any.', 'rules': ['lan #2 pass']},
            {'type': 'unused', 'severity': 'low', 'title': 'Rule without hits in 90 days',
             'detail': 'OPT1 rule #3 "Teste antigo" has 0 packets since 2026-08-10.', 'rules': ['opt1 #3 pass']},
        ],
    }
    return _task('explain_set', explain.SET_INSTRUCTIONS, 'Summarise these findings.'), data


# ------------------------------------------------------------------ war room


def _brief_inputs():
    return {
        'window_minutes': 15,
        'firewall_log': {'pass': 18240, 'block': 3112, 'block_in_wan': 2987,
                         'top_blocked_sources': [{'address': '203.0.113.45', 'count': 912, 'ports': [22, 2222]},
                                                 {'address': '198.51.100.77', 'count': 301, 'ports': [8443]},
                                                 {'address': '192.0.2.200', 'count': 88, 'ports': [3389]}],
                         'top_wan_ports': [{'port': 22, 'count': 1120}, {'port': 8443, 'count': 310},
                                           {'port': 3389, 'count': 140}]},
        'exposure': {'internet_reachable': [{'service': 'openvpn', 'proto': 'udp', 'port': 1194}],
                     'grade': 'B'},
        'policy_analyzer': {'high': 1, 'medium': 2, 'low': 1},
    }


def _war_room_brief():
    from ai import brief
    return _task('war_room_brief', brief.BRIEF_INSTRUCTIONS, 'Write the situational brief.'), _brief_inputs()


def _war_room_focus():
    from ai import brief
    data = _brief_inputs()
    data['focus'] = {'address': '198.51.100.77', 'blocked_in': 301, 'passed': 0, 'directions': {'in': 301},
                     'destination_ports': [{'port': 8443, 'count': 297}, {'port': 443, 'count': 4}],
                     'interfaces': ['wan'], 'first_seen_s': 840, 'last_seen_s': 12,
                     'touched_exposed_service': False}
    return _task('war_room_focus', brief.FOCUS_INSTRUCTIONS, 'Write the note about the focus address.'), data


# ------------------------------------------------------------------ AI Console


def _console_ask():
    from console import ask as cask
    q = 'Quem mais foi bloqueado hoje?'
    data = {
        'question_analysis': {'intents': ['top_blocked'], 'window': 'today', 'entities': []},
        'evidence_order': ['filterlog', 'quarantine', 'hosts'],
        'filterlog': {'available': True, 'complete': True, 'window': 'today 00:00-10:40',
                      'blocks': 41872, 'top_blocked_sources': [
                          {'address': '203.0.113.45', 'blocks': 9120, 'last': '10:38', 'ports': [22, 2222],
                           'rule': 'wan #1 block "Default deny"'},
                          {'address': '198.51.100.77', 'blocks': 3011, 'last': '10:31', 'ports': [8443],
                           'rule': 'wan #1 block "Default deny"'},
                          {'address': '10.20.30.61', 'blocks': 640, 'last': '10:12', 'ports': [53],
                           'rule': 'lan #7 block "DNS externo bloqueado"'}]},
        'quarantine': {'available': True, 'active': [{'address': '203.0.113.45', 'level': 2, 'since': '09:55'}]},
        'hosts': {'10.20.30.61': 'tv-sala.home.lan'},
    }
    return _task('console_ask', cask.ASK_INSTRUCTIONS, q), data


def _console_explain_log():
    from console import ask as cask
    data = {
        'event': {'ts': '2026-11-09T03:14:07', 'iface': 'wan', 'action': 'block', 'dir': 'in', 'proto': 'tcp',
                  'src': '192.0.2.10', 'sport': 51522, 'dst': '10.20.30.1', 'dport': 23, 'rid': 'a1f0c9'},
        'rule': {'rid': 'a1f0c9', 'interface': 'wan', 'action': 'block', 'description': 'Default deny rule',
                 'sequence': 'automatic'},
        'recent_same_source': {'events_24h': 57, 'ports': [23, 2323, 22], 'first': '02:51', 'last': '03:14'},
        'quarantine': {'address': '192.0.2.10', 'active': False},
        'path': {'verdict': 'block', 'matched': 'default deny (automatic)'},
        'hosts': {},
    }
    return _task('console_explain_log', cask.EXPLAIN_LOG, 'Explain this filter log event.'), data


def _console_explain_rule():
    from console import ask as cask
    data = {
        'rule': {'uuid': '7c1e2d3a-0b4c-4d5e-8f60-1a2b3c4d5e6f', 'interface': 'lan', 'action': 'pass',
                 'direction': 'in', 'quick': True, 'log': False, 'source': 'LAN net', 'destination': 'any',
                 'port': 'any', 'protocol': 'any', 'description': 'LAN para qualquer', 'position': 2},
        'counters': {'evaluations': 9120044, 'packets': 7781200, 'bytes': '41.2 GB', 'states': 512},
        'findings': [{'type': 'permissive', 'severity': 'medium', 'title': 'Pass rule with any destination and port'},
                     {'type': 'shadowed', 'severity': 'medium',
                      'title': 'Rule #9 "Bloqueia IoT para internet" is shadowed by this rule'}],
        'neighbours': [{'position': 1, 'action': 'pass', 'description': 'Anti-lockout'},
                       {'position': 9, 'action': 'block', 'description': 'Bloqueia IoT para internet'}],
        'log_hits_24h': 0,
    }
    return _task('console_explain_rule', cask.EXPLAIN_RULE, 'Review this firewall rule.'), data


def _console_explain_alert():
    from console import ask as cask
    data = {
        'alert': {'timestamp': '2026-11-09T01:22:41', 'signature': 'ET SCAN Suspicious inbound to mySQL port 3306',
                  'sid': 2010937, 'category': 'Potentially Bad Traffic', 'severity': 2, 'action': 'blocked',
                  'src_ip': '198.51.100.23', 'src_port': 40112, 'dest_ip': '10.20.30.1', 'dest_port': 3306,
                  'proto': 'TCP'},
        'filterlog_same_source': {'blocks_24h': 214, 'ports': [3306, 1433, 5432], 'first': '01:20', 'last': '01:24'},
        'quarantine': {'address': '198.51.100.23', 'active': True, 'level': 1},
        'hosts': {},
    }
    return _task('console_explain_alert', cask.EXPLAIN_ALERT, 'Explain this Suricata alert.'), data


# ------------------------------------------------------------------ incidents


def _incident_case():
    return {
        'title': 'SSH brute force from 203.0.113.45 against the firewall',
        'severity': 'high', 'score': 78, 'state': 'new', 'first_seen': 1794150000, 'last_activity': 1794156600,
        'matches': 3, 'rules': [{'rule': 'bruteforce_ssh'}, {'rule': 'scan_then_auth'}],
        'factors': [{'label': 'Failed logins', 'points': 30, 'detail': '612 failed SSH logins in 40 min'},
                    {'label': 'Port scan before', 'points': 20, 'detail': '18 ports probed before the logins'},
                    {'label': 'Reputation', 'points': 28, 'detail': 'listed by 2 feeds'}],
        'entities': [
            {'kind': 'ext', 'role': 'attacker', 'value': '203.0.113.45',
             'info': {'connections': 1530, 'quarantine': {'level': 1, 'active': False, 'reason': 'scan'}}},
            {'kind': 'int', 'role': 'target', 'value': '10.20.30.1', 'info': {'connections': 1530}},
            {'kind': 'rule', 'role': 'matched', 'value': '0d9e8f7a-1b2c-4d3e-9f40-5a6b7c8d9e0f',
             'info': {'description': 'SSH admin (WAN)'}},
        ],
        'evidence': [
            {'source': 'filterlog', 'rule': 'scan', 'first': 1794150000, 'last': 1794150300, 'count': 18,
             'text': '18 destination ports probed on the WAN address'},
            {'source': 'sshd', 'rule': 'bruteforce_ssh', 'first': 1794150400, 'last': 1794156600, 'count': 612,
             'text': '612 failed logins for root, admin and ubuntu'},
            {'source': 'suricata', 'rule': 'ids', 'first': 1794150410, 'last': 1794150420, 'count': 3,
             'text': 'ET SCAN Potential SSH Scan'},
        ],
        'evidence_total': 3,
    }


def _incident_summary():
    from incidents import triage
    case = _incident_case()
    cands = triage.candidates(case)
    task = _task('incident_summary', triage.SUMMARY_INSTRUCTIONS, 'Triage this case and answer with the JSON object.',
                 schema=triage.summary_schema(cands), check_ctx={'valid_ids': [c['id'] for c in cands]})
    return task, triage.case_payload(case, cands)


def incident_ctx():
    from incidents import triage
    return {'cands': triage.candidates(_incident_case())}


def _incident_digest():
    from incidents import triage
    data = {'day': '2026-11-08', 'cases': 5, 'new_cases': 4,
            'by_severity': {'high': 1, 'medium': 2, 'low': 2}, 'by_state': {'new': 4, 'investigating': 1},
            'by_rule': {'bruteforce_ssh': 1, 'scan': 3, 'dns_nxdomain_burst': 1},
            'top_cases': [
                {'title': 'SSH brute force from 203.0.113.45 against the firewall', 'severity': 'high', 'score': 78,
                 'state': 'new', 'new_today': True, 'rules': ['bruteforce_ssh'],
                 'entities': [{'kind': 'ext', 'value': '203.0.113.45'}], 'evidence_rows': 3},
                {'title': 'Many NXDOMAIN answers for 10.20.30.42', 'severity': 'medium', 'score': 51,
                 'state': 'investigating', 'new_today': False, 'rules': ['dns_nxdomain_burst'],
                 'entities': [{'kind': 'int', 'value': '10.20.30.42'}], 'evidence_rows': 2},
                {'title': 'Port scan from 198.51.100.77', 'severity': 'low', 'score': 22, 'state': 'new',
                 'new_today': True, 'rules': ['scan'], 'entities': [{'kind': 'ext', 'value': '198.51.100.77'}],
                 'evidence_rows': 1}]}
    return _task('incident_digest', triage.DIGEST_INSTRUCTIONS, 'Write the daily digest.'), data


# ------------------------------------------------------------------ anomalies


def _anomaly_explain():
    from anomalies import explain as aexplain
    data = {'type': 'beaconing', 'type_title': 'Periodic connections (beaconing)', 'severity': 'medium', 'score': 64,
            'max_score': 100, 'status': 'open', 'title': 'notebook-01.example.lan contacts one address every 60 s',
            'detail': '10.20.30.42 opened a TLS connection to 198.51.100.150:443 every 60 s (jitter 2 s) for 9 h.',
            'host': '10.20.30.42', 'hostname': 'notebook-01.example.lan', 'first_seen_iso': '2026-11-08T22:05',
            'last_seen_iso': '2026-11-09T07:04', 'occurrences': 1,
            'factors': [{'name': 'period_regularity', 'value': 0.97, 'threshold': 0.9, 'counted': True},
                        {'name': 'connections', 'value': 539, 'threshold': 200, 'counted': True},
                        {'name': 'destination_reputation', 'value': 'unknown', 'threshold': 'listed', 'counted': False}],
            'params': {'window_h': 12},
            'available_actions': ['mark_expected', 'open_live_view', 'ask_console']}
    return _task('anomaly_explain', aexplain.FINDING_INSTRUCTIONS, 'Explain this anomaly finding.'), data


def _anomaly_host():
    from anomalies import explain as aexplain
    data = {'host': '10.20.30.61', 'hostname': 'tv-sala.home.lan', 'vendor': 'Samsung Electronics',
            'baseline': {'out_bytes_per_hour': '180 MB', 'dns_queries_per_hour': 240, 'nxdomain_per_hour': 3,
                         'countries': ['BR', 'US'], 'asns': 6, 'domains_learned': 85, 'tls_fingerprints': 2},
            'now': {'out_bytes_this_hour': '2.9 GB', 'dns_queries_last_hour': 260, 'nxdomain_last_hour': 4,
                    'top_destinations_24h': [{'asn': 'CDN-EXEMPLO', 'bytes': '7.1 GB'}]},
            'findings': [{'type': 'volume_spike', 'severity': 'low', 'title': 'Outbound volume 16x the baseline'}],
            'available_actions': ['mark_expected', 'open_live_view']}
    return _task('anomaly_host', aexplain.HOST_INSTRUCTIONS,
                 'Describe this host: what is normal for it and what is happening now.'), data


# ------------------------------------------------------------------ vulnerabilities, devices


def _explain_cve():
    from vulns import explain as vexplain
    data = {'cve': 'CVE-2024-6387', 'package': 'openssh-portable', 'installed_version': '9.7p1,1',
            'fixed_in': '9.8p1,1', 'fix_available': True,
            'summary': 'Race condition in the signal handler of sshd (regreSSHion) may allow remote code execution.',
            'cvss': 8.1, 'cvss_vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'epss': 0.42,
            'epss_percentile': 0.97, 'kev': None, 'priority': 'P1', 'priority_rule': 'internet exposed + high EPSS',
            'factors': ['sshd listens on the WAN', 'EPSS in the top 3 %'], 'exposure': 'internet',
            'services': [{'service': 'sshd', 'service_name': 'Secure Shell', 'proto': 'tcp', 'port': 22,
                          'internet_reachable': True, 'management': True, 'link': '/ui/core/system'}]}
    return _task('explain_cve', vexplain.EXPLAIN_INSTRUCTIONS, 'Explain this vulnerability for this firewall.'), data


def _vuln_review_suggest():
    from vulns import explain as vexplain
    cands = [{'id': 'a1b2c3d4', 'service': 'unbound', 'service_name': 'Unbound DNS', 'proto': 'udp', 'port': 53,
              'internet_reachable': False, 'package': 'unbound'},
             {'id': 'b5c6d7e8', 'service': 'lighttpd', 'service_name': 'Web GUI', 'proto': 'tcp', 'port': 443,
              'internet_reachable': False, 'package': 'lighttpd'}]
    data = {'kind': 'package', 'component': 'unbound', 'version': '1.21.0', 'cves': ['CVE-2024-8508'],
            'why_in_review': 'package with a CVE and two listening services on the firewall', 'candidates': cands}
    ids = [c['id'] for c in cands]
    task = _task('vuln_review_suggest', vexplain.SUGGEST_INSTRUCTIONS, 'Suggest the mapping of this component.',
                 schema=vexplain.mapping_schema(ids), render=vexplain.render_mapping,
                 check_ctx={'first_values': ids + ['none', 'unsure']})
    return task, data


def _explain_device():
    from devices import common as dcommon, explain as dexplain
    data = {'mac': '44:19:b6:00:12:34', 'manufacturer': 'Hangzhou Hikvision Digital Technology',
            'hostname': 'cam-garagem.home.lan', 'address': '10.20.30.88', 'randomised_mac': False,
            'first_seen': '2026-10-02', 'last_seen': '2026-11-09', 'open_ports_seen': [80, 554, 8000],
            'risk': 'high', 'risk_reasons': ['camera vendor with a history of default passwords',
                                             'port forward WAN tcp/8000 -> 10.20.30.88:8000'],
            'dhcp_vendor_class': None}
    task = _task('explain_device', dexplain.INSTRUCTIONS, 'Explain this device of the local network.',
                 schema=dexplain.type_schema(), render=dexplain.render_type,
                 check_ctx={'first_values': list(dcommon.TYPES)})
    return task, data


# ------------------------------------------------------------------ posture, shadow AI, minimal rule


def _posture_check():
    from posture import cli as pcli
    data = {'id': 'PA-ACC-01', 'title': 'Web GUI not reachable from the WAN', 'category': 'access',
            'severity': 'critical', 'result': 'fail',
            'evidence': {'listen': 'all interfaces', 'wan_rule': 'wan #6 pass any to This Firewall port 443'},
            'recommendation': 'Listen only on LAN and remove the WAN pass rule to the GUI.',
            'fix': {'steps': ['System > Settings > Administration > Listen Interfaces: LAN',
                              'Firewall > Rules > WAN: disable rule #6'],
                    'note': 'Remote administration then needs the VPN.'}}
    return _task('posture_check', pcli.EXPLAIN_CHECK, 'Explain this health check result.'), data


def _posture_summary():
    from posture import cli as pcli
    data = {'score': 72, 'grade': 'C', 'previous': {'score': 68, 'grade': 'D'},
            'categories': {'access': 45, 'updates': 90, 'logging': 85, 'rules': 70, 'services': 75},
            'failed': [{'id': 'PA-ACC-01', 'severity': 'critical', 'title': 'Web GUI not reachable from the WAN'},
                       {'id': 'PA-ACC-04', 'severity': 'high', 'title': 'Two factor authentication for administrators'},
                       {'id': 'PA-RUL-02', 'severity': 'medium', 'title': 'Pass rules with any destination'}],
            'changes': [{'id': 'PA-UPD-01', 'from': 'fail', 'to': 'pass', 'title': 'Firmware up to date'}]}
    return _task('posture_summary', pcli.EXECUTIVE, 'Write the executive summary of this posture assessment.'), data


def _shadowai_overview():
    from shadowai import cli as scli
    data = {'window_days': 7, 'hosts_total': 14,
            'services': [{'service': 'ChatGPT', 'hosts': 5, 'queries': 4210, 'known': False, 'risk': 'normal',
                          'new': False},
                         {'service': 'DeepSeek', 'hosts': 1, 'queries': 380, 'known': False, 'risk': 'elevated',
                          'new': True, 'risk_reason': 'data stored outside the country'},
                         {'service': 'Claude (bridge of the firewall)', 'hosts': 1, 'queries': 950, 'known': True,
                          'risk': 'normal', 'new': False}],
            'hosts': [{'host': 'notebook-01.example.lan', 'services': 3}, {'host': 'pc-escritorio.home.lan',
                                                                          'services': 1}]}
    return _task('shadowai_overview', scli.OVERVIEW, 'Explain the AI usage on this network.'), data


def _minrule_explain():
    from minrule import cli as mcli
    data = {'rule': {'interface': 'lan', 'description': 'LAN para qualquer', 'source': 'LAN net',
                     'destination': 'any', 'port': 'any', 'protocol': 'any'},
            'window_days': 7, 'unit': 'connections (filter log, exact)', 'confidence': 'high',
            'observed': {'destinations': 212, 'ports': [{'port': 443, 'share': 0.81}, {'port': 80, 'share': 0.11},
                                                        {'port': 53, 'share': 0.05}, {'port': 123, 'share': 0.02}]},
            'proposal': {'protocol': 'tcp/udp', 'ports_alias': 'PA_lan_web_dns_ntp (80, 443, 53, 123)',
                         'destination': 'any'},
            'coverage': 0.99, 'not_covered': [{'port': 5228, 'connections': 31, 'note': 'push notifications'}]}
    return _task('minrule_explain', mcli.EXPLAIN, 'Explain the risk of this rule and the minimal rule proposal.'), data


# ------------------------------------------------------------------ reports, notifications, quick test


def _report_summary():
    from reports import aisum
    data = {'period': 'daily 2026-11-08', 'blocked_wan': 41872, 'top_countries': ['US', 'CN', 'NL'],
            'quarantine': {'new': 3, 'active': 9, 'level_max': 3},
            'cves': {'P1': 1, 'P2': 0, 'kev': 0, 'top': 'CVE-2024-6387 openssh-portable (P1)'},
            'new_devices': 1, 'posture': {'score': 72, 'grade': 'C', 'previous_score': 68},
            'findings': {'high': 1, 'medium': 2}}
    return _task('report_summary', aisum.EXEC_INSTRUCTIONS, 'Write the executive summary of this report.'), data


def _notification_summary():
    from reports import aisum
    data = {'events': [{'type': 'quarantine', 'severity': 'high', 'title': '203.0.113.45 put in quarantine (level 3)',
                        'detail': '612 failed SSH logins in 40 min after a port scan',
                        'facts': {'address': '203.0.113.45', 'level': 3, 'duration': '2 days'}}]}
    return _task('notification_summary', aisum.NOTIFY_INSTRUCTIONS, 'Write the alert summary.'), data


def _quicktest():
    question = ('Hoje é segunda-feira, 9 de novembro de 2026. Em no máximo duas frases curtas, em português, dê '
                'uma dica rápida de segurança de rede para um firewall doméstico.')
    return _task('quicktest', 'You answer short questions of the administrator.', question), {}


# ------------------------------------------------------------------ the list

FIXTURES = (
    {'id': 'finding-smb-wan', 'scenario': 'explain_finding', 'subject': 'NAS SMB exposed on the WAN',
     'build': _explain_finding, 'facts': [r'445|smb', r'wan|internet', r'restring|vpn|remov|desativ|limit',
                                          r'libera nas|regra'],
     'forbidden': [r'(?:eu )?(?:ja )?(?:apliquei|alterei|removi) a regra']},
    {'id': 'set-4-findings', 'scenario': 'explain_set', 'subject': '4 findings (1 high, 2 medium, 1 low)',
     'build': _explain_set, 'facts': [r'445|smb|nas', r'sombread|nunca (?:e |sera )?(?:casad|aplicad|avaliad|usad)|'
                                      r'shadow|ordem', r'qualquer|any|permissiv', r'teste antigo|sem uso|sem acerto|'
                                      r'0 pacote|nao usad']},
    {'id': 'brief-ssh-scan', 'scenario': 'war_room_brief', 'subject': '15 min window with an SSH scan',
     'build': _war_room_brief, 'facts': [r'bloque', r'203\.0\.113\.45', r'\b22\b|ssh',
                                         r'varredura|scan|ruido|rotina|comum']},
    {'id': 'focus-8443', 'scenario': 'war_room_focus', 'subject': 'source 198.51.100.77 on port 8443',
     'build': _war_room_focus, 'facts': [r'198\.51\.100\.77', r'8443', r'varredura|scan|forca bruta|tentativ',
                                         r'nao (?:atingiu|alcancou|chegou|tocou)|nenhum servico exposto|nao exposto'],
     'forbidden': [r'sera bloquead|foi colocad[oa] em quarentena|sera colocad|vou bloquear']},
    # the subject of console_ask is the question itself (evaluation data, Portuguese)
    {'id': 'ask-top-blocked', 'scenario': 'console_ask', 'subject': 'Quem mais foi bloqueado hoje?',
     'build': _console_ask, 'facts': [r'203\.0\.113\.45', r'9\.?120', r'198\.51\.100\.77',
                                      r'quarentena|quarantine'], 'max_words': 320},
    {'id': 'log-telnet', 'scenario': 'console_explain_log', 'subject': 'tcp/23 block on the WAN',
     'build': _console_explain_log, 'facts': [r'\b23\b|telnet', r'192\.0\.2\.10', r'default deny|bloqueio padrao|'
                                              r'regra padrao|negacao padrao|automatic', r'varredura|scan|esperado|'
                                              r'ruido|bot'], 'max_words': 380},
    {'id': 'rule-lan-any', 'scenario': 'console_explain_rule', 'subject': 'LAN any/any rule',
     'build': _console_explain_rule, 'facts': [r'qualquer|any', r'#9|bloqueia iot|sombread|shadow',
                                               r'restring|limitar|reduzir|estreitar|portas', r'contador|pacotes|'
                                               r'7\.?781\.?200|uso'], 'max_words': 420},
    {'id': 'alert-mysql-scan', 'scenario': 'console_explain_alert', 'subject': 'ET SCAN mysql 3306',
     'build': _console_explain_alert, 'facts': [r'3306|mysql', r'198\.51\.100\.23', r'bloquead|blocked',
                                                r'varredura|scan', r'falso positivo|ameaca real|real'],
     'max_words': 400},
    {'id': 'case-ssh-bruteforce', 'scenario': 'incident_summary', 'subject': 'SSH brute force case, score 78',
     'build': _incident_summary, 'ctx': incident_ctx,
     'facts': [r'ssh', r'forca bruta|brute|tentativas de login|logins? (?:falh|invalid)', r'203\.0\.113\.45'],
     'expect': {'actions_any': ['quarantine_1'], 'confidence_in': ['medium', 'high']}},
    {'id': 'digest-5-cases', 'scenario': 'incident_digest', 'subject': '5 cases of the day',
     'build': _incident_digest, 'facts': [r'\b5\b|cinco', r'ssh|forca bruta|brute', r'nxdomain|dns',
                                          r'ruido|rotina|comum|varredura|scan']},
    {'id': 'anomaly-beacon', 'scenario': 'anomaly_explain', 'subject': 'beaconing every 60 s',
     'build': _anomaly_explain, 'facts': [r'60 ?s|60 segundos|a cada minuto|periodic', r'10\.20\.30\.42|notebook-01',
                                          r'atualiza|backup|agente|monitor|sincroniz', r'marcar como esperado|'
                                          r'mark as expected|mark_expected|esperado']},
    {'id': 'host-tv-volume', 'scenario': 'anomaly_host', 'subject': 'TV with 16x volume',
     'build': _anomaly_host, 'facts': [r'tv|televis|samsung', r'2[.,]9 ?gb|16 ?x|16 vezes', r'180 ?mb',
                                       r'streaming|video|atualiza']},
    {'id': 'cve-regresshion', 'scenario': 'explain_cve', 'subject': 'CVE-2024-6387 openssh P1',
     'build': _explain_cve, 'facts': [r'cve-2024-6387|regresshion', r'\bp1\b', r'\b22\b|ssh|wan|internet',
                                      r'9\.8p1|atualiz|firmware']},
    {'id': 'map-unbound', 'scenario': 'vuln_review_suggest', 'subject': 'unbound with 2 candidates',
     'build': _vuln_review_suggest, 'facts': [r'unbound|dns'], 'expect': {'first_value': ['a1b2c3d4']},
     'max_words': 140},
    {'id': 'device-camera', 'scenario': 'explain_device', 'subject': 'camera with port forward 8000',
     'build': _explain_device, 'facts': [r'camera|cftv|hikvision', r'8000|redirecionamento|port forward',
                                         r'senha|firmware', r'iot|isolad|vlan|rede separada'],
     'expect': {'first_value': ['camera', 'nvr']}},
    {'id': 'check-gui-wan', 'scenario': 'posture_check', 'subject': 'PA-ACC-01 failed',
     'build': _posture_check, 'facts': [r'wan|internet', r'listen interfaces|interfaces de escuta|lan',
                                        r'#6|regra', r'vpn']},
    {'id': 'posture-72-c', 'scenario': 'posture_summary', 'subject': 'score 72 (C), was 68',
     'build': _posture_summary, 'facts': [r'\b72\b', r'\bc\b|nota c', r'pa-acc-01', r'68|melhor|subiu|melhorou',
                                          r'atualiza|updates|firmware']},
    {'id': 'shadowai-deepseek', 'scenario': 'shadowai_overview', 'subject': '3 AI services, DeepSeek new',
     'build': _shadowai_overview, 'facts': [r'chatgpt', r'deepseek', r'elevad|risco|fora do pais',
                                            r'esperad|ponte|known|conhecid'],
     'forbidden': [r'bloquear (?:o )?(?:uso do )?claude|bloqueie (?:o )?claude']},
    {'id': 'minrule-lan-any', 'scenario': 'minrule_explain', 'subject': 'LAN any → 80/443/53/123',
     'build': _minrule_explain, 'facts': [r'443', r'99 ?%|0[.,]99|cobertura', r'5228|push|notifica',
                                          r'alias', r'reverter|valores antigos|log ao vivo|live']},
    {'id': 'report-daily', 'scenario': 'report_summary', 'subject': 'synthetic daily report',
     'build': _report_summary, 'facts': [r'41\.?872|bloque', r'cve-2024-6387|\bp1\b|openssh',
                                         r'atencao|critico|tranquilo', r'quarentena']},
    {'id': 'notify-quarantine', 'scenario': 'notification_summary', 'subject': 'quarantine level 3',
     'build': _notification_summary, 'facts': [r'203\.0\.113\.45', r'quarentena', r'ssh|login']},
    {'id': 'quick-tip', 'scenario': 'quicktest', 'subject': 'security tip',
     'build': _quicktest, 'facts': [r'senha|atualiz|firmware|porta|regra|acesso|wan|vpn'], 'max_words': 70},
)
BY_ID = {f['id']: f for f in FIXTURES}


def for_scenario(scenario):
    return [f for f in FIXTURES if f['scenario'] == scenario]


def get(fixture_id):
    if fixture_id not in BY_ID:
        raise KeyError('unknown fixture %s' % fixture_id)
    return BY_ID[fixture_id]


def build(fixture_id):
    """ :return: (Task, data, ctx) of a fixture """
    fx = get(fixture_id)
    task, data = fx['build']()
    ctx = fx['ctx']() if fx.get('ctx') else None
    return task, data, ctx


def haystack(fixture_id):
    """ the text a good answer may take facts from: the data and the question (instructions excluded) """
    import json
    task, data, _ctx = build(fixture_id)
    return task.question + '\n' + json.dumps(data, ensure_ascii=False, default=str)
