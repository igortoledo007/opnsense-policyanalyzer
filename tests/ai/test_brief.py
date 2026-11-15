"""
AI brief for the Max Cyber war room (ai/brief.py): log aggregation, inputs, state file, lock and the
background refresh.  No network and no AI: a fake provider answers, the spawn is replaced by a callable.
Addresses are documentation ranges only (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from ai_helpers import SCRIPTS
from ai import AIConfig, Assistant
from ai.audit import NullAuditLog
from ai.providers import ProviderError
from ai.providers.base import GenerateResult
from ai import brief

NOW = 1794200000.0           # fixed clock for the log window (2026-11-08T...)
WAN_DEV = 'pppoe1'

CONFIG = """<?xml version="1.0"?>
<opnsense>
  <interfaces>
    <wan><if>pppoe1</if><ipaddr>pppoe</ipaddr></wan>
    <lan><if>igc1</if><ipaddr>192.168.1.1</ipaddr></lan>
    <opt1><if>igc2</if><ipaddr>dhcp</ipaddr></opt1>
    <opt2><if>wg0</if></opt2>
  </interfaces>
  <OPNsense><policyanalyzer version="1.0.0">
    <ai><enabled>{enabled}</enabled><provider>ollama</provider><anonymize>1</anonymize><language>auto</language></ai>
    <ollama><location>local</location><model>qwen2.5:3b</model></ollama>
  </policyanalyzer></OPNsense>
</opnsense>
"""

EXPOSURE = {
    'version': 1, 'kind': 'exposure', 'generated': '2026-11-08T03:10:51+00:00', 'status': 'ok',
    'summary': {'services': 20, 'reachable': 1, 'maybe_reachable': 1, 'admin_reachable': 0, 'cves_total': 11,
                'kev': 0, 'findings': 10, 'by_severity': {'high': 0, 'medium': 0, 'low': 10, 'info': 0},
                'posture': 'hardened', 'posture_confidence': 'full',
                'attack_surface': [
                    {'service': 'wireguard', 'label': 'WireGuard (kernel)', 'proto': 'udp', 'port': 51830,
                     'internet_reachable': 'yes', 'admin': False, 'cves': 0, 'kev': 0},
                    {'service': 'ntp', 'label': 'NTP', 'proto': 'udp', 'port': 123,
                     'internet_reachable': 'maybe', 'admin': False, 'cves': 0, 'kev': 0},
                    {'service': 'web', 'label': 'lighttpd', 'proto': 'tcp', 'port': 443,
                     'internet_reachable': 'no', 'admin': True, 'cves': 2, 'kev': 0}]},
    'services': [],
}

REPORT = {'version': 1, 'generated': '2026-11-08T03:10:00Z',
          'summary': {'rules': 33, 'enabled': 31, 'findings': 22,
                      'by_severity': {'high': 0, 'medium': 0, 'low': 10, 'info': 12}}}


def stamp(epoch):
    """ RFC 5424 timestamp in -03:00, as syslog-ng writes it on the firewall """
    return time.strftime('%Y-%m-%dT%H:%M:%S-03:00', time.gmtime(epoch - 3 * 3600))


def v4(epoch, iface, action, direction, proto, src, dst, sport='', dport='', seq=1):
    num = {'tcp': '6', 'udp': '17', 'icmp': '1'}[proto]
    csv = ['55', '', '', '8faed529-7112-480b-bdcd-159350ed3f4c', iface, 'match', action, direction, '4', '0x0', '',
           '49', '19808', '0', 'none', num, proto, '52', src, dst]
    if proto in ('tcp', 'udp'):
        csv += [sport, dport, '0']
        if proto == 'tcp':
            csv += ['S', '1758505626', '', '65535', '', 'mss;nop;wscale']
    else:
        csv += ['request', '1', '1']
    return '<134>1 %s fw.example.lan filterlog 40707 - [meta sequenceId="%d"] %s' % (stamp(epoch), seq, ','.join(csv))


def v6(epoch, iface, action, direction, src, dst, dport):
    csv = ['60', '', '', 'abcdef0123456789abcdef0123456789', iface, 'match', action, direction, '6', '0x00', '0x00000',
           '57', 'tcp', '6', '40', src, dst, '40000', dport, '0', 'S', '1', '', '1024', '', '']
    return '<134>1 %s fw.example.lan filterlog 40707 - [meta sequenceId="9"] %s' % (stamp(epoch), ','.join(csv))


def sample_log():
    lines = []
    # older than the window: must be ignored
    lines.append(v4(NOW - 20 * 60, WAN_DEV, 'block', 'in', 'tcp', '198.51.100.99', '203.0.113.1', '1', '22'))
    # a scanner: 6 blocked attempts on different ports
    for i, port in enumerate(['22', '23', '3389', '5900', '8080', '22']):
        lines.append(v4(NOW - 600 + i, WAN_DEV, 'block', 'in', 'tcp', '198.51.100.7', '203.0.113.1', '4000', port))
    # a second source, 2 blocks on 22
    for i in range(2):
        lines.append(v4(NOW - 300 + i, WAN_DEV, 'block', 'in', 'tcp', '198.51.100.8', '203.0.113.1', '4001', '22'))
    # traffic to the exposed WireGuard port (passed)
    lines.append(v4(NOW - 200, WAN_DEV, 'pass', 'in', 'udp', '192.0.2.50', '203.0.113.1', '51000', '51830'))
    # LAN and outbound traffic: counted in the totals, not as WAN inbound
    lines.append(v4(NOW - 100, 'igc1', 'pass', 'in', 'tcp', '192.168.1.20', '192.0.2.80', '50000', '443'))
    lines.append(v4(NOW - 90, WAN_DEV, 'pass', 'out', 'tcp', '203.0.113.1', '192.0.2.80', '50001', '443'))
    lines.append(v4(NOW - 80, WAN_DEV, 'block', 'in', 'icmp', '198.51.100.9', '203.0.113.1'))
    lines.append(v6(NOW - 70, WAN_DEV, 'block', 'in', '2001:db8::7', '2001:db8:1::1', '445'))
    lines.append('<38>1 %s fw.example.lan sshd 1 - [meta] not a filter line' % stamp(NOW - 60))
    return lines


class FakeProvider:
    """ records the messages; answers with the first placeholder it sees (restore check) """

    def __init__(self, fail=None):
        self.fail = fail
        self.messages = None

    def endpoint(self):
        return 'http://127.0.0.1:11434'

    def chat(self, messages, stream=False, on_chunk=None):
        self.messages = messages
        if self.fail:
            raise ProviderError(self.fail)
        import re
        tokens = re.findall(r'IP4_(?:PUB|PRIV)_\d+', messages[1]['content'])
        return GenerateResult(text='**Background scanning**: %s probed 5 ports.\n' % (tokens[0] if tokens else '?'),
                              model='qwen2.5:3b', duration_ms=1234, prompt_tokens=300, completion_tokens=20)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.paths = {k: os.path.join(d, v) for k, v in {
            'config': 'config.xml', 'log': 'filter/filter_20261108.log', 'latest': 'filter/latest.log',
            'exposure': 'exposure.json', 'report': 'last.json', 'brief': 'db/ai-brief.json',
            'focus': 'db/ai-brief-focus.json', 'lock': 'db/ai-brief.lock'}.items()}
        os.makedirs(os.path.join(d, 'filter'))
        with open(self.paths['log'], 'w') as fh:
            fh.write('\n'.join(sample_log()) + '\n')
        os.symlink(self.paths['log'], self.paths['latest'])
        self.write_config(1)
        with open(self.paths['exposure'], 'w') as fh:
            json.dump(EXPOSURE, fh)
        with open(self.paths['report'], 'w') as fh:
            json.dump(REPORT, fh)
        patches = {'CONFIG_XML': 'config', 'FILTER_LOG': 'latest', 'EXPOSURE': 'exposure', 'REPORT': 'report',
                   'BRIEF': 'brief', 'BRIEF_FOCUS': 'focus', 'LOCK': 'lock'}
        for attr, key in patches.items():
            p = mock.patch.object(brief, attr, self.paths[key])
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def write_config(self, enabled):
        with open(self.paths['config'], 'w') as fh:
            fh.write(CONFIG.format(enabled=enabled))

    def assistant(self, provider):
        config = AIConfig.from_opnsense(brief.MOUNT, path=self.paths['config'])
        return Assistant(config, app='policyanalyzer', audit=NullAuditLog(), provider=provider)

    def stored(self, key='brief'):
        with open(self.paths[key]) as fh:
            return json.load(fh)


class ParseTest(Base):
    def test_rfc5424_v4_tcp(self):
        rec = brief.parse_line(v4(NOW, WAN_DEV, 'block', 'in', 'tcp', '198.51.100.7', '203.0.113.1', '4000', '22'))
        self.assertEqual((rec['iface'], rec['action'], rec['dir'], rec['proto']), (WAN_DEV, 'block', 'in', 'tcp'))
        self.assertEqual((rec['src'], rec['dst'], rec['dport']), ('198.51.100.7', '203.0.113.1', '22'))
        self.assertEqual(rec['ts'], NOW)

    def test_real_firewall_line_layout(self):
        # a line as seen in /var/log/filter/latest.log of the firewall (addresses replaced)
        line = ('<134>1 2026-11-08T01:51:43-03:00 OPNsense1.example.lan filterlog 40707 - [meta sequenceId="6112"] '
                '55,,,8faed529-7112-480b-bdcd-159350ed3f4c,pppoe1,match,block,in,4,0x0,,240,65031,0,none,6,tcp,40,'
                '198.51.100.89,203.0.113.178,52745,5741,0,S,620968920,,1024,,')
        rec = brief.parse_line(line)
        self.assertEqual(rec['dport'], '5741')
        self.assertEqual(rec["ts"], 1794113503)

    def test_v6_and_icmp(self):
        rec = brief.parse_line(v6(NOW, WAN_DEV, 'block', 'in', '2001:db8::7', '2001:db8:1::1', '445'))
        self.assertEqual((rec['ipver'], rec['proto'], rec['src'], rec['dport']), ('6', 'tcp', '2001:db8::7', '445'))
        rec = brief.parse_line(v4(NOW, WAN_DEV, 'block', 'in', 'icmp', '198.51.100.9', '203.0.113.1'))
        self.assertEqual((rec['proto'], rec['dport']), ('icmp', ''))

    def test_not_filterlog(self):
        self.assertIsNone(brief.parse_line('<38>1 2026-11-08T01:00:00-03:00 fw sshd 1 - [meta] hello'))
        self.assertIsNone(brief.parse_line('garbage'))

    def test_rfc3164(self):
        now = time.mktime((2026, 11, 8, 2, 0, 0, 0, 0, -1))
        rec = brief.parse_line('Nov  8 01:59:00 fw filterlog[123]: 5,,,0,em0,match,block,in,4,0x0,,64,1,0,none,17,'
                               'udp,40,198.51.100.1,203.0.113.2,53,5353,20', now)
        self.assertEqual((rec['proto'], rec['dport']), ('udp', '5353'))
        self.assertAlmostEqual(rec['ts'], now - 60, delta=1)


class AggregateTest(Base):
    def test_wan_interfaces(self):
        self.assertEqual(brief.wan_interfaces(self.paths['config']), {'pppoe1', 'igc2'})

    def test_window_and_aggregates(self):
        records, meta = brief.read_window(self.paths['latest'], NOW)
        self.assertTrue(meta['complete'])
        self.assertEqual(len(records), 13)                  # the 20 min old line and the sshd line are out
        data, wan_ports = brief.aggregate(records, {'pppoe1'}, NOW)
        self.assertEqual(data['events'], 13)
        self.assertEqual(data['block'], 10)
        self.assertEqual(data['pass'], 3)
        self.assertEqual(data['inbound_on_wan'], 11)
        self.assertEqual(data['distinct_blocked_sources'], 4)
        top = data['top_blocked_sources'][0]
        self.assertEqual((top['ip'], top['blocked'], top['distinct_ports']), ('198.51.100.7', 6, 5))
        self.assertEqual(top['ports'][0], '22/tcp')
        self.assertEqual(data['top_wan_ports'][0], {'port': '22/tcp', 'blocked': 4, 'passed': 0})
        self.assertEqual(wan_ports['51830/udp'], {'pass': 1})

    def test_budget_cut_is_reported(self):
        records, meta = brief.read_window(self.paths['latest'], NOW, max_lines=3)
        self.assertFalse(meta['complete'])
        self.assertLessEqual(len(records), 3)

    def test_previous_rotated_file(self):
        # after midnight latest.log is short: the window continues in the previous day's file
        old = os.path.join(self.tmp.name, 'filter', 'filter_20261107.log')
        os.replace(self.paths['log'], old)
        with open(self.paths['log'], 'w') as fh:
            fh.write(v4(NOW - 10, WAN_DEV, 'block', 'in', 'tcp', '198.51.100.70', '203.0.113.1', '1', '25') + '\n')
        records, meta = brief.read_window(self.paths['latest'], NOW)
        self.assertEqual(len(records), 14)
        self.assertTrue(meta['complete'])

    def test_focus(self):
        records, _ = brief.read_window(self.paths['latest'], NOW)
        data, _ = brief.aggregate(records, {'pppoe1'}, NOW, focus='198.51.100.7')
        f = data['focus']
        self.assertEqual(f['events'], 6)
        self.assertEqual(f['by_action'], {'inbound_block': 6})
        self.assertEqual(f['distinct_ports'], 5)
        self.assertEqual(f['interfaces'], ['pppoe1 (wan)'])
        self.assertEqual((f['first_seen_seconds_ago'], f['last_seen_seconds_ago']), (600, 595))

    def test_inputs_only_aggregates(self):
        inputs = brief.build_inputs(NOW, log_path=self.paths['latest'], config_path=self.paths['config'],
                                    report_path=self.paths['report'], exposure_path=self.paths['exposure'])
        blob = json.dumps(inputs)
        self.assertNotIn('filterlog', blob)                 # never a raw line
        self.assertNotIn('8faed529', blob)                  # nor rule ids
        self.assertNotIn('203.0.113.1', blob)               # nor our own WAN address (destinations are dropped)
        ex = inputs['exposure']
        self.assertEqual(ex['posture'], 'hardened')
        self.assertEqual([s['service'] for s in ex['internet_reachable_services']], ['WireGuard (kernel)', 'NTP'])
        self.assertEqual(ex['reachable_services_targeted'],
                         [{'service': 'WireGuard (kernel)', 'port': '51830/udp', 'attempts': 1, 'blocked': 0, 'passed': 1}])
        self.assertEqual(inputs['policy_analyzer']['by_severity']['low'], 10)

    def test_missing_reports(self):
        self.assertEqual(brief.exposure_inputs(None), {'available': False})
        self.assertEqual(brief.findings_inputs({}), {'available': False})


class StateTest(Base):
    def test_cached_none_and_disabled(self):
        self.assertEqual(brief.cmd_cached('pt_BR', None, NOW)['status'], 'none')
        self.write_config(0)
        self.assertEqual(brief.cmd_cached('pt_BR', None, NOW)['status'], 'disabled')
        self.assertEqual(brief.cmd_refresh('pt_BR', None, NOW, spawn=self.no_spawn)['status'], 'disabled')

    def test_refresh_spawns_once_then_throttles(self):
        calls = []

        def spawn(language, focus, fd):
            calls.append((language, focus))
            # the child would generate now; do it in-process, on the inherited lock
            brief.cmd_run(language, focus, lock_fd=os.dup(fd), assistant=self.assistant(FakeProvider()),
                          inputs={'firewall_log': {'top_blocked_sources': [{'ip': '198.51.100.7'}]}})

        out = brief.cmd_refresh('pt_BR', None, NOW, spawn=spawn)
        self.assertEqual(out['status'], 'running')
        self.assertEqual(calls, [('pt_BR', None)])
        rec = brief.cmd_cached('pt_BR', None)
        self.assertEqual(rec['status'], 'ok')
        self.assertEqual(rec['text'], 'Background scanning: 198.51.100.7 probed 5 ports.')     # restored, cleaned
        self.assertEqual(rec['model'], 'qwen2.5:3b')
        self.assertIn('inputs', rec)
        self.assertLess(rec['age_seconds'], 5)
        again = brief.cmd_refresh('pt_BR', None, time.time() + 60, spawn=spawn)
        self.assertTrue(again.get('throttled'))
        self.assertEqual(len(calls), 1)
        brief.cmd_refresh('pt_BR', None, time.time() + brief.MIN_AGE_OK + 1, spawn=spawn)
        self.assertEqual(len(calls), 2)

    def test_lock_held_means_running(self):
        holder = brief.Lock(self.paths['lock'])
        self.assertTrue(holder.acquire())
        try:
            brief.write_json(self.paths['brief'], {'status': 'running', 'started_at': brief.iso(NOW), 'text': 'old'})
            out = brief.cmd_refresh('en_US', None, NOW, spawn=self.no_spawn)
            self.assertEqual(out['status'], 'running')
            self.assertEqual(out['text'], 'old')
            # a focus asked while the general brief runs: busy, nothing spawned
            out = brief.cmd_refresh('en_US', '198.51.100.7', NOW, spawn=self.no_spawn)
            self.assertEqual(out['status'], 'none')
            self.assertTrue(out['busy'])
        finally:
            holder.release()

    def test_running_without_lock_is_interrupted(self):
        brief.write_json(self.paths['brief'], {'status': 'running', 'started_at': brief.iso(NOW)})
        rec = brief.cmd_cached('en_US', None, NOW)
        self.assertEqual(rec['status'], 'error')
        self.assertIn('interrupted', rec['message'])

    def test_error_keeps_previous_text(self):
        brief.write_json(self.paths['brief'], {'status': 'ok', 'text': 'previous brief', 'generated_at': brief.iso(NOW)})
        rec = brief.cmd_run('en_US', None, assistant=self.assistant(FakeProvider(fail='timeout after 360 seconds')),
                            inputs={'firewall_log': {}})
        self.assertEqual(rec['status'], 'error')
        stored = self.stored()
        self.assertEqual((stored['status'], stored['text']), ('error', 'previous brief'))
        self.assertIn('timeout', stored['message'])
        # an error may be retried after MIN_AGE_ERROR, not before
        self.assertTrue(brief.is_fresh(stored, time.time() + 10))
        self.assertFalse(brief.is_fresh(stored, time.time() + brief.MIN_AGE_ERROR + 1))

    def test_focus_file_and_payload_anonymized(self):
        provider = FakeProvider()
        inputs = brief.build_inputs(NOW, focus='198.51.100.7', log_path=self.paths['latest'],
                                    config_path=self.paths['config'], report_path=self.paths['report'],
                                    exposure_path=self.paths['exposure'])
        rec = brief.cmd_run('pt_BR', '198.51.100.7', assistant=self.assistant(provider), inputs=inputs)
        self.assertEqual(rec['status'], 'ok')
        sent = json.dumps(provider.messages)
        self.assertNotIn('198.51.100.7', sent)
        self.assertRegex(sent, r'IP4_(PUB|PRIV)_1')
        self.assertIn('Brazilian Portuguese', provider.messages[0]['content'])
        self.assertIn('ONE remote address', provider.messages[0]['content'])
        self.assertEqual(self.stored('focus')['focus'], '198.51.100.7')
        self.assertFalse(os.path.exists(self.paths['brief']))
        self.assertEqual(brief.cmd_cached('pt_BR', '198.51.100.7')['status'], 'ok')
        self.assertEqual(brief.cmd_cached('pt_BR', '198.51.100.8')['status'], 'none')

    def test_valid_focus(self):
        self.assertEqual(brief.valid_focus('-'), None)
        self.assertEqual(brief.valid_focus('2001:DB8::7'), '2001:db8::7')
        for bad in ('198.51.100.300', '1.2.3.4; rm', '../x', 'example.com'):
            with self.assertRaises(ValueError):
                brief.valid_focus(bad)

    def test_clean_text(self):
        self.assertEqual(brief.clean_text('## Title\n\n**a**  b\n- c'), 'Title a b - c')
        long = 'Short sentence. ' * 200
        self.assertLessEqual(len(brief.clean_text(long)), brief.MAX_TEXT)
        self.assertTrue(brief.clean_text(long).endswith('.'))

    def no_spawn(self, *args):
        raise AssertionError('must not spawn')


class CliTest(Base):
    def run_cli(self, *args):
        env = dict(os.environ, POLICYANALYZER_CONFIG=self.paths['config'], POLICYANALYZER_BRIEF=self.paths['brief'],
                   POLICYANALYZER_BRIEF_FOCUS=self.paths['focus'], POLICYANALYZER_BRIEF_LOCK=self.paths['lock'],
                   POLICYANALYZER_FILTERLOG=self.paths['latest'], PYTHONDONTWRITEBYTECODE='1')
        out = subprocess.run([sys.executable, os.path.join(SCRIPTS, 'ai', 'brief.py')] + list(args),
                             capture_output=True, text=True, env=env, timeout=30)
        return json.loads(out.stdout)

    def test_cli_cached_and_validation(self):
        self.assertEqual(self.run_cli('cached', 'pt_BR', '-')['status'], 'none')
        self.assertEqual(self.run_cli('cached', 'pt_BR', 'not-an-ip')['message'], 'invalid focus address')
        self.assertEqual(self.run_cli('bogus')['status'], 'error')
        brief.write_json(self.paths['brief'], {'status': 'ok', 'text': 'x', 'generated_at': brief.iso(time.time())})
        rec = self.run_cli('cached', 'en_US', '-')
        self.assertEqual((rec['status'], rec['text']), ('ok', 'x'))
        # fresh: refresh does not start anything
        self.assertTrue(self.run_cli('refresh', 'en_US', '-')['throttled'])


if __name__ == '__main__':
    unittest.main()
