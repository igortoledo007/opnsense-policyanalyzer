"""
Claude Code (LAN) provider against a fake claude-bridge on 127.0.0.1:<ephemeral port>.
The real bridge is never contacted.
"""

import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ai_helpers  # noqa: F401  (sets sys.path)
from ai import AIConfig, Assistant, AuditLog, ProviderError, Task
from ai.providers import describe, get_provider
from ai.providers.claudecode import DEFAULT_URL, MAX_REQUEST_BYTES, ClaudeCodeProvider

TOKEN = 'bridge-token-0123456789abcdefSECRET9876'
MESSAGES = [{'role': 'system', 'content': 'fixed rules'}, {'role': 'user', 'content': 'explain IP4_PRIV_1'}]
HEALTH = {'status': 'ok', 'service': 'claude-bridge', 'version': '1', 'claude_version': '2.1.319 (Claude Code)',
          'models': ['fable', 'opus', 'sonnet', 'haiku'], 'default_model': 'sonnet', 'busy': False}


def chat_ok(text='Answer about IP4_PRIV_1.', model='sonnet'):
    return {'status': 'ok', 'text': text, 'model': model, 'duration_ms': 4100,
            'usage': {'input_tokens': 120, 'output_tokens': 30}}


class FakeBridge:
    """ scripted answers: list of (status, body, delay) consumed per request; body bytes are sent raw """

    def __init__(self, script, token=TOKEN, redirect=False):
        self.script = list(script)
        self.token = token
        self.redirect = redirect
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _answer(self, body_in):
                headers = {k.lower(): v for k, v in self.headers.items()}
                fake.requests.append({'method': self.command, 'path': self.path, 'headers': headers, 'body': body_in})
                if fake.redirect:
                    self.send_response(302)
                    self.send_header('Location', 'http://example.invalid/steal')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                if headers.get('authorization') != 'Bearer %s' % fake.token:
                    status, body, delay = 401, {'status': 'error', 'message': 'unauthorized'}, 0
                else:
                    status, body, delay = fake.script.pop(0) if fake.script else (500, {'status': 'error',
                                                                                        'message': 'no script'}, 0)
                if delay:
                    time.sleep(delay)
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                try:
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass                    # the client gave up (timeout test)

            def do_GET(self):
                self._answer(None)

            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                self._answer(json.loads(self.rfile.read(length) or b'{}'))

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ClaudeCodeProviderTest(unittest.TestCase):
    def setUp(self):
        self.fakes = []

    def tearDown(self):
        for fake in self.fakes:
            fake.close()

    def bridge(self, script, **kw):
        fake = FakeBridge(script, **kw)
        self.fakes.append(fake)
        return fake

    def provider(self, fake, timeout=10, **opts):
        options = {'url': fake.url, 'token': TOKEN, 'model': 'sonnet', 'timeout_margin': 0}
        options.update(opts)
        return ClaudeCodeProvider(options, timeout=timeout)

    # health / models ---------------------------------------------------------------------------------
    def test_health_ok(self):
        fake = self.bridge([(200, HEALTH, 0)])
        health = self.provider(fake).health()
        self.assertEqual(health['version'], '2.1.319 (Claude Code)')
        self.assertEqual(health['bridge_version'], '1')
        self.assertFalse(health['busy'])
        req = fake.requests[0]
        self.assertEqual((req['method'], req['path']), ('GET', '/health'))
        self.assertEqual(req['headers']['authorization'], 'Bearer ' + TOKEN)

    def test_health_401(self):
        fake = self.bridge([], token='another-token-0000000000000000')
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake).health()
        self.assertIn('HTTP 401', str(ctx.exception))
        self.assertIn('token', str(ctx.exception))
        self.assertNotIn(TOKEN, str(ctx.exception))

    def test_health_403(self):
        fake = self.bridge([(403, {'status': 'error', 'message': 'forbidden'}, 0)])
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake).health()
        self.assertIn('HTTP 403', str(ctx.exception))

    def test_health_not_a_bridge(self):
        fake = self.bridge([(200, {'status': 'ok', 'service': 'something-else'}, 0), (200, b'<html>', 0)])
        with self.assertRaises(ProviderError):
            self.provider(fake).health()
        with self.assertRaises(ProviderError):
            self.provider(fake).health()

    def test_list_models_from_health(self):
        fake = self.bridge([(200, HEALTH, 0)])
        names = [m['name'] for m in self.provider(fake).list_models()]
        self.assertEqual(names, ['fable', 'opus', 'sonnet', 'haiku'])

    # chat --------------------------------------------------------------------------------------------
    def test_chat_ok_request_shape(self):
        fake = self.bridge([(200, chat_ok(), 0)])
        result = self.provider(fake, timeout=42, model='opus').chat(MESSAGES)
        self.assertEqual(result.text, 'Answer about IP4_PRIV_1.')
        self.assertEqual(result.model, 'sonnet')            # as reported by the bridge
        self.assertEqual(result.prompt_tokens, 120)
        self.assertEqual(result.completion_tokens, 30)
        self.assertEqual(result.usage, {'input_tokens': 120, 'output_tokens': 30})
        req = fake.requests[0]
        self.assertEqual((req['method'], req['path']), ('POST', '/v1/chat'))
        self.assertEqual(req['headers']['authorization'], 'Bearer ' + TOKEN)
        self.assertEqual(req['headers']['content-type'], 'application/json')
        self.assertEqual(req['body'], {'model': 'opus', 'messages': MESSAGES, 'timeout': 42})

    def test_chat_stream_calls_back_once(self):
        fake = self.bridge([(200, chat_ok('full text'), 0)])
        chunks = []
        result = self.provider(fake).chat(MESSAGES, stream=True, on_chunk=chunks.append)
        self.assertEqual(chunks, ['full text'])
        self.assertEqual(result.text, 'full text')
        self.assertNotIn('stream', fake.requests[0]['body'])

    def test_chat_busy_429(self):
        fake = self.bridge([(429, {'status': 'busy', 'message': 'queue full'}, 0)])
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake).chat(MESSAGES)
        self.assertIn('busy', str(ctx.exception))
        self.assertIn('queue full', str(ctx.exception))
        self.assertEqual(len(fake.requests), 1)           # no automatic retry

    def test_chat_error_5xx_message(self):
        fake = self.bridge([(502, {'status': 'error', 'message': 'claude exited with code 1'}, 0)])
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake).chat(MESSAGES)
        self.assertIn('HTTP 502', str(ctx.exception))
        self.assertIn('claude exited with code 1', str(ctx.exception))

    def test_chat_error_400_and_413(self):
        fake = self.bridge([(400, {'status': 'error', 'message': 'unknown model'}, 0),
                            (413, {'status': 'error', 'message': 'too large'}, 0)])
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake).chat(MESSAGES)
        self.assertIn('unknown model', str(ctx.exception))
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake).chat(MESSAGES)
        self.assertIn('256 KiB', str(ctx.exception))

    def test_chat_status_error_with_200(self):
        fake = self.bridge([(200, {'status': 'error', 'message': 'session expired'}, 0)])
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake).chat(MESSAGES)
        self.assertIn('session expired', str(ctx.exception))

    def test_chat_timeout(self):
        fake = self.bridge([(200, chat_ok(), 3)])
        start = time.monotonic()
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake, timeout=1).chat(MESSAGES)
        self.assertIn('timeout', str(ctx.exception))
        self.assertLess(time.monotonic() - start, 2.5)

    def test_request_size_limit_checked_before_sending(self):
        fake = self.bridge([])
        big = [{'role': 'user', 'content': 'x' * (MAX_REQUEST_BYTES + 1)}]
        with self.assertRaises(ProviderError):
            self.provider(fake).chat(big)
        self.assertEqual(fake.requests, [])

    def test_redirect_refused(self):
        fake = self.bridge([], redirect=True)
        with self.assertRaises(ProviderError) as ctx:
            self.provider(fake).health()
        self.assertIn('redirect', str(ctx.exception))

    def test_unreachable(self):
        fake = self.bridge([])
        url = fake.url
        fake.close()
        self.fakes.remove(fake)
        with self.assertRaises(ProviderError):
            ClaudeCodeProvider({'url': url, 'token': TOKEN}, timeout=2).health()

    # configuration -----------------------------------------------------------------------------------
    def test_defaults_and_validation(self):
        p = ClaudeCodeProvider({'token': TOKEN})
        self.assertEqual(p.endpoint(), DEFAULT_URL)
        self.assertEqual(p.model, 'sonnet')
        self.assertEqual(p.timeout, 300)
        self.assertEqual(ClaudeCodeProvider({'model': 'bogus'}).model, 'sonnet')
        for bad in ('ftp://host:11436', 'http://user:pw@host:11436', 'http://host:11436/?a=1', 'http://host:abc'):
            with self.assertRaises(ProviderError):
                ClaudeCodeProvider({'url': bad, 'token': TOKEN})
        self.assertEqual(ClaudeCodeProvider({'url': 'https://bridge.lan:8443/'}).endpoint(), 'https://bridge.lan:8443')
        with self.assertRaises(ProviderError):
            ClaudeCodeProvider({'token': ''}).health()
        with self.assertRaises(ProviderError):
            ClaudeCodeProvider({'token': 'bad token with spaces 1234567890'}).health()

    def test_registry(self):
        reg = describe()
        ids = [p['id'] for p in reg['providers']]
        self.assertEqual(ids, ['ollama', 'claudecode', 'claude'])
        cc = [p for p in reg['providers'] if p['id'] == 'claudecode'][0]
        self.assertEqual(cc['group'], 'local')
        self.assertTrue(cc['privacy_warn'])
        self.assertIn('Anthropic', cc['privacy'])
        self.assertEqual(cc['choices'][0]['badge'], 'LAN')
        fields = {f['id']: f for f in cc['fields']}
        self.assertTrue(fields['token']['secret'])
        self.assertEqual(fields['url']['default'], DEFAULT_URL)
        self.assertEqual(list(fields['model']['options']), ['fable', 'opus', 'sonnet', 'haiku'])
        self.assertEqual(fields['model']['default'], 'sonnet')
        self.assertIsInstance(get_provider('claudecode', {'token': TOKEN}), ClaudeCodeProvider)

    def test_config_from_dict(self):
        cfg = AIConfig.from_dict({'ai': {'enabled': '1', 'provider': 'claudecode'},
                                  'claudecode': {'url': 'http://10.0.0.5:11436', 'token': TOKEN, 'model': 'haiku'}})
        self.assertTrue(cfg.enabled)
        self.assertIsNone(cfg.timeout)
        self.assertEqual(cfg.options['url'], 'http://10.0.0.5:11436')
        self.assertEqual(cfg.options['model'], 'haiku')


class ClaudeCodeAssistantTest(unittest.TestCase):
    def test_test_and_ask_audit_without_token(self):
        fake = FakeBridge([(200, HEALTH, 0), (200, HEALTH, 0), (200, chat_ok(), 0),
                           (429, {'status': 'busy', 'message': 'queue full'}, 0)])
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'ai.log')
            cfg = AIConfig(enabled=True, provider='claudecode', anonymize=True,
                           options={'url': fake.url, 'token': TOKEN, 'model': 'sonnet'})
            assistant = Assistant(cfg, audit=AuditLog(log_path))
            try:
                test = assistant.test()
                result = assistant.ask(Task('t'), {'host': '192.168.1.20'})
                with self.assertRaises(ProviderError):
                    assistant.ask(Task('t'), {'host': '192.168.1.20'})
            finally:
                fake.close()
            with open(log_path) as fh:
                raw = fh.read()
        self.assertEqual(test['version'], '2.1.319 (Claude Code)')
        self.assertTrue(test['model_available'])
        self.assertEqual(test['models'], 4)
        self.assertIn('192.168.1.20', result['text'])      # placeholder restored in the answer
        sent = fake.requests[2]['body']['messages'][-1]['content']
        self.assertNotIn('192.168.1.20', sent)              # anonymized before leaving the firewall
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual([r['status'] for r in records], ['ok', 'ok', 'error'])
        self.assertEqual(records[1]['provider'], 'claudecode')
        self.assertEqual(records[1]['usage'], {'input_tokens': 120, 'output_tokens': 30})
        self.assertNotIn(TOKEN, raw)
        self.assertNotIn('SECRET9876', raw)


if __name__ == '__main__':
    unittest.main()
