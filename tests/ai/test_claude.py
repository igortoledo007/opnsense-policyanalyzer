import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ai_helpers  # noqa: F401  (sets sys.path)
from ai import AIConfig, Assistant, AuditLog, ProviderError, ProviderRefusal, Task
from ai.providers import describe
from ai.providers.claude import API_VERSION, FALLBACK_BETA, ClaudeProvider

KEY = 'sk-ant-test-0123456789abcdefSECRET1234'
MESSAGES = [{'role': 'system', 'content': 'fixed rules'}, {'role': 'user', 'content': 'explain IP4_PRIV_1'}]


class FakeAnthropic:
    """ scripted answers: a list of (status, body, headers) consumed per POST/GET """

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _answer(self, body_in):
                fake.requests.append({'method': self.command, 'path': self.path, 'headers': {k.lower(): v for k, v in self.headers.items()},
                                      'body': body_in})
                status, body, headers = fake.script.pop(0) if fake.script else (500, {}, {})
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._answer(None)

            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                self._answer(json.loads(self.rfile.read(length)))

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def message(text='Answer about IP4_PRIV_1.', stop='end_turn', usage=None, extra=None):
    body = {'id': 'msg_1', 'type': 'message', 'role': 'assistant', 'model': 'claude-opus-5-5',
            'content': [{'type': 'thinking', 'thinking': 'hidden'}, {'type': 'text', 'text': text}],
            'stop_reason': stop,
            'usage': usage or {'input_tokens': 100, 'output_tokens': 20, 'cache_read_input_tokens': 80,
                               'cache_creation_input_tokens': 0}}
    body.update(extra or {})
    return body


ERR401 = {'type': 'error', 'error': {'type': 'authentication_error', 'message': 'invalid x-api-key'}}
ERR429 = {'type': 'error', 'error': {'type': 'rate_limit_error', 'message': 'slow down'}}
ERR529 = {'type': 'error', 'error': {'type': 'overloaded_error', 'message': 'Overloaded'}}


class ClaudeProviderTest(unittest.TestCase):
    def provider(self, fake, **opts):
        options = {'base_url': fake.url, 'apikey': KEY, 'model': 'claude-opus-5-5', 'effort': 'medium',
                   'retry_cap': 0.2}
        options.update(opts)
        return ClaudeProvider(options, timeout=10)

    def test_success_request_shape(self):
        fake = FakeAnthropic([(200, message(), {})])
        try:
            result = self.provider(fake).chat(MESSAGES)
        finally:
            fake.close()
        req = fake.requests[0]
        self.assertEqual(req['path'], '/v1/messages')
        self.assertEqual(req['headers']['x-api-key'], KEY)
        self.assertEqual(req['headers']['anthropic-version'], API_VERSION)
        self.assertEqual(req['headers']['anthropic-beta'], FALLBACK_BETA)
        body = req['body']
        self.assertEqual(body['model'], 'claude-opus-5-5')
        self.assertEqual(body['max_tokens'], 16000)
        self.assertEqual(body['output_config'], {'effort': 'medium'})
        self.assertEqual(body['fallbacks'], 'default')
        self.assertEqual(body['system'], [{'type': 'text', 'text': 'fixed rules',
                                           'cache_control': {'type': 'ephemeral'}}])
        self.assertEqual(body['messages'], [{'role': 'user', 'content': 'explain IP4_PRIV_1'}])
        for forbidden in ('thinking', 'temperature', 'top_p', 'top_k', 'budget_tokens'):
            self.assertNotIn(forbidden, body)
        self.assertEqual(result.text, 'Answer about IP4_PRIV_1.')     # only text blocks
        self.assertEqual(result.usage['cache_read_input_tokens'], 80)
        self.assertFalse(result.truncated)

    def test_defaults_fable_high_with_fallback(self):
        fake = FakeAnthropic([(200, message(), {})])
        try:
            prov = ClaudeProvider({'base_url': fake.url, 'apikey': KEY})
            self.assertEqual(prov.timeout, 180)
            prov.chat(MESSAGES)
        finally:
            fake.close()
        req = fake.requests[0]
        self.assertEqual(req['body']['model'], 'claude-fable-5-1')
        self.assertEqual(req['body']['output_config'], {'effort': 'high'})
        self.assertEqual(req['headers']['anthropic-beta'], FALLBACK_BETA)
        self.assertEqual(req['body']['fallbacks'], 'default')
        self.assertEqual(req['body']['max_tokens'], 16000)
        for forbidden in ('thinking', 'temperature', 'top_p', 'top_k', 'tool_choice', 'tools'):
            self.assertNotIn(forbidden, req['body'])
        self.assertEqual([m['role'] for m in req['body']['messages']], ['user'])

    def test_all_efforts_accepted(self):
        for effort in ('low', 'medium', 'high', 'xhigh', 'max'):
            payload, _ = ClaudeProvider({'apikey': KEY, 'effort': effort}).build_payload(MESSAGES)
            self.assertEqual(payload['output_config']['effort'], effort)
        payload, _ = ClaudeProvider({'apikey': KEY, 'effort': 'bogus'}).build_payload(MESSAGES)
        self.assertEqual(payload['output_config']['effort'], 'high')

    def test_zero_data_retention_message(self):
        err = {'type': 'error', 'error': {'type': 'invalid_request_error',
                                          'message': 'This model is not available for organizations with zero data retention.'}}
        fake = FakeAnthropic([(400, err, {})])
        try:
            with self.assertRaises(ProviderError) as ctx:
                self.provider(fake, model='claude-fable-5-1').chat(MESSAGES)
        finally:
            fake.close()
        self.assertEqual(str(ctx.exception), 'this model is not available under zero data retention; choose Opus 5.5')
        self.assertEqual(len(fake.requests), 1)

    def test_model_labels_in_registry(self):
        claude = [p for p in describe()['providers'] if p['id'] == 'claude'][0]
        model = [f for f in claude['fields'] if f['id'] == 'model'][0]
        self.assertEqual(list(model['options']), ['claude-fable-5-1', 'claude-opus-5-5', 'claude-sonnet-5-5',
                                                  'claude-haiku-5-5'])
        self.assertIn('US$10/50', model['options']['claude-fable-5-1'])
        self.assertEqual(model['default'], 'claude-fable-5-1')

    def test_haiku_has_no_fallback(self):
        fake = FakeAnthropic([(200, message(), {})])
        try:
            self.provider(fake, model='claude-haiku-5-5').chat(MESSAGES)
        finally:
            fake.close()
        self.assertNotIn('anthropic-beta', fake.requests[0]['headers'])
        self.assertNotIn('fallbacks', fake.requests[0]['body'])

    def test_refusal(self):
        body = message(text='', stop='refusal', extra={
            'stop_details': {'category': 'cyber', 'explanation': 'cannot help with that'}})
        fake = FakeAnthropic([(200, body, {})])
        try:
            with self.assertRaises(ProviderRefusal) as ctx:
                self.provider(fake).chat(MESSAGES)
        finally:
            fake.close()
        self.assertIn('cyber', str(ctx.exception))
        self.assertIn('cannot help with that', str(ctx.exception))

    def test_max_tokens_truncated(self):
        fake = FakeAnthropic([(200, message(stop='max_tokens'), {})])
        try:
            result = self.provider(fake).chat(MESSAGES)
        finally:
            fake.close()
        self.assertTrue(result.truncated)

    def test_401(self):
        fake = FakeAnthropic([(401, ERR401, {})])
        try:
            with self.assertRaises(ProviderError) as ctx:
                self.provider(fake).chat(MESSAGES)
        finally:
            fake.close()
        self.assertIn('API key was rejected', str(ctx.exception))
        self.assertNotIn(KEY, str(ctx.exception))
        self.assertEqual(len(fake.requests), 1)        # no retry

    def test_429_retry_after(self):
        fake = FakeAnthropic([(429, ERR429, {'retry-after': '0.1'}), (200, message(), {})])
        try:
            result = self.provider(fake).chat(MESSAGES)
        finally:
            fake.close()
        self.assertEqual(len(fake.requests), 2)
        self.assertTrue(result.text)

    def test_429_twice_fails(self):
        fake = FakeAnthropic([(429, ERR429, {'retry-after': '0'}), (429, ERR429, {'retry-after': '0'})])
        try:
            with self.assertRaises(ProviderError) as ctx:
                self.provider(fake).chat(MESSAGES)
        finally:
            fake.close()
        self.assertIn('429', str(ctx.exception))

    def test_529_retry_then_ok(self):
        fake = FakeAnthropic([(529, ERR529, {}), (200, message(), {})])
        try:
            self.provider(fake).chat(MESSAGES)
        finally:
            fake.close()
        self.assertEqual(len(fake.requests), 2)

    def test_529_twice(self):
        fake = FakeAnthropic([(529, ERR529, {}), (529, ERR529, {})])
        try:
            with self.assertRaises(ProviderError) as ctx:
                self.provider(fake).chat(MESSAGES)
        finally:
            fake.close()
        self.assertIn('overloaded', str(ctx.exception))

    def test_models_and_health(self):
        models = {'data': [{'id': 'claude-sonnet-5-5', 'display_name': 'Claude Sonnet 5.5'},
                           {'id': 'claude-opus-5-5', 'display_name': 'Claude Opus 5.5'}]}
        fake = FakeAnthropic([(200, models, {}), (200, models, {})])
        try:
            prov = self.provider(fake)
            names = [m['name'] for m in prov.list_models()]
            prov.health()
        finally:
            fake.close()
        self.assertEqual(names, ['claude-opus-5-5', 'claude-sonnet-5-5'])
        self.assertTrue(fake.requests[0]['path'].startswith('/v1/models'))

    def test_https_required_and_key_checks(self):
        with self.assertRaises(ProviderError):
            ClaudeProvider({'base_url': 'http://api.example.com', 'apikey': KEY})
        with self.assertRaises(ProviderError):
            ClaudeProvider({'apikey': ''}).health()
        with self.assertRaises(ProviderError):
            ClaudeProvider({'apikey': 'bad key with spaces and more chars'}).health()

    def test_no_prefill(self):
        with self.assertRaises(ProviderError):
            ClaudeProvider({'apikey': KEY}).build_payload(MESSAGES + [{'role': 'assistant', 'content': 'Sure'}])

    def test_registry(self):
        reg = describe()
        ids = [p['id'] for p in reg['providers']]
        self.assertEqual(ids[0], 'ollama')          # local group first
        claude = [p for p in reg['providers'] if p['id'] == 'claude'][0]
        self.assertEqual(claude['group'], 'api')
        self.assertIn('Anthropic', claude['privacy'])
        self.assertTrue([f for f in claude['fields'] if f['id'] == 'apikey'][0]['secret'])


class ClaudeAssistantAuditTest(unittest.TestCase):
    def test_usage_logged_and_key_never_logged(self):
        fake = FakeAnthropic([(200, message(), {}), (401, ERR401, {})])
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'ai.log')
            cfg = AIConfig(enabled=True, provider='claude', anonymize=True,
                           options={'base_url': fake.url, 'apikey': KEY, 'model': 'claude-opus-5-5'})
            assistant = Assistant(cfg, audit=AuditLog(log_path))
            try:
                result = assistant.ask(Task('t'), {'host': '192.168.1.20'})
                with self.assertRaises(ProviderError):
                    assistant.ask(Task('t'), {'host': '192.168.1.20'})
            finally:
                fake.close()
            with open(log_path) as fh:
                raw = fh.read()
        records = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(records[0]['usage']['cache_read_input_tokens'], 80)
        self.assertEqual(records[0]['provider'], 'claude')
        self.assertEqual(records[1]['status'], 'error')
        self.assertNotIn(KEY, raw)
        self.assertNotIn('SECRET1234', raw)
        self.assertIn('192.168.1.20', result['text'])   # placeholder restored in the answer


if __name__ == '__main__':
    unittest.main()
