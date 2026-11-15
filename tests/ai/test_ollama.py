import json
import os
import tempfile
import unittest

from ai_helpers import FakeOllama
from ai.providers import ProviderError, get_provider
from ai.providers.ollama import OllamaProvider


MESSAGES = [{'role': 'system', 'content': 'be brief'}, {'role': 'user', 'content': 'hi'}]


class OllamaClientTest(unittest.TestCase):
    def test_health_and_models(self):
        with FakeOllama() as srv:
            provider = get_provider('ollama', {'location': 'lan', 'url': srv.url, 'model': 'llama3.2:3b'})
            self.assertEqual(provider.health()['version'], '0.12.0')
            names = [m['name'] for m in provider.list_models()]
            self.assertEqual(names, ['llama3.2:3b', 'qwen2.5:7b'])
            self.assertEqual(provider.list_models()[0]['parameters'], '3B')

    def test_chat_non_stream(self):
        with FakeOllama(answer='Hello there') as srv:
            provider = OllamaProvider({'location': 'lan', 'url': srv.url + '/', 'model': 'llama3.2:3b'})
            result = provider.chat(MESSAGES)
            self.assertEqual(result.text, 'Hello there')
            self.assertEqual(result.completion_tokens, 5)
            method, path, body = srv.requests[-1]
            self.assertEqual((method, path), ('POST', '/api/chat'))
            self.assertFalse(body['stream'])
            self.assertEqual(body['messages'], MESSAGES)
            self.assertEqual(body['options']['temperature'], 0.2)

    def test_chat_stream(self):
        with FakeOllama(answer='one two three') as srv:
            provider = OllamaProvider({'location': 'lan', 'url': srv.url, 'model': 'm'})
            pieces = []
            result = provider.chat(MESSAGES, stream=True, on_chunk=pieces.append)
            self.assertEqual(result.text, 'one two three')
            self.assertEqual(pieces, ['one ', 'two ', 'three'])
            self.assertEqual(result.done_reason, 'stop')

    def test_http_error_message(self):
        with FakeOllama(status=404) as srv:
            provider = OllamaProvider({'location': 'lan', 'url': srv.url, 'model': 'missing'})
            with self.assertRaises(ProviderError) as ctx:
                provider.chat(MESSAGES)
            self.assertIn('404', str(ctx.exception))
            self.assertIn('not found', str(ctx.exception))

    def test_timeout(self):
        with FakeOllama(delay=2) as srv:
            provider = OllamaProvider({'location': 'lan', 'url': srv.url, 'model': 'm'}, timeout=1)
            with self.assertRaises(ProviderError) as ctx:
                provider.chat(MESSAGES)
            self.assertIn('timeout', str(ctx.exception).lower())

    def test_unreachable(self):
        provider = OllamaProvider({'location': 'lan', 'url': 'http://127.0.0.1:9', 'model': 'm'}, timeout=2)
        with self.assertRaises(ProviderError):
            provider.health()

    def test_redirect_refused(self):
        with FakeOllama(redirect=True) as srv:
            provider = OllamaProvider({'location': 'lan', 'url': srv.url, 'model': 'm'})
            with self.assertRaises(ProviderError) as ctx:
                provider.health()
            self.assertIn('redirect', str(ctx.exception))

    def test_url_validation(self):
        for url in ('ftp://host', 'http://user:pw@host:11434', 'http://host:11434/?x=1', 'host:11434',
                    'http://host:99999'):
            with self.assertRaises(ProviderError, msg=url):
                OllamaProvider({'location': 'lan', 'url': url, 'model': 'm'})

    def test_local_default_and_model_validation(self):
        provider = OllamaProvider({'model': 'bad model;rm'})
        self.assertEqual(provider.endpoint(), 'http://127.0.0.1:11434')
        with self.assertRaises(ProviderError):
            provider.chat(MESSAGES)

    def test_size_cap(self):
        with FakeOllama(answer='x' * 5000) as srv:
            provider = OllamaProvider({'location': 'lan', 'url': srv.url, 'model': 'm'})
            provider.max_response_bytes = 1000
            with self.assertRaises(ProviderError):
                provider.chat(MESSAGES)

    def test_local_runtime_limits_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            limits = os.path.join(tmp, 'runtime-limits.json')
            with open(limits, 'w') as fh:
                json.dump({'threads': 2, 'ctx': 8192, 'cpus': '2-3'}, fh)
            local = OllamaProvider({'location': 'local', 'model': 'm', 'limits_file': limits})
            lan = OllamaProvider({'location': 'lan', 'url': 'http://192.168.1.5:11434', 'model': 'm',
                                  'limits_file': limits})
        self.assertEqual(local.endpoint(), 'http://127.0.0.1:11434')
        opts = local._payload(MESSAGES, False)['options']
        self.assertEqual((opts['num_thread'], opts['num_ctx']), (2, 8192))
        self.assertNotIn('num_thread', lan._payload(MESSAGES, False)['options'])

    def test_location_and_legacy_mode(self):
        self.assertEqual(OllamaProvider({'mode': 'network', 'url': 'http://10.1.1.1:11434'}).endpoint(),
                         'http://10.1.1.1:11434')
        self.assertEqual(OllamaProvider({'location': 'local', 'url': 'http://10.1.1.1:11434'}).endpoint(),
                         'http://127.0.0.1:11434')

    def test_unknown_provider(self):
        with self.assertRaises(ProviderError):
            get_provider('nope', {})


if __name__ == '__main__':
    unittest.main()
