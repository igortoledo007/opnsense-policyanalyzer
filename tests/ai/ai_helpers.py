"""
Shared helpers for the AI layer tests: import path and a fake Ollama server.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
SCRIPTS = os.path.join(ROOT, 'plugin', 'src', 'opnsense', 'scripts', 'policyanalyzer')
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)


class FakeOllama:
    """ minimal Ollama look-alike on 127.0.0.1:<random port> """

    def __init__(self, answer='ok', models=('llama3.2:3b', 'qwen2.5:7b'), delay=0.0, status=200, redirect=False,
                 show=None):
        self.answer = answer
        self.show = show                # /api/show document (None: answered like a chat, as before)
        self.models = list(models)
        self.delay = delay
        self.status = status
        self.redirect = redirect
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body, ctype='application/json'):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                fake.requests.append(('GET', self.path, None))
                if fake.redirect:
                    self.send_response(302)
                    self.send_header('Location', 'http://example.invalid/steal')
                    self.end_headers()
                elif self.path == '/api/version':
                    self._send(200, {'version': '0.12.0'})
                elif self.path == '/api/tags':
                    self._send(200, {'models': [
                        {'name': m, 'size': 123, 'modified_at': '2026-11-01T00:00:00Z',
                         'details': {'family': 'llama', 'parameter_size': '3B', 'quantization_level': 'Q4_K_M'}}
                        for m in fake.models
                    ]})
                else:
                    self._send(404, {'error': 'not found'})

            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(length) or b'{}')
                fake.requests.append(('POST', self.path, body))
                if self.path == '/api/show' and fake.show is not None:
                    self._send(200, fake.show)
                    return
                if fake.delay:
                    import time
                    time.sleep(fake.delay)
                if fake.status != 200:
                    self._send(fake.status, {'error': 'model "%s" not found' % body.get('model')})
                    return
                answer = fake.answer(body) if callable(fake.answer) else fake.answer
                if body.get('stream'):
                    words = answer.split(' ')
                    lines = []
                    for idx, word in enumerate(words):
                        piece = word + (' ' if idx < len(words) - 1 else '')
                        lines.append(json.dumps({'model': body['model'], 'message': {'role': 'assistant',
                                                 'content': piece}, 'done': False}))
                    lines.append(json.dumps({'model': body['model'], 'done': True, 'done_reason': 'stop',
                                             'prompt_eval_count': 10, 'eval_count': len(words)}))
                    self._send(200, ('\n'.join(lines) + '\n').encode(), 'application/x-ndjson')
                else:
                    self._send(200, {'model': body['model'], 'message': {'role': 'assistant', 'content': answer},
                                     'done': True, 'done_reason': 'stop', 'prompt_eval_count': 10, 'eval_count': 5})

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
