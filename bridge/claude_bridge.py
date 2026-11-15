#!/usr/bin/env python3
"""
claude-bridge: small HTTP bridge on a LAN computer so the OPNsense Policy Analyzer plugin ("Claude Code (LAN)"
provider) can use the Claude Code subscription of the owner of this computer.

Safety model
- Claude Code runs in print mode with ALL tools disabled (--tools ""), no MCP servers, no settings/hooks of the
  user (--setting-sources ""), no session persistence, from an empty working directory: it can only return text.
  Data sent by the firewall (already anonymized there) can not make it run commands or read files.
- Only the allowed source addresses (the firewall) and a bearer token are accepted; one request runs at a time,
  a small queue, body limit 256 KiB, timeout per request.

Protocol (see README.md):
  GET  /health      -> {"status":"ok","service":"claude-bridge","version":"1","claude_version":...,"models":[...],
                        "default_model":"sonnet","busy":false}
  POST /v1/chat     {"model":"sonnet","messages":[{"role":"system|user|assistant","content":"..."}],"timeout":300}
                    -> {"status":"ok","text":"...","model":"sonnet","duration_ms":...,"usage":{...}}
Errors: {"status":"error","message":...} (401 token, 403 source, 413 body, 429 {"status":"busy"} queue full).

Configuration: ~/.config/claude-bridge/config.json (created on first run) and ~/.config/claude-bridge/token (0600).
"""

import hmac
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = '1'
CONF_DIR = os.path.expanduser('~/.config/claude-bridge')
CONF_FILE = os.path.join(CONF_DIR, 'config.json')
TOKEN_FILE = os.path.join(CONF_DIR, 'token')
MODELS = ['fable', 'opus', 'sonnet', 'haiku']
MAX_BODY = 256 * 1024
DEFAULTS = {
    'listen': '0.0.0.0',
    'port': 11436,
    # the firewall (LAN address of the node and the CARP address) and this computer
    'allow': ['192.168.10.10/32', '192.168.10.11/32', '192.168.10.1/32', '127.0.0.1/32'],
    'default_model': 'sonnet',
    'max_queue': 2,
    'timeout': 300,
    'claude': shutil.which('claude') or '/opt/bin/claude',
}


def log(msg):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), msg, flush=True)


def load_config():
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    conf = dict(DEFAULTS)
    if os.path.isfile(CONF_FILE):
        with open(CONF_FILE) as fh:
            conf.update(json.load(fh))
    else:
        with open(CONF_FILE, 'w') as fh:
            json.dump(DEFAULTS, fh, indent=2)
    if not os.path.isfile(TOKEN_FILE):
        fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as fh:
            fh.write(secrets.token_urlsafe(32) + '\n')
    os.chmod(TOKEN_FILE, 0o600)
    with open(TOKEN_FILE) as fh:
        conf['token'] = fh.read().strip()
    conf['allow_nets'] = [ipaddress.ip_network(n, strict=False) for n in conf['allow']]
    return conf


CONF = None
SLOT = threading.Lock()            # one Claude Code run at a time
WAITING = {'n': 0}
WAIT_LOCK = threading.Lock()
CLAUDE_VERSION = {'v': None}


def claude_version():
    if CLAUDE_VERSION['v'] is None:
        try:
            out = subprocess.run([CONF['claude'], '--version'], capture_output=True, text=True, timeout=20)
            CLAUDE_VERSION['v'] = out.stdout.strip() or None
        except Exception:                   # noqa: BLE001
            CLAUDE_VERSION['v'] = None
    return CLAUDE_VERSION['v']


def run_claude(model, messages, timeout):
    system = '\n\n'.join(m['content'] for m in messages if m.get('role') == 'system') or \
        'You explain firewall findings. Answer with text only.'
    parts = []
    for m in messages:
        if m.get('role') == 'user':
            parts.append(m['content'])
        elif m.get('role') == 'assistant':
            parts.append('[previous answer]\n' + m['content'])
    prompt = '\n\n'.join(parts)
    argv = [CONF['claude'], '-p', '--output-format', 'json', '--tools', '', '--strict-mcp-config',
            '--no-session-persistence', '--setting-sources', '', '--model', model, '--system-prompt', system]
    with tempfile.TemporaryDirectory(prefix='claude-bridge-') as cwd:
        started = time.time()
        out = subprocess.run(argv, input=prompt, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        took = int((time.time() - started) * 1000)
    try:
        data = json.loads(out.stdout)
    except ValueError:
        raise RuntimeError('claude did not return JSON (exit %s): %s' % (out.returncode, (out.stderr or out.stdout)[-300:]))
    if data.get('is_error'):
        raise RuntimeError(str(data.get('result') or data.get('subtype') or 'claude error')[:500])
    usage = data.get('usage') or {}
    return {'status': 'ok', 'text': (data.get('result') or '').strip(), 'model': model, 'duration_ms': took,
            'usage': {'input_tokens': usage.get('input_tokens'), 'output_tokens': usage.get('output_tokens')}}


class Handler(BaseHTTPRequestHandler):
    server_version = 'claude-bridge/' + VERSION
    sys_version = ''

    def log_message(self, fmt, *args):
        log('%s %s' % (self.client_address[0], fmt % args))

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check(self):
        try:
            src = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            src = None
        if src is None or not any(src in n for n in CONF['allow_nets']):
            self._send(403, {'status': 'error', 'message': 'source address not allowed'})
            return False
        auth = self.headers.get('Authorization', '')
        token = auth[7:].strip() if auth.startswith('Bearer ') else ''
        if not token or not hmac.compare_digest(token, CONF['token']):
            self._send(401, {'status': 'error', 'message': 'unauthorized'})
            return False
        return True

    def do_GET(self):
        if self.path.split('?')[0] != '/health':
            return self._send(404, {'status': 'error', 'message': 'not found'})
        if not self._check():
            return None
        return self._send(200, {'status': 'ok', 'service': 'claude-bridge', 'version': VERSION,
                                'claude_version': claude_version(), 'models': MODELS,
                                'default_model': CONF['default_model'], 'busy': SLOT.locked()})

    def do_POST(self):
        if self.path.split('?')[0] != '/v1/chat':
            return self._send(404, {'status': 'error', 'message': 'not found'})
        if not self._check():
            return None
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0 or length > MAX_BODY:
            return self._send(413, {'status': 'error', 'message': 'body missing or larger than 256 KiB'})
        try:
            req = json.loads(self.rfile.read(length))
            messages = req.get('messages')
            if not isinstance(messages, list) or not messages or not all(
                    isinstance(m, dict) and m.get('role') in ('system', 'user', 'assistant')
                    and isinstance(m.get('content'), str) for m in messages):
                raise ValueError('messages must be a list of {role, content}')
            model = req.get('model') or CONF['default_model']
            if model not in MODELS:
                raise ValueError('model must be one of %s' % ', '.join(MODELS))
            timeout = max(10, min(int(req.get('timeout') or CONF['timeout']), 600))
        except (ValueError, TypeError) as exc:
            return self._send(400, {'status': 'error', 'message': str(exc)})
        with WAIT_LOCK:
            if WAITING['n'] >= CONF['max_queue'] + 1:
                return self._send(429, {'status': 'busy', 'message': 'queue full'})
            WAITING['n'] += 1
        try:
            with SLOT:
                result = run_claude(model, messages, timeout)
            log('chat ok model=%s %d ms' % (model, result['duration_ms']))
            return self._send(200, result)
        except subprocess.TimeoutExpired:
            return self._send(504, {'status': 'error', 'message': 'claude did not answer within %d s' % timeout})
        except Exception as exc:            # noqa: BLE001
            log('chat error: %s' % exc)
            return self._send(502, {'status': 'error', 'message': str(exc)[:500]})
        finally:
            with WAIT_LOCK:
                WAITING['n'] -= 1


def main():
    global CONF
    CONF = load_config()
    if len(sys.argv) > 1 and sys.argv[1] == 'token-path':
        print(TOKEN_FILE)
        return
    httpd = ThreadingHTTPServer((CONF['listen'], int(CONF['port'])), Handler)
    log('claude-bridge %s listening on %s:%s, allowed %s, claude %s' % (
        VERSION, CONF['listen'], CONF['port'], ','.join(CONF['allow']), claude_version()))
    httpd.serve_forever()


if __name__ == '__main__':
    main()
