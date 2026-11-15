"""
import_gguf: local GGUF file (scp to /var/db/ai/models/import/) or Hugging Face download, Modelfile with the chat
template, "ollama create" inside the jail, revert with "ollama rm". Fake system and fake HTTP: no network.
"""

import hashlib
import json
import os
import unittest
from unittest import mock

from setup_helpers import FakeHttp, SetupTestCase, _Resp, common

from setup import actions, gguf

WEIGHTS = b'GGUF' + b'\x03\x00\x00\x00' + b'weights ' * 4000
SHA = hashlib.sha256(WEIGHTS).hexdigest()
COMMIT = 'a' * 40
REPO = 'fdtn-ai/Foundation-Sec-8B-Instruct-Q4_K_M-GGUF'
FILE = 'foundation-sec-8b-instruct-q4_k_m.gguf'


class HfHttp(FakeHttp):
    def __init__(self, system, sha=SHA):
        super().__init__(system)
        self.sha = sha

    def open(self, url, data=None, headers=None, timeout=30, method=None):
        if url.startswith('https://huggingface.co/'):
            self._check(url)
            self.requests.append(('GET', url))
            if '/api/models/' in url:
                return _Resp(json.dumps({'sha': COMMIT, 'siblings': [
                    {'rfilename': 'README.md'},
                    {'rfilename': FILE, 'size': len(WEIGHTS), 'lfs': {'sha256': self.sha, 'size': len(WEIGHTS)}}]}
                ).encode())
            if '/resolve/%s/' % COMMIT in url:
                return _Resp(WEIGHTS)
        return super().open(url, data, headers, timeout, method)


class TestImportGguf(SetupTestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(gguf, 'MIN_BYTES', 1024)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.assertEqual(actions.apply('install_runtime', {}, self.ctx)['status'], 'ok')
        self.import_dir = self.root + '/var/db/ai/models/import'

    def copy_file(self, name=FILE, data=WEIGHTS):
        os.makedirs(self.import_dir, exist_ok=True)
        with open(os.path.join(self.import_dir, name), 'wb') as handle:
            handle.write(data)

    def args(self, **kw):
        tokens = [FILE, 'foundation-sec:8b', 'sha256=' + SHA] + ['%s=%s' % kv for kv in kw.items()]
        return actions.parse_cli_args('import_gguf', tokens)

    def test_cli_tokens(self):
        args = actions.parse_cli_args('import_gguf', ['hf:%s/%s@main' % (REPO, FILE), 'foundation-sec:8b',
                                                      'template=llama3', '+cleanup'])
        self.assertEqual(args, {'source': 'hf:%s/%s@main' % (REPO, FILE), 'name': 'foundation-sec:8b',
                                'template': 'llama3', 'cleanup': 'yes'})

    def test_plan_local_file(self):
        self.copy_file()
        plan = actions.plan('import_gguf', self.args(), self.ctx)
        self.assertEqual(plan['status'], 'ok', plan)
        types = [s['type'] for s in plan['steps']]
        self.assertEqual(types, ['gguf_verify', 'write_file', 'run', 'wait_http'])
        mf = plan['steps'][1]['content']
        self.assertIn('FROM /var/lib/ollama/models/import/%s' % FILE, mf)
        self.assertIn('<|start_header_id|>', mf)
        self.assertIn('PARAMETER stop "<|eot_id|>"', mf)
        run = plan['steps'][2]
        self.assertEqual(run['argv'][:2], ['/usr/sbin/jexec', 'ollama'])
        self.assertEqual(run['argv'][-4:], ['create', 'foundation-sec:8b', '-f',
                                            '/var/lib/ollama/models/import/foundation-sec-8b.Modelfile'])
        self.assertEqual(run['undo_argv'][-2:], ['rm', 'foundation-sec:8b'])
        self.assertTrue(plan['background'])
        self.assertEqual(self.system.writes()[-1:], self.system.writes()[-1:])     # plan wrote nothing new
        self.assertFalse(os.path.exists(os.path.join(self.import_dir, 'foundation-sec-8b.Modelfile')))
        chatml = actions.plan('import_gguf', self.args(template='chatml'), self.ctx)
        self.assertIn('<|im_start|>', chatml['steps'][1]['content'])
        embedded = actions.plan('import_gguf', self.args(template='gguf'), self.ctx)
        self.assertNotIn('TEMPLATE', embedded['steps'][1]['content'])
        self.assertTrue(embedded['warnings'])

    def test_plan_errors(self):
        res = actions.plan('import_gguf', self.args(), self.ctx)
        self.assertEqual(res['status'], 'blocked')                  # no import dir / no file
        self.copy_file(data=b'NOTGGUF' + WEIGHTS)
        self.assertIn('magic', json.dumps(actions.plan('import_gguf', self.args(), self.ctx)))
        for bad in (['x.bin', 'a:b', 'sha256=' + SHA], [FILE, 'Bad Name', 'sha256=' + SHA], [FILE, 'a:b'],
                    [FILE, 'a:b', 'sha256=zz'], [FILE, 'a:b', 'sha256=' + SHA, 'template=alpaca'],
                    ['../../etc/passwd.gguf', 'a:b', 'sha256=' + SHA]):
            try:
                args = actions.parse_cli_args('import_gguf', bad)
            except ValueError:
                continue
            self.assertEqual(actions.plan('import_gguf', args, self.ctx)['status'], 'error', bad)
        # runtime stopped: ollama create needs it
        self.copy_file()
        self.system.running = False
        self.assertIn('not running', json.dumps(actions.plan('import_gguf', self.args(), self.ctx)))

    def test_apply_and_revert(self):
        self.copy_file()
        res = actions.apply('import_gguf', self.args(), self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        modelfile = os.path.join(self.import_dir, 'foundation-sec-8b.Modelfile')
        self.assertTrue(os.path.isfile(modelfile))
        creates = [c for c in self.system.calls if c[0] == '/usr/sbin/jexec' and 'create' in c]
        self.assertEqual(len(creates), 1)
        self.assertIn('OLLAMA_HOST=127.0.0.1:11434', creates[0])
        rev = actions.revert_apply(res['journal'], {}, self.ctx)
        self.assertEqual(rev['status'], 'ok', rev)
        self.assertTrue(any(c[0] == '/usr/sbin/jexec' and c[-2:] == ['rm', 'foundation-sec:8b']
                            for c in self.system.calls))
        self.assertFalse(os.path.exists(modelfile))
        self.assertTrue(os.path.isfile(os.path.join(self.import_dir, FILE)))     # the admin's copy is kept

    def test_wrong_sha_fails_before_create(self):
        self.copy_file()
        args = actions.parse_cli_args('import_gguf', [FILE, 'foundation-sec:8b', 'sha256=' + 'b' * 64])
        res = actions.apply('import_gguf', args, self.ctx)
        self.assertEqual(res['status'], 'failed')
        self.assertIn('SHA-256 mismatch', res['message'])
        self.assertFalse([c for c in self.system.calls if 'create' in c and c[0] == '/usr/sbin/jexec'])

    def test_cleanup_is_irreversible(self):
        self.copy_file()
        args = self.args()
        args['cleanup'] = 'yes'
        plan = actions.plan('import_gguf', args, self.ctx)
        self.assertTrue(plan['irreversible'])
        res = actions.apply('import_gguf', args, self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        self.assertFalse(os.path.exists(os.path.join(self.import_dir, FILE)))

    def test_huggingface(self):
        self.http = HfHttp(self.system)
        self.ctx = self.make_ctx()
        args = actions.parse_cli_args('import_gguf', ['hf:%s/%s' % (REPO, FILE), 'foundation-sec:8b'])
        plan = actions.plan('import_gguf', args, self.ctx)
        self.assertEqual(plan['status'], 'ok', plan)
        self.assertEqual([s['type'] for s in plan['steps']][:2], ['mkdir', 'hf_download'])
        self.assertIn('/resolve/%s/%s' % (COMMIT, FILE), plan['steps'][1]['url'])
        self.assertEqual(plan['download_bytes'], len(WEIGHTS))
        res = actions.apply('import_gguf', args, self.ctx)
        self.assertEqual(res['status'], 'ok', res)
        with open(os.path.join(self.import_dir, FILE), 'rb') as handle:
            self.assertEqual(handle.read(), WEIGHTS)
        rev = actions.revert_apply(res['journal'], {}, self.ctx)
        self.assertEqual(rev['status'], 'ok', rev)
        self.assertFalse(os.path.exists(os.path.join(self.import_dir, FILE)))   # downloaded: removed
        # a SHA-256 that disagrees with the one published is refused in the plan
        bad = actions.parse_cli_args('import_gguf', ['hf:%s/%s' % (REPO, FILE), 'foundation-sec:8b',
                                                     'sha256=' + 'c' * 64])
        self.assertIn('does not match', json.dumps(actions.plan('import_gguf', bad, self.ctx)))

    def test_hf_allowlist_is_narrow(self):
        http = common.Http()
        http._check('https://huggingface.co/api/models/%s/revision/main?blobs=true' % REPO)
        http._check('https://huggingface.co/%s/resolve/%s/%s' % (REPO, COMMIT, FILE))
        for url in ('https://huggingface.co/%s/resolve/main/%s' % (REPO, FILE),          # branch, not a commit
                    'https://huggingface.co/%s/resolve/%s/model.safetensors' % (REPO, COMMIT),
                    'https://huggingface.co/login', 'http://huggingface.co/api/models/a/b/revision/main?blobs=true',
                    'https://huggingface.co.evil.example/api/models/a/b/revision/main?blobs=true'):
            with self.assertRaises(common.SetupError, msg=url):
                http._check(url)
        self.assertTrue(common.HF_REDIRECT_RE.match('https://cdn-lfs-us-1.hf.co/repos/x'))
        self.assertTrue(common.HF_REDIRECT_RE.match('https://cas-bridge.xethub.hf.co/xet-bridge-us/x'))
        self.assertFalse(common.HF_REDIRECT_RE.match('https://evil.example/hf.co/'))
        self.assertFalse(common.HF_REDIRECT_RE.match('http://cdn-lfs.hf.co/x'))
        handler = common._HfRedirect()
        with self.assertRaises(common.SetupError):
            handler.redirect_request(None, None, 302, 'Found', {}, 'https://evil.example/x')


if __name__ == '__main__':
    unittest.main()
