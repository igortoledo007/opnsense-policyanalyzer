"""
Fakes of the per scenario evaluation tests (ai/evaluate.py): a temporary bench database, a firewall hardware
record and measurement documents shaped like bench.summarize_result.  These are UNIT tests on the workstation: nothing
here measures a model, and nothing is written outside a temporary directory (the real history lives only on the
firewall).  The fake answers are in Portuguese on purpose: the evaluation scores answers in Brazilian
Portuguese (evaluate.LANG).
"""

import json
import os
import shutil
import tempfile
import unittest

import ai_helpers  # noqa: F401  (import path)

from ai import bench, eval_fixtures, evaluate

FIREWALL = {'hostname': 'fw-teste', 'os': 'FreeBSD', 'os_release': '14.3', 'cpu': 'Intel(R) N100', 'cores': 4,
            'ram_gib': 31.8, 'ollama_url': 'http://127.0.0.1:11434', 'ollama_version': '0.34.3', 'jail_threads': 2,
            'source': 'firewall'}
WORKSTATION = dict(FIREWALL, hostname='workstation', os='Linux', cpu='Intel(R) Core(TM) i5-4200U', source='outro')

GOOD = {
    'notify-quarantine': 'O endereço 203.0.113.45 foi colocado em quarentena nível 3 por dois dias após 612 tentativas '
                         'de login SSH. Isso indica força bruta contra o firewall. Sugiro revisar se o SSH pela WAN é '
                         'mesmo necessário.',
    'brief-ssh-scan': 'Nos últimos 15 minutos o firewall bloqueou 3.112 conexões, quase todas na WAN, o que parece '
                      'varredura comum da internet. A origem 203.0.113.45 se destaca, insistindo na porta 22 (SSH). '
                      'Nenhum serviço exposto foi alvo além do OpenVPN, e a postura de exposição é B. Sugiro conferir '
                      'se o SSH precisa mesmo responder na WAN.',
}


def doc(fixture_id, text=None, wall=40.0, error=None, tps=6.0, ttft=12.0, fmt_first=True, problems=None, **extra):
    fx = eval_fixtures.get(fixture_id)
    out = {'scenario': fx['scenario'], 'fixture': fixture_id, 'text': GOOD.get(fixture_id, '') if text is None else text,
           'error': error, 'wall_s': wall, 'gen_tps': tps, 'first_token_s': ttft, 'fmt_first_ok': fmt_first,
           'problems_final': problems or [], 'truncated': False, 'attempts': 1, 'load_after': 1.2,
           'models_loaded': [{'name': 'm:1b', 'size_gib': 2.0}], 'timeout': False}
    out.update(extra)
    return out


class EvalCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='pa-eval-test-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.db = evaluate.connect(os.path.join(self.tmp, 'ai-bench.db'))
        self.addCleanup(self.db.close)
        self.saved = {'eval_dir': evaluate.EVAL_DIR, 'tags': evaluate.tags, 'installed': bench.installed_models}
        evaluate.EVAL_DIR = os.path.join(self.tmp, 'ai-eval')
        self.installed = {}
        evaluate.tags = lambda: dict(self.installed)
        bench.installed_models = lambda: list(self.installed)
        self.addCleanup(self.restore)

    def restore(self):
        evaluate.EVAL_DIR = self.saved['eval_dir']
        evaluate.tags = self.saved['tags']
        bench.installed_models = self.saved['installed']

    def plan(self, tokens=('only=m:1b',)):
        pid = bench.create_plan(self.db, 'avaliacao', list(tokens))
        return self.db.execute('SELECT * FROM plans WHERE id = ?', (pid,)).fetchone()

    def evaluation(self, model, docs, hardware=FIREWALL, digest='sha256:abc', plan=None):
        """ an evaluation as the runner would leave it: eval_models + scored runs, then finalize """
        cur = self.db.execute("INSERT INTO eval_models (plan_id, round_id, model, digest, status, started, reps, "
                              "weights, fixtures_version, options, setup, hardware) VALUES (?, NULL, ?, ?, 'running', 1, "
                              "3, ?, ?, '{}', ?, ?)",
                              (plan, model, digest, json.dumps(evaluate.WEIGHTS), eval_fixtures.FIXTURES_VERSION,
                               json.dumps({'model': model, 'ram_gib': 2.0, 'think_mode': 'none', 'hardware': hardware,
                                           'routes': {'short': {'num_ctx': 8192}}}), json.dumps(hardware)))
        eid = cur.lastrowid
        for i, d in enumerate(docs):
            step = {'id': 1000 + i, 'round_id': None, 'model': model, 'scenario': d['scenario'],
                    'params': {'fixture': d['fixture'], 'rep': i + 1}}
            evaluate.record_run(self.db, step, d, eid)
        evaluate.finalize(self.db, eid)
        return eid
