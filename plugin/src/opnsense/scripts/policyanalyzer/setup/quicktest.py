#!/usr/local/bin/python3

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

    Quick test of the local AI (setup step 7): one real, short question with
    today's date and a random topic, sent straight to the Ollama of the jail
    (127.0.0.1:11434), in the language of the AI settings (English by default,
    Portuguese when ai.language or the GUI language is pt_*).  Read only:
    nothing is written; prints JSON.

        quicktest.py <model> [language]
"""

import json
import os
import random
import sys
import time

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from setup import common                          # noqa: E402

# the prompt in the language of the AI settings (ai.language; "auto" follows the GUI language of config.xml)
PROMPTS = {
    'en': {
        'months': ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October',
                   'November', 'December'],
        'weekdays': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
        'topics': [
            'a well known historical fact that happened on a {month} {day}',
            'an astronomy curiosity to watch in the sky in {month}',
            'a curiosity about computer networks or the internet',
            'a quick network security tip for a home firewall',
            'a curiosity about the history of FreeBSD or Unix',
            'a curiosity about nature or animals',
            'a mathematics curiosity that fits in two sentences',
            'a suggestion of something simple and healthy to do this {weekday}',
            'a curiosity about the origin of an English word',
            'a curiosity about cryptography',
        ],
        'prompt': 'Today is %(weekday)s, %(month)s %(day)d, %(year)d. Answer in English, in at most three short '
                  'sentences, without lists: tell %(topic)s. If you are not sure about a fact, say so.',
    },
    # Portuguese (Brazil) variant, used when the AI language (or the GUI language) is pt_*
    'pt': {
        'months': ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro',
                   'outubro', 'novembro', 'dezembro'],
        'weekdays': ['segunda-feira', 'terça-feira', 'quarta-feira', 'quinta-feira', 'sexta-feira', 'sábado',
                     'domingo'],
        'topics': [
            'um fato histórico conhecido que aconteceu num dia {day} de {month}',
            'uma curiosidade de astronomia para observar no céu em {month}',
            'uma curiosidade sobre redes de computadores ou a internet',
            'uma dica rápida de segurança de rede para um firewall doméstico',
            'uma curiosidade sobre a história do FreeBSD ou do Unix',
            'uma curiosidade sobre a natureza ou os animais do Brasil',
            'uma curiosidade de matemática que caiba em duas frases',
            'uma sugestão de algo simples e saudável para fazer nesta {weekday}',
            'uma curiosidade sobre a origem de uma palavra da língua portuguesa',
            'uma curiosidade sobre criptografia',
        ],
        'prompt': 'Hoje é %(weekday)s, %(day)d de %(month)s de %(year)d. Responda em português do Brasil, em no '
                  'máximo três frases curtas, sem listas: conte %(topic)s. Se não tiver certeza de um fato, diga isso.',
    },
}
# compatibility aliases (English is the default)
MONTHS = PROMPTS['en']['months']
WEEKDAYS = PROMPTS['en']['weekdays']
TOPICS = PROMPTS['en']['topics']


def quicktest_language(config_xml=None):
    """ ai.language of the settings; "auto" (or unreadable) follows system/language of config.xml, else en_US """
    path = config_xml or os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')
    try:
        from ai.config import AIConfig
        choice = AIConfig.from_opnsense('OPNsense/policyanalyzer', path=path).language
        if choice and choice != 'auto':
            return choice
    except Exception:                               # noqa: BLE001
        pass
    try:
        import xml.etree.ElementTree as ET
        return (ET.parse(path).getroot().findtext('./system/language') or '').strip() or 'en_US'
    except Exception:                               # noqa: BLE001
        return 'en_US'


def build_prompt(now, rng, language='en_US'):
    t = PROMPTS['pt' if str(language or '').startswith('pt') else 'en']
    day, month, weekday = now.tm_mday, t['months'][now.tm_mon - 1], t['weekdays'][now.tm_wday]
    topic = rng.choice(t['topics']).format(day=day, month=month, weekday=weekday)
    prompt = t['prompt'] % {'weekday': weekday, 'day': day, 'month': month, 'year': now.tm_year, 'topic': topic}
    return topic, prompt


def quicktest_route():
    """ the per scenario settings of "quicktest" (ai/scenarios.py), {} when absent or unreadable """
    try:
        from ai import scenarios
        return scenarios.load_routing().get('scenarios', {}).get('quicktest') or {}
    except Exception:                               # noqa: BLE001
        return {}


def main(argv, ctx=None, rng=None, now=None):
    ctx = ctx or common.Context()
    rng = rng or random.SystemRandom()
    now = now or time.localtime()
    if len(argv) < 1:
        return {'status': 'error', 'message': 'usage: quicktest.py <model>'}
    try:
        base, tag = common.validate_model(argv[0])
    except ValueError as exc:
        return {'status': 'error', 'message': str(exc)}
    model = '%s:%s' % (base, tag)
    threads = 2
    try:
        from setup.runtime import current_limits
        threads = int(current_limits(ctx).get('threads') or threads)
    except Exception:                               # noqa: BLE001
        pass
    language = argv[1] if len(argv) > 1 else quicktest_language()
    topic, prompt = build_prompt(now, rng, language)
    body = {'model': model, 'prompt': prompt, 'stream': False, 'think': False,
            'options': {'num_thread': threads, 'num_ctx': 2048, 'num_predict': 160, 'temperature': 0.8}}
    timeout = 300
    route = quicktest_route()
    if route:
        # scenario "quicktest" of the AI routing: timeout, keep_alive and num_ctx (same num_ctx = no reload)
        timeout = int(route.get('timeout') or timeout)
        if route.get('keep_alive'):
            body['keep_alive'] = route['keep_alive']
        if route.get('num_ctx'):
            body['options']['num_ctx'] = int(route['num_ctx'])
    started = time.time()
    try:
        result = ctx.http.get_json(common.OLLAMA_URL + '/api/generate', timeout=timeout, body=body) or {}
    except Exception as exc:                        # noqa: BLE001
        return {'status': 'error', 'model': model, 'topic': topic, 'prompt': prompt,
                'message': 'the local AI did not answer: %s' % exc}
    wall = time.time() - started
    ns = 1e9
    count, duration = result.get('eval_count'), result.get('eval_duration')
    return {'status': 'ok', 'model': model, 'topic': topic, 'prompt': prompt,
            'answer': (result.get('response') or '').strip(),
            'wall_seconds': round(wall, 1),
            'load_seconds': round((result.get('load_duration') or 0) / ns, 1),
            'tokens': count, 'tokens_per_second': round(count / (duration / ns), 1) if count and duration else None}


if __name__ == '__main__':
    print(json.dumps(main(sys.argv[1:]), ensure_ascii=False))
