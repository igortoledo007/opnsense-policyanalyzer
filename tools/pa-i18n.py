#!/usr/bin/env python3
# Copyright (C) 2026 Igor Toledo <contato@igor.eti.br>
# BSD 2-Clause License.
"""
Translations of the Policy Analyzer GUI (its own gettext domain "PolicyAnalyzer").

  extract   policy-analyzer/i18n/PolicyAnalyzer.pot from lang._('...') / gettext('...') in PHP and Volt,
            <label>/<help> of the forms, VisibleName of the menu and OptionValues of the model
  update    create or merge policy-analyzer/i18n/<lang>.po for every OPNsense language (msginit/msgmerge)
  check     every .po: placeholders (%s %d %1$s {name}), HTML tags and trailing newlines match the msgid
  compile   plugin/src/share/locale/<lang>/LC_MESSAGES/PolicyAnalyzer.mo (installed under /usr/local/share/locale)
  stats     translated / fuzzy / empty per language
"""
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PA = ROOT
SRC = os.path.join(PA, 'plugin', 'src', 'opnsense')
I18N = os.path.join(PA, 'i18n')
POT = os.path.join(I18N, 'PolicyAnalyzer.pot')
LOCALE_OUT = os.path.join(PA, 'plugin', 'src', 'share', 'locale')
DOMAIN = 'PolicyAnalyzer'
LANGS = ['cs_CZ', 'de_DE', 'el_GR', 'es_ES', 'fa_IR', 'fr_FR', 'it_IT', 'ja_JP', 'ko_KR', 'no_NO', 'pl_PL',
         'pt_BR', 'pt_PT', 'ru_RU', 'tr_TR', 'uk_UA', 'vi_VN', 'zh_CN', 'zh_TW']

CALL = re.compile(r"""(?:lang\._|\bgettext|L10n::t)\(\s*'((?:[^'\\]|\\.)*)'""", re.S)
PLACEHOLDER = re.compile(r'%(?:\d+\$)?[-+0#]*\d*(?:\.\d+)?[a-zA-Z%]|\{[A-Za-z0-9_]+\}')
TAG = re.compile(r'</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>')


def unescape(s):
    return s.replace("\\'", "'").replace('\\\\', '\\')


def po_quote(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t') + '"'


def extract():
    found = {}   # msgid -> [refs]
    for base, _, files in os.walk(SRC):
        for name in sorted(files):
            full = os.path.join(base, name)
            rel = os.path.relpath(full, SRC)
            if name.endswith(('.php', '.volt')):
                text = open(full, encoding='utf-8').read()
                for m in CALL.finditer(text):
                    line = text.count('\n', 0, m.start()) + 1
                    found.setdefault(unescape(m.group(1)), []).append('%s:%d' % (rel, line))
            elif name.endswith('.xml'):
                try:
                    tree = ET.parse(full)
                except ET.ParseError:
                    continue
                for el in tree.iter():
                    texts = []
                    if el.tag in ('label', 'help', 'hint') and el.text and el.text.strip():
                        texts.append(el.text.strip())
                    if el.get('VisibleName'):
                        texts.append(el.get('VisibleName'))
                    if el.tag == 'OptionValues':
                        texts += [c.text.strip() for c in el if c.text and c.text.strip()]
                    for t in texts:
                        found.setdefault(t, []).append(rel)
    found.pop('', None)
    os.makedirs(I18N, exist_ok=True)
    with open(POT, 'w', encoding='utf-8') as out:
        out.write('msgid ""\nmsgstr ""\n"Project-Id-Version: os-policyanalyzer\\n"\n'
                  '"Content-Type: text/plain; charset=UTF-8\\n"\n"Content-Transfer-Encoding: 8bit\\n"\n\n')
        for msgid in sorted(found):
            refs = sorted(set(found[msgid]))[:4]
            out.write('#: %s\n' % ' '.join(refs))
            if PLACEHOLDER.search(msgid) and '%' in msgid:
                out.write('#, php-format\n')
            out.write('msgid %s\nmsgstr ""\n\n' % po_quote(msgid))
    print('ok: %d strings in %s' % (len(found), POT))


def update():
    for lang in LANGS:
        po = os.path.join(I18N, lang + '.po')
        if os.path.exists(po):
            subprocess.run(['msgmerge', '-q', '--no-fuzzy-matching', '-U', '--backup=none', po, POT], check=True)
        else:
            subprocess.run(['msginit', '--no-translator', '-l', lang + '.UTF-8', '-i', POT, '-o', po], check=True,
                           stderr=subprocess.DEVNULL)
    print('ok: %d .po files in %s' % (len(LANGS), I18N))


def parse_po(path):
    """ minimal reader: [(msgid, msgstr, fuzzy)] (no plurals in this domain) """
    entries, cur, fuzzy, field = [], {}, False, None
    def flush():
        if 'msgid' in cur and cur['msgid']:
            entries.append((cur['msgid'], cur.get('msgstr', ''), fuzzy))
    for raw in open(path, encoding='utf-8'):
        line = raw.strip()
        if line.startswith('#,') and 'fuzzy' in line:
            fuzzy = True
        elif line.startswith('msgid '):
            flush(); cur, field = {'msgid': ''}, 'msgid'
            cur['msgid'] = eval(line[6:])
        elif line.startswith('msgstr '):
            field = 'msgstr'; cur['msgstr'] = eval(line[7:])
        elif line.startswith('"') and field:
            cur[field] += eval(line)
        elif not line:
            flush(); cur, field, fuzzy = {}, None, False
    flush()
    return entries


def check():
    bad = 0
    for lang in LANGS:
        po = os.path.join(I18N, lang + '.po')
        if not os.path.exists(po):
            continue
        for msgid, msgstr, _ in parse_po(po):
            if not msgstr:
                continue
            problems = []
            if sorted(PLACEHOLDER.findall(msgid)) != sorted(PLACEHOLDER.findall(msgstr)):
                problems.append('placeholders')
            if sorted(TAG.findall(msgid)) != sorted(TAG.findall(msgstr)):
                problems.append('html tags')
            if msgid.endswith('\n') != msgstr.endswith('\n'):
                problems.append('trailing newline')
            if problems:
                bad += 1
                print('%s: %s: %r' % (lang, ', '.join(problems), msgid[:70]))
        r = subprocess.run(['msgfmt', '--check-format', '-o', os.devnull, po], capture_output=True, text=True)
        if r.returncode:
            bad += 1
            print('%s: msgfmt: %s' % (lang, r.stderr.strip()[:300]))
    print('ok' if not bad else '%d problems' % bad)
    return bad


def compile_mo():
    n = 0
    for lang in LANGS:
        po = os.path.join(I18N, lang + '.po')
        if not os.path.exists(po):
            continue
        out = os.path.join(LOCALE_OUT, lang, 'LC_MESSAGES', DOMAIN + '.mo')
        os.makedirs(os.path.dirname(out), exist_ok=True)
        subprocess.run(['msgfmt', '--check-format', '-o', out, po], check=True)
        n += 1
    print('ok: %d .mo files under %s' % (n, LOCALE_OUT))


def stats():
    for lang in LANGS:
        po = os.path.join(I18N, lang + '.po')
        if not os.path.exists(po):
            print('%s: missing' % lang)
            continue
        e = parse_po(po)
        done = sum(1 for _, s, f in e if s and not f)
        print('%s: %d/%d translated, %d fuzzy' % (lang, done, len(e), sum(1 for _, s, f in e if f)))


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    funcs = {'extract': extract, 'update': update, 'check': check, 'compile': compile_mo, 'stats': stats}
    if cmd not in funcs:
        print(__doc__)
        sys.exit(2)
    sys.exit(1 if funcs[cmd]() else 0)
