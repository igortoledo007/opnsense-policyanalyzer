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

    Catalogs of the texts of the reports (e-mail HTML / text, PDF, charts, executive summary fallback, AI
    evaluation PDFs, e-mails and markdown): one UTF-8 JSON per language next to this file, <language>.json,
    with the same sections and keys as en_US.json (the reference).  The 20 languages of OPNsense are listed in
    LANGUAGES; en_US and pt_BR are complete, the others are filled by translators (a missing key falls back,
    key by key, to the "_meta.fallback" language of the catalog and then to en_US).

      normalize(language)        'pt' -> 'pt_BR', 'pt-pt' -> 'pt_PT', 'auto' / '' / unknown -> 'en_US'
      catalog(language)          the merged catalog (dict, cached; do not change it)
      section(language, name)    one section, e.g. section('pt_BR', 'report')['title']
      text(language, 'a.b.c')    one string by dotted path
      fmt_number(value, language, decimals)   31877.5 -> '31,877.5' (en_US) / '31.877,5' (pt_BR)
      fmt_date(ts, language)     local time with format.datetime of the catalog
      resolve(choice, config)    'auto' -> system/language of config.xml (the GUI language), else normalize
      missing(language)          dotted keys of en_US the catalog of <language> does not have (for translators)
      pdf_language(language, can_render, sections)   <language>, or en_US when pdf.py cannot draw its script

    Placeholders are Python %-format (%s, %d, %.0f, %%): a translation keeps the same placeholders in the same
    order (tests/reports/test_i18n.py checks it).  Section "format": number and date formats of the language,
    "pdf_complex_script" true for scripts pdf.py cannot shape (Persian: right to left + joining), whose PDFs are
    written in English while the e-mail body keeps the language.
"""

import copy
import json
import os
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = 'en_US'
LANGUAGES = ('en_US', 'cs_CZ', 'de_DE', 'el_GR', 'es_ES', 'fa_IR', 'fr_FR', 'it_IT', 'ja_JP', 'ko_KR', 'no_NO',
             'pl_PL', 'pt_BR', 'pt_PT', 'ru_RU', 'tr_TR', 'uk_UA', 'vi_VN', 'zh_CN', 'zh_TW')
# a bare language code (or one with an unknown region) goes to these
ALIASES = {'en': 'en_US', 'pt': 'pt_BR', 'zh': 'zh_CN', 'nb': 'no_NO', 'nn': 'no_NO', 'no': 'no_NO'}
ALIASES.update({code.split('_')[0].lower(): code for code in LANGUAGES if code.split('_')[0].lower() not in ALIASES})
_BY_LOWER = {code.lower(): code for code in LANGUAGES}
# zh_HK / zh_MO / zh_SG read the traditional / simplified catalog
_REGION_ALIASES = {'zh_hk': 'zh_TW', 'zh_mo': 'zh_TW', 'zh_sg': 'zh_CN', 'nb_no': 'no_NO', 'nn_no': 'no_NO'}
# %-placeholders; the space flag is left out on purpose (it would read "90 % after" as a placeholder)
PLACEHOLDER_RE = re.compile(r'%(?:\([^)]*\))?[-+#0]*(?:\d+|\*)?(?:\.\d+)?[diouxXeEfFgGcrs%]')

_cache = {}
_raw_cache = {}


def normalize(language):
    """ :return: one of LANGUAGES ('auto', empty and unknown codes -> en_US) """
    value = str(language or '').strip().replace('-', '_')
    if not value or value.lower() == 'auto':
        return DEFAULT
    value = value.split('.')[0].split('@')[0]           # pt_BR.UTF-8, sr_RS@latin
    low = value.lower()
    if low in _BY_LOWER:
        return _BY_LOWER[low]
    if low in _REGION_ALIASES:
        return _REGION_ALIASES[low]
    return ALIASES.get(low.split('_')[0], DEFAULT)


def path(language):
    return os.path.join(HERE, '%s.json' % language)


def raw(language):
    """ the catalog file of one language as it is (no fallback); {} when it is missing or broken """
    if language not in _raw_cache:
        try:
            with open(path(language), encoding='utf-8') as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            data = {}
        _raw_cache[language] = data if isinstance(data, dict) else {}
    return _raw_cache[language]


def empty(value):
    """ an untranslated value: None, '' or a list of empty strings (the skeletons of the translators) """
    if isinstance(value, (list, tuple)):
        return not any(v not in (None, '') for v in value)
    return value is None or value == '' or value == {}


def _merge(base, over):
    """ base updated with over, key by key (nested dicts merged; lists and strings replaced, empty ones skipped) """
    out = copy.deepcopy(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        elif not empty(value):
            out[key] = copy.deepcopy(value)
    return out


def chain(language):
    """ :return: the fallback chain, e.g. ['pt_PT', 'pt_BR', 'en_US'] """
    language = normalize(language)
    out = [language]
    while out[-1] != DEFAULT:
        nxt = normalize((raw(out[-1]).get('_meta') or {}).get('fallback') or DEFAULT)
        if nxt in out:
            nxt = DEFAULT
        out.append(nxt)
    return out


def catalog(language):
    """ :return: the merged catalog of the language (cached: never change the returned dict) """
    language = normalize(language)
    if language not in _cache:
        merged = {}
        for code in reversed(chain(language)):
            merged = _merge(merged, raw(code))
        merged['_meta'] = dict(merged.get('_meta') or {}, language=language)
        _cache[language] = merged
    return _cache[language]


def section(language, name):
    return catalog(language).get(name) or {}


def text(language, dotted, default=None):
    node = catalog(language)
    for part in dotted.split('.'):
        if not isinstance(node, dict) or part not in node:
            return dotted if default is None else default
        node = node[part]
    return node


def number_format(language):
    return section(language, 'format')


def fmt_number(value, language=DEFAULT, decimals=0):
    """ 31877 -> "31,877" (en_US) / "31.877" (pt_BR); 2.5 with decimals=1 -> "2.5" / "2,5"; None -> "-" """
    if value is None:
        return '-'
    try:
        value = float(value)
    except (TypeError, ValueError):
        return str(value)
    if decimals == 0:
        value = round(value)
    out = '{:,.{d}f}'.format(value, d=max(0, int(decimals)))
    if out.startswith('-') and not out.strip('-0.,'):
        out = out[1:]
    fmt = number_format(language)
    return out.replace(',', '\0').replace('.', fmt.get('decimal', '.')).replace('\0', fmt.get('thousands', ','))


def fmt_int(value, language=DEFAULT):
    """ ints only (bool and anything else is returned as is): 31877 -> 31,877 / 31.877 """
    if isinstance(value, bool) or not isinstance(value, int):
        return value
    return '{:,}'.format(value).replace(',', number_format(language).get('thousands', ','))


def fmt_date(ts, language=DEFAULT, key='datetime'):
    return time.strftime(number_format(language).get(key) or '%d/%m/%Y %H:%M', time.localtime(ts))


def resolve(choice, config_path=None):
    """
    the language of a report from a setting: a language code, or 'auto' / empty = the GUI language of
    config.xml (system/language); anything unreadable is en_US
    """
    choice = str(choice or '').strip()
    if choice and choice.lower() != 'auto':
        return normalize(choice)
    try:
        import xml.etree.ElementTree as ET
        root = ET.parse(config_path or os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')).getroot()
        return normalize((root.findtext('./system/language') or '').strip())
    except Exception:                               # noqa: BLE001 - no config: default language
        return DEFAULT


def flatten(data, prefix=''):
    """ {'a': {'b': 'x'}} -> {'a.b': 'x'}; lists are kept as one value """
    out = {}
    for key, value in (data or {}).items():
        name = prefix + key
        if isinstance(value, dict):
            out.update(flatten(value, name + '.'))
        else:
            out[name] = value
    return out


def missing(language):
    """ :return: sorted dotted keys of en_US that the file of <language> does not translate ("format" is locale
    data, not a translation: an empty value there is legitimate, e.g. compact_space of en_US) """
    ref = flatten({k: v for k, v in raw(DEFAULT).items() if k not in ('_meta', 'format')})
    own = flatten(raw(normalize(language)))
    return sorted(k for k in ref if empty(own.get(k)))


def placeholders(value):
    """ the %-placeholders of a string (or of every string of a list), in order """
    if isinstance(value, (list, tuple)):
        return [p for v in value for p in placeholders(v)]
    return PLACEHOLDER_RE.findall(value) if isinstance(value, str) else []


REPORT_PDF_SECTIONS = ('report', 'pdf', 'chart', 'axis', 'weekdays')
EVAL_PDF_SECTIONS = ('eval', 'eval_pdf')


def pdf_language(language, can_render, sections=REPORT_PDF_SECTIONS):
    """
    the language a PDF can be written in: <language> when every character of the (merged) catalog sections the PDF
    uses can be drawn (can_render(text) -> bool, see reports/pdf.py) and its script needs no shaping; else en_US
    (the e-mail body keeps the language, only the attachment falls back)
    """
    language = normalize(language)
    if language == DEFAULT:
        return language
    if number_format(language).get('pdf_complex_script'):
        return DEFAULT
    key = ('pdf', language, tuple(sections))
    if key not in _cache:
        cat = catalog(language)
        merged = flatten({k: cat.get(k) for k in sections if isinstance(cat.get(k), dict)})
        strings = [x for v in merged.values() for x in (v if isinstance(v, list) else [v]) if isinstance(x, str)]
        strings += [x for k in sections if isinstance(cat.get(k), list) for x in cat[k] if isinstance(x, str)]
        _cache[key] = all(can_render(x) for x in strings)
    return language if _cache[key] else DEFAULT


def reset():
    """ drop the caches (tests that write catalogs) """
    _cache.clear()
    _raw_cache.clear()
