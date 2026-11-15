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

    Domain name features, all deterministic and local (no list is downloaded):

      registrable()   eTLD+1 with a compact list of multi-label public suffixes (com.br, co.uk, ...); good
                      enough to group the subdomains of one service, not a full Public Suffix List
      name_score()    how "generated" a label looks, 0..1, from: character bigram likelihood under a model
                      of ordinary words and service names (embedded corpus below), Shannon entropy, the
                      longest consonant run, the vowel share and digits mixed with letters
      CDN / lookup    registrable domains whose subdomains are random by design (CDNs, cloud storage,
                      antivirus and reputation services that answer through DNS): never DGA or tunnel
"""

import math
import re

from .common import entropy

MULTI_SUFFIXES = frozenset("""
com.br net.br org.br gov.br edu.br art.br blog.br eco.br emp.br ind.br inf.br log.br nom.br tec.br app.br dev.br
co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk com.au net.au org.au edu.au gov.au co.nz org.nz net.nz
co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr ne.kr com.cn net.cn org.cn gov.cn com.hk com.tw com.sg com.my
com.mx com.ar com.co com.pe com.ve com.uy com.py com.ec com.bo co.za co.in net.in org.in co.id or.id
com.tr com.ua com.ru com.pl com.es com.pt co.il com.sa com.eg com.ng co.ke com.vn com.ph com.pk
amazonaws.com cloudfront.net azurewebsites.net blob.core.windows.net cloudapp.net herokuapp.com
appspot.com github.io gitlab.io netlify.app vercel.app pages.dev workers.dev firebaseapp.com web.app
""".split())

# subdomains are random by design: never DGA / tunnel (owner exceptions cover the rest)
RANDOM_BY_DESIGN = frozenset("""
akamaiedge.net akamaized.net akamai.net akadns.net akamaihd.net edgekey.net edgesuite.net cloudfront.net
amazonaws.com awsdns.com fastly.net fastlylb.net cloudflare.net cloudflare.com googleusercontent.com
googlevideo.com gvt1.com gvt2.com 1e100.net googleapis.com doubleclick.net azureedge.net azurefd.net
trafficmanager.net windows.net msedge.net azure.com office.net live.com cdn77.org llnwd.net footprint.net
edgecastcdn.net hwcdn.net b-cdn.net cdninstagram.com fbcdn.net whatsapp.net tiktokcdn.com bytecdn.cn
ttlivecdn.com nflxvideo.net nflxso.net aiv-cdn.net scdn.co spotifycdn.com dropboxusercontent.com
sophosxl.net mcafee.com trendmicro.com eset.com e5.sk avast.com avg.com kaspersky.com bitdefender.net
spamhaus.org spamcop.net sorbs.net surbl.org uribl.com barracudacentral.org dnswl.org mailspike.net
senderscore.com senderbase.org apple-dns.net aaplimg.com icloud.com mzstatic.com push.apple.com
tailscale.com ts.net plex.direct local arpa in-addr.arpa ip6.arpa
""".split())

_WORDS = """
the and for are but not you all any can her was one our out day get has him his how man new now old see two way
who boy did its let put say she too use that with have this will your from they know want been good much some
time very when come here just like long make many more only over such take than them well were mail web site
home page news shop store blog online cloud data info account login secure update service services server api
static media image images video cdn content assets search map maps play music photo photos drive docs office
mobile app apps games game live stream tv radio sport sports bank pay payment money market price deal deals
google facebook amazon microsoft apple netflix youtube twitter instagram whatsapp telegram yahoo bing linkedin
github gitlab cloudflare akamai adobe oracle samsung xiaomi huawei android windows ubuntu debian mozilla firefox
chrome opera spotify discord steam valve epic twitch reddit wikipedia pinterest tumblr paypal ebay alibaba
aliexpress mercado livre globo uol terra americanas magazine luiza submarino itau bradesco caixa santander nubank
inter correios receita fazenda governo brasil saude educacao noticias esporte futebol tempo previsao cidade
portal sistema empresa loja compras vendas cliente clientes contato suporte ajuda central servicos dados
connect network networks system systems analytics tracking metrics telemetry events event push notify
notification gateway proxy edge global world international national local office public private digital
studio design creative studio solutions technology tech software hardware device devices security safe
trust identity auth signin signup register portal center centre support help forum community group team
travel hotel hotels flight flights booking ticket tickets weather health care medical clinic hospital
school university college academy learn learning course courses library book books read reader press
times post daily journal today report review reviews guide guides list lists free best top pro plus prime
energy power solar green water food fresh pizza burger coffee beer wine fashion style beauty home house
garden auto autos car cars motor motors bike parts tools build builder project projects open source code
dev developer developers docs documentation status monitor monitoring backup storage files file share
sharing upload download downloads mirror mirrors repo repository package packages registry release
releases update updates install installer client clients agent agents manager management admin control
panel dashboard config settings profile profiles user users member members people friends chat message
messages voice call calls meet meeting meetings video conference email inbox calendar contacts photos
""".split()

_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789-'
_VOWELS = set('aeiouy')
_CONS_RE = re.compile(r'[bcdfghjklmnpqrstvwxz]+')


def _build_model():
    counts = {}
    totals = {}
    for word in _WORDS:
        text = '^' + word + '$'
        for a, b in zip(text, text[1:]):
            counts[(a, b)] = counts.get((a, b), 0) + 1
            totals[a] = totals.get(a, 0) + 1
    return counts, totals


_COUNTS, _TOTALS = _build_model()
_V = len(_ALPHABET) + 1


def bigram_logprob(label):
    """ average log10 probability per bigram (add-one smoothing); ordinary words ~ -1.1, random ~ -1.9 """
    text = '^' + label + '$'
    pairs = list(zip(text, text[1:]))
    if not pairs:
        return 0.0
    total = 0.0
    for a, b in pairs:
        total += math.log10((_COUNTS.get((a, b), 0) + 1.0) / (_TOTALS.get(a, 0) + _V))
    return total / len(pairs)


def registrable(name):
    """ "a.b.example.com.br" -> ("example.com.br", "a.b", "example") """
    labels = [x for x in name.lower().strip('.').split('.') if x]
    if len(labels) < 2:
        return name, '', labels[0] if labels else ''
    take = 2
    if len(labels) >= 3 and '.'.join(labels[-2:]) in MULTI_SUFFIXES:
        take = 3
    if len(labels) >= 4 and '.'.join(labels[-3:]) in MULTI_SUFFIXES:
        take = 4
    take = min(take, len(labels))
    return '.'.join(labels[-take:]), '.'.join(labels[:-take]), labels[-take]


def clamp(value, low=0.0, high=1.0):
    return max(low, min(high, value))


def name_features(label):
    label = label.lower()
    letters = sum(1 for c in label if c.isalpha())
    digits = sum(1 for c in label if c.isdigit())
    runs = _CONS_RE.findall(label)
    return {
        'length': len(label),
        'entropy': round(entropy(label), 3),
        'bigram': round(bigram_logprob(label), 3),
        'max_consonants': max((len(r) for r in runs), default=0),
        'vowel_ratio': round(sum(1 for c in label if c in _VOWELS) / float(letters), 3) if letters else 0.0,
        'digit_ratio': round(digits / float(len(label)), 3) if label else 0.0,
    }


def name_score(label):
    """ 0..1, how generated the label looks, and its features """
    f = name_features(label)
    n = f['length']
    if n < 7 or '-' in label.strip('-') and f['bigram'] > -1.5:
        return 0.0, f
    s_bg = clamp((-f['bigram'] - 1.35) / 0.35)
    s_ent = clamp((f['entropy'] - 2.8) / 0.8)
    s_cons = clamp((f['max_consonants'] - 3) / 2.0)
    s_vow = clamp((0.3 - f['vowel_ratio']) / 0.15)
    s_dig = 1.0 if 0.1 <= f['digit_ratio'] <= 0.7 and f['digit_ratio'] * n >= 2 else 0.0
    score = 0.4 * s_bg + 0.25 * s_ent + 0.2 * s_cons + 0.1 * s_vow + 0.05 * s_dig
    score *= clamp((n - 6) / 6.0)
    return round(score, 3), f


def is_random_by_design(reg):
    return reg in RANDOM_BY_DESIGN or any(reg.endswith('.' + d) for d in RANDOM_BY_DESIGN)


def skip_name(name):
    """ names that are never scored: service records, reverse lookups, local names, bare words """
    return (not name or name.startswith('_') or '._' in name or name.endswith('.arpa') or
            name.endswith('.local') or name.endswith('.lan') or name.endswith('.home.arpa') or
            name.endswith('.internal') or '.' not in name)
