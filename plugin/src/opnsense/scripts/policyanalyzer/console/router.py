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

    Deterministic intent router of the AI Console (pt-BR and English).

    The model gets no tools: this module reads the question, extracts the entities (addresses, ports,
    protocol, rule references, interfaces, host names, action, time window) and decides which read-only
    collectors run.  Same question, same plan: nothing here is learned or sent anywhere.

        plan = route('por que o 192.168.1.50 não acessa a porta 443 desde ontem?', known={...}, now=...)
        plan = {'intents': [...], 'entities': {...}, 'window': {...}, 'collectors': [{'name', 'params'}], ...}
"""

import ipaddress
import re
import time
import unicodedata

# ------------------------------------------------------------------------------------------------ vocabulary

SERVICES = {
    'ssh': 22, 'telnet': 23, 'smtp': 25, 'dns': 53, 'http': 80, 'web': 80, 'https': 443, 'ntp': 123,
    'imap': 143, 'snmp': 161, 'ldap': 389, 'smb': 445, 'samba': 445, 'rdp': 3389, 'vnc': 5900,
    'mysql': 3306, 'postgres': 5432, 'postgresql': 5432, 'mssql': 1433, 'ftp': 21, 'sip': 5060,
    'wireguard': 51820, 'openvpn': 1194, 'ipsec': 500, 'mqtt': 1883, 'redis': 6379, 'imaps': 993,
    'pop3': 110, 'submission': 587, 'smtps': 465, 'dot': 853, 'kerberos': 88, 'netbios': 139,
}

# intent -> (weight, regular expressions over the normalized text: lower case, no accents)
INTENTS = {
    'why_blocked': (3, [
        r'\bpor ?que\b.*\b(nao|n)\b.*\b(acess\w*|consegu\w*|conect\w*|naveg\w*|funcion\w*|abr\w*|ping\w*|'
        r'pega|carreg\w*|alcanc\w*|chega\w*)',
        r'\bnao (acessa|consegue|conecta|navega|funciona|abre|pinga|chega|alcanca|carrega)\b',
        r'\bsem acesso\b', r'\bbloquead[oa]s?\b', r'\bbloqueio\b', r'\bbarrad[oa]\b', r'\bderrubad[oa]\b',
        r"\bwhy (can'?t|cannot|can not|is|does|doesn'?t|isn'?t|was)\b", r"\b(can'?t|cannot|unable to) (reach|access|"
        r"connect|ping|open|browse|load)\b", r'\bnot (reachable|working|connecting)\b', r'\bblocked\b',
        r'\bdenied\b', r'\bdropped\b', r'\brejected\b',
    ]),
    'changes': (3, [
        r'\bo que mudou\b', r'\bmudou\b', r'\bmudanc\w*', r'\balterac\w*', r'\balter(ou|ado|aram)\b',
        r'\bmodifica\w*', r'\bquem (mudou|alterou|mexeu)\b', r'\bmexeram\b', r'\bwhat changed\b',
        r'\bchanged\b', r'\bchanges\b', r'\bmodified\b', r'\bwho (changed|modified|touched)\b',
        r'\bconfig(uracao|uration)? (change|mudanc|alterac)\w*', r'\bbackups?\b', r'\brevis(ao|oes|ion|ions)\b',
    ]),
    'top_blocked': (3, [
        r'\bquem mais\b', r'\bmais bloquead\w*', r'\bquem (foi|esta sendo|e|tem sido) bloquead\w*',
        r'\bquem (esta|anda) (atacando|escaneando|varrendo)\b', r'\btop\b', r'\bmaiores\b', r'\branking\b',
        r'\bwho else\b', r'\bmost blocked\b', r'\bwho (was|got|is|has been) (blocked|attacking|scanning)\b',
        r'\batacant\w*', r'\battackers?\b', r'\bvarredura\w*', r'\bscan(s|ning|ners?)?\b', r'\bataque\w*',
        r'\battacks?\b', r'\bbrute ?force\b', r'\bforca bruta\b',
    ]),
    'rule_usage': (3, [
        r'\bregra\b.*\b(usad[ao]|em uso|utilizad[ao]|funcionando|casando|batendo|pegando|sendo usada)\b',
        r'\b(sem uso|nunca usad[ao]|nao usad[ao]|nao e usad[ao]|inutil|obsolet[ao])\b', r'\bcontador(es)?\b',
        r'\bhits?\b', r'\b(is|are) (it|this|that|the rule|rule \S+)? ?(being )?used\b', r'\bunused\b',
        r'\bin use\b', r'\bbeing used\b', r'\bcounters?\b', r'\bmatch(es|ing)?\b', r'\bevaluations?\b',
        r'\bavaliac\w*', r'\bpacotes\b', r'\bpackets\b',
    ]),
    'exposure': (2, [
        r'\bexpost[oa]s?\b', r'\bexposic\w*', r'\bexposure\b', r'\bexposed\b', r'\bsuperficie\b',
        r'\battack surface\b', r'\bportas? abertas?\b', r'\bopen ports?\b', r'\bvulnerab\w*', r'\bcves?\b',
        r'\bkev\b', r'\bpostur\w*', r'\bacessivel da internet\b', r'\breachable from the internet\b',
        r'\bda internet\b', r'\bfrom the internet\b',
    ]),
    'findings': (2, [
        r'\bachados?\b', r'\bfindings?\b', r'\bpolicy analyzer\b', r'\bsombread\w*', r'\bshadow\w*',
        r'\bredundan\w*', r'\bduplicad\w*', r'\bduplicates?\b', r'\bpermissiv\w*', r'\bproblemas?\b',
        r'\bissues?\b', r'\briscos?\b', r'\brisks?\b', r'\bmelhor(ar|ias?)\b', r'\bimprove\w*',
        r'\brevisar\b', r'\breview\b', r'\blimpeza\b', r'\bclean ?up\b', r'\bconjunto de regras\b',
        r'\brule ?set\b',
    ]),
    'quarantine': (3, [
        r'\bquarentena\w*', r'\bquarantin\w*', r'\bmax cyber\b', r'\bbanid[oa]s?\b', r'\bbanned\b',
        r'\bpa_quarantine\b',
    ]),
    'host': (2, [
        r'\bquem e\b', r'\b(que|qual) (host|dispositivo|aparelho|maquina|equipamento)\b', r'\bdispositivos?\b',
        r'\baparelhos?\b', r'\bdevices?\b', r'\bhostnames?\b', r'\bwho is\b', r'\bwhat is\b',
        r'\bwhich (host|device|machine)\b', r'\bmac\b', r'\bfabricante\b', r'\bvendor\b', r'\bdhcp\b',
        r'\blease\b', r'\bnome do host\b',
    ]),
    'alias': (2, [r'\balias(es)?\b', r'\btabelas? (do )?pf\b', r'\bpf tables?\b']),
    'ids': (3, [
        r'\bsuricata\b', r'\bids\b', r'\bips\b(?! ?\d)', r'\balertas?\b', r'\balerts?\b', r'\bintrus\w*',
        r'\bassinaturas?\b', r'\bsignatures?\b', r'\bmalware\b', r'\btrojan\w*', r'\bsid\b', r'\beve\b',
    ]),
    'traffic': (1, [
        r'\btrafego\b', r'\btraffic\b', r'\bacess(ou|aram|os)\b', r'\baccess(ed)?\b', r'\bconex\w*',
        r'\bconnect\w*', r'\bo que (o|a|esse|este)? ?\S* ?fez\b', r'\bwhat did\b', r'\batividade\b',
        r'\bactivity\b', r'\blogs?\b', r'\beventos?\b', r'\bevents?\b', r'\bpassou\b', r'\bpermitid[oa]\b',
        r'\ballowed\b', r'\bliberad[oa]\b', r'\bfalando com\b', r'\btalking to\b', r'\bcomunica\w*',
    ]),
}

# which collectors answer each intent (order = priority in the context)
INTENT_COLLECTORS = {
    'why_blocked': ['filterlog', 'path_rules', 'hosts', 'aliases', 'quarantine', 'suricata'],
    'changes': ['changes'],
    'top_blocked': ['filterlog_top', 'quarantine', 'hosts'],
    'rule_usage': ['rules', 'findings', 'filterlog'],
    'exposure': ['exposure', 'filterlog_top'],
    'findings': ['findings'],
    'quarantine': ['quarantine'],
    'host': ['hosts', 'filterlog'],
    'alias': ['aliases'],
    'ids': ['suricata'],
    'traffic': ['filterlog', 'hosts'],
    'overview': ['filterlog_top', 'findings', 'exposure', 'quarantine'],
}

# default time window (seconds) when the question gives none
DEFAULT_WINDOW = {
    'why_blocked': 3600, 'traffic': 3600, 'host': 3600, 'rule_usage': 86400, 'top_blocked': 'today',
    'changes': 86400, 'ids': 86400, 'overview': 3600, 'quarantine': 86400,
}

ANAPHORA = re.compile(r'\b(ele|ela|dele|dela|nele|nela|isso|esse|essa|este|esta|mesm[oa]|ai|it|its|that|this|'
                      r'them|those|same|there|again|tambem|also|e (ontem|hoje|agora)|and (yesterday|today|now))\b')

STOP_AFTER_RULE = {
    'esta', 'estao', 'e', 'foi', 'tem', 'is', 'was', 'are', 'has', 'have', 'sendo', 'being', 'ainda', 'still',
    'usada', 'used', 'em', 'in', 'no', 'na', 'on', 'do', 'da', 'de', 'of', 'que', 'which', 'faz', 'does',
}
FILLER = {'a', 'o', 'the', 'minha', 'my', 'de', 'do', 'da', 'chamada', 'called', 'named'}

_IPV4 = re.compile(r'(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?(?::(\d{1,5}))?(?![\w.]*\w)')
_IPV6 = re.compile(r'(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?:/(\d{1,3}))?(?![\w:])')
_FQDN = re.compile(r'(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])', re.I)
_UUID = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I)
_LABEL = re.compile(r'\b[0-9a-f]{32}\b', re.I)
_QUOTED = re.compile(r'["“”«»\'‘’`]([^"“”«»\'‘’`]{2,80})["“”«»\'‘’`]')
_PORT_WORD = re.compile(r'\b(?:porta|portas|port|ports|porto)\s*(?:n[o.º°]?\s*)?[:#]?\s*'
                        r'(\d{1,5}(?:\s*(?:,|e|and|ou|or)\s*\d{1,5})*)', re.I)
_PORT_PROTO = re.compile(r'\b(\d{1,5})\s*/\s*(tcp|udp)\b', re.I)
_PROTO = re.compile(r'\b(tcp|udp|icmp|icmp6|ipv6-icmp|gre|esp)\b', re.I)
_NOT_TLD = {'json', 'xml', 'conf', 'php', 'py', 'log', 'txt', 'sh', 'inc', 'volt', 'html', 'js', 'css', 'db',
            'csv', 'md', 'pem', 'gz', 'local'}


def normalize(text):
    """ lower case, accents removed, spacing collapsed (keyword matching only) """
    text = unicodedata.normalize('NFKD', str(text or '').lower())
    text = ''.join(c for c in text if not unicodedata.combining(c))
    return re.sub(r'\s+', ' ', text).strip()


# ------------------------------------------------------------------------------------------------ entities

def _ips(text):
    found = []
    ports = []
    for m in _IPV4.finditer(text):
        try:
            if m.group(2):
                net = ipaddress.ip_network('%s/%s' % (m.group(1), m.group(2)), strict=False)
                found.append(str(net))
            else:
                found.append(str(ipaddress.IPv4Address(m.group(1))))
        except ValueError:
            continue
        if m.group(3):
            ports.append(int(m.group(3)))
    for m in _IPV6.finditer(text):
        if m.group(1).count(':') < 2:
            continue
        try:
            if m.group(2):
                found.append(str(ipaddress.ip_network('%s/%s' % (m.group(1), m.group(2)), strict=False)))
            else:
                found.append(str(ipaddress.IPv6Address(m.group(1))))
        except ValueError:
            continue
    seen = []
    for item in found:
        if item not in seen:
            seen.append(item)
    return seen[:6], ports


def _ports(text, norm):
    ports = []
    for m in _PORT_WORD.finditer(text):
        ports += [int(p) for p in re.findall(r'\d{1,5}', m.group(1))]
    for m in _PORT_PROTO.finditer(text):
        ports.append(int(m.group(1)))
    words = set(re.findall(r'[a-z0-9]+', norm))
    services = []
    for name, port in SERVICES.items():
        if name in words:
            ports.append(port)
            services.append(name)
    result = []
    for port in ports:
        if 0 < port < 65536 and port not in result:
            result.append(port)
    return result[:6], services


def _window(norm, now, default=None):
    """ :return: {since, until, label, explicit} """
    lt = time.localtime(now)
    midnight = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1))

    def rel(seconds, label):
        return {'since': int(now - seconds), 'until': int(now), 'label': label, 'explicit': True}

    m = re.search(r'\b(?:ultim[oa]s?|last|past|nas? ultim[oa]s?|nos ultimos|nas ultimas)\s+(\d{1,3})\s*'
                  r'(min\w*|m\b|h\b|hr?s?\b|hora\w*|hours?|d\b|dias?|days?|semanas?|weeks?)', norm)
    if not m:
        m = re.search(r'\b(?:ha|faz|desde ha)\s+(\d{1,3})\s*(min\w*|h\b|hora\w*|dias?|semanas?)', norm)
    if not m:
        m = re.search(r'\b(\d{1,3})\s*(min\w*|hours?|hora\w*|days?|dias?)\s+(?:ago|atras)\b', norm)
    if m:
        qty, unit = int(m.group(1)), m.group(2)
        if unit.startswith(('min', 'm')) and not unit.startswith('h'):
            secs, label = qty * 60, 'last %d min' % qty
        elif unit.startswith(('h', 'hora')):
            secs, label = qty * 3600, 'last %d h' % qty
        elif unit.startswith(('sem', 'week')):
            secs, label = qty * 7 * 86400, 'last %d weeks' % qty
        else:
            secs, label = qty * 86400, 'last %d days' % qty
        return rel(max(60, min(secs, 31 * 86400)), label)
    if re.search(r'\b(ultima hora|last hour|past hour|na ultima hora|uma hora)\b', norm):
        return rel(3600, 'last 1 h')
    if re.search(r'\b(desde ontem|since yesterday|de ontem pra ca|de ontem para ca|from yesterday)\b', norm):
        return {'since': int(midnight - 86400), 'until': int(now), 'label': 'since yesterday', 'explicit': True}
    if re.search(r'\b(anteontem|day before yesterday)\b', norm):
        return {'since': int(midnight - 2 * 86400), 'until': int(midnight - 86400), 'label': 'day before yesterday',
                'explicit': True}
    if re.search(r'\b(ontem|yesterday)\b', norm):
        return {'since': int(midnight - 86400), 'until': int(midnight), 'label': 'yesterday', 'explicit': True}
    m = re.search(r'\b(?:desde as|desde|since|a partir das?|from)\s+(\d{1,2})(?:[:h](\d{2}))?\s*(h|am|pm)?\b', norm)
    if m and (m.group(2) or m.group(3)):
        hour, minute = int(m.group(1)), int(m.group(2) or 0)
        if m.group(3) == 'pm' and hour < 12:
            hour += 12
        if hour < 24 and minute < 60:
            since = midnight + hour * 3600 + minute * 60
            if since > now:
                since -= 86400
            return {'since': int(since), 'until': int(now), 'label': 'since %02d:%02d' % (hour, minute),
                    'explicit': True}
    if re.search(r'\b(hoje|today|de hoje|neste dia)\b', norm):
        return {'since': int(midnight), 'until': int(now), 'label': 'today', 'explicit': True}
    if re.search(r'\b(esta semana|essa semana|nesta semana|nessa semana|this week|semana passada|last week|'
                 r'ultima semana|past week)\b', norm):
        return rel(7 * 86400, 'last 7 days')
    if re.search(r'\b(este mes|esse mes|this month|ultimo mes|last month)\b', norm):
        return rel(30 * 86400, 'last 30 days')
    if re.search(r'\b(agora|neste momento|right now|now|currently|atualmente|no momento)\b', norm):
        return rel(900, 'last 15 min')
    if default == 'today':
        return {'since': int(midnight), 'until': int(now), 'label': 'today', 'explicit': False}
    seconds = default or 3600
    label = 'last %d h' % (seconds // 3600) if seconds >= 3600 else 'last %d min' % (seconds // 60)
    return {'since': int(now - seconds), 'until': int(now), 'label': label, 'explicit': False}


def _rule_refs(text, norm):
    refs = {'uuids': [], 'labels': [], 'texts': []}
    refs['uuids'] = list(dict.fromkeys(m.group(0).lower() for m in _UUID.finditer(text)))[:3]
    refs['labels'] = list(dict.fromkeys(m.group(0).lower() for m in _LABEL.finditer(text)))[:3]
    for m in _QUOTED.finditer(text):
        value = m.group(1).strip()
        if value and value not in refs['texts']:
            refs['texts'].append(value)
    # unquoted: words after "regra"/"rule" up to a verb or the end of the clause
    m = re.search(r'\b(?:regra|rule)\s+(?:#\s*)?([^?.!,;]{1,80})', norm)
    if m and not refs['texts'] and not refs['uuids']:
        words = []
        for word in m.group(1).split():
            if word in STOP_AFTER_RULE and words:
                break
            if word in FILLER and not words:
                continue
            words.append(word)
            if len(words) >= 6:
                break
        phrase = ' '.join(w for w in words if w not in STOP_AFTER_RULE).strip()
        if len(phrase) >= 2:
            refs['texts'].append(phrase)
    refs['texts'] = refs['texts'][:3]
    return refs


def _domains(text, ips):
    result = []
    for m in _FQDN.finditer(text):
        name = m.group(1).lower().rstrip('.')
        tld = name.rsplit('.', 1)[-1]
        if tld in _NOT_TLD or any(name in ip for ip in ips) or re.fullmatch(r'[\d.]+', name):
            continue
        if name not in result:
            result.append(name)
    return result[:3]


def _known(norm, names):
    """ known names (interfaces, hosts) that appear as whole words; names are matched normalized """
    found = []
    for name in names or ():
        key = normalize(name)
        if len(key) < 2:
            continue
        if re.search(r'(?<![\w.-])' + re.escape(key) + r'(?![\w-])', norm) and name not in found:
            found.append(name)
    return found


def extract(text, known=None, now=None):
    """ entities of one question; known = {'interfaces': [...names], 'hosts': [...names]} """
    now = time.time() if now is None else now
    known = known or {}
    text = str(text or '')
    norm = normalize(text)
    ips, ip_ports = _ips(text)
    ports, services = _ports(text, norm)
    for port in ip_ports:
        if port not in ports:
            ports.append(port)
    protos = list(dict.fromkeys(p.lower() for p in _PROTO.findall(text)))
    action = None
    if re.search(r'\b(bloque\w*|negad\w*|barrad\w*|blocked|block|deny|denied|drop\w*|reject\w*|rejeit\w*)\b', norm):
        action = 'block'
    elif re.search(r'\b(permitid\w*|liberad\w*|passou|passaram|allowed|passed|pass)\b', norm):
        action = 'pass'
    rules = _rule_refs(text, norm)
    in_rule = ' '.join(normalize(t) for t in rules['texts'])
    for name in list(services):
        if re.search(r'\b%s\b' % re.escape(name), in_rule) and \
                not re.search(r'\b(?:porta|port)\s+%s\b' % re.escape(name), norm):
            services.remove(name)
            if SERVICES[name] in ports and str(SERVICES[name]) not in text:
                ports.remove(SERVICES[name])
    return {
        'ips': ips,
        'ports': ports[:6],
        'services': services,
        'protocols': protos,
        'domains': _domains(text, ips),
        'rules': rules,
        'interfaces': _known(norm, known.get('interfaces')),
        'hosts': [h for h in _known(norm, known.get('hosts')) if h.lower() not in SERVICES],
        'action': action,
        'severity': _severity(norm),
    }


def _severity(norm):
    m = re.search(r'\b(?:severidade|severity|sev)\s*(\d)\b', norm)
    if m and m.group(1) in '1234':
        return int(m.group(1))
    if re.search(r'\b(critic\w*|grave\w*|high|alta|alto|severe)\b', norm):
        return 1
    return None


# ------------------------------------------------------------------------------------------------ intents

def score(norm, entities):
    scores = {}
    for intent, (weight, patterns) in INTENTS.items():
        hits = sum(1 for p in patterns if re.search(p, norm))
        if hits:
            scores[intent] = weight * hits
    # entity hints
    if entities['ips'] or entities['hosts'] or entities['domains']:
        scores['traffic'] = scores.get('traffic', 0) + 1
    if entities['rules']['uuids'] or entities['rules']['labels'] or entities['rules']['texts']:
        if 'why_blocked' not in scores and 'changes' not in scores:
            scores['rule_usage'] = scores.get('rule_usage', 0) + 2
    if 'why_blocked' in scores and not (entities['ips'] or entities['hosts'] or entities['domains']):
        # "who is being blocked" without an address is a top list, not a path question
        if re.search(r'\bquem\b|\bwho\b|\bwhich\b|\bquais\b', norm):
            scores['top_blocked'] = scores.get('top_blocked', 0) + scores.pop('why_blocked')
    if 'changes' in scores and 'rule_usage' in scores and not re.search(r'\b(usad\w*|used|uso|use)\b', norm):
        scores.pop('rule_usage')
    return scores


def is_follow_up(norm, entities, scores):
    """ a question without its own subject that refers to the previous one ("e ontem?", "and port 22?") """
    has_subject = entities['ips'] or entities['hosts'] or entities['domains'] or entities['rules']['texts'] or \
        entities['rules']['uuids'] or entities['rules']['labels']
    if has_subject:
        return False
    if ANAPHORA.search(norm):
        return True
    # nothing of its own (only a time window, a port or a protocol)
    return not scores or set(scores) <= {'traffic'}


def route(question, known=None, now=None, history=None, max_intents=3):
    """
    :param question: the operator's text
    :param known: {'interfaces': [...], 'hosts': [...]} names that may appear in the text
    :param history: earlier questions of the conversation (newest last), used for follow-ups
    :return: plan dict
    """
    now = time.time() if now is None else now
    norm = normalize(question)
    entities = extract(question, known, now)
    scores = score(norm, entities)
    carried = []
    if history and is_follow_up(norm, entities, scores):
        for previous in reversed(history[-3:]):
            prev = extract(previous, known, now)
            for key in ('ips', 'hosts', 'domains', 'ports'):
                if not entities[key] and prev[key]:
                    entities[key] = prev[key]
                    carried.append(key)
            if not (entities['rules']['texts'] or entities['rules']['uuids']) and \
                    (prev['rules']['texts'] or prev['rules']['uuids']):
                entities['rules'] = prev['rules']
                carried.append('rules')
            if carried:
                if not scores or set(scores) <= {'traffic'}:
                    # same question about another time window / port: keep the previous intent
                    scores = score(normalize(previous), entities) or scores
                else:
                    scores = score(norm, entities)
                break
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], list(INTENTS).index(kv[0])))
    intents = [k for k, _ in ranked[:max_intents]] or ['overview']
    # "traffic" only adds information when nothing more specific was asked
    if len(intents) > 1 and 'traffic' in intents and scores.get('traffic', 0) <= 2:
        intents.remove('traffic')
    window = _window(norm, now, DEFAULT_WINDOW.get(intents[0], 3600))
    collectors = []
    for intent in intents:
        for name in INTENT_COLLECTORS[intent]:
            if name not in collectors:
                collectors.append(name)
    # collectors that need a subject are skipped when there is none
    subject = bool(entities['ips'] or entities['hosts'] or entities['domains'])
    if not subject:
        for name in ('path_rules', 'aliases'):
            if name in collectors and not ('alias' in intents and name == 'aliases'):
                collectors.remove(name)
        if 'filterlog' in collectors and not (entities['ports'] or entities['rules']['texts'] or
                                              entities['rules']['uuids'] or entities['interfaces']):
            collectors[collectors.index('filterlog')] = 'filterlog_top'
    if 'filterlog' in collectors and 'filterlog_top' in collectors:
        collectors.remove('filterlog_top')
    if entities['rules']['texts'] or entities['rules']['uuids'] or entities['rules']['labels']:
        if 'rules' not in collectors and 'path_rules' not in collectors:
            collectors.append('rules')
    return {
        'intents': intents,
        'scores': dict(ranked),
        'entities': entities,
        'carried_from_history': carried,
        'window': window,
        'collectors': collectors,
    }


def window_text(window):
    return '%s (%s .. %s)' % (window['label'], time.strftime('%Y-%m-%d %H:%M', time.localtime(window['since'])),
                              time.strftime('%Y-%m-%d %H:%M', time.localtime(window['until'])))
