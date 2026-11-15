"""Architecture diagram of the OPNsense Policy Analyzer (Max Cyber IA), hand laid out, SVG."""
import html
import sys

W, H = 1800, 1120
SANS = "'Source Sans Pro', 'DejaVu Sans', sans-serif"
MONO = "'DejaVu Sans Mono', monospace"
INK, MUTED, FAINT = '#0f172a', '#475569', '#64748b'
ORANGE, BLUE, GREEN, RED, GREY = '#f97316', '#2563eb', '#059669', '#dc2626', '#94a3b8'
out = []


def esc(s):
    return html.escape(s, quote=True)


def text(x, y, s, size=13, weight='normal', color=INK, anchor='start', mono=False, italic=False):
    fam = MONO if mono else SANS
    st = ' font-style="italic"' if italic else ''
    out.append('<text xml:space="preserve" x="%g" y="%g" font-family="%s" font-size="%g" font-weight="%s" fill="%s" '
               'text-anchor="%s"%s>%s</text>' % (x, y, fam, size, weight, color, anchor, st, esc(s)))


def rich(x, y, parts, size=13, anchor='start'):
    """ parts: list of (text, dict(weight, color, mono)) on one line """
    spans = []
    for s, o in parts:
        spans.append('<tspan font-family="%s" font-weight="%s" fill="%s">%s</tspan>' % (
            MONO if o.get('mono') else SANS, o.get('weight', 'normal'), o.get('color', INK), esc(s)))
    out.append('<text xml:space="preserve" x="%g" y="%g" font-size="%g" text-anchor="%s">%s</text>' % (x, y, size, anchor, ''.join(spans)))


def rect(x, y, w, h, fill='#ffffff', stroke=GREY, sw=1.2, r=10, dash=None, shadow=False):
    d = ' stroke-dasharray="%s"' % dash if dash else ''
    f = ' filter="url(#shadow)"' if shadow else ''
    out.append('<rect x="%g" y="%g" width="%g" height="%g" rx="%g" fill="%s" stroke="%s" stroke-width="%g"%s%s/>'
               % (x, y, w, h, r, fill, stroke, sw, d, f))


def card(x, y, w, h, title, lines=(), accent=GREY, fill='#ffffff', badge=None, title_mono=None, dash=None):
    rect(x, y, w, h, fill=fill, stroke=accent, sw=1.4, dash=dash, shadow=dash is None)
    out.append('<rect x="%g" y="%g" width="5" height="%g" rx="2" fill="%s"/>' % (x, y + 10, h - 20, accent))
    ty = y + 26
    if badge:
        out.append('<circle cx="%g" cy="%g" r="11" fill="%s"/>' % (x + 26, ty - 5, accent))
        text(x + 26, ty - 1, badge, 12, 'bold', '#ffffff', 'middle')
        tx = x + 44
    else:
        tx = x + 18
    if title_mono:
        rich(tx, ty, [(title, {'weight': 'bold'}), ('   ' + title_mono, {'mono': title_mono.startswith('/'), 'color': MUTED, 'weight': 'normal'})], 15)
    else:
        text(tx, ty, title, 15, 'bold')
    ly = ty + 24
    for line in lines:
        if isinstance(line, tuple):
            parts, size = line[0]
            rich(x + 18, ly, parts, size)
        else:
            text(x + 18, ly, line, 12.5, color=MUTED)
        ly += 18


def frame(x, y, w, h, label, sub, color, fill, dash=None):
    rect(x, y, w, h, fill=fill, stroke=color, sw=2 if not dash else 1.5, r=16, dash=dash)
    rich(x + 18, y + 26, [(label, {'weight': 'bold', 'color': INK}), ('   ' + sub, {'color': MUTED})], 16)


def arrow(points, color=FAINT, label=None, lx=None, ly=None, dash=None, anchor='middle', lcolor=None, both=False):
    d = 'M' + ' L'.join('%g %g' % p for p in points)
    da = ' stroke-dasharray="%s"' % dash if dash else ''
    mid = color.replace('#', '')
    ms = ' marker-start="url(#a%s)"' % mid if both else ''
    out.append('<path d="%s" fill="none" stroke="%s" stroke-width="1.8"%s marker-end="url(#a%s)"%s/>'
               % (d, color, da, mid, ms))
    if label:
        w = len(label) * 6.4 + 12
        ax = lx - (w / 2 if anchor == 'middle' else 0)
        out.append('<rect x="%g" y="%g" width="%g" height="18" rx="9" fill="#ffffff" stroke="%s" stroke-width="0.8"/>'
                   % (ax, ly - 13, w, color))
        text(ax + w / 2, ly, label, 11, 'bold', lcolor or color, 'middle')


# ------------------------------------------------------------------------------------------- canvas
out.append('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">' % (W, H, W, H))
markers = ''.join('<marker id="a%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                  'orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="%s"/></marker>' % (c[1:], c)
                  for c in (FAINT, ORANGE, BLUE, GREEN, RED, GREY, INK))
out.append('<defs>%s<filter id="shadow" x="-5%%" y="-5%%" width="110%%" height="120%%">'
           '<feDropShadow dx="0" dy="1.5" stdDeviation="2" flood-color="#0f172a" flood-opacity="0.12"/></filter></defs>'
           % markers)

PURPLE = '#7c3aed'
out.append('<rect x="0" y="0" width="%d" height="8" fill="%s"/>' % (W, ORANGE))
text(40, 54, 'OPNsense Policy Analyzer · AI providers and roadmap', 28, 'bold')
text(40, 82, 'The AI is optional and only explains findings and writes summaries; it never creates or changes rules. '
             'Solid = implemented · dashed = in development (separate pull requests) · dotted = ideas.', 14.5, color=MUTED)
text(W - 40, 54, 'os-policyanalyzer · OPNsense 26.7', 14, 'bold', MUTED, 'end')
text(W - 40, 76, 'github.com/igortoledo007/opnsense-policyanalyzer', 12.5, color=FAINT, anchor='end')

# firewall / AI layer
frame(30, 110, 470, 960, 'OPNsense firewall', 'ZFS or UFS root', ORANGE, '#fffaf5')
card(50, 160, 430, 250, 'AI layer', [
    'router: picks the provider per task',
    'anonymizer: addresses, names, hostnames',
    '   replaced before anything leaves the box',
    'prompt templates per task and language',
    'validation: JSON shape, refusals, length',
    'usage log and journal of every request',
    'benchmark and evaluation per model',
    'timeouts, retries, no tools for the model'], accent=ORANGE, badge='1')
card(50, 430, 430, 170, 'What the AI is asked to do', [
    'explain a rule finding in plain language',
    'summarize incidents and anomalies',
    'write the executive summary of PDF reports',
    'answer in the 20 OPNsense languages',
    'never: create, change or apply rules'], accent=ORANGE)
card(50, 620, 430, 200, 'Local runtime (optional)', [
    (([('Ollama jail on ', {'color': MUTED}), ('127.0.0.1:11434', {'mono': True, 'color': GREEN, 'weight': 'bold'})], 12.5),),
    'no network access, cpuset, nice, RCTL',
    (([('ZFS: ', {'weight': 'bold', 'color': BLUE}), ('zroot/ai', {'mono': True, 'color': BLUE})], 12.5),),
    (([('UFS: ', {'weight': 'bold', 'color': BLUE}), ('/var/db/ai', {'mono': True, 'color': BLUE}),
       (' or a pool in a file', {'color': MUTED})], 12.5),),
    'free-space guard before every download',
    'eight-step setup assistant, revertible'], accent=GREEN, badge='2')
card(50, 840, 430, 210, 'Same rules for every provider', [
    'opt-in, off by default',
    'privacy text and data policy shown',
    '   next to each provider in the settings',
    'secrets stored like other OPNsense secrets',
    'test button and benchmark before use',
    'one switch to turn the AI off again'], accent=INK)

# lanes
def lane(x, title, sub, color, fill, dash, w=410):
    frame(x, 110, w, 960, title, sub, color, fill, dash=dash)

lane(530, 'Implemented', 'working today', GREEN, '#f3fcf8', None)
card(550, 160, 370, 150, 'Ollama, local', [
    'jail on the firewall, models from the',
    'Ollama registry (SHA-256 checked)',
    'e.g. qwen3:4b · qwen3:8b · qwen3:30b-a3b',
    'nothing leaves the firewall'], accent=GREEN)
card(550, 330, 370, 130, 'Ollama in the LAN', [
    'a GPU box in your network',
    (([('http://<lan-host>:11434', {'mono': True, 'color': MUTED})], 12),),
    'data stays in your network'], accent=GREEN)
card(550, 480, 370, 130, 'Anthropic API (Claude)', [
    'remote API with your own key',
    'anonymized input, short answers',
    'data policy shown in the settings'], accent=GREEN)
card(550, 630, 370, 150, 'Claude Code bridge (LAN)', [
    'small HTTP bridge on a LAN machine',
    'calls the Claude Code CLI, tools off',
    'token, IP allow-list, timeouts',
    'subscription instead of an API key'], accent=GREEN)
card(550, 800, 370, 250, 'Storage for the local models', [
    'ZFS: datasets with tuned properties',
    'UFS: plain directory + free-space guard',
    'UFS opt-in: ZFS pool in a file',
    '   (fixed size, own rc script)',
    'tested on two KVM labs (ZFS and UFS)',
    'pull request #1'], accent=BLUE)

lane(970, 'In development', 'separate pull requests', BLUE, '#f5f9ff', '7 5')
card(990, 160, 370, 230, 'OpenAI-compatible APIs', [
    'one provider with presets:',
    'OpenAI · Mistral · xAI · DeepSeek',
    'Groq · OpenRouter · Together · Fireworks',
    'Cerebras · Qwen · Moonshot · Zhipu',
    'Maritaca (Brazil) · custom endpoint',
    'any OpenAI-compatible gateway (LiteLLM)',
    'pull request: AI providers'], accent=BLUE, dash='6 4')
card(990, 410, 370, 170, 'Native APIs', [
    'Google Gemini (generateContent)',
    'Azure OpenAI (deployment, api-version)',
    'Cohere (v2 chat)',
    'AWS Bedrock (Converse, SigV4 in stdlib)',
    'pull request: AI providers'], accent=BLUE, dash='6 4')
card(990, 600, 370, 150, 'Local/LAN OpenAI-compatible servers', [
    'LM Studio · llama.cpp server · vLLM',
    'LocalAI · Jan · Ollama /v1',
    'no key, data stays in the LAN',
    'pull request: AI providers'], accent=BLUE, dash='6 4')
card(990, 770, 370, 280, 'Agent bridge (LAN), multi-CLI', [
    'the Claude Code bridge, generalized:',
    'claude · goose (tools off, documented)',
    'codex · gemini · opencode · copilot ·',
    'cursor: experimental, off by default',
    'any CLI added by a manifest (no code)',
    'one container per backend (Dockerfile',
    '   + compose): read-only, no privileges',
    'text only: tools off, fixed argv, token,',
    'IP allow-list, size limits, GET /backends',
    'pull request: agent bridge'], accent=BLUE, dash='6 4')

lane(1400, 'Ideas', 'possible improvements', GREY, '#fafafa', '2 4', w=370)
ideas = [
    ('Routing and fallback', ['per-task provider (local first,', 'remote only when needed)', 'fallback chain on errors']),
    ('Budgets and usage', ['token and cost limits per provider', 'monthly usage report']),
    ('Response cache', ['same finding, same answer', 'fewer calls and lower cost']),
    ('Package repository', ['signed pkg repository for', 'one-command install and updates']),
    ('Thinner core', ['split optional parts into', 'smaller packages']),
    ('Evaluation per provider', ['the existing benchmark and quality', 'checks run against every provider']),
    ('Community translations', ['review of the 20 languages', 'by native speakers']),
    ('Read-only MCP server', ['query findings and reports from', 'your own agent, never write']),
]
y = 160
for title, lines in ideas:
    h = 40 + 18 * len(lines) + 10
    card(1420, y, 330, h, title, lines, accent=GREY, dash='2 4')
    y += h + 14

# arrows from the AI layer to the lanes
arrow([(480, 285), (550, 235)], GREEN)
arrow([(480, 285), (515, 285), (515, 395), (550, 395)], GREEN)
arrow([(480, 285), (515, 285), (515, 545), (550, 545)], GREEN, 'anonymized', 515, 470)
arrow([(480, 285), (515, 285), (515, 705), (550, 705)], GREEN)
arrow([(940, 160), (960, 160), (960, 275), (990, 275)], BLUE, dash='6 4')
text(955, 1090, 'new providers plug into the same AI layer, with the same rules', 13, 'bold', BLUE, 'middle')
arrow([(960, 275), (960, 495), (990, 495)], BLUE, dash='6 4')
arrow([(960, 495), (960, 675), (990, 675)], BLUE, dash='6 4')
arrow([(960, 675), (960, 910), (990, 910)], BLUE, dash='6 4')

out.append('</svg>')
with open(sys.argv[1], 'w') as fh:
    fh.write('\n'.join(out))
