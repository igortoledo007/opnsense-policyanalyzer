"""Architecture diagram of the OPNsense Policy Analyzer (Max Cyber IA), hand laid out, SVG."""
import html
import sys

W, H = 1800, 1250
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
rect(0, 0, W, H, fill='#ffffff', stroke='#ffffff', r=0)

# header
out.append('<rect x="0" y="0" width="%d" height="8" fill="%s"/>' % (W, ORANGE))
text(40, 54, 'OPNsense Policy Analyzer (Max Cyber IA) · architecture on the firewall', 28, 'bold')
text(40, 82, 'What the plugin installs and creates, how the parts talk to each other, and what may leave the box. '
             'Solid = always on the firewall · dashed = optional / opt-in.', 14.5, color=MUTED)
text(W - 40, 54, 'os-policyanalyzer · OPNsense 26.7', 14, 'bold', MUTED, 'end')
text(W - 40, 76, 'github.com/igortoledo007/opnsense-policyanalyzer', 12.5, color=FAINT, anchor='end')

# administrator
card(60, 104, 430, 52, 'Administrator', [], accent=INK)
text(190, 130, 'web browser · HTTPS · OPNsense login + ACL', 12.5, color=MUTED)

# ------------------------------------------------------------------------------------------- firewall frame
frame(30, 176, 1420, 860, 'OPNsense firewall', 'FreeBSD 15.1 · amd64',
      ORANGE, '#fffaf5')

# row A
card(60, 222, 430, 182, 'Web GUI', [
    (([('Firewall › Policy Analyzer', {'weight': 'bold'})], 13),),
    'Analysis · Incidents · Anomalies · Posture · Devices',
    'Vulnerabilities · AI Console · Reports · AI setup',
    (([('ACL ', {'weight': 'bold', 'color': MUTED}), ('page-firewall-policyanalyzer', {'mono': True, 'color': MUTED})], 11.5),),
    (([('    + ', {'color': MUTED}), ('page-firewall-policyanalyzer-admin', {'mono': True, 'color': MUTED})], 11.5),),
    'own gettext domain PolicyAnalyzer · 20 languages'], accent=ORANGE, badge='1', title_mono='lighttpd + PHP MVC')
card(530, 222, 330, 182, 'REST API', [
    (([('/api/policyanalyzer/*', {'mono': True, 'color': ORANGE})], 12.5),),
    'analysis · incidents · anomalies · posture',
    'vulns · devices · console · ai · setup',
    'change · quarantine · reports · settings',
    'minrule · shadowai',
    'CSRF-protected XHR from the pages'], accent=ORANGE)
rect(900, 222, 230, 182, fill=INK, stroke=INK, r=10, shadow=True)
out.append('<circle cx="926" cy="243" r="11" fill="%s"/>' % ORANGE)
text(926, 247, '2', 12, 'bold', '#ffffff', 'middle')
text(944, 248, 'configd', 15, 'bold', '#ffffff')
for i, s in enumerate(['129 actions, run as root', 'actions_policyanalyzer.conf', 'actions_pa_*.conf',
                       'the only path from the GUI', 'to privileged work']):
    text(918, 274 + i * 19, s, 12.5, color='#e2e8f0', mono=(1 <= i <= 2))
card(1170, 222, 250, 182, 'Cron', [
    'core cron model, no files of its own',
    (([('quarantine ', {'weight': 'bold'}), ('every 5 min', {'color': MUTED})], 12.5),),
    (([('incidents ', {'weight': 'bold'}), ('every 5 min', {'color': MUTED})], 12.5),),
    (([('anomalies ', {'weight': 'bold'}), ('every 15 min', {'color': MUTED})], 12.5),),
    'collectors · AI queue · reports'], accent=GREY, title_mono='scheduled')

# row B
card(60, 452, 300, 252, 'Data sources', [
    (([('read only', {'color': GREEN, 'weight': 'bold'})], 12),),
    '• config.xml + rule counters',
    '• filter log (pf)',
    '• Suricata eve.json',
    '• Unbound reporting (DuckDB)',
    '• Kea leases · ARP / NDP',
    '• Insight / NetFlow',
    '• GeoIP alias lists · ASN table',
    '• Monit SMTP settings'], accent=GREY)

ex, ey, ew, eh = 400, 452, 640, 252
rect(ex, ey, ew, eh, fill='#ffffff', stroke=ORANGE, sw=1.6, shadow=True)
out.append('<circle cx="%g" cy="%g" r="11" fill="%s"/>' % (ex + 26, ey + 21, ORANGE))
text(ex + 26, ey + 25, '3', 12, 'bold', '#ffffff', 'middle')
rich(ex + 44, ey + 26, [('Engine', {'weight': 'bold'})], 15)
text(ex + 112, ey + 26, '/usr/local/opnsense/scripts/policyanalyzer', 11.5, color=MUTED, mono=True)
text(ex + ew - 16, ey + 26, 'Python standard library only', 12, 'bold', GREEN, 'end')
cells = [('rule analysis', 'shadowed · redundant · unused · broad'), ('incidents', 'scored, correlated cases'),
         ('anomalies', 'beaconing · DNS · volume · scans'),
         ('posture', 'hardening checks, score'), ('exposure + vulns', 'NVD · KEV · EPSS · P1–P4'),
         ('devices', 'passive inventory, risk'),
         ('quarantine', 'escalating ladder, guards'), ('AI layer', 'router · anonymizer · validation'),
         ('reports', 'PDF + e-mail · 20 languages')]
cw, ch = (ew - 40) / 3.0, 48
for i, (t, s) in enumerate(cells):
    cx, cy = ex + 20 + (i % 3) * cw, ey + 42 + (i // 3) * (ch + 8)
    hot = t in ('quarantine', 'AI layer')
    rect(cx + 3, cy, cw - 6, ch, fill='#fff7ed' if hot else '#f1f5f9', stroke='#fdba74' if hot else '#e2e8f0', sw=1, r=7)
    text(cx + cw / 2, cy + 20, t, 13.5, 'bold', anchor='middle')
    text(cx + cw / 2, cy + 37, s, 11, color=MUTED, anchor='middle')
rect(ex + 23, ey + 42 + 3 * (ch + 8), ew - 46, 30, fill='#fef3c7', stroke='#fcd34d', sw=1, r=7)
rich(ex + ew / 2, ey + 42 + 3 * (ch + 8) + 20, [('change journal  ', {'weight': 'bold'}),
                                               ('every change is simulated → applied → revertible', {'color': MUTED})],
     12.5, anchor='middle')

card(1080, 452, 340, 252, 'Enforcement', [
    (([('optional · created by the quarantine assistant', {'color': RED, 'weight': 'bold'})], 11.5),),
    (([('pa_quarantine', {'mono': True}), ('   External alias', {'color': MUTED})], 12.5),),
    (([('pa_never_block', {'mono': True}), ('  allow-list alias', {'color': MUTED})], 12.5),),
    (([('floating block rule ', {'weight': 'bold'}), ('"Max Cyber IA"', {'color': MUTED})], 12.5),),
    '→ pf (packet filter) blocks the sources',
    '',
    'never touches other rules or aliases',
    'every step simulated first, revertible',
    'from the action history'], accent=RED, fill='#fff5f5', badge='4')

# row C: storage
frame(60, 740, 900, 280, 'Storage', 'ZFS or UFS root',
      BLUE, '#f5f9ff')
card(80, 790, 260, 210, 'State', [
    (([('/var/db/policyanalyzer', {'mono': True, 'color': BLUE})], 12),),
    'SQLite: quarantine ledger, incidents,',
    'anomalies, devices, posture, collectors',
    'JSON: findings, settings, journal',
    (([('/var/log/policyanalyzer', {'mono': True, 'color': BLUE})], 12),),
    'plain logs, rotated',
    'any root file system (ZFS or UFS)'], accent=BLUE, badge='5')
card(355, 790, 330, 210, 'Models · setup step 3', [
    (([('ZFS  ', {'weight': 'bold', 'color': BLUE}), ('zroot/ai', {'mono': True, 'color': BLUE}),
       (' → /var/db/ai', {'mono': True, 'color': MUTED})], 12),),
    'recordsize=1M · compression=off · atime=off',
    (([('UFS  ', {'weight': 'bold', 'color': BLUE}), ('/var/db/ai/models', {'mono': True, 'color': BLUE}),
       (' (directory)', {'color': MUTED})], 12),),
    'shares the system disk · space guard',
    'leaves ≥ max(20 % of size, 2 GiB) free',
    (([('UFS opt-in  ', {'weight': 'bold', 'color': BLUE}), ('aipool/ai', {'mono': True, 'color': BLUE})], 12),),
    (([('← /var/db/ai.zpool.img', {'mono': True, 'color': MUTED}), (' (md vnode)', {'color': MUTED})], 11.5),),
    'fixed size · ARC cap · own rc.d at boot'], accent=BLUE)
card(700, 790, 245, 210, 'Jail root · step 4', [
    (([('ZFS  ', {'weight': 'bold', 'color': BLUE}), ('zroot/ai/jail', {'mono': True, 'color': BLUE})], 12),),
    (([('UFS  ', {'weight': 'bold', 'color': BLUE}), ('/var/db/ai/jail', {'mono': True, 'color': BLUE})], 12),),
    (([('pool  ', {'weight': 'bold', 'color': BLUE}), ('aipool/ai/jail', {'mono': True, 'color': BLUE})], 12),),
    (([('→  ', {'color': MUTED}), ('/var/db/ai/jail', {'mono': True, 'color': MUTED})], 12),),
    'FreeBSD 15.1 base.txz (~0.7 GB)',
    '+ pkg ollama and dependencies',
    'jail root, ~0.8 GB on disk'], accent=BLUE)

# row C: jail
frame(1000, 740, 420, 280, 'Local AI runtime', 'jail "ollama"', GREEN, '#f3fcf8')
card(1020, 790, 380, 210, 'Ollama ≥ 0.17.1', [
    (([('127.0.0.1:11434', {'mono': True, 'color': GREEN, 'weight': 'bold'}), ('  (host only)', {'color': MUTED})], 12.5),),
    'non-VNET · ip4 = 127.0.0.1 only · no egress',
    'runs as nobody · cpuset · nice · RCTL memory',
    (([('models: nullfs rw → ', {'color': MUTED}), ('/var/lib/ollama/models', {'mono': True, 'color': MUTED})], 12),),
    (([('boot: ', {'color': MUTED}), ('/etc/jail.conf.d/ollama.conf', {'mono': True, 'color': MUTED})], 12),),
    'e.g. qwen3:4b · qwen3:8b · qwen3:30b-a3b',
    'default limits: CPUs 2–3 · 2 threads · ctx 8192'], accent=GREEN, badge='6')

# ------------------------------------------------------------------------------------------- outside
frame(1480, 420, 290, 616, 'Outside the firewall', 'optional', GREY, '#fafafa', dash='6 5')
card(1500, 470, 250, 92, 'SMTP server', ['Monit settings or own SMTP', 'reports and alerts'], accent=GREY, dash='5 4')
card(1500, 582, 250, 110, 'Remote AI providers', ['Ollama server in the LAN', 'Anthropic API', 'claude-bridge (LAN)',
                                                  ], accent=GREY, dash='5 4')
card(1500, 712, 250, 110, 'Feeds (opt-in)', ['NVD · CISA KEV · EPSS · OSV', 'IEEE OUI',
                                             'MaxMind GeoLite2 (own key)'], accent=GREY, dash='5 4')
card(1500, 842, 250, 110, 'Setup downloads', ['download.freebsd.org', 'pkg.FreeBSD.org',
                                              'registry.ollama.ai · SHA-256'], accent=GREY, dash='5 4')
card(1500, 104, 250, 52, 'Mailbox', [], accent=INK)
text(1600, 130, 'PDF reports, alerts', 12.5, color=MUTED)

# ------------------------------------------------------------------------------------------- flows
arrow([(440, 156), (440, 222)], INK)
text(450, 170, 'HTTPS', 11, 'bold', INK)
arrow([(490, 313), (530, 313)], ORANGE)
text(510, 304, 'XHR', 10.5, 'bold', ORANGE, 'middle')
arrow([(860, 313), (900, 313)], ORANGE)
text(880, 304, 'configctl', 10, 'bold', ORANGE, 'middle')
arrow([(1170, 313), (1130, 313)], FAINT)
arrow([(1015, 404), (1015, 452)], INK, 'runs as root', 1015, 432)
arrow([(360, 578), (400, 578)], GREEN)
text(380, 569, 'read', 10.5, 'bold', GREEN, 'middle')
arrow([(1040, 578), (1080, 578)], RED)
text(1060, 569, 'apply', 10.5, 'bold', RED, 'middle')
arrow([(520, 704), (520, 724), (310, 724), (310, 790)], BLUE, 'read / write', 415, 728)
arrow([(900, 704), (900, 724), (1340, 724), (1340, 790)], GREEN, 'HTTP 127.0.0.1:11434', 1120, 728)
arrow([(945, 895), (1020, 895)], BLUE)
text(982, 886, 'jail root', 10.5, 'bold', BLUE, 'middle')
arrow([(525, 1000), (525, 1028), (1100, 1028), (1100, 1000)], BLUE, 'nullfs rw · models', 660, 1032)
# opt-in bus to the right column
arrow([(1040, 472), (1060, 472), (1060, 428), (1462, 428), (1462, 516), (1500, 516)], GREY, 'opt-in · anonymized', 1250, 432,
      dash='6 4')
arrow([(1462, 516), (1462, 637), (1500, 637)], GREY, dash='6 4')
arrow([(1462, 637), (1462, 767), (1500, 767)], GREY, dash='6 4')
arrow([(1500, 897), (1466, 897), (1466, 1052), (815, 1052), (815, 1000)], GREY, 'setup only · by the host', 1140,
      1056, dash='6 4')
arrow([(1730, 470), (1730, 156)], GREY, dash='6 4')

# ------------------------------------------------------------------------------------------- setup sequence
sy = 1084
text(40, sy, 'AI setup assistant', 17, 'bold')
text(210, sy, 'eight steps · each one simulated first, written to the action history and revertible ("Remove local AI")',
     13.5, color=MUTED)
steps = [('Check', 'CPU, AVX2, RAM, load', 'file system · free space'), ('Provider', 'local · LAN', 'API · bridge'),
         ('Storage', 'ZFS dataset or UFS dir', '(opt-in file pool)'), ('Runtime', 'jail root · base.txz', 'pkg ollama · jail.conf'),
         ('Model', 'pull + SHA-256', 'or GGUF import'), ('Limits', 'cpuset · threads', 'context · RAM'),
         ('Test', 'benchmark', 'first explanation'), ('Finish', 'settings saved', 'AI on in the GUI')]
n = len(steps)
gx, gw = 40, (W - 80) / n
for i, (t, a, b) in enumerate(steps):
    x0, y0, h0 = gx + i * gw, sy + 18, 112
    tip = 18
    pts = [(x0, y0), (x0 + gw - tip, y0), (x0 + gw, y0 + h0 / 2), (x0 + gw - tip, y0 + h0), (x0, y0 + h0)]
    if i:
        pts.append((x0 + tip, y0 + h0 / 2))
    storage = t in ('Storage', 'Runtime')
    fill = '#eff6ff' if storage else ('#fff7ed' if i % 2 == 0 else '#ffedd5')
    stroke = BLUE if storage else '#fdba74'
    out.append('<polygon points="%s" fill="%s" stroke="%s" stroke-width="1.3"/>'
               % (' '.join('%g,%g' % p for p in pts), fill, stroke))
    cx = x0 + gw / 2 + (tip / 2 if i else 0) - tip / 2
    out.append('<circle cx="%g" cy="%g" r="13" fill="%s"/>' % (cx, y0 + 26, BLUE if storage else ORANGE))
    text(cx, y0 + 31, str(i + 1), 13, 'bold', '#ffffff', 'middle')
    text(cx, y0 + 60, t, 15, 'bold', anchor='middle')
    text(cx, y0 + 80, a, 12, color=MUTED, anchor='middle')
    text(cx, y0 + 96, b, 12, color=MUTED, anchor='middle')

out.append('</svg>')
with open(sys.argv[1], 'w') as fh:
    fh.write('\n'.join(out))
