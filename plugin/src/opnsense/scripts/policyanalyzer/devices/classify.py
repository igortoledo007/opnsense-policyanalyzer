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

    Heuristic device type from passive signals (manufacturer, hostname, randomised MAC), with a confidence and
    the reasons ("why"). The AI may suggest another type (explain.py); the owner's choice always wins.
    Types: camera, nvr, tv, phone, pc, ap, iot, printer, console, unknown.
"""

import re

# (keyword in the manufacturer name, type, weight). Weight 3 = the vendor makes (almost) only that.
VENDORS = [
    ('hikvision', 'camera', 3), ('dahua', 'camera', 3), ('reolink', 'camera', 3), ('axis communications', 'camera', 3),
    ('uniview', 'camera', 3), ('ezviz', 'camera', 3), ('amcrest', 'camera', 3), ('hanwha', 'camera', 3),
    ('intelbras', 'camera', 2), ('wyze', 'camera', 2), ('foscam', 'camera', 3), ('vivotek', 'camera', 3),
    ('roku', 'tv', 3), ('hisense', 'tv', 3), ('vizio', 'tv', 3), ('tcl ', 'tv', 2), ('lg electronics', 'tv', 2),
    ('sony', 'tv', 1), ('samsung electronics', 'tv', 1), ('philips', 'tv', 1),
    ('apple', 'phone', 1), ('xiaomi', 'phone', 1), ('oneplus', 'phone', 2), ('motorola mobility', 'phone', 2),
    ('huawei device', 'phone', 2), ('oppo', 'phone', 2), ('vivo mobile', 'phone', 2), ('realme', 'phone', 2),
    ('google', 'iot', 1),
    ('intel corporate', 'pc', 2), ('dell', 'pc', 2), ('lenovo', 'pc', 2), ('hewlett packard', 'pc', 1),
    ('asustek', 'pc', 1), ('micro-star', 'pc', 2), ('gigabyte', 'pc', 2), ('liteon', 'pc', 1), ('azurewave', 'pc', 1),
    ('acer', 'pc', 2), ('realtek', 'pc', 1), ('microsoft', 'pc', 1),
    ('ubiquiti', 'ap', 3), ('tp-link', 'ap', 2), ('mikrotik', 'ap', 3), ('ruckus', 'ap', 3), ('aruba', 'ap', 3),
    ('cisco meraki', 'ap', 3), ('netgear', 'ap', 2), ('zyxel', 'ap', 2), ('d-link', 'ap', 2), ('tenda', 'ap', 2),
    ('mercusys', 'ap', 2), ('huawei technologies', 'ap', 1), ('cambium', 'ap', 3), ('grandstream', 'ap', 1),
    ('espressif', 'iot', 3), ('tuya', 'iot', 3), ('shelly', 'iot', 3), ('allterco', 'iot', 3), ('itead', 'iot', 3),
    ('signify', 'iot', 3), ('amazon technologies', 'iot', 2), ('raspberry pi', 'iot', 1), ('sonos', 'iot', 2),
    ('ecobee', 'iot', 3), ('nest labs', 'iot', 3), ('wiz connected', 'iot', 3), ('broadlink', 'iot', 3),
    ('brother industries', 'printer', 3), ('canon', 'printer', 2), ('seiko epson', 'printer', 3),
    ('lexmark', 'printer', 3), ('kyocera', 'printer', 3), ('xerox', 'printer', 3), ('ricoh', 'printer', 3),
    ('nintendo', 'console', 3), ('sony interactive', 'console', 3),
]

HOSTNAMES = [
    (r'\b(ip)?cam(era)?\b|ipc[-_]?\d|^cam[-_]', 'camera', 3), (r'\b(nvr|dvr|xvr)\b', 'nvr', 3),
    (r'\b(smart)?tv\b|bravia|tizen|webos|chromecast|fire[-_]?tv|roku|androidtv|tv[-_]?box|mibox', 'tv', 3),
    (r'iphone|ipad|galaxy|^sm-[a-z]\d|android|redmi|^moto|pixel|poco', 'phone', 3),
    (r'^desktop-|^laptop-|macbook|imac|^pc[-_]|notebook|workstation|thinkpad|win(dows)?\d*', 'pc', 3),
    (r'\b(ap|wap)\d*\b|unifi|^uap|^eap\d|access[-_]?point|mesh|deco|omada|router|switch', 'ap', 2),
    (r'^esp[-_]|tasmota|shelly|sonoff|tuya|^wled|hue|echo|alexa|nest|plug|bulb|lamp|sensor|^ha$|homeassistant',
     'iot', 3),
    (r'printer|^hp[0-9a-f]{6}|^brw|^epson|laserjet|officejet|deskjet|mfc[-_]', 'printer', 3),
    (r'playstation|^ps[45]|xbox|nintendo|switch-', 'console', 3),
]
HOSTNAME_RES = [(re.compile(p, re.I), t, w) for p, t, w in HOSTNAMES]


def classify(vendor=None, hostname=None, randomized=False):
    """ :return: {type, confidence: low|medium|high, score, why[]} """
    scores = {}
    why = []
    low_vendor = (vendor or '').lower()
    for key, kind, weight in VENDORS:
        if key in low_vendor:
            scores[kind] = scores.get(kind, 0) + weight
            why.append('manufacturer "%s" usually makes %s devices' % (vendor, kind))
            break
    for regex, kind, weight in HOSTNAME_RES:
        if hostname and regex.search(hostname):
            scores[kind] = scores.get(kind, 0) + weight
            why.append('hostname "%s" looks like a %s' % (hostname, kind))
            break
    if randomized:
        scores['phone'] = scores.get('phone', 0) + 1
        why.append('randomised (private) MAC address: typical of phones, tablets and recent laptops')
    if not scores:
        return {'type': 'unknown', 'confidence': 'low', 'score': 0,
                'why': why or ['no manufacturer or hostname signal']}
    kind, best = max(scores.items(), key=lambda kv: (kv[1], kv[0] != 'phone'))
    confidence = 'high' if best >= 5 else ('medium' if best >= 3 else 'low')
    return {'type': kind, 'confidence': confidence, 'score': best, 'why': why}
