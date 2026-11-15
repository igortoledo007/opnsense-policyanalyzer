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

    Inferred risk of a LAN device without knowing its firmware version (proposta 8.2): it is a hint, never a
    confirmed vulnerability.

      port_forward    destination NAT sends internet traffic to it                         high
      vendor_kev      its manufacturer (device makers of VENDOR_HISTORY, or any vendor of a camera/NVR/AP) has
                      entries in CISA KEV (local cache of the vulns module)                 medium
                      (high for cameras/NVRs/APs, the usual targets of mass exploitation)
      vendor_history  manufacturer with a public history of mass exploited devices (built-in list)  medium
      new_device      first seen less than 7 days ago and not marked as known             medium
      unknown_type    no signal for the type and not known                                low
"""

from . import common

# manufacturers with campaigns of mass exploitation of their devices (botnets, KEV entries)
VENDOR_HISTORY = {
    'hikvision': 'IP cameras/NVRs repeatedly exploited (e.g. CVE-2021-36260)',
    'dahua': 'cameras/NVRs with authentication bypasses exploited in the wild',
    'tp-link': 'routers/APs targeted by botnets (Mirai variants, KEV entries)',
    'd-link': 'end-of-life routers/NAS with unpatched, exploited flaws',
    'zyxel': 'firewalls/routers with exploited command injection flaws',
    'tenda': 'routers exploited by botnets',
    'netgear': 'routers with exploited remote code execution flaws',
    'mikrotik': 'RouterOS devices exploited for botnets (e.g. Meris)',
    'huawei': 'home gateways exploited by Mirai variants',
    'realtek': 'devices built on the Realtek SDK exploited by botnets',
    'ubiquiti': 'EdgeRouter/UniFi devices abused by botnets when exposed',
    'intelbras': 'DVRs/cameras with published authentication flaws',
}
LEVELS = ('info', 'low', 'medium', 'high')
TARGETED_TYPES = ('camera', 'nvr', 'ap')


def kev_vendor_counts(kev_items):
    """ {lowercase vendorProject: count} from the vulns KEV cache (vendor names are kept there) """
    counts = {}
    for info in (kev_items or {}).values():
        vendor = (info.get('vendor') or '').strip().lower()
        if vendor:
            counts[vendor] = counts.get(vendor, 0) + 1
    return counts


def _vendor_key(vendor):
    low = (vendor or '').lower()
    for key in VENDOR_HISTORY:
        if key in low:
            return key
    return None


def assess(dev, kev_counts=None, forwards=None, now=None, new_days=common.NEW_DAYS):
    """ :param dev: {vendor, type, known, first_seen, ips[]}; :return: {level, reasons[{code, level, text}]} """
    now = common.now() if now is None else now
    reasons = []
    for ip in dev.get('ips') or []:
        for fwd in (forwards or {}).get(ip, []):
            reasons.append({'code': 'port_forward', 'level': 'high',
                            'text': 'reachable from the internet: %s NAT %s/%s -> %s%s' % (
                                fwd['kind'], fwd['proto'], fwd['port'], ip,
                                (' (%s)' % fwd['descr']) if fwd.get('descr') else '')})
    vendor = dev.get('vendor') or ''
    key = _vendor_key(vendor)
    low = vendor.lower()
    kev = 0
    for name, count in (kev_counts or {}).items():
        if name and (name in low or (key and key in name)):
            kev += count
    targeted = dev.get('type') in TARGETED_TYPES
    # big platform vendors (Apple, Google, Microsoft...) all have KEV entries for their software: the count only
    # means something for device makers (built-in list) or for the types botnets target
    if kev and (key or targeted):
        reasons.append({'code': 'vendor_kev', 'level': 'high' if targeted else 'medium',
                        'text': '%d CISA KEV entr%s for this manufacturer (%s); firmware version unknown, so '
                                'this is a hint, not a confirmed vulnerability' % (kev, 'y' if kev == 1 else 'ies',
                                                                                  vendor)})
    elif key:
        reasons.append({'code': 'vendor_history', 'level': 'medium' if targeted else 'low',
                        'text': '%s: %s' % (vendor, VENDOR_HISTORY[key])})
    first = dev.get('first_seen')
    if not dev.get('known') and first and now - first < new_days * 86400:
        reasons.append({'code': 'new_device', 'level': 'medium',
                        'text': 'new device: first seen %.0f hour(s) ago and not marked as known'
                                % ((now - first) / 3600.0)})
    if dev.get('type') in (None, '', 'unknown') and not dev.get('known'):
        reasons.append({'code': 'unknown_type', 'level': 'low', 'text': 'type unknown: identify it or mark it as known'})
    level = 'info'
    for reason in reasons:
        if LEVELS.index(reason['level']) > LEVELS.index(level):
            level = reason['level']
    return {'level': level, 'reasons': reasons, 'kev_vendor_entries': kev}
