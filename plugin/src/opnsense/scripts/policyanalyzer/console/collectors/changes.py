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

    Configuration changes collector (read only): "what changed since yesterday?"

    OPNsense keeps a copy of config.xml for every saved change in /conf/backup/config-<epoch>.xml (the
    configuration *after* that change, with its <revision>: time, user, description).  This collector lists
    the revisions inside the window and compares the newest backup from before the window (the baseline)
    with the current /conf/config.xml: rules, NAT, aliases, reservations and host overrides item by item,
    every other section by name.  Only non secret fields are shown with their values; for everything else
    (users, certificates, keys, passwords, tokens) only the names of the changed fields are reported.
"""

import hashlib
import os
import re
import time
import xml.etree.ElementTree as ET

from ..common import clean_text

BACKUP_RE = re.compile(r'^config-(\d{9,11})(?:\.\d+)?\.xml$')
REVISION_RE = re.compile(rb'<revision>(.*?)</revision>', re.S)
MAX_REVISIONS = 25
MAX_ITEMS = 12

RULE_VALUES = ('enabled', 'disabled', 'action', 'type', 'quick', 'interface', 'interfacenot', 'direction',
               'ipprotocol', 'protocol', 'source_net', 'source_not', 'source_port', 'destination_net',
               'destination_not', 'destination_port', 'log', 'sequence', 'description', 'descr', 'gateway',
               'categories', 'statetype', 'target', 'local-port', 'floating', 'source', 'destination')
ALIAS_VALUES = ('name', 'type', 'enabled', 'description', 'proto', 'interface', 'updatefreq')
HOST_VALUES = ('enabled', 'hostname', 'domain', 'server', 'ip_address', 'description', 'rr')

COLLECTIONS = (
    # label, path, key, fields whose values may be shown
    ('filter rules', './OPNsense/Firewall/Filter/rules/rule', 'uuid', RULE_VALUES),
    ('source NAT rules', './OPNsense/Firewall/Filter/snatrules/rule', 'uuid', RULE_VALUES),
    ('one-to-one NAT rules', './OPNsense/Firewall/Filter/onetoone/rule', 'uuid', RULE_VALUES),
    ('legacy filter rules', './filter/rule', 'index', RULE_VALUES),
    ('port forwards', './nat/rule', 'index', RULE_VALUES),
    ('outbound NAT rules', './nat/outbound/rule', 'index', RULE_VALUES),
    ('aliases', './OPNsense/Firewall/Alias/aliases/alias', 'name', ALIAS_VALUES),
    ('DHCP reservations (Kea)', './OPNsense/Kea/dhcp4/reservations/reservation', 'uuid', HOST_VALUES),
    ('DNS host overrides (Unbound)', './OPNsense/unboundplus/hosts/host', 'uuid', HOST_VALUES),
    ('users', './system/user', 'name', ()),
)


def backups(directory):
    """ [(epoch, path)] oldest first """
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    result = []
    for name in names:
        m = BACKUP_RE.match(name)
        if m:
            result.append((int(m.group(1)), os.path.join(directory, name)))
    result.sort()
    return result


def revision(path, max_bytes=1024 * 1024):
    """ {time, user, description} of one config file, read from its head only """
    try:
        with open(path, 'rb') as handle:
            head = handle.read(max_bytes)
    except OSError:
        return None
    m = REVISION_RE.search(head)
    if not m:
        return None
    block = m.group(1).decode('utf-8', 'replace')

    def tag(name):
        t = re.search(r'<%s>(.*?)</%s>' % (name, name), block, re.S)
        return t.group(1).strip() if t else ''
    try:
        epoch = float(tag('time') or 0)
    except ValueError:
        epoch = 0
    desc = re.sub(r'&[a-z]+;', ' ', tag('description'))
    return {'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch)) if epoch else None,
            'epoch': int(epoch), 'user': clean_text(tag('username'), 80), 'what': clean_text(desc, 160)}


def _fields(node):
    return {child.tag: (child.text or '').strip() if len(child) == 0 else _digest(child)
            for child in node if child.tag not in ('audit', 'updated', 'created')}


def _digest(node):
    return hashlib.sha1(ET.tostring(node)).hexdigest()[:12]


def _label(fields, key, keyval):
    for name in ('description', 'descr', 'name', 'hostname'):
        if fields.get(name):
            return clean_text(fields[name], 80)
    return '%s %s' % (key, keyval)


def _items(root, path, key):
    out = {}
    for idx, node in enumerate(root.findall(path)):
        if key == 'uuid':
            keyval = node.get('uuid') or 'index-%d' % idx
        elif key == 'name':
            keyval = (node.findtext('name') or '').strip() or 'index-%d' % idx
        else:
            keyval = (node.findtext('tracker') or '').strip() or 'index-%d' % idx
        out[keyval] = _fields(node)
    return out


def _diff_collection(old_root, new_root, label, path, key, visible):
    old, new = _items(old_root, path, key), _items(new_root, path, key)
    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]
    changed = [k for k in new if k in old and new[k] != old[k]]
    if not (added or removed or changed):
        return None

    def show(fields):
        return {k: clean_text(v, 120) for k, v in fields.items() if k in visible and v}

    result = {'collection': label, 'added': len(added), 'removed': len(removed), 'changed': len(changed)}
    result['added_items'] = [dict(item=_label(new[k], key, k), **show(new[k])) for k in added[:MAX_ITEMS]]
    result['removed_items'] = [dict(item=_label(old[k], key, k), **show(old[k])) for k in removed[:MAX_ITEMS]]
    changes = []
    for k in changed[:MAX_ITEMS]:
        before, after = old[k], new[k]
        names = sorted(set(before) | set(after))
        diff = [n for n in names if before.get(n) != after.get(n)]
        item = {'item': _label(after, key, k), 'fields': diff}
        values = {n: {'before': clean_text(before.get(n, ''), 120), 'after': clean_text(after.get(n, ''), 120)}
                  for n in diff if n in visible}
        if 'content' in diff and label == 'aliases':
            b = set(x.strip() for x in re.split(r'[\n,]', before.get('content', '')) if x.strip())
            a = set(x.strip() for x in re.split(r'[\n,]', after.get('content', '')) if x.strip())
            values['content'] = {'added': sorted(a - b)[:10], 'removed': sorted(b - a)[:10],
                                 'entries_before': len(b), 'entries_after': len(a)}
        if values:
            item['values'] = values
        changes.append(item)
    result['changed_items'] = changes
    if label == 'users':
        # user names are personal data: under the "user" key the anonymizer always hides them
        for name in ('added_items', 'removed_items', 'changed_items'):
            for item in result[name]:
                item['user'] = item.pop('item')
    for name in ('added_items', 'removed_items', 'changed_items'):
        if not result[name]:
            del result[name]
    return result


def _sections(root):
    """ top level sections (and OPNsense/* models) -> (digest, {child tag: digest}) """
    out = {}
    for child in root:
        if child.tag == 'revision':
            continue
        if child.tag == 'OPNsense':
            for model in child:
                out['OPNsense/' + model.tag] = model
        else:
            out[child.tag] = child
    return out


def diff(old_path, new_path):
    try:
        old_root = ET.parse(old_path).getroot()
        new_root = ET.parse(new_path).getroot()
    except (OSError, ET.ParseError) as exc:
        return {'error': 'unable to compare: %s' % exc.__class__.__name__}
    collections = []
    for label, path, key, visible in COLLECTIONS:
        item = _diff_collection(old_root, new_root, label, path, key, visible)
        if item:
            collections.append(item)
    old_s, new_s = _sections(old_root), _sections(new_root)
    sections = []
    for name in sorted(set(old_s) | set(new_s)):
        if name not in old_s:
            sections.append({'section': name, 'change': 'added'})
            continue
        if name not in new_s:
            sections.append({'section': name, 'change': 'removed'})
            continue
        if ET.tostring(old_s[name]) == ET.tostring(new_s[name]):
            continue
        old_c = {}
        for child in old_s[name]:
            old_c.setdefault(child.tag, []).append(ET.tostring(child))
        new_c = {}
        for child in new_s[name]:
            new_c.setdefault(child.tag, []).append(ET.tostring(child))
        parts = sorted(t for t in set(old_c) | set(new_c) if old_c.get(t) != new_c.get(t))
        sections.append({'section': name, 'change': 'modified', 'parts': parts[:10]})
    return {'collections': collections, 'sections_changed': sections}


def collect(paths, window, budget=None, now=None):
    now = time.time() if now is None else now
    files = backups(paths.backups)
    if not files:
        return {'available': False, 'message': 'no configuration backups found in %s' % paths.backups}
    since, until = window['since'], window['until']
    revisions = []
    for epoch, path in reversed(files):
        if epoch < since:
            break
        if epoch <= until + 60:
            rev = revision(path) or {'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch))}
            revisions.append(rev)
        if budget is not None and budget.expired():
            break
    baseline = None
    for epoch, path in reversed(files):
        if epoch < since:
            baseline = (epoch, path)
            break
    note = None
    if baseline is None:
        baseline = files[0]
        note = 'the oldest backup is newer than the start of the window; changes before it are not visible'
    result = {
        'available': True,
        'source': 'configuration history (/conf/backup) compared with the current configuration',
        'window': window['label'],
        'backups_total': len(files),
        'oldest_backup': time.strftime('%Y-%m-%d %H:%M', time.localtime(files[0][0])),
        'baseline': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(baseline[0])),
        'revisions_in_window': len(revisions),
        'revisions': [{k: v for k, v in r.items() if k != 'epoch'} for r in revisions[:MAX_REVISIONS]],
    }
    if note:
        result['note'] = note
    current_rev = revision(paths.config)
    if current_rev:
        result['current_revision'] = {k: v for k, v in current_rev.items() if k != 'epoch'}
    if window['until'] < now - 120:
        # a closed window in the past (e.g. "yesterday"): compare its two ends
        end = None
        for epoch, path in reversed(files):
            if epoch <= until:
                end = (epoch, path)
                break
        target = end[1] if end else paths.config
        result['compared_with'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end[0])) if end else 'current'
    else:
        target = paths.config
        result['compared_with'] = 'current configuration'
    if not revisions:
        result['message'] = 'no configuration change was saved in this window'
        result['diff'] = {'collections': [], 'sections_changed': []}
        return result
    result['diff'] = diff(baseline[1], target)
    return result
