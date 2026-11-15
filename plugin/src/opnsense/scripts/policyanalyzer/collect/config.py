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

    Config collector (port of "opn.py coletar/historico"): versions the sanitized config.xml in
    /var/db/policyanalyzer/collect/config.db.

    Sources, read directly: /conf/backup/config-*.xml (the core keeps one file per saved revision) and
    /conf/config.xml (the live file).  New files (name/size/mtime not seen before) are parsed, sanitized
    (sanitize.py) and registered in revision order when the sanitized XML is new (sha256).  Each new snapshot
    is itemized (same sections as opn.py) and diffed against the previous snapshot by revision time: one row
    in "changes" per added / removed / changed item, with the changed fields and who/when from <revision>
    (<username> "user@address", <time>, <description>).  The first run walks the whole /conf/backup (the
    oldest snapshot is the baseline and has no changes); later runs only see the new revisions.
"""

import glob
import hashlib
import json
import os
import re
import time
import xml.etree.ElementTree as ET
import zlib

from . import common, sanitize, store

MAX_FILES = 400                  # per run (the rest is taken by the next run)
_USER_RE = re.compile(r'^(?P<user>.*?)@(?P<ip>[0-9A-Fa-f:.]+)$')


def split_user(username):
    """ "root@192.0.2.10" -> ("root", "192.0.2.10"); "(root)" -> ("(root)", None) """
    if not username:
        return None, None
    match = _USER_RE.match(username.strip())
    if match:
        return match.group('user'), match.group('ip')
    return username.strip(), None


def version(ctx):
    try:
        with open(ctx.version_file) as handle:
            data = json.load(handle)
        return data.get('product_version') or data.get('CORE_PKGVERSION') or data.get('CORE_VERSION')
    except (OSError, ValueError):
        return None


def candidates(ctx):
    files = sorted(glob.glob(os.path.join(ctx.backup_dir, 'config-*.xml')))
    if os.path.exists(ctx.config_xml):
        files.append(ctx.config_xml)
    return files


def _revision(root):
    rev = root.find('./revision')
    if rev is None:
        return None, None, None
    try:
        when = float(rev.findtext('time') or '')
    except ValueError:
        when = None
    return when, rev.findtext('username'), rev.findtext('description')


def register(con, ctx, xml_bytes, origin, source_file, key, ver=None, now=None):
    """ :return: dict (snapshot id, changes) or None when the sanitized XML is already known """
    root = ET.fromstring(xml_bytes)
    root, masked = sanitize.sanitize(root, key)
    clean = ET.tostring(root, encoding='utf-8')
    sha = hashlib.sha256(clean).hexdigest()
    if con.execute('SELECT 1 FROM snapshots WHERE sha256 = ?', (sha,)).fetchone():
        return None
    rev_time, rev_user, rev_descr = _revision(root)
    author, author_ip = split_user(rev_user)
    host = '.'.join(filter(None, [root.findtext('./system/hostname'), root.findtext('./system/domain')]))
    cur = con.execute(
        'INSERT INTO snapshots (collected_at, origin, source_file, sha256, revision_time, revision_user, author,'
        ' author_ip, revision_descr, hostname, version, size, masked, xml) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (now or time.time(), origin, source_file, sha, rev_time, rev_user, author, author_ip, rev_descr, host,
         ver, len(clean), masked, zlib.compress(clean, 9)))
    snap = cur.lastrowid
    items = sanitize.extract_items(root)
    con.executemany('INSERT OR IGNORE INTO blobs (sha256, content) VALUES (?, ?)',
                    [(h, js) for (_d, js, h) in items.values()])
    con.executemany('INSERT INTO items (snapshot_id, section, key, descr, sha256) VALUES (?,?,?,?,?)',
                    [(snap, s, k, d, h) for (s, k), (d, _js, h) in items.items()])
    # previous snapshot by revision time (local chain only: imported history uses another HMAC key)
    prev = con.execute(
        "SELECT id FROM snapshots WHERE id <> ? AND origin NOT LIKE 'import:%' AND "
        "coalesce(revision_time, 0) <= coalesce(?, 0) ORDER BY revision_time DESC, id DESC LIMIT 1",
        (snap, rev_time)).fetchone()
    changes = 0
    if prev:
        old = {(s, k): (d, h) for s, k, d, h in con.execute(
            'SELECT section, key, descr, sha256 FROM items WHERE snapshot_id = ?', (prev[0],))}
        rows = []
        for k in sorted(set(old) | set(items)):
            if k not in old:
                kind, descr, fields = 'added', items[k][0], sanitize.field_diff(None, items[k][1], limit=12)
            elif k not in items:
                kind, descr, fields = 'removed', old[k][0], []
            elif old[k][1] != items[k][2]:
                before = con.execute('SELECT content FROM blobs WHERE sha256 = ?', (old[k][1],)).fetchone()
                kind, descr = 'changed', items[k][0]
                fields = sanitize.field_diff(before[0] if before else None, items[k][1])
            else:
                continue
            rows.append((rev_time, author, author_ip, rev_descr, k[0], k[1], kind, descr,
                         json.dumps(fields, ensure_ascii=False), prev[0], snap))
        con.executemany(
            'INSERT INTO changes (occurred_at, author, author_ip, revision_descr, section, key, kind, item_descr,'
            ' fields, snapshot_before, snapshot_after) VALUES (?,?,?,?,?,?,?,?,?,?,?)', rows)
        changes = len(rows)
    return {'id': snap, 'revision_time': rev_time, 'author': rev_user, 'description': rev_descr,
            'items': len(items), 'changes': changes, 'baseline': prev is None, 'masked': masked}


def run(ctx, settings, deadline=None, rescan=False):
    con = store.open_db(ctx, 'config')
    key = sanitize.hmac_key(ctx.hmac_key)
    ver = version(ctx)
    now = ctx.clock()
    pending = []
    skipped = 0
    for path in candidates(ctx):
        try:
            st = os.stat(path)
        except OSError:
            continue
        name = os.path.basename(path)
        seen = con.execute('SELECT size, mtime FROM seen_files WHERE name = ?', (name,)).fetchone()
        if not rescan and seen and seen[0] == st.st_size and abs((seen[1] or 0) - st.st_mtime) < 0.001:
            skipped += 1
            continue
        pending.append((path, name, st))
    parsed = []
    errors = []
    for path, name, st in pending[:MAX_FILES]:
        try:
            with open(path, 'rb') as handle:
                data = handle.read()
            root = ET.fromstring(data)
        except (OSError, ET.ParseError) as exc:
            errors.append('%s: %s' % (name, exc))
            con.execute('INSERT OR REPLACE INTO seen_files VALUES (?,?,?,?)', (name, st.st_size, st.st_mtime, None))
            continue
        rev_time, _u, _d = _revision(root)
        parsed.append((rev_time or st.st_mtime, path, name, st, data))
    parsed.sort(key=lambda x: (x[0], x[2] == os.path.basename(ctx.config_xml)))
    registered = []
    complete = len(pending) <= MAX_FILES
    for _rt, path, name, st, data in parsed:
        if deadline is not None and time.monotonic() > deadline:
            complete = False
            break
        origin = 'current' if path == ctx.config_xml else 'backup'
        result = register(con, ctx, data, origin, name, key, ver, now)
        con.execute('INSERT OR REPLACE INTO seen_files VALUES (?,?,?,?)', (name, st.st_size, st.st_mtime, None))
        con.commit()
        if result:
            registered.append(result)
    # files that disappeared from /conf/backup (the core keeps a fixed number) are forgotten
    present = {os.path.basename(p) for p in candidates(ctx)}
    for (name,) in con.execute('SELECT name FROM seen_files').fetchall():
        if name not in present:
            con.execute('DELETE FROM seen_files WHERE name = ?', (name,))
    if registered and not common.meta_get(con, 'local_since'):
        first = con.execute("SELECT min(revision_time) FROM snapshots WHERE origin NOT LIKE 'import:%'").fetchone()
        common.meta_set(con, 'local_since', first[0])
    maintenance = store.maintain(ctx, 'config', con, settings, now)
    result = {
        'status': 'ok', 'kind': 'config', 'ts': common.iso(now), 'files_new': len(pending),
        'files_unchanged': skipped, 'snapshots': len(registered),
        'changes': sum(r['changes'] for r in registered), 'complete': complete,
        'latest': registered[-1] if registered else None, 'errors': errors[:10],
    }
    if maintenance:
        result['maintenance'] = maintenance
    common.meta_set(con, 'last_run', result)
    con.commit()
    con.close()
    return result
