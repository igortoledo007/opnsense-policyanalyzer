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

    Shared helpers: a command runner that tests replace, paths and small utilities.
"""

import datetime
import hashlib
import os
import subprocess

DB_DIR = os.environ.get('POLICYANALYZER_DB', '/var/db/policyanalyzer')
CONFIG_XML = os.environ.get('POLICYANALYZER_CONFIG', '/conf/config.xml')
VULN_XML = '/var/db/pkg/vuln.xml'
SURICATA_RULES = '/usr/local/etc/suricata/rules'
CA_FILES = ('/usr/local/etc/ssl/cert.pem', '/etc/ssl/cert.pem')

# commands that may be prefixed with "sudo -n" when running unprivileged with --sudo-read (all read only)
SUDO_READ_ALLOWED = ('sockstat', 'procstat')


class Runner(object):
    """ runs a command and returns (rc, stdout, stderr); rc None when the command can not be started.
        Never uses a shell. Tests replace it with a fake that answers from fixtures. """

    def __init__(self, timeout=60, sudo_read=False):
        self.timeout = timeout
        self.sudo_read = sudo_read and os.geteuid() != 0
        self.calls = []

    def __call__(self, argv, timeout=None):
        argv = list(argv)
        if self.sudo_read and os.path.basename(argv[0]) in SUDO_READ_ALLOWED:
            argv = ['sudo', '-n'] + argv
        self.calls.append(argv)
        try:
            proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout or self.timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return None, '', str(exc)
        return proc.returncode, proc.stdout.decode('utf-8', 'replace'), proc.stderr.decode('utf-8', 'replace')


def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:      # pragma: no cover
        return False


def now_iso(ts=None):
    if ts is None:
        dt = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    else:
        dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).replace(microsecond=0)
    return dt.isoformat()


def short_id(*parts):
    return hashlib.sha1(':'.join(str(p) for p in parts).encode('utf-8')).hexdigest()[:16]


def unavailable(reason):
    """ the uniform "could not read this" marker """
    return {'value': None, 'reason': reason}


def split_pkg_version(nv):
    """ 'sqlite3-3.53.4,1' -> ('sqlite3', '3.53.4,1') ; package names may contain dashes """
    nv = nv.strip()
    if '-' not in nv:
        return nv, ''
    name, version = nv.rsplit('-', 1)
    return name, version
