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

    CVSS helpers. OSV only publishes vectors, so the v3.x base score is computed here
    (FIRST CVSS v3.1 specification, section 7). CVSS v4 vectors are kept as text without a score
    (the v4 score needs the full macro vector table); NVD gives the v4 score directly.
"""

import decimal
import math

AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
AC = {'L': 0.77, 'H': 0.44}
PR_U = {'N': 0.85, 'L': 0.62, 'H': 0.27}
PR_C = {'N': 0.85, 'L': 0.68, 'H': 0.5}
UI = {'N': 0.85, 'R': 0.62}
CIA = {'H': 0.56, 'L': 0.22, 'N': 0.0}


def roundup(value):
    """ CVSS v3.1 Roundup (avoids floating point surprises) """
    as_int = int(round(value * 100000))
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def v3_base_score(vector):
    """ 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> 9.8 ; None when invalid """
    if not vector or not vector.startswith('CVSS:3'):
        return None
    try:
        metrics = dict(part.split(':', 1) for part in vector.split('/')[1:])
        scope_changed = metrics['S'] == 'C'
        iss = 1 - (1 - CIA[metrics['C']]) * (1 - CIA[metrics['I']]) * (1 - CIA[metrics['A']])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (PR_C if scope_changed else PR_U)[metrics['PR']]
        exploitability = 8.22 * AV[metrics['AV']] * AC[metrics['AC']] * pr * UI[metrics['UI']]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity(score):
    """ qualitative rating (v3/v4 share the bands) """
    if score is None:
        return None
    score = float(decimal.Decimal(str(score)))
    if score == 0:
        return 'none'
    if score < 4.0:
        return 'low'
    if score < 7.0:
        return 'medium'
    if score < 9.0:
        return 'high'
    return 'critical'
