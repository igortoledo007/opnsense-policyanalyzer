"""
    Copyright (c) 2026 Igor Toledo
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

    Interval sets.

    A set is an immutable, sorted tuple of disjoint, non adjacent (lo, hi) integer pairs (inclusive).
    Addresses are kept per family as a pair (v4set, v6set), ports as a single set over 0..65535.
"""

import ipaddress

V4_MAX = (1 << 32) - 1
V6_MAX = (1 << 128) - 1
PORT_MAX = 65535

EMPTY = ()
ALL4 = ((0, V4_MAX),)
ALL6 = ((0, V6_MAX),)
ALL_PORTS = ((0, PORT_MAX),)

# address pair helpers: index 0 = IPv4, index 1 = IPv6
ADDR_EMPTY = (EMPTY, EMPTY)
ADDR_ALL = (ALL4, ALL6)
FAMILIES = (4, 6)


def fidx(family):
    return 0 if family == 4 else 1


def normalize(ranges):
    """ sort and merge a list of (lo, hi) pairs """
    items = sorted(r for r in ranges if r[0] <= r[1])
    result = []
    for lo, hi in items:
        if result and lo <= result[-1][1] + 1:
            if hi > result[-1][1]:
                result[-1] = (result[-1][0], hi)
        else:
            result.append((lo, hi))
    return tuple(result)


def union(a, b):
    if not a:
        return b
    if not b:
        return a
    return normalize(list(a) + list(b))


def intersect(a, b):
    result = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo <= hi:
            result.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return tuple(result)


def subtract(a, b):
    """ a minus b """
    if not a or not b:
        return a
    result = []
    j = 0
    for lo, hi in a:
        cur = lo
        while j < len(b) and b[j][1] < cur:
            j += 1
        k = j
        while k < len(b) and b[k][0] <= hi:
            if b[k][0] > cur:
                result.append((cur, b[k][0] - 1))
            cur = max(cur, b[k][1] + 1)
            if cur > hi:
                break
            k += 1
        if cur <= hi:
            result.append((cur, hi))
    return tuple(result)


def complement(a, maxval):
    return subtract(((0, maxval),), a)


def is_subset(a, b):
    """ every element of a is in b """
    if not a:
        return True
    if not b:
        return False
    j = 0
    for lo, hi in a:
        while j < len(b) and b[j][1] < lo:
            j += 1
        if j >= len(b) or b[j][0] > lo or b[j][1] < hi:
            return False
    return True


def overlaps(a, b):
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i][1] < b[j][0]:
            i += 1
        elif b[j][1] < a[i][0]:
            j += 1
        else:
            return True
    return False


def size(a):
    return sum(hi - lo + 1 for lo, hi in a)


# ---------------------------------------------------------------- address pairs

def addr_union(a, b):
    return (union(a[0], b[0]), union(a[1], b[1]))


def addr_subtract(a, b):
    return (subtract(a[0], b[0]), subtract(a[1], b[1]))


def addr_complement(a):
    return (complement(a[0], V4_MAX), complement(a[1], V6_MAX))


def addr_is_empty(a):
    return not a[0] and not a[1]


def parse_address(value):
    """ parse a literal address, network or range into an address pair
        :return: (v4set, v6set) or None when not a literal
    """
    value = (value or '').strip()
    if not value:
        return None
    if '-' in value and '/' not in value:
        parts = value.split('-')
        if len(parts) != 2:
            return None
        try:
            lo = ipaddress.ip_address(parts[0].strip())
            hi = ipaddress.ip_address(parts[1].strip())
        except ValueError:
            return None
        if lo.version != hi.version:
            return None
        rng = normalize([(int(lo), int(hi))])
        return (rng, EMPTY) if lo.version == 4 else (EMPTY, rng)
    try:
        if '%' in value:
            # scoped address (fe80::1%igb0), the scope does not change the matched address
            value = value.split('%')[0]
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    rng = ((int(net.network_address), int(net.broadcast_address)),)
    return (rng, EMPTY) if net.version == 4 else (EMPTY, rng)


def is_address_literal(value):
    return parse_address(value) is not None


def host_pair(value):
    """ a single host address as address pair (None if invalid) """
    try:
        if '%' in value:
            value = value.split('%')[0]
        ip = ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return None
    rng = ((int(ip), int(ip)),)
    return (rng, EMPTY) if ip.version == 4 else (EMPTY, rng)


def network_pair(address, bits):
    """ network of address/bits as address pair (None if invalid) """
    try:
        net = ipaddress.ip_network('%s/%s' % (address.strip().split('%')[0], int(bits)), strict=False)
    except (ValueError, AttributeError, TypeError):
        return None
    rng = ((int(net.network_address), int(net.broadcast_address)),)
    return (rng, EMPTY) if net.version == 4 else (EMPTY, rng)


def parse_port(value):
    """ parse a single port, a range (a-b, a:b) into a port set, None when not numeric """
    value = (value or '').strip()
    if not value:
        return None
    for sep in ('-', ':'):
        if sep in value:
            parts = value.split(sep)
            if len(parts) != 2:
                return None
            lo, hi = parts[0].strip(), parts[1].strip()
            lo = '1' if lo == 'any' else lo
            hi = str(PORT_MAX) if hi == 'any' else hi
            if lo.isdigit() and hi.isdigit():
                lo, hi = int(lo), int(hi)
                if lo > hi:
                    lo, hi = hi, lo
                if hi > PORT_MAX:
                    return None
                return ((lo, hi),)
            return None
    if value.isdigit() and int(value) <= PORT_MAX:
        return ((int(value), int(value)),)
    return None


def ports_to_text(pset):
    parts = []
    for lo, hi in pset:
        parts.append(str(lo) if lo == hi else '%d-%d' % (lo, hi))
    return ','.join(parts)
