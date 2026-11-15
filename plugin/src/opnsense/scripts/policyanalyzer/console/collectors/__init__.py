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

    Read-only context collectors of the AI Console.  Each one reads one local source and returns a small
    JSON-able dict with at least "available" (bool) and, when it reads a log, "complete" (bool: the whole
    window was read within the budget) and "source".  None of them writes, reloads or calls the network
    (except aliases.member_of, which only asks pf whether a table holds an address).

        fwinfo      interfaces, devices, subnets, WAN role (config.xml)
        filterlog   filter log, read backwards (focus aggregates, top lists, viewer tail)
        rules       rules in evaluation order with counters (configctl filter rule stats) and findings
        aliases     aliases holding an address (config + pfctl -T test), alias contents
        hosts       host names (Kea leases/reservations, Unbound overrides, Host discovery)
        quarantine  quarantine ledger, SQLite opened read only
        reports     Policy Analyzer findings (last.json) and exposure report (exposure.json)
        changes     configuration history (/conf/backup) and a summarized diff
        suricata    IDS alerts from eve.json
"""
