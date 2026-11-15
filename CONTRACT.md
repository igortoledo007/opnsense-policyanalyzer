# Policy Analyzer: data contracts

This document describes the data formats that the components of the Policy Analyzer exchange: the JSON report of
the rule analyzer, the change action contract, and the files and SQLite databases of the quarantine, the local
collectors, the vulnerability prioritisation, the device inventory and the reports. The source code cites the
sections below by name.

All examples use documentation values only (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32,
AS64500, `example.lan`, gateways `WAN_A` / `WAN_B`).

Contents:

1. [Report format](#report-format) (analyzer JSON, version 1, revisions 1 and 2)
2. [Findings](#findings) (finding object and finding ids, shared by every module that produces findings)
3. [Change actions](#change-actions) (plan / apply / revert, journal)
4. [Automatic quarantine](#automatic-quarantine) (Max Cyber IA)
5. [Quarantine ledger](#quarantine-ledger) (SQLite schema and example queries)
6. [Local collectors](#local-collectors)
7. [Vulnerability prioritisation](#vulnerability-prioritisation)
8. [Device inventory](#device-inventory)
9. [Reports and notifications](#reports-and-notifications)

## Report format

`configctl policyanalyzer analyze` runs `scripts/policyanalyzer/analyze.py`, writes
`/var/db/policyanalyzer/last.json` and prints the same JSON. Read only: it reads `/conf/config.xml` and the pf
counters and never changes a rule or a setting.

```
{
  "version": 1, "generated": "ISO-8601", "duration_ms": int,
  "summary": {"rules": int, "enabled": int, "findings": int,
              "by_severity": {"high": n, "medium": n, "low": n, "info": n}},
  "stats_available": bool,                       # were the pf counters read?
  "stats": {...},                                # revision 1, below
  "findings": [<finding>, ...]                   # see "Findings"
}
```

UI strings (titles, details, recommendations) are in English, as upstream; the plugin translates them with
gettext.

### Revision 1

- New top level object `"stats": {"source": "configctl filter rule stats" | "rule_stats.py" | "file",
  "ruleset_loaded": "ISO", "boot_time": "ISO", "keepcounters": bool, "counters_since": "ISO"}`: the GUI shows
  since when the counters count. Without counters every field is `null` except `keepcounters`.
- Additional official types: `inactive` (enabled rule dropped by the generator: missing interface, alias or port;
  or uuid absent from the loaded ruleset) and `never_matches` (rule that matches no packet, e.g. `inet` with an
  IPv6-only destination).
- `evidence.mode` in pair findings: `earlier_quick` | `later_overrides` | `later_covers`.
- Items of `rules[]` gain `quick` (bool), `enabled` (bool), `priority_group` (`floating` | `group` | `interface`)
  and `ref` (relative URL to edit the rule, e.g. `ui/firewall/filter#search=<uuid>`).
- In pair findings `rules[0]` is the affected rule and `rules[1]` the one that covers or overrides it.

### Revision 2 (OPNsense 27.1)

- `rules[].action` may be `match` (27.1, Filter.xml ≥ 1.0.8). The internal verdict of the engine is `pass` |
  `deny` | `match`: a match rule applies options (scrub, tag, queue, priority) and never decides pass/block. It
  neither covers nor is covered by pass/block/reject rules in `shadowed` / `redundant` / `duplicate`. Between
  match rules only `duplicate` (same match and same options, `evidence.mode = match_duplicate`) and `unused` are
  reported.
- Exception: a match with `quick` ends the pf evaluation. A later pass/block rule covered by it is reported as
  `shadowed` high with `evidence.mode = quick_match` (`rules[1]` is the match rule).
- `evidence.mode` accepts: `earlier_quick` | `later_overrides` | `later_covers` | `quick_match` |
  `match_duplicate`.
- The options `scrub_no_df`, `scrub_random_id`, `scrub_max_mss`, `scrub_min_ttl` and `scrub_set_tos` count as
  part of the effect of the rule: two rules that differ only in them are never `duplicate` / `redundant` (they are
  reported as `shadowed` medium with the difference in `evidence.differences`).
- `stats` gains `keepcounters_source` (`"mvc"` = `//OPNsense/Firewall/Filter/settings/filter/keep_counters`,
  27.1; `"legacy"` = `system/keepcounters`, 26.7; `null` = not set anywhere) and `settings_page`
  (`ui/firewall/settings` when the MVC settings node exists, else `system_advanced_firewall.php`), so the GUI can
  build the "enable keep counters" link. With both formats in the same config the MVC key wins, key by key.
- Leftover legacy `filter/scrub/rule` in a config with Filter ≥ 1.0.8 (normalisation already migrated to match
  rules and ignored by pf) does not count as alias usage for `unused_alias`; below that version the scrub rules
  are still active and count.

The exact logic of every detector is in `tests/README.md` ("Detectors (exact logic)").

## Findings

Every module that produces findings (rule analyzer, exposure report, posture, ...) uses the same object:

```
{
  "id": "short stable hex digest",
  "type": "shadowed|redundant|duplicate|unused|inactive|never_matches|permissive|wan_exposed|disabled|
           no_description|empty_alias|unused_alias|exposed_vulnerable_service|known_exploited_vuln|...",
  "severity": "high|medium|low|info",
  "title": "short sentence in English",
  "detail": "deterministic explanation in English",
  "recommendation": "what to do (in English)",
  "rules": [{"uuid": "...", "source": "mvc|legacy", "interface": "lan", "direction": "in", "action": "pass",
             "sequence": int, "description": "...", "quick": bool, "enabled": bool,
             "priority_group": "floating|group|interface", "ref": "ui/firewall/filter#search=<uuid>",
             "summary": "pass in on lan from LAN net to any port 443"}],
  "aliases": ["name", ...],
  "evidence": {...}                              # counters, compared fields, mode, ports, ...
}
```

### Finding ids

Finding ids are short lowercase hex digests, stable between runs as long as the inputs keep their identity. The
rule analyzer uses `sha1(type:uuids:aliases:mode)[:16]` (in pair findings the order is affected rule, covering
rule); other modules hash their own stable key the same way. The API accepts `^[0-9a-f]{6,64}$`.

## Change actions

Every change the plugin can make goes through one contract: **plan** (simulation, nothing changes), **apply**
(executes the plan and writes a journal entry) and **revert** (undoes one journal entry). Endpoints:
`/api/policyanalyzer/change/plan|apply|history|actions`; configd: `policyanalyzer plan|apply ...` and the module
topics (`pa_reports`, `pa_vulns`, `pa_devices`, `pa_collect`, ...).

- Actions are classes registered in `scripts/policyanalyzer/ai/changes.py` (`@changes.register`), either in the
  core of the AI layer or by an extension package listed in `ai/changes.py` `EXTENSIONS` (`setup`, `quarantine`,
  `incidents`, `reports`, `vulns`, `devices`, `anomalies`, `collect`): `scripts/policyanalyzer/<package>/__init__.py`
  imports its action modules.
- The journal lives in `/var/db/policyanalyzer/undo/` (ids `YYYYMMDDTHHMMSS-<6 hex>`, written by `ai/journal.py`).
  The entries show up in the "Action history" tab with Revert, whichever topic applied them. A module controller
  (`ModuleHelperTrait`) can run its actions through its own configd topic, so they work even before the package is
  listed in `EXTENSIONS`; reverting from the "Action history" tab needs the package to be listed there.
- A plan returns `steps` (description and command), optional `warnings`, `warning_actions` (a missing
  prerequisite, e.g. `{"id": "qsetup_aliases", "args": ["create"]}`; such a plan has no steps and apply refuses
  it), `info: [{title, items[]}]` blocks (rendered by `PASimulation`), the risk (`none` | `low` | `medium` |
  `high`) and whether a step is irreversible (double confirmation).
- `change_plan` / `change_apply` take up to 5 arguments (`ChangeController::MAX_ARGS`).

See also `plugin/README.md` ("Simulate → apply → revert").

## Automatic quarantine

Automatic blocking of external sources that insist on the WAN, with an escalating ladder for repeat offenders,
scenarios, guards and a permanent history. Code: `scripts/policyanalyzer/quarantine/` (common, store, sources,
fwconfig, guards, lookup, pf, engine, actions, steps, wizard, cli, model.php). Tests: `tests/quarantine/`.

### Objects on the firewall

Created by the steps of the assistant / `install_quarantine` through the core model (`model.php`); nothing edits
config.xml by hand and the plugin never reboots the firewall.

- Alias `pa_quarantine`, type **External (advanced)**, counters on: the content is the pf table, maintained at
  runtime (`pfctl -t pa_quarantine -T add|delete`) without writing the config. `filter.inc` declares
  `table <pa_quarantine> persist` without addresses, so `filter reload` keeps the content. A reboot empties the
  table: the hook `/usr/local/etc/rc.syshook.d/start/90-policyanalyzer-quarantine` runs
  `configctl policyanalyzer quarantine_sync` at boot and every run checks again (table = ledger). Quarantined
  networks that contain a protected address get `!addr` holes.
- Alias `pa_never_block`, type Network(s), created empty; the owner edits it in Firewall › Aliases.
- Rule with the description exactly **`Max Cyber IA`**: block, quick, direction in, IPv4+IPv6 (`inet46`), source
  `pa_quarantine`, logging on, on the WAN interfaces (wan + interfaces with a gateway or a dynamic uplink; with 2+
  WANs it is floating, priority 200000, evaluated before every interface rule). Sequence = lowest sequence of the
  enabled floating rules − 1 (minimum 1). Always identified by its description (`fwconfig.quarantine_rules`).
- Cron (System › Settings › Cron, `origin=PolicyAnalyzer`): `*/5 * * * *` `policyanalyzer quarantine_run`, applied
  with `configctl cron restart`.

### Run

`quarantine_run` (flock on `quarantine.lock`, budget 20 s):

1. Reads `/var/log/filter/latest.log` (daily file; at midnight it finishes the previous one, found by inode) and
   `/var/log/suricata/eve.json` (only `"event_type":"alert"` lines) from the **marker** `{dev, ino, offset}`
   stored in SQLite **in the same transaction** as the offenses: nothing is lost or repeated; complete lines only;
   the first run starts at the end of the file; a truncated file starts again from 0; events older than 24 h are
   ignored; at most 48 MiB per source and run.
2. Only `dir=in` on the WAN interfaces (by device name, e.g. `pppoe1`, `igc2`). TCP only counts connection
   attempts (SYN without ACK).
3. Per external (not protected) source, in time order:

| scenario | condition in the window | minimum level |
|---|---|---|
| base | ≥ 1 inbound connection blocked on the WAN | 1 (30 min) |
| scan | ≥ `scan_ports` (10) distinct destination ports in `scan_window` (300 s), sliding window | 2 (2 h) |
| bait | blocked connection to a bait port (`bait_ports` = 23, 3389, 5900, 445, 1433), TCP or UDP | 2 (2 h) |
| suricata | alert with `alert.severity` ≤ `suricata_severity` (1) and an external `src_ip` | 3 (2 days) |

   Level = max(minimum of the scenario, previous level + 1) for a repeat offense (a new offense after the previous
   quarantine ended); back to 1 after `reset_days` (90) without offenses; ceiling 5. Ladder: 1 = 30 min, 2 = 2 h,
   3 = 2 days, 4 = 10 days, 5 = 30 days; 6 = permanent (manual only). Main reason: suricata > scan > bait > base
   (all that fired stay in the `reasons` mask). Events while the quarantine is in force (including the ones
   blocked by the rule itself, recognised by `rid` = uuid of the rule) are **hits**, not offenses; a stronger
   scenario in that period **upgrades** the entry. Inbound states of sources entering through suricata or manual
   are killed (`pfctl -k`).
4. Expires (`until <= now`), releases entries that became protected (`guard_release`) and syncs the pf table.
5. Limit `max_active` (20,000 pf entries): above it the offense is only recorded (`limited=1`, event `limit`,
   syslog, warning with a "Raise the limit" button).
6. Country/ASN index: when `/usr/local/share/GeoIP/alias/*` or `/usr/local/share/bgp/asn.csv` (core data) are
   newer than `/var/db/policyanalyzer/quarantine-lookup.db`, `nice -n 20 manage.py quarantine index` runs in the
   background (at most once per hour); until then the old index is used.

**Pause**: `quarantine_pause` disables the rule (`enabled=0` + `filter reload`) and sets `paused=1`; the run
keeps recording (ledger and ladder go on); `quarantine_resume` enables it again.

### Guards

Valid for automatic and manual entries: outside the global space (private, reserved, CGNAT 100.64/10, loopback,
link-local, multicast, documentation); addresses of the firewall itself (config + `ifconfig -a`); gateways and
monitors (config, default route, PPP peer); DNS servers (system/dnsserver, Unbound DoT/forward,
`/etc/resolv.conf`); NTP (system/timeservers resolved + `ntpq -pn`); WireGuard peers (resolved config +
`wg show all endpoints`) and Tailscale (`tailscale status --json`, if enabled); **every IP with an ALLOWED inbound
connection to a WireGuard server port in the last 24 h** (table `wg_allowed`, from the log; the pass rule needs
logging, the status warns with a button otherwise); `pa_never_block`; open SSH/GUI sessions (`sockstat -c`). Names
resolved with a 1 h cache and 2 s per name. Manual: a protected address is refused; a network that covers a
protected address enters with `!protected`; a non public network is refused; larger than /16 (v4) or /32 (v6), an
ASN with more than 256 prefixes or permanent → double confirmation; larger than /8 (v4) or /16 (v6) refused; a range
`a-b` becomes up to 64 CIDRs.

### Files, configd and API

Files: `/var/db/policyanalyzer/quarantine.db` (+ `-wal`/`-shm`, 0640), `quarantine-lookup.db`, `quarantine.lock`,
`quarantine-lookup.lock`, `asn.csv.previous` (backup of `update_asn_db`).

configd (`actions_policyanalyzer.conf`): `quarantine_run`, `quarantine_sync`, `quarantine_index`,
`quarantine_status`, `quarantine_summary`, `quarantine_guards`, `quarantine_wizard`, `quarantine_preview`,
`quarantine_list <filters> <sort> <page:rows>`,
`quarantine_history <offenses|events|yearly> <ip|-> <YYYY|YYYYMMDD-YYYYMMDD|-> <page:rows>`,
`quarantine_export <period> <ip|->` (CSV), `quarantine_entry <id|address>`, and journaled shortcuts
`quarantine_release <ids>`, `quarantine_add <target> <duration> <comment-base64|->`, `quarantine_pause`,
`quarantine_resume`. Filters: `state=active|expired|released|permanent|blocked+reason=...+origin=auto|manual+
country=US+asn=64500+year=2026+level=3+search=203.0.113`.

Change actions (see "Change actions"): `install_quarantine` (idempotent, chains the step actions below),
`remove_quarantine [purge_db=yes]` (keeps the database by default), `quarantine_add <target>
<auto|l1..l5|permanent> <comment base64|->` (target: IP, CIDR, `a-b` or `AS<n>`, resolved through `asn.csv`),
`quarantine_release <ids>`, `quarantine_extend <ids> <next|l1..l5>`, `quarantine_permanent <ids>`,
`never_block_add <id>`, `quarantine_pause`, `quarantine_resume`, `quarantine_settings <key> <value>`,
`update_asn_db` (downloads `https://rulesets.opnsense.org/alias/asn.gz`, the same source as the core). Batch ids:
`12+15+20`, up to 30. Step actions of the assistant, each with its own journal entry: `qsetup_rule_log <uuid>
<on|off>`, `qsetup_ledger [create|attach <file>|detach|purge]`, `qsetup_aliases [create|remove]`,
`qsetup_never_block <add|del> <address|CIDR>`, `qsetup_rule [create [on|off]|remove]`,
`qsetup_scenarios <key=value:key=value...|defaults>`, `qsetup_schedule [create|remove]`, `qsetup_activate`.

API `/api/policyanalyzer/quarantine/*` (`QuarantineController`): read (view ACL): `status`, `summary`, `search`
(UIBootgrid + `state`, `reason`, `origin`, `country`, `asn`, `year`, `level`), `history`, `export`, `entry`,
`guards`, `wizard`, `preview`; change (admin ACL; POST, journaled): `release`, `add` (refuses the address of the
own session), `pause`, `resume`. Other changes use `/api/policyanalyzer/change/*`.

Summary for the Max Cyber HUD, `GET /api/policyanalyzer/quarantine/summary`:

```
{"status": "ok", "installed": true, "paused": false, "rule_enabled": true, "generated": "ISO Z",
 "active": 105, "by_level": {"1": 36, "2": 28, "3": 27, "4": 5, "5": 8, "6": 1},
 "offenses_24h": 83, "new_24h": 2, "by_reason_24h": {"base": 44, "scan": 16, "bait": 13, "suricata": 8},
 "last_run": "ISO Z",
 "latest": [{"addr": "203.0.113.9", "kind": "ip|net|asn", "level": 1, "reason": "base", "country": "US",
             "since": "ISO Z", "until": "ISO Z|null", "expires_in": 1730}]}      # 20 most recent in force
```

## Quarantine ledger

SQLite database `/var/db/policyanalyzer/quarantine.db` (WAL, short transactions). The history is **permanent**:
no automatic cleanup; only a summary per offense (never raw log lines). Times are epoch UTC (`INTEGER`); the views
convert them to local time. Year = local year.

| table | columns |
|---|---|
| `entries` | `id`, `addr` (unique: `203.0.113.5`, `203.0.113.0/24`, `AS64500`), `kind` (ip/net/asn), `asn`, `country`, `level` (0–6), `state` (active/expired/released/permanent), `origin` (auto/manual), `reason` (1 base, 2 scan, 3 bait, 4 suricata, 5 manual), `first_seen`, `last_offense`, `since`, `until` (NULL = permanent), `offenses`, `hits`, `iface`, `comment`, `resolved_at` |
| `asn_prefixes` | `entry_id`, `prefix` |
| `offenses` | `id`, `ts`, `entry_id`, `reason`, `reasons` (mask: 1 base, 2 scan, 4 bait, 8 suricata, 16 manual), `level`, `until`, `origin`, `events`, `ports` (up to 8 `port/proto`), `detail` (e.g. `sid 2003933 sev 1: ...`, `14 ports in 300 s`, manual comment), `iface`, `country`, `limited` |
| `events` | `id`, `ts`, `entry_id` (NULL for pause/resume/settings), `kind` (enter, upgrade, extend, expire, release, permanent, never_block, guard_release, limit, uninstall, revert, reinstall, pause, resume, settings), `level`, `until`, `origin`, `note` |
| `yearly` | `entry_id`, `year`, `offenses`, `first_seen`, `last_seen`, `max_level`, `reasons`; updated in the same transaction as each offense |
| `wg_allowed` | `ip`, `last_seen` (24 h only) |
| `meta`, `settings` | markers, pause, last run; owner settings |

Indexes: `offenses(entry_id, ts)`, `offenses(ts)`, `events(entry_id, ts)`, `events(ts)`, `yearly(year)`,
`entries(state, until)`, `entries(last_offense)`. Views: `v_entries`, `v_offenses` (`time`, `year`, `addr`,
`reason` by name...), `v_events`, `v_yearly` (`reasons` spelled out). Size: about 80–120 bytes per offense with
indexes; repeat offenders aggregate in `yearly`.

```sh
sqlite3 -readonly /var/db/policyanalyzer/quarantine.db
```
```sql
-- 2026: top offenders
SELECT addr, offenses, max_level, reasons, first_seen, last_seen FROM v_yearly WHERE year = 2026
 ORDER BY offenses DESC LIMIT 20;
-- every offense of one IP, all years
SELECT time, reason, level, until, ports, detail, iface, country FROM v_offenses WHERE addr = '203.0.113.9'
 ORDER BY ts;
-- entries into and exits from the quarantine of one IP
SELECT time, kind, level, until, origin, note FROM v_events WHERE addr = '203.0.113.9' ORDER BY ts;
-- offenses per month and reason in 2025
SELECT strftime('%Y-%m', ts, 'unixepoch', 'localtime') AS month, reason, count(*) FROM v_offenses
 WHERE year = 2025 GROUP BY month, reason ORDER BY month;
-- countries with the most distinct IPs in the year
SELECT country, count(DISTINCT addr) FROM v_yearly WHERE year = 2026 GROUP BY country ORDER BY 2 DESC;
-- date range (local time)
SELECT * FROM v_offenses WHERE ts >= strftime('%s', '2026-03-01', 'utc') AND ts < strftime('%s', '2026-04-01', 'utc');
-- export one year as CSV
.headers on
.mode csv
.output /root/quarantine-2026.csv
SELECT * FROM v_offenses WHERE year = 2026 ORDER BY ts;
.output stdout
```

The console collector (`console/collectors/quarantine.py`) opens this database read only (`mode=ro`).

## Local collectors

Three routines run on the firewall itself, reading local files and tools directly (no HTTP API, no token). Code:
`scripts/policyanalyzer/collect/` (common, sanitize, store, config, health, flows, query, importer, actions, cli,
model.php). Tests: `tests/collect/` (no network).

### Collectors

`configctl pa_collect run <config|health|flows>` (flock per kind; busy → `status: busy`; budget 100/60/80 s; one
JSON per run):

- `config`: `/conf/backup/config-*.xml` + `/conf/config.xml`. A new file (name/size/mtime) is sanitised
  (`sanitize.py`: secrets become `REDACTED:<hmac16>` with the local key `collect/hmac.key`, 0600; 0/1/yes/no flags,
  certificates and public keys stay) and recorded in `<revision><time>` order if the SHA-256 of the sanitised XML is
  new. Diff against the previous revision → `changes` (added/removed/changed, changed fields with the sanitised
  value), author and IP from `<revision><username>` (`user@ip`), revision description. First run: the whole history
  of `/conf/backup` (the oldest is the baseline). No retention by days by default; the size limit drops the XML of
  the oldest revisions (items and changes stay).
- `health`: one sample per run (hourly cron): `kern.cp_time`, `vm.loadavg`, memory (`vm.stats.vm.*`,
  `hw.physmem`, ARC), temperatures (`dev.cpu.N`, `hw.acpi.thermal.tzN`), `swapinfo -k`, `zpool list -Hp` (or
  `df -kP /` without ZFS), `pfctl -si/-sm`, dpinger (`/var/run/dpinger_*.sock`: RTT, deviation, loss),
  `netstat -ibdn`, `netstat -m`, `pluginctl -S` (stopped services → metric + event), `ps` (RSS/CPU of
  `processes`), `wg show all dump` (rx/tx/handshake age per peer; keys are never read beyond the public field),
  `arp -an` (table `hosts`). Events: `ALERT:` lines of `/var/log/gateways/latest.log`, reboot (change of
  `kern.boottime`), `service_stopped`. A broken probe does not stop the others (`errors`).
- `flows`: every 5 minutes. Blocks: `/var/log/filter/latest.log` with the incremental reader of the quarantine
  (marker `{dev, ino, offset}`), only `block`/`reject`, aggregated per hour × interface (device) × direction ×
  action × proto × source × destination × port × rule (rid), with the source country from the quarantine GeoIP
  index (`quarantine-lookup.db`, if present). DNS: the resolver in use according to `config.xml` → Unbound:
  `/var/unbound/data/unbound.duckdb` table `query` (read only through `duckdb_helper.DbConnection`, cursor = last
  complete second, 120 s behind the logger, up to 400,000 rows per run); without DuckDB the resolver log;
  dnsmasq: `query[...] ... from ...` + `config ... is 0.0.0.0|NXDOMAIN`. Aggregated per hour × client × domain ×
  action (`pass|block|drop`) + NXDOMAIN. First run: since local midnight. Aggregates and markers in the same
  transaction. Maintenance once a day: compaction, retention, size limit.

### Files and retention

`/var/db/policyanalyzer/collect/` (0750; databases 0640, WAL): `config.db`, `health.db`, `flows.db`, `hmac.key`
(0600), `settings.json` (only through `collect_settings`), `<kind>.lock`, `import/`.

`settings.json` defaults: `retention_days` 90 (flows and health), `compact_after_days` 7 (hourly rows become daily
rows per local day: `blocks_daily`, `dns_daily`, `metrics_daily` with avg/min/max/last/n), `config_retention_days`
0 (= forever), `max_mb_flows` 1024, `max_mb_health` 256, `max_mb_config` 512 (above: delete the oldest day, never
today; `auto_vacuum=INCREMENTAL`), `dns_source` auto|unbound|dnsmasq|none, `ignore_services` (ids of
`pluginctl -S`, e.g. `dpinger/WAN_B`), `processes` (suricata, unbound, ollama, php-cgi).

### Schema

Hours and `ts` in epoch UTC; `day` = local day `YYYY-MM-DD`; `origin` = `local` | `import:<id>`.

| database | tables |
|---|---|
| `flows.db` | `blocks_hourly`/`blocks_daily` (hour\|day, iface, dir, action, proto, src, dst, dport, rid, cc, n, [first, last], origin), `dns_hourly`/`dns_daily` (hour\|day, client, domain, action, n, nx, origin), `runs` (ts, blocks, dns, filter_lines, filter_bytes, dns_source, complete, seconds), `meta` (filter_marker, dns_cursor, blocks_since, dns_since, last_run, last_maintenance), `imports` |
| `health.db` | `metrics` (ts, key, value, origin), `metrics_daily` (day, key, avg, min, max, last, n), `events` (ts, kind gateway\|service_stopped\|reboot, source, text), `hosts` (mac, ip, name, vendor, iface, first_seen, last_seen), `meta` (probe_state, gateway_marker, local_since), `imports` |
| `config.db` | `snapshots` (id, revision_time, revision_user, author, author_ip, revision_descr, hostname, version, sha256, masked, origin local\|backup\|current\|import:…, xml zlib), `items` (snapshot_id, section, key, descr, sha256) + `blobs` (sha256, JSON of the item, deduplicated), `changes` (occurred_at, author, author_ip, revision_descr, section, key, kind, item_descr, fields JSON, snapshot_before/after, origin), `seen_files`, `imports` |

Metric keys: `cpu_idle_pct`, `cpu_user_pct`, `cpu_system_pct`, `cpu_interrupt_pct`, `load_1m/5m/15m`, `ncpu`,
`mem_total_mb`, `mem_used_mb` (includes ARC/wired), `mem_used_pct`, `mem_wired_mb`, `mem_free_mb`, `zfs_arc_mb`,
`uptime_s`, `temp_cpu` (average), `temp_cpu_max`, `temp_acpi`, `swap_total_mb`, `swap_used_mb`,
`zpool:<pool>:{size_gb,alloc_gb,free_gb,cap_pct,frag_pct,healthy}`, `disk_root_used_pct`, `pf_states`,
`pf_states_limit`, `pf_states_pct`, `pf:<counter>_rate`, `gw:<gateway>:{rtt_ms,rttsd_ms,loss_pct}`,
`if:<dev>:{rx,tx,drops,errors,rx_bps,tx_bps}`, `mbuf_clusters_pct`, `services_total`, `services_stopped`,
`proc:<name>:{res_mb,cpu,count}`, `wg:<peer>:{rx,tx,handshake_s}`, `hosts_arp`, `collect:<kind>_mb`.

### Read interface

`collect/query.py`, used by the charts of the PDFs and reports; everything read only, a missing database = empty
result. `q = query.Query()` (or the module functions with the same name). Times: epoch, `YYYY-MM-DD` (local
midnight; for `until`, the end of the day), ISO 8601, relative `24h`/`7d`/`2w`, `now`. Interval `[since, until)`.
Every point has `t` (local ISO) and `ts` (epoch); series fill empty buckets with 0. Hourly detail only for the
last `compact_after_days`; before that `bucket='hour'` returns the day as one point at midnight with
`daily: true`.

| function | returns |
|---|---|
| `coverage()` | per database: available, size, last run, `blocks_since`/`dns_since`/`local_since`, hour/day ranges, imports |
| `blocks_series(since, until, bucket='hour'\|'day', wan_only=False, direction=None, iface=None)` | `[{t, ts, blocks, daily?}]` |
| `top_sources(since, until, limit=10, wan_only=True, direction='in')` | `[{ip, blocks, ports, country}]` |
| `top_countries(...)` | `[{country ('??' = no index), blocks, sources}]` |
| `top_ports(...)` | `[{port, proto, label (SSH, RDP…), blocks, sources}]` |
| `top_rules(since, until, limit)` | `[{rid, label, blocks}]` |
| `top_interfaces(since, until, limit)` | `[{iface, name, wan, blocks}]` |
| `dns_series(since, until, bucket)` | `[{t, ts, queries, blocked, nxdomain, daily?}]` |
| `top_domains(since, until, limit, action='all'\|'pass'\|'blocked', client=None)` | `[{domain, queries, clients}]` |
| `top_dns_clients(since, until, limit, action)` | `[{client, queries, blocked, domains}]` |
| `health_keys(pattern=None)` | list of keys (glob `gw:*:rtt_ms`) |
| `health_series(keys, since, until, bucket, agg='avg'\|'max'\|'min'\|'last')` | `{key: [{t, ts, value}]}` |
| `health_latest()` | `{ts, t, metrics {key: value}}` |
| `health_events(since, until, kind=None)` | `[{t, ts, kind, source, text}]` |
| `config_revisions(since, until)` | `[{id, t, ts, author, author_ip, description, origin, changes}]` |
| `config_changes(since, until, section=None ('filter.*'))` | `[{t, ts, author, author_ip, revision, section, key, kind, item, fields [{field, old, new}], snapshot_before, snapshot_after, origin}]` |
| `config_diff(id_a, id_b, context=3)` | unified diff of the sanitised XML (text) |
| `summary(since, until, limit=5)` | blocks/DNS/health/config summarised for a report |
| `compare(since, until)` | totals per local day (side by side validation with an older collector) |

`wan_only` uses the WAN interfaces of `config.xml` (wan + interfaces with a gateway or a dynamic address),
compared by the device name of the log.

### configd and change actions

configd (`actions_pa_collect.conf`): `pa_collect run <kind>` (cron command), `pa_collect status`,
`pa_collect query <name> [args…]` (positional arguments in the order of the table above, `-` = default, only
`[A-Za-z0-9_.:*,/+-]`), `pa_collect import <file> <plan|apply>`, `pa_collect import_undo <id>`,
`pa_collect schedule <plan|apply> <create|remove>`, `pa_collect settings <plan|apply|show> [k=v+k=v|defaults]`,
`pa_collect revert <plan|apply> <journal id>`, `pa_collect maintain <kind>`.

Change actions (`collect/actions.py`):

- `collect_schedule <create|remove>`: 3 cron jobs through the core model (`collect/model.php cron_set|cron_del
  <kind>`, `origin=PolicyAnalyzer`): `*/5 *` flows, `7 *` health, `3 *` config; then `configctl cron restart`.
  Idempotent. Revert undoes only the jobs that apply created (or recreates the ones it removed); the databases stay.
- `collect_settings <k=v+…|defaults>`: writes `settings.json` (validated); revert restores the previous file (or
  removes it). A shorter retention warns and flags as irreversible what would be deleted.

Import of an older history (once): a `pa-collect-export` v1 file (tables `config_snapshots`, `config_changes`,
`health_metrics`, `health_events`, `health_hosts`, `flow_blocks`, `dns_daily`; see the docstring of
`collect/importer.py`) copied to `collect/import/` and loaded with `pa_collect import <file> plan|apply`. No
overlap: each part only brings what is older than the first local data of that collector; the imported XML is
sanitised again with the local key; the same file (SHA-256) is never imported twice; `import_undo <id>` deletes
everything with `origin = import:<id>`.

## Vulnerability prioritisation

Code: `scripts/policyanalyzer/vulns/` (common, intel, prioritize, review, explain, actions, cli). Read only on the
firewall: the CVEs of the exposure inventory (`/var/db/policyanalyzer/exposure.json`, written by the exposure
report) ranked P1..P4 with CISA KEV and FIRST EPSS from a local cache, the review queue ("Under review") and AI
explanations (text only).

| priority | label | rule |
|---|---|---|
| P1 | critical | reachable from the internet AND (in CISA KEV OR EPSS ≥ `epss_high`) |
| P2 | high | reachable from the internet AND CVSS ≥ `cvss_high`, OR in KEV while not exposed |
| P3 | medium | listening only on LAN/VPN AND CVSS ≥ `cvss_high`, OR EPSS ≥ `epss_medium`, OR reachable without a high score |
| P4 | low | everything else (typically a library without a listening socket) |

Thresholds (defaults, `vulns-settings.json` may override them): `epss_high` 0.5, `epss_medium` 0.1, `cvss_high`
7.0. "maybe" reachability counts as reachable and says so in the factors. Every item carries its `factors`
(`exposure`, `kev`, `epss`, `cvss`, each with `met` and a text) and the `rule` that decided.

Files (`/var/db/policyanalyzer/`): `vulns/kev.json`, `vulns/epss.json` (cache, downloaded only by the change
action `vulns_intel_update`; only CVE ids are sent), `vulns-review.json` (`{version, decisions, suggestions}`),
`vulns-settings.json`, `vulns-explain/` (AI answers), `vuln-cache/` (exposure feed cache, read only here).

Review queue kinds: `package_unmapped`, `dependency_link`, `service_unknown`, `binary_unowned`,
`advisory_unclear`, `cve_unscored`. Owner decisions (`vulns_review_decide`, journaled): `map:<service id>`,
`none`, `ignore[=days]` (default 90, max 365), `finding`.

configd (`actions_pa_vulns.conf`): `pa_vulns summary|list [P1+P2|all]|cve <id>|intel|explain|suggest|plan|apply`.

## Device inventory

Code: `scripts/policyanalyzer/devices/` (common, sources, oui, classify, risk, store, inventory, view, explain,
actions, cli). Passive inventory of the LAN devices (no probe, no scan): Host discovery (hostwatch), Kea/Dnsmasq
leases and reservations, ARP, local DNS, manufacturer from the IEEE OUI registry (`oui.csv`), heuristic type,
inferred risk.

`/var/db/policyanalyzer/devices.db` (SQLite, permanent history, no automatic cleanup; times in epoch UTC):

| table | columns |
|---|---|
| `devices` | `id`, `mac` (unique), `first_seen`, `last_seen`, `hostname`, `hostname_source`, `vendor`, `randomized`, `iface`, `iface_descr`, `ip4`, `ip6`, `auto_type`, `auto_confidence`, `auto_why`, `user_type`, `user_name`, `ai_type`, `ai_text`, `ai_at`, `known`, `known_at`, `risk`, `risk_reasons`, `present`, `updated` |
| `ips` | `device_id`, `ip`, `first_seen`, `last_seen` (every address a device used) |
| `events` | `id`, `ts`, `device_id`, `kind` (new, ip, hostname, vendor, known, unknown, type, name, ai), `old`, `new`, `note` |
| `dns` | `ip`, `name`, `resolved_at` (reverse lookup cache of the local resolver) |
| `meta` | last scan, sources state |

View `v_devices`: `id`, `mac`, `name` (owner name or hostname), `type` (owner type or automatic type), `vendor`,
`ip4`, `ip6`, `interface`, `first_seen`, `last_seen` (local time), `known`, `risk`.

configd (`actions_pa_devices.conf`): `pa_devices scan|summary|list|device|oui|explain|plan|apply`. Change actions:
`devices_mark_known`, `devices_set` (owner type/name), `devices_oui_update`.

## Reports and notifications

Code: `scripts/policyanalyzer/reports/` (common, settings, monit, collect, aisum, render, charts, pdf, pdfreport,
mailer, store, deliver, notify, actions, cli, model.php). Periodic security reports (every 6 h / daily / weekly) and
the notification center, delivered by e-mail through the SMTP settings of Monit (by reference, or imported into
the plugin), with an optional PDF attachment built from the same data.

Files (`/var/db/policyanalyzer/`): `reports-settings.json` (only through `reports_settings`), `reports-secret.json`
(SMTP password, never returned by the API), `reports.db`.

`reports.db` (SQLite, 0640, permanent history, bodies compressed with zlib):

| table | columns |
|---|---|
| `messages` | one row per e-mail (`kind`: report_6h, report_daily, report_manual, test, notification, digest): `id`, `ts`, `kind`, `subject`, `recipients`, `status` (sent \| failed \| skipped), `error`, `period_from`, `period_to`, `html`, `text`, `summary`, `ai_used`, `attempts`, `duration_ms`, `channel` |
| `notifications` | one row per event (unique `key`): `id`, `ts`, `type`, `source`, `severity`, `title`, `detail`, `link`, `data`, `status` (queued \| held \| sent \| failed \| suppressed), `reason`, `attempts`, `next_try`, `sent_at`, `message_id` |
| `meta` | markers of the event sources, last runs, baselines |

Notification types (`reports/settings.py` `EVENTS`): `incident`, `quarantine_long`, `vuln_kev_p1`, `anomaly`,
`posture_drop`, `ai_down`, `device_new`, `report`, each with a default minimum severity and throttle.

Report language: `language` of `reports-settings.json` (`en_US` by default, `pt_BR` available); the HTML, text and
PDF bodies use the same strings (`render.py`, `pdfreport.py`).

configd (`actions_pa_reports.conf`): `pa_reports settings|monit|preview|send|notify|notify_preview|history|
message|notifications|resend|summary|plan|apply`. Change actions: `reports_settings`, `reports_import_monit`,
`reports_send_test`.
