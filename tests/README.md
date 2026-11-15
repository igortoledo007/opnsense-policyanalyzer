# Policy Analyzer engine tests

Tests of the engine (`plugin/src/opnsense/scripts/policyanalyzer/analyze.py` + `engine/`), standard library only
(`unittest`). Every configuration is **synthetic** and uses documentation addresses only
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32). Nothing comes from a real firewall.

## How to run

From the project root (the directory that holds `plugin/` and `tests/`):

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest discover -s tests -v
```

Run the engine offline on the static fixture (without writing `/var/db/policyanalyzer/last.json`):

```sh
/usr/bin/python3 plugin/src/opnsense/scripts/policyanalyzer/analyze.py \
    --config tests/fixtures/sample-config.xml --stats tests/fixtures/sample-stats.json --no-write --pretty
```

Options of `analyze.py`: `--config PATH` (default `/conf/config.xml`), `--stats PATH` (JSON in the format of
`rule_stats.py`), `--no-stats`, `--no-write`, `--pretty`. Without `--stats` the counters come from
`rule_stats.py` (as root) or from `configctl filter rule stats`, the same source as the GUI
(`FilterController::searchRuleAction`). If neither answers, `stats_available` is `false` and the `unused`
detector does not run.

| file | content |
|---|---|
| `helpers.py` | builds a `config.xml` in memory (`io.BytesIO`, nothing on disk): interfaces wan/lan/opt1/opt2/opt3, group `INTERNAL` (lan, opt1), a VIP on opt1, webgui on 8443, ssh on 22; `filter_settings`/`filter_version` build the 27.1 layout |
| `test_detectors.py` | one case that fires and cases that must **not** fire for every detector |
| `test_opnsense_27_1.py` | `match` rules, `scrub_*` options, migrated settings and leftover `filter/scrub` (27.1), with 26.7 unchanged |
| `test_cli.py` | `analyze.py` from the command line, missing stats file, invalid config and performance (500 rules < 2 s) |
| `fixtures/sample-config.xml`, `fixtures/sample-stats.json` | static fixture used by the CLI test |

## Model used by the engine

**Rule sources.** MVC rules in `//OPNsense/Firewall/Filter/rules/rule` (defaults of `Filter.xml` applied when a
field is missing) and legacy rules in `/filter/rule`, converted to the MVC names as in `list_legacy_rules.php`
(`type`→action, `source/destination{any|network|address,port,not}`, `floating`, missing `quick` = quick, except
for a legacy floating rule, which is not quick, as in `FilterRule::parseFilterRules`).

**Evaluation order** (`FilterRuleContainerField::getPriority`, `filter_core_rules_user`,
`Plugin::iterateFilterRules`): priority 200000 for floating (MVC rule with 0 or 2+ interfaces or an inverted
interface; legacy rule with `<floating>`), 300000 + the group `sequence` for a rule on an interface group,
400000 for a rule on one interface. Within the same priority, MVC (by `sequence`) comes before legacy (config
order). pf uses the last matching rule, except when the rule is `quick`. Automatic rules (anti-lockout, bogons,
default deny, plugin rules) are not in the config and are not analysed.

**Match space** of each rule: set of interfaces (groups expanded into their members; floating without an
interface = all; `interfacenot` = all but the list; dynamic groups such as `wireguard` stay opaque), direction
(`in`, `out`, or both for `any`), family (`inet`, `inet6`, `inet46` = both), protocol per family (`TCP/UDP` =
{tcp, udp}; `ICMP` on IPv6 = ipv6-icmp), source and destination, source and destination ports (tcp/udp only),
and extra conditions that only narrow the match (`icmptype`, `icmp6type`, `tagged`, `sched`, `tos`, `prio`,
`received-on`, `tcpflags*`, `os`).

**Addresses and ports with lower and upper bounds.** Every token becomes a pair (lower bound = addresses that
certainly match; upper bound = addresses that may match), per family, as sets of intervals:

| token | lower | upper |
|---|---|---|
| `any` | everything | everything |
| IP, CIDR, range `a-b` | exact | exact |
| static host/network/networkgroup alias (nested, `!exclusion`) | entries − exclusions | entries |
| FQDN entry or wildcard mask inside the alias | — | everything |
| url/urltable/urljson/geoip/asn/mac/dynipv6host/authgroup/external/internal alias, dynamic `__name` (Q-Feeds, captive portal), disabled alias | empty | everything (**opaque**) |
| interface network (`lan`, `__lan_network`) with a static IP | network of the IP + ipalias/carp VIPs (+ fe80::/10 on IPv6) | same as the lower bound in the family with a static IP; everything in a dynamic family or without an IP |
| interface address (`lanip`, `wanip`, `optNip`) | static IP + VIPs | the same on static IPv4; everything on IPv6 or dynamic |
| `(self)` | every static IP of the firewall + loopback | everything |
| unknown name | empty | everything, and the rule is flagged as not loaded (the generator disables the rule: "Unable to convert address") |

Ports: number, range (`a-b`, `a:b`, `any` at either end), known names of `PortField`, port alias (nested). An
empty port alias matches nothing (pf generates `0 <> 65535`).

**Containment B ⊆ A** (`Rule.covers`): interfaces of B ⊆ interfaces of A; directions of B ⊆ those of A; for
every family in which B may match something: the family is in A, protocols of B ⊆ those of A (A `any` covers
everything), and for source and destination every token of B is the **same token** of A or has an upper bound ⊆
the lower bound of A; ports (A without a port covers everything; B without a port is only covered by A without
a port); every extra condition of A exists, equal, in B (for ICMP types, the types of B ⊆ those of A). Since the
upper bound of B is always compared with the lower bound of A, opaque content never yields a false shadowing.
The only, intentional, exception is the same alias on both sides: same name = same pf table.

**Effect** of a rule: action + `gateway`, `replyto`, `tag`, shaper, `set-prio`, `divert-to`, state options and
limits (ignored on block/reject). `log` does not count as an effect (it shows up in `evidence.log_differs`).

## Fields of contract revision 1

See `../CONTRACT.md` ("Report format") for the full JSON contract.

- `stats` at the top: `source` (`configctl filter rule stats`, `rule_stats.py` or `file`), `ruleset_loaded` (mtime
  of `/tmp/rules.debug`), `boot_time` (`kern.boottime`), `keepcounters` (from the config), `keepcounters_source`
  (`mvc`, `legacy` or `null`, revision 2), `counters_since` (= `boot_time` with keepcounters, else
  `ruleset_loaded`) and `settings_page` (revision 2). Without counters everything is `null` except
  `keepcounters`. Per rule, the `evidence.counters_since` of `unused` still takes the last change of the rule
  into account when keepcounters is on.
- Items of `rules[]`: `quick`, `enabled`, `priority_group` (`floating` < 300000, `group` < 400000, else
  `interface`) and `ref`. MVC: `ui/firewall/filter#search=<uuid>`. The rules page of 26.7 only understands
  `#interface=<if>` and `#search=<text>` in the hash, and the search of `FilterController` includes the uuid, so
  the link opens the list already filtered down to the rule. The core `#ref` (`pf.inc`) is
  `ui/firewall/filter#<uuid>`, but that one only opens the list. Legacy rule:
  `firewall_rules_edit.php?if=<if|FloatingRules>&id=<index>` if `/usr/local/www/firewall_rules.php` exists, else
  `ui/firewall/migration` (the 26.x case, `filter_core_rules_user`).
- Pair findings (`shadowed`, `redundant`, `duplicate`): `rules[0]` is the affected rule, `rules[1]` the one that
  covers or overrides it; `evidence.mode` is `earlier_quick`, `later_overrides` or `later_covers`.

## Compatibility with 27.1 (contract revision 2)

Covers the Filter.xml 1.1.7 of master without changing the result on 26.7 (`test_opnsense_27_1.py`, 18 cases):

- **`match` action**: its own verdict (`Rule.verdict` = `match`). The rule goes into `ctx.matching`, not into
  `ctx.decisive`; `detect_order` only looks at the decisive ones, so a match rule never covers nor is covered by
  pass/block (project decision: a match after a block quick that covers it is **not** reported either). The
  rules migrated by the normalisation (MFP1_0_8: floating, `quick=0`, `direction=any`, `statetype=none`) stay
  silent. `permissive`/`wan_exposed` already require `pass`; `unused` applies to match (pf counts packets on
  them).
- **`detect_quick_match`**: a match with `quick` ends the evaluation (pf.conf: "this rule is considered the last
  matching rule"; the core says the same in MFP1_0_8). A later pass/block covered by it: `shadowed` high,
  `mode = quick_match`, `rules[1]` = the match.
- **`detect_match_duplicates`**: two match rules with the same space (`same_match`), the same options and the
  same `quick`: `duplicate` medium, `mode = match_duplicate`.
- **Effect of match rules**: only `tag`, shaper, `set-prio`, `divert-to`, `allowopts` and `scrub_*`
  (`MATCH_EFFECT_FIELDS`); gateway/reply-to and state options are dropped by `FilterRule` for everything that is
  not pass.
- **`scrub_*`** are part of `EFFECT_FIELDS` (the booleans `scrub_no_df`/`scrub_random_id` are normalised, so a
  26.7 rule without the nodes and a 27.1 rule with `0` have the same effect).
- **Firewall settings** (`FirewallConfig.filter_settings`): reads `//OPNsense/Firewall/Filter/settings/filter`
  and falls back to the legacy nodes key by key (`FILTER_SETTINGS_LEGACY`: `keep_counters`←`system/keepcounters`,
  `skip_rules_gw_down`, `disable_reply_to`, `no_antilockout`, `disabled`, `state_policy`). `keepcounters_source`
  tells where it came from. `settings_page` picks the link by `_model`. The text of `inactive not_loaded` only
  mentions "skip rules when gateway is down" if the option is on and the rule has a gateway.
- **Leftover `filter/scrub`**: ignored in `text_tokens()` when the Filter version is ≥ 1.0.8
  (`SCRUB_MIGRATED_VERSION`); on 26.7 the scrub rules are real and still count as alias usage.

Extra validation: the fixtures of the 27.1 working notes (`f26-equiv.xml`, `f27-base.xml`, `f27-match.xml`, not
shipped) give the expected result: `keepcounters` read in both formats; `f27-match` yields `shadowed high
quick_match`, `shadowed medium` with `differences: [scrub_max_mss]` and no finding for the migrated match rules.

## Detectors (exact logic)

Only enabled, loaded rules that can match some packet are evaluated (the `evaluated` list), except where noted.

| type | severity | fires when |
|---|---|---|
| `shadowed` | high / medium | An earlier **quick** rule covers the whole space of the rule (B ⊆ A) and the effect differs. **high** if one is pass and the other block/reject; **medium** if both block (block × reject) or if the action is the same but another option differs (e.g. gateway). It also fires (mode `later_overrides`) for a **non quick** rule covered by any later rule, because its decision is always overridden (last match). `evidence.differences` lists the differing fields. |
| `duplicate` | medium | Same case as above with an equal effect and identical spaces (A ⊆ B and B ⊆ A). Reported once, on the later rule. Between match rules (27.1): same space, same options and same quick, `mode = match_duplicate`. |
| `redundant` | medium | Same case as above with an equal effect and the space of B strictly smaller. |
| `shadowed` (mode `quick_match`) | high | A match rule with `quick` covers a later pass/block: the evaluation stops at the match and the decision stays with the last earlier pass/block (or the default rule). |
| `redundant` (mode `later_covers`) | low | Quick rule B covered by a later quick rule C with the same effect, and no quick rule between B and C with a different effect can match the same traffic (conservative intersection test on the upper bounds). Removing B does not change the policy. |
| `unused` | low / info | Counters only. MVC rule present in the counters with `packets == 0` and `states == 0`. Window: without `keepcounters`, since the last ruleset load (mtime of `/tmp/rules.debug`); with `keepcounters`, since the later of boot (`kern.boottime`) and the last change of the rule (`audit.updated`). **info** if the window is unknown or shorter than 7 days. Legacy rules are skipped (their label is an md5 computed in PHP). |
| `inactive` | medium | Enabled rule the generator does not load: missing interface, address or port that does not resolve. If the counters show the label of the rule it is considered loaded and the finding is not raised. |
| `inactive` (mode `not_loaded`) | low | With counters: enabled, analysable MVC rule whose uuid is not in the ruleset (gateway down with "skip rules", pending apply). |
| `never_matches` | medium | Enabled, loaded rule that matches nothing (e.g. `inet` with an IPv6-only destination), when the cause is not an empty alias. |
| `permissive` | high / medium / low / info | Pass rules only. `any_any`: source any, destination any, protocol any: **high** if it enters a WAN interface, else **medium**. `wan_any_source_any_port`: inbound on the WAN, source any, no port restriction: **medium**. `wan_any_source_any_destination`: inbound on the WAN, source and destination any with a restricted port: **medium**. `any_any_protocol_limited`: any→any outside the WAN with a restricted protocol/port: **low**. `wan_any_source`: inbound on the WAN with source any (destination and port restricted, e.g. a port forward): **info**, omitted when the same rule is already reported as `wan_exposed`. Source "LAN net" → any is not permissive. |
| `wan_exposed` | high / medium / low | Pass rule entering (`in` or `any`) a WAN interface. Admin ports = the webgui port (or 443/80 depending on the protocol) and ssh (if enabled, default 22), TCP only. Explicit firewall destination (`(self)`, `wanip`/`lanip`/`optNip`, a literal that includes a firewall IP): **high** if it reaches an admin port with source any, **medium** with a restricted source, **low** if only a non admin service with source any (e.g. VPN). Destination that includes the firewall (any, interface network, alias, inverted) with an explicitly restricted port that includes an admin port: **high** with source any, else **medium**. |
| `disabled` | info / low | Every disabled rule. **low** if the last change (MVC `audit` or legacy `updated/created`) is 90 days old or more. |
| `no_description` | info | Enabled rule without a description. |
| `empty_alias` | medium / low / info | host/network/networkgroup/port/url/geoip etc. alias without any entry in the config (or whose content resolves to empty). Referenced by an enabled rule: **medium** for a port alias, **low** for an address table (it may be filled at runtime through the alias API). Not referenced: **info**. Rules that match nothing because of it do not yield `never_matches` and are left out of the order analysis. |
| `unused_alias` | info | User alias whose name (or uuid) does not appear as a value anywhere in the config, apart from its own definition and free texts (`descr`/`description`). Covers rules, NAT, nested aliases and settings of other plugins. |

**WAN**: interface `wan`, or one with `gateway`/`gatewayv6`, or dynamic IPv4 (dhcp, pppoe, pptp, l2tp, ppp),
IPv6 dhcp6/slaac/6rd/6to4/pppoe, or with `blockbogons`/`blockpriv`. A rule "enters the WAN" if its direction
includes `in` and its set of interfaces may contain a WAN (floating without an interface counts).

**IDs**: `sha1(type:uuids:aliases:mode)[:16]`; in pair findings (shadowed/redundant/duplicate) the order is
affected rule, covering rule. Stable between runs as long as the rules keep their uuid.

## Known limitations

- Coverage by **one** rule only (B covered by the union of several rules is not detected).
- Automatic rules (anti-lockout, bogons, default deny, rules generated by plugins) are not considered.
- Opaque tables (url, GeoIP, FQDN, dynamic) never cover another rule; only the same alias on both sides.
- The implicit `flags S/SA` of stateful pass rules is ignored (per connection analysis, not per packet).
- Counters of legacy rules are not associated (md5 label from PHP).
- Runtime changes of entries through the alias API are not seen (the engine only reads the config).
