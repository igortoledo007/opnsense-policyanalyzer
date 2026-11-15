# os-policyanalyzer (development)

Read-only analysis of the OPNsense firewall rule set, with optional AI explanations.
Target: opnsense/plugins `security/policyanalyzer`, OPNsense 26.7.

- **Firewall › Policy Analyzer** (`/ui/policyanalyzer/`). Two ACL entries (with `<authority>` for 27.1+,
  ignored by 26.7): `page-firewall-policyanalyzer` (limited: run/read the analysis, AI state, history, read
  settings) and `page-firewall-policyanalyzer-admin` (administrative: settings set/clear, change plan/apply/revert,
  AI explain/test/models). The GUI never needs root: everything privileged goes through configd.
- Tabs: **Findings**, **Action history**, **Settings**
- **AI setup**: a step by step assistant in a modal over the page (full screen on phones), opened by the
  "AI setup" button of the Findings tab, "Open AI setup" in the Settings, `/ui/policyanalyzer/#setup[-N]` and the
  route `/ui/policyanalyzer/setup` (renders the same page with the modal open). See "AI setup assistant" below.
- The analysis never changes rules or settings. The AI only explains and suggests in text.
  Every change the page *can* make (settings, model storage) is simulated first and can be reverted.

The JSON produced by the analyzer is described in `../CONTRACT.md` ("Report format": version 1 + revisions 1 and 2).

## Layout

```
Makefile, pkg-descr
src/opnsense/mvc/app/
  models/OPNsense/PolicyAnalyzer/PolicyAnalyzer.{xml,php}   settings (mount //OPNsense/policyanalyzer)
  models/OPNsense/PolicyAnalyzer/{ACL,Menu}/                 ACL + menu entry
  controllers/OPNsense/PolicyAnalyzer/IndexController.php    page
  controllers/OPNsense/PolicyAnalyzer/SetupController.php    /ui/policyanalyzer/setup: the page with the AI setup open
  controllers/OPNsense/PolicyAnalyzer/forms/settings.xml      shared AI fields
  controllers/OPNsense/PolicyAnalyzer/Api/
    AnalysisController.php   analyze, findings, summary, search, finding/<id>
    AiController.php         status, providers, explain, test, models, storage
    SettingsController.php   get, set (journaled), clear_secret (journaled)
    ChangeController.php     plan, apply, history, actions (generic simulate/apply/revert)
    SetupController.php      setup/hwprofile (read only probe for the AI setup, plus the product version)
    ApiHelperTrait.php       configd JSON helper, id/argument patterns, GUI language
  views/OPNsense/PolicyAnalyzer/index.volt
  views/OPNsense/PolicyAnalyzer/setup.volt                    partial: strings of the AI setup (included by index.volt)
src/opnsense/www/js/policyanalyzer/simulation.js            reusable simulation dialog + background job progress
src/opnsense/www/js/policyanalyzer/recommend.js             reusable "Recommended for this hardware" block
src/opnsense/www/js/policyanalyzer/setup.js                 AI setup assistant (PASetup.bind/open), modal
src/opnsense/www/css/policyanalyzer/setup.css               AI setup styles (stepper, sticky footer)
src/opnsense/www/css/policyanalyzer/policyanalyzer.css      page styles (mobile), theme independent
src/opnsense/service/conf/actions.d/actions_policyanalyzer.conf
src/opnsense/scripts/policyanalyzer/
  analyze.py, engine/      the analyzer (separate component, see ../CONTRACT.md, "Report format")
  explain.py               configd entry: explain | test | models | providers
  manage.py                configd entry: status | list | history | plan | apply | settings
  ai/                      reusable AI layer (below)
  setup/                   local runtime (jail) actions, separate component
```

## API and configd

| API | configd (`configctl policyanalyzer ...`) | notes |
|---|---|---|
| POST `analysis/analyze` | `analyze` | runs analyze.py, stores `/var/db/policyanalyzer/last.json` |
| GET `analysis/findings`, `analysis/summary`, POST `analysis/search`, GET `analysis/finding/<id>` | `findings` | reads last.json |
| POST `ai/explain` `{id: <finding id>\|all, preview: 0\|1}` | `explain <id> <lang> <send\|preview>` | only ids, never free text |
| POST `ai/test`, GET `ai/models`, GET `ai/providers`, GET `ai/status` | `ai_test`, `ai_models`, `ai_providers` | test/models use the *saved* settings, send no findings |
| GET `ai/runtime`, GET `ai/job` | `ai_runtime`, `setup_job` | local runtime state and background job progress (from `setup/`) |
| GET `setup/hwprofile` | `ai_hw_profile` | hardware profile for the AI setup check step (`manage.py status hw_profile`) + product version |
| GET `ai/storage?path=` | `ai_storage <path>` | read only: exists, writable, filesystem, ZFS dataset, free space |
| GET/POST `settings/get`, `settings/set`, POST `settings/clear_secret {field}` | `settings_journal snapshot\|record\|reverted <id>` | every save becomes an undo journal entry |
| POST `change/plan`, `change/apply` `{action, args[]}`; GET `change/history`, `change/actions` | `change_plan`, `change_apply`, `change_history`, `change_list` | generic simulate/apply/revert |

Rule links use the analyzer's `ref` (`ui/firewall/filter#search=<uuid>`) and always open a new page load
(`target=_blank`), because changing only the hash of an open rules page does not re-run the search. Legacy rules
(`source: legacy`) are shown read-only by the 26.x rules page; the page links to Firewall › Rules › Migration.

## Installing on a test firewall (documentation only)

Development package (preferred), on a build host with the opnsense/plugins tree:

```sh
# copy this plugin/ directory to plugins/security/policyanalyzer
cd plugins/security/policyanalyzer
make package             # -> work/pkg/os-policyanalyzer-devel-0.1.pkg (PLUGIN_DEVEL=yes)
# on the firewall:
pkg add ./os-policyanalyzer-devel-0.1.pkg
```

Or copy the files directly on a lab firewall:

```sh
# from this directory
scp -r src/opnsense/* root@fw:/usr/local/opnsense/
ssh root@fw 'chmod 755 /usr/local/opnsense/scripts/policyanalyzer/*.py && service configd restart'
# the menu/ACL caches live in the PHP temp dir, not /tmp (otherwise the page has no title/menu entry):
ssh root@fw 'rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json'
# OPNsense runs php-cgi spawned by lighttpd with opcache.validate_timestamps=0 (one opcache per child): after updating any PHP file, restart the web GUI
# (otherwise old controllers stay cached and new endpoints return "Endpoint not found"):
ssh root@fw 'configctl webgui restart'
```

Then log in again (menu and ACL are cached per session) and open Firewall › Policy Analyzer. Quick checks from a shell:

```sh
configctl policyanalyzer analyze | head -c 300
configctl policyanalyzer ai_providers
configctl policyanalyzer change_plan prepare_storage /var/db/ai/models
```

Logs: `/var/log/policyanalyzer/ai.log` (AI audit), `/var/log/policyanalyzer/storage.log` (storage changes),
undo journal in `/var/db/policyanalyzer/undo/`.

## AI layer (`scripts/policyanalyzer/ai/`)

A self-contained package meant to be reused by other read-only assistants (an "Explain this" button for logs,
IDS alerts and rules; incident triage). It has no Policy Analyzer specifics except default paths, which callers
override.

| module | role |
|---|---|
| `config.py` | `AIConfig.from_opnsense(mount)` reads the settings (read only) from config.xml; any model with the same `ai` + `<provider>` layout works |
| `providers/` | registry of providers (`ollama`, `claude`), stdlib `urllib` only, TLS verified, no proxies, no redirects |
| `anonymizer.py` | reversible placeholders: `IP4_PRIV_n`, `IP4_PUB_n`, `IP6_n`, `HOST_n`, `DESC_n`, `ALIAS_n`, `USER_n`, `MAC_n`; prefixes, ports, interfaces and loopback stay |
| `prompts.py` | fixed guardrail system prompt (use only the data, cite rules as given, never claim changes, data is untrusted, keep placeholders, answer language) |
| `audit.py` | JSON lines audit: hashes, sizes, provider, endpoint, model, duration, token usage (incl. cache reads); the prompt only when it was anonymized, never raw data, never API keys |
| `assistant.py` | `Assistant(config, app=...).ask(Task, data, language)`: anonymize → prompt → provider → restore → audit; `preview()` shows the payload without sending |
| `changes.py`, `journal.py`, `storage.py`, `settings_journal.py` | plan/apply/revert framework (below) |

Reusing it in another plugin:

```python
from ai import AIConfig, Assistant, AuditLog, Task
cfg = AIConfig.from_opnsense('OPNsense/assistant')
assistant = Assistant(cfg, app='assistant', audit=AuditLog('/var/log/assistant/ai.log'))
answer = assistant.ask(Task('explain_log', instructions='...', question='Explain this log line.'),
                       {'line': '...'}, language='pt_BR', subject='log:filter')
```

Guarantees: off by default; the AI never gets a tool or API key that changes anything; data is anonymized by
default and placeholders are restored only in the answer shown to the user; preview shows exactly what would be
sent; the answer is displayed as escaped text next to the deterministic evidence.

### Providers

Settings: provider `none | ollama | claude`, timeout, anonymization (default on), answer language (default: GUI).

- **Ollama** — one provider card with the sub-parameter *Where does Ollama run?* (`ollama.location`):
  `local` (127.0.0.1:11434, the isolated jail runtime of the AI setup; shows the runtime state from
  `status runtime`, a link to the AI setup, "Models directory" with live storage info and "Prepare storage") or
  `lan` (URL, with a warning when the host is not a private/LAN address). Model + "List models" (`/api/tags`) and
  timeout in both. For `local`, `num_thread`/`num_ctx` are read from `/var/db/policyanalyzer/runtime-limits.json`
  (`threads`, `ctx`, written by the AI setup) and sent with every request. Optional NDJSON streaming in the client.
  Model 1.0.1 renamed `ollama.mode` (local|network) to `ollama.location` (local|lan); migration `M1_0_1` maps the
  old values (and the early `ollama_local`/`ollama_lan` provider values).
- **Claude (Anthropic API)** — API key (write-only field, shown as `configured ****1234`, clear with revert),
  model `claude-fable-5-1` (default, most capable, US$10/50 per MTok in/out), `claude-opus-5-5` (US$4/20),
  `claude-sonnet-5-5` (US$2/10), `claude-haiku-5-5` (US$0.10/0.50); effort `low|medium|high|xhigh|max`
  (default high); default timeout 180 s (an empty timeout means the provider default: Ollama 120 s, Claude 180 s).
  Fable requires 30 day data retention on the Anthropic organization: a 400 mentioning retention is shown as
  "this model is not available under zero data retention; choose Opus 5.5". `POST https://api.anthropic.com/v1/messages` with `anthropic-version: 2026-10-21`,
  `max_tokens: 16000`, `output_config.effort`, system prompt as a cached text block
  (`cache_control: ephemeral`, nothing variable in it), refusal fallback (`anthropic-beta:
  server-side-fallback-2026-07-01`, `fallbacks: "default"`) for Fable, Opus and Sonnet (not Haiku). `stop_reason` is checked first
  (`refusal` → explanation shown, `max_tokens` → truncation warning); only `text` blocks are used. 401/403 →
  key message; 429 → one retry honouring `retry-after`; 5xx/529 → one retry with backoff. No temperature,
  `thinking` (in any form), `tool_choice` or prefill parameters. The GUI warns that data leaves the firewall for api.anthropic.com.
  The official SDK exists in ports (`misc/py-anthropic`) and would be the preferred client, but it pulls in a
  large dependency tree (httpx, pydantic, ...) that a small plugin should not add to the firewall, so the
  provider speaks the HTTP API with urllib. Python's own CA store is empty on OPNsense; the client falls back to
  the system store `/usr/local/etc/ssl/cert.pem` and always verifies certificates.

#### Adding a provider

1. `ai/providers/<name>.py`: subclass `BaseProvider`, declare `name`, `label`, `group` (`local` or `api`),
   `choices` (entries of the initial choice, e.g. Ollama has "on this firewall" and "network server"),
   `fields` (`id`, `label`, `type` text|password|dropdown|url|choice|status, `required`, `secret`, `default`,
   `options`, `option_help`, `help`, `show_if`, `list_models`, `storage`, `warn_public`, `probe`, `wizard_url`;
   type `recommend` with `target`)
   and `privacy`. A `choice` field is a sub-parameter rendered as stacked options; other fields use
   `show_if: {<choice id>: <value>}` to appear only for one value; implement `endpoint()`, `health()`,
   `list_models()`, `chat()`.
2. Add it to `PROVIDERS` in `ai/providers/__init__.py`.
3. In `PolicyAnalyzer.xml`: an option in `ai.provider` and a container named after the provider with one
   element per field (secrets as `UpdateOnlyTextField`); optional `validateProvider<Name>()` in `PolicyAnalyzer.php`.

The Settings tab builds the grouped choice (Local / API), the fields and the privacy note from
`configctl policyanalyzer ai_providers`; the volt and JS need no change.

## Simulate → apply → revert (contract for every change)

Every action that changes the system goes through `manage.py plan|apply <action> [args]` (configd
`change_plan`/`change_apply`, API `change/plan`/`change/apply`) and the reusable dialog `PASimulation`
(`www/js/policyanalyzer/simulation.js`): the plan is shown (steps with command and effect, warnings, what can not
be reverted, risk, disk space), Apply stays disabled until the operator confirms (twice when something is
irreversible or other changes depend on it), and the result is recorded in the undo journal.

JSON returned by plan and apply:

```json
{"status": "ok", "action": "prepare_storage", "args": {"path": "/var/db/ai/models"},
 "steps": [{"description": "...", "command": "...", "effect": "..."}],
 "warnings": [], "irreversible": [], "revert": ["how it will be reverted"],
 "risk": "none|low|medium|high", "space": "optional note",
 "requires_confirmation": true, "requires_double_confirmation": false,
 "apply_via": "backend",
 "done": true, "completed": ["command", "..."], "journal_id": "20261107T183000-1a2b3c"}
```

Rules: `plan` never changes anything; `apply` recomputes the plan itself (nothing executable comes from the
browser, only validated arguments; arguments that come from the settings — e.g. the models directory — are
resolved by `ChangeController::$modelArgs`); idempotent; existing objects are never destroyed or modified unless
the plan says so; every executed step is logged.

**Reversion.** Every apply returns `state` (what it created/changed and previous values); the dispatcher writes
`/var/db/policyanalyzer/undo/<id>.json` (`id, ts, action, args, status, completed, state, irreversible,
depends_on, reverted`, mode 0600). `plan revert <id> [flag...]` / `apply revert <id> [flag...]` call the action's
`revert_plan(entry[, flags])` / `revert_apply(entry[, flags])` (optional flags are simple tokens such as `force` or
`keep_models=no`, passed as a dict to implementations that accept a second argument); reverts are simulated like any change. If a newer, not reverted
entry lists this one in `depends_on`, the revert plan warns and requires double confirmation, and apply refuses
until the dependent change is reverted first. The **Action history** tab lists the journal with a Revert button
per entry. Built-in revertible actions:

- `prepare_storage <path>` (only below `/var/db/`): on a ZFS root and a path below `/var/db/ai`, creates
  `<pool>/ai` (`mountpoint=/var/db/ai recordsize=1M compression=off atime=off primarycache=metadata`) unless it
  exists (never modified) or `/var/db/ai` is a non-empty plain directory; then `mkdir -p -m 0750` (root:wheel).
  Revert removes only the directories this run created and destroys the dataset only if this run created it and
  it holds no files, children or snapshots; otherwise it explains and offers to remove the empty folders only.
- `settings` (journaled by the API on every save / clear): revert restores the previous values through the
  model (`apply_via: gui`; the values never reach the browser, secrets are displayed masked).

Recommended manual equivalent of the storage action (for documentation; the button does this with a
simulation and journal):

```sh
zfs create -o mountpoint=/var/db/ai -o recordsize=1M -o compression=off -o atime=off \
    -o primarycache=metadata zroot/ai
mkdir -p -m 0750 /var/db/ai/models
# the model server then uses OLLAMA_MODELS=/var/db/ai/models
```

The dataset shares the pool's free space (no quota); on a single-pool appliance this is the same space as `/`
and `/var/log`.

### Adding an action (AI setup wizard: install_runtime, pull_model, set_limits, benchmark, ...)

```python
# scripts/policyanalyzer/<package>/__init__.py imports the module below; <package> is listed in
# ai.changes.EXTENSIONS (currently "setup") and loaded by manage.py before dispatching.
from ai.changes import ChangeAction, register

@register
class PullModel(ChangeAction):
    name = 'pull_model'
    description = 'Download a model into the local runtime'

    def parse_args(self, args):          # list of strings from configd -> validated kwargs, ValueError otherwise
        ...
    def plan(self, **kw):                # contract above, read only; list "irreversible" items here
        ...
    def apply(self, **kw):               # same contract + "state" (+ "depends_on": [journal ids])
        ...
    def revert_plan(self, entry):        # entry = journal JSON
        ...
    def revert_apply(self, entry):
        ...
```

- Arguments: at most 3 simple tokens (`[A-Za-z0-9/_.:@+-]`, no `..`) per configd call; anything that comes from
  the settings is resolved server side via `ChangeController::$modelArgs`.
- Long running actions return `{"status": "started", "job": "<id>"}` and run detached; the page polls
  `GET /api/policyanalyzer/ai/job` (`manage.py status setup_job`) and shows progress (`step_index/step_total`,
  `step`, `bytes_done/bytes_total`) with a Cancel button (`change/apply` of `setup_cancel`), both in the simulation
  dialog and at the top of the Action history. The plan must already state the download size.
- `manage.py` merges `setup.adapter.STATUS_PROBES` (`runtime`, `setup_job`, `hw_profile`, `recommend`) into its
  `status` probes when the package is present (API `ai/runtime`, `ai/job`, `ai/recommend`).
- `www/js/policyanalyzer/recommend.js` (`PARecommend.load($el, {onUse})`) renders "Recommended for this
  hardware" (recommended model with s/finding, RAM, backend and notes such as the GPU note; alternatives with
  verdicts; suggested num_thread/num_ctx as text). "Use this model" passes the concrete model name. Settings uses
  it for Ollama local (field type `recommend`); the wizard can reuse it in step 5.
- The GUI side is `PASimulation.run({action, args, title, onDone})`; the history tab and revert need nothing.

Extension points for the wizard (safe to extend): `ai/changes.py` (`EXTENSIONS`, new `@register` classes in its
own package), `manage.py` (`STATUS` probes), `ChangeController::$modelArgs`, `PolicyAnalyzer.xml` (new
containers/fields), `providers/` (new providers), a new view/tab that reuses `simulation.js`.

## AI setup assistant

`www/js/policyanalyzer/setup.js` (`PASetup`), strings in `views/.../setup.volt`. A modal (BootstrapDialog via
`PASimulation.dialog`, class `pa-setup-dialog`) that uses the height of the screen: the header holds the title, the
thin step bar and "?" (what the assistant does); the footer holds Back / Skip / Undo / Simulate ... / Apply ... /
Next: <step> (Next disabled, with the reason as tooltip, until the step is done); only the body between them could
scroll, and on desktops every step is laid out in two columns (description and detected state on the left, every
option of the step on the right) so that it fits without scrolling from 1350x570 up. Simulation, result and undo
dialogs stack on top. Every step reads its state from the probes when it is shown (never cookies), so it can be
closed and reopened at any step (`#setup-N`). Closing never cancels a background job (notice + link to the history).

Rules: every notice that asks the user for something comes with the button that does it (Go to <step>, Run analysis,
Open Settings, Enable RAM limit, Resume ...); warnings of plans and of `status runtime` that carry
`warning_actions: [{warning, action: {id, label, args}} | {warning, link: {label, url}}]` are rendered with that
button / link (`PASimulation.warningItems`, `actionButton`). How to undo is said in plain words (`plainRevert`),
the technical revert list of the plan sits under "Technical details".

| step | probes (GET) | change (POST `change/plan` then `change/apply`) |
|---|---|---|
| 1 Check | `setup/hwprofile`, `ai/runtime` | none (fit / reservations / not recommended); RAM limit notice with `enable_racct` |
| 2 Provider | `ai/providers`, `settings/get` | none; Ollama LAN and Claude jump to step 8 |
| 3 Storage | `ai/storage` | `prepare_storage` |
| 4 Runtime | `ai/runtime` (+ `warning_actions`, `job`) | `install_runtime <quarterly\|latest> [cpus] [+no_start] [+no_boot]`; unfinished states: "Resume installation" (install again, idempotent), "Clean up partial install" (`uninstall_runtime`), "Start" (`start_runtime`); `stop_runtime`, `enable_runtime`, `disable_runtime`; **Remove local AI** = `revert <install id> [keep_models=no]` (fallback without journal entry: `uninstall_runtime [+remove_dataset <dataset>]`) |
| 5 Model | `ai/runtime`, `ai/recommend` (recommended + 3 alternatives, "See all models"), `ai/models` | `pull_model <name> [+custom] [+large]` (flags from the candidate `action`), "Resume download" after an interrupted pull, `remove_model <name>` |
| 6 Limits | `ai/runtime`, `change/actions`, `change/history` | `set_limits cpus/threads/ctx/nice[/mem_gb]`; RAM limit field disabled with "Enable RAM limit" (`enable_racct`) while `racct.enabled_now` is false, "pending reboot" + System: Power: Reboot link while `racct.pending_reboot` |
| 7 Test | `ai/runtime`, `ai/status`, `ai/job`, `analysis/search` | `benchmark <model>`; `ai/explain` preview and send of the first finding (answers in their own dialog) |
| 8 Finish | `settings/get`, `ai/status`, `ai/runtime` | `settings/set` (journaled; simulated as a settings diff first); Disable AI; Test connection |

The Revert of an `install_runtime` entry (Action history and Undo) goes through the same "Remove local AI" dialog:
one checkbox "Also delete downloaded models (X GB: names)", unchecked by default; ticking it plans again with
`keep_models=no` and Apply uses it. `install_runtime` takes at most 3 configd arguments: with cpuset, `+no_start`
and `+no_boot` together the cpuset is dropped and applied in the Limits step (the GUI says so).

## Mobile

The page works from 360 px up without depending on the theme (`www/css/policyanalyzer/policyanalyzer.css`,
layout only, colours from Bootstrap classes of the theme): severity cards 2×2; below 768 px the findings grid is
replaced by a list of cards (UIBootgrid's `responsive` option in 26.7 only wraps cell text, it has no card or
collapse mode); details, explanation, simulation and revert dialogs are full screen; touch targets ≥ 44 px;
Settings and the provider choice in one column; the Action history as stacked cards; no horizontal page scroll.

## Tests

`tests/ai/` (stdlib `unittest`, local fake HTTP servers, no network):

```sh
cd tests/ai && python3 -m unittest -v
```

Covers the anonymizer (round trip, consistency, streaming restore), the Ollama client (chat, streaming, errors,
timeout, redirect refusal, size cap), the Claude client (request shape, refusal, max_tokens, 401, 429 +
retry-after, 529, cache usage in the audit log, key never logged), explain.py end to end (anonymized payload, no
raw data in the audit log without anonymization, preview sends nothing), plan/apply/revert of the storage
action, settings journal masking and dependency checks.

## Exposure & vulnerabilities (`scripts/policyanalyzer/exposure/`)

Read-only backend that answers "what runs on this firewall, can the internet reach it, and which known
vulnerabilities affect it". Python 3 stdlib only; it reuses the rule engine (`engine/`) for reachability and
never changes the firewall. The network is used only when the caller passes `online`.

### Probes

`exposure.adapter.STATUS_PROBES` is merged by `manage.py` like `setup.adapter.STATUS_PROBES`
(`manage.py status <probe> [tokens]`):

| probe | what it returns |
|---|---|
| `inventory` | packages (`pkg query`), OPNsense (`opnsense-version -v/-O`) and FreeBSD (`freebsd-version -ku`) versions, listening sockets (`sockstat -46 -l -P tcp,udp`) grouped into services, binary (`procstat -b`) and owning package (`pkg which`), interfaces with WAN flag and live addresses (`configctl interface list ifconfig`, fallback: static addresses of config.xml), local addresses, admin ports, `limitations` |
| `exposure` | the services plus `internet_reachable: yes\|maybe\|no`, the opening rules (contract `rules[]` items with `level` and `notes`), targets per WAN interface/family, `source_restricted` |
| `vulns [online] [refresh]` | `pkg audit -q --raw=json-compact` (fallback: plain `pkg audit`), per package `{name, version, cves:[...], fixed_in, fix_available, reverse_deps, source}`; every CVE `{id, cvss, cvss_version, cvss_vector, severity, kev, kev_*, epss, epss_percentile, summary, refs, cwe, sources, provenance}`; feed status |
| `exposure_report [online] [refresh] [no-write]` | everything above + findings + `summary`; stores `/var/db/policyanalyzer/exposure.json` (0640) unless `no-write` |

Tokens: `online` / `online=1` (query the feeds), `refresh` (only with `online`: `pkg audit -F` downloads VuXML),
`no-write` (no exposure.json, no feed cache writes). CLI for tests/lab:
`python3 exposure/adapter.py <probe> [tokens] [--config PATH] [--pretty]`.

Services come from a data map (`exposure/services.py`: process → service, label, admin flag, packages that make
it up, attack classes). The GUI port of lighttpd is `webgui` (admin), its redirect listener too; sshd is `ssh`
(admin); unbound 953 and chrony 323 are control channels (admin); kernel sockets without a process are WireGuard
when the port matches an enabled instance. Anything else becomes a `needs_review` finding.

### Reachability

A service is a candidate when it listens on a wildcard address or on an address of a WAN interface (engine
definition of WAN: `wan`, gateway, dynamic IPv4/IPv6, block bogons/private). A probe packet "from any host, in on
the WAN, to the WAN address, proto/port of the service" is walked through the user rules in pf order (quick stops,
otherwise last match): `yes` when a pass rule certainly matches (any source, destination certainly the WAN
address — `(self)`, the interface address, any, a static network containing it — port certain, no extra
conditions), `maybe` when it may match (opaque alias such as GeoIP/URL/FQDN, restricted source, dynamic address the
engine only bounds from above), `no` otherwise. A block that certainly matches stops the walk when quick and
cancels earlier non quick passes. Loopback-only or LAN-only binds are `no` with the reason.

### Findings (contract format of CONTRACT.md, "Findings")

| type | severity |
|---|---|
| `exposed_vulnerable_service` | reachable (yes/maybe) with a KEV CVE or CVSS ≥ 9: **high** (`maybe` + CVSS ≥ 9 without KEV: medium); reachable otherwise: **medium**; not reachable or not used by any listening service: **low**. Link `direct` (the package is the service or one of its components) or `dependency` (a component of the service depends on it, e.g. sqlite3 ← php85-sqlite3 ← web GUI; capped at medium without KEV; interpreters such as python/perl are not linked through dependencies). One finding per service and package; all ports in `evidence.ports`. |
| `known_exploited_vuln` | **high**: an installed package has a CVE in a KEV feed (reachable services listed in the evidence) |
| `admin_exposed_to_internet` | management service (web GUI, ssh, control channels) reachable: **high** (`yes`, or `maybe` with any source), **medium** (`maybe` with restricted source). Complements `wan_exposed` of the rule analysis with what really listens; `evidence.suggested_rule` holds a quick block rule (not applied). |
| `service_listening_all_interfaces` | **low**: bound to the wildcard address |
| `outdated_component` | `pkg version -U -vRl '<'` (local catalogue, no download): **low** when vulnerable or part of a listening service, else **info** |
| `needs_review` | **info**: unknown listening process or kernel socket, binary not owned by a package, OPNsense advisory whose version range could not be compared, VuXML missing or older than 7 days, partial service list (not root) |

Recommendations are concrete and only suggested: update to the version the repository offers (or say that the
fixed version is not published yet), isolate from the WAN (quick block above the opening rule, restrict the source,
VPN, listen interfaces) and the local Suricata rules that reference the CVE (`reference:cve,…` in
`/usr/local/etc/suricata/rules/*.rules`, sid and whether it is enabled).

`summary` (for the Max Cyber HUD): `services, reachable, maybe_reachable, admin_reachable,
listening_all_interfaces, packages, vulnerable_packages, cves_total, kev, findings, by_severity, posture`
(`critical` = any high finding; `exposed` = any medium finding or a non-VPN service reachable; else `hardened`),
`posture_confidence` (`partial` when the service list is incomplete), `services_complete`, `online` and
`attack_surface` (reachable services with CVE/KEV counts). The document also has `services`, `vulns`,
`outdated`, `inventory` and a reserved `devices: {status: "not_collected", items: [], source: null}` for the
LAN devices front.

### Feeds (opt-in) and cache

Online sources come from a registry merged by `id` (later wins): built-in defaults → config.xml
`//OPNsense/policyanalyzer/exposure/feeds/feed` (`id, name, url, type, enabled, ttl, max_requests, interval`;
model still to be added) → `/var/db/policyanalyzer/feeds.json` (`{"feeds": [...]}`).

| id | type / mode | source |
|---|---|---|
| `cisa_kev` | `kev` / bulk | CISA Known Exploited Vulnerabilities JSON |
| `first_epss` | `epss` / batch (100 CVEs) | `api.first.org/data/v1/epss?cve={cves}` |
| `nvd` | `nvd` / per CVE | NVD 2.0 `cves/2.0?cveId={cve}`; no API key: 6.5 s between requests, at most 20 per run (the rest is `deferred` and filled on later runs thanks to the cache) |
| `osv` | `osv` / per CVE | `api.osv.dev/v1/vulns/{cve}`; CVSS v3 score computed from the vector (`exposure/cvss.py`), v4 kept as vector |
| `opnsense_ghsa` | `ghsa_opnsense` / bulk | GitHub security advisories of opnsense/core (the `docs.opnsense.org/vulnerabilities.html` page does not exist), matched against `opnsense-version` per release series; affecting advisories appear as package `opnsense` (id = CVE or GHSA id) |

Merge: per CVE, each field from the best source (CVSS: NVD > OSV > advisory; summary: NVD > OSV > advisory >
VuXML; KEV/EPSS from their feeds), `sources` lists every contributor and `provenance` the source of each field;
a CVE seen in several packages is counted once. Validation: https only, URL placeholders limited to
`{cve}`/`{cves}` (filled with validated CVE ids — nothing else about the firewall is ever sent), known parser types,
TTL 1 h – 30 d. HTTP: urllib, TLS verified with `/usr/local/etc/ssl/cert.pem` when Python's store is empty, no
proxy, no redirects, 10 s timeout, 32 MB cap. Cache: `/var/db/policyanalyzer/vuln-cache/<feed>/<hash>.json`
(0640, TTL 24 h by default; negative answers are cached too). Offline runs never touch the network and use the
cache even when expired (`stale` in the feed status).

### Limitations

- Listening sockets of other users need root (`see_other_uids=0` on OPNsense): run through configd; without root
  the list is partial and the report says so (`services_complete: false`, `needs_review`).
- Automatic rules (anti-lockout, IPsec/OpenVPN automatic rules, plugin rules) and NAT port forwards to the firewall
  itself are not in the user rule set and are not considered; runtime alias contents are not seen (opaque → maybe).
- FreeBSD base (kernel/userland) advisories are not checked unless the base is installed as packages
  (`pkg audit` then covers it); the versions are reported.
- VuXML is as fresh as `/var/db/pkg/vuln.xml` (updated by the firmware audit/cron or `refresh`).
- A dependency link means "a component of the service depends on the package", not that the vulnerable code path
  is reachable; the CVE description decides.
- LAN devices are out of scope (reserved `devices` slot).

### Tests

`tests/exposure/` (unittest, fake runner/HTTP, temporary files only, no network):

```sh
cd tests/exposure && python3 -m unittest -v
```
