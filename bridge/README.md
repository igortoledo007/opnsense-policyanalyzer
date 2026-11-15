# claude-bridge: "Claude Code (LAN)" provider for the Policy Analyzer

A small HTTP service for a Linux computer in your LAN that has [Claude Code](https://claude.com/claude-code)
installed and logged in. The Policy Analyzer on the firewall sends a prompt; the bridge runs `claude -p` and returns
only the text, so the plugin can use the Claude Code subscription of that computer's owner instead of an API key.

## Safety model

- Claude Code runs in print mode with **every tool disabled** (`--tools ""`), no MCP servers, none of the user's
  settings or hooks, no session persistence, from an empty working directory: it can only return text.
- Only the allowed source addresses (the firewall) and a bearer token are accepted.
- One request at a time, a queue of 2, body limit 256 KiB, 300 s timeout per request.
- The firewall anonymizes the data before sending it when **Anonymize** is enabled in the plugin settings.

## Install (as a systemd user service, no root)

```sh
./install.sh
```

On first start it creates `~/.config/claude-bridge/config.json` and `~/.config/claude-bridge/token` (mode 0600).
Edit `allow` in `config.json` to the LAN address(es) of your firewall and restart:

```sh
systemctl --user restart claude-bridge
```

To keep it running without an open session: `loginctl enable-linger $USER`.

If the computer runs firewalld, open port 11436/tcp only for the firewall:

```sh
FIREWALL_IPS="192.168.1.1" ./allow-firewalld.sh
```

## Plugin side

Firewall › Policy Analyzer › AI setup › Provider **Claude Code (LAN)**: URL `http://<this computer>:11436` and the
token from `~/.config/claude-bridge/token`. Models: fable, opus, sonnet (default), haiku.

## Protocol

- `GET /health` → `{"status":"ok","service":"claude-bridge","version":"1","claude_version":...,"models":[...],"default_model":"sonnet","busy":false}`
- `POST /v1/chat` with `{"model":"sonnet","messages":[{"role":"system|user|assistant","content":"..."}],"timeout":300}`
  → `{"status":"ok","text":"...","model":"sonnet","duration_ms":...,"usage":{...}}`
- Errors: `{"status":"error","message":...}` with 401 (token), 403 (source), 413 (body), 429 `{"status":"busy"}` (queue full).
