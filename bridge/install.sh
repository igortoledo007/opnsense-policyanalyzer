#!/bin/sh
# Installs or updates claude-bridge as a systemd user service (no root needed).
set -e
D="$(cd "$(dirname "$0")" && pwd)"
install -D -m 0755 "$D/claude_bridge.py" "$HOME/.local/lib/claude-bridge/claude_bridge.py"
install -D -m 0644 "$D/claude-bridge.service" "$HOME/.config/systemd/user/claude-bridge.service"
systemctl --user daemon-reload
systemctl --user enable --now claude-bridge.service
systemctl --user restart claude-bridge.service
sleep 2
systemctl --user --no-pager status claude-bridge.service | head -5
echo "token file: $(/usr/bin/python3 -I "$HOME/.local/lib/claude-bridge/claude_bridge.py" token-path)"
