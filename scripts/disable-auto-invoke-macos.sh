#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This helper currently supports macOS LaunchAgent only."
  exit 1
fi

PLIST_PATH="${HOME}/Library/LaunchAgents/ai.openclaw.cyber-security-engineer.plist"

launchctl bootout "gui/$(id -u)/ai.openclaw.cyber-security-engineer" >/dev/null 2>&1 || true
rm -f "${PLIST_PATH}"
echo "Auto-invoke disabled."
