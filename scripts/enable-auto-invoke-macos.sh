#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer currently supports macOS LaunchAgent only."
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${REPO_ROOT}/scripts/auto-invoke-security-cycle.sh"
PLIST_DIR="${HOME}/Library/LaunchAgents"
PLIST_PATH="${PLIST_DIR}/ai.openclaw.cyber-security-engineer.plist"
STDOUT_LOG="${HOME}/.openclaw/logs/cyber-security-engineer-launchd.out.log"
STDERR_LOG="${HOME}/.openclaw/logs/cyber-security-engineer-launchd.err.log"

mkdir -p "${PLIST_DIR}" "${HOME}/.openclaw/logs"

cat > "${PLIST_PATH}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>ai.openclaw.cyber-security-engineer</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${RUNNER}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>1800</integer>
  <key>StandardOutPath</key>
  <string>${STDOUT_LOG}</string>
  <key>StandardErrorPath</key>
  <string>${STDERR_LOG}</string>
</dict>
</plist>
EOF

launchctl bootout "gui/$(id -u)/ai.openclaw.cyber-security-engineer" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "${PLIST_PATH}"
launchctl enable "gui/$(id -u)/ai.openclaw.cyber-security-engineer" >/dev/null 2>&1 || true
launchctl kickstart -k "gui/$(id -u)/ai.openclaw.cyber-security-engineer"

echo "Auto-invoke enabled: ${PLIST_PATH}"
echo "Runs at login and every 30 minutes."
