#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer supports Linux only."
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found; use scripts/enable-auto-invoke-linux-cron.sh"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${REPO_ROOT}/scripts/auto-invoke-security-cycle.sh"
UNIT_DIR="${HOME}/.config/systemd/user"
SERVICE="${UNIT_DIR}/ai.openclaw.cyber-security-engineer.service"
TIMER="${UNIT_DIR}/ai.openclaw.cyber-security-engineer.timer"

mkdir -p "${UNIT_DIR}" "${HOME}/.openclaw/logs"

cat > "${SERVICE}" <<EOF
[Unit]
Description=OpenClaw Cyber Security Engineer auto cycle

[Service]
Type=oneshot
ExecStart=/bin/bash ${RUNNER}
EOF

cat > "${TIMER}" <<'EOF'
[Unit]
Description=Run OpenClaw Cyber Security Engineer auto cycle every 30 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now ai.openclaw.cyber-security-engineer.timer
systemctl --user start ai.openclaw.cyber-security-engineer.service

echo "Auto-invoke enabled via systemd user timer."
echo "Timer: ai.openclaw.cyber-security-engineer.timer"
