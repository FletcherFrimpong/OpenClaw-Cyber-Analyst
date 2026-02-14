#!/usr/bin/env bash
set -euo pipefail

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found; nothing to disable."
  exit 0
fi

UNIT_DIR="${HOME}/.config/systemd/user"
SERVICE_NAME="ai.openclaw.cyber-security-engineer.service"
TIMER_NAME="ai.openclaw.cyber-security-engineer.timer"

systemctl --user stop "${TIMER_NAME}" >/dev/null 2>&1 || true
systemctl --user disable "${TIMER_NAME}" >/dev/null 2>&1 || true
systemctl --user stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
rm -f "${UNIT_DIR}/${SERVICE_NAME}" "${UNIT_DIR}/${TIMER_NAME}"
systemctl --user daemon-reload >/dev/null 2>&1 || true

echo "Auto-invoke systemd timer disabled."
