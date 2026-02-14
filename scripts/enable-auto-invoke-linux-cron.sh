#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" && "$(uname -s)" != "Darwin" ]]; then
  echo "Cron installer supports Unix-like systems only."
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${REPO_ROOT}/scripts/auto-invoke-security-cycle.sh"
MARKER="# openclaw-cyber-security-engineer-auto"
LINE="*/30 * * * * /bin/bash \"${RUNNER}\" ${MARKER}"

TMP="$(mktemp)"
crontab -l 2>/dev/null | grep -v "${MARKER}" > "${TMP}" || true
printf '%s\n' "${LINE}" >> "${TMP}"
crontab "${TMP}"
rm -f "${TMP}"

echo "Auto-invoke enabled via cron (every 30 minutes)."
