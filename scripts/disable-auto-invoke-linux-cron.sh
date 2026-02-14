#!/usr/bin/env bash
set -euo pipefail

MARKER="# openclaw-cyber-security-engineer-auto"
TMP="$(mktemp)"
crontab -l 2>/dev/null | grep -v "${MARKER}" > "${TMP}" || true
crontab "${TMP}" || true
rm -f "${TMP}"

echo "Auto-invoke cron entry removed."
