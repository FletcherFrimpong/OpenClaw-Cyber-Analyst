#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OS="$(uname -s)"

case "${OS}" in
  Darwin)
    bash "${REPO_ROOT}/scripts/disable-auto-invoke-macos.sh"
    ;;
  Linux)
    bash "${REPO_ROOT}/scripts/disable-auto-invoke-linux-systemd.sh" || true
    bash "${REPO_ROOT}/scripts/disable-auto-invoke-linux-cron.sh" || true
    ;;
  *)
    echo "Unsupported OS for auto disable helper: ${OS}"
    echo "Windows: run scripts/disable-auto-invoke-windows.ps1 in PowerShell."
    exit 1
    ;;
esac
