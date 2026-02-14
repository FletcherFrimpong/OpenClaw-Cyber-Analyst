#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OS="$(uname -s)"

case "${OS}" in
  Darwin)
    bash "${REPO_ROOT}/scripts/enable-auto-invoke-macos.sh"
    ;;
  Linux)
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl --user show-environment >/dev/null 2>&1; then
        bash "${REPO_ROOT}/scripts/enable-auto-invoke-linux-systemd.sh"
      else
        bash "${REPO_ROOT}/scripts/enable-auto-invoke-linux-cron.sh"
      fi
    else
      bash "${REPO_ROOT}/scripts/enable-auto-invoke-linux-cron.sh"
    fi
    ;;
  *)
    echo "Unsupported OS for auto installer: ${OS}"
    echo "Windows: run scripts/enable-auto-invoke-windows.ps1 in PowerShell."
    exit 1
    ;;
esac
