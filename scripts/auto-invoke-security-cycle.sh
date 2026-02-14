#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALLED_RUNNER="${HOME}/.openclaw/workspace/skills/cyber-security-engineer/scripts/auto_invoke_cycle.sh"
REPO_RUNNER="${REPO_ROOT}/cyber-security-engineer/scripts/auto_invoke_cycle.sh"

if [[ -x "${INSTALLED_RUNNER}" ]]; then
  exec /bin/bash "${INSTALLED_RUNNER}"
fi

if [[ -x "${REPO_RUNNER}" ]]; then
  exec /bin/bash "${REPO_RUNNER}"
fi

echo "No auto cycle runner found. Expected one of:"
echo "  ${INSTALLED_RUNNER}"
echo "  ${REPO_RUNNER}"
exit 1
