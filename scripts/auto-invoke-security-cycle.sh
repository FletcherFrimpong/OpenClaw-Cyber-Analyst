#!/usr/bin/env bash
set -euo pipefail

# Runs one security cycle with the installed skill (or this repository's copy if
# the skill is not installed) and prints where the reports were written.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALLED_SKILL="${HOME}/.openclaw/workspace/skills/cyber-security-engineer"
REPO_SKILL="${REPO_ROOT}/cyber-security-engineer"

if [[ -x "${INSTALLED_SKILL}/scripts/auto_invoke_cycle.sh" ]]; then
  SKILL="${INSTALLED_SKILL}"
elif [[ -x "${REPO_SKILL}/scripts/auto_invoke_cycle.sh" ]]; then
  SKILL="${REPO_SKILL}"
else
  echo "No auto cycle runner found. Expected one of:"
  echo "  ${INSTALLED_SKILL}/scripts/auto_invoke_cycle.sh"
  echo "  ${REPO_SKILL}/scripts/auto_invoke_cycle.sh"
  exit 1
fi

/bin/bash "${SKILL}/scripts/auto_invoke_cycle.sh"

echo "Security cycle complete. Reports are in:"
echo "  ${SKILL}/assessments"
echo "Dashboard:"
echo "  ${SKILL}/assessments/compliance-dashboard.html"
