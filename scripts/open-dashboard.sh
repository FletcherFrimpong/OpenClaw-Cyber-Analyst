#!/usr/bin/env bash
set -euo pipefail

# Serves the compliance dashboard on this machine only and prints its address.
# Usage: ./scripts/open-dashboard.sh [port]   (default 8088; Ctrl-C to stop)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-8088}"
INSTALLED="${HOME}/.openclaw/workspace/skills/cyber-security-engineer/assessments"
REPO="${REPO_ROOT}/cyber-security-engineer/assessments"

if [[ -f "${INSTALLED}/compliance-dashboard.html" ]]; then
  DIR="${INSTALLED}"
elif [[ -f "${REPO}/compliance-dashboard.html" ]]; then
  DIR="${REPO}"
else
  echo "No dashboard found yet. Run ./scripts/auto-invoke-security-cycle.sh first."
  exit 1
fi

echo "Dashboard: http://127.0.0.1:${PORT}/compliance-dashboard.html"
echo "Serving ${DIR} (Ctrl-C to stop)"
exec python3 -m http.server "${PORT}" --bind 127.0.0.1 --directory "${DIR}"
