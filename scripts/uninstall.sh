#!/usr/bin/env bash
set -euo pipefail

# Removes what this project installed:
#   - the scheduled security cycle
#   - the sudo shim (~/.openclaw/bin/sudo) and its PATH entry in the gateway service
#   - the installed copies of the skill
#
# Your policy files, audit log and reports under ~/.openclaw/security are kept
# unless you pass --purge. OpenClaw itself is not touched.
#
# Usage: ./scripts/uninstall.sh [--purge] [--yes]

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_NAME="cyber-security-engineer"
PURGE=0
ASSUME_YES=0

for arg in "$@"; do
  case "${arg}" in
    --purge) PURGE=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help)
      sed -n '4,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: ${arg}" >&2
      exit 2
      ;;
  esac
done

log() {
  printf '[openclaw-cyber-analyst] %s\n' "$*"
}

confirm() {
  [[ "${ASSUME_YES}" == "1" ]] && return 0
  if [[ ! -t 0 ]]; then
    log "Not running in a terminal; pass --yes to confirm."
    return 1
  fi
  local reply
  printf '%s [y/N]: ' "$1"
  read -r reply
  [[ "${reply}" == "y" || "${reply}" == "Y" ]]
}

confirm "Remove the scheduled security cycle, the sudo shim and the installed skill?" || exit 1

bash "${REPO_ROOT}/scripts/disable-auto-invoke.sh" || log "Scheduler was not installed, or could not be removed automatically."

BIN_DIR="${HOME}/.openclaw/bin"
if [[ -e "${BIN_DIR}/sudo" ]]; then
  rm -f "${BIN_DIR}/sudo"
  rmdir "${BIN_DIR}" 2>/dev/null || true
  log "Removed sudo shim."
fi

# Take the shim directory back out of OpenClaw's command PATH.
if command -v openclaw >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  REMAINING="$(python3 - "${HOME}/.openclaw/openclaw.json" "${BIN_DIR}" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        current = json.load(f).get("tools", {}).get("exec", {}).get("pathPrepend")
except Exception:
    current = None
if isinstance(current, list) and sys.argv[2] in current:
    print(json.dumps([e for e in current if e != sys.argv[2]]))
PY
)" || REMAINING=""
  if [[ -n "${REMAINING}" ]]; then
    if openclaw config set tools.exec.pathPrepend "${REMAINING}" --strict-json >/dev/null 2>&1; then
      log "Removed ${BIN_DIR} from OpenClaw's command PATH. Restart the gateway to apply: openclaw gateway restart"
    fi
  fi
fi

PLIST="${HOME}/Library/LaunchAgents/ai.openclaw.gateway.plist"
if [[ "$(uname -s)" == "Darwin" && -f "${PLIST}" && -x /usr/libexec/PlistBuddy ]]; then
  CURRENT="$(/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:PATH" "${PLIST}" 2>/dev/null || true)"
  case ":${CURRENT}:" in
    *":${BIN_DIR}:"*)
      CLEANED="$(printf '%s' ":${CURRENT}:" | sed "s|:${BIN_DIR}:|:|g; s|^:||; s|:\$||")"
      /usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:PATH ${CLEANED}" "${PLIST}"
      log "Removed ${BIN_DIR} from the gateway service PATH."
      log "Reload the gateway to apply:"
      log "  launchctl bootout gui/\$(id -u)/ai.openclaw.gateway; launchctl bootstrap gui/\$(id -u) ${PLIST}"
      ;;
  esac
fi

for base in "${HOME}/.openclaw/workspace/skills" "${HOME}/.codex/skills"; do
  if [[ -d "${base}/${SKILL_NAME}" ]]; then
    rm -rf "${base:?}/${SKILL_NAME}"
    log "Removed ${base}/${SKILL_NAME}"
  fi
done

if [[ "${PURGE}" == "1" ]]; then
  if confirm "Also delete policy files, session state and the audit log in ~/.openclaw/security?"; then
    SEC="${HOME}/.openclaw/security"
    rm -f "${SEC}/approved_ports.json" "${SEC}/command-policy.json" "${SEC}/egress_allowlist.json" \
      "${SEC}/prompt-policy.json" "${SEC}/root-session-state.json" "${SEC}/session-state.key" \
      "${SEC}/violation-notify-state.json" "${SEC}/egress-dns-cache.json" \
      "${SEC}/privileged-audit.jsonl" "${SEC}/privileged-audit.jsonl.1"
    rmdir "${SEC}" 2>/dev/null || true
    log "Removed policy files, session state and audit log."
  fi
else
  log "Kept ~/.openclaw/security (policies and audit log). Pass --purge to delete them."
fi

log "Uninstall complete."
