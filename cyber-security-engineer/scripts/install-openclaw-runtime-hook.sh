#!/usr/bin/env bash
set -euo pipefail

# Installs a sudo shim under ~/.openclaw/security/bin/sudo.
#
# Goal: if OpenClaw (or a human) runs `sudo <cmd>`, route through the
# cyber-security-engineer approval/allowlist wrapper.
#
# Notes:
# - This is best-effort and intentionally conservative. If no TTY is present,
#   the shim refuses by default (to avoid silent privilege escalation).

log() {
  printf '[cyber-security-engineer] %s\n' "$*"
}

REAL_SUDO="$(command -v sudo || true)"
if [[ -z "${REAL_SUDO}" ]]; then
  log "sudo not found; nothing to install."
  exit 1
fi

SEC_DIR="${HOME}/.openclaw/security"
BIN_DIR="${SEC_DIR}/bin"
SKILL_DIR_DEFAULT="${HOME}/.openclaw/workspace/skills/cyber-security-engineer"

mkdir -p "${BIN_DIR}"
chmod 700 "${SEC_DIR}" "${BIN_DIR}" || true

WRAPPER="${BIN_DIR}/sudo"
cat > "${WRAPPER}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

REAL_SUDO="${OPENCLAW_REAL_SUDO:-__REAL_SUDO__}"
SKILL_DIR="${OPENCLAW_CYBER_SKILL_DIR:-__SKILL_DIR_DEFAULT__}"

# If sudo is being used for its own bookkeeping/options, pass through.
if [[ $# -eq 0 ]]; then
  exec "${REAL_SUDO}"
fi
case "${1:-}" in
  -h|--help|-V|--version|-v|-l|-k)
    exec "${REAL_SUDO}" "$@"
    ;;
esac

# Refuse non-interactive privilege escalation by default.
if [[ ! -t 0 && "${OPENCLAW_ALLOW_NONINTERACTIVE_SUDO:-0}" != "1" ]]; then
  echo "[cyber-security-engineer] Refusing non-interactive sudo (set OPENCLAW_ALLOW_NONINTERACTIVE_SUDO=1 to override)." >&2
  exit 2
fi

REASON="${OPENCLAW_PRIV_REASON:-OpenClaw requested privileged execution}"

export OPENCLAW_REAL_SUDO="${REAL_SUDO}"
exec python3 "${SKILL_DIR}/scripts/guarded_privileged_exec.py" \
  --reason "${REASON}" \
  --use-sudo \
  -- "$@"
SH

# Substitute install-time defaults.
perl -0777 -pe "s|__REAL_SUDO__|${REAL_SUDO}|g; s|__SKILL_DIR_DEFAULT__|${SKILL_DIR_DEFAULT}|g" -i "${WRAPPER}" 2>/dev/null || true
chmod 755 "${WRAPPER}"

log "Installed sudo shim: ${WRAPPER}"
log "Next: ensure OpenClaw gateway PATH includes ${BIN_DIR} before /usr/bin, then restart:"
log "  openclaw gateway restart"

