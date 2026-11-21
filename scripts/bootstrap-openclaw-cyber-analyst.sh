#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_SRC="${REPO_ROOT}/cyber-security-engineer"
SKILL_NAME="cyber-security-engineer"
OPENCLAW_SKILLS_DIR="${HOME}/.openclaw/workspace/skills"
# AUTO_INVOKE: 1 = install the 30-minute scheduler, 0 = skip, unset = ask.
AUTO_INVOKE="${AUTO_INVOKE:-ask}"
# What to install when OpenClaw is missing. Pin a release with e.g. OPENCLAW_NPM_SPEC=openclaw@2026.11.6
OPENCLAW_NPM_SPEC="${OPENCLAW_NPM_SPEC:-openclaw@latest}"
ENFORCE_PRIVILEGED_EXEC="${ENFORCE_PRIVILEGED_EXEC:-0}"

log() {
  printf '[openclaw-cyber-analyst] %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "Missing required command: $1"
    exit 1
  fi
}

cleanup_openclaw_npm_artifacts() {
  local npm_root
  npm_root="$(npm root -g 2>/dev/null || true)"
  if [[ -n "${npm_root}" ]]; then
    rm -rf "${npm_root}/openclaw" "${npm_root}/.openclaw-"* 2>/dev/null || true
  fi
  npm cache verify >/dev/null 2>&1 || true
}

install_openclaw() {
  if command -v openclaw >/dev/null 2>&1; then
    log "OpenClaw already installed: $(openclaw --version 2>/dev/null || echo unknown)"
    return
  fi

  log "Installing ${OPENCLAW_NPM_SPEC} via npm..."
  if ! env SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm --loglevel warn --no-fund install -g "${OPENCLAW_NPM_SPEC}"; then
    log "Initial install failed. Cleaning npm artifacts and retrying..."
    npm uninstall -g openclaw >/dev/null 2>&1 || true
    cleanup_openclaw_npm_artifacts
    env SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm --loglevel warn --no-fund install -g "${OPENCLAW_NPM_SPEC}"
  fi
  log "Installed: $(openclaw --version 2>/dev/null || echo unknown)"
}

configure_openclaw() {
  log "Running OpenClaw setup..."
  openclaw setup

  log "Applying secure local gateway defaults..."
  openclaw config set gateway.mode local
  openclaw config set gateway.bind loopback
  openclaw doctor --fix || true

  mkdir -p "${HOME}/.openclaw/credentials"
  chmod 700 "${HOME}/.openclaw" || true

  log "Installing/restarting OpenClaw gateway service..."
  openclaw gateway install || true
  openclaw gateway restart || openclaw gateway start || true
}

install_skill() {
  bash "${REPO_ROOT}/scripts/install-skill.sh"
}

verify_install() {
  log "Running readiness checks..."
  openclaw --version
  openclaw doctor || true
  openclaw gateway status || true
  python3 "${OPENCLAW_SKILLS_DIR}/${SKILL_NAME}/scripts/port_monitor.py" --json >/dev/null
  log "Bootstrap complete."
}

enable_auto_invoke() {
  if [[ "${AUTO_INVOKE}" == "ask" ]]; then
    # A background job that runs every 30 minutes is only installed with consent.
    if [[ -t 0 ]]; then
      local reply
      printf '[openclaw-cyber-analyst] Install a background job that runs the security cycle every 30 minutes? [y/N]: '
      read -r reply
      if [[ "${reply}" == "y" || "${reply}" == "Y" ]]; then AUTO_INVOKE=1; else AUTO_INVOKE=0; fi
    else
      AUTO_INVOKE=0
    fi
  fi
  if [[ "${AUTO_INVOKE}" != "1" ]]; then
    log "Scheduler not installed. To add it later: ./scripts/enable-auto-invoke.sh"
    log "To run a security cycle now: ./scripts/auto-invoke-security-cycle.sh"
    return
  fi

  log "Running immediate security cycle..."
  bash "${REPO_ROOT}/scripts/auto-invoke-security-cycle.sh"

  log "Enabling platform auto-invoke scheduler..."
  if ! bash "${REPO_ROOT}/scripts/enable-auto-invoke.sh"; then
    log "Auto scheduler setup failed. Configure your scheduler to run:"
    log "  ${REPO_ROOT}/scripts/auto-invoke-security-cycle.sh"
    log "Recommended interval: every 30 minutes."
  fi
}

main() {
  require_cmd npm
  require_cmd python3
  install_openclaw
  require_cmd openclaw
  configure_openclaw
  install_skill
  if [[ "${ENFORCE_PRIVILEGED_EXEC}" == "1" ]]; then
    log "Installing OpenClaw runtime privileged-exec hook (opt-in via ENFORCE_PRIVILEGED_EXEC=1)..."
    bash "${REPO_ROOT}/cyber-security-engineer/scripts/install-openclaw-runtime-hook.sh" || true
  else
    log "Runtime privileged-exec hook not installed (default). To enable, re-run with:"
    log "  ENFORCE_PRIVILEGED_EXEC=1 ./scripts/bootstrap-openclaw-cyber-analyst.sh"
  fi
  enable_auto_invoke
  verify_install
}

main "$@"
