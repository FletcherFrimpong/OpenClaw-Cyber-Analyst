#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_SRC="${REPO_ROOT}/cyber-security-engineer"
SKILL_NAME="cyber-security-engineer"
CODEX_SKILLS_DIR="${HOME}/.codex/skills"
OPENCLAW_SKILLS_DIR="${HOME}/.openclaw/workspace/skills"
AUTO_INVOKE="${AUTO_INVOKE:-1}"

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

  log "Installing OpenClaw via npm..."
  if ! env SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm --loglevel warn --no-fund --no-audit install -g openclaw@latest; then
    log "Initial install failed. Cleaning npm artifacts and retrying..."
    npm uninstall -g openclaw >/dev/null 2>&1 || true
    cleanup_openclaw_npm_artifacts
    env SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm --loglevel warn --no-fund --no-audit install -g openclaw@latest
  fi
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
  if [[ ! -d "${SKILL_SRC}" ]]; then
    log "Skill folder not found: ${SKILL_SRC}"
    exit 1
  fi

  log "Installing skill to Codex user skills path..."
  mkdir -p "${CODEX_SKILLS_DIR}"
  rm -rf "${CODEX_SKILLS_DIR}/${SKILL_NAME}"
  cp -R "${SKILL_SRC}" "${CODEX_SKILLS_DIR}/${SKILL_NAME}"

  log "Installing skill to OpenClaw workspace skills path..."
  mkdir -p "${OPENCLAW_SKILLS_DIR}"
  rm -rf "${OPENCLAW_SKILLS_DIR}/${SKILL_NAME}"
  cp -R "${SKILL_SRC}" "${OPENCLAW_SKILLS_DIR}/${SKILL_NAME}"
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
  if [[ "${AUTO_INVOKE}" != "1" ]]; then
    log "AUTO_INVOKE disabled; skipping auto-run service setup."
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
  enable_auto_invoke
  verify_install
}

main "$@"
