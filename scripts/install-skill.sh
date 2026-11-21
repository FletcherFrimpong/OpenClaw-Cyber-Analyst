#!/usr/bin/env bash
set -euo pipefail

# Copies the skill from this repository into the places OpenClaw (and Codex, if
# present) load skills from. Run it again after pulling changes: the scheduled
# security cycle runs the installed copy, not the repository.
#
# Generated reports in the installed copy's assessments/ folder are kept.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_NAME="cyber-security-engineer"
SKILL_SRC="${REPO_ROOT}/${SKILL_NAME}"

log() {
  printf '[openclaw-cyber-analyst] %s\n' "$*"
}

if [[ ! -f "${SKILL_SRC}/SKILL.md" ]]; then
  log "Skill folder not found: ${SKILL_SRC}"
  exit 1
fi

install_to() {
  local dest="$1/${SKILL_NAME}"
  mkdir -p "${dest}"
  local item name
  # Replace everything except generated reports.
  for item in "${dest}"/* "${dest}"/.[!.]*; do
    [[ -e "${item}" ]] || continue
    name="$(basename "${item}")"
    [[ "${name}" == "assessments" ]] && continue
    rm -rf "${item}"
  done
  for item in "${SKILL_SRC}"/*; do
    name="$(basename "${item}")"
    [[ "${name}" == "assessments" ]] && continue
    cp -R "${item}" "${dest}/"
  done
  find "${dest}" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "${dest}" -name '.DS_Store' -delete 2>/dev/null || true
  mkdir -p "${dest}/assessments"
  log "Installed ${SKILL_NAME} to ${dest}"
}

install_to "${HOME}/.openclaw/workspace/skills"
if [[ -d "${HOME}/.codex" ]]; then
  install_to "${HOME}/.codex/skills"
fi

VERSION="$(sed -n 's/^version:[[:space:]]*//p' "${SKILL_SRC}/SKILL.md" | head -1)"
log "Version ${VERSION:-unknown} is installed."
