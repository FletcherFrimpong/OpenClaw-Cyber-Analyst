# Changelog

All notable changes to this project are recorded here. Versions follow
[Semantic Versioning](https://semver.org/); the version is the `version` field in
`cyber-security-engineer/SKILL.md`.

## 0.2.0 - 2026-11-21

### Security

- **Approval can no longer be given through stdin.** The approval prompt is shown
  and answered on the controlling terminal. With no terminal attached, privileged
  execution is refused. Previously, piping `y` into the guard approved the command.
- **Session state is signed and private.** A state file that is unsigned, altered,
  unreadable, or readable by other users is discarded and approval is required.
  Previously, a hand-written state file skipped approval.
- **sudo asks for the password on every run.** Cached sudo credentials are discarded
  before a guarded command by default (`--no-sudo-kill-cache` restores the old behaviour).
- **The audit log is hash-chained, private and rotated.** `audit_logger.py verify`
  detects edited, removed or inserted entries. A privileged command that cannot be
  recorded no longer runs (`OPENCLAW_AUDIT_OPTIONAL=1` allows it).
- **A broken command policy blocks everything.** An unreadable policy file or an
  invalid pattern used to be skipped silently.
- **The approval token is compared in constant time and typed without echo.**

### Changed

- **Compliance controls are tested, not assumed.** The assessment now runs self-tests
  of the guard (no terminal, forged session file, idle timeout), checks that sudo
  requires a password, checks the gateway's PATH, and verifies the audit chain.
- **`alternate_privilege_paths_restricted` no longer passes just because the sudo
  shim exists.** It reports whether sudo can be used without a password.
- **`update_hygiene` can be compliant.** It reads the release date from OpenClaw's
  date-based version; a release more than 3 months old is partial.
- **Compliant controls carry no gap, mitigation or due date.** Open controls keep the
  due date they were first given instead of a new one on every run.
- **Settings in `~/.openclaw/env` are enforced.** The guard reads the file, so the
  session-ID and approval-token controls report what is actually in force.
- **Bare command names work through the sudo shim.** `sudo ls` is resolved in the
  system directories only.
- **Port monitor:** full process names, an empty result when nothing is listening,
  one finding per service, optional UDP (`--include-udp`), and listeners on all
  interfaces must be approved with `"allow_public": true`.
- **Egress monitor redesigned:** evaluates only OpenClaw's own outbound connections,
  resolves allowlisted hostnames, and supports `host`, `hosts`, `cidr` and `ports` rules.
- **Dashboard redesigned:** sidebar, overview charts, tabbed and paginated tables,
  filters, search, CSV export, dark mode.
- **Bootstrap asks before installing the 30-minute scheduler**, and the OpenClaw
  package to install can be pinned with `OPENCLAW_NPM_SPEC`.
- Minimum Python version is 3.9.

### Added

- New control `public_listeners_justified`.
- `scripts/install-skill.sh` to update the installed skill, and `scripts/uninstall.sh`.
- Unit tests for every script, run in CI on Linux and macOS.
- Threat model, egress monitoring policy, licence, security policy and this changelog.

### Fixed

- The egress monitor always reported zero connections on macOS.
- The command policy template's allow rules could never match.
- The Windows scheduler passed a Windows path to bash in WSL.
- A failed egress scan was reported as clean.

### Removed

- Generated reports are no longer tracked in the repository.

## 0.1.9 - 2026-04-01

- The sudo shim became opt-in, with a confirmation before the gateway LaunchAgent is modified.
