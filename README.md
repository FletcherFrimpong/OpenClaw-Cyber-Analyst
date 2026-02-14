# OpenClaw-Cyber-Analyst

Security automation skillset for OpenClaw.

This repo adds a `cyber-security-engineer` skill that continuously checks your host/OpenClaw posture and updates a local compliance dashboard.
It also adds an `openclaw-coder` skill so you can prompt OpenClaw to code on your behalf.

## What This Skill Does

- Enforces least-privilege workflow patterns for privileged actions
- Requires approval-first execution pattern for elevated tasks
- Applies 30-minute idle timeout logic for elevated sessions
- Enforces per-task privilege scoping: approvals apply to the exact privileged command argv (different commands require new approval)
- Monitors listening ports and flags insecure/unapproved exposure
- Builds ISO 27001 + NIST control mapping and compliance dashboard views
- Supports auto-invoke scheduling so checks run continuously

## Least Privilege (How Root Is Scoped)

The skill does not keep root open. Privileged actions should be executed via:

```bash
python3 cyber-security-engineer/scripts/guarded_privileged_exec.py \
  --reason "why root is needed" \
  --use-sudo \
  -- <command> <args...>
```

Behavior:

- Prompts for approval for the exact command argv it will run.
- Records an allowlist entry for that argv for the current task session.
- Drops back to normal after the command completes (default).
- If you truly need multiple privileged steps, use `--keep-session` (still restricted to the allowlisted argv; expires on idle timeout).

## Coding Skill

Skill name: `openclaw-coder`

Use this when you want OpenClaw to implement code tasks directly.

Example prompts:

- `Use $openclaw-coder to add JWT auth middleware and tests.`
- `Use $openclaw-coder to debug this failing endpoint and provide a patch.`
- `Use $openclaw-coder to refactor this module for readability and keep behavior unchanged.`

## Recommended Install (New Users)

From repo root:

```bash
chmod +x scripts/bootstrap-openclaw-cyber-analyst.sh
./scripts/bootstrap-openclaw-cyber-analyst.sh
```

The bootstrap script:

- Installs OpenClaw (with retry/cleanup for npm corruption issues)
- Runs `openclaw setup`
- Applies secure defaults: `gateway.mode=local`, `gateway.bind=loopback`
- Runs `openclaw doctor --fix`
- Installs the skill in:
  - `~/.codex/skills/cyber-security-engineer`
  - `~/.openclaw/workspace/skills/cyber-security-engineer`
- Runs one immediate live security cycle
- Enables auto-invoke scheduler by platform:
  - macOS: LaunchAgent
  - Linux: systemd user timer (fallback: cron)
  - Windows: Task Scheduler script provided

Skip scheduler setup:

```bash
AUTO_INVOKE=0 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

## Run It Manually

```bash
./scripts/auto-invoke-security-cycle.sh
```

This refreshes:

- `cyber-security-engineer/assessments/openclaw-assessment.json`
- `cyber-security-engineer/assessments/compliance-summary.json`
- `cyber-security-engineer/assessments/compliance-dashboard.html`
- `cyber-security-engineer/assessments/port-monitor-latest.json`

## Approved Ports Baseline

Port monitoring compares listeners to an approved baseline. Generate one from current services:

```bash
python3 cyber-security-engineer/scripts/generate_approved_ports.py
```

This writes `~/.openclaw/security/approved_ports.json`. Review and prune it for approved services.
A starter template is available at `cyber-security-engineer/references/approved_ports.template.json`.

Port discovery uses `lsof` when available, with fallbacks to `ss` (Linux) or `netstat` (Windows).

## Runtime Enforcement Hook

Install a runtime hook that wraps `sudo` with approval enforcement for OpenClaw tasks:

```bash
./cyber-security-engineer/scripts/install-openclaw-runtime-hook.sh
```

The bootstrap script enables this by default. To skip it:

```bash
ENFORCE_PRIVILEGED_EXEC=0 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

After installation, restart the OpenClaw gateway so it picks up the PATH override:

```bash
openclaw gateway restart
```

## Auto-Invoke (All Platforms)

Auto-detect helper:

```bash
./scripts/enable-auto-invoke.sh
./scripts/disable-auto-invoke.sh
```

Platform-specific:

```bash
# macOS
./scripts/enable-auto-invoke-macos.sh
./scripts/disable-auto-invoke-macos.sh

# Linux (systemd)
./scripts/enable-auto-invoke-linux-systemd.sh
./scripts/disable-auto-invoke-linux-systemd.sh

# Linux (cron fallback)
./scripts/enable-auto-invoke-linux-cron.sh
./scripts/disable-auto-invoke-linux-cron.sh
```

Windows (PowerShell; Task Scheduler + WSL runner):

```powershell
.\scripts\enable-auto-invoke-windows.ps1
.\scripts\disable-auto-invoke-windows.ps1
```

## Dashboard

Render manually:

```bash
python3 cyber-security-engineer/scripts/compliance_dashboard.py render \
  --assessment-file cyber-security-engineer/assessments/openclaw-assessment.json \
  --output-html cyber-security-engineer/assessments/compliance-dashboard.html \
  --output-summary cyber-security-engineer/assessments/compliance-summary.json
```

Serve locally:

```bash
cd cyber-security-engineer/assessments
python3 -m http.server 8088
```

Open:

- `http://127.0.0.1:8088/compliance-dashboard.html`

## Optional: Route Telegram To The Cyber Agent

If you want Telegram messages to go to a dedicated `cyber-security-engineer` agent (instead of `main`), do this.

1. Create the agent (safe, schema-valid):

```bash
openclaw agents add cyber-security-engineer \
  --workspace ~/.openclaw/workspace \
  --model openai/gpt-4.1-mini \
  --non-interactive \
  --json
```

2. Add a routing binding for Telegram (note: binding objects are `{agentId, match}`; fields like `name`, `action`, or `wakeMode` will fail config validation):

```bash
openclaw config set bindings '[{"agentId":"cyber-security-engineer","match":{"channel":"telegram","accountId":"default"}}]' --json
openclaw gateway restart
```

To undo:

```bash
openclaw config unset bindings
openclaw gateway restart
```

## Troubleshooting

If global install fails with `TAR_ENTRY_ERROR` or `ENOENT`:

```bash
npm uninstall -g openclaw || true
npm root -g | xargs -I{} sh -lc 'rm -rf {}/openclaw {}/.openclaw-*'
npm cache verify
env SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm --loglevel warn --no-fund --no-audit install -g openclaw@latest
```

If gateway mode/bind is wrong:

```bash
openclaw config set gateway.mode local
openclaw config set gateway.bind loopback
openclaw doctor --fix
openclaw gateway restart
```
