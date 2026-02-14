# OpenClaw-Cyber-Analyst

Security automation skillset for OpenClaw.

This repo adds a `cyber-security-engineer` skill that continuously checks your host/OpenClaw posture and updates a local compliance dashboard.

## What This Skill Does

- Enforces least-privilege workflow patterns for privileged actions
- Requires approval-first execution pattern for elevated tasks
- Applies 30-minute idle timeout logic for elevated sessions
- Monitors listening ports and flags insecure/unapproved exposure
- Builds ISO 27001 + NIST control mapping and compliance dashboard views
- Supports auto-invoke scheduling so checks run continuously

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
