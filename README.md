# OpenClaw-Cyber-Analyst
This is to ensure your openclaw setup is running securely in your environment. 

## Recommended Installation (One Command)

From this repo root:

```bash
chmod +x scripts/bootstrap-openclaw-cyber-analyst.sh
./scripts/bootstrap-openclaw-cyber-analyst.sh
```

This script:
- Installs OpenClaw (with automatic retry/cleanup for common npm corruption issues)
- Runs `openclaw setup`
- Applies secure gateway defaults (`gateway.mode=local`, `gateway.bind=loopback`)
- Runs `openclaw doctor --fix`
- Installs this skill in both:
  - `~/.codex/skills/cyber-security-engineer`
  - `~/.openclaw/workspace/skills/cyber-security-engineer`
- Runs one immediate security cycle (live assessment + dashboard refresh)
- Enables auto-invoke on supported platforms:
  - macOS: LaunchAgent
  - Linux: systemd user timer (fallback: cron)
  - Windows: use provided PowerShell scheduler script
- Restarts gateway and runs readiness checks

To skip auto-invoke setup:

```bash
AUTO_INVOKE=0 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

## Included Skill

- `cyber-security-engineer/`
  - Least-privilege + approval-first elevated execution
  - 30-minute idle timeout for elevated sessions
  - Port monitoring with insecure-port recommendations
  - ISO 27001 / NIST compliance dashboard scaffold

## Quick Start

```bash
python3 ~/.openclaw/workspace/skills/cyber-security-engineer/scripts/port_monitor.py --json
python3 ~/.openclaw/workspace/skills/cyber-security-engineer/scripts/compliance_dashboard.py init-assessment --system "OpenClaw"
python3 ~/.openclaw/workspace/skills/cyber-security-engineer/scripts/compliance_dashboard.py render
```

## Auto-Invoke Security Mode

Run one cycle manually:

```bash
./scripts/auto-invoke-security-cycle.sh
```

Enable persistent auto-invoke (auto-detect platform):

```bash
./scripts/enable-auto-invoke.sh
```

Disable persistent auto-invoke (auto-detect platform):

```bash
./scripts/disable-auto-invoke.sh
```

Platform-specific options:

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

Windows (PowerShell, uses Task Scheduler + WSL bash runner):

```powershell
.\scripts\enable-auto-invoke-windows.ps1
.\scripts\disable-auto-invoke-windows.ps1
```

## Troubleshooting

If global install fails with `npm WARN tar TAR_ENTRY_ERROR` or `ENOENT`:

```bash
npm uninstall -g openclaw || true
npm root -g | xargs -I{} sh -lc 'rm -rf {}/openclaw {}/.openclaw-*'
npm cache verify
env SHARP_IGNORE_GLOBAL_LIBVIPS=1 npm --loglevel warn --no-fund --no-audit install -g openclaw@latest
```

If OpenClaw reports gateway mode/bind problems:

```bash
openclaw config set gateway.mode local
openclaw config set gateway.bind loopback
openclaw doctor --fix
openclaw gateway restart
```
