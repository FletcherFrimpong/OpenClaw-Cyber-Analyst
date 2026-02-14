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
- Restarts gateway and runs readiness checks

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
