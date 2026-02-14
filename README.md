# OpenClaw-Cyber-Analyst

Security automation skillset for OpenClaw.

This repo ships:

- `cyber-security-engineer`: least-privilege enforcement helpers, port monitoring, and ISO 27001 + NIST benchmarking with a local dashboard.

## What The Cyber Security Engineer Skill Does

### 1. Least-Privilege + Approval-First Privileged Execution

- Default posture is **non-root**.
- When privileged execution is needed, run it through:

```bash
python3 cyber-security-engineer/scripts/guarded_privileged_exec.py \
  --reason "why root is needed" \
  --use-sudo \
  -- <command> <args...>
```

This wrapper enforces:

- User approval before privileged execution.
- Per-task scoping: approvals apply to the **exact command argv** (different command requires new approval).
- Automatic privilege drop after the command (default; `--keep-session` is available for multi-step tasks).
- Append-only privileged audit trail at `~/.openclaw/security/privileged-audit.jsonl`.

### 2. Runtime Enforcement Hook (Optional)

To reduce bypasses (running raw `sudo` instead of the wrapper), you can install a runtime hook that places a `sudo` shim at:

`~/.openclaw/bin/sudo`

Install:

```bash
./cyber-security-engineer/scripts/install-openclaw-runtime-hook.sh
openclaw gateway restart
```

Notes:

- The shim is only effective if the OpenClaw gateway PATH includes `~/.openclaw/bin` before `/usr/bin`.
- On macOS LaunchAgent installs, the installer attempts best-effort PATH injection into `~/Library/LaunchAgents/ai.openclaw.gateway.plist`.

Skip hook during bootstrap:

```bash
ENFORCE_PRIVILEGED_EXEC=0 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

### 3. Listening Port Monitoring + Secure-Port Recommendations

The skill inventories listening TCP ports and flags:

- Unapproved listeners (not in approved baseline).
- Insecure ports (e.g. 21/23/80/110/143/389, etc.) with secure recommendations.
- Public binds (`0.0.0.0`, `::`, `*`) that increase exposure.

Port discovery uses `lsof` when available, with fallbacks to `ss` (Linux) or `netstat` (Windows).

### 4. Approved Ports Baseline

Port monitoring compares listeners to an approved baseline file:

`~/.openclaw/security/approved_ports.json`

Generate a starter baseline from the current machine:

```bash
python3 cyber-security-engineer/scripts/generate_approved_ports.py
```

Then review and prune it. A starter template exists at:

`cyber-security-engineer/references/approved_ports.template.json`

### 5. ISO 27001 + NIST Compliance Dashboard

The skill maps observed OpenClaw/host posture to ISO 27001 and NIST categories, including checks for:

- Channel allowlists + group mention requirements
- Gateway loopback + token auth validation
- Secrets/config permission hardening
- Privileged audit logging presence
- Backup/recovery presence
- Update hygiene (captures `openclaw --version`)

## Install (New Users)

From repo root:

```bash
chmod +x scripts/bootstrap-openclaw-cyber-analyst.sh
./scripts/bootstrap-openclaw-cyber-analyst.sh
```

Bootstrap does:

- Installs OpenClaw (npm) with retry/cleanup for common install issues
- Runs `openclaw setup`
- Applies secure defaults: `gateway.mode=local`, `gateway.bind=loopback`
- Runs `openclaw doctor --fix`
- Installs the skill into:
  - `~/.codex/skills/cyber-security-engineer`
  - `~/.openclaw/workspace/skills/cyber-security-engineer`
- Optionally installs the runtime enforcement hook (`ENFORCE_PRIVILEGED_EXEC=1` default)
- Runs one immediate security cycle and enables auto-invoke scheduling

Skip scheduler setup:

```bash
AUTO_INVOKE=0 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

## Run Manually

```bash
./scripts/auto-invoke-security-cycle.sh
```

Outputs (refreshed each cycle):

- `cyber-security-engineer/assessments/openclaw-assessment.json`
- `cyber-security-engineer/assessments/compliance-summary.json`
- `cyber-security-engineer/assessments/compliance-dashboard.html`
- `cyber-security-engineer/assessments/port-monitor-latest.json`

## View The Dashboard Locally

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
