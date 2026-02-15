# OpenClaw-Cyber-Analyst

Security automation skillset for OpenClaw.

This repo ships the `cyber-security-engineer` skill: least-privilege guardrails, approval-first elevation, port + egress monitoring, and ISO 27001 + NIST benchmarking with a local dashboard.

## Core Capabilities

### Least Privilege, Scoped Approvals, Audit Trail

Privileged actions should be executed through:

```bash
python3 cyber-security-engineer/scripts/guarded_privileged_exec.py \
  --reason "why root is needed" \
  --use-sudo \
  -- <command> <args...>
```

This enforces:

- Approval-first privileged execution
- Command allow/deny policy enforcement (when configured)
- Per-task session scoping (optional)
- Automatic drop back to normal after the command (default; `--keep-session` is available)
- Append-only privileged audit log: `~/.openclaw/security/privileged-audit.jsonl`

### Approved Ports Baseline

Port monitoring compares listeners to an approved baseline. Generate one from current services:

```bash
python3 cyber-security-engineer/scripts/generate_approved_ports.py
```

This writes `~/.openclaw/security/approved_ports.json`. Review and prune it for approved services.
A starter template is available at `cyber-security-engineer/references/approved_ports.template.json`.

Port discovery uses `lsof` when available, with fallbacks to `ss` (Linux) or `netstat` (Windows).

### Runtime Enforcement Hook (Optional)

To reduce bypasses (running raw `sudo`), install the runtime hook which places a `sudo` shim at:

`~/.openclaw/bin/sudo`

Install:

```bash
./cyber-security-engineer/scripts/install-openclaw-runtime-hook.sh
openclaw gateway restart
```

Skip hook during bootstrap:

```bash
ENFORCE_PRIVILEGED_EXEC=0 ./scripts/bootstrap-openclaw-cyber-analyst.sh
```

### Egress Monitoring (Outbound Allowlist)

Egress monitoring inventories outbound TCP connections and compares them to:

`~/.openclaw/security/egress_allowlist.json`

Run:

```bash
python3 cyber-security-engineer/scripts/egress_monitor.py --json
```

Template:

`cyber-security-engineer/references/egress-allowlist.template.json`

## Install (New Users)

From repo root:

```bash
chmod +x scripts/bootstrap-openclaw-cyber-analyst.sh
./scripts/bootstrap-openclaw-cyber-analyst.sh
```

Skip scheduler:

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
- `cyber-security-engineer/assessments/egress-monitor-latest.json`

## View Dashboard Locally

```bash
cd cyber-security-engineer/assessments
python3 -m http.server 8088
```

Open:

- `http://127.0.0.1:8088/compliance-dashboard.html`
