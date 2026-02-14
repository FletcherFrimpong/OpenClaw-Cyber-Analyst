---
name: cyber-security-engineer
description: Security engineering workflow for OpenClaw privilege governance and hardening. Use for least-privilege execution, approval-first privileged actions, idle timeout controls, listening-port and egress monitoring, and ISO 27001/NIST-aligned compliance reporting with mitigations.
---

# Cyber Security Engineer

Implement these controls in every security-sensitive task:

1. Keep default execution in normal (non-root) mode.
2. Request explicit user approval before any elevated command.
3. Scope elevation to the minimum command set required for the active task.
4. Drop elevated state immediately after the privileged command completes.
5. Expire elevated state after 30 idle minutes and require re-approval.
6. Monitor listening network ports and flag insecure or unapproved exposure.
7. Monitor outbound connections and flag destinations not in the egress allowlist.
8. If no approved baseline exists, generate one and require user review/pruning.
9. Benchmark controls against ISO 27001 and NIST and report violations with mitigations.

## Non-Goals (Web Browsing)

- Do not use web browsing / web search as part of this skill. Keep assessments and recommendations based on local host/OpenClaw state and the bundled references in this skill.

## Files To Use

- `references/least-privilege-policy.md`
- `references/port-monitoring-policy.md`
- `references/compliance-controls-map.json`
- `references/approved_ports.template.json`
- `references/command-policy.template.json`
- `references/prompt-policy.template.json`
- `references/egress-allowlist.template.json`
- `scripts/root_session_guard.py`
- `scripts/audit_logger.py`
- `scripts/command_policy.py`
- `scripts/prompt_policy.py`
- `scripts/guarded_privileged_exec.py`
- `scripts/install-openclaw-runtime-hook.sh`
- `scripts/port_monitor.py`
- `scripts/generate_approved_ports.py`
- `scripts/egress_monitor.py`
- `scripts/compliance_dashboard.py`
- `scripts/live_assessment.py`

## Required Behaviors

- Never keep root/elevated access open between unrelated tasks.
- Never execute root commands without an explicit approval step in the current flow.
- Enforce command allow/deny policy when configured (`~/.openclaw/security/command-policy.json`).
- If `OPENCLAW_UNTRUSTED_SOURCE=1` and prompt policy requires it, require explicit confirmation before privileged work.
- If `OPENCLAW_REQUIRE_SESSION_ID=1`, require `OPENCLAW_TASK_SESSION_ID` and scope approvals to that id.
- If `OPENCLAW_APPROVAL_TOKEN` is configured, require it for privileged approvals.
- Log privileged actions to `~/.openclaw/security/privileged-audit.jsonl` (best-effort).

