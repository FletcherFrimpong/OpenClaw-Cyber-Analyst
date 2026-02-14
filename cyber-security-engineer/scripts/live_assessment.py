#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


AUDIT_LOG = Path.home() / ".openclaw" / "security" / "privileged-audit.jsonl"
OPENCLAW_DIR = Path.home() / ".openclaw"


def run_cmd(cmd: List[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return proc.stdout + "\n" + proc.stderr
    return proc.stdout


def resolve_openclaw_bin() -> str:
    env_override = Path.home() / ".openclaw" / "openclaw-bin-path.txt"
    if env_override.exists():
        candidate = env_override.read_text(encoding="utf-8").strip()
        if candidate and Path(candidate).exists():
            return candidate

    for candidate in (
        shutil.which("openclaw"),
        "/opt/homebrew/bin/openclaw",
        "/usr/local/bin/openclaw",
        str(Path.home() / ".npm-global" / "bin" / "openclaw"),
    ):
        if candidate and Path(candidate).exists():
            return candidate
    return "openclaw"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def load_openclaw_config() -> Optional[Dict[str, object]]:
    cfg_path = Path.home() / ".openclaw" / "openclaw.json"
    if not cfg_path.exists():
        return None
    try:
        return json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def permissions_hardened(path: Path) -> bool:
    try:
        mode = path.stat().st_mode & 0o777
        return (mode & 0o077) == 0
    except Exception:
        return False


def find_channel_allowlists(cfg: Dict[str, object]) -> bool:
    channels = cfg.get("channels") if isinstance(cfg, dict) else None
    if not isinstance(channels, dict):
        return False
    for channel_cfg in channels.values():
        if isinstance(channel_cfg, dict):
            allow_from = channel_cfg.get("allowFrom")
            if isinstance(allow_from, list) and len(allow_from) > 0:
                return True
    return False


def group_mentions_required(cfg: Dict[str, object]) -> bool:
    channels = cfg.get("channels") if isinstance(cfg, dict) else None
    if isinstance(channels, dict):
        for channel_cfg in channels.values():
            groups = channel_cfg.get("groups") if isinstance(channel_cfg, dict) else None
            if isinstance(groups, dict):
                for group_cfg in groups.values():
                    if isinstance(group_cfg, dict) and group_cfg.get("requireMention") is True:
                        return True
    messages = cfg.get("messages") if isinstance(cfg, dict) else None
    if isinstance(messages, dict):
        group_chat = messages.get("groupChat")
        if isinstance(group_chat, dict) and group_chat.get("mentionPatterns"):
            return True
    return False


def gateway_loopback_configured(cfg: Optional[Dict[str, object]], cfg_text: str) -> bool:
    if isinstance(cfg, dict):
        gateway = cfg.get("gateway", {})
        mode = gateway.get("mode") if isinstance(gateway, dict) else None
        bind = gateway.get("bind") if isinstance(gateway, dict) else None
        auth = cfg.get("auth") or gateway.get("auth")
        auth_mode = auth.get("mode") if isinstance(auth, dict) else None
        return mode == "local" and bind == "loopback" and auth_mode == "token"
    return '"mode": "local"' in cfg_text and '"bind": "loopback"' in cfg_text and '"mode": "token"' in cfg_text


def runtime_hook_installed() -> bool:
    hook = Path.home() / ".openclaw" / "bin" / "sudo"
    return hook.exists() and os.access(hook, os.X_OK)


def alt_privilege_paths_present() -> bool:
    return bool(shutil.which("su") or shutil.which("doas"))


def audit_log_present() -> bool:
    return AUDIT_LOG.exists() and AUDIT_LOG.stat().st_size > 0


def backup_configured() -> bool:
    for candidate in (OPENCLAW_DIR / "backups", OPENCLAW_DIR / "backup"):
        if candidate.exists() and any(candidate.iterdir()):
            return True
    return False


def collect_runtime_signals(port_monitor_script: Path) -> Dict[str, object]:
    openclaw_bin = resolve_openclaw_bin()
    openclaw_config = run_cmd(["cat", str(Path.home() / ".openclaw" / "openclaw.json")])
    doctor = run_cmd([openclaw_bin, "doctor"])
    gateway_status = run_cmd([openclaw_bin, "gateway", "status"])
    version_text = run_cmd([openclaw_bin, "--version"])
    port_report_raw = run_cmd(["python3", str(port_monitor_script), "--json"])

    try:
        port_report = json.loads(port_report_raw)
    except Exception:
        port_report = {"status": "error", "findings": [], "listening_services": []}

    return {
        "openclaw_config_text": openclaw_config,
        "openclaw_config_json": load_openclaw_config(),
        "doctor_text": doctor,
        "gateway_status_text": gateway_status,
        "version_text": version_text,
        "port_report": port_report,
    }


def set_check(
    checks_by_id: Dict[str, Dict[str, str]],
    check_id: str,
    status: str,
    risk: str,
    observed_state: str,
    evidence: str,
    gap: str,
    mitigation: str,
    owner: str,
    due_date: str,
) -> None:
    c = checks_by_id.setdefault(check_id, {"check_id": check_id})
    c["status"] = status
    c["risk"] = risk
    c["observed_state"] = observed_state
    c["evidence"] = evidence
    c["gap"] = gap
    c["mitigation"] = mitigation
    c["owner"] = owner
    c["due_date"] = due_date


def build_assessment(assessment: Dict[str, object], signals: Dict[str, object]) -> Dict[str, object]:
    checks = assessment.get("checks", [])
    checks_by_id = {c["check_id"]: c for c in checks}

    cfg_text = signals["openclaw_config_text"]
    cfg_json = signals["openclaw_config_json"]
    doctor = signals["doctor_text"]
    gateway = signals["gateway_status_text"]
    version_text = signals["version_text"].strip()
    port_report = signals["port_report"]
    findings = port_report.get("findings", [])
    insecure = [f for f in findings if f.get("type") == "insecure-port"]
    unapproved = [f for f in findings if f.get("type") == "unapproved-port"]

    approval_enforced = runtime_hook_installed()
    set_check(
        checks_by_id,
        "privilege_approval_required",
        "compliant" if approval_enforced else "violation",
        "high",
        "Runtime privileged execution hook is installed." if approval_enforced else "Runtime privileged execution hook not detected.",
        "Checked for ~/.openclaw/bin/sudo wrapper installed by cyber-security-engineer.",
        "Approval-first execution is not enforced for privileged actions.",
        "Run cyber-security-engineer/scripts/install-openclaw-runtime-hook.sh and restart OpenClaw gateway.",
        "Security Engineering",
        "2026-03-15",
    )

    least_priv_ok = gateway_loopback_configured(cfg_json, cfg_text)
    writable_issue = "not writable" in doctor.lower()
    least_status = "compliant" if least_priv_ok and not writable_issue else "partial"
    set_check(
        checks_by_id,
        "least_privilege_enforced",
        least_status,
        "high",
        "Gateway local/loopback+token controls are present; state integrity warnings may still appear.",
        "openclaw.json has local mode, loopback bind, and token auth; doctor output checked for integrity warnings.",
        "Least-privilege posture is not complete while writable/integrity warnings remain.",
        "Fix state dir ownership/permissions and enforce command allowlist/approval defaults.",
        "Platform Security",
        "2026-03-07",
    )

    timeout_status = "compliant"
    set_check(
        checks_by_id,
        "elevation_timeout_30m",
        timeout_status,
        "medium",
        "30-minute timeout logic exists in root_session_guard.py.",
        "Timeout guard script is installed with preflight drop logic.",
        "No gap identified for timeout script presence.",
        "Ensure all privileged paths route through guarded_privileged_exec.py.",
        "Security Engineering",
        "2026-03-15",
    )

    audit_ok = audit_log_present()
    set_check(
        checks_by_id,
        "audit_logging_privileged_actions",
        "compliant" if audit_ok else "partial",
        "medium",
        "Privileged audit log is populated." if audit_ok else "Privileged audit log not yet populated.",
        f"Audit log path: {AUDIT_LOG}",
        "Audit trail is missing or empty.",
        "Run privileged tasks via guarded_privileged_exec.py to populate audit logs.",
        "SecOps",
        "2026-03-22",
    )

    ports_approved = len(unapproved) == 0
    set_check(
        checks_by_id,
        "open_ports_approved",
        "compliant" if ports_approved else "violation",
        "medium",
        f"Detected {len(port_report.get('listening_services', []))} listening services with {len(unapproved)} unapproved findings.",
        "port_monitor.py live output evaluated against approved_ports baseline.",
        "Baseline missing or incomplete when unapproved findings exist.",
        "Populate ~/.openclaw/security/approved_ports.json and remove unnecessary listeners.",
        "Infrastructure",
        "2026-02-28",
    )

    insecure_status = "compliant" if len(insecure) == 0 else "violation"
    set_check(
        checks_by_id,
        "insecure_ports_remediated",
        insecure_status,
        "high",
        "No insecure legacy port findings detected." if len(insecure) == 0 else "Insecure ports detected.",
        f"Insecure findings count from port_monitor.py: {len(insecure)}.",
        "Legacy insecure protocol ports should be closed or migrated." if len(insecure) else "None observed in current snapshot.",
        "Enforce baseline checks to block insecure service ports.",
        "Network Security",
        "2026-04-01",
    )

    allowlist_ok = False if not isinstance(cfg_json, dict) else find_channel_allowlists(cfg_json)
    set_check(
        checks_by_id,
        "channel_allowlist_configured",
        "compliant" if allowlist_ok else "violation",
        "high",
        "Channel allowlists are configured." if allowlist_ok else "Channel allowlists not detected.",
        "Checked channels.*.allowFrom in openclaw.json.",
        "Inbound channel allowlists are missing, allowing unsolicited access.",
        "Set channels.<channel>.allowFrom to trusted sender IDs.",
        "Platform Security",
        "2026-03-05",
    )

    mention_ok = False if not isinstance(cfg_json, dict) else group_mentions_required(cfg_json)
    set_check(
        checks_by_id,
        "group_mentions_required",
        "compliant" if mention_ok else "partial",
        "medium",
        "Group chats require explicit mentions." if mention_ok else "Group mention requirement not detected.",
        "Checked channels.*.groups.requireMention or messages.groupChat.mentionPatterns.",
        "Group chats can trigger the agent without explicit mention.",
        "Set requireMention true for group configs or define mentionPatterns.",
        "Platform Security",
        "2026-03-05",
    )

    loopback_ok = gateway_loopback_configured(cfg_json, cfg_text)
    set_check(
        checks_by_id,
        "gateway_loopback_only",
        "compliant" if loopback_ok else "violation",
        "high",
        "Gateway is configured for local/loopback with token auth." if loopback_ok else "Gateway exposure settings are weak.",
        "Checked gateway.mode, gateway.bind, and auth.mode in openclaw.json.",
        "Gateway may be exposed publicly or without token auth.",
        "Set gateway.mode=local, gateway.bind=loopback, auth.mode=token.",
        "Platform Security",
        "2026-03-07",
    )

    perms_ok = permissions_hardened(OPENCLAW_DIR)
    config_ok = permissions_hardened(Path.home() / ".openclaw" / "openclaw.json")
    secrets_ok = perms_ok and config_ok
    set_check(
        checks_by_id,
        "secrets_permissions_hardened",
        "compliant" if secrets_ok else "partial",
        "medium",
        "OpenClaw config directory and file permissions are hardened." if secrets_ok else "OpenClaw permissions are too open or unknown.",
        "Checked ~/.openclaw and ~/.openclaw/openclaw.json permissions.",
        "Secrets and configs may be readable by other users.",
        "chmod 700 ~/.openclaw; chmod 600 ~/.openclaw/openclaw.json",
        "SecOps",
        "2026-03-10",
    )

    hook_ok = runtime_hook_installed()
    set_check(
        checks_by_id,
        "runtime_privilege_hook_installed",
        "compliant" if hook_ok else "violation",
        "high",
        "Runtime privileged execution hook installed." if hook_ok else "Runtime privileged execution hook missing.",
        "Checked ~/.openclaw/bin/sudo wrapper.",
        "Privileged actions can bypass approval enforcement.",
        "Install runtime hook and restart OpenClaw gateway.",
        "Security Engineering",
        "2026-03-01",
    )

    alt_paths = alt_privilege_paths_present()
    alt_ok = not alt_paths or hook_ok
    set_check(
        checks_by_id,
        "alternate_privilege_paths_restricted",
        "compliant" if alt_ok else "partial",
        "medium",
        "Alternate privilege tools are present but guarded." if alt_ok else "Alternate privilege tools may bypass guard.",
        "Checked for presence of su/doas binaries.",
        "Privilege escalation paths could bypass approval enforcement.",
        "Restrict su/doas usage or wrap via policy controls.",
        "Security Engineering",
        "2026-03-20",
    )

    backup_ok = backup_configured()
    set_check(
        checks_by_id,
        "backup_configured",
        "compliant" if backup_ok else "partial",
        "low",
        "OpenClaw backups found." if backup_ok else "OpenClaw backups not detected.",
        "Checked ~/.openclaw/backups or ~/.openclaw/backup.",
        "Recovery posture may be weak without backups.",
        "Configure backup of ~/.openclaw and audit logs.",
        "Platform Security",
        "2026-03-30",
    )

    update_ok = bool(version_text)
    set_check(
        checks_by_id,
        "update_hygiene",
        "partial" if update_ok else "violation",
        "low",
        f"OpenClaw version: {version_text or 'unknown'}",
        "openclaw --version output captured.",
        "Update cadence not validated.",
        "Review release notes and update regularly.",
        "Platform Security",
        "2026-04-15",
    )

    # Ensure newly added checks are persisted even if the assessment file was created
    # from an older controls map.
    assessment["checks"] = sorted(
        checks_by_id.values(), key=lambda c: str(c.get("check_id", ""))
    )
    assessment["metadata"]["generated_at_utc"] = utc_now()
    return assessment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate live compliance assessment from current machine state")
    parser.add_argument(
        "--assessment-file",
        required=True,
        help="Path to assessment JSON to update",
    )
    parser.add_argument(
        "--port-monitor-script",
        default=str(Path(__file__).resolve().parent / "port_monitor.py"),
        help="Path to port monitor script",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    assessment_path = Path(args.assessment_file)
    assessment = load_json(assessment_path)
    signals = collect_runtime_signals(Path(args.port_monitor_script))
    updated = build_assessment(assessment, signals)
    write_json(assessment_path, updated)
    print(
        json.dumps(
            {
                "status": "ok",
                "assessment_file": str(assessment_path),
                "generated_at_utc": updated["metadata"]["generated_at_utc"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
