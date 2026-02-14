#!/usr/bin/env python3
import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional


DEFAULT_TIMEOUT_MINUTES = 30
STATE_PATH = Path.home() / ".openclaw" / "security" / "root-session-state.json"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def from_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


@dataclass
class SessionState:
    privilege_mode: str
    last_elevated_activity_utc: Optional[str]
    last_normal_activity_utc: Optional[str]
    last_transition_utc: str
    last_action: str

    def as_dict(self) -> Dict[str, Optional[str]]:
        return {
            "privilege_mode": self.privilege_mode,
            "last_elevated_activity_utc": self.last_elevated_activity_utc,
            "last_normal_activity_utc": self.last_normal_activity_utc,
            "last_transition_utc": self.last_transition_utc,
            "last_action": self.last_action,
        }


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def default_state() -> SessionState:
    ts = to_iso(now_utc())
    return SessionState(
        privilege_mode="normal",
        last_elevated_activity_utc=None,
        last_normal_activity_utc=ts,
        last_transition_utc=ts,
        last_action="init-normal",
    )


def load_state(path: Path) -> SessionState:
    if not path.exists():
        state = default_state()
        save_state(path, state)
        return state
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return SessionState(
        privilege_mode=raw.get("privilege_mode", "normal"),
        last_elevated_activity_utc=raw.get("last_elevated_activity_utc"),
        last_normal_activity_utc=raw.get("last_normal_activity_utc"),
        last_transition_utc=raw.get("last_transition_utc", to_iso(now_utc())),
        last_action=raw.get("last_action", "unknown"),
    )


def save_state(path: Path, state: SessionState) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as f:
        json.dump(state.as_dict(), f, indent=2)
        f.write("\n")


def minutes_since(ts_iso: Optional[str]) -> Optional[float]:
    ts = from_iso(ts_iso)
    if ts is None:
        return None
    delta = now_utc() - ts
    return round(delta.total_seconds() / 60.0, 2)


def preflight(state: SessionState, timeout_minutes: int) -> int:
    idle_mins = minutes_since(state.last_elevated_activity_utc)
    timed_out = (
        state.privilege_mode == "elevated"
        and idle_mins is not None
        and idle_mins >= timeout_minutes
    )

    action = "continue-normal"
    approval_required = True
    if state.privilege_mode == "elevated" and not timed_out:
        action = "elevated-active"
        approval_required = False
    elif timed_out:
        action = "drop-elevation"
        state.privilege_mode = "normal"
        state.last_transition_utc = to_iso(now_utc())
        state.last_action = "timeout-drop"

    result = {
        "status": "REQUIRES_APPROVAL" if approval_required else "ELEVATED_AVAILABLE",
        "privilege_mode": state.privilege_mode,
        "idle_minutes_since_elevated": idle_mins,
        "timeout_minutes": timeout_minutes,
        "action": action,
    }
    print(json.dumps(result, indent=2))
    return 2 if approval_required else 0


def mark_elevated_used(state: SessionState) -> None:
    ts = to_iso(now_utc())
    state.privilege_mode = "elevated"
    state.last_elevated_activity_utc = ts
    state.last_transition_utc = ts
    state.last_action = "elevated-used"


def mark_normal_used(state: SessionState) -> None:
    ts = to_iso(now_utc())
    state.privilege_mode = "normal"
    state.last_normal_activity_utc = ts
    state.last_transition_utc = ts
    state.last_action = "normal-used"


def drop(state: SessionState, reason: str) -> None:
    ts = to_iso(now_utc())
    state.privilege_mode = "normal"
    state.last_transition_utc = ts
    state.last_action = reason


def status(state: SessionState, timeout_minutes: int) -> None:
    idle_mins = minutes_since(state.last_elevated_activity_utc)
    timed_out = (
        state.privilege_mode == "elevated"
        and idle_mins is not None
        and idle_mins >= timeout_minutes
    )
    result = state.as_dict()
    result["idle_minutes_since_elevated"] = idle_mins
    result["timeout_minutes"] = timeout_minutes
    result["timed_out"] = timed_out
    result["approval_required"] = state.privilege_mode != "elevated" or timed_out
    print(json.dumps(result, indent=2))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OpenClaw root/elevated session guard")
    parser.add_argument(
        "--state-file",
        default=str(STATE_PATH),
        help="Path to session state JSON file",
    )
    parser.add_argument(
        "--timeout-minutes",
        type=int,
        default=DEFAULT_TIMEOUT_MINUTES,
        help="Idle timeout for elevated mode",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight", help="Check timeout and approval requirement")
    sub.add_parser("elevated-used", help="Mark elevated mode as used now")
    sub.add_parser("normal-used", help="Mark normal mode activity now")
    sub.add_parser("drop", help="Drop to normal mode")
    sub.add_parser("status", help="Print current state and timeout info")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    state_file = Path(os.path.expanduser(args.state_file))
    state = load_state(state_file)

    if args.command == "preflight":
        code = preflight(state, args.timeout_minutes)
        save_state(state_file, state)
        return code
    if args.command == "elevated-used":
        mark_elevated_used(state)
        save_state(state_file, state)
        print('{"status":"OK","action":"elevated-used"}')
        return 0
    if args.command == "normal-used":
        mark_normal_used(state)
        save_state(state_file, state)
        print('{"status":"OK","action":"normal-used"}')
        return 0
    if args.command == "drop":
        drop(state, "manual-drop")
        save_state(state_file, state)
        print('{"status":"OK","action":"drop-elevation"}')
        return 0
    if args.command == "status":
        status(state, args.timeout_minutes)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
