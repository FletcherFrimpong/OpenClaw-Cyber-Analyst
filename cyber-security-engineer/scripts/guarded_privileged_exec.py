#!/usr/bin/env python3
import argparse
import shlex
import subprocess
import sys
from pathlib import Path


def run_guard(args, *guard_args):
    cmd = [
        sys.executable,
        str(Path(__file__).with_name("root_session_guard.py")),
        "--state-file",
        args.state_file,
        "--timeout-minutes",
        str(args.timeout_minutes),
        *guard_args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def ask_for_approval(reason: str, command: str) -> bool:
    print("Approval required for elevated execution.")
    print(f"Reason: {reason}")
    print(f"Command: {command}")
    answer = input("Approve elevated access for this command? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def run_command(cmd: str, use_sudo: bool) -> int:
    shell_cmd = f"sudo {cmd}" if use_sudo else cmd
    print(f"Executing: {shell_cmd}")
    result = subprocess.run(shell_cmd, shell=True)
    return result.returncode


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute privileged commands with approval + idle-timeout guard",
    )
    parser.add_argument(
        "--state-file",
        default=str(Path.home() / ".openclaw" / "security" / "root-session-state.json"),
        help="Path to root session state file",
    )
    parser.add_argument(
        "--timeout-minutes",
        type=int,
        default=30,
        help="Idle timeout for elevated mode",
    )
    parser.add_argument(
        "--reason",
        required=True,
        help="Business/security reason for privileged command",
    )
    parser.add_argument(
        "--use-sudo",
        action="store_true",
        help="Prefix command with sudo",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help='Command to run, e.g. -- "systemctl restart nginx"',
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.command:
        print("No command supplied.", file=sys.stderr)
        return 2

    cmd_tokens = args.command
    if cmd_tokens and cmd_tokens[0] == "--":
        cmd_tokens = cmd_tokens[1:]
    if not cmd_tokens:
        print("No command supplied after -- delimiter.", file=sys.stderr)
        return 2

    command = shlex.join(cmd_tokens)
    preflight = run_guard(args, "preflight")
    if preflight.returncode not in (0, 2):
        sys.stderr.write(preflight.stderr or preflight.stdout)
        return preflight.returncode

    needs_approval = preflight.returncode == 2
    if needs_approval and not ask_for_approval(args.reason, command):
        print("User denied elevated access. Running in normal mode is required.")
        run_guard(args, "normal-used")
        return 1

    if needs_approval:
        mark = run_guard(args, "elevated-used")
        if mark.returncode != 0:
            sys.stderr.write(mark.stderr or mark.stdout)
            return mark.returncode

    try:
        return run_command(command, args.use_sudo)
    finally:
        # Always drop elevation to enforce post-task least privilege.
        run_guard(args, "drop")


if __name__ == "__main__":
    raise SystemExit(main())
