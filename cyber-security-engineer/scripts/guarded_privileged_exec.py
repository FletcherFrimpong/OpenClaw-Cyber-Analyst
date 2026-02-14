#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List


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


def ask_for_approval(reason: str, command_argv: List[str]) -> bool:
    print("Approval required for elevated execution.")
    print(f"Reason: {reason}")
    print("Command argv:")
    print(json.dumps(command_argv, indent=2))
    answer = input("Approve elevated access for this command? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def run_command(argv: List[str], use_sudo: bool, sudo_kill_cache: bool) -> int:
    exec_argv = ["sudo", "--"] + argv if use_sudo else argv
    print("Executing argv:")
    print(json.dumps(exec_argv, indent=2))
    if use_sudo and sudo_kill_cache:
        # Best-effort: ensure sudo timestamp for this user is not reused implicitly.
        subprocess.run(["sudo", "-k"], check=False, capture_output=True, text=True)
    result = subprocess.run(exec_argv)
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
        help="Idle timeout for elevated mode / approval session",
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
        "--sudo-kill-cache",
        action="store_true",
        default=False,
        help="Run `sudo -k` before execution to reduce implicit sudo reuse",
    )
    parser.add_argument(
        "--keep-session",
        action="store_true",
        default=False,
        help="Keep elevated session after command (still restricted to allowlisted argv; expires on idle timeout)",
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

    argv = args.command
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("No command supplied after -- delimiter.", file=sys.stderr)
        return 2

    argv_json = json.dumps(argv)
    authz = run_guard(args, "authorize", "--argv-json", argv_json)
    if authz.returncode not in (0, 2):
        sys.stderr.write(authz.stderr or authz.stdout)
        return authz.returncode

    needs_approval = authz.returncode == 2
    if needs_approval and not ask_for_approval(args.reason, argv):
        print("User denied elevated access. Running in normal mode is required.")
        run_guard(args, "normal-used")
        return 1

    if needs_approval:
        approve = run_guard(args, "approve", "--reason", args.reason, "--argv-json", argv_json)
        if approve.returncode != 0:
            sys.stderr.write(approve.stderr or approve.stdout)
            return approve.returncode

    try:
        # Mark elevated activity if we're about to use sudo.
        if args.use_sudo:
            run_guard(args, "elevated-used")
        return run_command(argv, args.use_sudo, args.sudo_kill_cache)
    finally:
        # Default: always drop elevation to enforce post-task least privilege.
        # If --keep-session is set, elevated session remains active, but only allowlisted argv are authorized.
        if not args.keep_session:
            run_guard(args, "drop")
        if args.use_sudo and args.sudo_kill_cache:
            subprocess.run(["sudo", "-k"], check=False, capture_output=True, text=True)


if __name__ == "__main__":
    raise SystemExit(main())
