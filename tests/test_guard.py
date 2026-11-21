#!/usr/bin/env python3
"""Tests for the approval guard: configuration, audit log, session state, command
policy and guarded_privileged_exec.py.

Run from the repository root:

    python3 -m unittest discover -s tests -v

Every test runs against a temporary home directory. Nothing is run with sudo; the
only command executed is /usr/bin/true as the current user.
"""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "cyber-security-engineer" / "scripts"
REFERENCES = SCRIPTS.parent / "references"
sys.path.insert(0, str(SCRIPTS))
import audit_logger  # noqa: E402
import command_policy  # noqa: E402
import guarded_privileged_exec as guarded  # noqa: E402
import prompt_policy  # noqa: E402
import root_session_guard as guard  # noqa: E402
import security_config  # noqa: E402

TRUE = "/usr/bin/true"


class FakeTerminal:
    """Stands in for the person at the terminal."""

    def __init__(self, answers=(), available=True):
        self.answers = list(answers)
        self.is_available = available
        self.prompts = []

    def available(self):
        return self.is_available

    def show(self, text):
        pass

    def ask(self, prompt):
        self.prompts.append(prompt)
        return self.answers.pop(0) if self.answers else ""

    secret = ask


class HomeCase(unittest.TestCase):
    """Points every script at a throwaway home directory."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.security = self.home / ".openclaw" / "security"
        self.security.mkdir(parents=True)
        self.audit = self.security / "privileged-audit.jsonl"
        self.state = self.security / "root-session-state.json"
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("OPENCLAW_")}
        clean_env["HOME"] = str(self.home)  # child processes resolve ~/.openclaw from this
        for patcher in (
            mock.patch.dict(os.environ, clean_env, clear=True),
            mock.patch.object(audit_logger, "AUDIT_LOG", self.audit),
            mock.patch.object(guard, "KEY_PATH", self.security / "session-state.key"),
            mock.patch.object(command_policy, "POLICY_PATH", self.security / "command-policy.json"),
            mock.patch.object(prompt_policy, "POLICY_PATH", self.security / "prompt-policy.json"),
            mock.patch.object(security_config, "ENV_FILE", self.home / ".openclaw" / "env"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def events(self):
        if not self.audit.exists():
            return []
        return [json.loads(line)["action"] for line in self.audit.read_text().splitlines()]

    def run_guard(self, *command, terminal=None, extra=()):
        terminal = FakeTerminal(available=False) if terminal is None else terminal
        argv = ["--state-file", str(self.state), "--reason", "test", *extra, "--", *command]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = guarded.main(argv, prompter=terminal)
        self.stderr = err.getvalue()
        return code


class SecurityConfigTests(unittest.TestCase):
    def test_parse_env_text(self):
        text = '# comment\nexport A=1\nB="two words"\nC=\'x\'\nnot a setting\nD=\n'
        self.assertEqual(security_config.parse_env_text(text), {"A": "1", "B": "two words", "C": "x", "D": ""})

    def test_a_protection_is_on_when_either_source_sets_it(self):
        self.assertTrue(security_config.flag("X", {"X": "1"}, {}))
        self.assertTrue(security_config.flag("X", {}, {"X": "1"}))
        self.assertTrue(security_config.flag("X", {"X": "1"}, {"X": "0"}))  # the environment cannot switch it off
        self.assertFalse(security_config.flag("X", {"X": "yes"}, {}))
        self.assertFalse(security_config.flag("X", {}, {}))

    def test_setting_prefers_the_file(self):
        self.assertEqual(security_config.setting("T", {"T": "file"}, {"T": "env"}), "file")
        self.assertEqual(security_config.setting("T", {}, {"T": "env"}), "env")
        self.assertIsNone(security_config.setting("T", {}, {}))

    def test_private_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "secret"
            security_config.write_private(path, "x")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertTrue(security_config.is_private(path))
            path.chmod(0o644)
            self.assertFalse(security_config.is_private(path))
            self.assertFalse(security_config.is_private(Path(tmp) / "missing"))
            self.assertEqual(security_config.load_env_file(Path(tmp) / "missing"), {})


class AuditLogTests(HomeCase):
    def write(self, count):
        for i in range(count):
            self.assertTrue(audit_logger.append_audit({"action": f"event-{i}"}))

    def test_entries_are_chained_and_private(self):
        self.write(3)
        report = audit_logger.verify()
        self.assertEqual((report["ok"], report["entries"], report["chained"]), (True, 3, 3))
        self.assertEqual(stat.S_IMODE(self.audit.stat().st_mode), 0o600)
        first = json.loads(self.audit.read_text().splitlines()[0])
        self.assertEqual(first["prev"], "")
        self.assertIn("user", first)
        self.assertIn("pid", first)

    def test_editing_an_entry_breaks_the_chain(self):
        self.write(3)
        lines = self.audit.read_text().splitlines()
        lines[0] = lines[0].replace("event-0", "event-X")
        self.audit.write_text("\n".join(lines) + "\n")
        report = audit_logger.verify()
        self.assertFalse(report["ok"])
        self.assertEqual(report["broken_at"], 2)

    def test_removing_an_entry_breaks_the_chain(self):
        self.write(3)
        lines = self.audit.read_text().splitlines()
        self.audit.write_text("\n".join([lines[0], lines[2]]) + "\n")
        self.assertFalse(audit_logger.verify()["ok"])

    def test_entries_from_before_chaining_are_accepted_only_at_the_start(self):
        self.audit.write_text('{"ts_utc":"2026-02-14T00:00:00Z","action":"old"}\n')
        self.write(2)
        report = audit_logger.verify()
        self.assertEqual((report["ok"], report["legacy"], report["chained"]), (True, 1, 2))
        with self.audit.open("a") as f:
            f.write('{"ts_utc":"2026-11-21T00:00:00Z","action":"inserted by hand"}\n')
        self.assertFalse(audit_logger.verify()["ok"])

    def test_rotation_keeps_the_chain_going(self):
        self.write(2)
        last_before = self.audit.read_bytes().splitlines()[-1]
        with mock.patch.object(audit_logger, "MAX_BYTES", 10):
            self.write(1)
        rotated = Path(str(self.audit) + ".1")
        self.assertTrue(rotated.exists())
        entry = json.loads(self.audit.read_text().splitlines()[0])
        self.assertEqual(entry["prev"], audit_logger._line_hash(last_before))
        self.assertTrue(audit_logger.verify()["ok"])

    def test_failed_write_is_reported(self):
        blocker = self.home / "not-a-directory"
        blocker.write_text("x")
        self.assertFalse(audit_logger.append_audit({"action": "x"}, blocker / "audit.jsonl"))

    def test_missing_log_verifies_as_empty(self):
        self.assertEqual(audit_logger.verify()["entries"], 0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit_logger.main(["verify", "--file", str(self.audit)]), 0)


class SessionStateTests(HomeCase):
    def approved_state(self):
        state = guard.default_state()
        guard.approve_command(state, "reason", [TRUE], None)
        guard.save_state(self.state, state)
        return state

    def load(self):
        with contextlib.redirect_stderr(io.StringIO()):
            return guard.load_state(self.state)

    def test_round_trip_is_signed_and_private(self):
        self.approved_state()
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertIn("mac", json.loads(self.state.read_text()))
        loaded = self.load()
        self.assertEqual((loaded.privilege_mode, loaded.integrity), ("elevated", "ok"))
        self.assertTrue(guard.is_allowed(loaded, [TRUE]))

    def assert_reset(self):
        loaded = self.load()
        self.assertEqual((loaded.privilege_mode, loaded.integrity), ("normal", "reset"))
        self.assertEqual(loaded.allowed_commands, [])

    def test_edited_state_is_discarded(self):
        self.approved_state()
        raw = json.loads(self.state.read_text())
        raw["allowed_commands"].append({"argv": ["/bin/sh"], "added_at_utc": raw["last_transition_utc"]})
        security_config.write_private(self.state, json.dumps(raw))
        self.assert_reset()

    def test_unsigned_state_is_discarded(self):
        now = guard.to_iso(guard.now_utc())
        forged = {"privilege_mode": "elevated", "last_elevated_activity_utc": now, "last_transition_utc": now,
                  "last_action": "forged", "allowed_commands": [{"argv": [TRUE], "added_at_utc": now}]}
        security_config.write_private(self.state, json.dumps(forged))
        self.assert_reset()

    def test_state_signed_with_another_key_is_discarded(self):
        self.approved_state()
        guard.KEY_PATH.unlink()  # a new key is generated, so the old signature no longer matches
        self.assert_reset()

    def test_state_readable_by_others_is_discarded(self):
        self.approved_state()
        self.state.chmod(0o644)
        self.assert_reset()

    def test_corrupt_state_is_discarded(self):
        security_config.write_private(self.state, "{not json")
        self.assert_reset()

    def authorize(self, state, argv, session_id=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return guard.authorize(state, 30, argv, session_id)

    def test_only_the_exact_approved_command_is_authorized(self):
        state = self.approved_state()
        self.assertEqual(self.authorize(state, [TRUE]), 0)
        self.assertEqual(self.authorize(state, [TRUE, "--extra"]), 2)
        self.assertEqual(self.authorize(state, ["/bin/sh"]), 2)

    def test_idle_session_expires(self):
        state = self.approved_state()
        state.last_elevated_activity_utc = guard.to_iso(guard.now_utc() - timedelta(minutes=31))
        self.assertEqual(self.authorize(state, [TRUE]), 2)
        self.assertEqual((state.privilege_mode, state.allowed_commands), ("normal", []))

    def test_approval_is_scoped_to_its_task_session(self):
        state = guard.default_state()
        guard.approve_command(state, "reason", [TRUE], "task-1")
        self.assertEqual(self.authorize(state, [TRUE], "task-1"), 0)
        self.assertEqual(self.authorize(state, [TRUE], "task-2"), 2)

    def test_drop_clears_everything(self):
        state = self.approved_state()
        guard.drop(state, "manual-drop")
        self.assertEqual((state.privilege_mode, state.allowed_commands, state.approved_reason), ("normal", [], None))


class CommandPolicyTests(HomeCase):
    def policy(self, value):
        text = value if isinstance(value, str) else json.dumps(value)
        command_policy.POLICY_PATH.write_text(text)

    def evaluate(self, *argv):
        with contextlib.redirect_stderr(io.StringIO()):
            return command_policy.evaluate_command(list(argv))

    def test_no_policy_file_allows(self):
        self.assertTrue(self.evaluate("/bin/ls")["allowed"])

    def test_deny_patterns(self):
        self.policy({"deny": ["\\brm\\s+-rf\\b"]})
        self.assertEqual(self.evaluate("/bin/rm", "-rf", "/x")["reason"], "deny_match")
        self.assertTrue(self.evaluate("/bin/ls")["allowed"])

    def test_deny_wins_over_allow(self):
        self.policy({"allow": ["^/bin/"], "deny": ["\\brm\\b"]})
        self.assertFalse(self.evaluate("/bin/rm", "x")["allowed"])
        self.assertTrue(self.evaluate("/bin/ls")["allowed"])
        self.assertEqual(self.evaluate("/usr/bin/id")["reason"], "not_in_allowlist")

    def test_exact_rules(self):
        self.policy({"allow_exact": [["/bin/ls", "-l"]], "deny_exact": [["/bin/ls", "-la"]]})
        self.assertTrue(self.evaluate("/bin/ls", "-l")["allowed"])
        self.assertEqual(self.evaluate("/bin/ls")["reason"], "not_in_allow_exact")
        self.assertEqual(self.evaluate("/bin/ls", "-la")["reason"], "deny_exact_match")

    def test_broken_policy_blocks_everything(self):
        for broken in ({"deny": ["("]}, {"allow": ["["]}, {"deny": "rm"}, {"deny": [5]}, "{not json", "[]",
                       {"deny_exact": [["/bin/rm", 5]]}, {"deny_exact": ["/bin/rm -rf /"]}, {"allow_exact": [[]]},
                       {"deny_exact": "x"}):
            self.policy(broken)
            result = self.evaluate("/bin/ls")
            self.assertEqual((result["allowed"], result["reason"]), (False, "invalid_policy"), broken)

    def test_shipped_template_is_valid_and_blocks_destructive_commands(self):
        self.policy((REFERENCES / "command-policy.template.json").read_text())
        self.assertTrue(self.evaluate("/bin/ls", "-l")["allowed"])
        for argv in (["/bin/rm", "-rf", "/x"], ["/bin/rm", "-fr", "/x"], ["/sbin/shutdown", "-h", "now"],
                     ["/sbin/reboot"], ["/bin/dd", "if=/dev/zero", "of=/dev/disk0"], ["/usr/sbin/visudo"]):
            self.assertFalse(self.evaluate(*argv)["allowed"], argv)


class ResolveCommandTests(unittest.TestCase):
    def test_bare_name_is_resolved_in_system_directories_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "true"
            planted.write_text("#!/bin/sh\nexit 1\n")
            planted.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": tmp}):
                argv, err = guarded.resolve_command(["true", "x"])
        self.assertIsNone(err)
        self.assertEqual(argv[1:], ["x"])
        self.assertTrue(os.path.isabs(argv[0]))
        self.assertNotEqual(argv[0], str(planted))

    def test_paths_are_left_alone(self):
        self.assertEqual(guarded.resolve_command(["/opt/tool", "a"]), (["/opt/tool", "a"], None))
        self.assertEqual(guarded.resolve_command(["./tool"]), (["./tool"], None))

    def test_errors(self):
        self.assertIn("option", guarded.resolve_command(["-u", "root", "id"])[1])
        self.assertIn("not found", guarded.resolve_command(["no-such-command-xyz"])[1])
        self.assertEqual(guarded.resolve_command([])[1], "empty argv")

    def test_validation_rejects_binaries_the_user_could_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            mine = Path(tmp) / "tool"
            mine.write_text("#!/bin/sh\n")
            mine.chmod(0o755)
            self.assertIn("not root-owned", guarded._validate_command_argv([str(mine)]))
        self.assertIsNone(guarded._validate_command_argv([TRUE]))
        self.assertEqual(guarded._validate_command_argv(["true"]), "command path must be absolute")
        self.assertEqual(guarded._validate_command_argv(["/no/such/binary"]), "command path does not exist")


class ApprovalTests(HomeCase):
    def test_no_terminal_means_no_approval(self):
        self.assertEqual(guarded.obtain_approval(FakeTerminal(available=False), "r", [TRUE]), (False, "no_terminal"))
        self.assertEqual(self.events(), ["approval_requested", "approval_unavailable"])

    def test_only_yes_approves(self):
        for answer, expected in (("y", True), ("YES", True), ("", False), ("n", False), ("sure", False)):
            self.assertEqual(guarded.obtain_approval(FakeTerminal([answer]), "r", [TRUE])[0], expected, answer)

    def test_token(self):
        self.assertEqual(guarded.obtain_approval(FakeTerminal(["y", "s3cret"]), "r", [TRUE], "s3cret"), (True, "approved"))
        self.assertEqual(guarded.obtain_approval(FakeTerminal(["y", "wrong"]), "r", [TRUE], "s3cret"), (False, "token_failed"))
        self.assertEqual(guarded.obtain_approval(FakeTerminal(["n"]), "r", [TRUE], "s3cret"), (False, "denied"))

    def test_self_test_mode_writes_no_audit_entries(self):
        guarded.obtain_approval(FakeTerminal(available=False), "r", [TRUE], audit=False)
        self.assertEqual(self.events(), [])


class GuardedExecTests(HomeCase):
    def test_refuses_without_a_terminal_even_if_stdin_says_yes(self):
        with mock.patch.object(sys, "stdin", io.StringIO("y\ny\n")):
            self.assertEqual(self.run_guard(TRUE), guarded.EXIT_NO_TERMINAL)
        self.assertNotIn("exec_start", self.events())

    def test_approved_command_runs_is_logged_and_drops_the_session(self):
        self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y"])), 0)
        events = self.events()
        for expected in ("guard_invoked", "approval_requested", "approval_decision", "approval_granted",
                         "exec_start", "exec_finish", "drop_elevation"):
            self.assertIn(expected, events)
        self.assertTrue(audit_logger.verify()["ok"])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(guard.load_state(self.state).privilege_mode, "normal")

    def test_denied_command_does_not_run(self):
        self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["n"])), 1)
        self.assertNotIn("exec_start", self.events())

    def test_bare_command_name_is_resolved(self):
        self.assertEqual(self.run_guard("true", terminal=FakeTerminal(["y"])), 0)

    def test_invalid_commands_are_refused(self):
        self.assertEqual(self.run_guard("-u", "root", "id", terminal=FakeTerminal(["y"])), 8)
        self.assertEqual(self.run_guard("no-such-command-xyz", terminal=FakeTerminal(["y"])), 8)
        self.assertNotIn("exec_start", self.events())

    def test_policy_blocks_before_anyone_is_asked(self):
        command_policy.POLICY_PATH.write_text(json.dumps({"deny": ["\\btrue\\b"]}))
        terminal = FakeTerminal(["y"])
        self.assertEqual(self.run_guard(TRUE, terminal=terminal), 3)
        self.assertEqual(terminal.prompts, [])
        self.assertIn("policy_block", self.events())

    def test_broken_policy_blocks(self):
        command_policy.POLICY_PATH.write_text('{"deny": ["("]}')
        self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y"])), 3)

    def test_forged_session_file_does_not_skip_approval(self):
        now = guard.to_iso(guard.now_utc())
        forged = {"privilege_mode": "elevated", "last_elevated_activity_utc": now, "last_normal_activity_utc": now,
                  "last_transition_utc": now, "last_action": "forged", "approved_reason": "forged",
                  "approved_session_id": None, "allowed_commands": [{"argv": [TRUE], "added_at_utc": now}]}
        security_config.write_private(self.state, json.dumps(forged))
        self.assertEqual(self.run_guard(TRUE), guarded.EXIT_NO_TERMINAL)
        self.assertIn("state_integrity_failed", self.events())
        self.assertNotIn("exec_start", self.events())

    def test_kept_session_reuses_approval_for_the_same_command_only(self):
        self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y"]), extra=["--keep-session"]), 0)
        self.assertEqual(self.run_guard(TRUE, extra=["--keep-session"]), 0)  # no terminal needed: already approved
        self.assertEqual(self.run_guard(TRUE, "--other"), guarded.EXIT_NO_TERMINAL)

    def test_env_file_settings_are_enforced(self):
        security_config.ENV_FILE.write_text("OPENCLAW_REQUIRE_SESSION_ID=1\nOPENCLAW_APPROVAL_TOKEN=s3cret\n")
        self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y", "s3cret"])), 6)
        with mock.patch.dict(os.environ, {"OPENCLAW_TASK_SESSION_ID": "task-1"}):
            self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y", "wrong"])), 4)
            self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y", "s3cret"])), 0)

    def test_required_policy_files(self):
        with mock.patch.dict(os.environ, {"OPENCLAW_REQUIRE_POLICY_FILES": "1"}):
            self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y"])), 7)

    def test_untrusted_source_needs_confirmation_at_a_terminal(self):
        prompt_policy.POLICY_PATH.write_text('{"require_confirmation_for_untrusted": true}')
        with mock.patch.dict(os.environ, {"OPENCLAW_UNTRUSTED_SOURCE": "1"}):
            self.assertEqual(self.run_guard(TRUE), 5)
            self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["n"])), 5)
            self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y", "y"])), 0)

    def test_unwritable_audit_log_stops_execution_unless_made_optional(self):
        blocker = self.home / "not-a-directory"
        blocker.write_text("x")
        with mock.patch.object(audit_logger, "AUDIT_LOG", blocker / "audit.jsonl"):
            self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y"])), guarded.EXIT_AUDIT_FAILED)
            with mock.patch.dict(os.environ, {"OPENCLAW_AUDIT_OPTIONAL": "1"}):
                self.assertEqual(self.run_guard(TRUE, terminal=FakeTerminal(["y"])), 0)

    def test_no_command(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(guarded.main(["--reason", "x"], prompter=FakeTerminal()), 2)
            self.assertEqual(guarded.main(["--reason", "x", "--"], prompter=FakeTerminal()), 2)

    def test_sudo_always_ignores_cached_credentials(self):
        completed = mock.Mock(returncode=0)
        with mock.patch.object(guarded, "find_sudo", return_value="/usr/bin/sudo"), \
                mock.patch.object(guarded.subprocess, "run", return_value=completed) as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(guarded.run_command([TRUE, "x"], use_sudo=True), 0)
        self.assertEqual(run.call_args[0][0], ["/usr/bin/sudo", "-k", "--", TRUE, "x"])
        # There is no flag to turn that off.
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            guarded.parse_args(["--reason", "x", "--no-sudo-kill-cache", "--", TRUE])
        guarded.parse_args(["--reason", "x", "--sudo-kill-cache", "--", TRUE])  # old callers still parse

    def test_sudo_is_never_taken_from_the_environment(self):
        with mock.patch.dict(os.environ, {"OPENCLAW_REAL_SUDO": TRUE}):
            self.assertIn(guarded.find_sudo(), (None,) + guarded.SUDO_CANDIDATES)
        with mock.patch.object(guarded, "SUDO_CANDIDATES", ("/no/such/sudo",)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(guarded.find_sudo())
            self.assertEqual(guarded.run_command([TRUE], use_sudo=True), 9)

    def test_caller_cannot_lengthen_the_idle_timeout(self):
        captured = mock.Mock(returncode=0, stdout="", stderr="")
        for requested, expected in (("99999", "30"), ("5", "5"), ("0", "1")):
            args = guarded.parse_args(["--reason", "x", "--timeout-minutes", requested, "--", TRUE])
            with mock.patch.object(guarded.subprocess, "run", return_value=captured) as run:
                guarded.run_guard(args, "status")
            argv = run.call_args[0][0]
            self.assertEqual(argv[argv.index("--timeout-minutes") + 1], expected)

    def test_the_resolved_file_is_what_gets_approved_checked_and_run(self):
        link = self.home / "innocent-name"
        link.symlink_to(TRUE)
        # Validation follows the link to a root-owned binary, and that real path is what is used.
        real = os.path.realpath(TRUE)
        command_policy.POLICY_PATH.write_text(json.dumps({"deny": ["^" + real + "$"]}))
        terminal = FakeTerminal(["y"])
        self.assertEqual(self.run_guard(str(link), terminal=terminal), 3)  # policy on the real path applies
        command_policy.POLICY_PATH.unlink()
        self.assertEqual(self.run_guard(str(link), terminal=FakeTerminal(["y"])), 0)
        started = [json.loads(line) for line in self.audit.read_text().splitlines()
                   if json.loads(line)["action"] == "exec_start"]
        self.assertEqual(started[-1]["argv"], [real])


if __name__ == "__main__":
    unittest.main()
