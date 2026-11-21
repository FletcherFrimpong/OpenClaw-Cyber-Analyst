#!/usr/bin/env python3
"""Tests for cyber-security-engineer/scripts/notify_on_violation.py."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "cyber-security-engineer" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import notify_on_violation as nv  # noqa: E402


def finding(status="violation", risk="high", title="T"):
    return {"status": status, "risk": risk, "title": title}


class DiffTests(unittest.TestCase):
    def test_new_and_escalated_findings_are_reported_once(self):
        prev = {"a": finding("partial"), "b": finding("violation"), "c": finding("partial")}
        cur = {"a": finding("violation"), "b": finding("violation"), "c": finding("partial"), "d": finding("partial")}
        self.assertEqual([check for check, _ in nv._diff_new(prev, cur)], ["a", "d"])
        self.assertEqual(nv._diff_new(cur, cur), [])
        self.assertEqual(nv._diff_new(cur, {}), [])  # a finding that cleared is not news

    def test_state_is_read_from_the_summary(self):
        summary = {"violations": [{"check_id": "x", "status": "partial", "risk": "low", "title": "X"}, {"status": "partial"}]}
        self.assertEqual(nv._extract_violation_state(summary), {"x": {"status": "partial", "risk": "low", "title": "X"}})

    def test_message_lists_each_finding(self):
        text = nv._format_message([("x", finding("partial", "low", "X control"))], "summary.json")
        self.assertIn("- x: partial (low) - X control", text)


class NotifierCommandTests(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(nv._validate_notify_argv([]), "empty argv")
        self.assertIn("absolute", nv._validate_notify_argv(["logger"]))
        for launcher in ("/bin/sh", "/bin/bash", "/usr/bin/env", "/usr/bin/python3", "/usr/bin/sudo"):
            self.assertIn("launcher", nv._validate_notify_argv([launcher, "-c", "x"]), launcher)
        self.assertIn("does not exist", nv._validate_notify_argv(["/no/such/notifier"]))
        self.assertIsNone(nv._validate_notify_argv(["/usr/bin/true"]))

    def test_exact_argv_allowlist(self):
        allow = json.dumps([["/usr/bin/logger", "-t", "openclaw"]])
        with mock.patch.dict(os.environ, {"OPENCLAW_VIOLATION_NOTIFY_ALLOWLIST": allow}):
            self.assertTrue(nv._is_allowed_notify_command(["/usr/bin/logger", "-t", "openclaw"]))
            self.assertFalse(nv._is_allowed_notify_command(["/usr/bin/logger", "-t", "other"]))
            self.assertFalse(nv._is_allowed_notify_command(["/usr/bin/logger"]))
        with mock.patch.dict(os.environ, {"OPENCLAW_VIOLATION_NOTIFY_ALLOWLIST": ""}):
            self.assertFalse(nv._is_allowed_notify_command(["/usr/bin/logger"]))

    def test_command_parsing(self):
        self.assertEqual(nv._parse_notify_command('["/usr/bin/logger", "-t", "x y"]'), ["/usr/bin/logger", "-t", "x y"])
        self.assertEqual(nv._parse_notify_command("/usr/bin/logger -t tag"), ["/usr/bin/logger", "-t", "tag"])
        self.assertEqual(nv._parse_notify_command("  "), [])

    def test_notifier_gets_named_variables_only(self):
        env = {"OPENCLAW_VIOLATION_NOTIFY_CMD": "/usr/bin/true", "OPENCLAW_VIOLATION_NOTIFY_ALLOWLIST": "/usr/bin/true",
               "PATH": "/usr/bin", "HOME": "/home/x", "AWS_SECRET_ACCESS_KEY": "s", "LD_PRELOAD": "/x.so"}
        completed = mock.Mock(returncode=0)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(nv.subprocess, "run", return_value=completed) as run:
            nv._send_notification("message")
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin", "HOME": "/home/x"})

    def test_unlisted_notifier_is_never_run(self):
        env = {"OPENCLAW_VIOLATION_NOTIFY_CMD": "/usr/bin/true", "OPENCLAW_VIOLATION_NOTIFY_ALLOWLIST": "/usr/bin/false"}
        with mock.patch.dict(os.environ, env), mock.patch.object(nv.subprocess, "run") as run:
            with contextlib.redirect_stderr(io.StringIO()):
                nv._send_notification("message")
        run.assert_not_called()


class EndToEndTests(unittest.TestCase):
    def test_second_run_with_the_same_findings_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary, state = Path(tmp) / "summary.json", Path(tmp) / "state.json"
            summary.write_text(json.dumps({"violations": [{"check_id": "x", "status": "partial", "risk": "low", "title": "X"}]}))
            argv = ["notify_on_violation.py", "--summary-file", str(summary), "--state-file", str(state)]
            outputs = []
            for _ in range(2):
                out = io.StringIO()
                with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, {"OPENCLAW_VIOLATION_NOTIFY_CMD": ""}):
                    with contextlib.redirect_stdout(out):
                        self.assertEqual(nv.main(), 0)
                outputs.append(out.getvalue())
            self.assertIn("- x: partial (low) - X", outputs[0])
            self.assertEqual(outputs[1], "")


if __name__ == "__main__":
    unittest.main()
