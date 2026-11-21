#!/usr/bin/env python3
"""Tests for cyber-security-engineer/scripts/live_assessment.py.

Host signals are supplied directly, so no OpenClaw install, sudo or network is used.
"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "cyber-security-engineer" / "scripts"
REFERENCES = SCRIPTS.parent / "references"
sys.path.insert(0, str(SCRIPTS))
import live_assessment as la  # noqa: E402
import root_session_guard as guard  # noqa: E402

TODAY = datetime(2026, 11, 21, tzinfo=timezone.utc)
GOOD_CONFIG = {
    "gateway": {"mode": "local", "bind": "loopback", "auth": {"mode": "token"}},
    "channels": {"telegram": {"allowFrom": ["1"], "groups": {"*": {"requireMention": True}}}},
}


def signals(**overrides):
    """A host where every control passes."""
    base = {
        "openclaw_config_text": json.dumps(GOOD_CONFIG),
        "openclaw_config_json": GOOD_CONFIG,
        "doctor_text": "all good",
        "gateway_status_text": "running",
        "version_text": "OpenClaw 2026.10.1 (abc1234)",
        "today": TODAY,
        "port_report": {"status": "ok", "findings": []},
        "egress_report": {"status": "ok", "findings": [], "summary": {"evaluated": 2}},
        "env_flags": {"OPENCLAW_REQUIRE_SESSION_ID": "1", "OPENCLAW_APPROVAL_TOKEN": "t"},
        "command_policy": {"deny": ["x"]},
        "prompt_policy": {"require_confirmation_for_untrusted": True},
        "egress_allowlist": [{"host": "api.example.com"}],
        "hook_installed": True,
        "hook_on_gateway_path": True,
        "passwordless_sudo": False,
        "runs_as_root": False,
        "timeout_selftest": True,
        "guard_selftest": {"refuses_without_terminal": True, "discards_forged_state": True},
        "audit_chain": {"ok": True, "entries": 5, "broken_at": None},
        "backup_configured": True,
        "secrets_hardened": True,
    }
    base.update(overrides)
    return base


def assess(previous=None, **overrides):
    assessment = previous or {"metadata": {}, "checks": []}
    result = la.build_assessment(assessment, signals(**overrides))
    return {c["check_id"]: c for c in result["checks"]}


class CoverageTests(unittest.TestCase):
    def test_every_mapped_control_is_assessed_and_nothing_else(self):
        mapped = {c["check_id"] for c in json.loads((REFERENCES / "compliance-controls-map.json").read_text())}
        self.assertEqual(set(assess()), mapped)

    def test_a_healthy_host_is_fully_compliant_with_nothing_outstanding(self):
        for check_id, check in assess().items():
            self.assertEqual(check["status"], "compliant", check_id)
            self.assertEqual((check["gap"], check["mitigation"], check["due_date"]), ("", "", ""), check_id)
            self.assertTrue(check["observed_state"], check_id)
            self.assertTrue(check["evidence"], check_id)


class ControlTests(unittest.TestCase):
    def status(self, check_id, **overrides):
        return assess(**overrides)[check_id]["status"]

    def test_approval_guard(self):
        check = "privilege_approval_required"
        self.assertEqual(self.status(check, guard_selftest={"refuses_without_terminal": False, "discards_forged_state": True}), "violation")
        self.assertEqual(self.status(check, guard_selftest={"refuses_without_terminal": True, "discards_forged_state": False}), "violation")
        self.assertEqual(self.status(check, guard_selftest={}), "violation")
        self.assertEqual(self.status(check, hook_installed=False), "violation")

    def test_hook_must_be_on_the_gateway_path(self):
        check = "runtime_privilege_hook_installed"
        self.assertEqual(self.status(check, hook_installed=False), "violation")
        self.assertEqual(self.status(check, hook_on_gateway_path=False), "partial")
        self.assertEqual(self.status(check, hook_on_gateway_path=None), "partial")

    def test_passwordless_sudo_is_a_violation_even_with_the_hook(self):
        check = "alternate_privilege_paths_restricted"
        self.assertEqual(self.status(check, passwordless_sudo=True, hook_installed=True), "violation")
        self.assertEqual(self.status(check, passwordless_sudo=None), "partial")

    def test_least_privilege(self):
        check = "least_privilege_enforced"
        self.assertEqual(self.status(check, runs_as_root=True), "violation")
        self.assertEqual(self.status(check, doctor_text="state dir is NOT WRITABLE"), "partial")

    def test_timeout_is_tested_not_assumed(self):
        self.assertEqual(self.status("elevation_timeout_30m", timeout_selftest=False), "violation")

    def test_audit_log(self):
        check = "audit_logging_privileged_actions"
        self.assertEqual(self.status(check, audit_chain={"ok": True, "entries": 0}), "partial")
        self.assertEqual(self.status(check, audit_chain={"ok": False, "entries": 9, "broken_at": 4, "error": "x"}), "violation")

    def test_update_hygiene_follows_the_release_date(self):
        check = "update_hygiene"
        self.assertEqual(self.status(check, version_text="OpenClaw 2026.8.3"), "compliant")
        self.assertEqual(self.status(check, version_text="OpenClaw 2026.4.2 (d74a122)"), "partial")
        self.assertEqual(self.status(check, version_text=""), "violation")
        self.assertEqual(self.status(check, version_text="openclaw: command not found"), "violation")

    def test_ports(self):
        report = {"status": "ok", "findings": [
            {"type": "unapproved-port", "port": 1}, {"type": "public-bind", "port": 2}, {"type": "insecure-port", "port": 3}]}
        result = assess(port_report=report)
        self.assertEqual(result["open_ports_approved"]["status"], "partial")
        self.assertEqual(result["public_listeners_justified"]["status"], "partial")
        self.assertEqual(result["insecure_ports_remediated"]["status"], "violation")

    def test_settings_come_from_the_env_file(self):
        result = assess(env_flags={})
        self.assertEqual(result["session_boundary_enforced"]["status"], "partial")
        self.assertEqual(result["multi_factor_approval"]["status"], "partial")

    def test_egress(self):
        self.assertEqual(self.status("egress_connections_approved", egress_report={"status": "error"}), "partial")
        self.assertEqual(self.status("egress_connections_approved", egress_report={"status": "ok", "findings": [{}], "summary": {"evaluated": 1}}), "partial")
        self.assertEqual(self.status("egress_allowlist_configured", egress_allowlist=[]), "partial")

    def test_config_controls(self):
        result = assess(openclaw_config_json={"gateway": {"mode": "remote"}}, openclaw_config_text="{}")
        self.assertEqual(result["gateway_loopback_only"]["status"], "violation")
        self.assertEqual(result["channel_allowlist_configured"]["status"], "violation")
        self.assertEqual(result["group_mentions_required"]["status"], "partial")


class OutstandingWorkTests(unittest.TestCase):
    def test_open_control_keeps_its_first_due_date(self):
        with mock.patch.object(la, "due_in", return_value="2026-12-01"):
            first = la.build_assessment({"metadata": {}, "checks": []}, signals(env_flags={}))
        with mock.patch.object(la, "due_in", return_value="2027-01-15"):
            second = la.build_assessment(first, signals(env_flags={}))
        check = {c["check_id"]: c for c in second["checks"]}["multi_factor_approval"]
        self.assertEqual(check["due_date"], "2026-12-01")
        self.assertTrue(check["gap"])
        self.assertTrue(check["mitigation"])

    def test_fixed_control_is_cleared_and_gets_a_new_date_if_it_reopens(self):
        with mock.patch.object(la, "due_in", return_value="2026-12-01"):
            opened = la.build_assessment({"metadata": {}, "checks": []}, signals(env_flags={}))
        fixed = la.build_assessment(opened, signals())
        check = {c["check_id"]: c for c in fixed["checks"]}["multi_factor_approval"]
        self.assertEqual((check["status"], check["due_date"], check["mitigation"]), ("compliant", "", ""))
        with mock.patch.object(la, "due_in", return_value="2027-02-01"):
            reopened = la.build_assessment(fixed, signals(env_flags={}))
        self.assertEqual({c["check_id"]: c for c in reopened["checks"]}["multi_factor_approval"]["due_date"], "2027-02-01")


class ProbeTests(unittest.TestCase):
    def test_release_age(self):
        self.assertEqual(la.release_age_months("OpenClaw 2026.4.2 (d74a122)", TODAY), 7)
        self.assertEqual(la.release_age_months("OpenClaw 2026.11.6", TODAY), 0)
        self.assertEqual(la.release_age_months("OpenClaw 2025.12.1", TODAY), 11)
        self.assertEqual(la.release_age_months("OpenClaw 2027.1.1", TODAY), 0)  # clock skew never goes negative
        self.assertIsNone(la.release_age_months("v1.2.3", TODAY))
        self.assertIsNone(la.release_age_months("OpenClaw 2026.13.1", TODAY))
        self.assertIsNone(la.release_age_months("", TODAY))

    def test_self_tests_pass_against_the_shipped_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(guard, "KEY_PATH", Path(tmp) / "session-state.key"):
                self.assertTrue(la.timeout_selftest())
                self.assertEqual(la.guard_selftest(), {"refuses_without_terminal": True, "discards_forged_state": True})

    def test_self_test_catches_a_guard_that_trusts_forged_state(self):
        trusting = guard.default_state()
        trusting.privilege_mode = "elevated"
        trusting.allowed_commands = [guard.AllowedCommand(argv=["/usr/bin/true"], added_at_utc="x")]
        with mock.patch.object(guard, "load_state", return_value=trusting):
            self.assertFalse(la.guard_selftest()["discards_forged_state"])

    def test_gateway_path_check(self):
        import plistlib

        with tempfile.TemporaryDirectory() as tmp:
            plist = Path(tmp) / "gateway.plist"
            shim = str(la.OPENCLAW_DIR / "bin")
            with mock.patch.object(la, "GATEWAY_PLIST", plist):
                self.assertIsNone(la.hook_on_gateway_path())
                for path, expected in ((f"{shim}:/usr/bin:/bin", True), (f"/opt/x/bin:{shim}:/usr/bin", True),
                                       (f"/usr/bin:{shim}", False), ("/usr/bin:/bin", False)):
                    plist.write_bytes(plistlib.dumps({"EnvironmentVariables": {"PATH": path}}))
                    self.assertIs(la.hook_on_gateway_path(), expected, path)
                plist.write_bytes(plistlib.dumps({}))
                self.assertIs(la.hook_on_gateway_path(), False)


if __name__ == "__main__":
    unittest.main()
