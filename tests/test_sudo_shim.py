#!/usr/bin/env python3
"""Tests for the sudo shim template and its installer.

The shim is filled in with stand-in programs, so neither sudo nor the real guard
is ever run.
"""
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "cyber-security-engineer" / "scripts"
TEMPLATE = SCRIPTS / "sudo-shim.template.sh"
INSTALLER = SCRIPTS / "install-openclaw-runtime-hook.sh"


def executable(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)
    return path


@unittest.skipUnless(shutil.which("bash"), "bash is required")
class ShimTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        # Stand-ins that report how they were called.
        self.real_sudo = executable(self.tmp / "real sudo", 'printf "REAL"; printf " [%s]" "$@"; echo\n')
        self.python = executable(self.tmp / "python3", 'printf "GUARD"; printf " [%s]" "$@"; echo\n')
        self.skill = self.tmp / "skill dir"
        text = TEMPLATE.read_text()
        for placeholder, value in (("@REAL_SUDO@", self.real_sudo), ("@PYTHON3@", self.python), ("@SKILL_DIR@", self.skill)):
            text = text.replace(placeholder, shlex.quote(str(value)))
        self.shim = executable(self.tmp / "bin" / "sudo", "")
        self.shim.write_text(text)

    def run_shim(self, *args, env=None):
        full_env = dict(os.environ, **(env or {}))
        return subprocess.run([str(self.shim), *args], capture_output=True, text=True, env=full_env).stdout.strip()

    def test_commands_go_to_the_guard(self):
        out = self.run_shim("ls", "-l", "/tmp/a b")
        guard = str(self.skill / "scripts" / "guarded_privileged_exec.py")
        self.assertEqual(
            out,
            f"GUARD [{guard}] [--reason] [OpenClaw requested privileged execution] [--use-sudo] [--] [ls] [-l] [/tmp/a b]",
        )

    def test_single_harmless_flags_go_to_the_real_sudo(self):
        for flag in ("-h", "--help", "-V", "--version", "-k", "-K"):
            self.assertEqual(self.run_shim(flag), f"REAL [{flag}]", flag)
        self.assertEqual(self.run_shim(), "REAL []")  # no arguments: the stand-in prints one empty slot

    def test_a_flag_followed_by_a_command_is_not_passed_through(self):
        # "sudo -k rm ..." runs a command, so it must reach the guard, never the real sudo.
        for args in (["-k", "rm", "-rf", "/x"], ["-V", "id"], ["-h", "sh"], ["-l"], ["-v"], ["-n", "true"], ["-K", "x"]):
            self.assertTrue(self.run_shim(*args).startswith("GUARD "), args)

    def test_paths_cannot_be_redirected_through_the_environment(self):
        evil = executable(self.tmp / "evil", 'echo EVIL "$@"\n')
        env = {
            "OPENCLAW_REAL_SUDO": str(evil),
            "OPENCLAW_PYTHON3": str(evil),
            "OPENCLAW_CYBER_SKILL_DIR": str(self.tmp / "evil-skill"),
            "OPENCLAW_ALLOW_NONINTERACTIVE_SUDO": "1",
        }
        self.assertTrue(self.run_shim("id", env=env).startswith("GUARD "))
        self.assertIn(str(self.skill), self.run_shim("id", env=env))
        self.assertEqual(self.run_shim("-V", env=env), "REAL [-V]")

    def test_reason_is_reduced_to_plain_characters(self):
        out = self.run_shim("id", env={"OPENCLAW_PRIV_REASON": 'fix $(rm -rf /) `x`; "quoted" | ok'})
        self.assertIn("[fix rm -rf / x quoted  ok]", out)

    def test_template_has_no_unfilled_placeholders_after_install(self):
        for name in ("@REAL_SUDO@", "@PYTHON3@", "@SKILL_DIR@"):
            self.assertIn(name, TEMPLATE.read_text())
            self.assertNotIn(name, self.shim.read_text())


@unittest.skipUnless(os.path.exists("/usr/bin/sudo") and shutil.which("bash"), "needs bash and a system sudo")
class InstallerTests(unittest.TestCase):
    def install(self, home: Path, **extra_env):
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
        env.update(extra_env)
        return subprocess.run(["bash", str(INSTALLER)], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)

    def test_nothing_persistent_changes_without_a_clear_yes(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            guard = home / ".openclaw" / "workspace" / "skills" / "cyber-security-engineer" / "scripts" / "guarded_privileged_exec.py"
            guard.parent.mkdir(parents=True)
            guard.write_text("")
            result = self.install(home)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("was not changed", result.stdout)
            shim = home / ".openclaw" / "bin" / "sudo"
            self.assertEqual(stat.S_IMODE(shim.stat().st_mode), 0o700)
            text = shim.read_text()
            self.assertIn("REAL_SUDO=/usr/bin/sudo", text)
            self.assertIn(f"SKILL_DIR={shlex.quote(str(guard.parent.parent))}", text)
            self.assertNotIn("@REAL_SUDO@", text)
            self.assertFalse((home / ".openclaw" / "openclaw.json").exists())

    def test_refuses_when_the_skill_is_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.install(Path(tmp))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not installed", result.stdout)
            self.assertFalse((Path(tmp) / ".openclaw" / "bin" / "sudo").exists())


if __name__ == "__main__":
    unittest.main()
