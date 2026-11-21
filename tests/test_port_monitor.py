#!/usr/bin/env python3
"""Tests for cyber-security-engineer/scripts/port_monitor.py and generate_approved_ports.py.

Command output is supplied as sample text; no real sockets are inspected.
"""
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "cyber-security-engineer" / "scripts"
sys.path.insert(0, str(SCRIPTS))
import generate_approved_ports  # noqa: E402
import port_monitor as pm  # noqa: E402

LSOF_TCP = """\
COMMAND         PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
node           9905 user   18u  IPv4 0x1      0t0  TCP 127.0.0.1:18789 (LISTEN)
node           9905 user   19u  IPv6 0x2      0t0  TCP [::1]:18789 (LISTEN)
ControlCenter   729 user   10u  IPv4 0x3      0t0  TCP *:7000 (LISTEN)
httpd           800 root    4u  IPv6 0x4      0t0  TCP *:80 (LISTEN)
"""

LSOF_UDP = """\
COMMAND     PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
mDNSRespo   400 user    6u  IPv4 0x5      0t0  UDP *:5353
chat        500 user    7u  IPv4 0x6      0t0  UDP 10.0.0.2:50000->1.2.3.4:3478
syslogd     300 root    5u  IPv4 0x7      0t0  UDP *:*
"""

SS_TCP = """\
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128    0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))
LISTEN 0      511    127.0.0.1:18789 0.0.0.0:* users:(("node",pid=123,fd=18))
"""

SS_UDP = """\
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
UNCONN 0      0      0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=700,fd=12))
"""

NETSTAT = """\
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       888
  TCP    192.168.1.5:50000      1.2.3.4:443            ESTABLISHED     1234
"""


def entry(port, command="node", host="127.0.0.1", protocol="tcp"):
    return {"command": command, "pid": 1, "user": "user", "host": host, "port": port, "protocol": protocol}


def kinds(findings):
    return sorted((f["type"], f["port"]) for f in findings)


class ParserTests(unittest.TestCase):
    def test_lsof_tcp(self):
        entries = pm.parse_lsof_output(LSOF_TCP)
        self.assertEqual(
            [(e["command"], e["host"], e["port"], e["protocol"]) for e in entries],
            [("node", "127.0.0.1", 18789, "tcp"), ("node", "::1", 18789, "tcp"),
             ("ControlCenter", "*", 7000, "tcp"), ("httpd", "*", 80, "tcp")],
        )

    def test_lsof_udp_skips_connected_and_portless_sockets(self):
        entries = pm.parse_lsof_output(LSOF_UDP, protocol="udp")
        self.assertEqual([(e["command"], e["port"], e["protocol"]) for e in entries], [("mDNSRespo", 5353, "udp")])

    def test_ss(self):
        self.assertEqual([(e["command"], e["port"]) for e in pm.parse_ss_output(SS_TCP)], [("sshd", 22), ("node", 18789)])
        udp = pm.parse_ss_output(SS_UDP, protocol="udp")
        self.assertEqual([(e["command"], e["port"], e["protocol"]) for e in udp], [("avahi-daemon", 5353, "udp")])

    def test_netstat_windows(self):
        self.assertEqual([(e["port"], e["pid"]) for e in pm.parse_netstat_windows_output(NETSTAT)], [(135, 888)])

    def test_empty_output(self):
        self.assertEqual(pm.parse_lsof_output(""), [])

    def test_lsof_with_no_listeners_is_an_empty_result_not_an_error(self):
        nothing = subprocess.CompletedProcess([], 1, stdout="", stderr="")
        with mock.patch.object(pm.subprocess, "run", return_value=nothing):
            self.assertEqual(pm.run_lsof(), "")
        broken = subprocess.CompletedProcess([], 1, stdout="", stderr="lsof: permission denied")
        with mock.patch.object(pm.subprocess, "run", return_value=broken):
            with self.assertRaises(RuntimeError):
                pm.run_lsof()

    def test_lsof_is_asked_for_full_process_names(self):
        ok = subprocess.CompletedProcess([], 0, stdout=LSOF_TCP, stderr="")
        with mock.patch.object(pm.subprocess, "run", return_value=ok) as run:
            pm.run_lsof()
        self.assertEqual(run.call_args[0][0][:3], ["lsof", "+c", "0"])


class ApprovalTests(unittest.TestCase):
    def test_command_names(self):
        self.assertTrue(pm.commands_match("node", "Node"))
        # A baseline written when lsof printed 9 characters still matches the full name.
        self.assertTrue(pm.commands_match("ControlCe", "ControlCenter"))
        self.assertTrue(pm.commands_match("ControlCenter", "ControlCe"))
        self.assertFalse(pm.commands_match("Control", "ControlCenter"))
        self.assertFalse(pm.commands_match("node", "nodejs"))

    def test_rule_matching(self):
        rules = [{"port": 18789, "protocol": "tcp", "command": "node"}, {"port": 22}, {"port": "junk"}]
        self.assertTrue(pm.is_approved(entry(18789), rules))
        self.assertFalse(pm.is_approved(entry(18789, command="python"), rules))
        self.assertTrue(pm.is_approved(entry(22, command="sshd"), rules))  # no command given: any process
        self.assertFalse(pm.is_approved(entry(22, protocol="udp"), rules))  # protocol defaults to tcp
        self.assertFalse(pm.is_approved(entry(9999), rules))

    def test_unapproved_and_insecure(self):
        findings = pm.build_findings([entry(8080), entry(80, command="httpd")], [{"port": 80}])
        self.assertEqual(kinds(findings), [("insecure-port", 80), ("unapproved-port", 8080)])

    def test_public_bind_needs_explicit_approval(self):
        public = entry(7000, command="ControlCenter", host="*")
        self.assertEqual(kinds(pm.build_findings([public], [{"port": 7000}])), [("public-bind", 7000)])
        self.assertEqual(kinds(pm.build_findings([public], [{"port": 7000, "allow_public": False}])), [("public-bind", 7000)])
        self.assertEqual(pm.build_findings([public], [{"port": 7000, "allow_public": True}]), [])
        self.assertEqual(pm.build_findings([entry(7000)], [{"port": 7000}]), [])  # loopback is not public

    def test_one_finding_per_service_across_address_families(self):
        both = [entry(18789, host="127.0.0.1"), entry(18789, host="::1")]
        self.assertEqual(kinds(pm.build_findings(both, [])), [("unapproved-port", 18789)])

    def test_insecure_port_numbers_apply_to_tcp_only(self):
        self.assertEqual(kinds(pm.build_findings([entry(69, protocol="udp")], [{"port": 69, "protocol": "udp"}])), [])


class BaselineGeneratorTests(unittest.TestCase):
    def test_public_listeners_are_not_approved_for_exposure_by_default(self):
        rules, _ = generate_approved_ports.normalize_listeners(
            [entry(7000, command="ControlCenter", host="*"), entry(18789), entry(18789, host="::1")],
            include_command=True,
        )
        self.assertEqual([r["port"] for r in rules], [7000, 18789])
        self.assertIs(rules[0]["allow_public"], False)
        self.assertNotIn("allow_public", rules[1])
        # The generated baseline approves the ports but still reports the public listener.
        findings = pm.build_findings([entry(7000, command="ControlCenter", host="*"), entry(18789)], rules)
        self.assertEqual(kinds(findings), [("public-bind", 7000)])


if __name__ == "__main__":
    unittest.main()
