#!/usr/bin/env python3
"""Tests for cyber-security-engineer/scripts/egress_monitor.py.

Run from the repository root:

    python3 -m unittest discover -s tests -v

No network access and no real host state is used: command output is supplied
as sample text and DNS is replaced by a fake resolver.
"""
import json
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cyber-security-engineer" / "scripts"))
import egress_monitor as em  # noqa: E402

LSOF_ESTABLISHED = """\
COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node       9905 user   20u  IPv4 0xaaaaaaaaaaaaaaaa      0t0  TCP 192.168.1.5:50000->104.18.7.192:443 (ESTABLISHED)
node       9905 user   21u  IPv4 0xbbbbbbbbbbbbbbbb      0t0  TCP 192.168.1.5:50000->104.18.7.192:443 (ESTABLISHED)
node       9905 user   22u  IPv4 0xcccccccccccccccc      0t0  TCP 127.0.0.1:18789->127.0.0.1:61000 (ESTABLISHED)
Safari      702 user   23u  IPv6 0xdddddddddddddddd      0t0  TCP [fe80:b::1]:57168->[fe80:b::2]:55345 (ESTABLISHED)
curl       9999 user    5u  IPv4 0xeeeeeeeeeeeeeeee      0t0  TCP 10.0.0.2:1234->1.2.3.4:80
"""

LSOF_LISTEN = """\
COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node       9905 user   18u  IPv4 0x1111111111111111      0t0  TCP 127.0.0.1:18789 (LISTEN)
node       9905 user   19u  IPv6 0x2222222222222222      0t0  TCP [::1]:18789 (LISTEN)
ControlCe   729 user   10u  IPv4 0x3333333333333333      0t0  TCP *:7000 (LISTEN)
"""

SS_ESTABLISHED = """\
Recv-Q Send-Q Local Address:Port Peer Address:Port Process
0      0      192.168.0.10:49820 1.2.3.4:443 users:(("node",pid=123,fd=20))
0      0      [::1]:5432 [::1]:40000 users:(("postgres",pid=77,fd=9))
"""

SS_LISTEN = """\
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128    0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3))
LISTEN 0      511    127.0.0.1:18789 0.0.0.0:* users:(("node",pid=123,fd=18))
"""

NETSTAT = """\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       888
  TCP    192.168.1.5:50000      1.2.3.4:443            ESTABLISHED     1234
  TCP    192.168.1.5:50001      5.6.7.8:443            TIME_WAIT       1234
"""

PS = """\
    1     0 /sbin/launchd
 9900     1 openclaw
 9905  9900 openclaw-gateway
 9910  9905 /usr/bin/curl -s https://example.com
 9950     1 node /opt/homebrew/lib/node_modules/openclaw/dist/worker.js
  702     1 /Applications/Safari.app/Contents/MacOS/Safari
 4000     1 /bin/zsh -c cd /repos/OpenClaw-Cyber-Analyst && python3 x.py
 4001  4000 python3 /Users/me/.openclaw/workspace/skills/cyber-security-engineer/scripts/egress_monitor.py
"""

NOW = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)


def conn(command="node", pid=9905, remote_host="104.18.7.192", remote_port=443, local_port=50000):
    return {
        "command": command,
        "pid": pid,
        "user": "user",
        "local_host": "192.168.1.5",
        "local_port": local_port,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "protocol": "tcp",
    }


def rules(*raw):
    return em.compile_rules(list(raw))


class SplitHostPortTests(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(em.split_host_port("1.2.3.4:443"), ("1.2.3.4", 443))
        self.assertEqual(em.split_host_port("[::1]:443"), ("::1", 443))
        self.assertEqual(em.split_host_port("fe80::1%en0:443"), ("fe80::1%en0", 443))
        self.assertEqual(em.split_host_port("*:7000"), ("*", 7000))

    def test_rejects_non_endpoints(self):
        for token in ("", "(ESTABLISHED)", "0", "0.0.0.0:*", "users:((", "[::1]"):
            self.assertEqual(em.split_host_port(token), (None, None), token)


class ParserTests(unittest.TestCase):
    def test_lsof_reads_remote_endpoint_not_tcp_state(self):
        # Regression: the trailing "(ESTABLISHED)" token used to be parsed as the address,
        # so every connection was dropped and the monitor always reported zero.
        conns = em.parse_lsof(LSOF_ESTABLISHED)
        self.assertEqual(
            [(c["command"], c["remote_host"], c["remote_port"]) for c in conns],
            [
                ("node", "104.18.7.192", 443),
                ("node", "127.0.0.1", 61000),
                ("Safari", "fe80:b::2", 55345),
                ("curl", "1.2.3.4", 80),
            ],
        )

    def test_lsof_records_local_port_and_dedupes_shared_sockets(self):
        conns = em.parse_lsof(LSOF_ESTABLISHED)
        self.assertEqual(len([c for c in conns if c["remote_host"] == "104.18.7.192"]), 1)
        self.assertEqual(conns[0]["local_port"], 50000)
        self.assertEqual(conns[0]["pid"], 9905)

    def test_lsof_empty_output(self):
        self.assertEqual(em.parse_lsof(""), [])
        self.assertEqual(em.parse_lsof_listeners(""), set())

    def test_lsof_listeners(self):
        self.assertEqual(em.parse_lsof_listeners(LSOF_LISTEN), {(9905, 18789), (729, 7000)})

    def test_ss(self):
        conns = em.parse_ss(SS_ESTABLISHED)
        self.assertEqual(
            [(c["command"], c["pid"], c["local_port"], c["remote_host"], c["remote_port"]) for c in conns],
            [("node", 123, 49820, "1.2.3.4", 443), ("postgres", 77, 5432, "::1", 40000)],
        )

    def test_ss_with_state_column(self):
        line = 'ESTAB 0 0 192.168.0.10:49820 1.2.3.4:443 users:(("node",pid=123,fd=20))\n'
        conns = em.parse_ss(line)
        self.assertEqual((conns[0]["remote_host"], conns[0]["remote_port"]), ("1.2.3.4", 443))

    def test_ss_listeners(self):
        self.assertEqual(em.parse_ss_listeners(SS_LISTEN), {(900, 22), (123, 18789)})

    def test_netstat_windows(self):
        conns = em.parse_netstat_windows(NETSTAT)
        self.assertEqual(len(conns), 1)
        self.assertEqual((conns[0]["pid"], conns[0]["remote_host"], conns[0]["remote_port"]), (1234, "1.2.3.4", 443))
        self.assertEqual(em.parse_netstat_windows_listeners(NETSTAT), {(888, 135)})

    def test_ps(self):
        table = em.parse_ps(PS)
        self.assertEqual(table[9905], (9900, "openclaw-gateway"))
        self.assertEqual(table[9910][0], 9905)


class ScopeTests(unittest.TestCase):
    def test_openclaw_commands(self):
        for command in (
            "openclaw",
            "openclaw-gateway",
            "/opt/homebrew/bin/openclaw gateway start",
            "node /opt/homebrew/lib/node_modules/openclaw/openclaw.mjs gateway",
            "node --no-warnings /srv/app/openclaw.mjs",
            "C:\\Users\\me\\AppData\\Roaming\\npm\\openclaw.cmd gateway",
        ):
            self.assertTrue(em.is_openclaw_command(command), command)

    def test_paths_that_merely_mention_openclaw_are_not_openclaw(self):
        for command in (
            "/bin/zsh -c cd /repos/OpenClaw-Cyber-Analyst && python3 x.py",
            "python3 /Users/me/.openclaw/workspace/skills/cyber-security-engineer/scripts/egress_monitor.py",
            "python3 -m http.server 3002 --directory /repos/OpenClaw-Cyber-Analyst/assessments",
            "/Applications/Safari.app/Contents/MacOS/Safari",
            "ls OpenClaw-Cyber-Analyst",
            # A folder called "OpenClaw Security Analyst" splits into a bare "OpenClaw" token.
            "python3 /repos/OpenClaw Security Analyst/scripts/egress_monitor.py --json",
            "/usr/bin/python3 /repos/OpenClaw",
            "",
        ):
            self.assertFalse(em.is_openclaw_command(command), command)

    def test_scope_includes_descendants_only(self):
        scoped = em.openclaw_pids(em.parse_ps(PS), set(), 18789)
        self.assertEqual(scoped, {9900, 9905, 9910, 9950})

    def test_gateway_port_listener_is_in_scope_even_if_renamed(self):
        table = {500: (1, "node /srv/custom-launcher.js"), 501: (500, "/usr/bin/curl x"), 600: (1, "Safari")}
        scoped = em.openclaw_pids(table, {(500, 18789), (600, 7000)}, 18789)
        self.assertEqual(scoped, {500, 501})

    def test_include_process_pattern(self):
        table = {700: (1, "my-claw-wrapper --serve"), 701: (700, "worker")}
        self.assertEqual(em.openclaw_pids(table, set(), 18789), set())
        self.assertEqual(em.openclaw_pids(table, set(), 18789, [re.compile("claw-wrapper")]), {700, 701})

    def test_excluded_roots_are_not_matched_by_name_but_stay_in_scope_as_children(self):
        table = {10: (1, "openclaw"), 11: (10, "openclaw-helper"), 20: (1, "openclaw")}
        self.assertEqual(em.openclaw_pids(table, set(), 18789, exclude_roots={11, 20}), {10, 11})

    def test_gateway_port_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "openclaw.json"
            self.assertEqual(em.gateway_port(cfg), em.DEFAULT_GATEWAY_PORT)
            cfg.write_text(json.dumps({"gateway": {"port": 19000}}))
            self.assertEqual(em.gateway_port(cfg), 19000)
            cfg.write_text("{not json")
            self.assertEqual(em.gateway_port(cfg), em.DEFAULT_GATEWAY_PORT)


class DestinationTests(unittest.TestCase):
    def test_local_destinations(self):
        for host in ("127.0.0.1", "::1", "fe80::1", "fe80::1%en0", "169.254.10.1", "224.0.0.251", "0.0.0.0",
                     "::ffff:127.0.0.1", "localhost"):
            self.assertTrue(em.is_local_destination(host), host)

    def test_remote_destinations_include_private_lan(self):
        for host in ("104.18.7.192", "192.168.1.20", "10.0.0.8", "2606:4700::6810:7c0", "api.openai.com"):
            self.assertFalse(em.is_local_destination(host), host)


class RuleTests(unittest.TestCase):
    RESOLVED = {"api.openai.com": {"104.18.7.192", "2606:4700::6810:7c0"}, "api.telegram.org": {"149.154.167.220"}}

    def allowed(self, rule_list, connection, resolved=None):
        return any(r.matches(connection, self.RESOLVED if resolved is None else resolved) for r in rule_list)

    def test_hostname_rule_matches_resolved_address_and_port(self):
        r = rules({"host": "api.openai.com", "port": 443})
        self.assertTrue(self.allowed(r, conn()))
        self.assertTrue(self.allowed(r, conn(remote_host="2606:4700::6810:7c0")))
        self.assertFalse(self.allowed(r, conn(remote_port=80)))
        self.assertFalse(self.allowed(r, conn(remote_host="8.8.8.8")))

    def test_hostname_rule_without_resolution_allows_nothing(self):
        self.assertFalse(self.allowed(rules({"host": "api.openai.com", "port": 443}), conn(), resolved={}))

    def test_hosts_list_ip_literal_and_ports_list(self):
        r = rules({"hosts": ["api.telegram.org", "8.8.8.8"], "ports": [443, 853]})
        self.assertTrue(self.allowed(r, conn(remote_host="149.154.167.220")))
        self.assertTrue(self.allowed(r, conn(remote_host="8.8.8.8", remote_port=853)))
        self.assertFalse(self.allowed(r, conn(remote_host="8.8.4.4")))

    def test_cidr(self):
        r = rules({"cidr": ["149.154.160.0/20", "2001:67c:4e8::/48"], "port": 443})
        self.assertTrue(self.allowed(r, conn(remote_host="149.154.167.220")))
        self.assertTrue(self.allowed(r, conn(remote_host="2001:67c:4e8:f004::9")))
        self.assertFalse(self.allowed(r, conn(remote_host="149.154.176.1")))

    def test_ipv4_mapped_ipv6_matches_ipv4_rule(self):
        self.assertTrue(self.allowed(rules({"host": "8.8.8.8"}), conn(remote_host="::ffff:8.8.8.8")))

    def test_every_destination_constraint_must_hold(self):
        # host AND cidr: an address that satisfies only one of them is not allowed.
        both = rules({"host": "api.openai.com", "cidr": "104.18.0.0/16", "port": 443})
        self.assertTrue(self.allowed(both, conn(remote_host="104.18.7.192")))
        self.assertFalse(self.allowed(both, conn(remote_host="2606:4700::6810:7c0")))  # host only
        self.assertFalse(self.allowed(both, conn(remote_host="104.18.99.1")))  # cidr only
        with_regex = rules({"cidr": "10.0.0.0/8", "host_regex": "^10\\.1\\."})
        self.assertTrue(self.allowed(with_regex, conn(remote_host="10.1.2.3")))
        self.assertFalse(self.allowed(with_regex, conn(remote_host="10.2.2.3")))  # cidr only
        self.assertFalse(self.allowed(with_regex, conn(remote_host="11.1.2.3")))  # neither
        all_three = rules({"host": "api.openai.com", "cidr": "104.18.0.0/16", "host_regex": "openai\\.com$"})
        self.assertTrue(self.allowed(all_three, conn(remote_host="104.18.7.192")))
        self.assertFalse(self.allowed(rules({"host": "8.8.8.8", "cidr": "10.0.0.0/8"}), conn(remote_host="8.8.8.8")))

    def test_command_is_case_insensitive(self):
        r = rules({"host": "api.openai.com", "command": "Node"})
        self.assertTrue(self.allowed(r, conn(command="node")))
        self.assertFalse(self.allowed(r, conn(command="curl")))

    def test_legacy_host_regex_with_literal_hostnames(self):
        # The original template format keeps working: names in the pattern are resolved.
        r = rules({"protocol": "tcp", "host_regex": "^(api\\.openai\\.com|api\\.telegram\\.org)$", "port": 443})
        self.assertEqual(r[0].hostnames, ["api.openai.com", "api.telegram.org"])
        self.assertTrue(self.allowed(r, conn()))
        self.assertTrue(self.allowed(r, conn(remote_host="149.154.167.220")))
        self.assertFalse(self.allowed(r, conn(remote_host="8.8.8.8")))

    def test_host_regex_against_ip(self):
        r = rules({"host_regex": "^10\\.1\\.2\\.\\d+$"})
        self.assertTrue(self.allowed(r, conn(remote_host="10.1.2.9")))
        self.assertFalse(self.allowed(r, conn(remote_host="10.1.3.9")))

    def test_hostname_extraction_never_widens_the_pattern(self):
        pattern = ".*\\.openai\\.com$"
        self.assertEqual(em.hostnames_in_regex(pattern, re.compile(pattern)), [])
        pattern = "^api\\.openai\\.com$"
        self.assertEqual(em.hostnames_in_regex(pattern, re.compile(pattern)), ["api.openai.com"])

    def test_rule_without_host_constraint_allows_any_destination_on_port(self):
        r = rules({"port": 443})
        self.assertTrue(self.allowed(r, conn(remote_host="8.8.8.8")))
        self.assertFalse(self.allowed(r, conn(remote_host="8.8.8.8", remote_port=22)))

    def test_invalid_rules_are_reported_and_allow_nothing(self):
        for raw in ({"host_regex": "("}, {"cidr": "not-a-network"}, {"host_regex": "a" * 201}):
            r = rules(raw)
            self.assertTrue(r[0].errors, raw)
            self.assertFalse(self.allowed(r, conn()), raw)

    def test_protocol_must_match(self):
        self.assertFalse(self.allowed(rules({"protocol": "udp", "host": "api.openai.com"}), conn()))

    def test_load_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "allow.json"
            self.assertEqual(em.load_allowlist(path), [])
            path.write_text(json.dumps([{"host": "a.example"}, "junk", 5]))
            self.assertEqual(em.load_allowlist(path), [{"host": "a.example"}])
            path.write_text(json.dumps({"host": "a.example"}))
            self.assertEqual(em.load_allowlist(path), [])

    def test_shipped_template_is_valid(self):
        template = (
            Path(__file__).resolve().parent.parent
            / "cyber-security-engineer" / "references" / "egress-allowlist.template.json"
        )
        compiled = em.compile_rules(em.load_allowlist(template))
        self.assertTrue(compiled)
        for rule in compiled:
            self.assertEqual(rule.errors, [])
            self.assertTrue(rule.constrains_host)


class ResolutionTests(unittest.TestCase):
    def test_fresh_answers_are_merged_with_remembered_ones(self):
        cache = {"api.openai.com": {"104.18.6.192": "2026-11-20T12:00:00Z"}}
        resolved, failed = em.resolve_hostnames(
            ["api.openai.com"], cache, NOW, resolver=lambda name: {"104.18.7.192"}
        )
        self.assertEqual(resolved["api.openai.com"], {"104.18.6.192", "104.18.7.192"})
        self.assertEqual(failed, [])
        self.assertEqual(cache["api.openai.com"]["104.18.7.192"], "2026-11-21T12:00:00Z")

    def test_failed_lookup_falls_back_to_remembered_answers(self):
        def broken(name):
            raise OSError("no network")

        cache = {"api.openai.com": {"104.18.6.192": "2026-11-20T12:00:00Z"}}
        resolved, failed = em.resolve_hostnames(["api.openai.com", "x.example"], cache, NOW, resolver=broken)
        self.assertEqual(resolved, {"api.openai.com": {"104.18.6.192"}, "x.example": set()})
        self.assertEqual(failed, ["api.openai.com", "x.example"])

    def test_no_resolver_uses_cache_only(self):
        cache = {"api.openai.com": {"104.18.6.192": "2026-11-20T12:00:00Z"}}
        resolved, failed = em.resolve_hostnames(["api.openai.com"], cache, NOW, resolver=None)
        self.assertEqual(resolved, {"api.openai.com": {"104.18.6.192"}})
        self.assertEqual(failed, [])

    def test_cache_round_trip_prunes_old_and_invalid_entries(self):
        old = (NOW - timedelta(days=em.DNS_CACHE_MAX_AGE_DAYS + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "cache.json"
            em.save_dns_cache(
                path,
                {
                    "api.openai.com": {"104.18.7.192": "2026-11-21T11:00:00Z", "104.18.0.1": old, "junk": old},
                    "gone.example": {"1.1.1.1": old},
                },
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                em.load_dns_cache(path, NOW), {"api.openai.com": {"104.18.7.192": "2026-11-21T11:00:00Z"}}
            )

    def test_missing_or_corrupt_cache_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.json"
            self.assertEqual(em.load_dns_cache(path, NOW), {})
            path.write_text("{nope")
            self.assertEqual(em.load_dns_cache(path, NOW), {})


class EvaluateTests(unittest.TestCase):
    RESOLVED = {"api.openai.com": {"104.18.7.192"}}

    def run_eval(self, conns, scoped={9905}, include_local=False, listeners={(9905, 18789)}):
        return em.evaluate(
            conns, listeners, scoped, rules({"host": "api.openai.com", "port": 443, "comment": "Model provider"}),
            self.RESOLVED, include_local=include_local,
        )

    def test_end_to_end_classification(self):
        conns = [
            conn(),                                                  # allowed egress
            conn(remote_host="8.8.8.8"),                             # unapproved egress
            conn(remote_host="127.0.0.1", remote_port=61000, local_port=18789),  # inbound to gateway
            conn(remote_host="127.0.0.1", remote_port=5432),         # local-only
            conn(command="Safari", pid=702, remote_host="9.9.9.9"),  # another application
        ]
        evaluated, findings, summary = self.run_eval(conns)
        self.assertEqual(
            summary,
            {
                "connections_seen": 5, "out_of_scope": 1, "ignored_inbound": 1, "ignored_local": 1,
                "evaluated": 2, "allowed": 1, "unapproved": 1,
            },
        )
        self.assertEqual([c["allowed"] for c in evaluated], [True, False])
        self.assertEqual(evaluated[0]["matched_rule"], "Model provider")
        self.assertEqual(evaluated[0]["remote_names"], ["api.openai.com"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "unapproved-egress")
        self.assertEqual((findings[0]["remote_host"], findings[0]["remote_port"], findings[0]["pid"]), ("8.8.8.8", 443, 9905))

    def test_scope_all_evaluates_every_process(self):
        _, findings, summary = self.run_eval([conn(command="Safari", pid=702, remote_host="9.9.9.9")], scoped=None)
        self.assertEqual(summary["out_of_scope"], 0)
        self.assertEqual(len(findings), 1)

    def test_include_local(self):
        _, findings, summary = self.run_eval([conn(remote_host="127.0.0.1", remote_port=5432)], include_local=True)
        self.assertEqual(summary["ignored_local"], 0)
        self.assertEqual(len(findings), 1)

    def test_nothing_in_scope_evaluates_nothing(self):
        evaluated, findings, summary = self.run_eval([conn()], scoped=set())
        self.assertEqual((evaluated, findings, summary["evaluated"], summary["out_of_scope"]), ([], [], 0, 1))

    def test_no_rules_flags_all_real_egress(self):
        _, findings, _ = em.evaluate([conn()], set(), {9905}, [], {})
        self.assertEqual(len(findings), 1)


class OutputTests(unittest.TestCase):
    def test_text_report(self):
        evaluated, findings, summary = em.evaluate(
            [conn(), conn(remote_host="2001:db8::1")], set(), {9905},
            rules({"host": "api.openai.com", "port": 443, "comment": "Model provider"}),
            {"api.openai.com": {"104.18.7.192"}},
        )
        text = em.render_text(
            {
                "status": "ok", "tool": "lsof", "scope": "openclaw", "allowlist_file": "/x/allow.json",
                "allowlist_rules_count": 1, "summary": summary, "connections": evaluated,
                "findings": findings, "warnings": ["Could not resolve x.example; relying on previously seen addresses."],
            }
        )
        self.assertIn("node (pid 9905) -> 104.18.7.192:443 (api.openai.com): allowed by Model provider", text)
        self.assertIn("node (pid 9905) -> [2001:db8::1]:443: UNAPPROVED", text)
        self.assertIn("unapproved             : 1", text)
        self.assertIn("Warning: Could not resolve x.example", text)

    def test_text_report_for_failed_scan(self):
        self.assertIn("lsof exploded", em.render_text({"status": "error", "error": "lsof exploded"}))


if __name__ == "__main__":
    unittest.main()
