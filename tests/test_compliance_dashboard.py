#!/usr/bin/env python3
"""Tests for cyber-security-engineer/scripts/compliance_dashboard.py.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""
import re
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cyber-security-engineer" / "scripts"))
import compliance_dashboard as cd  # noqa: E402


def control(check_id, status="compliant", risk="medium", **extra):
    base = {
        "check_id": check_id,
        "title": f"Title of {check_id}",
        "iso27001": ["A.5.15"],
        "nist": ["PR.AA-01"],
        "expected_state": "expected",
        "status": status,
        "risk": risk,
        "observed_state": "observed",
        "evidence": f"evidence for {check_id}",
        "gap": f"gap for {check_id}",
        "mitigation": f"mitigation for {check_id}",
        "owner": "Security Engineering",
        "due_date": "2026-12-05",
    }
    base.update(extra)
    return base


def render(merged, **kwargs):
    return cd.render_html("OpenClaw", merged, cd.summarize(merged), **kwargs)


class Rows(HTMLParser):
    """Collects the body rows of each view, as {view: [{"status", "risk", "text"}]}."""

    def __init__(self):
        super().__init__()
        self.views = {}
        self._view = None
        self._in_body = False
        self._row = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "section" and "data-view" in attrs:
            self._view = attrs["data-view"]
            self.views[self._view] = []
        elif tag == "tbody":
            self._in_body = True
        elif tag == "tr" and self._in_body:
            self._row = {"status": attrs.get("data-status"), "risk": attrs.get("data-risk"), "text": ""}

    def handle_endtag(self, tag):
        if tag == "tbody":
            self._in_body = False
        elif tag == "tr" and self._row is not None:
            self.views[self._view].append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._row is not None:
            self._row["text"] += data + " "


def rows_of(page):
    parser = Rows()
    parser.feed(page)
    return parser.views


SAMPLE = [
    control("a_high_ok", "compliant", "high"),
    control("b_high_bad", "violation", "high"),
    control("c_medium_partial", "partial", "medium"),
    control("d_low_ok", "compliant", "low", mitigation=""),
    control("e_unassessed", "not_assessed", "medium"),
]


class RenderTests(unittest.TestCase):
    def test_page_is_self_contained(self):
        page = render(SAMPLE)
        self.assertTrue(page.startswith("<!doctype html>"))
        # No external scripts, styles, fonts or images: the report must open offline.
        self.assertIsNone(re.search(r"""(src|href)=["'](https?:)?//""", page))
        self.assertNotIn("@import", page)

    def test_each_view_lists_the_right_controls(self):
        views = rows_of(render(SAMPLE))
        self.assertEqual(len(views["controls"]), 5)
        self.assertEqual(
            [r["status"] for r in views["findings"]], ["violation", "partial"]
        )
        self.assertEqual(len(views["mitigations"]), 4)  # the control with no mitigation is left out
        self.assertIn("gap for b_high_bad", views["findings"][0]["text"])
        self.assertIn("evidence for b_high_bad", views["findings"][0]["text"])
        self.assertIn("mitigation for a_high_ok", views["mitigations"][0]["text"])

    def test_rows_carry_filter_attributes(self):
        first = rows_of(render(SAMPLE))["controls"][1]
        self.assertEqual((first["status"], first["risk"]), ("violation", "high"))

    def test_counts_and_percentage(self):
        page = render(SAMPLE)
        self.assertIn('<span class="hero-figure">40%</span>', page)
        self.assertIn("2 of 5 controls compliant", page)
        self.assertIn("High risk: 1 of 2 controls compliant", page)
        self.assertIn("Medium risk: 0 of 2 controls compliant", page)
        self.assertIn("Low risk: 1 of 1 controls compliant", page)
        self.assertNotIn("Critical risk:", page)  # no meter for a level with no controls
        for label, count in (("Compliant", 2), ("Partial", 1), ("Violations", 1), ("Not Assessed", 1)):
            self.assertIn(f"{label}<b>{count}</b>", page)

    def test_status_ring_has_one_arc_per_status_present(self):
        page = render(SAMPLE)
        self.assertEqual(len(re.findall(r'<circle class="seg ', page)), 4)
        only_ok = render([control("x"), control("y")])
        self.assertEqual(len(re.findall(r'<circle class="seg ', only_ok)), 1)

    def test_status_is_never_colour_alone(self):
        page = render(SAMPLE)
        for status, label in cd.STATUS_LABELS.items():
            self.assertRegex(page, rf'class="badge st-{status}"><svg[^>]*>.*?</svg>{label}</span>')

    def test_untrusted_text_is_escaped(self):
        hostile = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
        merged = [
            control(hostile, "violation", "high", title=hostile, gap=hostile, evidence=hostile,
                    mitigation=hostile, owner=hostile, due_date=hostile, iso27001=[hostile], nist=[hostile])
        ]
        page = cd.render_html(hostile, merged, cd.summarize(merged), summary_href=hostile)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<img src=x", page)
        self.assertEqual(page.count("<script>"), 1)  # only the page's own script block
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_empty_assessment_renders(self):
        page = render([])
        views = rows_of(page)
        self.assertEqual(views, {"controls": [], "findings": [], "mitigations": []})
        self.assertIn('<span class="hero-figure">0%</span>', page)
        self.assertIn("No violations or partial findings.", page)
        self.assertIn("No mitigation actions recorded.", page)
        self.assertIn('class="donut-empty"', page)

    def test_assets_are_inlined_so_the_page_is_one_file(self):
        page = render(SAMPLE)
        self.assertIn(cd._asset("dashboard.css").strip().splitlines()[-1], page)
        self.assertIn("function showPage()", page)
        self.assertNotIn("dashboard.css", page.replace("/* Styles for the compliance dashboard.", ""))

    def test_tables_are_paginated_past_the_page_size(self):
        page = render(SAMPLE)
        self.assertEqual(cd.PAGE_SIZE, 10)
        self.assertIn("var PAGE_SIZE = 10;", page)
        self.assertNotIn("__PAGE_SIZE__", page)
        for element_id in ("pager", "pager-range", "pager-page", "pager-prev", "pager-next"):
            self.assertEqual(page.count(f'id="{element_id}"'), 1, element_id)
        # Every row is still in the page; the script only decides which are on screen.
        many = [control(f"c{i}") for i in range(25)]
        self.assertEqual(len(rows_of(render(many))["controls"]), 25)

    def test_summary_link_is_optional(self):
        self.assertNotIn("Summary JSON", render(SAMPLE))
        self.assertIn('href="compliance-summary.json"', render(SAMPLE, summary_href="compliance-summary.json"))


class PipelineTests(unittest.TestCase):
    def test_shipped_controls_map_renders_from_a_fresh_assessment(self):
        controls = cd.load_json(cd.default_controls_path())
        assessment = cd.init_assessment(controls, "OpenClaw")
        cd.validate_assessment(assessment)
        merged = cd.merge_controls(controls, assessment)
        page = cd.render_html("OpenClaw", merged, cd.summarize(merged))
        self.assertEqual(len(rows_of(page)["controls"]), len(controls))
        self.assertIn(f"Not Assessed<b>{len(controls)}</b>", page)


if __name__ == "__main__":
    unittest.main()
