#!/usr/bin/env python3
import argparse
import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


VALID_STATUS = {"compliant", "partial", "violation", "not_assessed"}
VALID_RISK = {"low", "medium", "high", "critical"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def default_controls_path() -> Path:
    return Path(__file__).resolve().parent.parent / "references" / "compliance-controls-map.json"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def init_assessment(controls: List[Dict[str, object]], system_name: str) -> Dict[str, object]:
    checks = []
    for ctrl in controls:
        checks.append(
            {
                "check_id": ctrl["check_id"],
                "status": "not_assessed",
                "risk": ctrl.get("default_risk", "medium"),
                "observed_state": "",
                "evidence": "",
                "gap": "",
                "mitigation": "",
                "owner": "",
                "due_date": "",
            }
        )
    return {
        "metadata": {
            "system": system_name,
            "generated_at_utc": utc_now(),
            "frameworks": ["ISO/IEC 27001:2022", "NIST CSF"],
        },
        "checks": checks,
    }


def validate_assessment(assessment: Dict[str, object]) -> None:
    checks = assessment.get("checks", [])
    if not isinstance(checks, list):
        raise ValueError("Assessment must include 'checks' list.")
    for c in checks:
        status = c.get("status", "")
        risk = c.get("risk", "")
        if status not in VALID_STATUS:
            raise ValueError(f"Invalid status '{status}' for check {c.get('check_id')}")
        if risk not in VALID_RISK:
            raise ValueError(f"Invalid risk '{risk}' for check {c.get('check_id')}")


def merge_controls(controls: List[Dict[str, object]], assessment: Dict[str, object]) -> List[Dict[str, object]]:
    by_id = {c["check_id"]: c for c in assessment.get("checks", [])}
    merged = []
    for ctrl in controls:
        check = by_id.get(ctrl["check_id"], {})
        merged.append(
            {
                "check_id": ctrl["check_id"],
                "title": ctrl["title"],
                "iso27001": ctrl.get("iso27001", []),
                "nist": ctrl.get("nist", []),
                "expected_state": ctrl.get("expected_state", ""),
                "status": check.get("status", "not_assessed"),
                "risk": check.get("risk", ctrl.get("default_risk", "medium")),
                "observed_state": check.get("observed_state", ""),
                "evidence": check.get("evidence", ""),
                "gap": check.get("gap", ""),
                "mitigation": check.get("mitigation", ""),
                "owner": check.get("owner", ""),
                "due_date": check.get("due_date", ""),
            }
        )
    return merged


def summarize(merged: List[Dict[str, object]]) -> Dict[str, object]:
    status_counts = Counter(item["status"] for item in merged)
    risk_counts = Counter(item["risk"] for item in merged)
    violations = [m for m in merged if m["status"] in ("violation", "partial")]
    mitigations = [m for m in merged if m["mitigation"]]
    return {
        "status_counts": dict(status_counts),
        "risk_counts": dict(risk_counts),
        "violations": violations,
        "mitigations": mitigations,
    }


STATUS_ORDER = ["compliant", "partial", "violation", "not_assessed"]
STATUS_LABELS = {
    "compliant": "Compliant",
    "partial": "Partial",
    "violation": "Violation",
    "not_assessed": "Not assessed",
}
# Plural forms used where the dashboard counts controls per status.
STATUS_COUNT_LABELS = {
    "compliant": "Compliant",
    "partial": "Partial",
    "violation": "Violations",
    "not_assessed": "Not Assessed",
}
RISK_ORDER = ["critical", "high", "medium", "low"]
RISK_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# Rows shown per page in each table; a table with more rows than this is paginated.
PAGE_SIZE = 10

# 16px stroke icons (viewBox 0 0 16 16). Inline so the page needs no network access.
ICONS = {
    "overview": '<rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/>'
    '<rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/>',
    "controls": '<path d="M8 1.8 13 3.6v4c0 3-2 5.4-5 6.6-3-1.2-5-3.600-5-6.600v-4z"/><path d="m5.800 8 1.600 1.600 2.900-3"/>',
    "findings": '<path d="M8 2.200 14.200 13H1.800z"/><path d="M8 6.500v3"/><path d="M8 11.300v.2"/>',
    "mitigations": '<path d="M5.500 4h8"/><path d="M5.500 8h8"/><path d="M5.500 12h8"/>'
    '<path d="m2 4 .8.800L4 3.500"/><path d="m2 8 .8.800L4 7.500"/><path d="m2 12 .8.800L4 11.500"/>',
    "file": '<path d="M4 1.800h5l3 3v9.400H4z"/><path d="M9 1.800v3h3"/>',
    "search": '<circle cx="7" cy="7" r="4.200"/><path d="m10.200 10.200 3.300 3.300"/>',
    "export": '<path d="M8 10.500V2.500"/><path d="m5 5.300 3-3 3 3"/><path d="M2.500 10.500v3h11v-3"/>',
    "compliant": '<circle cx="8" cy="8" r="6"/><path d="m5.400 8.200 1.800 1.800 3.400-3.700"/>',
    "partial": '<path d="M8 2.200 14.200 13H1.800z"/><path d="M8 6.500v3"/><path d="M8 11.300v.2"/>',
    "violation": '<circle cx="8" cy="8" r="6"/><path d="m5.800 5.800 4.400 4.400"/><path d="m10.200 5.800-4.400 4.400"/>',
    "not_assessed": '<circle cx="8" cy="8" r="6"/><path d="M5.500 8h5"/>',
}

DASHBOARD_CSS = """
:root {
  color-scheme: light;
  --page: #f7f7f5; --surface: #ffffff; --raised: #fafaf9;
  --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --line: #e6e5e0; --line-strong: #d3d2cb; --hover: #efeeea; --active: #e8e7e2;
  --good: #0ca30c; --warning: #fab219; --critical: #d03b3b; --neutral: #898781;
  --good-track: #d7efd7;
  --good-bg: #e8f6e8; --good-line: #b5dfb5; --good-ink: #0a5a0a;
  --warning-bg: #fff3d4; --warning-line: #f3d48a; --warning-ink: #6f4500;
  --critical-bg: #fdeaea; --critical-line: #f1b8b8; --critical-ink: #971c1c;
  --neutral-bg: #f1f0ec; --neutral-line: #dcdbd4; --neutral-ink: #52514e;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --raised: #1f1f1e;
    --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
    --line: #2c2c2a; --line-strong: #383835; --hover: #242423; --active: #2c2c2a;
    --good-track: #17361a;
    --good-bg: #12301a; --good-line: #1f5a2a; --good-ink: #8fdc8f;
    --warning-bg: #3a2c08; --warning-line: #6b520f; --warning-ink: #fbd06b;
    --critical-bg: #3b1616; --critical-line: #6d2626; --critical-ink: #f3a3a3;
    --neutral-bg: #262625; --neutral-line: #383835; --neutral-ink: #c3c2b7;
  }
}
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0; background: var(--surface); color: var(--ink);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
}
svg.ico { width: 16px; height: 16px; flex: none; fill: none; stroke: currentColor;
  stroke-width: 1.4; stroke-linecap: round; stroke-linejoin: round; }
.app { display: grid; grid-template-columns: 248px minmax(0, 1fr); min-height: 100%; }

/* Sidebar */
.side { background: var(--page); border-right: 1px solid var(--line); display: flex; flex-direction: column;
  position: sticky; top: 0; height: 100vh; }
.brand { display: flex; align-items: center; gap: 10px; height: 54px; padding: 0 16px;
  border-bottom: 1px solid var(--line); font-weight: 600; font-size: 15px; }
.brand-mark { width: 24px; height: 24px; border-radius: 50%; background: var(--ink); color: var(--surface);
  display: grid; place-items: center; font-size: 12px; font-weight: 700; }
.side nav { padding: 8px 10px; flex: 1; overflow: auto; }
.nav-group { margin: 14px 8px 6px; color: var(--muted); font-size: 13px; }
.nav { display: flex; align-items: center; gap: 10px; width: 100%; padding: 7px 8px; border: 0; border-radius: 8px;
  background: none; color: var(--ink); font: inherit; font-weight: 500; text-decoration: none; cursor: pointer;
  text-align: left; }
.nav:hover { background: var(--hover); }
.nav.is-active { background: var(--active); }
.nav .count { margin-left: auto; color: var(--muted); font-weight: 400; font-variant-numeric: tabular-nums; }

/* Main */
main { min-width: 0; }
.top { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 54px;
  padding: 8px 20px; border-bottom: 1px solid var(--line); }
.top h1 { margin: 0; font-size: 15px; font-weight: 600; }
.top .stamp { color: var(--ink-2); font-size: 13px; white-space: nowrap; }
.content { padding: 16px 20px 32px; display: grid; grid-template-columns: minmax(0, 1fr); gap: 16px; }
.cards { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 16px; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; }
.card-pad { padding: 18px 20px 20px; }
.card h2 { margin: 0; font-size: 15px; font-weight: 500; }
.card h2.quiet { color: var(--ink-2); font-size: 14px; font-weight: 400; }

/* Compliance by risk level */
.hero { display: flex; align-items: baseline; gap: 12px; margin: 14px 0 20px; flex-wrap: wrap; }
.hero-figure { font-size: 48px; line-height: 1; font-weight: 600; letter-spacing: -0.02em; }
.hero-label { color: var(--ink-2); }
.meters { display: grid; gap: 14px; margin: 0; padding: 0; list-style: none; }
.meter { display: grid; grid-template-columns: 110px minmax(0, 1fr) 150px; align-items: center; gap: 14px;
  border-radius: 6px; outline-offset: 4px; }
.meter-track { height: 8px; border-radius: 999px; background: var(--good-track); overflow: hidden; }
.meter-fill { height: 100%; border-radius: 999px; background: var(--good); }
.meter-figure { color: var(--ink-2); text-align: right; font-variant-numeric: tabular-nums; }
.meter-figure b { color: var(--ink); font-weight: 600; }
.meter:hover .meter-fill, .meter:focus-visible .meter-fill { filter: brightness(1.12); }

/* Status donut */
.donut-wrap { display: grid; justify-items: center; gap: 16px; padding-top: 10px; }
.donut { position: relative; width: 168px; height: 168px; }
.donut svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.donut circle { fill: none; stroke-width: 9; transition: stroke-width .12s ease; outline: none; }
.donut circle.seg { cursor: default; }
.donut circle.seg:hover, .donut circle.seg:focus-visible { stroke-width: 12; }
.seg-compliant { stroke: var(--good); } .seg-partial { stroke: var(--warning); }
.seg-violation { stroke: var(--critical); } .seg-not_assessed { stroke: var(--neutral); }
.donut-empty { stroke: var(--line); }
.donut-center { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; pointer-events: none; }
.donut-total { font-size: 30px; font-weight: 600; line-height: 1.1; }
.donut-caption { color: var(--ink-2); font-size: 13px; }
.legend { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 18px; margin: 0; padding: 0; list-style: none; width: 100%; }
.legend li { display: flex; align-items: center; gap: 8px; color: var(--ink-2); }
.legend b { margin-left: auto; color: var(--ink); font-weight: 600; font-variant-numeric: tabular-nums; }
.swatch { width: 9px; height: 9px; border-radius: 2px; flex: none; }
.sw-compliant { background: var(--good); } .sw-partial { background: var(--warning); }
.sw-violation { background: var(--critical); } .sw-not_assessed { background: var(--neutral); }

/* Table card */
.tabs { display: inline-flex; gap: 2px; margin: 12px 12px 0; padding: 3px; border-radius: 9px; background: var(--page); }
.tab { border: 0; background: none; color: var(--muted); font: inherit; padding: 5px 12px; border-radius: 7px; cursor: pointer; }
.tab[aria-selected="true"] { background: var(--surface); color: var(--ink); box-shadow: 0 0 0 1px var(--line); }
.tab .count { margin-left: 6px; font-variant-numeric: tabular-nums; }
.toolbar { display: flex; align-items: center; gap: 10px; padding: 12px; flex-wrap: wrap; }
.toolbar .spacer { flex: 1; }
.control { height: 34px; border: 1px solid var(--line-strong); border-radius: 8px; background: var(--surface);
  color: var(--ink); font: inherit; font-weight: 500; padding: 0 10px; }
select.control { padding-right: 6px; cursor: pointer; }
.search { display: flex; align-items: center; gap: 8px; height: 34px; padding: 0 10px; border-radius: 8px;
  background: var(--page); color: var(--muted); min-width: 220px; }
.search input { border: 0; outline: 0; background: none; color: var(--ink); font: inherit; width: 100%; }
.search:focus-within { box-shadow: 0 0 0 2px var(--line-strong); }
button.control { display: inline-flex; align-items: center; gap: 8px; background: var(--page); border-color: transparent; cursor: pointer; }
button.control:hover { background: var(--hover); }
.table-scroll { overflow-x: auto; border-top: 1px solid var(--line); }
#records { overflow: hidden; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 11px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }
thead th { background: var(--raised); color: var(--ink-2); font-size: 13px; font-weight: 400; white-space: nowrap; }
tbody tr.alt { background: var(--raised); }
tbody tr.last td { border-bottom: 0; }
td.num, th.num { width: 44px; color: var(--ink-2); font-variant-numeric: tabular-nums; border-right: 1px solid var(--line); }
.control-title { font-weight: 500; }
.control-id { color: var(--muted); font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
.chips { display: flex; gap: 4px; }
.chip { border: 1px solid var(--line); border-radius: 5px; padding: 1px 6px; color: var(--ink-2); background: var(--surface);
  font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: nowrap; }
.badge { display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px 2px 6px; border-radius: 6px; border: 1px solid;
  font-size: 13px; font-weight: 500; white-space: nowrap; }
.badge svg.ico { width: 13px; height: 13px; stroke-width: 1.7; }
.st-compliant { background: var(--good-bg); border-color: var(--good-line); color: var(--good-ink); }
.st-partial { background: var(--warning-bg); border-color: var(--warning-line); color: var(--warning-ink); }
.st-violation { background: var(--critical-bg); border-color: var(--critical-line); color: var(--critical-ink); }
.st-not_assessed { background: var(--neutral-bg); border-color: var(--neutral-line); color: var(--neutral-ink); }
.risk { display: inline-flex; align-items: center; gap: 8px; white-space: nowrap; }
.bars { display: inline-flex; align-items: flex-end; gap: 2px; height: 12px; }
.bars i { width: 3px; border-radius: 1px; background: var(--line-strong); }
.bars i:nth-child(1) { height: 4px; } .bars i:nth-child(2) { height: 7px; }
.bars i:nth-child(3) { height: 10px; } .bars i:nth-child(4) { height: 12px; }
.bars i.on { background: var(--ink); }
td.wrap { min-width: 220px; color: var(--ink-2); }
td.nowrap { white-space: nowrap; }
.pager { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-top: 1px solid var(--line);
  color: var(--ink-2); font-size: 13px; font-variant-numeric: tabular-nums; }
.pager .spacer { flex: 1; }
.pager button.control { height: 30px; }
.pager button.control:disabled { color: var(--muted); cursor: default; background: none; }
.empty { padding: 28px 16px; text-align: center; color: var(--ink-2); border-top: 1px solid var(--line); }
[hidden] { display: none !important; }
.tip { position: fixed; z-index: 10; pointer-events: none; background: var(--ink); color: var(--surface);
  padding: 5px 9px; border-radius: 6px; font-size: 12.5px; white-space: nowrap; }
:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }

@media (max-width: 1080px) { .cards { grid-template-columns: 1fr; } }
@media (max-width: 860px) {
  .app { grid-template-columns: 1fr; }
  .side { position: static; height: auto; border-right: 0; border-bottom: 1px solid var(--line); }
  .side nav { display: flex; flex-wrap: wrap; gap: 2px; padding: 8px 10px; }
  .nav { width: auto; } .nav-group { display: none; }
  .meter { grid-template-columns: 90px minmax(0, 1fr); } .meter-figure { grid-column: 1 / -1; text-align: left; }
  .top { flex-wrap: wrap; } .search { flex: 1; min-width: 160px; }
}
@media print {
  .side, .toolbar, .tabs, .pager { display: none; } .app { display: block; }
  section[data-view] { display: block !important; break-inside: avoid; }
}
"""

DASHBOARD_JS = """
(function () {
  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"]'));
  var views = Array.prototype.slice.call(document.querySelectorAll('[data-view]'));
  var navs = Array.prototype.slice.call(document.querySelectorAll('.nav[data-target]'));
  var status = document.getElementById('filter-status');
  var risk = document.getElementById('filter-risk');
  var query = document.getElementById('filter-query');
  var empty = document.getElementById('empty');
  var pager = document.getElementById('pager');
  var pagerRange = document.getElementById('pager-range');
  var pagerPage = document.getElementById('pager-page');
  var prev = document.getElementById('pager-prev');
  var next = document.getElementById('pager-next');
  var PAGE_SIZE = __PAGE_SIZE__;
  var current = 'controls';
  var page = 1;
  var matched = [];

  function activeView() {
    return views.filter(function (v) { return v.getAttribute('data-view') === current; })[0];
  }

  function applyFilters() {
    var view = activeView();
    var rows = Array.prototype.slice.call(view.querySelectorAll('tbody tr'));
    var s = status.value, r = risk.value, q = query.value.trim().toLowerCase();
    matched = rows.filter(function (row) {
      return (!s || row.getAttribute('data-status') === s) &&
             (!r || row.getAttribute('data-risk') === r) &&
             (!q || row.textContent.toLowerCase().indexOf(q) !== -1);
    });
    rows.forEach(function (row) { row.hidden = true; });
    view.querySelector('.table-scroll').hidden = matched.length === 0;
    empty.hidden = matched.length !== 0;
    empty.textContent = rows.length === 0 ? view.getAttribute('data-empty') : 'No controls match these filters.';
    page = 1;
    showPage();
  }

  function showPage() {
    var pages = Math.max(1, Math.ceil(matched.length / PAGE_SIZE));
    page = Math.min(Math.max(1, page), pages);
    var first = (page - 1) * PAGE_SIZE, last = Math.min(first + PAGE_SIZE, matched.length);
    matched.forEach(function (row, i) {
      var on = i >= first && i < last;
      row.hidden = !on;
      row.classList.toggle('alt', on && (i - first) % 2 === 1);
      row.classList.toggle('last', on && i === last - 1 && pages === 1);
    });
    // The pager appears only when the rows do not fit on one page.
    pager.hidden = pages === 1;
    pagerRange.textContent = 'Showing ' + (first + 1) + '-' + last + ' of ' + matched.length;
    pagerPage.textContent = 'Page ' + page + ' of ' + pages;
    prev.disabled = page === 1;
    next.disabled = page === pages;
  }

  function turnPage(step) {
    page += step;
    showPage();
    var card = document.getElementById('records');
    if (card.getBoundingClientRect().top < 0) { card.scrollIntoView({ block: 'start' }); }
  }
  prev.addEventListener('click', function () { turnPage(-1); });
  next.addEventListener('click', function () { turnPage(1); });

  function markNav(target) {
    navs.forEach(function (n) { n.classList.toggle('is-active', n.getAttribute('data-target') === target); });
  }

  function showView(name) {
    current = name;
    tabs.forEach(function (t) {
      var on = t.getAttribute('data-tab') === name;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
    });
    views.forEach(function (v) { v.hidden = v.getAttribute('data-view') !== name; });
    applyFilters();
  }

  tabs.forEach(function (t, i) {
    t.addEventListener('click', function () { showView(t.getAttribute('data-tab')); markNav(t.getAttribute('data-tab')); });
    t.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') { return; }
      var next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      next.focus(); next.click();
    });
  });

  navs.forEach(function (n) {
    n.addEventListener('click', function () {
      var target = n.getAttribute('data-target');
      markNav(target);
      if (target === 'overview') {
        document.getElementById('overview').scrollIntoView({ block: 'start' });
        window.scrollTo(0, 0);
        return;
      }
      showView(target);
      document.getElementById('records').scrollIntoView({ block: 'start' });
    });
  });

  [status, risk].forEach(function (el) { el.addEventListener('change', applyFilters); });
  query.addEventListener('input', applyFilters);

  function cellText(cell) { return cell.textContent.replace(/\\s+/g, ' ').trim(); }
  function csvField(text) {
    // Neutralise spreadsheet formulas before quoting.
    if (/^[=+\\-@]/.test(text)) { text = "'" + text; }
    return '"' + text.replace(/"/g, '""') + '"';
  }
  document.getElementById('export').addEventListener('click', function () {
    var view = activeView();
    var lines = [];
    [view.querySelector('thead tr')].concat(matched).forEach(function (row) {
      lines.push(Array.prototype.slice.call(row.children).map(function (c) { return csvField(cellText(c)); }).join(','));
    });
    var blob = new Blob([lines.join('\\r\\n') + '\\r\\n'], { type: 'text/csv;charset=utf-8' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'compliance-' + current + '.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(link.href); }, 1000);
  });

  // One shared tooltip for chart marks; the same text is shown on keyboard focus.
  var tip = document.createElement('div');
  tip.className = 'tip';
  tip.hidden = true;
  document.body.appendChild(tip);
  function place(x, y) {
    tip.style.left = Math.max(8, Math.min(x + 12, window.innerWidth - tip.offsetWidth - 8)) + 'px';
    tip.style.top = Math.max(8, y - tip.offsetHeight - 10) + 'px';
  }
  Array.prototype.slice.call(document.querySelectorAll('[data-tip]')).forEach(function (el) {
    function open(x, y) { tip.textContent = el.getAttribute('data-tip'); tip.hidden = false; place(x, y); }
    el.addEventListener('pointermove', function (e) { open(e.clientX, e.clientY); });
    el.addEventListener('pointerleave', function () { tip.hidden = true; });
    el.addEventListener('focus', function () {
      var box = el.getBoundingClientRect();
      open(box.left + box.width / 2, box.top);
    });
    el.addEventListener('blur', function () { tip.hidden = true; });
  });

  showView(current);
})();
"""


def render_html(
    system_name: str,
    merged: List[Dict[str, object]],
    summary: Dict[str, object],
    summary_href: Optional[str] = None,
) -> str:
    """Render the dashboard as one self-contained HTML page (no external assets).

    ``summary_href`` is a relative link to the JSON summary, shown in the sidebar
    when the summary is written next to the page.
    """

    def esc(val: object) -> str:
        return html.escape(str(val), quote=True)

    def icon(name: str) -> str:
        return f'<svg class="ico" viewBox="0 0 16 16" aria-hidden="true">{ICONS[name]}</svg>'

    def chips(items: List[str]) -> str:
        if not items:
            return "-"
        return '<div class="chips">' + "".join(f'<span class="chip">{esc(i)}</span>' for i in items) + "</div>"

    def status_badge(status: str) -> str:
        label = STATUS_LABELS.get(status, status)
        return f'<span class="badge st-{esc(status)}">{icon(status)}{esc(label)}</span>'

    def risk_mark(risk: str) -> str:
        level = RISK_LEVELS.get(risk, 0)
        bars = "".join(f'<i class="{"on" if n <= level else ""}"></i>' for n in range(1, 5))
        return f'<span class="risk"><span class="bars" aria-hidden="true">{bars}</span>{esc(risk.capitalize())}</span>'

    def control_cell(m: Dict[str, object]) -> str:
        return (
            f'<td><div class="control-title">{esc(m["title"])}</div>'
            f'<div class="control-id">{esc(m["check_id"])}</div></td>'
        )

    def row_attrs(m: Dict[str, object]) -> str:
        return f'data-status="{esc(m["status"])}" data-risk="{esc(m["risk"])}"'

    def table(view: str, label: str, empty_text: str, head: List[str], rows: List[str], hidden: bool) -> str:
        cells = "".join(f'<th class="num">{h}</th>' if h == "#" else f"<th>{h}</th>" for h in head)
        return (
            f'<section data-view="{view}" data-empty="{esc(empty_text)}" role="tabpanel" aria-label="{esc(label)}"'
            f'{" hidden" if hidden else ""}>\n'
            f'<div class="table-scroll"><table><thead><tr>{cells}</tr></thead>\n<tbody>\n'
            + "\n".join(rows)
            + "\n</tbody></table></div></section>"
        )

    violations: List[Dict[str, object]] = summary["violations"]  # type: ignore[assignment]
    mitigations: List[Dict[str, object]] = summary["mitigations"]  # type: ignore[assignment]
    status_counts: Dict[str, int] = summary["status_counts"]  # type: ignore[assignment]
    total = len(merged)
    compliant = status_counts.get("compliant", 0)
    percent = round(100 * compliant / total) if total else 0

    control_rows = [
        f'<tr {row_attrs(m)}><td class="num">{i}</td>{control_cell(m)}<td>{chips(m["iso27001"])}</td>'
        f'<td>{chips(m["nist"])}</td><td>{risk_mark(str(m["risk"]))}</td><td>{status_badge(str(m["status"]))}</td>'
        f'<td class="nowrap">{esc(m["owner"] or "-")}</td><td class="nowrap">{esc(m["due_date"] or "-")}</td></tr>'
        for i, m in enumerate(merged, 1)
    ]
    finding_rows = [
        f'<tr {row_attrs(m)}><td class="num">{i}</td>{control_cell(m)}<td>{status_badge(str(m["status"]))}</td>'
        f'<td>{risk_mark(str(m["risk"]))}</td><td class="wrap">{esc(m["gap"] or "-")}</td>'
        f'<td class="wrap">{esc(m["evidence"] or "-")}</td></tr>'
        for i, m in enumerate(violations, 1)
    ]
    mitigation_rows = [
        f'<tr {row_attrs(m)}><td class="num">{i}</td>{control_cell(m)}<td class="wrap">{esc(m["mitigation"])}</td>'
        f'<td class="nowrap">{esc(m["owner"] or "-")}</td><td class="nowrap">{esc(m["due_date"] or "-")}</td></tr>'
        for i, m in enumerate(mitigations, 1)
    ]

    # Compliance by risk level: one meter per level that has controls.
    meters = []
    for risk in RISK_ORDER:
        in_level = [m for m in merged if m["risk"] == risk]
        if not in_level:
            continue
        ok = sum(1 for m in in_level if m["status"] == "compliant")
        width = 100 * ok / len(in_level)
        tip = f"{risk.capitalize()} risk: {ok} of {len(in_level)} controls compliant"
        meters.append(
            f'<li class="meter" tabindex="0" data-tip="{esc(tip)}" aria-label="{esc(tip)}">{risk_mark(risk)}'
            f'<div class="meter-track"><div class="meter-fill" style="width:{width:.1f}%"></div></div>'
            f'<div class="meter-figure"><b>{ok}</b> of {len(in_level)} compliant</div></li>'
        )

    # Status ring: one arc per status, separated by a small gap in the surface colour.
    radius, circumference = 50.0, 2 * 3.141592653589793 * 50.0
    present = [(s, status_counts.get(s, 0)) for s in STATUS_ORDER if status_counts.get(s, 0)]
    gap = 1.6 if len(present) > 1 else 0.0
    arcs, offset = [], 0.0
    for status, count in present:
        length = circumference * count / total
        tip = f"{STATUS_COUNT_LABELS[status]}: {count} of {total} controls"
        arcs.append(
            f'<circle class="seg seg-{status}" cx="60" cy="60" r="{radius:g}" tabindex="0" data-tip="{esc(tip)}"'
            f' aria-label="{esc(tip)}" stroke-dasharray="{max(length - gap, 0.5):.2f} {circumference:.2f}"'
            f' stroke-dashoffset="{-(offset + gap / 2):.2f}"/>'
        )
        offset += length
    if not arcs:
        arcs.append(f'<circle class="donut-empty" cx="60" cy="60" r="{radius:g}"/>')
    legend = "".join(
        f'<li><span class="swatch sw-{s}"></span>{STATUS_COUNT_LABELS[s]}<b>{status_counts.get(s, 0)}</b></li>'
        for s in STATUS_ORDER
    )

    generated = datetime.now(timezone.utc)
    stamp = generated.strftime("%d %b %Y, %H:%M UTC").lstrip("0")
    status_options = "".join(f'<option value="{s}">{STATUS_LABELS[s]}</option>' for s in STATUS_ORDER)
    risk_options = "".join(f'<option value="{r}">{r.capitalize()}</option>' for r in RISK_ORDER)
    summary_link = (
        f'<div class="nav-group">Data</div>\n'
        f'      <a class="nav" href="{esc(summary_href)}">{icon("file")}Summary JSON</a>'
        if summary_href
        else ""
    )
    brand_mark = esc((system_name.strip() or "?")[0].upper())

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Compliance Dashboard - {esc(system_name)}</title>
  <style>{DASHBOARD_CSS}</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand"><span class="brand-mark" aria-hidden="true">{brand_mark}</span>{esc(system_name)}</div>
    <nav aria-label="Dashboard">
      <div class="nav-group">Compliance</div>
      <button class="nav is-active" type="button" data-target="overview">{icon("overview")}Overview</button>
      <button class="nav" type="button" data-target="controls">{icon("controls")}Controls<span class="count">{total}</span></button>
      <button class="nav" type="button" data-target="findings">{icon("findings")}Findings<span class="count">{len(violations)}</span></button>
      <button class="nav" type="button" data-target="mitigations">{icon("mitigations")}Mitigations<span class="count">{len(mitigations)}</span></button>
      {summary_link}
    </nav>
  </aside>

  <main>
    <header class="top">
      <h1>ISO 27001 / NIST Compliance Dashboard</h1>
      <span class="stamp">Generated <time datetime="{generated.isoformat().replace("+00:00", "Z")}">{stamp}</time></span>
    </header>

    <div class="content">
      <div class="cards" id="overview">
        <section class="card card-pad" aria-labelledby="risk-title">
          <h2 id="risk-title">Compliance by risk level</h2>
          <div class="hero">
            <span class="hero-figure">{percent}%</span>
            <span class="hero-label">{compliant} of {total} controls compliant</span>
          </div>
          <ul class="meters">
            {"".join(meters)}
          </ul>
        </section>

        <section class="card card-pad" aria-labelledby="status-title">
          <h2 id="status-title" class="quiet">Status</h2>
          <div class="donut-wrap">
            <div class="donut">
              <svg viewBox="0 0 120 120" role="img" aria-label="Controls by status">{"".join(arcs)}</svg>
              <div class="donut-center"><div class="donut-total">{total}</div><div class="donut-caption">Controls</div></div>
            </div>
            <ul class="legend">{legend}</ul>
          </div>
        </section>
      </div>

      <div class="card" id="records">
        <div class="tabs" role="tablist" aria-label="Views">
          <button class="tab" type="button" role="tab" data-tab="controls" aria-selected="true">Controls<span class="count">{total}</span></button>
          <button class="tab" type="button" role="tab" data-tab="findings" aria-selected="false" tabindex="-1">Findings<span class="count">{len(violations)}</span></button>
          <button class="tab" type="button" role="tab" data-tab="mitigations" aria-selected="false" tabindex="-1">Mitigations<span class="count">{len(mitigations)}</span></button>
        </div>
        <div class="toolbar">
          <select class="control" id="filter-status" aria-label="Status"><option value="">All statuses</option>{status_options}</select>
          <select class="control" id="filter-risk" aria-label="Risk"><option value="">All risk levels</option>{risk_options}</select>
          <span class="spacer"></span>
          <label class="search">{icon("search")}<input id="filter-query" type="search" placeholder="Search" aria-label="Search" /></label>
          <button class="control" id="export" type="button">{icon("export")}Export</button>
        </div>
        {table("controls", "Controls", "No controls defined.",
               ["#", "Control", "ISO 27001", "NIST", "Risk", "Status", "Owner", "Due Date"], control_rows, False)}
        {table("findings", "Findings", "No violations or partial findings.",
               ["#", "Control", "Status", "Risk", "Gap", "Evidence"], finding_rows, True)}
        {table("mitigations", "Mitigations", "No mitigation actions recorded.",
               ["#", "Control", "Mitigation", "Owner", "Due Date"], mitigation_rows, True)}
        <div class="empty" id="empty" hidden></div>
        <div class="pager" id="pager" hidden>
          <span id="pager-range"></span>
          <span class="spacer"></span>
          <span id="pager-page"></span>
          <button class="control" id="pager-prev" type="button">Previous</button>
          <button class="control" id="pager-next" type="button">Next</button>
        </div>
      </div>
    </div>
  </main>
</div>
<script>{DASHBOARD_JS.replace("__PAGE_SIZE__", str(PAGE_SIZE))}</script>
</body>
</html>
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ISO 27001/NIST dashboard scaffold for OpenClaw")
    parser.add_argument(
        "--controls-file",
        default=str(default_controls_path()),
        help="Controls map JSON file",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init-assessment", help="Create scaffold assessment JSON")
    init_cmd.add_argument("--system", default="OpenClaw", help="System name")
    init_cmd.add_argument(
        "--output",
        default="cyber-security-engineer/assessments/openclaw-assessment.json",
        help="Output path for assessment scaffold",
    )

    render_cmd = sub.add_parser("render", help="Render dashboard from controls+assessment")
    render_cmd.add_argument(
        "--assessment-file",
        default="cyber-security-engineer/assessments/openclaw-assessment.json",
        help="Assessment input JSON path",
    )
    render_cmd.add_argument(
        "--output-html",
        default="cyber-security-engineer/assessments/compliance-dashboard.html",
        help="Output HTML dashboard path",
    )
    render_cmd.add_argument(
        "--output-summary",
        default="cyber-security-engineer/assessments/compliance-summary.json",
        help="Output summary JSON path",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    controls = load_json(Path(args.controls_file).expanduser())
    if not isinstance(controls, list):
        raise ValueError("Controls file must be a JSON array.")

    if args.command == "init-assessment":
        scaffold = init_assessment(controls, args.system)
        out = Path(args.output)
        write_json(out, scaffold)
        print(json.dumps({"status": "ok", "created": str(out), "checks": len(scaffold["checks"])}))
        return 0

    if args.command == "render":
        assessment_path = Path(args.assessment_file)
        assessment = load_json(assessment_path)
        validate_assessment(assessment)

        merged = merge_controls(controls, assessment)
        summary = summarize(merged)
        system_name = assessment.get("metadata", {}).get("system", "OpenClaw")

        out_html = Path(args.output_html)
        out_summary = Path(args.output_summary)
        # Link the summary from the page only when both files sit in the same folder.
        same_folder = out_html.resolve().parent == out_summary.resolve().parent
        page = render_html(system_name, merged, summary, summary_href=out_summary.name if same_folder else None)
        out_html.parent.mkdir(parents=True, exist_ok=True)
        out_html.write_text(page, encoding="utf-8")

        write_json(
            out_summary,
            {
                "generated_at_utc": utc_now(),
                "system": system_name,
                "summary": summary,
                "controls": merged,
            },
        )
        print(
            json.dumps(
                {
                    "status": "ok",
                    "output_html": str(out_html),
                    "output_summary": str(out_summary),
                    "violations_or_partial": len(summary["violations"]),
                }
            )
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
