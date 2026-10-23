"""Qlty-format SARIF handling.

Qlty emits a single ``run`` whose ``driver.name`` is ``"qlty"``; the real
linter is embedded as the first segment of each ``ruleId`` (``"<linter>:<rule
...>"``). These tests lock the behavior described in the bug report:

  * ``tools`` is broken out per real linter and never contains ``"qlty"``.
  * canonical rule ids keep the Qlty prefix verbatim and are NOT re-prefixed
    with ``driver.name`` (no ``qlty:markdownlint:MD013`` duplication).
  * multi-colon ruleIds attribute only the first segment to the tool.
  * a catalog keyed by the canonical id (``markdownlint:MD013``) is applied.
  * classic per-tool SARIF (ruleId without ``:``) still falls back to
    ``driver.name``.
"""

import json
from pathlib import Path

from sarif_report.aggregate import aggregate

FIX = Path(__file__).parent / "fixtures"


def _load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def _d(catalog=None):
    sarif = _load(FIX / "qlty_sample.sarif")
    return aggregate(sarif, config={}, catalog=catalog or {})


def test_tools_are_split_per_linter_and_no_qlty():
    d = _d()
    tool_ids = {t["id"] for t in d["tools"]}
    # Every embedded linter is surfaced as its own tool.
    assert {"markdownlint", "yamllint", "prettier", "zizmor"} <= tool_ids
    # The Qlty wrapper name must never leak through as a tool.
    assert "qlty" not in tool_ids


def test_canonical_rule_id_is_not_duplicated():
    d = _d()
    rule_ids = {r["id"] for r in d["rules"]}
    # Exact canonical id, not the duplicated "qlty:markdownlint:MD013".
    assert "markdownlint:MD013" in rule_ids
    assert "qlty:markdownlint:MD013" not in rule_ids
    # No rule id anywhere should carry the bogus "qlty:" prefix.
    assert not any(rid.startswith("qlty:") for rid in rule_ids)


def test_multi_colon_rule_id_uses_first_segment_as_tool():
    d = _d()
    by_id = {r["id"]: r for r in d["rules"]}
    rule = by_id["radarlint-iac:docker:S7031"]
    # Tool is only the first segment; the rule id is preserved in full.
    assert rule["tool"] == "radarlint-iac"
    assert rule["id"] == "radarlint-iac:docker:S7031"


def test_catalog_entry_applies_to_canonical_id():
    catalog = {
        "markdownlint:MD013": {"desc": "Línea de Markdown demasiado larga."}
    }
    d = _d(catalog=catalog)
    md013 = next(r for r in d["rules"] if r["id"] == "markdownlint:MD013")
    assert md013["desc"] == "Línea de Markdown demasiado larga."
    assert md013["tool"] == "markdownlint"


def test_rule_without_colon_falls_back_to_driver_name():
    # The fixture includes a classic per-tool run: driver "checkstyle" with a
    # bare "maxLineLen" ruleId (no colon). That keeps the legacy behavior.
    d = _d()
    by_id = {r["id"]: r for r in d["rules"]}
    assert "checkstyle:maxLineLen" in by_id
    assert by_id["checkstyle:maxLineLen"]["tool"] == "checkstyle"


def test_security_groups_use_derived_tool():
    d = _d()
    # zizmor and osv-scanner are embedded under the qlty driver; grouping must
    # key off the DERIVED tool, not driver.name.
    assert "zizmor" in d["security"]
    assert "cves" in d["security"]  # osv-scanner is keyed "cves"
    assert d["security"]["cves"][0]["rule"] == "osv-scanner:CVE-2025-9999"
    assert d["security"]["zizmor"][0]["rule"] == "zizmor:zizmor/template-injection"


def test_qlty_fixture_is_deterministic():
    sarif = _load(FIX / "qlty_sample.sarif")
    catalog = _load(FIX / "qlty_catalog.json")
    d1 = aggregate(sarif, config={}, catalog=catalog)
    d2 = aggregate(sarif, config={}, catalog=catalog)
    assert json.dumps(d1, sort_keys=False) == json.dumps(d2, sort_keys=False)


def test_qlty_totals_consistent():
    d = _d()
    assert d["meta"]["total"] == len(d["findings"])
    assert sum(t["n"] for t in d["tools"]) == d["meta"]["total"]
    assert sum(s["n"] for s in d["sev"]) == d["meta"]["total"]
