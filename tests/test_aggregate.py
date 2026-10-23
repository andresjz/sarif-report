"""Golden test: aggregate(sample.sarif) must equal expected_D.json.

This locks determinism: the same SARIF + config + catalog must always reduce
to the same D, field for field.
"""

import json
from pathlib import Path

from sarif_report.aggregate import aggregate

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def _load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def test_aggregate_matches_golden():
    sarif = _load(FIX / "sample.sarif")
    config = _load(ROOT / "examples" / "api.config.json")
    catalog = _load(ROOT / "examples" / "rules-catalog.example.json")
    expected = _load(FIX / "expected_D.json")

    d = aggregate(sarif, config=config, catalog=catalog)
    assert d == expected


def test_aggregate_is_deterministic_across_runs():
    sarif = _load(FIX / "sample.sarif")
    config = _load(ROOT / "examples" / "api.config.json")
    catalog = _load(ROOT / "examples" / "rules-catalog.example.json")

    d1 = aggregate(sarif, config=config, catalog=catalog)
    d2 = aggregate(sarif, config=config, catalog=catalog)
    # Serialized form must be byte-identical.
    assert json.dumps(d1, sort_keys=False) == json.dumps(d2, sort_keys=False)


def test_totals_consistent():
    sarif = _load(FIX / "sample.sarif")
    config = _load(ROOT / "examples" / "api.config.json")
    d = aggregate(sarif, config=config)

    assert d["meta"]["total"] == len(d["findings"])
    assert d["meta"]["rules"] == len(d["rules"])
    assert d["meta"]["files"] == len(d["files"])
    assert sum(s["n"] for s in d["sev"]) == d["meta"]["total"]
    assert sum(t["n"] for t in d["tools"]) == d["meta"]["total"]
    assert sum(a["t"] for a in d["areas"]) == d["meta"]["total"]


def test_rules_sorted_count_desc_then_id():
    sarif = _load(FIX / "sample.sarif")
    d = aggregate(sarif, config=_load(ROOT / "examples" / "api.config.json"))
    keys = [(-r["t"], r["id"]) for r in d["rules"]]
    assert keys == sorted(keys)


def test_desc_falls_back_to_sarif_then_ruleid():
    sarif = _load(FIX / "sample.sarif")
    # No catalog: eslint:eqeqeq has a SARIF fullDescription; checkstyle rules
    # have no SARIF description so they fall back to the rule id.
    d = aggregate(sarif, config=_load(ROOT / "examples" / "api.config.json"))
    by_id = {r["id"]: r for r in d["rules"]}
    assert by_id["eslint:eqeqeq"]["desc"] == "Require the use of === and !==."
    assert by_id["eslint:no-unused-vars"]["desc"] == "Disallow unused variables."
    assert by_id["checkstyle:maxLineLen"]["desc"] == "checkstyle:maxLineLen"


def test_security_grouped_dynamically():
    sarif = _load(FIX / "sample.sarif")
    d = aggregate(sarif, config=_load(ROOT / "examples" / "api.config.json"))
    assert set(d["security"].keys()) == {"cves", "bandit"}
    assert d["security"]["cves"][0]["rule"] == "osv-scanner:CVE-2025-0001"


def test_level_defaults_from_rule_config():
    """A result without a level inherits its rule's defaultConfiguration."""
    sarif = _load(FIX / "sample.sarif")
    d = aggregate(sarif, config=_load(ROOT / "examples" / "api.config.json"))
    # eqeqeq default level is error -> both eqeqeq findings are errors.
    eq = next(r for r in d["rules"] if r["id"] == "eslint:eqeqeq")
    assert eq["e"] == 2 and eq["w"] == 0 and eq["n"] == 0
