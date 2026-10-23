"""Render tests: HTML must embed a valid D and expose expected keys."""

import json
import re
from pathlib import Path

from sarif_report.aggregate import aggregate
from sarif_report.render import render, data_to_json

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def _load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def _d():
    sarif = _load(FIX / "sample.sarif")
    config = _load(ROOT / "examples" / "api.config.json")
    catalog = _load(ROOT / "examples" / "rules-catalog.example.json")
    return aggregate(sarif, config=config, catalog=catalog), config


def test_html_contains_const_d_and_title():
    d, config = _d()
    html = render(d, config=config)
    assert "const D =" in html
    assert "UTEM-API Quality Report" in html
    # No unresolved placeholders remain.
    assert "__SARIF_REPORT_" not in html


def test_embedded_d_is_valid_json_and_has_correct_total():
    d, config = _d()
    html = render(d, config=config)
    # Extract the injected literal between 'const D =' and the terminating ';'.
    m = re.search(r"const D = (.*?);\n", html, re.S)
    assert m, "could not locate injected D literal"
    literal = m.group(1)
    # Undo the HTML-safety escaping applied by data_to_json.
    literal = literal.replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&")
    parsed = json.loads(literal)
    assert parsed["meta"]["total"] == d["meta"]["total"] == 10
    assert parsed == d


def test_data_to_json_escapes_script_breakout():
    payload = {"msgs": ["</script><b>x</b> & <done>"]}
    out = data_to_json(payload)
    assert "</script>" not in out
    assert "<" not in out and ">" not in out
    # Round-trips back to the original once unescaped.
    restored = out.replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&")
    assert json.loads(restored) == payload


def test_render_is_deterministic():
    d, config = _d()
    assert render(d, config=config) == render(d, config=config)


def test_render_keys_referenced_by_template_exist():
    """The template reads these D keys; aggregate must always produce them."""
    d, _ = _d()
    for key in ("meta", "sev", "areas", "tools", "rules", "files", "msgs", "findings", "security"):
        assert key in d
    for r in d["rules"]:
        assert set(r.keys()) >= {"id", "tool", "t", "e", "w", "n", "desc", "ex"}
    for f in d["files"]:
        assert set(f.keys()) >= {"p", "a", "t", "e", "w", "n", "top"}
    # findings are 5-tuples [fileIdx, sev, msgIdx, ruleIdx, line]
    for fd in d["findings"]:
        assert len(fd) == 5
        assert 0 <= fd[0] < len(d["files"])
        assert fd[1] in (0, 1, 2)
        assert 0 <= fd[2] < len(d["msgs"])
        assert 0 <= fd[3] < len(d["rules"])
