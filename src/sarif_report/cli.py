"""Command-line interface: argparse + orchestration (the only IO layer)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from . import __version__
from .aggregate import aggregate
from .render import render


def _load_json(path: Optional[str], what: str) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"error: {what} file not found: {path}")
    try:
        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:  # pragma: no cover - error path
        raise SystemExit(f"error: {what} is not valid JSON ({path}): {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sarif-report",
        description="Deterministic HTML report generator from SARIF (Static Analysis Results Interchange Format) output.",
    )
    parser.add_argument("--sarif", required=True, help="Path to the SARIF input file (required).")
    parser.add_argument("--config", help="Path to the project report config JSON.")
    parser.add_argument("--catalog", help="Path to the curated rules catalog JSON.")
    parser.add_argument("--out", default="report.html", help="Output HTML path (default: report.html).")
    parser.add_argument("--emit-data", dest="emit_data", help="Also write the D object as JSON to this path.")
    parser.add_argument("--version", action="version", version=f"sarif-report {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    sarif = _load_json(args.sarif, "sarif")
    if sarif is None:
        raise SystemExit("error: --sarif is required")
    config = _load_json(args.config, "config") or {}
    catalog = _load_json(args.catalog, "catalog") or {}

    d = aggregate(sarif, config=config, catalog=catalog)

    if args.emit_data:
        data_json = json.dumps(d, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
        Path(args.emit_data).write_text(data_json, encoding="utf-8")

    html_out = render(d, config=config)
    Path(args.out).write_text(html_out, encoding="utf-8")

    print(
        f"Wrote {args.out} "
        f"({d['meta']['total']} findings, {d['meta']['files']} files, {d['meta']['rules']} rules)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
