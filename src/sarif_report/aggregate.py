"""Pure SARIF -> D reduction.

``aggregate(sarif, config, catalog)`` takes already-parsed Python dicts and
returns the ``D`` dict consumed by the HTML template. It performs **no IO** and
is fully deterministic: the same inputs always produce the same output, with
every list ordered by a stable key (count desc, then id asc).

The only non-derivable fields are:
  * ``rules[].desc`` -- Spanish description from the catalog, falling back to
    the SARIF rule shortDescription/fullDescription, then the rule id.
  * ``waves``        -- curated remediation plan taken verbatim from config.
Everything else is computed by reduction over the SARIF results.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from .areas import classify, resolve_areas

# SARIF level -> severity code (0=error, 1=warning, 2=note)
_LEVEL_TO_CODE = {
    "error": 0,
    "warning": 1,
    "note": 2,
    "none": 2,
}
_CODE_TO_ID = {0: "error", 1: "warning", 2: "note"}

# Tools whose findings are surfaced in the dedicated "security" section.
# Grouped dynamically: any tool listed here that actually appears in the SARIF
# gets its own key in ``security``.
_SECURITY_TOOLS = (
    "osv-scanner",
    "zizmor",
    "bandit",
    "trivy",
    "semgrep",
    "gitleaks",
    "trufflehog",
)


def _level_code(result: Dict[str, Any], rule_defaults: Dict[str, int], rule_id: str) -> int:
    """Resolve a result's severity code from its level or its rule default."""
    level = result.get("level")
    if level is None:
        # Fall back to the rule's configured default level if present.
        level = rule_defaults.get(rule_id)
    if level is None:
        level = "warning"
    return _LEVEL_TO_CODE.get(str(level).lower(), 1)


def _driver_name(run: Dict[str, Any]) -> str:
    driver = (run.get("tool") or {}).get("driver") or {}
    return str(driver.get("name") or "unknown")


def _derive_tool_and_rule(raw_rule_id: str, driver_name: str) -> Tuple[str, str]:
    """Derive ``(tool, canonical_rule_id)`` from a raw SARIF ruleId.

    Handles the Qlty convention, where a single run reports ``driver.name ==
    "qlty"`` and the real linter is embedded as the first segment of the
    ``ruleId`` (``"<linter>:<rule...>"``), as well as classic per-tool SARIF
    where ``driver.name`` is the tool and the ``ruleId`` carries no prefix.

    Rules:
      * If the raw ruleId contains ``:`` -> the tool is the **first segment**
        before the first ``:`` (so ``radarlint-iac:docker:S7031`` -> tool
        ``radarlint-iac``) and the canonical rule id is the raw ruleId left
        **exactly as-is** (never re-prefixed with ``driver.name``).
      * Otherwise -> fall back to the legacy behavior: tool = ``driver.name``
        (or ``"unknown"``) and canonical id = ``"<driver.name>:<ruleId>"``.
      * Defensive special case: a ``driver.name`` of exactly ``"qlty"`` is
        never used as a tool or prefix. Qlty always prefixes its ruleIds, so
        the ``:`` branch handles it; if a ``qlty`` run ever lacks a prefix we
        fall back to ``"unknown"`` instead of ``"qlty"``.
    """
    if ":" in raw_rule_id:
        tool = raw_rule_id.split(":", 1)[0] or "unknown"
        return tool, raw_rule_id
    # No prefix: legacy per-tool SARIF. Never attribute to the "qlty" wrapper.
    tool = driver_name if driver_name and driver_name != "qlty" else "unknown"
    return tool, f"{tool}:{raw_rule_id}"


def _rule_default_levels(run: Dict[str, Any]) -> Dict[str, int]:
    """Map ruleId -> SARIF level string from the driver's rule definitions."""
    driver = (run.get("tool") or {}).get("driver") or {}
    out: Dict[str, int] = {}
    for rule in driver.get("rules") or []:
        rid = rule.get("id")
        if rid is None:
            continue
        cfg = rule.get("defaultConfiguration") or {}
        lvl = cfg.get("level")
        if lvl is not None:
            out[rid] = lvl
    return out


def _rule_descriptions(run: Dict[str, Any]) -> Dict[str, str]:
    """Map ruleId -> best available SARIF-provided description text."""
    driver = (run.get("tool") or {}).get("driver") or {}
    out: Dict[str, str] = {}
    for rule in driver.get("rules") or []:
        rid = rule.get("id")
        if rid is None:
            continue
        short = (rule.get("shortDescription") or {}).get("text")
        full = (rule.get("fullDescription") or {}).get("text")
        text = short or full
        if text:
            out[rid] = str(text).strip()
    return out


def _result_message(result: Dict[str, Any]) -> str:
    msg = result.get("message") or {}
    text = msg.get("text")
    if text is None:
        # Some tools only emit markdown.
        text = msg.get("markdown")
    return str(text).strip() if text is not None else ""


def _result_location(result: Dict[str, Any]) -> Tuple[Optional[str], int]:
    """Return (path, line) for a result; line is -1 when unknown."""
    locations = result.get("locations") or []
    for loc in locations:
        phys = loc.get("physicalLocation") or {}
        art = phys.get("artifactLocation") or {}
        uri = art.get("uri")
        if uri is None:
            continue
        uri = str(uri)
        if uri.startswith("file://"):
            uri = uri[len("file://"):]
        region = phys.get("region") or {}
        line = region.get("startLine")
        try:
            line_i = int(line) if line is not None else -1
        except (TypeError, ValueError):
            line_i = -1
        return uri, line_i
    return None, -1


def aggregate(
    sarif: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
    catalog: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Reduce a parsed SARIF document into the D data object."""
    config = config or {}
    catalog = catalog or {}
    areas_def = resolve_areas(config)
    area_labels = [str(a.get("label", f"area{i}")) for i, a in enumerate(areas_def)]

    # ---- First pass: collect raw findings ------------------------------------
    # raw finding: (path, sev_code, msg_text, qualified_rule_id, line, tool)
    raw: List[Tuple[Optional[str], int, str, str, int, str]] = []
    sarif_descs: Dict[str, str] = {}

    for run in sarif.get("runs") or []:
        driver_name = _driver_name(run)
        defaults = _rule_default_levels(run)
        descs_by_raw = _rule_descriptions(run)
        for raw_rid, text in descs_by_raw.items():
            _tool, qid = _derive_tool_and_rule(raw_rid, driver_name)
            sarif_descs.setdefault(qid, text)
        for result in run.get("results") or []:
            rule_id = result.get("ruleId")
            if rule_id is None:
                rule_id = "unknown"
            rule_id = str(rule_id)
            # Severity defaults are keyed by the raw ruleId as it appears in the
            # driver's rule definitions (Qlty keeps the full prefixed id there).
            sev = _level_code(result, defaults, rule_id)
            msg = _result_message(result)
            path, line = _result_location(result)
            tool, qid = _derive_tool_and_rule(rule_id, driver_name)
            raw.append((path, sev, msg, qid, line, tool))

    # ---- Severity totals -----------------------------------------------------
    sev_counts = {0: 0, 1: 0, 2: 0}
    for _p, sev, _m, _q, _l, _t in raw:
        sev_counts[sev] += 1

    # ---- Tool totals ---------------------------------------------------------
    tool_counts: Dict[str, int] = {}
    for _p, _s, _m, _q, _l, tool in raw:
        tool_counts[tool] = tool_counts.get(tool, 0) + 1

    # ---- Area / file aggregation ---------------------------------------------
    # file key -> {a, t, e, w, n, rules: {qid: count}}
    file_agg: Dict[str, Dict[str, Any]] = {}
    for path, sev, _m, qid, _l, _t in raw:
        key = path if path is not None else "(no location)"
        area_idx = classify(path, areas_def) if path is not None else max(0, len(areas_def) - 1)
        rec = file_agg.get(key)
        if rec is None:
            rec = {"a": area_idx, "t": 0, "e": 0, "w": 0, "n": 0, "rules": {}}
            file_agg[key] = rec
        rec["t"] += 1
        rec[("e", "w", "n")[sev]] += 1
        rec["rules"][qid] = rec["rules"].get(qid, 0) + 1

    # ---- Rule aggregation ----------------------------------------------------
    rule_agg: Dict[str, Dict[str, int]] = {}
    for _p, sev, _m, qid, _l, tool in raw:
        rec = rule_agg.get(qid)
        if rec is None:
            rec = {"t": 0, "e": 0, "w": 0, "n": 0, "_tool": tool}
            rule_agg[qid] = rec
        rec["t"] += 1
        rec[("e", "w", "n")[sev]] += 1

    # ---- Message dedup (stable order: first appearance) ----------------------
    # To keep output deterministic regardless of input ordering, we sort unique
    # messages lexicographically and assign indices.
    unique_msgs = sorted({m for _p, _s, m, _q, _l, _t in raw})
    msg_index = {m: i for i, m in enumerate(unique_msgs)}

    # ---- Rules list ordering (count desc, id asc) ----------------------------
    ordered_rule_ids = sorted(rule_agg.keys(), key=lambda q: (-rule_agg[q]["t"], q))
    rule_index = {q: i for i, q in enumerate(ordered_rule_ids)}

    # ---- Build example message indices per rule (stable) ---------------------
    # ex = up to 3 distinct message indices seen for that rule, sorted.
    rule_examples: Dict[str, List[int]] = {q: [] for q in rule_agg}
    seen_ex: Dict[str, set] = {q: set() for q in rule_agg}
    for _p, _s, m, qid, _l, _t in raw:
        mi = msg_index[m]
        if mi not in seen_ex[qid]:
            seen_ex[qid].add(mi)
    for q in rule_agg:
        rule_examples[q] = sorted(seen_ex[q])[:3]

    def _tool_of(qid: str) -> str:
        return rule_agg[qid]["_tool"]

    rules_list: List[Dict[str, Any]] = []
    for qid in ordered_rule_ids:
        rec = rule_agg[qid]
        desc = _resolve_desc(qid, catalog, sarif_descs)
        rules_list.append(
            {
                "id": qid,
                "tool": rec["_tool"],
                "t": rec["t"],
                "e": rec["e"],
                "w": rec["w"],
                "n": rec["n"],
                "desc": desc,
                "ex": rule_examples[qid],
            }
        )

    # ---- Files list ordering (count desc, path asc) --------------------------
    def _top_rule(rules: Dict[str, int]) -> int:
        if not rules:
            return 0
        # count desc, then rule id asc for determinism
        best = sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        return rule_index.get(best, 0)

    ordered_file_keys = sorted(
        file_agg.keys(), key=lambda p: (-file_agg[p]["t"], p)
    )
    file_index = {p: i for i, p in enumerate(ordered_file_keys)}
    files_list: List[Dict[str, Any]] = []
    for p in ordered_file_keys:
        rec = file_agg[p]
        files_list.append(
            {
                "p": p,
                "a": rec["a"],
                "t": rec["t"],
                "e": rec["e"],
                "w": rec["w"],
                "n": rec["n"],
                "top": _top_rule(rec["rules"]),
            }
        )

    # ---- Areas list (follows config order; keeps empty areas too) ------------
    area_tot = [
        {"id": i, "label": area_labels[i], "t": 0, "e": 0, "w": 0, "n": 0}
        for i in range(len(areas_def))
    ]
    for rec in file_agg.values():
        a = rec["a"]
        area_tot[a]["t"] += rec["t"]
        area_tot[a]["e"] += rec["e"]
        area_tot[a]["w"] += rec["w"]
        area_tot[a]["n"] += rec["n"]
    # Drop areas with zero findings to keep the report focused, but preserve
    # config order for the ones that remain. Re-id sequentially and remap files.
    kept = [a for a in area_tot if a["t"] > 0]
    old_to_new = {a["id"]: new_id for new_id, a in enumerate(kept)}
    for new_id, a in enumerate(kept):
        a["id"] = new_id
    if old_to_new:
        for f in files_list:
            f["a"] = old_to_new.get(f["a"], len(kept) - 1 if kept else 0)

    # ---- Findings (compact, stable order) ------------------------------------
    # Each finding: [fileIdx, sevCode, msgIdx, ruleIdx, line].
    findings: List[List[int]] = []
    for path, sev, m, qid, line, _t in raw:
        key = path if path is not None else "(no location)"
        findings.append(
            [
                file_index[key],
                sev,
                msg_index[m],
                rule_index[qid],
                line,
            ]
        )
    # Deterministic order: by rule index, then file, then line, then msg.
    findings.sort(key=lambda f: (f[3], f[0], f[4], f[2], f[1]))

    # ---- Tools list ordering (count desc, id asc) ----------------------------
    tools_list = [
        {"id": t, "n": n}
        for t, n in sorted(tool_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    # ---- Severity list (fixed order error/warning/note) ----------------------
    sev_list = [{"id": _CODE_TO_ID[c], "n": sev_counts[c]} for c in (0, 1, 2)]

    # ---- Security section (dynamic grouping by scanner) ----------------------
    security = _build_security(raw)

    # ---- Meta ----------------------------------------------------------------
    meta = {
        "source": str(config.get("source_label", "qlty.sarif")),
        "generated": str(config.get("generated", _default_generated(sarif))),
        "total": len(raw),
        "files": len(files_list),
        "rules": len(rules_list),
    }

    # ---- Waves (curated, verbatim from config) -------------------------------
    waves = config.get("waves") or []
    # Only include waves whose rule ids resolve; map rule ids to indices if the
    # config used string ids, else assume integer indices are already correct.
    waves_out = _resolve_waves(waves, rule_index)

    d: Dict[str, Any] = {
        "meta": meta,
        "sev": sev_list,
        "areas": kept,
        "tools": tools_list,
        "rules": rules_list,
        "files": files_list,
        "msgs": unique_msgs,
        "findings": findings,
        "security": security,
    }
    if waves_out:
        d["waves"] = waves_out
    return d


def _resolve_desc(
    qid: str, catalog: Dict[str, Any], sarif_descs: Dict[str, str]
) -> str:
    """Catalog desc -> SARIF description -> rule id."""
    entry = catalog.get(qid)
    if isinstance(entry, dict) and entry.get("desc"):
        return str(entry["desc"])
    if isinstance(entry, str) and entry:
        return entry
    if qid in sarif_descs:
        return sarif_descs[qid]
    return qid


def _default_generated(sarif: Dict[str, Any]) -> str:
    """Derive a stable 'generated' date from the SARIF if possible.

    Determinism rule: we never read the wall clock here. Callers who want a
    specific date pass it via config. Absent both, we emit an empty string so
    the output stays reproducible for a given SARIF.
    """
    return ""


def _build_security(
    raw: Sequence[Tuple[Optional[str], int, str, str, int, str]]
) -> Dict[str, List[Dict[str, Any]]]:
    """Group security-scanner findings into ``{tool: [items...]}``.

    Keys appear only for scanners present in the SARIF. Items are sorted by
    (file, line, rule) for stable output. The OSV/CVE key is named ``cves``
    to match the reference template's expectations.
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for path, sev, msg, qid, line, tool in raw:
        if tool not in _SECURITY_TOOLS:
            continue
        key = "cves" if tool == "osv-scanner" else tool
        item: Dict[str, Any] = {
            "file": path if path is not None else "",
            "line": line,
            "sev": sev,
            "rule": qid,
            "msg": msg,
        }
        groups.setdefault(key, []).append(item)
    for key in groups:
        groups[key].sort(key=lambda it: (it["file"], it["line"], it["rule"], it["msg"]))
    return groups


def _resolve_waves(
    waves: Sequence[Dict[str, Any]], rule_index: Dict[str, int]
) -> List[Dict[str, Any]]:
    """Normalize curated waves. Rule refs may be composite ids or indices."""
    out: List[Dict[str, Any]] = []
    for w in waves:
        if not isinstance(w, dict):
            continue
        rules = w.get("rules") or []
        resolved: List[int] = []
        for r in rules:
            if isinstance(r, int):
                resolved.append(r)
            elif isinstance(r, str) and r in rule_index:
                resolved.append(rule_index[r])
        out.append(
            {
                "id": w.get("id", ""),
                "label": w.get("label", ""),
                "t": w.get("t", 0),
                "note": w.get("note", ""),
                "rules": resolved,
                "tool": w.get("tool"),
            }
        )
    return out
