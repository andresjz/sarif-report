# sarif-report

**Deterministic HTML report generator from [SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) output.**

`sarif-report` turns a standard SARIF file into a single self-contained,
interactive HTML report (tabs for severity/areas/rules/files/findings, plus
optional security and remediation-plan views). It is a *pure, deterministic*
generator: **the same SARIF always produces the same report, byte for byte.**
The only things that change between projects are **configuration files**, never
code — so one tool serves a Java backend and a TypeScript frontend without
modification.

SARIF is a tool-agnostic standard, so `sarif-report` works with **any tool that
emits SARIF** — ESLint, Checkstyle, Bandit, CodeQL, Semgrep, Trivy, and many
others. [Qlty](https://qlty.sh) is just one example of a SARIF producer: it can
aggregate several linters into a single SARIF file, which is a convenient input,
but it is in no way required.

### Qlty-aggregated SARIF

Qlty emits a **single `run`** whose `tool.driver.name` is `"qlty"` and encodes
the real linter as the **first segment of each `ruleId`**, using the form
`"<linter>:<rule...>"` (e.g. `markdownlint:MD013`, `yamllint:line-length`,
`zizmor:zizmor/template-injection`, `radarlint-iac:docker:S7031`). `sarif-report`
unpacks this automatically:

* The **tool** is the first `:`-segment of the `ruleId` (so
  `radarlint-iac:docker:S7031` → tool `radarlint-iac`), never the `qlty`
  wrapper. The `tools` breakdown therefore lists `markdownlint`, `yamllint`,
  `prettier`, `zizmor`, … instead of a single `qlty` bucket.
* The **canonical rule id is the raw `ruleId` as-is** — it is *not* re-prefixed
  with `driver.name`, so catalog keys like `markdownlint:MD013` match (no
  `qlty:markdownlint:MD013` duplication).
* A classic per-tool SARIF (where `driver.name` is the real tool and the
  `ruleId` carries no `:`) keeps the legacy behavior: tool = `driver.name`,
  canonical id = `"<driver.name>:<ruleId>"`.

## Quick start (no install, via `uvx`)

```bash
uvx --from git+https://github.com/andresjz/sarif-report sarif-report \
  --sarif qlty.sarif \
  --config report.config.json \
  --catalog rules-catalog.json \
  --out qlty-report.html
```

Any SARIF file works as `--sarif` input. Here the input is named `qlty.sarif`
because it was produced by Qlty, and the output is named `qlty-report.html`, but
both names are arbitrary — use whatever fits your pipeline.

Or run it as a module from a clone:

```bash
python -m sarif_report --sarif results.sarif --out report.html
```

### CLI flags

| Flag | Required | Default | Purpose |
|------|----------|---------|---------|
| `--sarif PATH`     | yes | — | SARIF input file (from any SARIF-emitting tool). |
| `--config PATH`    | no  | — | Project report config (title, areas, waves). |
| `--catalog PATH`   | no  | — | Curated Spanish rule descriptions. |
| `--out PATH`       | no  | `report.html` | Output HTML file. |
| `--emit-data PATH` | no  | — | Also dump the computed `D` object as JSON (debug / determinism checks). |
| `--version`        | no  | — | Print version and exit. |

## How it works

```
SARIF (dict) ──aggregate()──▶ D (dict) ──render()──▶ HTML string
              pure, no IO                inject into template.html
```

* **`aggregate.py`** is a **pure function**: `aggregate(sarif, config, catalog) -> D`.
  It reduces the SARIF results into aggregated counts. No clock, no filesystem,
  no randomness. Every list is sorted by a stable key (**count desc, then id
  asc**), so the output is reproducible.
* **`render.py`** injects `D` (as compact, HTML-safe JSON) and the project
  labels into `template.html`, which carries the entire presentation layer
  (CSS + vanilla-JS render functions). The template is reused verbatim across
  projects.

### What is derived vs. curated

Everything in `D` is **computed from the SARIF** — `meta`, `sev`, `areas`,
`tools`, `rules` counts, `files`, `msgs`, `findings`, `security` — **except two
fields**, which come from versioned config files (never invented at runtime):

1. **`rules[].desc`** — the Spanish description per rule. Resolution order:
   `catalog[tool:rule].desc` → SARIF `shortDescription`/`fullDescription` →
   the rule id itself.
2. **`waves`** — a curated remediation plan. If the config provides `waves`,
   they are used; otherwise the Plan tab is omitted.

## Config format (`report.config.json`)

```json
{
  "title": "UTEM-UI Quality Report",
  "brand": "UTEM-UI Quality Report",
  "source_label": "qlty.sarif",
  "generated": "2026-10-17",
  "areas": [
    {"label": "src/pages",      "match": ["src/pages/"]},
    {"label": "src/components", "match": ["src/components/"]},
    {"label": ".github (CI)",   "match": [".github/"]},
    {"label": "Build",          "match": ["Dockerfile", "vite.config", "package.json", "tsconfig"]},
    {"label": "Otros",          "match": ["*"]}
  ],
  "waves": []
}
```

* **`title` / `brand`** — shown in the document title and header.
* **`source_label`** — label shown next to the brand (defaults to `qlty.sarif`).
* **`generated`** — optional date string (`YYYY-MM-DD`) shown in the footer. It
  is **never** read from the wall clock, to preserve determinism; if omitted,
  the footer simply shows no date.
* **`areas`** — ordered list of `{label, match}`. **Classification is
  deterministic: the first area whose patterns match a path wins.** A pattern
  matches as a **prefix or substring**; `"*"` is a catch-all and should be last.
  Areas with zero findings are dropped from the report.
* **`waves`** — optional curated remediation plan (see below).

Example configs live in [`examples/`](examples/): `ui.config.json` (frontend)
and `api.config.json` (backend).

### Waves format (optional, curated)

```json
"waves": [
  {
    "id": "w1",
    "label": "Seguridad y CI",
    "note": "CVEs en dependencias y escáneres de seguridad.",
    "rules": ["osv-scanner:CVE-2025-0001", "bandit:B310"],
    "tool": ["osv-scanner", "bandit"]
  }
]
```

`rules` may be composite rule ids (`"tool:rule"`) — resolved to internal indices
automatically — or raw integer indices. Unknown rule ids are dropped.

## Catalog format (`rules-catalog.json`)

```json
{
  "eslint:no-unused-vars": {"desc": "Variable declarada sin uso.", "note": "opcional"},
  "checkstyle:maxLineLen": {"desc": "Línea de más de 100 caracteres."}
}
```

Keys are composite `tool:rule` ids. Only `desc` is required per entry. See
[`examples/rules-catalog.example.json`](examples/rules-catalog.example.json).

## The `D` data contract

Top-level keys: `meta`, `sev`, `areas`, `tools`, `rules`, `files`, `msgs`,
`findings`, `security`, and (optionally) `waves`.

* `meta`: `{source, generated, total, files, rules}`
* `sev`: `[{id: "error"|"warning"|"note", n}]`
* `areas`: `[{id, label, t, e, w, n}]` (t=total, e/w/n per severity)
* `tools`: `[{id, n}]`
* `rules`: `[{id: "tool:rule", tool, t, e, w, n, desc, ex:[msgIdx,...]}]`
* `files`: `[{p, a: areaId, t, e, w, n, top: ruleIdx}]`
* `msgs`: `[str, ...]` (deduplicated, sorted)
* `findings`: `[[fileIdx, sevCode(0/1/2), msgIdx, ruleIdx, line], ...]`
* `security`: `{<scanner>: [{file, line, sev, rule, msg}], ...}` — grouped
  dynamically; the OSV/`osv-scanner` group is keyed `cves`.
* `waves`: `[{id, label, t, note, rules:[ruleIdx], tool}]`

## Determinism guarantee

Running the generator twice on the same inputs yields identical output:

```bash
sarif-report --sarif s.sarif --emit-data d1.json --out r1.html
sarif-report --sarif s.sarif --emit-data d2.json --out r2.html
diff d1.json d2.json && diff r1.html r2.html   # both empty
```

This is enforced by a golden test (`tests/test_aggregate.py`) and by the CI
double-run diff.

## Development

```bash
uv run pytest            # or: python -m pytest
```

## License

MIT © andresjz
