"""Path classification into areas.

Areas are declared in the project config as an ordered list of
``{"label": str, "match": [patterns...]}`` entries. Classification is
deterministic: the first area whose patterns match a given path wins, and the
special pattern ``"*"`` is a catch-all. Matching is prefix-or-substring based.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence


DEFAULT_AREAS: List[Dict[str, object]] = [
    {"label": "Otros", "match": ["*"]},
]


def _normalize(path: str) -> str:
    """Normalize a path for matching (forward slashes, no leading ./)."""
    p = path.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    return p


def _pattern_matches(path: str, pattern: str) -> bool:
    """A pattern matches if it is the catch-all, a path prefix, or a substring.

    Substring matching lets build-file patterns like ``vite.config`` or
    ``package.json`` match regardless of directory depth, while directory
    patterns like ``src/pages/`` behave as prefixes.
    """
    if pattern == "*":
        return True
    if not pattern:
        return False
    # Prefix first (most intuitive for directory-style patterns), then substring.
    return path.startswith(pattern) or pattern in path


def classify(path: str, areas: Sequence[Dict[str, object]]) -> int:
    """Return the index of the first area that matches ``path``.

    If no area matches (no catch-all configured), returns the last area index
    as a stable fallback so every file lands somewhere deterministically.
    """
    norm = _normalize(path)
    for idx, area in enumerate(areas):
        patterns = area.get("match", []) or []
        for pat in patterns:
            if _pattern_matches(norm, str(pat)):
                return idx
    return max(0, len(areas) - 1)


def area_labels(areas: Sequence[Dict[str, object]]) -> List[str]:
    return [str(a.get("label", f"area{idx}")) for idx, a in enumerate(areas)]


def resolve_areas(config: Optional[Dict[str, object]]) -> List[Dict[str, object]]:
    """Pull the area definitions from a config dict, with a safe default."""
    if not config:
        return list(DEFAULT_AREAS)
    areas = config.get("areas")
    if not areas or not isinstance(areas, list):
        return list(DEFAULT_AREAS)
    # Shallow-copy to avoid mutating caller data.
    return [dict(a) for a in areas]
