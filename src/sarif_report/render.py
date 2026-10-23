"""D + template -> HTML string.

The template is a static HTML file with three text placeholders:
  * ``__SARIF_REPORT_DATA__``  -> the D object serialized as JSON
  * ``__SARIF_REPORT_TITLE__`` -> document title
  * ``__SARIF_REPORT_BRAND__`` -> header brand text
  * ``__SARIF_REPORT_SRC__``   -> source label shown next to the brand

Serialization is deterministic: ``json.dumps`` with ``sort_keys=False`` (D is
already built in a stable key order), ``ensure_ascii=False`` and compact
separators. The same D always yields byte-identical HTML.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, Optional

_TEMPLATE_PATH = Path(__file__).with_name("template.html")

_DATA_TOKEN = "__SARIF_REPORT_DATA__"
_TITLE_TOKEN = "__SARIF_REPORT_TITLE__"
_BRAND_TOKEN = "__SARIF_REPORT_BRAND__"
_SRC_TOKEN = "__SARIF_REPORT_SRC__"


def load_template() -> str:
    return _TEMPLATE_PATH.read_text(encoding="utf-8")


def data_to_json(d: Dict[str, Any]) -> str:
    """Serialize D to a compact, deterministic, HTML-safe JSON literal.

    ``</script>`` sequences are escaped so the JSON can live inside a
    ``<script>`` tag without prematurely closing it.
    """
    text = json.dumps(d, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
    # Prevent </script> breakout and HTML comment edge cases inside the inline JS.
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return text


def render(
    d: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
    template: Optional[str] = None,
) -> str:
    """Produce the final HTML string from D and optional config labels."""
    config = config or {}
    tpl = template if template is not None else load_template()

    title = str(config.get("title", "Quality Report"))
    brand = str(config.get("brand", title))
    src = str(d.get("meta", {}).get("source", config.get("source_label", "qlty.sarif")))

    out = tpl.replace(_DATA_TOKEN, data_to_json(d))
    out = out.replace(_TITLE_TOKEN, html.escape(title, quote=True))
    out = out.replace(_BRAND_TOKEN, html.escape(brand, quote=True))
    out = out.replace(_SRC_TOKEN, html.escape(src, quote=True))
    return out
