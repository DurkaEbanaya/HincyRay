#!/usr/bin/env python3
"""Static Web UI ↔ daemon API contract test.

The Web UI is a single embedded HTML/JS file. This test prevents the recurring
class of regressions where a button calls an endpoint that the Rust daemon does
not serve, or uses the wrong HTTP method.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "src" / "webui" / "index.html"
DAEMON = ROOT / "src" / "hincyray.rs"


def served_routes() -> set[tuple[str, str]]:
    text = DAEMON.read_text(encoding="utf-8")
    return {
        (method, path)
        for method, path in re.findall(r'\("(GET|POST)",\s*"([^"]+)"\)\s*=>', text)
    }


def ui_routes() -> set[tuple[str, str]]:
    text = HTML.read_text(encoding="utf-8")
    routes: set[tuple[str, str]] = set()
    patterns = [
        r"apiAction\('(?P<method>GET|POST)'\s*,\s*'(?P<path>/api/[^']+)'",
        r"api\('(?P<method>GET|POST)'\s*,\s*'(?P<path>/api/[^']+)'",
        r"confirmCmd\([^,]+,\s*'(?P<path>/api/[^']+)'",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            method = match.groupdict().get("method") or "POST"
            routes.add((method, match.group("path")))
    return routes


REQUIRED_MARKERS = [
    "globalSearchInput",
    "/api/mihomo-config/validate",
    "/api/diagnostics/dns",
    "/api/diagnostics/udp-quic",
    "/api/memory-guard",
    "/api/subscriptions/refresh-report",
    "/api/undo",
]

SYSTEM_DOM_IDS = [
    "sysCpu",
    "sysCpuModel",
    "sysRam",
    "sysRamText",
    "sysTemp",
    "sysLoad",
    "sysUptime",
    "sysHost",
    "sysModel",
    "sysCores",
    "sysCpuBar",
    "sysRamBar",
    "sysTempBar",
]


def nav_sections(html_text: str) -> set[str]:
    return set(re.findall(r'class="nav-sub-item"\s+data-section="([^"]+)"', html_text))


def panel_sections(html_text: str) -> set[str]:
    return set(
        re.findall(
            r'<section\s+class="[^"]*\bsection-panel\b[^"]*"\s+data-section="([^"]+)"',
            html_text,
        )
    )


def nav_map_sections(html_text: str) -> set[str]:
    match = re.search(r"const NAV_MAP = \{(?P<body>.*?)\n\};", html_text, re.S)
    if not match:
        return set()
    return set(re.findall(r"'([^']+)'\s*:", match.group("body")))


def dom_id_exists(html_text: str, dom_id: str) -> bool:
    return f'id="{dom_id}"' in html_text or f"id='{dom_id}'" in html_text


def main() -> int:
    html_text = HTML.read_text(encoding="utf-8")
    missing_markers = [marker for marker in REQUIRED_MARKERS if marker not in html_text]
    missing_system_ids = [dom_id for dom_id in SYSTEM_DOM_IDS if not dom_id_exists(html_text, dom_id)]
    nav = nav_sections(html_text)
    panels = panel_sections(html_text)
    nav_map = nav_map_sections(html_text)
    nav_without_panel = sorted(nav - panels)
    nav_without_map = sorted(nav - nav_map)
    map_without_panel = sorted(nav_map - panels)
    served = served_routes()
    used = ui_routes()
    missing_routes = sorted(used - served)
    missing_routes = [(method, path) for method, path in missing_routes if not path.endswith("/")]
    if missing_markers or missing_system_ids or nav_without_panel or nav_without_map or map_without_panel or missing_routes:
        if missing_markers:
            print("Missing required UI markers:")
            for marker in missing_markers:
                print(f"  - {marker}")
        if missing_system_ids:
            print("System renderer writes to missing DOM ids:")
            for dom_id in missing_system_ids:
                print(f"  - {dom_id}")
        if nav_without_panel:
            print("Sidebar navigation points to missing section panels:")
            for section in nav_without_panel:
                print(f"  - {section}")
        if nav_without_map:
            print("Sidebar navigation points to sections missing from NAV_MAP:")
            for section in nav_without_map:
                print(f"  - {section}")
        if map_without_panel:
            print("NAV_MAP points to missing section panels:")
            for section in map_without_panel:
                print(f"  - {section}")
        if missing_routes:
            print("UI calls endpoints not served by daemon:")
            for method, path in missing_routes:
                print(f"  - {method} {path}")
        return 1
    print(f"frontend contract ok: {len(used)} UI routes checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
