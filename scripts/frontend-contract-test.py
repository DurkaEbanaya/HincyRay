#!/usr/bin/env python3
"""Static Web UI ↔ daemon API contract test.

The Web UI is a single embedded HTML/JS file. This test prevents the recurring
class of regressions where a button calls an endpoint that the Rust daemon does
not serve, or uses the wrong HTTP method.
"""

from __future__ import annotations

import re
import subprocess
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
    "/api/telegram-probe/status",
    "/api/telegram-probe/request-code",
    "/api/telegram-probe/confirm",
    "/api/telegram-probe/delete",
    "v1.1.0",
    "/api/memory-guard",
    "/api/subscriptions/refresh-report",
    "/api/undo",
    "function refreshSystem()",
    "function refreshStatus()",
    "function startAutoRefreshLoops()",
    "function showMemoryBreakdown()",
    "hrSystemRefreshInterval",
    "hrStatusRefreshInterval",
    ".btn, .chip, .section-header,",
    "addEventListener('pointermove'",
    "if (va.missing !== vb.missing) return va.missing ? 1 : -1;",
    "const favorites = applyProfileSort(data.filter(p => p.favorite));",
    "last_download_mbps: st.last_download_mbps ?? null",
    "last_upload_mbps: st.last_upload_mbps ?? null",
    "if (r.download_mbps != null) p.last_download_mbps = r.download_mbps;",
    "if (r.upload_mbps != null) p.last_upload_mbps = r.upload_mbps;",
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
    "reader.readAsText(file, 'UTF-8');",
    "function handleGeoBaseFile(event)",
    "function resetGeoBaseFile()",
    '<option value="upload">Файл</option>',
    "if (kind !== 'url') payload.content = content;",
    "if (kind !== 'url') {",
    "const payload = {name,source:{kind,value},static_entries};",
    "data.manifest?.bases",
    "completed * 100 / total",
    "runtime.error",
    "data.requires_apply === true",
    "GEOBASE_MAX_FILE_BYTES = 8 * 1024 * 1024",
    "file.size > GEOBASE_MAX_FILE_BYTES",
    "geobaseFileReader.abort()",
    "generation !== geobaseFileGeneration",
    "document.getElementById('confirmText').textContent",
    "data-geobase-action=\"delete\"",
    "target:'direct'",
    "target:'active'",
    "source_networks",
    "— серый список → ACTIVE (proxy-active)",
    "— белый список → DIRECT",
    "data-geobase-action=\"edit-static\"",
    "function openGeoBaseEditor(id, name)",
    "Array.isArray(data.lists?.static_entries)",
    "const payload = {id:geobaseEditState.id,expected_revision:geobaseEditState.expected_revision,static_entries};",
    "if (/^IP-CIDR6?$/i.test(tokens[0] || '')) candidate = tokens[1] || '';",
    "runtime.sync_diff || runtime.diff || runtime",
    "value.removed_static || value.removed_static_entries || value.static_removed",
    "geobaseJobExpected || geobaseRuntimeRunning",
    ".finally(() => {",
    "Math.min(15000, 2000 * (2 ** geobasePollFailures))",
    "runtime.running === true",
    "sr.auto_vpn_learning_enabled === true",
    "function quickBenchSelected()",
    "method:'quick', test_download:false, test_upload:false",
    "function profileServiceTestsHtml(resourceTests)",
    "resourceTests.filter(test => test.contract_version === 6)",
    "profile-service-test ${ok?'ok':'bad'}",
    "[['youtube','YT'],['telegram','TG'],['ai','AI']]",
    "function toggleProfileMetricSettings(event)",
    "hr_profile_metrics",
    "data-profile-metric=\"latency\"",
    "resource_tests: Array.isArray(st.resource_tests) ? st.resource_tests : []",
    "Домены из списка всегда идут через VPN",
    "🚂 Паровозик",
    "id=\"rParovozikEnabled\"",
    "id=\"rParovozikWagons\"",
    "parovozik_enabled: document.getElementById('rParovozikEnabled')?.checked === true",
    "parovozik_server_refs: [...parovozikSelectedRefs]",
    "function renderParovozikServers(selectedRefs)",
    "function toggleParovozikWagon(serverRef)",
    "function saveParovozikConsist()",
    "Сохранить состав вагонов",
    "const subscription = subscriptionForGroup(group);",
    "subscription?.title || shortGroupName(group || t('Без группы'))",
    "!server.active && !server.dead && server.ref",
    "let parovozikConsistDirty = false;",
    "if (!parovozikConsistDirty) renderParovozikServers(sr.parovozik_server_refs);",
    "Паровозик Direct",
    "Паровозик VPN",
    "safeChecked('autoSwitchEnabled', sr.auto_switch);",
    "safeChecked('rAutoSwitch', d.auto_switch);",
    "managed_routing_rules: []",
    "MOCK.managed_routing_rules = d.managed_rules || [];",
    "MOCK.geobase_requires_apply = d.geobase_requires_apply === true;",
    "function renderManagedRoutingRules(rules, requiresApply)",
    'class="managed-routing-rule"',
    "🔒 managed",
    "${target} / ${outbound}",
    "'proxy-active'",
    "'DIRECT'",
    "data-geobase-id=",
    "api('POST','/api/routing/rules',{rules:MOCK.routing_rules, apply:true})",
    "result.activation_error || t('требуется повторное применение')",
    "Array.isArray(result.errors) && result.errors.length",
    "/api/routing/resource-route",
    "/api/routing/explain",
    "/api/routing/preview",
    "/api/routing/connection-context",
    "/api/onboarding/status",
    "/api/memory-estimate",
    "/api/safe-mode",
    "/api/mihomo-api/connections/page",
    "/api/mihomo-api/connections/device-traffic",
    "const CONNECTIONS_TABLE_PAGE_SIZE = 100;",
    "api('POST','/api/mihomo-api/connections/page',{query,offset,limit:CONNECTIONS_TABLE_PAGE_SIZE},true)",
    "function changeConnectionsTablePage(direction)",
    "api('POST','/api/mihomo-api/connections/device-traffic',{source_ips},true)",
    "data-testid=\"connections-action\" data-native-select=\"1\" data-resource=\"${resource}\" onchange=\"routeConnectionResource(this)\"",
    "select:not([data-native-select]):not([data-custom-select-enhanced])",
    "select.dataset.nativeSelect",
    "function routeConnectionResource(select)",
    "const resource = String(select?.dataset?.resource || '').trim();",
    "data-resource=\"${resource}\" onclick=\"reloadConnectionResource(this)\"",
    "function reloadConnectionResource(button)",
    "const resource = String(button?.dataset?.resource || '').trim();",
    "api('POST','/api/mihomo-api/connections/close',{resource})",
    "Маршрутизация по серверам",
    "MOCK.routing_servers = Array.isArray(d.servers) ? d.servers : [];",
    "`server:${String(server.ref)}`",
    "если выбранный сервер недоступен — текущий активный VPN; DIRECT не используется",
    "function routingTargetOptions(selectedTarget)",
    "function routingTargetPresentation(target)",
    "Сервер удалён или недоступен",
    "routingTargetOptions(r.target)",
    "data-section=\"connections-table\"",
    "function renderConnectionsTable(status, connections)",
    "function filterConnectionsTable(value)",
    "function connectionServerQuery(value)",
    "String.fromCharCode(ch.codePointAt(0) - 127397)",
    "normalizeConnections(connectionsData, null)",
    "observed Mihomo chain",
    "let visualRoutingRefreshTimer = null;",
    "function startConnectionsTableAutoRefresh()",
    "function stopConnectionsTableAutoRefresh()",
    "function setVisualRoutingInterval(value)",
    "function isConnectionsTableActive()",
    "id=\"routingVisualInterval\"",
    "Автообновление работает только пока эта вкладка открыта",
    "data-testid=\"profile-rename-modal\"",
    "function openFormDialog(",
    "function enhanceResponsiveTables(",
    "function previewAndApplyRouting()",
    "function loadOperationalSafety()",
    "function explainConnectionResource(button)",
    "sessionStorage.getItem('hincyray_token')",
    "deadServerBulk",
    "const DEAD_SERVERS_GROUP_KEY = 'virtual:dead-servers';",
    "const selectedServerRefs = new Set();",
    "function profileGroupDescriptors(data)",
    "if (profile.dead)",
    "groups.push({key:DEAD_SERVERS_GROUP_KEY",
    "data-server-ref=",
    "api('POST','/api/trash/move',{server_refs})",
    "api('POST','/api/trash/restore',{server_refs})",
    "function benchSubscription(subscriptionUrl)",
    "{subscription_url:subscriptionUrl}",
    "server_ref: p.server_ref || st.server_ref",
    "dead: p.dead ?? st.dead ?? false",
    "const byServerRef = new Map();",
    "s.server_ref",
    "p.dead?`<span class=\"badge badge-danger\">${t('Дохлые серверы')}</span>`",
]

FORBIDDEN_MARKERS = [
    "openVisualRoutingWindow",
    "buildVisualRoutingTableHtml",
    "routingVisualWindowShell",
    "visualRoutingWindowRef",
    "syncVisualRoutingTheme",
    "isVisualRoutingWindowOpen",
    "routing-visual-modal",
    "hrDashboardRefreshInterval",
    "setInterval(refreshDashboard",
    "setInterval(loadGeoBases",
    "setInterval(() => loadGeoBases",
    "kind === 'file'",
    "value=\"file\">Файл",
    "Array.isArray(data.bases)",
    "progress_percent",
    "onchange=\"setGeoBaseEnabled(",
    "onclick=\"syncGeoBase(",
    "onclick=\"deleteGeoBase(",
    "{rules:MOCK.managed_routing_rules}",
    "api('POST','/api/routing/rules',{rules:MOCK.routing_rules})",
    "sourceAttr",
    "{host:resource, destination_ip:resource",
    "routeConnectionResource(this,'${resource}')",
    "reloadConnectionResource('${resource}')",
    'value="profile:0"',
    "server.raw",
    "prompt(",
    "api('GET','/api/mihomo-api/connections',undefined,true)",
    "{query:'',offset:0,limit:500}",
    "function aggregateDeviceTraffic(conns)",
    "api('GET','/api/routing',undefined,true),\n    api('GET','/api/status'",
    "localStorage.setItem('hincyray_token'",
    "s.profile_raw",
    "data-raw=",
    "DB_EXPLICIT_SELECTED.add(p.raw)",
    "apiAction('POST', '/api/trash/restore', { raw }",
    "Сырой профиль: ${raw}",
]

GEOBASE_DOM_IDS = [
    "experimentalFeatures",
    "geobaseConstructor",
    "geobaseSourceKind",
    "geobaseName",
    "geobaseUrlField",
    "geobaseSourceUrl",
    "geobaseFileField",
    "geobaseFile",
    "geobaseFileStatus",
    "geobaseOfficialPreset",
    "geobaseContentField",
    "geobaseContent",
    "geobaseAnalyze",
    "geobaseCancel",
    "geobaseRuntime",
    "geobaseRuntimeText",
    "geobaseProgress",
    "geobaseRuntimeError",
    "geobaseStaticEditor",
    "geobaseStaticUnassigned",
    "geobaseStaticDirect",
    "geobaseStaticActive",
    "geobaseEditModal",
    "geobaseEditTitle",
    "geobaseEditAvailable",
    "geobaseEditDirect",
    "geobaseEditActive",
    "geobaseEditDiff",
    "geobaseEditSave",
    "geobaseTable",
    "geobaseList",
    "geobaseApplyWarning",
    "geobaseApplyRouting",
    "rRuDirectMode",
    "rRuDirectExceptions",
    "rAutoVpnLearning",
    "rAutoVpnExceptions",
]

GEOBASE_UI_ROUTES = {
    ("GET", "/api/geobases"),
    ("POST", "/api/geobases/analyze"),
    ("POST", "/api/geobases/cancel"),
    ("POST", "/api/geobases/enabled"),
    ("POST", "/api/geobases/sync"),
    ("POST", "/api/geobases/delete"),
    ("POST", "/api/geobases/details"),
    ("POST", "/api/geobases/static"),
    ("POST", "/api/routing/apply"),
}

SYSTEM_DOM_IDS = [
    "sysCpu",
    "sysCpuModel",
    "sysRam",
    "sysRamText",
    "sysMihomoRam",
    "sysTemp",
    "sysLoad",
    "sysUptime",
    "sysHost",
    "sysModel",
    "sysCores",
    "sysCpuBar",
    "sysRamBar",
    "sysTempBar",
    "sysMemoryCard",
]

DEAD_SERVERS_DOM_IDS = [
    "deadServerBulk",
    "deadServerSelectedCount",
    "deadServerSelectedBreakdown",
    "deadServerMoveSelected",
    "deadServerRestoreSelected",
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


def dom_id_count(html_text: str, dom_id: str) -> int:
    return len(re.findall(rf"\bid=['\"]{re.escape(dom_id)}['\"]", html_text))


def js_function(html_text: str, name: str) -> str:
    start = html_text.find(f"function {name}(")
    if start < 0:
        raise ValueError(f"missing JavaScript function {name}")
    brace = html_text.find("{", start)
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(brace, len(html_text)):
        char = html_text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return html_text[start : index + 1]
    raise ValueError(f"unterminated JavaScript function {name}")


def verify_nullable_sort(html_text: str) -> str | None:
    try:
        functions = "\n".join(
            js_function(html_text, name) for name in ("getSortValue", "applyProfileSort")
        )
    except ValueError as error:
        return str(error)
    program = f"""
let profileSortState = {{key:'last_download_mbps', dir:'asc'}};
{functions}
const data = [
  {{id:'missing', name:null, address:null, last_download_mbps:null}},
  {{id:'fast', name:'Zulu', address:'z.example', last_download_mbps:100}},
  {{id:'zero', name:'Alpha', address:'a.example', last_download_mbps:0}}
];
function ids() {{ return applyProfileSort(data).map(p => p.id).join(','); }}
if (ids() !== 'zero,fast,missing') throw new Error('numeric asc: '+ids());
profileSortState.dir = 'desc';
if (ids() !== 'fast,zero,missing') throw new Error('numeric desc: '+ids());
profileSortState = {{key:'name', dir:'asc'}};
if (ids() !== 'zero,fast,missing') throw new Error('string asc: '+ids());
profileSortState.dir = 'desc';
if (ids() !== 'fast,zero,missing') throw new Error('string desc: '+ids());
profileSortState = {{key:'address', dir:'desc'}};
if (ids() !== 'fast,zero,missing') throw new Error('address desc: '+ids());
"""
    result = subprocess.run(
        ["node", "-e", program], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return (result.stderr or result.stdout).strip()
    return None


def verify_geobase_network_parser(html_text: str) -> str | None:
    try:
        functions = "\n".join(
            js_function(html_text, name)
            for name in ("isGeoBaseIpv4", "isGeoBaseIpv6", "geoBaseNetworkToken", "geoBaseNetworkLines")
        )
    except ValueError as error:
        return str(error)
    program = f"""
{functions}
const parsed = geoBaseNetworkLines(`IP-CIDR,192.0.2.0/24,DIRECT
IP-CIDR6,2001:db8::/32,proxy-active
198.51.100.7
2001:db8::1
DOMAIN-SUFFIX,example.com,DIRECT
192.0.2.999
192.0.2.0/24 trailing`);
const expected = ['192.0.2.0/24','2001:db8::/32','198.51.100.7','2001:db8::1'];
if (JSON.stringify(parsed) !== JSON.stringify(expected)) throw new Error(JSON.stringify(parsed));
"""
    result = subprocess.run(["node", "-e", program], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return (result.stderr or result.stdout).strip()
    return None


def verify_dead_server_projection(html_text: str) -> str | None:
    try:
        projection = js_function(html_text, "profileGroupDescriptors")
    except ValueError as error:
        return str(error)
    program = f"""
const DEAD_SERVERS_GROUP_KEY = 'virtual:dead-servers';
{projection}
const input = [
  {{id:1,group:'Дохлые серверы',dead:false}},
  {{id:2,group:'subscription-a',dead:true}},
  {{id:3,group:'subscription-a',dead:false}}
];
const groups = profileGroupDescriptors(input);
const virtual = groups.find(group => group.key === DEAD_SERVERS_GROUP_KEY);
const realNamed = groups.find(group => group.source === 'Дохлые серверы');
if (!virtual || virtual.items.length !== 1 || virtual.items[0].id !== 2) throw new Error('bad virtual group');
if (!realNamed || realNamed.dead || realNamed.items[0].id !== 1) throw new Error('real group collision');
if (input[1].group !== 'subscription-a') throw new Error('profile provenance mutated');
"""
    result = subprocess.run(["node", "-e", program], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return (result.stderr or result.stdout).strip()
    return None


def main() -> int:
    html_text = HTML.read_text(encoding="utf-8")
    missing_markers = [marker for marker in REQUIRED_MARKERS if marker not in html_text]
    forbidden_markers = [marker for marker in FORBIDDEN_MARKERS if marker in html_text]
    missing_system_ids = [dom_id for dom_id in SYSTEM_DOM_IDS if not dom_id_exists(html_text, dom_id)]
    missing_dead_server_ids = [dom_id for dom_id in DEAD_SERVERS_DOM_IDS if not dom_id_exists(html_text, dom_id)]
    missing_geobase_ids = [dom_id for dom_id in GEOBASE_DOM_IDS if not dom_id_exists(html_text, dom_id)]
    duplicate_geobase_ids = [dom_id for dom_id in GEOBASE_DOM_IDS if dom_id_count(html_text, dom_id) > 1]
    nav = nav_sections(html_text)
    panels = panel_sections(html_text)
    nav_map = nav_map_sections(html_text)
    nav_without_panel = sorted(nav - panels)
    nav_without_map = sorted(nav - nav_map)
    map_without_panel = sorted(nav_map - panels)
    served = served_routes()
    used = ui_routes()
    missing_geobase_routes = sorted(GEOBASE_UI_ROUTES - used)
    missing_routes = sorted(used - served)
    missing_routes = [(method, path) for method, path in missing_routes if not path.endswith("/")]
    sort_error = verify_nullable_sort(html_text)
    geobase_parser_error = verify_geobase_network_parser(html_text)
    dead_server_projection_error = verify_dead_server_projection(html_text)
    rule_target_markup = re.search(r'<select id="ruleTarget">(?P<body>.*?)</select>', html_text, re.S)
    numeric_profile_targets = re.findall(r"profile:\d+", rule_target_markup.group("body") if rule_target_markup else "")
    if missing_markers or forbidden_markers or numeric_profile_targets or missing_system_ids or missing_dead_server_ids or missing_geobase_ids or duplicate_geobase_ids or missing_geobase_routes or nav_without_panel or nav_without_map or map_without_panel or missing_routes or sort_error or geobase_parser_error or dead_server_projection_error:
        if missing_markers:
            print("Missing required UI markers:")
            for marker in missing_markers:
                print(f"  - {marker}")
        if forbidden_markers:
            print("Forbidden heavyweight auto-refresh markers found:")
            for marker in forbidden_markers:
                print(f"  - {marker}")
        if numeric_profile_targets:
            print("Legacy numeric profile UI targets found:")
            for marker in sorted(set(numeric_profile_targets)):
                print(f"  - {marker}")
        if missing_system_ids:
            print("System renderer writes to missing DOM ids:")
            for dom_id in missing_system_ids:
                print(f"  - {dom_id}")
        if missing_dead_server_ids:
            print("Dead Servers controls are missing required DOM ids:")
            for dom_id in missing_dead_server_ids:
                print(f"  - {dom_id}")
        if missing_geobase_ids:
            print("GeoBase Constructor is missing required DOM ids:")
            for dom_id in missing_geobase_ids:
                print(f"  - {dom_id}")
        if duplicate_geobase_ids:
            print("Experimental routing controls have duplicate DOM ids:")
            for dom_id in duplicate_geobase_ids:
                print(f"  - {dom_id}")
        if missing_geobase_routes:
            print("GeoBase Constructor is missing required API calls:")
            for method, path in missing_geobase_routes:
                print(f"  - {method} {path}")
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
        if sort_error:
            print(f"Nullable profile sorting contract failed: {sort_error}")
        if geobase_parser_error:
            print(f"GeoBase network parser contract failed: {geobase_parser_error}")
        if dead_server_projection_error:
            print(f"Dead Servers virtual projection contract failed: {dead_server_projection_error}")
        return 1
    print(f"frontend contract ok: {len(used)} UI routes checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
