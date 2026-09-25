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
    routes = {
        (method, path)
        for method, path in re.findall(r'\("(GET|POST)",\s*"([^"]+)"\)\s*=>', text)
    }
    if 'path.strip_prefix("/api/profiles/")' in text:
        routes.add(("GET", "/api/profiles/{id}"))
    return routes


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
    if "api('GET','/api/profiles/'+profileId" in text:
        routes.add(("GET", "/api/profiles/{id}"))
    return routes


REQUIRED_MARKERS = [
    "globalSearchInput",
    "/api/mihomo-config/validate",
    "/api/diagnostics/dns",
    "/api/diagnostics/udp-quic",
    "/api/diagnostics/direct-availability",
    "/api/telegram-probe/status",
    "/api/telegram-probe/request-code",
    "/api/telegram-probe/confirm",
    "/api/telegram-probe/delete",
    "v1.3.28",
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
    'id="benchConcurrency"',
    'id="benchConcurrency" data-native-select="1"',
    'label for="benchConcurrency"',
    'id="benchSearchTarget" type="number" min="1" max="20" step="1" value="5"',
    'id="benchSearchServices" data-native-select="1"',
    '<option value="youtube">YT</option><option value="telegram">YT+TG</option><option value="ai">YT+TG+AI</option>',
    'id="benchSearchAll"',
    'id="benchDetails"',
    'id="benchAdvancedParameters"',
    'id="benchAdvancedSearch" onclick="startServerSearch({advanced:true})"',
    'id="benchNativeCompatibility"',
    'id="benchResultStatus"',
    'id="benchSearchSelected"',
    'id="benchSearchStopMode" data-native-select="1"',
    'id="benchSearchFailFast"',
    'Стоп после сбоя YT/TG',
    'Stop after YT/TG failure',
    'Services and stop after failure are shared by all checks',
    "required_services:'all',fail_fast:false",
    'body.service_checks = {required_services,fail_fast}',
    'Even if all ping checks fail, YouTube is still tested',
    'Ping failure alone does not prove unreachability',
    'id="benchSelectionSearchHelp"',
    'id="benchConcurrencyStatus"',
    'id="benchConcurrencyHelp"',
    'YouTube channel and thumbnails (contract 1) run in parallel across admitted workers',
    'Each candidate has its own private temporary core and files; decoder limits are unchanged',
    'Native YouTube (contract 7) and the shared Telegram session remain serialized',
    'Ordinary explicit-policy checks require min(requested, candidates) workers or HTTP 503',
    '4 workers need an estimated 272 MiB available memory',
    'id="benchSearchPartialHelp"',
    'id="benchSearchHelp"',
    'id="benchYouTubeHelp"',
    'only the @MrBeast channel page and 3 thumbnails',
    'not video playback',
    'id="benchSearchStatus"',
    'id="benchInconclusiveStatus"',
    'id="benchInconclusive"',
    'id="benchPreflightDiagnostics"',
    'id="benchPreflightFailures"',
    'function hasInconclusiveTests(resourceTests)',
    'function renderBenchDiagnostics(data)',
    'function boundedDiagnosticText(value, maxBytes = 2048)',
    'data?.summary?.inconclusive',
    'data.preflight_failures.slice(-20)',
    '.profile-service-test.unknown{color:var(--warning)',
    'function startServerSearch(scope)',
    'function syncServerSearchParameters(changed)',
    'function renderBenchConcurrencyStatus(data)',
    'data?.concurrency_status',
    'data?.requested_concurrency',
    "limit_reasons.slice(0,3)",
    "hr_search_",
    'function renderBenchSearchStatus(data)',
    'search.preflight_completed',
    'search.preflight_rejected',
    'search.quick_completed',
    'search.found_good',
    'search.finish_reason',
    "concurrency: benchConcurrency()",
    "function normalizeBenchConcurrency(value)",
    "localStorage.getItem('hr_bench_concurrency')",
    'id="benchPromoteSuccessful"',
    'id="benchNativePostActionsLabel"',
    'Нативные пост-действия (совместимость)',
    'Native post-actions (compatibility)',
    'settings apply to legacy native tests; thumbnail checks do not trigger them',
    'both complete scope and N servers, never triggers server promotion, movement to Dead Servers, or AutoSelect',
    'YouTube @MrBeast channel page and 3 thumbnails, Telegram media, and the AI Studio region',
    'id="benchAutoMoveNoPing"',
    "function loadProfileTestSettings()",
    "function saveProfileTestSettings()",
    "promote_successful_tested_servers",
    "auto_move_no_ping_to_dead_servers",
    "api('GET','/api/bench/settings')",
    "apiAction('POST','/api/bench/settings'",
    "active_profiles",
    'data-bench-scope="single"',
    'function benchGroup(ids)',
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
    "function profileServiceTestsHtml(resourceTests, serviceTimestamp, now = Math.floor(Date.now()/1000))",
    "profileServiceTestsHtml(p.resource_tests,p.last_service_test_unix)",
    "function isCurrentSearchResourceTest(test)",
    "function hasCurrentThumbnailTest(resourceTests)",
    "resourceTests.filter(isCurrentSearchResourceTest)",
    "profile-service-test ${inconclusive?'unknown':skipped?'skipped':ok?'ok':'bad'}",
    "[['youtube_thumbnails','YT'],['telegram','TG'],['ai','AI']]",
    "startsWith('ping_')",
    "last_service_test_success: !hasCurrentThumbnailTest(resource_tests) || hasInconclusiveTests(resource_tests) ? null : st.last_service_test_success ?? null",
    "function toggleProfileMetricSettings(event)",
    "hr_profile_metrics",
    "data-profile-metric=\"latency\"",
    "const resource_tests = Array.isArray(st.resource_tests)",
    "Домены из списка всегда идут через VPN",
    "🚂 Паровозик",
    "id=\"rParovozikEnabled\"",
    "id=\"rParovozikWagons\"",
    "parovozik_enabled: document.getElementById('rParovozikEnabled')?.checked === true",
    "parovozik_server_refs: [...parovozikSelectedRefs]",
    "function renderParovozikServers(selectedRefs)",
    "function toggleParovozikWagon(serverRef)",
    "function saveParovozikConsist()",
    'id="rParovozikConsist"',
    "Сохранить состав вагонов",
    "const subscription = subscriptionForGroup(group);",
    "subscription?.title || shortGroupName(group || t('Без группы'))",
    "!server.active && !server.dead && server.ref",
    "let parovozikConsistDirty = false;",
    "if (!parovozikConsistDirty) renderParovozikServers(sr.parovozik_server_refs);",
    "Паровозик Direct",
    "Паровозик VPN",
    "id=\"torrentSocksCard\"",
    "id=\"rTorrentSocksEnabled\"",
    "id=\"rTorrentSocksListen\"",
    "id=\"rTorrentSocksPassword\" type=\"password\"",
    "id=\"rTorrentSocksPasswordLength\"",
    "function updateTorrentSocksPasswordHint()",
    "new TextEncoder().encode(password).length",
    "id=\"rTorrentSocksTarget\" data-routing-target-select=\"1\"",
    "const torrentSettings = {",
    "if (torrentPassword) torrentSettings.password = torrentPassword;",
    "body.torrent_socks = torrentSettings;",
    "const torrent = sr.torrent_socks || {};",
    "safeValue('rTorrentSocksPassword', '');",
    "torrent.password_set ? t('Пароль настроен') : t('Пароль не настроен')",
    "id=\"rTorrentSocksClear\"",
    "авторизация панели не требуется",
    "function clearTorrentSocksCredentials()",
    "torrent_socks:{enabled:false,clear_credentials:true}",
    "function refreshTorrentSocksTargetSelect(selectedTarget)",
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
    "/api/routing/resource-reload",
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
    "data-testid=\"connections-action\" data-routing-target-select=\"1\" data-searchable-select=\"1\"",
    "select:not([data-native-select]):not([data-custom-select-enhanced])",
    "select.dataset.nativeSelect",
    "function routeConnectionResource(select)",
    "const resource = String(select?.dataset?.resource || '').trim();",
    "onclick=\"reloadConnectionResource(this)\"",
    "function reloadConnectionResource(button)",
    "const resource = String(button?.dataset?.resource || '').trim();",
    "api('POST','/api/routing/resource-reload',request)",
    "function connectionRoutingSelectOpen()",
    "if (connectionRoutingEditorActive()) {",
    "function populateCustomSelectMenu(select, shell, menu)",
    "routing-target-dialog",
    "function routingEditActive()",
    "function flushDeferredRoutingReload()",
    "if (!options.force && routingEditActive())",
    "function deleteRoutingRule(idx)",
    "onclick=\"deleteRoutingRule(${i})\"",
    "data-searchable-select=\"1\"",
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
    "data-testid=\"profile-editor-modal\"",
    'id="profileEditorRaw" class="mono profile-secret-mask" rows="6" maxlength="65536"',
    'id="profileEditorSave" type="submit" disabled',
    "api('GET','/api/profiles/'+profileId,undefined,true)",
    "api('POST','/api/profiles/update',payload)",
    "expected_server_ref:state.expectedServerRef",
    "if (!state.subscriptionManaged) payload.raw = raw;",
    "profileEditorState = null;",
    "safeValue('profileEditorRaw','');",
    "function clearProfileEditorSensitiveState()",
    "window.addEventListener('pagehide', clearProfileEditorSensitiveState);",
    "function normalizedProfileGroup(group)",
    "function normalizedSubscriptionUrl(value)",
    "const {raw:_raw,...safeProfile} = p;",
    "data-testid=\"revalidate-ungrouped\"",
    "source === null",
    "api('POST','/api/profiles/revalidate-ungrouped',{})",
    "apiAction('POST','/api/subscriptions/refresh-one',{url}",
    "function openFormDialog(",
    "function enhanceResponsiveTables(",
    "function previewAndApplyRouting()",
    "function loadOperationalSafety()",
    "function explainConnectionResource(button)",
    "sessionStorage.getItem('hincyray_token')",
    "deadServerBulk",
    "const DEAD_SERVERS_GROUP_KEY = 'virtual:dead-servers';",
    "const selectedServerRefs = new Set();",
    "function profileGroupDescriptors(data, subscriptions",
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
    'id="featSave"',
    'id="featSave" onclick="saveFeatures()" disabled',
    'id="featRuntimeGeoLoader"',
    'id="featRuntimeStoreFakeIp"',
    'id="featRuntimeUdp"',
    'id="featRuntimeEcAddress"',
    'id="featRuntimeEcConnected"',
    'id="featPerProxyTfo"',
    'id="featDnsPreferH3"',
    'id="featSnifferForceDomain"',
    "if (section === 'features') loadFeatures();",
    "api('POST','/api/mihomo-features',{parameters})",
    "setFeatureParameters(data.parameters || {});",
    "setFeatureRuntime(data.runtime || {});",
    "'Не задано':'Not set'",
    "if (featuresLoading || (!force && featuresLoaded)) return Promise.resolve();",
    "setFeaturesDirty(false);",
    "throw new Error(`${t(label)}: ${t('некорректная строка')} ${index + 1}`)",
    "function startProfileLogger()",
    "if (!sourceIp) { showToast('error',t('Укажите IP устройства')); return; }",
    "payload.source_ip = sourceIp",
    "function stopProfileLoggerPolling()",
    "profileLoggerPollTimer = setInterval(pollProfileLoggerStatus, 2000)",
    "api('POST','/api/profile-diagnostics/start',payload)",
    "api('POST','/api/profile-diagnostics/stop',{session_id:sessionId})",
    "api('GET','/api/profile-diagnostics/status',undefined,true)",
    "api('POST','/api/profile-diagnostics/report',{session_id:sessionId},true)",
    "report.session_id !== expectedSessionId",
    "api('POST','/api/profile-diagnostics/discard',payload)",
    "new Blob([profileLoggerReport.markdown]",
]

FORBIDDEN_MARKERS = [
    'These actions apply only after a complete, non-cancelled complete-scope check',
    'Вся область: все текущие проверки Ping+YT+TG+AI',
    'Остановить проверки сервера при первом сбое',
    'First failure stops checks for that server',
    'id="benchFullAll"',
    'id="benchQuickSelected"',
    'id="benchFindAll"',
    'id="benchFindSelected"',
    'function quickBenchSelected(',
    'function fullBenchAll(',
    'function findBenchServers(',
    'function startBenchWithIds(',
    'function startBenchScope(',
    'function quickTestTrash(',
    'function quickTestAllTrash(',
    'data-profile-metric="download"',
    'data-profile-metric="upload"',
    'data-profile-metric="ewma"',
    'data-profile-metric="jitter"',
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
    "if (s.split_routing) updateRoutingForm(s.split_routing)",
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
    "function editProfileName(",
    "profileEditorState.raw",
    'id="featPgEnabled"',
    'id="featEcSecret"',
    'id="featNtpEnabled"',
    'id="featAuth"',
    'id="featSubRules"',
    'id="featRawRules"',
    'id="typedRulesList"',
    'id="proxyProvidersList"',
    'id="ruleProvidersList"',
    "function featureControl(",
    "function addProxyProvider(",
    "function addRuleProvider(",
    "function addTypedRule(",
    "api('GET','/api/mihomo-features',undefined,true).catch",
    "dns_fallback_filter:",
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

PROFILE_LOGGER_DOM_IDS = [
    "profileLoggerProfile",
    "profileLoggerDuration",
    "profileLoggerSourceIp",
    "profileLoggerStart",
    "profileLoggerStop",
    "profileLoggerDiscard",
    "profileLoggerState",
    "profileLoggerElapsed",
    "profileLoggerRemaining",
    "profileLoggerConnections",
    "profileLoggerEvents",
    "profileLoggerTruncation",
    "profileLoggerReportPanel",
    "profileLoggerSummary",
    "profileLoggerMarkdown",
    "profileLoggerCopy",
    "profileLoggerSave",
]

PROFILE_LOGGER_UI_ROUTES = {
    ("POST", "/api/profile-diagnostics/start"),
    ("GET", "/api/profile-diagnostics/status"),
    ("POST", "/api/profile-diagnostics/stop"),
    ("POST", "/api/profile-diagnostics/report"),
    ("POST", "/api/profile-diagnostics/discard"),
}


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
        projection = "\n".join(
            js_function(html_text, name)
            for name in ("normalizedProfileGroup", "normalizedSubscriptionUrl", "profileGroupDescriptors")
        )
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


def verify_reduced_mihomo_features(html_text: str) -> str | None:
    try:
        save = js_function(html_text, "saveFeatures")
        parameters = js_function(html_text, "featureParametersFromControls")
    except ValueError as error:
        return str(error)
    forbidden_save_markers = (
        "api('GET','/api/mihomo-features'",
        "/api/routing/apply",
        "dnsSniffOverride",
        "proxy_group",
        "external_controller",
        "authentication",
        "proxy_providers",
        "rule_providers",
        "raw_rules",
        "typed_rules",
    )
    found = [marker for marker in forbidden_save_markers if marker in save or marker in parameters]
    if found:
        return "legacy/save fields found: " + ", ".join(found)
    if "let parameters;" not in save or "{parameters}" not in save:
        return "POST body is not the reduced parameters envelope"
    return None


def verify_discovery(html_text: str) -> str | None:
    try:
        start = "\n".join(js_function(html_text, name) for name in ("startServerSearch", "benchOne", "benchGroup", "benchSubscription"))
        poll = js_function(html_text, "pollBenchStatus")
        update = js_function(html_text, "updateBenchStatus")
    except ValueError as error:
        return str(error)
    if "if (benchPollInFlight)" not in poll or "setInterval" in poll:
        return "discovery must reuse single-flight benchmark polling"
    if "!data?.search && !running && results.length && isGroup" not in update:
        return "discovery must not show the generic passed/failed summary"
    sidebar_progress = html_text.split('id="benchProgress"', 1)[1].split('id="longOperationProgress"', 1)[0]
    details = html_text.split('id="benchDetails"', 1)[1].split('<h3', 1)[0]
    for dom_id in ("benchSearchStatus", "benchConcurrencyStatus", "benchConcurrencyHelp", "benchSearchPartialHelp", "benchInconclusiveStatus", "benchSummary", "benchPreflightDiagnostics"):
        if f'id="{dom_id}"' in sidebar_progress or f'id="{dom_id}"' not in details:
            return "technical service diagnostics must live in collapsed Profiles details, not the sidebar"
    concurrency_help = details.split('id="benchConcurrencyHelp"', 1)[1].split('</p>', 1)[0]
    for marker in ("Канал и превью YouTube (контракт 1) проверяются параллельно", "общая сессия Telegram", "контракт 7", "лимиты декодера прежние", "min(запрошено, кандидаты)", "HTTP 503", "272 МиБ доступной памяти"):
        if marker not in concurrency_help:
            return "collapsed concurrency help must distinguish parallel thumbnails, serialized native/session probes, and exact memory admission"
    if "YouTube и Telegram выполняются последовательно" in html_text or "YouTube and Telegram are serialized:" in html_text:
        return "concurrency help must not describe thumbnail checks as serialized"
    program = f"""
const controls = {{benchSearchStopMode:{{value:'complete_scope'}},benchSearchFailFast:{{checked:false}},benchSearchTarget:{{value:'5'}},benchSearchServices:{{value:'all'}}}};
const document = {{getElementById:id => controls[id]}};
let posted = [], errors = [], selected = [];
let benchResultFingerprint, benchWasRunning;
const window = {{benchIsGroup:true}};
const MOCK = {{profiles:[{{id:42,dead:false}},{{id:43,dead:true}}]}};
const t = text => text;
const showToast = (kind, text) => errors.push(text);
const selectedProfiles = () => selected;
const benchConcurrency = () => 4;
const renderBenchConcurrencyStatus = () => {{}};
const pollBenchStatus = () => {{}};
const api = (method, path, body) => {{
  if (method !== 'POST' || path !== '/api/bench/start') throw new Error('unexpected API');
  posted.push(body);
  return Promise.resolve({{}});
}};
// Primary scopes retain full availability intent, with explicit shared policy and no discovery.
const assertPolicy = (body, services, failFast) => {{
  if (body.method !== 'availability_full' || 'search' in body || JSON.stringify(body.service_checks) !== JSON.stringify({{required_services:services,fail_fast:failFast}})) throw new Error('explicit full-scope service policy');
}};
{start}
startServerSearch();
if (JSON.stringify(posted[0]) !== JSON.stringify({{method:'availability_full',concurrency:4,test_download:false,test_upload:false,service_checks:{{required_services:'all',fail_fast:false}}}})) throw new Error('default complete-scope body');
controls.benchSearchFailFast.checked = true;
startServerSearch();
assertPolicy(posted.at(-1),'all',true);
startServerSearch({{advanced:true}});
assertPolicy(posted.at(-1),'all',true);
selected = [{{id:42,dead:false}},{{id:43,dead:true}}];
startServerSearch({{selected:true}});
if (posted.at(-1).method !== 'availability_full' || posted.at(-1).profile_ids.join(',') !== '42,43') throw new Error('explicit selection full-scope intent');
controls.benchSearchStopMode.value = 'find_n';
controls.benchSearchServices.value = 'youtube';
startServerSearch();
assertPolicy(posted.at(-1),'youtube',true);
startServerSearch({{advanced:true}});
if (posted.at(-1).method !== 'availability_quick' || posted.at(-1).search.required_services !== 'youtube' || posted.at(-1).search.fail_fast !== true || 'service_checks' in posted.at(-1)) throw new Error('explicit discovery policy');
for (const service of ['all','youtube','telegram','ai']) {{
  controls.benchSearchServices.value = service;
  for (const failFast of [false,true]) {{
    controls.benchSearchFailFast.checked = failFast;
    for (const scope of [{{}},{{selected:true}},{{profile_ids:[42]}},{{profile_ids:[42,43]}},{{profile_ids:[43],diagnostic:true}},{{subscription_url:'https://provider.example/sub/<token>'}}]) {{
      startServerSearch(scope);
      assertPolicy(posted.at(-1),service,failFast);
      if (posted.at(-1).concurrency !== 4) throw new Error('requested concurrency changed');
    }}
    startServerSearch({{advanced:true}});
    if (JSON.stringify(posted.at(-1).search) !== JSON.stringify({{target_good:5,required_services:service,fail_fast:failFast}}) || 'service_checks' in posted.at(-1)) throw new Error('advanced prefix/fail-fast policy');
  }}
}}
let count = posted.length;
for (const value of ['', '0', '21', '1.5', '-1']) {{
  controls.benchSearchTarget.value = value;
  startServerSearch({{advanced:true}});
}}
if (posted.length !== count || errors.length !== 5) throw new Error('target bounds');
controls.benchSearchTarget.value = '20';
controls.benchSearchServices.value = 'invalid';
startServerSearch({{advanced:true}});
if (posted.length !== count) throw new Error('service validation');
controls.benchSearchServices.value = 'ai';
selected = [];
startServerSearch({{selected:true}});
selected = [{{id:43,dead:true}}];
startServerSearch({{selected:true}});
if (posted.at(-1).profile_ids.join(',') !== '43' || posted.at(-1).method !== 'availability_full' || 'search' in posted.at(-1)) throw new Error('explicit dead selection became discovery');
count = posted.length;
for (const ids of [[], undefined, null, ['42'], [-1]]) benchGroup(ids);
benchSubscription(undefined);
startServerSearch({{subscription_url:''}});
startServerSearch({{selected:true,profile_ids:[42]}});
startServerSearch({{subscription_url:'https://provider.example/sub/<token>',profile_ids:[42]}});
if (posted.length !== count) throw new Error('scope/count guards');
benchOne(42);
if (posted.at(-1).profile_ids.join(',') !== '42' || posted.at(-1).method !== 'availability_full' || 'search' in posted.at(-1)) throw new Error('single scope');
benchGroup([42,43]);
if (posted.at(-1).profile_ids.join(',') !== '42,43' || posted.at(-1).method !== 'availability_full' || 'search' in posted.at(-1)) throw new Error('complete explicit group');
benchSubscription('https://provider.example/sub/<token>');
if (posted.at(-1).subscription_url !== 'https://provider.example/sub/<token>' || posted.at(-1).method !== 'availability_full' || 'search' in posted.at(-1) || 'profile_ids' in posted.at(-1)) throw new Error('subscription scope');
controls.benchSearchTarget.value = '';
controls.benchSearchServices.value = 'ai';
controls.benchSearchFailFast.checked = false;
benchOne(43);
startServerSearch({{profile_ids:[43],diagnostic:true}});
if (posted.slice(-2).some(body => body.method !== 'availability_full' || 'search' in body || body.profile_ids.join(',') !== '43')) throw new Error('dead diagnostics retain full-scope intent');
posted.slice(-2).forEach(body => assertPolicy(body,'ai',false));
controls.benchSearchFailFast.checked = true;
startServerSearch({{profile_ids:[43],diagnostic:true}});
assertPolicy(posted.at(-1),'ai',true);
for (const mode of ['find_n','unsupported']) {{
  controls.benchSearchStopMode.value = mode;
  controls.benchSearchTarget.value = '0';
  controls.benchSearchServices.value = 'youtube';
  startServerSearch();
  assertPolicy(posted.at(-1),'youtube',true);
}}
count = posted.length;
controls.benchSearchServices.value = 'invalid';
startServerSearch();
benchOne(43);
if (posted.length !== count) throw new Error('primary service policy validation missing');
controls.benchSearchStopMode.value = 'find_n';
controls.benchSearchTarget.value = '5';
controls.benchSearchServices.value = 'all';
count = posted.length;
for (const scope of [{{profile_ids:[42]}},{{subscription_url:'https://provider.example/sub/<token>'}},{{selected:true}},{{selected:false}},{{diagnostic:true}},{{diagnostic:false}}]) {{
  startServerSearch({{...scope,advanced:true}});
}}
for (const advanced of [false,'true',1,null]) startServerSearch({{advanced}});
if (posted.length !== count) throw new Error('ambiguous advanced/scoped request accepted');
if (window.benchIsGroup !== true) throw new Error('presentation changed before start acceptance');
"""
    result = subprocess.run(["node", "-e", program], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return (result.stderr or result.stdout).strip()
    return None


def verify_inconclusive_diagnostics(html_text: str) -> str | None:
    try:
        functions = "\n".join(js_function(html_text, name) for name in (
            "isCurrentSearchResourceTest", "hasCurrentThumbnailTest", "hasInconclusiveTests", "searchResourceEvidence", "isFreshServiceTest", "profileServiceTestsHtml", "profileResultRank", "profileSuccessfulChecks", "profilePingMs", "getSortValue", "applyProfileSort",
            "boundedDiagnosticText", "renderBenchDiagnostics",
            "mergeBenchResultsIntoProfiles", "overlayAvailabilityEvidence", "normalizeProfiles",
        ))
        for name in ("attrEscape", "htmlEscape"):
            match = re.search(rf"function {name}\([^\n]*\) \{{\n.*?\n\}}", html_text, re.S)
            if not match:
                raise ValueError(f"missing escaping helper {name}")
            functions += "\n" + match.group(0)
        update = js_function(html_text, "updateBenchStatus")
    except ValueError as error:
        return str(error)
    if "results.filter(r => !hasInconclusiveTests(r.resource_tests))" not in update:
        return "inconclusive jobs must be excluded from passed and failed counts"
    for name in ("mergeBenchResultsIntoProfiles", "overlayAvailabilityEvidence"):
        if "last_checked" in js_function(html_text, name):
            return "resource freshness must never use the generic health timestamp"
    program = f"""
const t = text => text;
const PREVIEW_MODE = false;
let profileSortState = {{key:'results',dir:'desc'}};
const elements = Object.fromEntries(['benchInconclusive','benchInconclusiveStatus','benchPreflightDiagnostics','benchPreflightFailures'].map(id => [id,{{style:{{}},textContent:'',innerHTML:''}}]));
const document = {{getElementById:id => elements[id]}};
const safeSet = (id,text) => {{ if (elements[id]) elements[id].textContent = text; }};
const MOCK = {{profiles:[{{id:42,server_ref:'srv-v2-fixture',last_service_test_success:true}}]}};
let benchResultFingerprint = '', renders = 0;
const benchAvailabilityEvidence = new Map();
const renderProfiles = () => renders++;
{functions}
const resource = {{contract_version:1,id:'youtube_thumbnails',name:'YouTube channel/thumbnails',attempts:1,successes:1,stable:true,inconclusive:false}};
const result = {{profile_id:42,server_ref:'srv-v2-fixture',method:'availability_quick',timestamp:1,success:true,latency_ms:100,resource_tests:[resource]}};
mergeBenchResultsIntoProfiles([result]);
resource.inconclusive = true;
resource.error = 'HTTP 200: LOGIN_REQUIRED <img src=x>';
mergeBenchResultsIntoProfiles([result]);
if (renders !== 2 || MOCK.profiles[0].last_service_test_success !== null) throw new Error('unknown transition/legacy success');
result.success = false;
mergeBenchResultsIntoProfiles([result]);
if (MOCK.profiles[0].last_service_test_success !== null) throw new Error('legacy false is not an inconclusive failure');
for (const attempts of [0,1]) {{
  resource.attempts = attempts;
  const badge = profileServiceTestsHtml([resource],1,1);
  if (!badge.includes('profile-service-test unknown') || badge.includes('profile-service-test ok') || badge.includes('profile-service-test bad') || badge.includes('<img')) throw new Error('unknown badge priority/escaping');
}}
if (profileSuccessfulChecks({{resource_tests:[resource],last_service_test_unix:Math.floor(Date.now()/1000)}}) !== 0) throw new Error('unknown ranked as a successful check');
if (!profileServiceTestsHtml([{{...resource,contract_version:6}}]).includes('Устаревший результат; требуется новая проверка')) throw new Error('obsolete v6 outcome not neutral');
for (const native of [{{...resource,id:'youtube',contract_version:7}},{{...resource,contract_version:7}},{{...resource,contract_version:2}}]) {{
  const badges = profileServiceTestsHtml([native],Math.floor(Date.now()/1000));
  if (isCurrentSearchResourceTest(native) || hasCurrentThumbnailTest([native]) || (badges.match(/profile-service-test (?:skipped|stale)/g) || []).length !== 3 || badges.includes('profile-service-test ok') || profileSuccessfulChecks({{resource_tests:[native],last_service_test_unix:Math.floor(Date.now()/1000)}}) !== 0) throw new Error('native video or obsolete thumbnails used as availability evidence');
}}
if (!isCurrentSearchResourceTest({{id:'telegram',contract_version:7}}) || !isCurrentSearchResourceTest({{id:'ai',contract_version:7}})) throw new Error('native Telegram/AI contract lost');
mergeBenchResultsIntoProfiles([{{...result,method:'quick',resource_tests:[{{id:'youtube',contract_version:7,stable:true}}]}}]);
if (MOCK.profiles[0].resource_tests[0].id !== 'youtube_thumbnails') throw new Error('native cache overwrote thumbnail evidence');
const olderProfile = {{id:42,server_ref:'srv-v2-fixture',last_checked:300,last_service_test_unix:0,resource_tests:[]}};
overlayAvailabilityEvidence([olderProfile]);
if (olderProfile.resource_tests[0]?.id !== 'youtube_thumbnails' || olderProfile.last_service_test_success !== null) throw new Error('older refresh erased current availability evidence');
const reusedProfile = {{id:42,server_ref:'srv-v2-replacement',resource_tests:[]}};
overlayAvailabilityEvidence([reusedProfile]);
if (reusedProfile.resource_tests.length || benchAvailabilityEvidence.size) throw new Error('overlay rebound evidence to a reused ID');
MOCK.profiles = [reusedProfile];
mergeBenchResultsIntoProfiles([{{...result,timestamp:2}}]);
if (reusedProfile.resource_tests.length) throw new Error('retained result rebound to a reused ID');
const {{server_ref:ignored,...missingRef}} = result;
mergeBenchResultsIntoProfiles([{{...missingRef,timestamp:3,profile_name:'Same Name'}}]);
if (reusedProfile.resource_tests.length || benchAvailabilityEvidence.size) throw new Error('missing result ref attributed by ID/name');
const remapped = {{id:43,server_ref:result.server_ref,name:'Same Name',last_checked:300,last_service_test_unix:0,resource_tests:[]}};
const alias = {{id:44,server_ref:result.server_ref,name:'Same Name',resource_tests:[]}};
MOCK.profiles = [reusedProfile,remapped,alias];
mergeBenchResultsIntoProfiles([{{...result,profile_id:43,timestamp:3}}]);
if (remapped.resource_tests[0]?.id !== 'youtube_thumbnails' || alias.resource_tests.length || reusedProfile.resource_tests.length) throw new Error('public mapped ID/ref alias attribution');
mergeBenchResultsIntoProfiles([{{...result,profile_id:43,timestamp:2,resource_tests:[]}}]);
if (remapped.resource_tests[0]?.id !== 'youtube_thumbnails' || benchAvailabilityEvidence.get(43).timestamp !== 3) throw new Error('older result erased newer evidence');
const changedRef = {{...result,profile_id:42,server_ref:'srv-v2-unknown',timestamp:4}};
mergeBenchResultsIntoProfiles([changedRef]);
changedRef.server_ref = reusedProfile.server_ref;
mergeBenchResultsIntoProfiles([changedRef]);
if (reusedProfile.resource_tests[0]?.id !== 'youtube_thumbnails') throw new Error('result-ref fingerprint ignored');
const publicRef = 'srv-v2-00000000000000000000000000000050';
const metadata = {{profiles:[{{id:50,server_ref:publicRef}}]}};
const preview = {{id:'youtube_thumbnails',contract_version:1,attempts:1,successes:1,stable:true}};
const now = Math.floor(Date.now()/1000);
for (const timestamp of [undefined,null,0,-1,now-21601,now+61,Infinity,NaN]) {{
  if (isFreshServiceTest(timestamp,now)) throw new Error('invalid/stale clock accepted');
  const badges = profileServiceTestsHtml([preview],timestamp,now);
  if (!badges.includes('data-state="stale"') || badges.includes('profile-service-test ok') || badges.includes('profile-service-test bad')) throw new Error('stale thumbnail evidence rendered as current/failed');
}}
for (const timestamp of [now-21600,now,now+1,now+60]) {{
  if (!isFreshServiceTest(timestamp,now) || !profileServiceTestsHtml([preview],timestamp,now).includes('profile-service-test ok')) throw new Error('fresh clock boundary rejected');
}}
const stale = {{id:'stale',last_service_test_unix:now-7*86400,last_checked:now+86400,last_service_test_success:true,resource_tests:[preview]}};
const fresh = {{id:'fresh',last_service_test_unix:now,last_service_test_success:true,resource_tests:[preview]}};
if (profileSuccessfulChecks(stale) !== 0 || profileSuccessfulChecks(fresh) !== 1 || applyProfileSort([stale,fresh])[0].id !== 'fresh') throw new Error('stale service evidence counted/ranked as current');
if (!profileServiceTestsHtml([{{...preview,attempts:0}}],now,now).includes('data-state="skipped"') || !profileServiceTestsHtml([],0,now).includes('data-state="not-tested"')) throw new Error('skipped/not-tested distinction lost');
const stored = {{profile_id:50,server_ref:publicRef,last_checked:300,last_service_test_unix:100,resource_tests:[{{...preview,stable:false,successes:0}}]}};
for (const method of ['availability_quick','availability_full','search_availability']) {{
  benchAvailabilityEvidence.clear();
  MOCK.profiles = normalizeProfiles({{stats:[stored]}}, metadata);
  if (MOCK.profiles[0].last_service_test_unix !== 100) throw new Error('public service timestamp not normalized');
  mergeBenchResultsIntoProfiles([{{profile_id:50,server_ref:publicRef,timestamp:200,method,success:true,resource_tests:[preview]}}]);
  if (MOCK.profiles[0].resource_tests[0].stable !== true || MOCK.profiles[0].last_service_test_unix !== 200 || benchAvailabilityEvidence.get(50)?.timestamp !== 200) throw new Error('generic health timestamp suppressed service pass');
  const refreshed = normalizeProfiles({{stats:[{{...stored,last_checked:400}}]}}, metadata);
  overlayAvailabilityEvidence(refreshed);
  if (refreshed[0].resource_tests[0].stable !== true || refreshed[0].last_service_test_unix !== 200 || refreshed[0].last_checked !== 400 || benchAvailabilityEvidence.get(50).timestamp !== 200) throw new Error('generic health refresh replaced service evidence/time');
}}
for (const timestamp of [undefined,0]) {{
  benchAvailabilityEvidence.clear();
  MOCK.profiles = normalizeProfiles({{stats:[{{...stored,last_service_test_unix:timestamp}}]}}, metadata);
  overlayAvailabilityEvidence(MOCK.profiles);
  if (MOCK.profiles[0].last_service_test_unix !== 0 || benchAvailabilityEvidence.size) throw new Error('unknown source clock invented from health');
  for (const test of [{{id:'telegram',contract_version:7,attempts:1,stable:true}},{{id:'youtube',contract_version:7,attempts:1,stable:true}}]) {{
    mergeBenchResultsIntoProfiles([{{profile_id:50,server_ref:publicRef,timestamp:500,method:'availability_quick',success:true,resource_tests:[test]}}]);
    if (MOCK.profiles[0].last_service_test_unix !== 0 || benchAvailabilityEvidence.size) throw new Error('non-thumbnail result advanced service overlay clock');
  }}
}}
const longError = '<img src=x> https://provider.example/sub/<token> '+ '\u0416'.repeat(2200);
const bounded = boundedDiagnosticText(longError);
if (new TextEncoder().encode(bounded).length > 2048 || bounded.includes('\uFFFD')) throw new Error('UTF-8 diagnostic bound');
renderBenchDiagnostics({{results:[result],summary:{{inconclusive:1}},preflight_failures:Array.from({{length:25}},(_,i) => ({{profile_id:i,phase:'transport',error:longError,raw:'CANARY',username:'CANARY'}})),raw:'CANARY'}});
if (elements.benchInconclusive.textContent !== '1') throw new Error('unknown jobs double counted');
const diagnostics = elements.benchPreflightFailures.innerHTML;
if ((diagnostics.match(/<li>/g) || []).length !== 20 || diagnostics.includes('CANARY') || diagnostics.includes('<img') || !diagnostics.includes('#5 ')) throw new Error('diagnostic whitelist/bound/escaping');
renderBenchDiagnostics({{results:[],preflight_failures:[]}});
if (elements.benchPreflightDiagnostics.style.display !== 'none' || elements.benchPreflightFailures.innerHTML !== '') throw new Error('stale diagnostics');
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
    missing_profile_logger_ids = [dom_id for dom_id in PROFILE_LOGGER_DOM_IDS if not dom_id_exists(html_text, dom_id)]
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
    missing_profile_logger_routes = sorted(PROFILE_LOGGER_UI_ROUTES - used)
    missing_routes = sorted(used - served)
    missing_routes = [(method, path) for method, path in missing_routes if not path.endswith("/")]
    sort_error = verify_nullable_sort(html_text)
    geobase_parser_error = verify_geobase_network_parser(html_text)
    dead_server_projection_error = verify_dead_server_projection(html_text)
    mihomo_features_error = verify_reduced_mihomo_features(html_text)
    discovery_error = verify_discovery(html_text)
    inconclusive_error = verify_inconclusive_diagnostics(html_text)
    rule_target_markup = re.search(r'<select id="ruleTarget">(?P<body>.*?)</select>', html_text, re.S)
    numeric_profile_targets = re.findall(r"profile:\d+", rule_target_markup.group("body") if rule_target_markup else "")
    if missing_markers or forbidden_markers or numeric_profile_targets or missing_system_ids or missing_dead_server_ids or missing_profile_logger_ids or missing_geobase_ids or duplicate_geobase_ids or missing_geobase_routes or missing_profile_logger_routes or nav_without_panel or nav_without_map or map_without_panel or missing_routes or sort_error or geobase_parser_error or dead_server_projection_error or mihomo_features_error or discovery_error or inconclusive_error:
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
        if missing_profile_logger_ids:
            print("Profile Logger is missing required DOM ids:")
            for dom_id in missing_profile_logger_ids:
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
        if missing_profile_logger_routes:
            print("Profile Logger is missing required API calls:")
            for method, path in missing_profile_logger_routes:
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
        if mihomo_features_error:
            print(f"Reduced Mihomo features contract failed: {mihomo_features_error}")
        if discovery_error:
            print(f"Adaptive discovery contract failed: {discovery_error}")
        if inconclusive_error:
            print(f"Inconclusive outcome/diagnostics contract failed: {inconclusive_error}")
        return 1
    print(f"frontend contract ok: {len(used)} UI routes checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
