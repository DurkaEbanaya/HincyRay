import { readFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const webUiPath = path.resolve(fixtureDir, '../../src/webui/index.html');
const webUi = await readFile(webUiPath);
const port = Number(process.env.PLAYWRIGHT_FIXTURE_PORT || 4173);

const fixtureSubscriptionUrl = 'https://provider.example/sub/fixture-token';
const fixtureSecondSubscriptionUrl = 'https://provider.example/sub/second-token';
const profile = {
  id: 101,
  server_ref: 'srv-v2-fixture-subscription',
  name: 'Fixture Profile',
  protocol: 'VLESS',
  transport: 'tcp',
  address: 'fixture.proxy.test',
  port: 443,
  active: true,
  favorite: false,
  group: fixtureSubscriptionUrl,
  dead: false,
  block_quic: false,
};
const manualProfile = {
  id: 102,
  server_ref: 'srv-v2-fixture-manual',
  name: 'Fixture Manual',
  protocol: 'VLESS',
  transport: 'ws',
  address: '192.0.2.44',
  port: 8443,
  active: false,
  favorite: false,
  group: null,
  dead: false,
  block_quic: true,
};
const secondSubscriptionProfile = {
  ...manualProfile,
  id: 104,
  server_ref: 'srv-v2-fixture-second-subscription',
  name: 'Fixture Second Subscription',
  group: fixtureSecondSubscriptionUrl,
};
const profileDiagnosticSecretCanary = 'PROFILE-DIAGNOSTIC-SECRET-CANARY';
let profileDiagnostic = { active: null, completed: null, statusPolls: 0 };

function diagnosticStatus(session, state = 'running') {
  if (!session) return null;
  return {
    session_id: session.session_id,
    state,
    profile_id: profile.id,
    profile_name: profile.name,
    server_ref: profile.server_ref,
    started_at_unix: session.started_at_unix,
    deadline_unix: session.deadline_unix,
    completed_at_unix: state === 'running' ? null : session.started_at_unix + 8,
    finalization_reason: state === 'running' ? null : session.finalization_reason || 'stopped',
    connection_count: state === 'running' ? profileDiagnostic.statusPolls + 1 : 3,
    event_count: state === 'running' ? profileDiagnostic.statusPolls : 2,
  };
}

function diagnosticReport(session) {
  const markdown = `# Profile diagnostic: ${profile.name}\n\n- Session: ${session.session_id}\n- Profile ID: ${profile.id}\n- Source IP: ${session.source_ip}\n- Connections: 3\n- Events: 2\n- Errors: 1\n\n## Finding\nFixture TLS timeout while watching YouTube.\n`;
  return {
    session_id: session.session_id,
    purpose: 'active profile traffic diagnostics',
    state: 'completed',
    started_at_unix: session.started_at_unix,
    ended_at_unix: session.started_at_unix + 8,
    requested_duration_seconds: session.duration_seconds,
    observed_duration_seconds: 8,
    finalization_reason: session.finalization_reason || 'stopped',
    source_ip: session.source_ip,
    profile: {
      id: profile.id,
      server_ref: profile.server_ref,
      name: profile.name,
      protocol: profile.protocol,
      transport: profile.transport,
      address: profile.address,
      port: profile.port,
    },
    environment_start: {
      hincyray_version: 'fixture', mihomo_version: 'fixture', core_generation: 1,
      core_status: 'running', firewall_status: 'running', socks_port: 10808,
      mixed_port: 10809, redirect_port: 10810, tproxy_port: 10811, dns_port: 1053,
      memory: { hincyray_rss_kb: 1024, mihomo_rss_kb: 2048, system_available_kb: 262144 },
    },
    environment_end: {
      hincyray_version: 'fixture', mihomo_version: 'fixture', core_generation: 1,
      core_status: 'running', firewall_status: 'running', socks_port: 10808,
      mixed_port: 10809, redirect_port: 10810, tproxy_port: 10811, dns_port: 1053,
      memory: { hincyray_rss_kb: 1030, mihomo_rss_kb: 2050, system_available_kb: 262000 },
    },
    summary: {
      connections: 3, open_connections: 1, closed_connections: 2,
      upload_bytes: 1024, download_bytes: 8192, events: 2, poll_errors: 0,
      dropped_connections: 1, dropped_events: 0, failure_classifications: { tls_timeout: 1 },
    },
    connections: [{
      id: 'connection-1', domain: 'youtube.example', destination_ip: '203.0.113.30',
      destination_port: 443, network: 'tcp', rule: 'MATCH', rule_payload: '',
      chains: ['proxy-active', profile.name], upload_bytes: 1024, download_bytes: 8192,
      first_seen_unix: session.started_at_unix, last_seen_unix: session.started_at_unix + 5,
      open: false, source_ip: session.source_ip,
    }],
    events: [{ timestamp_unix: session.started_at_unix + 4, severity: 'error', message: 'TLS timeout', classification: 'tls_timeout' }],
    latest_stats: null,
    config_summary: 'Active profile only; secrets structurally redacted.',
    redaction_note: 'Keys and subscription URLs are not collected.',
    markdown,
  };
}
const initialProfileNames = new Map([[profile.id, profile.name], [manualProfile.id, manualProfile.name]]);
const initialProfileRaws = new Map([
  [profile.id, 'vless://subscription-secret@fixture.proxy.test:443?security=reality&type=tcp#Fixture'],
  [manualProfile.id, 'vless://manual-key@192.0.2.44:8443?encryption=none&security=tls&type=ws&host=hidden.example&path=%2Fsecret#Fixture-Manual'],
]);
const profileDetails = new Map([
  [profile.id, { ...profile, raw: initialProfileRaws.get(profile.id), subscription_managed: true }],
  [manualProfile.id, { ...manualProfile, raw: initialProfileRaws.get(manualProfile.id), subscription_managed: false }],
  [103, {
    id: 103, server_ref: 'srv-v2-fixture-xhttp', name: 'Fixture XHTTP', protocol: 'VLESS',
    transport: 'xhttp', address: 'xhttp.fixture.test', port: 443, active: false, favorite: false,
    group: null, dead: false, block_quic: false, subscription_managed: false,
    raw: 'vless://fixture-xhttp@xhttp.fixture.test:443?type=xhttp&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%2C%22scMaxEachPostBytes%22%3A%222048-2048%22%7D#Fixture-XHTTP',
    xhttp_tuning: { sc_max_each_post_bytes: '2048', sc_min_posts_interval_ms: null },
  }],
]);
const deadServerRef = 'srv-v2-fixture-dead';
let mihomoFeatures = {
  parameters: {
    unified_delay: true,
    store_selected: true,
    keep_alive_interval: 30,
    keep_alive_idle: 120,
    disable_keep_alive: false,
    tcp_concurrent: true,
    per_proxy: { tfo: false, mptcp: false, ip_version: 'dual' },
    dns: {
      prefer_h3: false,
      respect_rules: true,
      default_nameserver: ['1.1.1.1'],
      nameserver_policy: { 'geosite:private': ['192.168.1.1'] },
      proxy_server_nameserver_policy: { 'provider.example': ['1.0.0.1'] },
      direct_nameserver_follow_policy: true,
      fake_ip_filter_mode: 'blacklist',
      fake_ip_filter: ['*.lan', '*.local'],
      fake_ip_ttl: 60,
    },
    sniffer: {
      force_domain: ['+.netflix.com'],
      skip_domain: ['+.apple.com'],
      skip_src_address: ['192.168.0.0/16'],
      skip_dst_address: ['127.0.0.1/8'],
    },
    tunnels: [{ network: ['tcp'], address: '127.0.0.1:8080', target: 'fixture.test:80', proxy: null }],
    hosts: { 'local.test': '127.0.0.1' },
    experimental: { quic_go_disable_gso: false, quic_go_disable_ecn: true },
  },
  runtime: {
    geodata_loader: 'memconservative',
    store_fake_ip: true,
    udp: true,
    external_controller: { enabled: true, address: '127.0.0.1:9090', connected: true },
  },
};

const canonicalConnection = {
      id: 'canonical-chatgpt',
      metadata: {
        host: 'chatgpt.com',
        sourceIP: '192.0.2.10',
        destinationIP: '203.0.113.10',
        destinationPort: '443',
        destinationCountry: 'RU',
        network: 'tcp',
      },
      chains: ['proxy-active'],
      rule: 'DOMAIN-SUFFIX',
      rulePayload: 'chatgpt.com',
      upload: 1024,
      download: 8192,
    };
const unrelatedConnection = {
      id: 'unrelated-row',
      metadata: {
        host: 'example.net',
        sourceIP: '192.0.2.20',
        destinationIP: '203.0.113.20',
        destinationPort: '80',
        destinationCountry: 'US',
        network: 'tcp',
      },
      chains: ['DIRECT'],
      rule: 'MATCH',
      upload: 512,
      download: 2048,
    };
const connections = {
  connections: [
    unrelatedConnection,
    ...Array.from({ length: 649 }, (_, index) => ({
      id: `generated-${index}`,
      metadata: {
        host: `generated-${index}.example.net`,
        sourceIP: '192.0.2.20',
        destinationIP: `198.51.100.${index % 255}`,
        destinationPort: '443',
        destinationCountry: 'US',
        network: 'tcp',
      },
      chains: ['DIRECT'],
      rule: 'MATCH',
      upload: 1,
      download: 2,
    })),
    canonicalConnection,
    ...Array.from({ length: 51 }, (_, index) => ({
      id: `tail-${index}`,
      metadata: {
        host: `tail-${index}.example.org`,
        sourceIP: '192.0.2.30',
        destinationIP: `203.0.113.${index}`,
        destinationPort: '80',
        destinationCountry: 'DE',
        network: 'tcp',
      },
      chains: ['proxy-active'],
      rule: 'MATCH',
      upload: 3,
      download: 4,
    })),
  ],
};

const routing = {
  rules: [],
  managed_rules: [],
  conflicts: [],
  catalog: [],
  servers: [
    {
      ref: 'srv-v1-fixture',
      name: 'Fixture Profile',
      protocol: 'VLESS',
      address: 'fixture.proxy.test',
      group: fixtureSubscriptionUrl,
      active: true,
    },
    {
      ref: 'srv-v1-wagon',
      name: 'Fixture Wagon',
      protocol: 'VLESS',
      address: 'wagon.proxy.test',
      group: fixtureSubscriptionUrl,
      active: false,
      dead: false,
    },
  ],
  settings: {
    enabled: true,
    auto_switch: false,
    rule_source: 'fixture',
    vpn_subnet: '192.0.2.0/24',
    redirect_port: 10810,
    policy_name: 'Fixture',
    port_mode: 'all',
    proxy_ports: [],
    bypass_ports: [],
    ru_direct_mode: 'off',
    ru_direct_exceptions: [],
    auto_vpn_learning_enabled: false,
    auto_vpn_exceptions: [],
  },
};

const responses = new Map([
  ['/api/status', {
    core_status: 'running',
    active_profile_name: profile.name,
    active_profile_protocol: profile.protocol,
    profile_count: 2,
    listen_host: '127.0.0.1',
    socks_port: 10808,
    http_port: 10809,
    mihomo_version: 'fixture',
    split_routing: routing.settings,
  }],
  ['/api/system', {
    cpu: { usage_pct: 1, model: 'Fixture CPU', cores: 1, usage_per_core: [1] },
    memory: { usage_pct: 25, total_kb: 524288, available_kb: 393216 },
    load: { '1': 0, '5': 0, '15': 0 },
    uptime_secs: 3600,
    hostname: 'fixture-router',
    model: 'Fixture Router',
  }],
  ['/api/memory-guard', { mihomo: { pid: 100, rss_kb: 1024 }, top_processes: [], warnings: [] }],
  ['/api/stats', { stats: [{ profile_id: profile.id, last_latency_ms: 25, last_service_test_success: false, resource_tests: [
    { contract_version: 6, id: 'ping_icmp', name: 'ICMP ping', attempts: 1, successes: 1, reachable: true, stable: true, avg_ttfb_ms: 22 },
    { contract_version: 6, id: 'ping_tcp', name: 'TCP ping', attempts: 1, successes: 1, reachable: true, stable: true, avg_ttfb_ms: 25 },
    { contract_version: 6, id: 'ping_proxy', name: 'Proxy HTTPS ping', attempts: 1, successes: 1, reachable: true, stable: true, avg_ttfb_ms: 28 },
    { contract_version: 6, id: 'youtube', name: 'YouTube', attempts: 1, successes: 1, stable: true, avg_ttfb_ms: 120 },
    { contract_version: 6, id: 'telegram', name: 'Telegram', attempts: 1, successes: 0, stable: false, avg_ttfb_ms: 240 },
    { contract_version: 6, id: 'ai', name: 'AI Studio', attempts: 1, successes: 1, stable: true, avg_ttfb_ms: 180 },
  ] }] }],
  ['/api/profiles', { profiles: [profile, manualProfile, secondSubscriptionProfile] }],
  ['/api/routing', routing],
  ['/api/routing/connection-context', { servers: routing.servers }],
  ['/api/routing/preview', { requires_apply: true, core_restart: true, firewall_reload: true, desired_config_sha256: 'desired', applied_config_sha256: 'applied', changes: ['fixture change'], warnings: [] }],
  ['/api/onboarding/status', { ready: true, checks: [] }],
  ['/api/safe-mode', { enabled: false, suppressed: [] }],
  ['/api/memory-estimate', { risk: 'observed-ok', reasons: [] }],
  ['/api/subscriptions', { subscriptions: [{
    url: fixtureSubscriptionUrl,
    title: 'Fixture VPN',
    announcement: '🍿 Streaming servers\n🎮 Low-latency servers',
    profile_count: 1,
    last_loaded_unix: 1719900000,
    last_error: null,
  }, {
    url: fixtureSecondSubscriptionUrl,
    title: 'Fixture Second VPN',
    profile_count: 0,
    last_loaded_unix: 1719900000,
    last_error: null,
  }] }],
  ['/api/subscriptions/refresh-report', { report: [] }],
  ['/api/backups', { backups: [] }],
  ['/api/traffic', { current_up_kbps: 0, current_down_kbps: 0, total_up_bytes: 0, total_down_bytes: 0 }],
  ['/api/connection-log', { connection_log: [] }],
  ['/api/mihomo-api/connections', connections],
  ['/api/mihomo-api/proxies', { proxies: {} }],
  ['/api/mihomo-api/memory', { inuse: 1024 }],
  ['/api/dns', { dns: { enabled: true, query_strategy: 'UseIPv4', remote_servers: [], local_servers: [] }, sniffer_override_destination: true }],
  ['/api/mihomo-features', mihomoFeatures],
  ['/api/hwid', { hwid: {} }],
  ['/api/auth-settings', { enabled: false, username: 'admin' }],
  ['/api/update/status', { current_version: 'fixture', auto_update_enabled: false }],
  ['/api/bench/status', { running: false, results: [] }],
  ['/api/active-profile/status', { generation: 1, state: 'running', profile_id: 102, profile_name: 'Fixture Manual', stage: 'waiting-core', updated_at_unix: 1719900000 }],
  ['/api/trash', { count: 1, trash: [{
    server_ref: deadServerRef,
    name: 'Fixture Dead',
    profile_id: 202,
    group: fixtureSubscriptionUrl,
    promoted_at_unix: 1719900000,
    still_in_profiles: true,
  }] }],
  ['/api/telegram-probe/status', { configured: false, session_exists: false, authorized: false, login_pending: false }],
  ['/api/geo/status', {}],
  ['/api/geobases', { geobases: [] }],
  ['/api/devices', { count: 1, devices: [{ iface: 'br0', ip: '192.0.2.10', mac: 'aa:bb:cc:dd:ee:ff' }] }],
]);

const requests = [];

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  if (!chunks.length) return null;
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
  });
  response.end(JSON.stringify(body));
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host}`);

  if (request.method === 'GET' && url.pathname === '/') {
    response.writeHead(200, {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/html; charset=utf-8',
    });
    response.end(webUi);
    return;
  }

  if (request.method === 'GET' && url.pathname === '/__fixture/health') {
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === 'GET' && url.pathname === '/__fixture/requests') {
    sendJson(response, 200, { requests });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/__fixture/reset') {
    requests.length = 0;
    for (const item of [profile, manualProfile]) {
      item.name = initialProfileNames.get(item.id);
      profileDetails.get(item.id).name = item.name;
      profileDetails.get(item.id).raw = initialProfileRaws.get(item.id);
    }
    responses.set('/api/bench/status', { running: false, results: [] });
    profileDiagnostic = { active: null, completed: null, statusPolls: 0 };
    sendJson(response, 200, { ok: true });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/__fixture/bench-status') {
    try {
      responses.set('/api/bench/status', await readJson(request));
    } catch {
      sendJson(response, 400, { error: 'fixture expected valid JSON' });
      return;
    }
    sendJson(response, 200, { ok: true });
    return;
  }

  if (url.pathname.startsWith('/api/')) {
    let body = null;
    try {
      body = await readJson(request);
    } catch {
      sendJson(response, 400, { error: 'fixture expected valid JSON' });
      return;
    }
    requests.push({ method: request.method, path: url.pathname, body });

    if (request.method === 'POST' && url.pathname === '/api/routing/resource-route') {
      sendJson(response, 200, { ok: true, closed_connections: 1 });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/profile-diagnostics/start') {
      if (body?.profile_id !== profile.id || ![60, 120, 180, 300].includes(body?.duration_seconds) || !body?.source_ip) {
        sendJson(response, 400, { error: 'fixture expected the active profile, source IP, and a bounded duration' });
        return;
      }
      const startedAt = Math.floor(Date.now() / 1000);
      profileDiagnostic = {
        active: {
          session_id: 'diag-fixture-session',
          started_at_unix: startedAt,
          deadline_unix: startedAt + body.duration_seconds,
          duration_seconds: body.duration_seconds,
          source_ip: body.source_ip || null,
        },
        completed: null,
        statusPolls: 0,
      };
      sendJson(response, 200, { session: diagnosticStatus(profileDiagnostic.active) });
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/profile-diagnostics/status') {
      if (profileDiagnostic.active) {
        profileDiagnostic.statusPolls += 1;
        if (profileDiagnostic.statusPolls >= 4) {
          profileDiagnostic.active.finalization_reason = 'duration_elapsed';
          profileDiagnostic.completed = profileDiagnostic.active;
          profileDiagnostic.active = null;
        }
      }
      sendJson(response, 200, {
        active: diagnosticStatus(profileDiagnostic.active),
        completed: diagnosticStatus(profileDiagnostic.completed, 'completed'),
        completed_ttl_seconds: 300,
      });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/profile-diagnostics/stop') {
      if (!profileDiagnostic.active || body?.session_id !== profileDiagnostic.active.session_id) {
        sendJson(response, 409, { error: 'fixture diagnostic session mismatch' });
        return;
      }
      profileDiagnostic.active.finalization_reason = 'stopped';
      profileDiagnostic.completed = profileDiagnostic.active;
      profileDiagnostic.active = null;
      sendJson(response, 200, { report: diagnosticReport(profileDiagnostic.completed) });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/profile-diagnostics/report') {
      if (!profileDiagnostic.completed) {
        sendJson(response, 404, { error: 'fixture has no completed diagnostic report' });
        return;
      }
      if (body?.session_id !== profileDiagnostic.completed.session_id) {
        sendJson(response, 409, { error: 'fixture diagnostic report mismatch' });
        return;
      }
      const report = diagnosticReport(profileDiagnostic.completed);
      if (JSON.stringify(report).includes(profileDiagnosticSecretCanary)) {
        sendJson(response, 500, { error: 'fixture leaked diagnostic secret canary' });
        return;
      }
      sendJson(response, 200, { report });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/profile-diagnostics/discard') {
      const sessionId = profileDiagnostic.active?.session_id || profileDiagnostic.completed?.session_id || null;
      if (body?.session_id && body.session_id !== sessionId) {
        sendJson(response, 409, { error: 'fixture diagnostic discard mismatch' });
        return;
      }
      const discarded = !!sessionId;
      profileDiagnostic = { active: null, completed: null, statusPolls: 0 };
      sendJson(response, 200, { discarded, session_id: sessionId });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/login') {
      sendJson(response, 200, { token: 'fixture-token' });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/telegram-probe/request-code') {
      sendJson(response, 200, { code_requested: true });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/telegram-probe/confirm') {
      sendJson(response, 200, { authorized: true });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/telegram-probe/delete') {
      sendJson(response, 200, { deleted: true, revoked: true });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/routing/rules') {
      sendJson(response, 200, { ok: true });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/routing/apply') {
      sendJson(response, 200, { ok: true });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/dns') {
      sendJson(response, 200, { ok: true });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/mihomo-features') {
      if (!body || Object.keys(body).join(',') !== 'parameters') {
        sendJson(response, 400, { error: 'fixture expected reduced Mihomo parameters envelope' });
        return;
      }
      mihomoFeatures = { parameters: body.parameters, runtime: mihomoFeatures.runtime };
      responses.set('/api/mihomo-features', mihomoFeatures);
      sendJson(response, 200, mihomoFeatures);
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/profiles/import') {
      sendJson(response, 200, { imported: 1 });
      return;
    }
    if (request.method === 'GET' && /^\/api\/profiles\/\d+$/.test(url.pathname)) {
      const id = Number(url.pathname.split('/').at(-1));
      const detail = profileDetails.get(id);
      if (!detail) {
        sendJson(response, 404, { error: 'profile not found' });
        return;
      }
      sendJson(response, 200, { profile: detail });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/mihomo-api/connections/page') {
      const queryTerms = String(body?.query || '').toLowerCase().split(/\s+/).filter(Boolean);
      const filteredRows = connections.connections.filter(connection => {
        const metadata = connection.metadata || {};
        const text = [
          metadata.host, metadata.sourceIP, metadata.destinationIP, metadata.destinationPort,
          metadata.destinationCountry, metadata.network, connection.rule, connection.rulePayload,
          ...(connection.chains || []),
        ].join(' ').toLowerCase();
        return queryTerms.every(term => text.includes(term));
      });
      const offset = Number(body?.offset || 0);
      const limit = Math.min(500, Math.max(1, Number(body?.limit || 100)));
      sendJson(response, 200, {
        total: connections.connections.length,
        filtered: filteredRows.length,
        offset,
        limit,
        connections: filteredRows.slice(offset, offset + limit),
      });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/mihomo-api/connections/device-traffic') {
      sendJson(response, 200, {
        devices: {
          '192.0.2.10': { upload: 614400, download: 921600, connections: 601 },
        },
      });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/routing/explain') {
      sendJson(response, 200, { decision: 'active', resource: body?.resource, reason: 'fixture' });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/profiles/update') {
      const allowedKeys = body && Object.keys(body).every(key => ['profile_id', 'expected_server_ref', 'name', 'raw', 'block_quic', 'xhttp_tuning'].includes(key));
      const detail = profileDetails.get(body?.profile_id);
      if (!allowedKeys || !detail || body.expected_server_ref !== detail.server_ref || JSON.stringify(body).length > 66_000) {
        sendJson(response, 400, { error: 'fixture rejected unbounded or unstable profile update payload' });
        return;
      }
      if (!String(body.name || '').trim() || (!detail.subscription_managed && !String(body.raw || '').trim())) {
        sendJson(response, 400, { error: 'fixture expected nonempty profile fields' });
        return;
      }
      if (detail.subscription_managed && Object.hasOwn(body, 'raw')) {
        sendJson(response, 400, { error: 'fixture forbids subscription raw updates' });
        return;
      }
      if (body.name === 'Fixture rejected name') {
        sendJson(response, 409, { error: 'fixture rejected profile update' });
        return;
      }
      detail.name = body.name;
      if (Object.hasOwn(body, 'raw')) detail.raw = body.raw;
      const listProfile = body.profile_id === profile.id ? profile : manualProfile;
      listProfile.name = detail.name;
      sendJson(response, 200, { profile: { ...detail, raw: undefined }, dataplane_applied: false });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/subscriptions/move') {
      if (![fixtureSubscriptionUrl,fixtureSecondSubscriptionUrl].includes(body?.url) || ![fixtureSubscriptionUrl,fixtureSecondSubscriptionUrl].includes(body?.adjacent_url) || !['up','down'].includes(body.direction)) {
        sendJson(response, 400, { error: 'fixture rejected subscription move' });
        return;
      }
      sendJson(response, 200, { url: body.url, moved: true });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/profiles/revalidate-ungrouped') {
      if (body && Object.keys(body).length) {
        sendJson(response, 400, { error: 'fixture expected an empty revalidation payload' });
        return;
      }
      sendJson(response, 200, { checked: 1, updated: 1, unchanged: 0, dataplane_applied: false, errors: [] });
      return;
    }
    sendJson(response, 200, responses.get(url.pathname) ?? {});
    return;
  }

  sendJson(response, 404, { error: 'not found' });
});

server.listen(port, '127.0.0.1');

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
