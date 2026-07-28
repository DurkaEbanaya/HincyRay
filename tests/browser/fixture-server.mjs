import { readFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const webUiPath = path.resolve(fixtureDir, '../../src/webui/index.html');
const webUi = await readFile(webUiPath);
const port = Number(process.env.PLAYWRIGHT_FIXTURE_PORT || 4173);

const fixtureSubscriptionUrl = 'https://provider.example/sub/fixture-token';
const profile = {
  id: 101,
  name: 'Fixture Profile',
  protocol: 'VLESS',
  transport: 'tcp',
  address: 'fixture.proxy.test',
  port: 443,
  active: true,
  favorite: false,
  group: fixtureSubscriptionUrl,
  raw: 'vless://fixture@example.invalid:443',
};
const deadServerRef = 'srv-v2-fixture-dead';

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
    profile_count: 1,
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
  ['/api/stats', { stats: [{ profile_id: profile.id, last_latency_ms: 25, resource_tests: [
    { contract_version: 6, id: 'youtube', name: 'YouTube', attempts: 1, successes: 1, stable: true, avg_ttfb_ms: 120 },
    { contract_version: 6, id: 'telegram', name: 'Telegram', attempts: 1, successes: 0, stable: false, avg_ttfb_ms: 240 },
    { contract_version: 6, id: 'ai', name: 'AI Studio', attempts: 1, successes: 1, stable: true, avg_ttfb_ms: 180 },
  ] }] }],
  ['/api/profiles', { profiles: [profile] }],
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
  }] }],
  ['/api/subscriptions/refresh-report', { report: [] }],
  ['/api/backups', { backups: [] }],
  ['/api/traffic', { current_up_kbps: 0, current_down_kbps: 0, total_up_bytes: 0, total_down_bytes: 0 }],
  ['/api/connection-log', { connection_log: [] }],
  ['/api/mihomo-api/connections', connections],
  ['/api/mihomo-api/proxies', { proxies: {} }],
  ['/api/mihomo-api/memory', { inuse: 1024 }],
  ['/api/dns', { dns: { enabled: true, query_strategy: 'UseIPv4', remote_servers: [], local_servers: [] }, sniffer_override_destination: true }],
  ['/api/hwid', { hwid: {} }],
  ['/api/auth-settings', { enabled: false, username: 'admin' }],
  ['/api/update/status', { current_version: 'fixture', auto_update_enabled: false }],
  ['/api/bench/status', { running: false, results: [] }],
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
    if (request.method === 'POST' && url.pathname === '/api/profiles/import') {
      sendJson(response, 200, { imported: 1 });
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
      sendJson(response, 200, { ok: true });
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
