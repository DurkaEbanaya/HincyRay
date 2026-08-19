import { expect, test } from '@playwright/test';

async function openFixture(page) {
  await page.addInitScript(() => {
    window.__fixturePromptCalled = false;
    window.prompt = () => {
      window.__fixturePromptCalled = true;
      return null;
    };
  });
  await page.goto('/');
  await expect(page).toHaveTitle(/HincyRay/);
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
}

async function navigateTo(page, section) {
  await page.evaluate(sectionName => window.navTo(sectionName), section);
  await expect(page.locator(`.section-panel[data-section="${section}"]`)).toHaveClass(/open/);
}

test('page boots without JavaScript errors', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(`pageerror: ${error.stack || error.message}`));
  page.on('console', message => {
    if (message.type() === 'error') errors.push(`console: ${message.text()}`);
  });

  await openFixture(page);
  await page.waitForTimeout(100);

  expect(errors).toEqual([]);
  await expect(page.locator('.sidebar-brand .brand-icon')).toBeVisible();
  await expect(page.locator('.sidebar-brand .version')).toHaveText('v1.3.0');
});

test('profile table shows compact service status and configurable metric columns', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const row = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Profile' });
  await expect(row.locator('.profile-service-test')).toHaveText(['P 25', 'YT', 'TG', 'AI']);
  await expect(row.locator('.profile-service-test.bad')).toHaveText('TG');

  await page.locator('#profileMetricSettings > button').click();
  await page.locator('#profileMetricSettings input[data-profile-metric="latency"]').uncheck();
  await expect(page.locator('#profilesTable thead [data-profile-metric="latency"]')).toBeHidden();
  await expect(row.locator('.profile-name-cell .profile-service-test')).toHaveText(['P 25', 'YT', 'TG', 'AI']);
  await expect(page.locator('#profileMetricSettings input[data-profile-metric="upload"]')).toHaveCount(0);
});

test('profile technical columns are optional and row actions stay beside the name', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const row = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Profile' });
  await expect(page.locator('#profilesTable thead [data-profile-metric="id"]')).toBeHidden();
  await expect(page.locator('#profilesTable thead [data-profile-metric="protocol"]')).toBeHidden();
  await expect(page.locator('#profilesTable thead [data-profile-metric="transport"]')).toBeHidden();
  await expect(page.locator('#profilesTable thead [data-profile-metric="address"]')).toBeHidden();
  await expect(row.locator('.profile-name-cell .profile-row-actions')).toContainText('Активен');
  await expect(row.locator('[data-bench-scope="single"]')).toHaveAttribute('title', 'Quick Test только этого сервера');
  await expect(row.locator('.profile-row-actions').getByTitle('Редактировать профиль')).toBeVisible();
  await expect(row.locator('.profile-name-cell').getByTitle('Удалить')).toBeVisible();
  const starCell = row.locator('td').first();
  await expect(starCell.locator('.star')).toBeVisible();
  expect(await starCell.evaluate(cell => ({ width: cell.getBoundingClientRect().width, position: getComputedStyle(cell).position }))).toEqual(expect.objectContaining({ position: 'static' }));
  expect((await starCell.evaluate(cell => cell.getBoundingClientRect().width))).toBeLessThanOrEqual(40);

  await page.locator('#profileMetricSettings > button').click();
  await page.locator('#profileMetricSettings input[data-profile-metric="protocol"]').check();
  await expect(page.locator('#profilesTable thead [data-profile-metric="protocol"]')).toBeVisible();
});

test('profile group shows provider title and announcement from subscription metadata', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const announcement = page.locator('#profilesBody .subscription-announcement');
  await expect(page.locator('#profilesBody')).toContainText('Fixture VPN');
  await expect(announcement.locator('.subscription-announcement-label')).toHaveText('От автора подписки');
  await expect(announcement.locator('.subscription-announcement-text')).toHaveText('🍿 Streaming servers\n🎮 Low-latency servers');
  const alignment = await announcement.evaluate(element => {
    const table = element.closest('table');
    const wrapper = table.parentElement;
    const groupHeader = table.querySelector('.profile-group-row td');
    return {
      announcementLeft: element.getBoundingClientRect().left,
      tableLeft: table.getBoundingClientRect().left,
      announcementWidth: element.getBoundingClientRect().width,
      tableWidth: table.getBoundingClientRect().width,
      wrapperWidth: wrapper.getBoundingClientRect().width,
      groupHeaderAlign: getComputedStyle(groupHeader).textAlign,
    };
  });
  expect(Math.abs(alignment.announcementLeft - alignment.tableLeft)).toBeLessThanOrEqual(1);
  expect(Math.abs(alignment.announcementWidth - alignment.wrapperWidth)).toBeLessThanOrEqual(1);
  expect(alignment.groupHeaderAlign).toBe('left');
  expect(alignment.tableWidth).toBe(alignment.wrapperWidth);
  await expect(announcement).toHaveCSS('text-align', 'left');
});

test('profiles use the available desktop width and long-operation scanner moves', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const layout = await page.locator('#profilesTable').evaluate(table => {
    const wrapper = table.parentElement;
    const group = table.querySelector('.profile-group-row');
    const deleteButton = group.querySelector('[title="Удалить подписку?"]');
    return {
      columns: getComputedStyle(table.tBodies[0]).gridTemplateColumns.split(' ').length,
      tableWidth: table.getBoundingClientRect().width,
      wrapperWidth: wrapper.getBoundingClientRect().width,
      groupRight: group.getBoundingClientRect().right,
      deleteRight: deleteButton.getBoundingClientRect().right,
    };
  });
  expect(layout.columns).toBeGreaterThan(1);
  expect(Math.abs(layout.tableWidth - layout.wrapperWidth)).toBeLessThanOrEqual(1);
  expect(layout.groupRight - layout.deleteRight).toBeGreaterThanOrEqual(2);

  await page.setViewportSize({ width: 800, height: 900 });
  expect(await page.locator('#profilesBody').evaluate(body => getComputedStyle(body).gridTemplateColumns.split(' ').length)).toBeGreaterThan(1);

  await page.emulateMedia({ reducedMotion: 'no-preference' });
  const token = await page.evaluate(() => beginLongOperation('/test-operation', 'Тестовая операция'));
  await expect(page.locator('#longOperationKitt')).toHaveClass(/running/);
  expect(await page.locator('#longOperationScanner').evaluate(element =>
    getComputedStyle(element).animationName
  )).not.toBe('none');
  await page.evaluate(token => endLongOperation(token), token);
});

test('same-path long operations finish independently without a stuck sidebar event', async ({ page }) => {
  await openFixture(page);
  const tokens = await page.evaluate(() => [
    beginLongOperation('/api/routing/apply', 'Первое применение'),
    beginLongOperation('/api/routing/apply', 'Второе применение'),
  ]);
  await expect(page.locator('#longOperationProgress')).toBeVisible();
  await page.evaluate(token => endLongOperation(token), tokens[0]);
  await page.waitForTimeout(1000);
  await expect(page.locator('#longOperationProgress')).toBeVisible();
  await expect(page.locator('#longOperationLabel')).toHaveText('Второе применение');
  await page.evaluate(token => endLongOperation(token), tokens[1]);
  await expect(page.locator('#longOperationProgress')).toBeHidden();
});

test('persisted concurrency survives reload and group/global tests send four workers', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await page.getByText('Настройки тестирования').click();
  await expect(page.locator('label[for="benchConcurrency"]')).toHaveText('Параллельных серверов');
  expect(await page.locator('#benchConcurrency').evaluate(select => ({
    native: select.dataset.nativeSelect,
    enhanced: select.dataset.customSelectEnhanced || null,
    wrapped: select.parentElement?.classList.contains('custom-select') || false,
  }))).toEqual({ native: '1', enhanced: null, wrapped: false });
  await page.locator('#benchConcurrency').selectOption('4');
  await expect.poll(() => page.evaluate(() => localStorage.getItem('hr_bench_concurrency'))).toBe('4');

  await page.reload();
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
  await navigateTo(page, 'profiles');
  await expect(page.locator('#benchConcurrency')).toHaveValue('4');

  const groupRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start'
  );
  await page.locator('.profile-group-row').filter({ hasText: 'Fixture VPN' }).locator('[data-bench-scope="group"]').click();
  expect((await groupRequest).postDataJSON()).toEqual(expect.objectContaining({
    method: 'quick',
    concurrency: 4,
    subscription_url: 'https://provider.example/sub/fixture-token',
  }));

  await page.evaluate(() => api('POST','/api/bench/stop',{}));
  await page.getByText('Настройки тестирования').click();

  const fullRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start'
  );
  await page.locator('#benchFullAll').click();
  expect((await fullRequest).postDataJSON()).toEqual(expect.objectContaining({
    method: 'full',
    concurrency: 4,
    test_download: false,
    test_upload: false,
  }));
});

test('benchmark help and stable scope titles explain single versus parallel tests in RU and EN', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await page.getByText('Настройки тестирования').click();
  await expect(page.locator('#benchSemanticsHelp')).toContainText('⚡ в строке проверяет только один сервер');
  await expect(page.locator('#benchConcurrencyHelp')).toContainText('строка ⚡ всегда одна');
  await expect(page.locator('[data-bench-scope="single"]').first()).toHaveAttribute('title', 'Quick Test только этого сервера');
  await expect(page.locator('[data-bench-scope="group"]').first()).toHaveAttribute('title', /до настроенного числа серверов параллельно/);
  await expect(page.locator('#benchFullAll')).toHaveAttribute('title', 'Full Test всех серверов, до выбранного числа параллельно');

  await page.evaluate(() => toggleLang());
  await expect(page.locator('#benchSemanticsHelp')).toContainText('A row ⚡ tests only one server');
  await expect(page.locator('#benchConcurrencyHelp')).toContainText('a row ⚡ always tests one');
  await expect(page.locator('#benchConcurrency')).toHaveAttribute('title', 'From 1 to 6; a row test always checks one server');
  await expect(page.locator('#benchFullAll')).toHaveAttribute('title', 'Full Test all servers, up to the selected parallel count');
});

test('benchmark status renders all bounded active profile names', async ({ page }) => {
  await openFixture(page);
  await page.request.post('/__fixture/bench-status', { data: {
    running: true,
    method: 'quick',
    total: 6,
    completed: 2,
    current_profile_id: 104,
    current_profile_name: 'Worker Four',
    active_profiles: [
      { id: 101, name: 'Worker One' },
      { id: 102, name: 'Worker Two' },
      { id: 103, name: 'Worker Three' },
      { id: 104, name: 'Worker Four' },
    ],
    results: [],
  }});
  await page.evaluate(() => pollBenchStatus());

  await expect(page.locator('#benchCurrent')).toHaveText('В работе: 4 · Worker One, Worker Two, Worker Three, Worker Four');
  await expect(page.locator('#benchCounter')).toHaveText('2/6');
});

test('Dead Servers supports single and bulk diagnostics, restore, and clear', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'trash');
  const list = page.locator('#trashList');
  await expect(list).toContainText('Fixture Dead');

  const singleQuick = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start'
  );
  await list.getByRole('button', { name: '⚡ Быстрый тест', exact: true }).click();
  expect((await singleQuick).postDataJSON()).toEqual(expect.objectContaining({
    profile_ids: [202],
    method: 'quick',
    test_download: false,
    test_upload: false,
  }));

  const bulkQuick = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start'
  );
  await page.locator('#trashQuickAll').click();
  expect((await bulkQuick).postDataJSON()).toEqual(expect.objectContaining({
    profile_ids: [202],
    method: 'quick',
    test_download: false,
    test_upload: false,
  }));

  const restoreAll = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/trash/restore'
  );
  await page.locator('#trashRestoreAll').click();
  expect((await restoreAll).postDataJSON()).toEqual({ server_refs: ['srv-v2-fixture-dead'] });

  const clearAll = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/trash/clear'
  );
  await page.locator('#trashClearAll').click();
  await page.locator('#confirmBtn').click();
  expect((await clearAll).postDataJSON()).toEqual({});
});

test('Telegram provisioning posts secrets without persisting them in the browser', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await page.getByText('Настройки тестирования').click();
  await page.getByText('Telegram media probe').click();
  await page.locator('#telegramApiId').fill('12345');
  await page.locator('#telegramApiHash').fill('fixture-api-hash');
  await page.locator('#telegramPhone').fill('+10000000000');
  await page.locator('#telegramPeer').fill('fixture_channel');
  await page.locator('#telegramMessageId').fill('42');
  const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/telegram-probe/request-code');
  await page.getByRole('button', { name: 'Получить код' }).click();
  expect((await posted).postDataJSON()).toEqual({
    api_id: 12345,
    api_hash: 'fixture-api-hash',
    phone: '+10000000000',
    peer: 'fixture_channel',
    message_id: 42,
  });
  await expect(page.locator('#telegramApiHash')).toHaveValue('');
  await expect(page.locator('#telegramPhone')).toHaveValue('');
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('fixture-api-hash');
});

test('login overlay authenticates and stores the bearer in sessionStorage', async ({ page }) => {
  await page.addInitScript(() => {
    window.__fixturePromptCalled = false;
    window.prompt = () => {
      window.__fixturePromptCalled = true;
      return null;
    };
  });
  await page.route('**/api/auth-settings', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ enabled: true, username: 'admin' }),
  }));
  await page.goto('/');
  await expect(page.locator('#loginOverlay')).toBeVisible();
  await page.locator('#loginUser').fill('admin');
  await page.locator('#loginPass').fill('secret');
  await page.getByRole('button', { name: 'Войти' }).click();
  await expect(page.locator('#loginOverlay')).toBeHidden();
  await expect.poll(() => page.evaluate(() => sessionStorage.getItem('hincyray_token'))).toBe('fixture-token');
});

test("connection search keeps the canonical '🇷🇺 chatgpt.com' row", async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'connections-table');

  const body = page.locator('#connectionsRoutingBody');
  await expect(body).not.toContainText('chatgpt.com');
  const searched = page.waitForRequest(request => {
    if (request.method() !== 'POST' || new URL(request.url()).pathname !== '/api/mihomo-api/connections/page') return false;
    return request.postDataJSON()?.query === 'RU chatgpt.com';
  });
  await page.locator('#connectionsTableSearch').fill('🇷🇺 chatgpt.com');
  const searchRequest = await searched;

  expect(searchRequest.postDataJSON()).toEqual({ query: 'RU chatgpt.com', offset: 0, limit: 100 });
  await expect(body.locator('tr')).toHaveCount(1);
  await expect(body.locator('tr')).toContainText('🇷🇺 chatgpt.com');
  await expect(body.locator('tr')).not.toContainText('example.net');
});

test('connection table pages through the server instead of loading 500 rows', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'connections-table');
  await expect(page.locator('#connectionsTablePage')).toHaveText('1–100 / 702');

  const paged = page.waitForRequest(request =>
    request.method() === 'POST' &&
    new URL(request.url()).pathname === '/api/mihomo-api/connections/page' &&
    request.postDataJSON()?.offset === 100
  );
  await page.locator('#connectionsTableNext').click();
  const request = await paged;

  expect(request.postDataJSON()).toEqual({ query: '', offset: 100, limit: 100 });
  await expect(page.locator('#connectionsTablePage')).toHaveText('101–200 / 702');
});

test('device accounting uses the bounded backend projection', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'devices');

  const row = page.locator('#devicesBody tr').filter({ hasText: '192.0.2.10' });
  await expect(row).toContainText('601 active');
  await expect(row).toContainText('600.0 KB');
  await expect(row).toContainText('900.0 KB');

  const requests = await page.request.get('/__fixture/requests').then(response => response.json());
  const projection = requests.requests.find(request => request.path === '/api/mihomo-api/connections/device-traffic');
  expect(projection).toEqual({
    method: 'POST',
    path: '/api/mihomo-api/connections/device-traffic',
    body: { source_ips: ['192.0.2.10'] },
  });
});

test('native connection action changes target and posts the resource route', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'connections-table');
  await page.locator('#connectionsTableSearch').fill('🇷🇺 chatgpt.com');

  const action = page.getByTestId('connections-action');
  await expect(action).toHaveCount(1);
  await expect(action).toHaveAttribute('data-native-select', '1');
  await action.click();
  await expect(action).toBeFocused();

  const posted = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/resource-route'
  );
  expect(await action.selectOption('direct')).toEqual(['direct']);

  const request = await posted;
  expect(request.postDataJSON()).toEqual({
    resource: 'chatgpt.com',
    target: 'direct',
    close_connections: true,
  });
});

test('connection rule editor creates or updates a resource rule', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'connections-table');
  await page.locator('#connectionsTableSearch').fill('🇷🇺 chatgpt.com');
  await expect(page.locator('#connectionsRoutingBody tr')).toHaveCount(1);

  await page.locator('#connectionsRoutingBody tr').getByRole('button', { name: /Создать\/изменить правило/ }).click();
  await expect(page.locator('#resultModal')).toBeVisible();
  await page.locator('#connectionRuleTarget').selectOption('direct');
  const posted = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/resource-route'
  );
  await page.locator('#resultModal button').filter({ hasText: 'Создать/изменить правило' }).click();
  expect((await posted).postDataJSON()).toEqual({
    resource: 'chatgpt.com',
    target: 'direct',
    close_connections: true,
  });
});

test('routing rule add and apply are posted through the API contract', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#ruleName').fill('Fixture rule');
  await page.locator('#ruleEntries').fill('fixture.example');
  await page.locator('#ruleTarget').selectOption('direct');

  const rulesPost = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/rules'
  );
  await page.locator('#ruleSubmitBtn').click();
  const rulesBody = (await rulesPost).postDataJSON();
  expect(rulesBody.apply).toBe(true);
  expect(rulesBody.rules).toContainEqual(expect.objectContaining({
    name: 'Fixture rule',
    target: 'direct',
    domains: ['fixture.example'],
  }));

  const applyPost = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/apply'
  );
  await page.getByRole('button', { name: '⬆ Применить' }).click();
  expect((await applyPost).postDataJSON()).toBeNull();
});

test('unsaved Parovozik selection survives status refresh', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  const wagon = page.locator('[data-parovozik-ref="srv-v1-wagon"]');
  await page.evaluate(() => window.toggleParovozikWagon('srv-v1-wagon'));
  await expect(wagon).toBeChecked();
  await page.evaluate(() => window.refreshStatus());
  await page.waitForTimeout(100);
  await expect(wagon).toBeChecked();
});

test('DNS save persists settings and applies routing', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'dns');
  await page.locator('#dnsRemote').fill('https://1.1.1.1/dns-query');
  await page.locator('#dnsLocal').fill('223.5.5.5');
  const dnsPost = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/dns'
  );
  const applyPost = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/apply'
  );
  await page.locator('.section-panel[data-section="dns"] button').filter({ hasText: 'Сохранить' }).click();
  expect((await dnsPost).postDataJSON()).toEqual(expect.objectContaining({
    remote_servers: ['https://1.1.1.1/dns-query'],
    local_servers: ['223.5.5.5'],
  }));
  expect((await applyPost).postDataJSON()).toEqual({});
});

test('Mihomo parameters auto-load runtime and save one reduced payload by stable IDs in English', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('hr_lang', 'EN');
    window.__fixturePromptCalled = false;
    window.prompt = () => {
      window.__fixturePromptCalled = true;
      return null;
    };
  });
  await page.goto('/');
  await expect(page).toHaveTitle(/HincyRay/);
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
  await expect(page.locator('.nav-sub-item[data-section="features"]')).toContainText('Parameters');
  await page.request.post('/__fixture/reset');

  const loaded = page.waitForRequest(request =>
    request.method() === 'GET' && new URL(request.url()).pathname === '/api/mihomo-features'
  );
  await expect(page.locator('#featSave')).toBeDisabled();
  await navigateTo(page, 'features');
  await loaded;

  await expect(page.locator('#featSave')).toBeEnabled();
  await expect(page.locator('#featRuntimeGeoLoader')).toHaveText('memconservative');
  await expect(page.locator('#featRuntimeStoreFakeIp')).toHaveText('enabled');
  await expect(page.locator('#featRuntimeUdp')).toHaveText('enabled');
  await expect(page.locator('#featRuntimeEcAddress')).toHaveText('127.0.0.1:9090');
  await expect(page.locator('#featRuntimeEcConnected')).toHaveText('Connected');
  await expect(page.locator('#featDnsFakeIpFilterMode option').first()).toHaveText('Not set');
  await expect(page.locator('#featDnsFakeIpTtl')).toHaveAttribute('placeholder', 'Not set');

  await expect(page.locator('#featPgEnabled, #featEcSecret, #featNtpEnabled, #featAuth, #proxyProvidersList, #ruleProvidersList, #featRawRules')).toHaveCount(0);
  await expect(page.locator('.section-panel[data-section="features"] #dnsSniffOverride')).toHaveCount(0);

  await page.locator('#featUnifiedDelay').evaluate(control => { control.checked = false; });
  await page.locator('#featKaInterval').fill('45');
  await page.locator('#featPerProxyTfo').evaluate(control => { control.checked = true; });
  await page.locator('#featPerProxyIpVersion').selectOption('ipv4-prefer');
  await page.locator('#featDnsPreferH3').evaluate(control => { control.checked = true; });
  await page.locator('#featDnsDefaultNameserver').fill('9.9.9.9\n1.1.1.1');
  await page.locator('#featDnsNameserverPolicy').fill('geosite:private = 192.168.1.1, 192.168.1.2');
  await page.locator('#featSnifferForceDomain').fill('+.fixture.test');
  await page.locator('#featHosts').fill('fixture.test=192.0.2.5');

  const posted = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/mihomo-features'
  );
  await page.locator('#featSave').click();
  const body = (await posted).postDataJSON();
  expect(body).toEqual({
    parameters: {
      unified_delay: false,
      store_selected: true,
      keep_alive_interval: 45,
      keep_alive_idle: 120,
      disable_keep_alive: false,
      tcp_concurrent: true,
      per_proxy: { tfo: true, mptcp: false, ip_version: 'ipv4-prefer' },
      dns: {
        prefer_h3: true,
        respect_rules: true,
        default_nameserver: ['9.9.9.9', '1.1.1.1'],
        nameserver_policy: { 'geosite:private': ['192.168.1.1', '192.168.1.2'] },
        proxy_server_nameserver_policy: { 'provider.example': ['1.0.0.1'] },
        direct_nameserver_follow_policy: true,
        fake_ip_filter_mode: 'blacklist',
        fake_ip_filter: ['*.lan', '*.local'],
        fake_ip_ttl: 60,
      },
      sniffer: {
        force_domain: ['+.fixture.test'],
        skip_domain: ['+.apple.com'],
        skip_src_address: ['192.168.0.0/16'],
        skip_dst_address: ['127.0.0.1/8'],
      },
      tunnels: [{ network: ['tcp'], address: '127.0.0.1:8080', target: 'fixture.test:80', proxy: null }],
      hosts: { 'fixture.test': '192.0.2.5' },
      experimental: { quic_go_disable_gso: false, quic_go_disable_ecn: true },
    },
  });

  const requests = await page.request.get('/__fixture/requests').then(response => response.json());
  const featureRequests = requests.requests.filter(request => request.path === '/api/mihomo-features');
  expect(featureRequests.filter(request => request.method === 'GET')).toHaveLength(1);
  expect(featureRequests.filter(request => request.method === 'POST')).toHaveLength(1);
  expect(featureRequests.at(-1).body.runtime).toBeUndefined();
  expect(featureRequests.at(-1).body.parameters.proxy_group).toBeUndefined();
  expect(requests.requests.filter(request => request.path === '/api/routing/apply')).toHaveLength(0);
});

for (const invalid of [
  {
    name: 'malformed host',
    edit: async page => page.locator('#featHosts').fill('fixture.test=192.0.2.5\nmalformed-host'),
    error: /Hosts.*(некорректная строка|invalid line)/,
  },
  {
    name: 'malformed policy',
    edit: async page => page.locator('#featDnsNameserverPolicy').fill('geosite:private = 192.168.1.1\nmalformed-policy'),
    error: /(Nameserver policy).*(некорректная строка|invalid line)/,
  },
  {
    name: 'incomplete tunnel',
    edit: async page => page.getByRole('button', { name: /Добавить tunnel|Add Tunnel/ }).click(),
    error: /Tunnels.*(заполните address и target|fill address and target)/,
  },
  {
    name: 'empty required number',
    edit: async page => page.locator('#featKaInterval').evaluate(control => {
      control.value = '';
      control.dispatchEvent(new Event('input', { bubbles: true }));
    }),
    error: /обязательные числовые поля|required numeric fields/,
  },
]) {
  test(`Mihomo parameters reject ${invalid.name} without a request`, async ({ page }) => {
    await openFixture(page);
    await navigateTo(page, 'features');
    await expect(page.locator('#featSave')).toBeEnabled();
    await page.request.post('/__fixture/reset');

    await invalid.edit(page);
    await page.locator('#featSave').click();

    await expect(page.locator('#msgBar')).toHaveText(invalid.error);
    const requests = await page.request.get('/__fixture/requests').then(response => response.json());
    expect(requests.requests.filter(request => request.method === 'POST' && request.path === '/api/mihomo-features')).toHaveLength(0);
  });
}

test('Mihomo parameters retain dirty drafts across navigation without reloading', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'features');
  await expect(page.locator('#featSave')).toBeEnabled();
  await page.request.post('/__fixture/reset');

  await page.locator('#featHosts').fill('draft.test=192.0.2.88');
  await navigateTo(page, 'config');
  await navigateTo(page, 'features');

  await expect(page.locator('#featHosts')).toHaveValue('draft.test=192.0.2.88');
  const requests = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(requests.requests.filter(request => request.method === 'GET' && request.path === '/api/mihomo-features')).toHaveLength(0);
});

test('profile import posts pasted subscription text', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'import');
  await page.locator('#importText').fill('vless://fixture@example.invalid:443#fixture');
  const imported = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/profiles/import'
  );
  await page.getByRole('button', { name: 'Импортировать' }).click();
  expect((await imported).postDataJSON()).toEqual({
    text: 'vless://fixture@example.invalid:443#fixture',
  });
});

test('mobile bottom navigation opens routing without horizontal table dependence', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openFixture(page);
  await expect(page.locator('#bottomNav')).toBeVisible();
  await page.locator('.bottom-nav-item[data-group="routing"]').click();
  await expect(page.locator('.section-panel[data-section="routing"]')).toHaveClass(/open/);
  await expect(page.locator('table.responsive-cards').first()).toHaveCount(1);
});

test('manual profile editor loads detail on demand, protects raw, and posts stable bounded fields', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const modal = page.getByTestId('profile-editor-modal');
  const profileRow = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' });
  const detailRequest = page.waitForRequest(request =>
    request.method() === 'GET' && new URL(request.url()).pathname === '/api/profiles/102'
  );
  await profileRow.locator('.profile-name-edit').click();
  await detailRequest;

  await expect(modal).toBeVisible();
  await expect(modal.locator('#profileEditorName')).toHaveValue('Fixture Manual');
  await expect(modal.locator('#profileEditorProtocol')).toHaveText('VLESS');
  await expect(modal.locator('#profileEditorTransport')).toHaveText('ws');
  await expect(modal.locator('#profileEditorAddress')).toHaveText('192.0.2.44');
  await expect(modal.locator('#profileEditorPort')).toHaveText('8443');
  await expect(modal.locator('#profileEditorGroup')).toHaveText('Без группы');
  await expect(modal.locator('#profileEditorActive')).toHaveText('нет');
  await expect(modal.locator('#profileEditorDead')).toHaveText('нет');
  const raw = modal.locator('#profileEditorRaw');
  await expect(raw).toHaveValue(/manual-key.*host=hidden\.example.*path=%2Fsecret/);
  await expect(raw).toHaveClass(/profile-secret-mask/);
  await expect(raw).not.toHaveClass(/revealed/);
  await expect(modal.locator('#profileEditorReveal')).toHaveAttribute('aria-pressed', 'false');
  expect(await page.evaluate(() => JSON.stringify({ mock: window.MOCK.profiles, localStorage: { ...localStorage } }))).not.toContain('manual-key');

  await modal.locator('#profileEditorReveal').click();
  await expect(raw).toHaveClass(/revealed/);
  await expect(modal.locator('#profileEditorReveal')).toHaveAttribute('aria-pressed', 'true');
  await modal.locator('#profileEditorName').fill('Fixture Manual Updated');
  await raw.fill('vless://new-manual-key@192.0.2.45:9443?security=tls&type=ws&host=new-hidden.example#Updated');
  const updateRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/profiles/update'
  );
  await modal.locator('#profileEditorSave').click();
  expect((await updateRequest).postDataJSON()).toEqual({
    profile_id: 102,
    expected_server_ref: 'srv-v2-fixture-manual',
    name: 'Fixture Manual Updated',
    raw: 'vless://new-manual-key@192.0.2.45:9443?security=tls&type=ws&host=new-hidden.example#Updated',
  });

  await expect(modal).toBeHidden();
  await expect(raw).toHaveValue('');
  expect(await page.evaluate(() => profileEditorState)).toBeNull();
  await expect(page.locator('#profilesBody')).toContainText('Fixture Manual Updated');
  expect(await page.evaluate(() => window.__fixturePromptCalled)).toBe(false);
});

test('subscription profile raw is read-only while rename remains available', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const modal = page.getByTestId('profile-editor-modal');
  await page.locator('#profilesBody tr').filter({ hasText: 'Fixture Profile' }).locator('.profile-name-edit').click();

  await expect(modal.locator('#profileEditorRaw')).toBeDisabled();
  await expect(modal.locator('#profileEditorRaw')).toHaveValue(/subscription-secret/);
  await expect(modal.locator('#profileEditorManagedNote')).toBeVisible();
  await modal.locator('#profileEditorName').fill('Fixture Subscription Renamed');
  const updateRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/profiles/update'
  );
  await modal.locator('#profileEditorSave').click();
  expect((await updateRequest).postDataJSON()).toEqual({
    profile_id: 101,
    expected_server_ref: 'srv-v2-fixture-subscription',
    name: 'Fixture Subscription Renamed',
  });
  await expect(modal).toBeHidden();
  await expect(page.locator('#profilesBody')).toContainText('Fixture Subscription Renamed');
});

test('manual XHTTP editor exposes reusable tuning without replacing the share-link editor', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  const modal = page.getByTestId('profile-editor-modal');
  await page.evaluate(() => openProfileEditor(103));
  await expect(modal).toBeVisible();
  await expect(modal.locator('#profileEditorXhttpTuning')).toBeVisible();
  await expect(modal.locator('#profileEditorScMaxEachPostBytes')).toHaveValue('2048');
  await modal.locator('#profileEditorScMaxEachPostBytes').fill('4096-4096');
  await modal.locator('#profileEditorScMinPostsIntervalMs').fill('15-15');
  const updateRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/profiles/update'
  );
  await modal.locator('#profileEditorSave').click();
  expect((await updateRequest).postDataJSON()).toMatchObject({
    profile_id: 103,
    expected_server_ref: 'srv-v2-fixture-xhttp',
    xhttp_tuning: {
      sc_max_each_post_bytes: '4096-4096',
      sc_min_posts_interval_ms: '15-15',
    },
  });
});

test('repeated active-profile clicks create one request and show real daemon stage', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.route('**/api/active-profile', async route => {
    await new Promise(resolve => setTimeout(resolve, 350));
    await route.continue();
  });
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await page.evaluate(() => {
    const button = document.querySelector('[data-profile-select]');
    selectActiveProfile(102, 'Fixture Manual', button);
    selectActiveProfile(102, 'Fixture Manual', button);
  });
  await expect(page.locator('#serverSwitchProgress')).toBeVisible();
  await expect(page.locator('#serverSwitchStage')).toHaveText('Ожидание готовности ядра…');
  await page.waitForTimeout(500);
  const requests = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(requests.requests.filter(request => request.method === 'POST' && request.path === '/api/active-profile')).toHaveLength(1);
});

test('late active-profile status response cannot resurrect a completed indicator', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  let statusRequests = 0;
  await page.route('**/api/active-profile/status', async route => {
    statusRequests += 1;
    if (statusRequests === 1) await new Promise(resolve => setTimeout(resolve, 700));
    await route.continue();
  });
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await page.locator('[data-profile-select]').first().click();
  await expect(page.locator('#serverSwitchProgress')).toBeHidden({ timeout: 3000 });
  await page.waitForTimeout(900);
  await expect(page.locator('#serverSwitchProgress')).toBeHidden();
  expect(statusRequests).toBeLessThanOrEqual(2);
});

test('profile editor sends nothing before detail loads and clears raw on cancel', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.route('**/api/profiles/102', async route => {
    await new Promise(resolve => setTimeout(resolve, 300));
    await route.continue();
  });
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const modal = page.getByTestId('profile-editor-modal');
  await page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' }).locator('.profile-name-edit').click();
  await expect(modal.locator('#profileEditorSave')).toBeDisabled();
  await modal.locator('#profileEditorSave').click({ force: true });
  await expect(modal.locator('#profileEditorRaw')).toHaveValue(/manual-key/);
  await modal.getByRole('button', { name: 'Отмена' }).click();
  await expect(modal).toBeHidden();
  await expect(modal.locator('#profileEditorRaw')).toHaveValue('');
  const requests = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(requests.requests.filter(request => request.method === 'POST' && request.path === '/api/profiles/update')).toHaveLength(0);
});

test('profile editor clears sensitive raw generation-safely on auth and page lifecycle events', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.route('**/api/profiles/102', async route => {
    await new Promise(resolve => setTimeout(resolve, 200));
    await route.continue();
  });
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const modal = page.getByTestId('profile-editor-modal');
  const raw = modal.locator('#profileEditorRaw');
  const manualRow = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' });

  await manualRow.locator('.profile-name-edit').click();
  await page.evaluate(() => showLoginOverlay());
  await page.waitForTimeout(300);
  await expect(modal).toBeHidden();
  await expect(raw).toHaveValue('');
  expect(await page.evaluate(() => profileEditorState)).toBeNull();

  await page.evaluate(() => { document.getElementById('loginOverlay').style.display = 'none'; });
  await manualRow.locator('.profile-name-edit').click();
  await expect(raw).toHaveValue(/manual-key/);
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
  await expect(modal).toBeHidden();
  await expect(raw).toHaveValue('');
  expect(await page.evaluate(() => profileEditorState)).toBeNull();
});

test('whitespace profile group is rendered as No group', async ({ page }) => {
  await page.addInitScript(() => {
    window.addEventListener('DOMContentLoaded', () => {
      const profile = window.MOCK?.profiles?.find(item => item.id === 102);
      if (profile) profile.group = '   ';
    });
  });
  await openFixture(page);
  await navigateTo(page, 'profiles');

  const noGroup = page.locator('#profilesBody .profile-group-row').filter({ hasText: 'Без группы' });
  await expect(noGroup).toHaveCount(1);
  await expect(noGroup.getByTestId('revalidate-ungrouped')).toBeVisible();
});

test('profile update errors preserve the editor draft and do not mutate the list', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const modal = page.getByTestId('profile-editor-modal');
  await page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' }).locator('.profile-name-edit').click();
  await modal.locator('#profileEditorName').fill('Fixture rejected name');
  const originalRaw = await modal.locator('#profileEditorRaw').inputValue();
  await modal.locator('#profileEditorSave').click();

  await expect(page.locator('#msgBar')).toHaveText('fixture rejected profile update');
  await expect(modal).toBeVisible();
  await expect(modal.locator('#profileEditorName')).toBeEnabled();
  await expect(modal.locator('#profileEditorName')).toHaveValue('Fixture rejected name');
  await expect(modal.locator('#profileEditorRaw')).toHaveValue(originalRaw);
  await expect(page.locator('#profilesBody')).toContainText('Fixture Manual');
  await expect(page.locator('#profilesBody')).not.toContainText('Fixture rejected name');
});

test('No group revalidates local links while subscription groups refresh their source', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const noGroup = page.locator('#profilesBody .profile-group-row').filter({ hasText: 'Без группы' });
  const revalidateRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/profiles/revalidate-ungrouped'
  );
  await noGroup.getByTestId('revalidate-ungrouped').click();
  expect((await revalidateRequest).postDataJSON()).toEqual({});
  await expect(page.locator('#msgBar')).toContainText('Локальная проверка завершена');
  await expect(page.locator('#msgBar')).toContainText('обновлено 1');

  const subscriptionGroup = page.locator('#profilesBody .profile-group-row').filter({ hasText: 'Fixture VPN' });
  const refreshRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/subscriptions/refresh-one'
  );
  await subscriptionGroup.getByTitle('Обновить эту подписку из источника').click();
  expect((await refreshRequest).postDataJSON()).toEqual({ url: 'https://provider.example/sub/fixture-token' });
});

test('No group revalidation errors leave profile rows unchanged', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.route('**/api/profiles/revalidate-ungrouped', route => route.fulfill({
    status: 400,
    contentType: 'application/json',
    body: JSON.stringify({
      checked: 1,
      updated: 0,
      unchanged: 1,
      dataplane_applied: false,
      errors: [{ profile_id: 102, name: 'Fixture Manual', error: 'invalid local share link' }],
    }),
  }));
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const before = await page.locator('#profilesBody').textContent();
  await page.getByTestId('revalidate-ungrouped').click();

  await expect(page.locator('#msgBar')).toContainText('Fixture Manual: invalid local share link');
  await expect(page.locator('#profilesBody')).toHaveText(before);
  const requests = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(requests.requests.filter(request => request.path === '/api/subscriptions/refresh-one')).toHaveLength(0);
});

test('English No group is selected by null source and keeps local revalidation wording', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('hr_lang', 'EN'));
  await page.request.post('/__fixture/reset');
  await page.goto('/');
  await expect(page.locator('#profilesBody')).toContainText('Fixture Manual');
  await navigateTo(page, 'profiles');
  const noGroup = page.locator('#profilesBody .profile-group-row').filter({ hasText: 'No group' });
  await expect(noGroup.getByTestId('revalidate-ungrouped')).toContainText('Revalidate local profiles');
  await expect(noGroup.getByTestId('revalidate-ungrouped')).toHaveAttribute('title', /No subscription or network fetch/);
});

test('Profile Logger starts only the active profile with bounded duration and source IP', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profile-logger');

  const options = page.locator('#profileLoggerProfile option');
  await expect(options).toHaveCount(2);
  await expect(options.nth(0)).toBeEnabled();
  await expect(options.nth(0)).toContainText('Fixture Profile (#101)');
  await expect(options.nth(1)).toBeDisabled();
  await expect(page.locator('#profileLoggerActiveIdentity')).toHaveText('Fixture Profile · ID 101');
  await expect(page.locator('#profileLoggerStart')).toBeDisabled();

  await page.locator('#profileLoggerDuration').selectOption('120');
  await page.locator('#profileLoggerSourceIp').fill('192.168.2.10');
  await expect(page.locator('#profileLoggerStart')).toBeEnabled();
  const started = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/profile-diagnostics/start');
  await page.locator('#profileLoggerStart').click();
  expect((await started).postDataJSON()).toEqual({
    profile_id: 101,
    duration_seconds: 120,
    source_ip: '192.168.2.10',
  });
  await expect(page.locator('#profileLoggerState')).toContainText('Запись активна');
  await expect(page.locator('#profileLoggerStop')).toBeEnabled();
});

test('Profile Logger polls without overlap, stops by session, and uses exact safe report Markdown', async ({ page, context }) => {
  await page.request.post('/__fixture/reset');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  let activeStatusRequests = 0;
  let maxConcurrentStatusRequests = 0;
  let concurrentStatusRequests = 0;
  await page.route('**/api/profile-diagnostics/status', async route => {
    activeStatusRequests += 1;
    concurrentStatusRequests += 1;
    maxConcurrentStatusRequests = Math.max(maxConcurrentStatusRequests, concurrentStatusRequests);
    await new Promise(resolve => setTimeout(resolve, 250));
    await route.continue();
    concurrentStatusRequests -= 1;
  });
  await openFixture(page);
  await navigateTo(page, 'profile-logger');
  await page.locator('#profileLoggerSourceIp').fill('192.168.2.10');
  await page.locator('#profileLoggerStart').click();
  await page.waitForTimeout(4300);
  expect(activeStatusRequests).toBeGreaterThanOrEqual(3);
  expect(maxConcurrentStatusRequests).toBe(1);

  const stopped = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/profile-diagnostics/stop');
  await page.locator('#profileLoggerStop').click();
  expect((await stopped).postDataJSON()).toEqual({ session_id: 'diag-fixture-session' });
  await expect(page.locator('#profileLoggerMarkdown')).toHaveValue(/# Profile diagnostic: Fixture Profile/);
  await expect(page.locator('#profileLoggerMarkdown')).toHaveValue(/Fixture TLS timeout while watching YouTube\./);
  await expect(page.locator('#profileLoggerTruncation')).toBeVisible();
  await page.locator('#profileLoggerCopy').click();
  const rendered = await page.locator('#profileLoggerMarkdown').inputValue();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(rendered);

  const requests = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(requests.requests.filter(request => request.path === '/api/profile-diagnostics/report')).toHaveLength(0);
  const repeated = await page.request.post('/api/profile-diagnostics/report', { data: { session_id: 'diag-fixture-session' } });
  expect(repeated.ok()).toBe(true);
  expect((await repeated.json()).report.session_id).toBe('diag-fixture-session');
  const mismatched = await page.request.post('/api/profile-diagnostics/report', { data: { session_id: 'wrong-session' } });
  expect(mismatched.status()).toBe(409);
  const statusAfterReads = await page.request.get('/api/profile-diagnostics/status').then(response => response.json());
  expect(statusAfterReads.active).toBeNull();
  expect(statusAfterReads.completed.session_id).toBe('diag-fixture-session');
  expect(rendered).not.toContain('PROFILE-DIAGNOSTIC-SECRET-CANARY');
  expect(await page.locator('body').innerText()).not.toContain('PROFILE-DIAGNOSTIC-SECRET-CANARY');
});

test('Profile Logger discard clears report and English workflow is complete', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('hr_lang', 'EN'));
  await page.request.post('/__fixture/reset');
  await page.goto('/');
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
  await navigateTo(page, 'profile-logger');
  await expect(page.locator('#contextSection')).toHaveText('Profile Logger');
  await expect(page.locator('#profileLoggerWorkflow')).toContainText('new connections created after Start');
  await expect(page.locator('#profileLoggerPrivacy')).toContainText('contains no keys or subscription URLs');
  await expect(page.locator('#profileLoggerPrivacy')).toContainText('exact specified client');
  await page.locator('#profileLoggerSourceIp').fill('192.168.2.10');
  await page.locator('#profileLoggerStart').click();
  await page.locator('#profileLoggerStop').click();
  await expect(page.locator('#profileLoggerReportPanel')).toBeVisible();

  const discarded = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/profile-diagnostics/discard');
  await page.locator('#profileLoggerDiscard').click();
  expect((await discarded).postDataJSON()).toEqual({ session_id: 'diag-fixture-session' });
  await expect(page.locator('#profileLoggerReportPanel')).toBeHidden();
  await expect(page.locator('#profileLoggerMarkdown')).toHaveValue('');
  await expect(page.locator('#profileLoggerStart')).toBeDisabled();
  await page.locator('#profileLoggerSourceIp').fill('192.168.2.10');
  await expect(page.locator('#profileLoggerStart')).toBeEnabled();
});
