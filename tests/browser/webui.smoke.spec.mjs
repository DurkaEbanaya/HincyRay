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
});

test('profile table shows compact service status and configurable metric columns', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const row = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Profile' });
  await expect(row.locator('.profile-service-test')).toHaveText(['YT', 'TG', 'AI']);
  await expect(row.locator('.profile-service-test.bad')).toHaveText('TG');

  await page.locator('#profileMetricSettings > button').click();
  await page.locator('#profileMetricSettings input[data-profile-metric="latency"]').uncheck();
  await expect(page.locator('#profilesTable thead [data-profile-metric="latency"]')).toBeHidden();
  await expect(row.locator('.profile-name-cell .profile-service-test')).toHaveText(['YT', 'TG', 'AI']);

  const uploadToggle = page.locator('#profileMetricSettings input[data-profile-metric="upload"]');
  await expect(uploadToggle).not.toBeChecked();
  await uploadToggle.check();
  await expect(page.locator('#profilesTable thead [data-profile-metric="upload"]')).toBeVisible();
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem('hr_profile_metrics') || '[]').includes('upload'))).toBe(true);
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
  await expect(row.locator('.profile-name-cell').getByTitle('Тест сервера')).toBeVisible();
  await expect(row.locator('.profile-name-cell').getByTitle('Переименовать')).toBeVisible();
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
  expect(Math.abs(alignment.announcementWidth - alignment.tableWidth)).toBeLessThanOrEqual(1);
  expect(alignment.groupHeaderAlign).toBe('left');
  expect(alignment.tableWidth).toBeLessThan(alignment.wrapperWidth);
  await expect(announcement).toHaveCSS('text-align', 'left');
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

test('profile rename uses a modal instead of window.prompt', async ({ page }) => {
  await openFixture(page);
  const modal = page.getByTestId('profile-rename-modal');
  test.skip(
    await modal.count() === 0,
    'WebUI has no data-testid="profile-rename-modal" marker yet; enable after the modal implementation lands.',
  );

  await navigateTo(page, 'profiles');
  const profileRow = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Profile' });
  await profileRow.getByTitle('Переименовать').click();

  await expect(modal).toBeVisible();
  expect(await page.evaluate(() => window.__fixturePromptCalled)).toBe(false);
});
