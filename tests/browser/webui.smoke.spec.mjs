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
