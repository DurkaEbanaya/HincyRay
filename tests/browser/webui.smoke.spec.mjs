import { expect, test } from '@playwright/test';
const serviceEpoch = Math.floor(Date.now()/1000) - 300;

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

async function openAdvancedParameters(page) {
  await page.evaluate(() => {
    document.getElementById('testPanel').open = true;
    document.getElementById('benchAdvancedParameters').open = true;
  });
}

async function openCheckDetails(page) {
  await navigateTo(page,'profiles');
  await page.evaluate(() => { document.getElementById('benchDetails').open = true; });
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
  await expect(page.locator('.sidebar-brand .version')).toHaveText('v1.3.35');
});

test('core memory cleanup resets the process, reports RSS and blocks overlapping resets', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page,'ov-system');
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let requests = 0;
  await page.route('**/api/core/cleanup', async route => {
    requests++;
    await gate;
    await route.fulfill({json:{previous_pid:1482,pid:1483,rss_before_kb:118784,rss_after_kb:65536}});
  });
  await expect(page.locator('#coreCleanupHint')).toContainText('обрывает все его соединения');
  await page.locator('#coreCleanupButton').click();
  await expect(page.locator('#coreCleanupButton')).toBeDisabled();
  await expect(page.locator('#coreRestartButton')).toBeDisabled();
  await page.evaluate(() => { runCoreReset(true); runCoreReset(false); });
  expect(requests).toBe(1);
  release();
  await expect(page.locator('#coreResetResult')).toContainText('1482 → 1483');
  await expect(page.locator('#coreResetResult')).toContainText('RSS:');
  await expect(page.locator('#coreResetResult')).toContainText('Соединения сброшены');
  await expect(page.locator('#coreRestartButton')).toBeEnabled();
  const restart = page.waitForRequest(r => new URL(r.url()).pathname === '/api/core/restart' && r.method() === 'POST');
  await page.locator('#coreRestartButton').click();
  await restart;
  await expect(page.locator('#coreCleanupButton')).toBeEnabled();
});

test('core cleanup failure is visible and permits retry', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page,'ov-system');
  await page.route('**/api/core/cleanup', route => route.fulfill({status:500,json:{error:'Fixture restart failed'}}));
  await page.locator('#coreCleanupButton').click();
  await expect(page.locator('#coreResetResult')).toContainText('Fixture restart failed');
  await expect(page.locator('#coreCleanupButton')).toBeEnabled();
  await expect(page.locator('#coreRestartButton')).toBeEnabled();
});

test('Direct availability card checks each site and shows independent colors', async ({ page }) => {
  await openFixture(page);
  const request = page.waitForRequest(request => request.method() === 'GET' && new URL(request.url()).pathname === '/api/diagnostics/direct-availability');
  await page.locator('#directAvailabilityButton').click();
  await request;
  await expect(page.locator('[data-direct-site="google"]')).toHaveClass(/ok/);
  await expect(page.locator('[data-direct-site="vk"]')).toHaveClass(/ok/);
  await expect(page.locator('[data-direct-site="ya"]')).toHaveClass(/ok/);
  await expect(page.locator('[data-direct-site="bing"]')).toHaveCount(0);
  await expect(page.locator('[data-direct-site="telegram"]')).toHaveCount(0);
  await expect(page.locator('[data-direct-site]')).toHaveCount(4);
  await expect(page.locator('[data-direct-site="youtube"]')).toHaveClass(/bad/);
});

test('Direct policy automation stays opt-in and selects devices by MAC', async ({ page }) => {
  await openFixture(page);
  await page.evaluate(() => navTo('direct-policy'));
  await expect(page.locator('#directPolicyEnabled')).not.toBeChecked();
  await expect(page.locator('#directPolicyDevices')).toContainText('192.168.2.33');
  await expect(page.locator('#directPolicyDevices .direct-policy-lamp.online')).toHaveAttribute('aria-label', 'Подключено');
  await expect(page.locator('#directPolicyOffline')).not.toHaveAttribute('open', '');
  await expect(page.locator('#directPolicyOfflineSummary')).toHaveText('Не подключены (1)');
  await expect(page.locator('#directPolicyOfflineDevices .direct-policy-lamp.offline')).toHaveAttribute('aria-label', 'Не подключено');
  await expect(page.locator('#directPolicyOfflineDevices input[data-policy-mac]')).toBeChecked();
  await page.locator('#directPolicyOfflineSummary').click();
  await expect(page.locator('#directPolicyOfflineDevices')).toBeVisible();
  await page.locator('#directPolicyDevices label.toggle').click();
  await page.locator('[data-section="direct-policy"] .section-body > .form-row label.toggle').click();
  const request = page.waitForRequest(r => r.method() === 'POST' && new URL(r.url()).pathname === '/api/automation/direct-policy');
  await page.locator('#directPolicySave').click();
  expect((await request).postDataJSON()).toEqual({enabled:true,devices:['02:00:00:00:00:33','02:00:00:00:00:44']});
});

test('best-of-best stays opt-in, uses routing refs, and ranks both target pickers by checked services then ping', async ({ page }) => {
  await page.route('**/api/stats', async route => {
    const response = await route.fetch();
    const data = await response.json();
    const now = Math.floor(Date.now() / 1000);
    data.stats.push({profile_id:102,server_ref:'srv-v2-fixture-manual',last_service_test_unix:now,
      resource_tests:[{id:'youtube_thumbnails',contract_version:1,attempts:1,successes:1,stable:true},
        {id:'telegram',contract_version:7,attempts:1,successes:1,stable:true},
        {id:'ai',contract_version:7,attempts:1,successes:1,stable:true},
        {id:'ping_proxy',contract_version:7,attempts:1,successes:1,reachable:true,avg_ttfb_ms:300}]});
    await route.fulfill({response,json:data});
  });
  await openFixture(page);
  await page.evaluate(() => navTo('best-of-best'));
  await expect(page.locator('#bestOfBestEnabled')).not.toBeChecked();
  await expect(page.locator('#bestOfBestCandidates')).toContainText('Fixture Profile');
  const checkbox = page.locator('#bestOfBestCandidates input[data-best-ref="srv-v1-fixture"]');
  await checkbox.check();
  await setBestOfBestOption(page,'HideUntested',false);
  await page.locator('#bestOfBestSearch').fill('#102');
  const manual = page.locator('#bestOfBestCandidates input[data-best-ref="srv-v1-wagon"]');
  await manual.check();
  await expect(page.locator('#bestOfBestCount')).toHaveText('В пуле: 2 / 16');
  await manual.uncheck();
  await expect(page.locator('#bestOfBestCount')).toHaveText('В пуле: 1 / 16');
  const posted = page.waitForRequest(r => r.method() === 'POST' && new URL(r.url()).pathname === '/api/automation/best-of-best');
  await page.locator('#bestOfBestSave').click();
  expect((await posted).postDataJSON()).toEqual({enabled:false,server_refs:['srv-v1-fixture']});

  const order = await page.evaluate(() => {
    const values = html => Array.from(new DOMParser().parseFromString(`<select>${html}</select>`,'text/html').querySelectorAll('option[value^="server:"]')).map(option => option.value);
    return {rules:values(routingTargetOptions('active')),connections:values(routingTargetServerOptions(''))};
  });
  expect(order.rules.slice(0,2)).toEqual(['server:srv-v1-wagon','server:srv-v1-fixture']);
  expect(order.connections.slice(0,2)).toEqual(order.rules.slice(0,2));
  expect(order.rules.at(-1)).toBe('server:srv-v1-dead-route');
  const byPing = await page.evaluate(() => {
    const originalServers = MOCK.routing_servers;
    const originalProfiles = MOCK.profiles;
    const source = originalProfiles.find(profile => profile.id === 102);
    MOCK.profiles = [...originalProfiles, {...source,id:200,server_ref:'srv-v2-fixture-fast',resource_tests:source.resource_tests.map(test => test.id === 'ping_proxy' ? {...test,avg_ttfb_ms:20} : test)}];
    MOCK.routing_servers = [...originalServers,{id:200,ref:'srv-v1-fixture-fast',lifecycle_ref:'srv-v2-fixture-fast',name:'Fast fixture',group:'https://provider.example/sub/fixture-token',dead:false}];
    const result = new DOMParser().parseFromString(`<select>${routingTargetServerOptions('')}</select>`,'text/html');
    const values = [...result.querySelectorAll('option[value^="server:"]')].map(option => option.value);
    MOCK.profiles = originalProfiles;
    MOCK.routing_servers = originalServers;
    return values;
  });
  expect(byPing.slice(0,2)).toEqual(['server:srv-v1-fixture-fast','server:srv-v1-wagon']);
});

async function installBestOfBestCatalogFixture(page) {
  const check = state => ({state,tested:!['not-tested','skipped'].includes(state)});
  const candidate = (id, yt, tg, ai, ping, pingMs) => ({
    id,ref:`srv-v1-catalog-${id}`,name:`Catalog ${id}`,ping_ms:pingMs,
    tested:[yt,tg,ai,ping].some(state => !['not-tested','skipped'].includes(state)),
    checks:{youtube_thumbnails:check(yt),telegram:check(tg),ai:check(ai),ping_proxy:check(ping)},
  });
  const data = {settings:{enabled:false,server_refs:['srv-v1-catalog-7','srv-v1-missing-member'],selected_ref:null},max_candidates:16,candidates:[
    candidate(1,'passed','failed','unknown','passed',10),
    candidate(2,'failed','passed','passed','passed',40),
    candidate(3,'passed','passed','failed','passed',60),
    candidate(4,'stale','stale','stale','stale',null),
    candidate(5,'not-tested','not-tested','not-tested','not-tested',null),
    candidate(6,'unknown','skipped','unknown','unknown',null),
    candidate(7,'not-tested','not-tested','not-tested','not-tested',null),
    candidate(8,'passed','passed','passed','passed',20),
  ]};
  await page.route('**/api/automation/best-of-best', async route => {
    if (route.request().method() === 'POST') data.settings = {...route.request().postDataJSON(),selected_ref:null};
    await route.fulfill({json:data});
  });
  await openFixture(page);
  await navigateTo(page,'best-of-best');
  await expect(page.locator('#bestOfBestCandidates')).toContainText('Catalog 8');
}

async function visibleBestOfBestIds(page) {
  return page.locator('#bestOfBestCandidates [data-best-search]').evaluateAll(rows => rows
    .filter(row => row.style.display !== 'none').map(row => Number(row.querySelector('input').dataset.bestRef.split('-').at(-1))));
}

async function setBestOfBestOption(page, option, checked) {
  const input = page.locator(`#bestOfBest${option}`);
  if (await input.isChecked() !== checked) await input.locator('..').click();
  await expect(input).toBeChecked({checked});
}

test('best-of-best independent criteria cover single, combined, ping-only and disabled sorting', async ({ page }) => {
  await installBestOfBestCatalogFixture(page);
  await expect(page.locator('#bestOfBestHideUntested')).toBeChecked();
  await expect(page.locator('#bestOfBestHideFailed')).not.toBeChecked();
  expect(await visibleBestOfBestIds(page)).toEqual([8,2,3,1,4,6,7]);
  const row = page.locator('#bestOfBestCandidates label').filter({hasText:'Catalog 1'});
  await expect(row.locator('.profile-service-test')).toHaveText(['P 10 ms','YT','TG','AI ?']);
  expect(await row.locator('.profile-service-test').evaluateAll(badges => badges.map(badge => badge.dataset.state))).toEqual(['passed','passed','failed','unknown']);
  const cases = [
    [[],1], [['Ping'],1], [['Youtube'],1], [['Telegram'],2], [['Ai'],2],
    [['Youtube','Telegram'],3], [['Youtube','Ai'],8], [['Telegram','Ai'],2],
    [['Youtube','Telegram','Ai'],8], [['Ping','Youtube'],1], [['Ping','Telegram'],8],
    [['Ping','Ai'],8], [['Ping','Youtube','Telegram'],8], [['Ping','Youtube','Ai'],8],
    [['Ping','Telegram','Ai'],8], [['Ping','Youtube','Telegram','Ai'],8],
  ];
  for (const [enabled,first] of cases) {
    for (const key of ['Ping','Youtube','Telegram','Ai']) {
      await setBestOfBestOption(page,`Sort${key}`,enabled.includes(key));
    }
    expect((await visibleBestOfBestIds(page))[0], enabled.join('+') || 'no criteria').toBe(first);
  }
  for (const key of ['Youtube','Telegram','Ai']) await setBestOfBestOption(page,`Sort${key}`,false);
  expect(await visibleBestOfBestIds(page)).toEqual([1,8,2,3,4,6,7]);
});

test('best-of-best filters distinguish missing, failed, stale and unknown checks and preserve membership order', async ({ page }) => {
  await installBestOfBestCatalogFixture(page);
  await setBestOfBestOption(page,'HideFailed',true);
  expect(await visibleBestOfBestIds(page)).toEqual([8,4,6,7]);
  await setBestOfBestOption(page,'HideUntested',false);
  expect(await visibleBestOfBestIds(page)).toEqual([8,4,5,6,7]);
  await setBestOfBestOption(page,'SortTelegram',false);
  expect(await visibleBestOfBestIds(page)).toEqual([8,1,4,5,6,7]);
  await setBestOfBestOption(page,'SortYoutube',false);
  await setBestOfBestOption(page,'SortAi',false);
  await setBestOfBestOption(page,'SortPing',false);
  expect(await visibleBestOfBestIds(page)).toEqual([1,2,3,4,5,6,7,8]);
  await setBestOfBestOption(page,'SortYoutube',true);
  await setBestOfBestOption(page,'SortTelegram',true);
  await setBestOfBestOption(page,'SortAi',true);
  await setBestOfBestOption(page,'SortPing',true);
  await setBestOfBestOption(page,'HideUntested',true);
  await setBestOfBestOption(page,'HideFailed',false);
  await page.locator('input[data-best-ref="srv-v1-catalog-1"]').check();
  await page.locator('input[data-best-ref="srv-v1-catalog-2"]').check();
  await setBestOfBestOption(page,'HideFailed',true);
  expect(await visibleBestOfBestIds(page)).toEqual([8,2,1,4,6,7]);
  await page.locator('#bestOfBestSearch').fill('absent');
  await expect(page.locator('#bestOfBestEmpty')).toBeVisible();
  await expect(page.locator('#bestOfBestVisibleCount')).toHaveText('Показано: 0 / 8');
  // A late refresh must not replace the draft, including invisible/missing refs.
  await page.evaluate(() => loadBestOfBest());
  await expect(page.locator('#bestOfBestCount')).toHaveText('В пуле: 4 / 16');
  const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/automation/best-of-best');
  await page.locator('#bestOfBestSave').click();
  expect((await posted).postDataJSON()).toEqual({enabled:false,server_refs:[
    'srv-v1-catalog-7','srv-v1-missing-member','srv-v1-catalog-1','srv-v1-catalog-2',
  ]});
  await page.locator('#bestOfBestSearch').fill('Catalog 1');
  await page.locator('input[data-best-ref="srv-v1-catalog-1"]').uncheck();
  await expect(page.locator('input[data-best-ref="srv-v1-catalog-1"]')).toBeHidden();
  await expect(page.locator('#bestOfBestCount')).toHaveText('В пуле: 3 / 16');
});

test('best-of-best catalog preferences survive reload and fit a narrow mobile screen', async ({ page }) => {
  await installBestOfBestCatalogFixture(page);
  await setBestOfBestOption(page,'HideUntested',false);
  await setBestOfBestOption(page,'HideFailed',true);
  await setBestOfBestOption(page,'SortYoutube',false);
  await setBestOfBestOption(page,'SortAi',false);
  await page.reload();
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
  await navigateTo(page,'best-of-best');
  await expect(page.locator('#bestOfBestHideUntested')).not.toBeChecked();
  await expect(page.locator('#bestOfBestHideFailed')).toBeChecked();
  await expect(page.locator('#bestOfBestSortYoutube')).not.toBeChecked();
  await expect(page.locator('#bestOfBestSortAi')).not.toBeChecked();
  await expect(page.locator('#bestOfBestSortTelegram')).toBeChecked();
  await expect(page.locator('#bestOfBestSortPing')).toBeChecked();
  expect(await visibleBestOfBestIds(page)).toEqual([8,2,3,4,5,6,7]);
  await page.setViewportSize({width:360,height:800});
  await expect(page.locator('#bestOfBestSort')).toBeVisible();
  const dimensions = await page.evaluate(() => ({width:innerWidth,scroll:document.documentElement.scrollWidth}));
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.width);
});

test('best-of-best applies the POST snapshot, ignores old GETs and indicates progress in the sidebar', async ({ page }) => {
  const data = {settings:{enabled:false,server_refs:['srv-v1-fixture'],selected_ref:null},max_candidates:16,candidates:[
    {ref:'srv-v1-fixture',id:101,name:'Fixture Profile',tested:true,checks:{}},
  ]};
  let releaseOldGet;
  const oldGet = new Promise(resolve => { releaseOldGet = resolve; });
  let releasePost;
  const post = new Promise(resolve => { releasePost = resolve; });
  let getCount = 0;
  await page.route('**/api/automation/best-of-best', async route => {
    if (route.request().method() === 'GET') {
      const stale = structuredClone(data);
      if (++getCount === 2) await oldGet;
      await route.fulfill({json:stale});
    } else {
      data.settings = {...route.request().postDataJSON(),selected_ref:null};
      await post;
      await route.fulfill({json:data});
    }
  });
  await openFixture(page);
  await navigateTo(page,'best-of-best');
  await expect(page.locator('#bestOfBestState')).toHaveText('Пул выключен');
  await page.evaluate(() => { window.__oldBestLoad = loadBestOfBest(); });
  await expect.poll(() => getCount).toBe(2);
  await setBestOfBestOption(page,'Enabled',true);
  await expect(page.locator('#bestOfBestState')).toContainText('ещё не применены');
  await page.locator('#bestOfBestSave').click();
  await expect(page.locator('#longOperationProgress')).toBeVisible();
  await expect(page.locator('#longOperationLabel')).toContainText('Применение пула');
  await expect(page.locator('#longOperationKitt')).toHaveClass(/running/);
  await expect(page.locator('#longOperationProgress')).toHaveAttribute('data-operation-section','best-of-best');
  await expect(page.locator('#bestOfBestSave')).toHaveAttribute('aria-busy','true');
  await expect(page.locator('#bestOfBestEnabled')).toBeDisabled();
  await expect(page.locator('input[data-best-ref]')).toBeDisabled();
  releasePost();
  await expect(page.locator('#bestOfBestState')).toHaveText('Пул включён');
  await expect(page.locator('#bestOfBestEnabled')).toBeChecked();
  await expect(page.locator('#msgBar')).toHaveText('Пул включён, состав применён');
  releaseOldGet();
  await page.evaluate(() => window.__oldBestLoad);
  await expect(page.locator('#bestOfBestEnabled')).toBeChecked();
  expect(getCount).toBe(2);
  await expect(page.locator('#longOperationProgress')).toBeHidden();
  await page.reload();
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
  await navigateTo(page,'best-of-best');
  await expect(page.locator('#bestOfBestEnabled')).toBeChecked();
  await setBestOfBestOption(page,'Enabled',false);
  await page.locator('#bestOfBestSave').click();
  await expect(page.locator('#bestOfBestState')).toHaveText('Пул выключен');
  await expect(page.locator('#bestOfBestSelected')).toHaveText('Пул выключен; состав сохранён');
  await expect(page.locator('#msgBar')).toHaveText('Пул выключен, состав сохранён');
});

test('best-of-best failed apply retains the draft for retry and clears busy indicators', async ({ page }) => {
  await installBestOfBestCatalogFixture(page);
  await page.route('**/api/automation/best-of-best', async route => {
    if (route.request().method() !== 'POST') return route.fallback();
    await route.fulfill({status:500,json:{error:'Fixture apply failed'}});
  });
  await setBestOfBestOption(page,'Enabled',true);
  await page.locator('input[data-best-ref="srv-v1-catalog-8"]').check();
  await page.locator('#bestOfBestSave').click();
  await expect(page.locator('#msgBar')).toHaveText('Fixture apply failed');
  await expect(page.locator('#bestOfBestEnabled')).toBeChecked();
  await expect(page.locator('#bestOfBestState')).toContainText('ещё не применены');
  await expect(page.locator('input[data-best-ref="srv-v1-catalog-8"]')).toBeChecked();
  await expect(page.locator('#bestOfBestSave')).toBeEnabled();
  await expect(page.locator('#bestOfBestSave')).not.toHaveAttribute('aria-busy','true');
  await expect(page.locator('#longOperationProgress')).toBeHidden();
});

test('best-of-best excludes dead catalog entries while unavailable members can be explicitly removed', async ({ page }) => {
  const data = {settings:{enabled:false,server_refs:['srv-v1-dead','srv-v1-missing','srv-v1-live'],selected_ref:null},max_candidates:16,candidates:[
    {ref:'srv-v1-live',id:1,name:'Living candidate',tested:true,checks:{}},
    {ref:'srv-v1-dead',id:2,name:'Dead candidate',dead:true,tested:true,checks:{}},
    {ref:'srv-v1-dead-unselected',id:3,name:'Dead unselected',dead:true,tested:false,checks:{}},
  ]};
  await page.route('**/api/automation/best-of-best', async route => {
    if (route.request().method() === 'POST') data.settings = {...route.request().postDataJSON(),selected_ref:null};
    await route.fulfill({json:data});
  });
  await openFixture(page);
  await navigateTo(page,'best-of-best');
  await expect(page.locator('#bestOfBestCandidates')).toContainText('Living candidate');
  await setBestOfBestOption(page,'HideUntested',false);
  await expect(page.locator('#bestOfBestCandidates')).not.toContainText('Dead');
  await expect(page.locator('#bestOfBestCandidates [data-best-search]')).toHaveCount(1);
  await expect(page.locator('#bestOfBestCount')).toHaveText('В пуле: 3 / 16');
  await expect(page.locator('#bestOfBestUnavailableCount')).toContainText('2');
  await page.locator('#bestOfBestUnavailable button').click();
  await expect(page.locator('#bestOfBestUnavailable')).toBeHidden();
  const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/automation/best-of-best');
  await page.locator('#bestOfBestSave').click();
  expect((await posted).postDataJSON()).toEqual({enabled:false,server_refs:['srv-v1-live']});
});

test('best-of-best manual bad marks demote even the best server, persist and preserve pool membership', async ({ page }) => {
  await installBestOfBestCatalogFixture(page);
  await page.locator('input[data-best-ref="srv-v1-catalog-8"]').check();
  const mark = page.locator('button[data-best-bad="srv-v1-catalog-8"]');
  await mark.click();
  await expect(mark).toHaveAttribute('aria-pressed','true');
  expect((await visibleBestOfBestIds(page)).at(-1)).toBe(8);
  await setBestOfBestOption(page,'SortPing',false);
  expect((await visibleBestOfBestIds(page)).at(-1)).toBe(8);
  await setBestOfBestOption(page,'SortPing',true);
  await page.locator('#bestOfBestSave').click();
  await expect(page.locator('#bestOfBestState')).toHaveText('Пул выключен');
  await expect(page.locator('input[data-best-ref="srv-v1-catalog-8"]')).toBeChecked();
  await page.reload();
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
  await navigateTo(page,'best-of-best');
  await expect(mark).toHaveAttribute('aria-pressed','true');
  expect((await visibleBestOfBestIds(page)).at(-1)).toBe(8);
  await mark.click();
  await expect(mark).toHaveAttribute('aria-pressed','false');
  expect((await visibleBestOfBestIds(page))[0]).toBe(8);
  await expect(page.locator('#bestOfBestCount')).toHaveText('В пуле: 3 / 16');
});

test('Direct bot settings accept a private token and prompt /start pairing', async ({ page }) => {
  await openFixture(page);
  await page.locator('#directBotToken').fill('123456:abcdefghijklmnopqrstuvwxyz');
  const request = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/diagnostics/direct-monitor');
  await page.locator('#directBotSave').click();
  const submitted = await request;
  expect(submitted.postDataJSON()).toEqual({enabled:true,token:'123456:abcdefghijklmnopqrstuvwxyz'});
  await expect(page.locator('#directBotToken')).toBeEmpty();
  await expect(page.locator('#directBotStatus')).toContainText('/start');
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
  await expect(row.locator('[data-bench-scope="single"]')).toHaveAttribute('title', 'Для этого сервера');
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
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect.poll(() => page.locator('#longOperationScanner').evaluate(element => ({
    name: getComputedStyle(element).animationName,
    duration: getComputedStyle(element).animationDuration,
  }))).toEqual({ name: 'bench-kitt-scan', duration: '3.4s' });
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

test('shared search defaults, failure policy, service prefix, target, and concurrency persist', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await openAdvancedParameters(page);
  await expect(page.locator('#benchSearchStopMode')).toHaveValue('complete_scope');
  await expect(page.locator('#benchSearchTarget')).toHaveValue('5');
  await expect(page.locator('#benchSearchTarget')).toBeDisabled();
  await expect(page.locator('#benchSearchServices')).toHaveValue('all');
  await expect(page.locator('#benchSearchServices')).toBeEnabled();
  await expect(page.locator('#benchSearchFailFast')).not.toBeChecked();
  await expect(page.locator('#benchSearchFailFast')).toBeEnabled();
  await expect(page.locator('label[for="benchConcurrency"]')).toHaveText('Параллельных серверов');
  expect(await page.locator('#benchConcurrency').evaluate(select => ({
    native: select.dataset.nativeSelect,
    enhanced: select.dataset.customSelectEnhanced || null,
    wrapped: select.parentElement?.classList.contains('custom-select') || false,
  }))).toEqual({ native: '1', enhanced: null, wrapped: false });
  await page.locator('#benchConcurrency').selectOption('4');
  await page.locator('#benchSearchStopMode').selectOption('find_n');
  await expect(page.locator('#benchSearchServices')).toHaveValue('all');
  await expect(page.locator('#benchSearchServices option[value="all"]')).toBeEnabled();
  await expect(page.locator('#benchSearchFailFast')).toBeEnabled();
  await page.locator('#benchSearchFailFast').locator('xpath=..').click();
  await page.locator('#benchSearchTarget').fill('20');
  await page.locator('#benchSearchServices').selectOption('ai');
  await expect.poll(() => page.evaluate(() => localStorage.getItem('hr_bench_concurrency'))).toBe('4');

  await page.reload();
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
  await navigateTo(page, 'profiles');
  await expect(page.locator('#benchConcurrency')).toHaveValue('4');
  await expect(page.locator('#benchSearchStopMode')).toHaveValue('find_n');
  await expect(page.locator('#benchSearchTarget')).toHaveValue('20');
  await expect(page.locator('#benchSearchServices')).toHaveValue('ai');
  await expect(page.locator('#benchSearchFailFast')).toBeChecked();
  await expect(page.locator('#benchSearchFailFast')).toBeEnabled();
  await openAdvancedParameters(page);
  await page.locator('#benchSearchStopMode').selectOption('complete_scope');
  await expect(page.locator('#benchSearchServices')).toHaveValue('ai');
  await expect(page.locator('#benchSearchServices')).toBeEnabled();
  await expect(page.locator('#benchSearchFailFast')).toBeChecked();
  await expect(page.locator('label[for="benchSearchFailFast"]')).toHaveText('Стоп после сбоя YT/TG');
  await page.locator('#benchSearchStopMode').selectOption('find_n');
  await expect(page.locator('#benchSearchServices')).toHaveValue('ai');
  expect(await page.evaluate(() => Object.fromEntries(Object.entries(localStorage).filter(([key]) => key.startsWith('hr_search_'))))).toEqual({
    hr_search_stop_mode: '"find_n"', hr_search_target_good: '20', hr_search_required_services: '"ai"', hr_search_fail_fast: 'true', hr_search_reject_no_ping: 'false', hr_search_full_ping: 'false',
  });
  await page.locator('#benchSearchServices').selectOption('all');
  await page.reload();
  await expect(page.locator('#benchSearchServices')).toHaveValue('all');
  expect(await page.evaluate(() => localStorage.getItem('hr_search_required_services'))).toBe('"all"');
});

test('profile test post-actions load and save exact persisted settings', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await page.locator('#testPanel > summary').click();
  await page.locator('#benchNativeCompatibility > summary').click();
  await expect(page.locator('#benchPromoteSuccessful')).not.toBeChecked();
  await expect(page.locator('#benchAutoMoveNoPing')).not.toBeChecked();
  await expect(page.locator('#benchNativePostActionsLabel')).toHaveText('Нативные пост-действия (совместимость)');
  await expect(page.locator('#benchPromoteSuccessful')).toBeEnabled();
  await expect(page.locator('#benchAutoMoveNoPing')).toBeEnabled();

  await page.locator('#benchPromoteSuccessful').locator('xpath=..').click();
  await page.locator('#benchAutoMoveNoPing').locator('xpath=..').click();
  const saveRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/settings'
  );
  await page.locator('#benchSettingsSave').click();
  expect((await saveRequest).postDataJSON()).toEqual({
    promote_successful_tested_servers: true,
    auto_move_no_ping_to_dead_servers: true,
  });

  await page.reload();
  await expect(page.locator('#profilesBody')).toContainText('Fixture Profile');
  await expect(page.locator('#benchPromoteSuccessful')).toBeChecked();
  await expect(page.locator('#benchAutoMoveNoPing')).toBeChecked();
  await page.request.post('/__fixture/reset');
});

test('inconclusive YouTube is amber, not a pass or failure, with exhausted discovery and setup diagnostics', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await openCheckDetails(page);
  const fixture = await page.request.post('/__fixture/bench-inconclusive').then(response => response.json());
  expect(fixture.summary).toEqual({ total: 1, passed: 0, failed: 0, inconclusive: 1, avg_latency_ms: 0 });
  expect(fixture.results[0].success).toBe(false);
  expect(fixture.search).toEqual(expect.objectContaining({ found_good: 0, quick_completed: 1, preflight_rejected: 1, finish_reason: 'exhausted' }));
  await page.evaluate(() => loadProfiles());
  await page.evaluate(() => pollBenchStatus());
  const row = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' });
  const youtube = row.locator('.profile-service-test.unknown');
  await expect(youtube).toHaveText('YT ?');
  await expect(youtube).toHaveCSS('color', 'rgb(255, 185, 0)');
  await expect(youtube).toHaveAttribute('title', /Страницу канала\/превью не удалось подтвердить.*Не подтверждает непригодность сервера.*HTTP 200: LOGIN_REQUIRED/);
  await expect(row.locator('.profile-service-test.ok, .profile-service-test.bad')).toHaveCount(0);
  await expect(row.locator('.profile-service-test.skipped')).toHaveText(['TG', 'AI']);
  expect(await page.evaluate(() => MOCK.profiles.find(profile => profile.id === 102).last_service_test_success)).toBeNull();
  await expect(page.locator('#benchCurrent')).toHaveText('Проверка завершена');
  await expect(page.locator('#benchSearchStatus')).toHaveText('Найдено: 0/5 (YT) · Предпроверено: 2 · Отсеяно предпроверкой: 1 · Сервисы проверены: 1');
  await expect(page.locator('#benchInconclusiveStatus')).toContainText('Проверку доступности не удалось подтвердить: 1');
  await expect(page.locator('#benchSummary')).toBeHidden();
  await expect(page.locator('#benchPreflightDiagnostics')).toBeVisible();
  await page.locator('#benchPreflightDiagnostics > summary').click();
  await expect(page.locator('#benchPreflightFailures')).toContainText('#104 · Подготовка ядра: Temporary core setup rejected; https://provider.example/sub/<token>');
  await page.evaluate(() => toggleLang());
  await expect(youtube).toHaveAttribute('title', /Channel page\/thumbnails could not be verified.*Does not prove the server is unusable/);
  await expect(page.locator('#benchInconclusiveStatus')).toHaveText('Availability checks could not be verified: 1. Not counted as success or a proven server failure.');
  await expect(page.locator('#benchPreflightDiagnostics > summary')).toHaveText('Preflight diagnostics (last 20)');
  await expect(page.locator('#benchPreflightFailures')).toContainText('#104 · Core setup');
  await page.request.post('/__fixture/bench-status', { data: { ...fixture, search: null, results: [{ ...fixture.results[0], method: 'availability_quick' }] } });
  await page.evaluate(() => pollBenchStatus());
  await expect(page.locator('#benchSummary')).toHaveCSS('display', 'grid');
  await expect(page.locator('#benchPassed')).toHaveText('0');
  await expect(page.locator('#benchFailed')).toHaveText('0');
  await expect(page.locator('#benchInconclusive')).toHaveText('1');
  await expect(page.locator('#benchAvg')).toHaveText('— ms');
  await page.request.post('/__fixture/reset');
});

test('inconclusive overrides legacy success and zero attempts, including unchanged result fingerprints', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  for (const attempts of [1,0]) {
    await page.evaluate(attempts => {
      const resource = { contract_version: 1, id: 'youtube_thumbnails', name: 'YouTube channel/thumbnails', stable: true, reachable: true, successes: 1, attempts: 1, inconclusive: false };
      const result = { profile_id: 102, server_ref: 'srv-v2-fixture-manual', method: 'availability_quick', success: true, timestamp: Math.floor(Date.now()/1000), latency_ms: 100, resource_tests: [resource] };
      updateBenchStatus({ running: false, method: 'availability_quick', results: [result] });
      resource.inconclusive = true;
      resource.attempts = attempts;
      resource.error = 'HTTP 200: LOGIN_REQUIRED; channel page/thumbnails not verified';
      updateBenchStatus({ running: false, method: 'availability_quick', results: [result], summary: { inconclusive: 1 } });
    }, attempts);
    const row = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' });
    await expect(row.locator('.profile-service-test.unknown')).toHaveText('YT ?');
    await expect(row.locator('.profile-service-test.ok, .profile-service-test.bad')).toHaveCount(0);
    await expect(row.locator('.profile-service-test.skipped')).toHaveText(['TG', 'AI']);
    await expect(page.locator('#benchPassed')).toHaveText('0');
    await expect(page.locator('#benchFailed')).toHaveText('0');
    expect(await page.evaluate(() => MOCK.profiles.find(profile => profile.id === 102).last_service_test_success)).toBeNull();
    expect(await page.evaluate(() => profileSuccessfulChecks(MOCK.profiles.find(profile => profile.id === 102)))).toBe(0);
  }
  const legacy = await page.evaluate(() => profileServiceTestsHtml([{ contract_version: 6, id: 'youtube', stable: true, successes: 1, attempts: 1 }],Math.floor(Date.now()/1000)));
  expect(legacy).toContain('Устаревший результат; требуется новая проверка');
  expect(legacy.match(/profile-service-test (?:skipped|stale)/g)).toHaveLength(3);
});

test('native video caches never become thumbnail passes and cannot overwrite availability evidence', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const classifications = await page.evaluate(() => {
    const base = { stable: true, reachable: true, attempts: 1, successes: 1 };
    const obsolete = [
      { ...base, id: 'youtube', contract_version: 7 },
      { ...base, id: 'youtube_thumbnails', contract_version: 7 },
      { ...base, id: 'youtube_thumbnails', contract_version: 2 },
    ];
    return obsolete.map(resource => ({
      neutral: (profileServiceTestsHtml([resource],Math.floor(Date.now()/1000)).match(/profile-service-test (?:skipped|stale)/g) || []).length,
      checks: profileSuccessfulChecks({ resource_tests: [resource],last_service_test_unix:Math.floor(Date.now()/1000) }),
      overall: normalizeProfiles({ stats: [{ profile_id: 102, last_service_test_unix:Math.floor(Date.now()/1000), last_service_test_success: true, resource_tests: [resource] }] }, { profiles: [{ id: 102 }] })[0].last_service_test_success,
    }));
  });
  expect(classifications).toEqual(Array.from({ length: 3 }, () => ({ neutral: 3, checks: 0, overall: null })));
  await page.evaluate(() => {
    const native = { contract_version: 7, id: 'youtube', name: 'Native video', attempts: 1, successes: 0, stable: false, inconclusive: true };
    const thumbnails = { contract_version: 1, id: 'youtube_thumbnails', name: 'YouTube channel/thumbnails', attempts: 1, successes: 1, stable: true };
    const result = { profile_id: 102, server_ref: 'srv-v2-fixture-manual', timestamp: Math.floor(Date.now()/1000), method: 'availability_quick', success: true, resource_tests: [native,thumbnails] };
    updateBenchStatus({ running: false, method: 'availability_quick', results: [result], summary: { inconclusive: 0 } });
  });
  const row = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' });
  await expect(row.locator('.profile-service-test')).toHaveText(['YT', 'TG', 'AI']);
  await expect(row.locator('.profile-service-test.ok')).toHaveAttribute('title', /YouTube channel\/thumbnails/);
  await expect(page.locator('#benchPassed')).toHaveText('1');
  await expect(page.locator('#benchInconclusiveStatus')).toBeHidden();
  expect(await page.evaluate(() => MOCK.profiles.find(profile => profile.id === 102).last_service_test_success)).toBe(true);
  await page.evaluate(() => updateBenchStatus({ running: false, method: 'quick', summary: { passed: 1, inconclusive: 1 }, results: [{
    profile_id: 102, server_ref: 'srv-v2-fixture-manual', timestamp: Math.floor(Date.now()/1000), method: 'quick', success: true, resource_tests: [{ contract_version: 7, id: 'youtube', stable: true, attempts: 1, successes: 1 }],
  }] }));
  await expect(page.locator('#benchSummary')).toBeHidden();
  await expect(page.locator('#benchInconclusiveStatus')).toBeHidden();
  await expect(row.locator('.profile-service-test.ok')).toHaveAttribute('title', /YouTube channel\/thumbnails/);
  expect(await page.evaluate(() => MOCK.profiles.find(profile => profile.id === 102).last_service_test_success)).toBe(true);
});

test('preflight diagnostics whitelist and escape fields, retain last 20, and bound UTF-8 errors to 2 KiB', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await openCheckDetails(page);
  const failures = Array.from({ length: 25 }, (_, index) => ({
    profile_id: 1000 + index, phase: index === 5 ? '<img src=x onerror="window.__diagnosticInjected=true">' : 'transport',
    error: index === 24 ? '<script>window.__diagnosticInjected=true</script> https://provider.example/sub/<token> ' + 'Ж'.repeat(2200) + 'DROPPED-SUFFIX' : `Rejected transport ${index}`,
    raw: 'RAW-DIAGNOSTIC-CANARY', username: 'USER-DIAGNOSTIC-CANARY',
  }));
  await page.request.post('/__fixture/bench-status', { data: {
    running: false, results: [], summary: { passed: 0, failed: 0, inconclusive: 0 }, preflight_failures: failures,
    raw: 'PARENT-RAW-CANARY', username: 'PARENT-USER-CANARY',
  }});
  await page.evaluate(() => pollBenchStatus());
  await page.locator('#benchPreflightDiagnostics > summary').click();
  const list = page.locator('#benchPreflightFailures');
  await expect(list.locator('li')).toHaveCount(20);
  await expect(list.locator('li').first()).toContainText('#1005 · <img src=x');
  await expect(list.locator('li').last()).toContainText('<script>window.__diagnosticInjected=true</script> https://provider.example/sub/<token>');
  await expect(list.locator('img, script, a')).toHaveCount(0);
  await expect(list).not.toContainText('DROPPED-SUFFIX');
  await expect(list).not.toContainText('CANARY');
  const bounded = await list.locator('li').last().evaluate(li => {
    const error = Array.from(li.childNodes).filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent).join('').slice(2);
    return { bytes: new TextEncoder().encode(error).length, replacement: error.includes('\uFFFD') };
  });
  expect(bounded.bytes).toBeLessThanOrEqual(2048);
  expect(bounded.bytes).toBeGreaterThanOrEqual(2047);
  expect(bounded.replacement).toBe(false);
  expect(await page.evaluate(() => window.__diagnosticInjected || false)).toBe(false);
  await expect(page.locator('#benchSummary')).toBeHidden();
  await page.request.post('/__fixture/bench-status', { data: { running: false, results: [], preflight_failures: [] } });
  await page.evaluate(() => pollBenchStatus());
  await expect(page.locator('#benchPreflightDiagnostics')).toBeHidden();
  await expect(list.locator('li')).toHaveCount(0);
});

test('all profile rows retain neutral service chips without current or requested evidence', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  for (const name of ['Fixture Manual', 'Fixture Second Subscription', 'Fixture Dead']) {
    const row = page.locator('#profilesBody tr').filter({ has: page.locator('.profile-name', { hasText: name }) });
    await expect(row.locator('.profile-service-test.skipped')).toHaveText(['YT', 'TG', 'AI']);
    await expect(row.locator('.profile-service-test.ok, .profile-service-test.bad')).toHaveCount(0);
    await expect(row.locator('.profile-service-test').first()).toHaveAttribute('title', /Не проверено/);
  }
  await page.evaluate(() => {
    MOCK.profiles.find(profile => profile.id === 102).resource_tests = [{ id: 'youtube', contract_version: 7, stable: true }];
    renderProfiles(MOCK.profiles);
  });
  const manual = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' });
  await expect(manual.locator('.profile-service-test').first()).toHaveAttribute('title', /Устаревший результат/);
  await page.evaluate(() => toggleLang());
  await expect(manual.locator('.profile-service-test').first()).toHaveAttribute('title', /Stale result/);
  await expect(manual.locator('.profile-service-test').nth(1)).toHaveAttribute('title', /Not tested/);
});

test('subscription table lightning uses the same persisted server-search parameters', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await page.evaluate(() => {
    document.getElementById('benchSearchStopMode').value = 'find_n';
    syncServerSearchParameters('stop_mode');
    document.getElementById('benchSearchServices').value = 'telegram';
    syncServerSearchParameters('required_services');
    document.getElementById('benchSearchTarget').value = '2';
    syncServerSearchParameters('target_good');
    saveBenchConcurrency(4);
  });
  await navigateTo(page, 'import');
  const search = page.locator('#subsBody tr').filter({ hasText: 'Fixture VPN' }).locator('[data-bench-scope="subscription"]');
  await expect(search).toHaveText('⚡ Проверить сервисы');
  const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start');
  await search.click();
  expect((await posted).postDataJSON()).toEqual({ method: 'availability_full', concurrency: 4, test_download: false, test_upload: false,
    subscription_url: 'https://provider.example/sub/fixture-token', service_checks: {required_services:'telegram',fail_fast:false} });
  await page.evaluate(() => toggleLang());
  await expect(search).toHaveText('⚡ Check services');
  await page.request.post('/__fixture/reset');
});

test('336 candidates with 335 preflight rejections means one verified YT and 335 not YouTube-tested', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await openCheckDetails(page);
  const status = {
    running: false, method: 'availability_quick', total: 336, completed: 336,
    search: { target_good: 1, required_services: 'youtube', found_good: 1, preflight_completed: 336, preflight_rejected: 335, quick_completed: 1, finish_reason: 'target_reached' },
    results: [{ profile_id: 102, server_ref: 'srv-v2-fixture-manual', timestamp: serviceEpoch+200, method: 'search_availability', success: true, resource_tests: [
      { id: 'youtube_thumbnails', contract_version: 1, name: 'YouTube channel/thumbnails', attempts: 1, successes: 1, stable: true },
    ] }],
    preflight_failures: Array.from({ length: 20 }, (_, index) => ({ profile_id: index === 19 ? 104 : 1000 + index, phase: 'transport', error: 'curl rc=35, http=000, TLS EOF; upstream dial/stream deadline exceeded [deadline_exceeded]' })),
  };
  await page.request.post('/__fixture/bench-status', { data: status });
  await page.evaluate(() => pollBenchStatus());
  await expect(page.locator('#benchSearchPartialHelp')).toContainText('Подтверждено YT (канал/превью): 1 · YouTube не проверен: 335');
  await expect(page.locator('#benchSummary')).toBeHidden();
  const rejected = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Second Subscription' });
  await expect(rejected.locator('.profile-preflight')).toHaveCount(0);
  await expect(rejected.locator('.profile-service-test.skipped')).toHaveText(['YT', 'TG', 'AI']);
  await expect(rejected.locator('.profile-service-test.bad')).toHaveCount(0);
  await page.locator('#benchPreflightDiagnostics > summary').click();
  await expect(page.locator('#benchPreflightFailures li')).toHaveCount(20);
  await expect(page.locator('#benchPreflightFailures li').last()).toContainText('#104 · Транспорт: curl rc=35, http=000, TLS EOF; upstream dial/stream deadline exceeded [deadline_exceeded]');
  await page.evaluate(() => toggleLang());
  await expect(page.locator('#benchSearchPartialHelp')).toContainText('Verified YT (channel/thumbnails): 1 · YouTube not tested: 335');
  await expect(page.locator('#benchPreflightDiagnostics')).toContainText('Diagnostic IDs belong to the original run, not current rows after renumbering.');
  await page.request.post('/__fixture/reset');
});

for (const refresh of ['older stats', 'newer stats', 'reused ID', 'renumbered identity']) {
  test(`terminal availability evidence is identity-safe after ${refresh}`, async ({ page }) => {
    await page.request.post('/__fixture/reset');
    await openFixture(page);
    await navigateTo(page, 'profiles');
    const profiles = await page.request.get('/api/profiles').then(response => response.json());
    const metricsBefore = await page.evaluate(() => {
      const profile = MOCK.profiles.find(profile => profile.id === 102);
      return [profile.last_latency_ms ?? null,profile.success_count ?? 0,profile.failure_count ?? 0];
    });
    const resource = { id: 'youtube_thumbnails', contract_version: 1, name: 'YouTube channel/thumbnails', attempts: 1, successes: 1, stable: true };
    const result = { profile_id: 102, server_ref: 'srv-v2-fixture-manual', timestamp: serviceEpoch+200, method: 'search_availability', success: true, resource_tests: [resource] };
    const running = { running: true, method: 'availability_quick', total: 1, completed: 0, results: [] };
    await page.request.post('/__fixture/bench-status', { data: running });
    await page.evaluate(() => pollBenchStatus());
    const manual = profiles.profiles.find(profile => profile.id === 102);
    const originalRef = manual.server_ref;
    if (refresh === 'reused ID') manual.server_ref = 'srv-v2-fixture-replacement';
    if (refresh === 'renumbered identity') manual.id = 302;
    const stats = { stats: [{ profile_id: 102, server_ref: originalRef, last_checked: serviceEpoch+(refresh === 'newer stats' ? 300 : 100), last_service_test_unix: serviceEpoch+(refresh === 'newer stats' ? 300 : 100),
      resource_tests: refresh === 'newer stats' ? [{ ...resource, successes: 0, stable: false }] : refresh === 'reused ID' ? [resource] : [], last_service_test_success: null }] };
    await page.route('**/api/stats', route => route.fulfill({ json: stats }));
    await page.route('**/api/profiles', route => route.fulfill({ json: profiles }));
    const loaded = page.waitForResponse(response => new URL(response.url()).pathname === '/api/profiles');
    const terminal = { ...running, running: false, completed: 1, results: [result] };
    await page.request.post('/__fixture/bench-status', { data: terminal });
    await page.evaluate(() => pollBenchStatus());
    await loaded;
    await page.evaluate(() => loadProfiles());
    await page.evaluate(() => pollBenchStatus());
    const row = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' });
    if (refresh === 'older stats') {
      await expect(row.locator('.profile-service-test.ok')).toHaveText('YT');
      await expect(row.locator('.profile-service-test.skipped')).toHaveText(['TG', 'AI']);
      expect(await page.evaluate(() => {
        const profile = MOCK.profiles.find(profile => profile.id === 102);
        return [profile.last_latency_ms ?? null,profile.success_count ?? 0,profile.failure_count ?? 0];
      })).toEqual(metricsBefore);
      expect(await page.evaluate(() => JSON.stringify([...benchAvailabilityEvidence]))).not.toContain('CANARY');
    } else if (refresh === 'newer stats') {
      await expect(row.locator('.profile-service-test.bad')).toHaveText('YT');
      await expect(row.locator('.profile-service-test.ok')).toHaveCount(0);
    } else {
      await expect(row.locator('.profile-service-test.skipped')).toHaveText(['YT', 'TG', 'AI']);
      await expect(row.locator('.profile-service-test.ok, .profile-service-test.bad')).toHaveCount(0);
      // Changing diagnostic text must not rebind the same retained result to a reused ID.
      await page.request.post('/__fixture/bench-status', { data: { ...terminal, results: [{ ...result, resource_tests: [{ ...resource, error: 'Updated diagnostic' }] }] } });
      await page.evaluate(() => pollBenchStatus());
      await expect(row.locator('.profile-service-test.ok, .profile-service-test.bad')).toHaveCount(0);
    }
    if (['older stats','newer stats'].includes(refresh)) {
      if (refresh === 'older stats') {
        stats.stats[0].last_checked = serviceEpoch+200;
        stats.stats[0].last_service_test_unix = serviceEpoch+200;
        stats.stats[0].resource_tests = [resource];
        await page.evaluate(() => loadProfiles());
      }
      stats.stats[0].last_checked = serviceEpoch+100;
      stats.stats[0].last_service_test_unix = serviceEpoch+100;
      stats.stats[0].resource_tests = [];
      await page.evaluate(() => loadProfiles());
      await page.evaluate(() => pollBenchStatus());
      await expect(row.locator(refresh === 'older stats' ? '.profile-service-test.ok' : '.profile-service-test.bad')).toHaveText('YT');
    }
    const recorded = await page.request.get('/__fixture/requests').then(response => response.json());
    expect(recorded.requests.filter(request => request.method === 'POST' && ['/api/bench/settings', '/api/trash/move', '/api/profiles/select'].includes(request.path))).toHaveLength(0);
    await page.request.post('/__fixture/reset');
  });
}

for (const testedActive of [true,false]) {
  test(`public mapped result survives same-name active/inactive reindex when tested server is ${testedActive ? 'active' : 'inactive'}`, async ({ page }) => {
    await page.request.post('/__fixture/reset');
    await openFixture(page);
    await navigateTo(page, 'profiles');
    await openCheckDetails(page);
    const profiles = await page.request.get('/api/profiles').then(response => response.json());
    const active = profiles.profiles.find(profile => profile.id === 101);
    const inactive = profiles.profiles.find(profile => profile.id === 102);
    active.name = inactive.name = 'Same Name';
    active.server_ref = 'srv-v2-00000000000000000000000000000001';
    inactive.server_ref = 'srv-v2-00000000000000000000000000000002';
    const tested = testedActive ? active : inactive;
    const originalId = tested.id;
    const alias = { ...tested, id: 304, active: false, group: null };
    profiles.profiles.push(alias);
    const stats = { stats: [active,inactive].map(profile => ({ profile_id: profile.id, server_ref: profile.server_ref, last_checked: serviceEpoch+100, last_service_test_unix: serviceEpoch+100,
      resource_tests: [{ id: 'youtube', contract_version: 7, attempts: 1, successes: 1, stable: true }], last_service_test_success: true })) };
    await page.route('**/api/profiles', route => route.fulfill({ json: profiles }));
    await page.route('**/api/stats', route => route.fulfill({ json: stats }));
    await page.evaluate(() => loadProfiles());
    const resource = { id: 'youtube_thumbnails', contract_version: 1, attempts: 1, successes: 1, stable: true };
    const result = { profile_id: originalId, server_ref: tested.server_ref, profile_name: 'Same Name', timestamp: serviceEpoch+200,
      method: 'search_availability', success: true, resource_tests: [resource] };
    const status = { running: true, method: 'availability_quick', total: 1, completed: 1, results: [result],
      preflight_failures: [{ profile_id: testedActive ? 102 : 101, phase: 'transport', error: 'curl rc=35, http=000, TLS EOF; upstream dial/stream deadline exceeded [deadline_exceeded]' }] };
    await page.request.post('/__fixture/bench-status', { data: status });
    await page.evaluate(() => pollBenchStatus());
    active.id = 102;
    inactive.id = 101;
    const loaded = page.waitForResponse(response => new URL(response.url()).pathname === '/api/profiles');
    const terminal = { ...status, running: false, results: [{ ...result, profile_id: tested.id }] };
    await page.request.post('/__fixture/bench-status', { data: terminal });
    await page.evaluate(() => pollBenchStatus());
    await loaded;
    await page.evaluate(() => loadProfiles());
    // The public payload is unchanged, but its mapped ID now resolves to the correct lifecycle ref.
    await page.evaluate(() => pollBenchStatus());
    await page.evaluate(() => loadProfiles());
    const testedRow = page.locator('#profilesBody tr').filter({ has: page.locator(`[onclick="benchOne(${tested.id})"]`) });
    await expect(testedRow.locator('.profile-service-test.ok')).toHaveText('YT');
    await expect(testedRow.locator('.profile-service-test.skipped')).toHaveText(['TG', 'AI']);
    for (const id of [originalId,alias.id]) {
      const otherRow = page.locator('#profilesBody tr').filter({ has: page.locator(`[onclick="benchOne(${id})"]`) });
      await expect(otherRow.locator('.profile-service-test.skipped')).toHaveText(['YT', 'TG', 'AI']);
      await expect(otherRow.locator('.profile-service-test.ok, .profile-service-test.bad')).toHaveCount(0);
    }
    await expect(page.locator('#profilesBody .profile-preflight')).toHaveCount(0);
    await page.locator('#benchPreflightDiagnostics > summary').click();
    await expect(page.locator('#benchPreflightFailures')).toContainText(`#${testedActive ? 102 : 101} · Транспорт: curl rc=35, http=000, TLS EOF; upstream dial/stream deadline exceeded [deadline_exceeded]`);
    expect(await page.evaluate(() => MOCK.profiles.find(profile => profile.active).server_ref)).toBe(active.server_ref);
    expect(await page.evaluate(id => MOCK.profiles.find(profile => profile.id === id).last_service_test_success, tested.id)).toBeNull();
    expect(await page.evaluate(() => JSON.stringify(benchLastStatus.results))).not.toMatch(/profile_raw|"raw"|"result"/);
    await page.request.post('/__fixture/reset');
  });
}

test('missing, unknown or mismatched public refs and native methods never attribute by ID or name', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const checks = await page.evaluate(() => {
    const refs = ['srv-v2-00000000000000000000000000000001','srv-v2-00000000000000000000000000000002'];
    MOCK.profiles = [{id:102,server_ref:refs[0],name:'Same Name',active:true,resource_tests:[]},
      {id:104,server_ref:refs[1],name:'Same Name',active:false,resource_tests:[]},
      {id:304,server_ref:refs[0],name:'Same Name',active:false,resource_tests:[]}];
    benchAvailabilityEvidence.clear();
    const result = { profile_id:102,server_ref:refs[0],profile_name:'Same Name',timestamp:Math.floor(Date.now()/1000),method:'search_availability',success:true,
      resource_tests:[{id:'youtube_thumbnails',contract_version:1,stable:true,attempts:1,successes:1}] };
    const before = JSON.stringify(MOCK.profiles);
    const {server_ref:ignored,...missingRef} = result;
    const invalid = [missingRef, {...result,server_ref:null}, {...result,server_ref:'srv-v1-00000000000000000000000000000001'},
      {...result,server_ref:'server:srv-v1-00000000000000000000000000000001'}, {...result,server_ref:'srv-v2-00000000000000000000000000000003'},
      {...result,profile_id:104}, {...result,profile_id:999},
      ...['quick','full','search'].map(method => ({...result,method}))];
    return invalid.map(result => {
      mergeBenchResultsIntoProfiles([result]);
      return JSON.stringify(MOCK.profiles) === before && benchAvailabilityEvidence.size === 0;
    });
  });
  expect(checks).toEqual(Array(10).fill(true));
});

test('result-ref fingerprint changes are observed and older same-server results cannot erase newer evidence', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const state = await page.evaluate(serviceEpoch => {
    const resource = { id:'youtube_thumbnails',contract_version:1,attempts:1,successes:1,stable:true };
    const result = { profile_id:102,server_ref:'srv-v2-unknown',timestamp:serviceEpoch+200,method:'search_availability',success:true,resource_tests:[resource] };
    mergeBenchResultsIntoProfiles([result]);
    result.server_ref = MOCK.profiles.find(profile => profile.id === 102).server_ref;
    mergeBenchResultsIntoProfiles([result]);
    mergeBenchResultsIntoProfiles([{...result,timestamp:serviceEpoch+150,success:false,resource_tests:[{...resource,stable:false,successes:0}]}]);
    return { stable:MOCK.profiles.find(profile => profile.id === 102).resource_tests[0].stable, timestamp:benchAvailabilityEvidence.get(102).timestamp };
  },serviceEpoch);
  expect(state).toEqual({ stable:true,timestamp:serviceEpoch+200 });
});

test('fresh persisted native video evidence cannot revive a thumbnail pass through an older refresh', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  const state = await page.evaluate(serviceEpoch => {
    const profile = MOCK.profiles.find(profile => profile.id === 102);
    const result = {profile_id:profile.id,server_ref:profile.server_ref,timestamp:serviceEpoch+200,method:'search_availability',success:true,
      resource_tests:[{id:'youtube_thumbnails',contract_version:1,attempts:1,successes:1,stable:true}]};
    mergeBenchResultsIntoProfiles([result]);
    const native = normalizeProfiles({stats:[{profile_id:profile.id,server_ref:profile.server_ref,last_checked:serviceEpoch+300,last_service_test_unix:serviceEpoch+300,last_service_test_success:true,
      resource_tests:[{id:'youtube',contract_version:7,attempts:1,successes:1,stable:true}]}]}, {profiles:[{id:profile.id,server_ref:profile.server_ref}]});
    overlayAvailabilityEvidence(native);
    const older = normalizeProfiles({stats:[{profile_id:profile.id,server_ref:profile.server_ref,last_checked:serviceEpoch+100,last_service_test_unix:serviceEpoch+100,resource_tests:[]}]}, {profiles:[{id:profile.id,server_ref:profile.server_ref}]});
    overlayAvailabilityEvidence(older);
    MOCK.profiles = older;
    mergeBenchResultsIntoProfiles([result]);
    return {tests:older[0].resource_tests,overall:older[0].last_service_test_success,timestamp:benchAvailabilityEvidence.get(profile.id).timestamp};
  },serviceEpoch);
  expect(state).toEqual({tests:[],overall:null,timestamp:serviceEpoch+300});
});

test('newer generic health timestamps cannot suppress completed thumbnail evidence or replace it on refresh', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const resource = {id:'youtube_thumbnails',contract_version:1,attempts:1,successes:1,stable:true};
  const stats = {stats:[{profile_id:102,server_ref:'srv-v2-fixture-manual',last_checked:serviceEpoch+300,last_service_test_unix:serviceEpoch+100,
    last_latency_ms:99,success_count:17,failure_count:13,last_service_test_success:false,resource_tests:[{...resource,stable:false,successes:0}]}]};
  await page.route('**/api/stats', route => route.fulfill({json:stats}));
  const row = page.locator('#profilesBody tr').filter({hasText:'Fixture Manual'});
  for (const method of ['availability_quick','availability_full','search_availability']) {
    stats.stats[0].last_checked = serviceEpoch+300;
    await page.evaluate(() => { benchAvailabilityEvidence.clear(); });
    await page.evaluate(() => loadProfiles());
    await expect(row.locator('.profile-service-test.bad')).toHaveText('YT');
    expect(await page.evaluate(() => MOCK.profiles.find(profile => profile.id === 102).last_service_test_unix)).toBe(serviceEpoch+100);
    const running = {running:true,method:method === 'availability_full' ? 'availability_full' : 'availability_quick',total:1,completed:0,results:[]};
    await page.request.post('/__fixture/bench-status', {data:running});
    await page.evaluate(() => pollBenchStatus());
    const loaded = page.waitForResponse(response => new URL(response.url()).pathname === '/api/profiles');
    const result = {profile_id:102,server_ref:'srv-v2-fixture-manual',timestamp:serviceEpoch+200,method,success:true,latency_ms:1,resource_tests:[resource]};
    await page.request.post('/__fixture/bench-status', {data:{...running,running:false,completed:1,results:[result]}});
    await page.evaluate(() => pollBenchStatus());
    await loaded;
    await page.evaluate(() => loadProfiles());
    stats.stats[0].last_checked = serviceEpoch+400;
    await page.evaluate(() => loadProfiles());
    await page.evaluate(() => pollBenchStatus());
    await expect(row.locator('.profile-service-test.ok')).toHaveText('YT');
    expect(await page.evaluate(() => {
      const profile = MOCK.profiles.find(profile => profile.id === 102);
      return {service:profile.last_service_test_unix,health:profile.last_checked,overlay:benchAvailabilityEvidence.get(102).timestamp,
        latency:profile.last_latency_ms,successes:profile.success_count,failures:profile.failure_count};
    })).toEqual({service:serviceEpoch+200,health:serviceEpoch+400,overlay:serviceEpoch+200,latency:99,successes:17,failures:13});
  }
  await page.request.post('/__fixture/reset');
});

test('unknown legacy service timestamps remain zero and non-thumbnail results never advance the service overlay clock', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  const states = await page.evaluate(() => {
    const profile = MOCK.profiles.find(profile => profile.id === 102);
    const metadata = {profiles:[{id:profile.id,server_ref:profile.server_ref}]};
    const stats = {profile_id:profile.id,server_ref:profile.server_ref,last_checked:300,resource_tests:[]};
    return [undefined,0].map(timestamp => {
      benchAvailabilityEvidence.clear();
      const source = timestamp === undefined ? stats : {...stats,last_service_test_unix:timestamp};
      MOCK.profiles = normalizeProfiles({stats:[source]},metadata);
      overlayAvailabilityEvidence(MOCK.profiles);
      const clocks = [MOCK.profiles[0].last_service_test_unix,normalizeProfiles({stats:[source]},null)[0].last_service_test_unix];
      for (const result of [
        {method:'tcp',resource_tests:[]},
        {method:'availability_quick',resource_tests:[{id:'telegram',contract_version:7,attempts:1,stable:true}]},
        {method:'availability_full',resource_tests:[{id:'youtube',contract_version:7,attempts:1,stable:true}]},
      ]) {
        mergeBenchResultsIntoProfiles([{...result,profile_id:profile.id,server_ref:profile.server_ref,timestamp:500,success:true}]);
        clocks.push(MOCK.profiles[0].last_service_test_unix);
      }
      return {clocks,overlays:benchAvailabilityEvidence.size};
    });
  });
  expect(states).toEqual([{clocks:[0,0,0,0,0],overlays:0},{clocks:[0,0,0,0,0],overlays:0}]);
});

test('expired, unknown and far-future service epochs stay neutral in profiles and favorites despite fresh generic health', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page,'profiles');
  const now = Math.floor(Date.now()/1000);
  const stats = {stats:[{profile_id:102,server_ref:'srv-v2-fixture-manual',favorite:true,last_checked:now+86400,last_service_test_unix:now-7*86400,
    last_service_test_success:true,resource_tests:[
      {id:'youtube_thumbnails',contract_version:1,attempts:1,successes:1,stable:true},
      {id:'telegram',contract_version:7,attempts:1,successes:1,stable:true,inconclusive:true},
      {id:'ai',contract_version:7,attempts:1,successes:0,stable:false},
    ]}]};
  await page.route('**/api/stats',route => route.fulfill({json:stats}));
  for (const timestamp of [now-7*86400,now-21610,0,undefined,now+3600]) {
    if (timestamp === undefined) delete stats.stats[0].last_service_test_unix;
    else stats.stats[0].last_service_test_unix = timestamp;
    await page.evaluate(() => loadProfiles());
    for (const body of ['profilesBody','favoritesBody']) {
      const row = page.locator(`#${body} tr`).filter({hasText:'Fixture Manual'});
      await expect(row.locator('.profile-service-test.stale')).toHaveText(['YT','TG','AI']);
      await expect(row.locator('.profile-service-test.ok, .profile-service-test.bad, .profile-service-test.unknown')).toHaveCount(0);
      await expect(row.locator('.profile-service-test').first()).toHaveAttribute('data-state','stale');
      await expect(row.locator('.profile-service-test').first()).toHaveAttribute('title',/Устаревший результат; требуется новая проверка/);
    }
    expect(await page.evaluate(() => profileSuccessfulChecks(MOCK.profiles.find(profile => profile.id === 102)))).toBe(0);
  }
  await page.evaluate(() => toggleLang());
  await expect(page.locator('#profilesBody tr').filter({hasText:'Fixture Manual'}).locator('.profile-service-test').first()).toHaveAttribute('title',/Stale result; a new check is required/);
  await page.request.post('/__fixture/reset');
});

test('fresh inactive service evidence retains current, inconclusive, skipped and not-tested states and outranks stale evidence', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page,'profiles');
  const now = Math.floor(Date.now()/1000);
  const preview = {id:'youtube_thumbnails',contract_version:1,attempts:1,successes:1,stable:true};
  const manual = {profile_id:102,server_ref:'srv-v2-fixture-manual',favorite:true,last_service_test_unix:now+1,last_service_test_success:true,resource_tests:[
    preview,{id:'telegram',contract_version:7,attempts:1,successes:0,stable:false,inconclusive:true},
    {id:'ai',contract_version:7,attempts:1,successes:0,stable:false},
  ]};
  const stats = {stats:[manual,{profile_id:104,server_ref:'srv-v2-fixture-second-subscription',last_service_test_unix:now-7*86400,last_checked:now+86400,
    last_service_test_success:true,resource_tests:[preview,{id:'telegram',contract_version:7,attempts:1,successes:1,stable:true},{id:'ai',contract_version:7,attempts:1,successes:1,stable:true}]}]};
  await page.route('**/api/stats',route => route.fulfill({json:stats}));
  await page.evaluate(() => loadProfiles());
  for (const body of ['profilesBody','favoritesBody']) {
    const row = page.locator(`#${body} tr`).filter({hasText:'Fixture Manual'});
    await expect(row.locator('.profile-service-test.ok')).toHaveText('YT');
    await expect(row.locator('.profile-service-test.unknown')).toHaveText('TG ?');
    await expect(row.locator('.profile-service-test.bad')).toHaveText('AI');
    await expect(row.locator('.profile-service-test.stale')).toHaveCount(0);
    await expect(row.locator('.profile-service-test').first()).toHaveAttribute('data-state','current');
  }
  expect(await page.evaluate(() => {
    const fresh = MOCK.profiles.find(profile => profile.id === 102), stale = MOCK.profiles.find(profile => profile.id === 104);
    profileSortState = {key:'results',dir:'desc'};
    return {active:fresh.active,checks:profileSuccessfulChecks(fresh),staleChecks:profileSuccessfulChecks(stale),first:applyProfileSort([stale,fresh])[0].id};
  })).toEqual({active:false,checks:1,staleChecks:0,first:102});
  manual.resource_tests[2] = {...manual.resource_tests[2],attempts:0,stable:true};
  await page.evaluate(() => loadProfiles());
  const row = page.locator('#profilesBody tr').filter({hasText:'Fixture Manual'});
  await expect(row.locator('.profile-service-test.skipped')).toHaveText('AI');
  await expect(row.locator('.profile-service-test.skipped')).toHaveAttribute('data-state','skipped');
  expect(await page.evaluate(() => profileSuccessfulChecks(MOCK.profiles.find(profile => profile.id === 102)))).toBe(1);
  manual.resource_tests.pop();
  await page.evaluate(() => loadProfiles());
  await expect(row.locator('.profile-service-test.skipped')).toHaveAttribute('data-state','not-tested');
  manual.resource_tests[0] = {...preview,id:'youtube',contract_version:7};
  await page.evaluate(() => loadProfiles());
  await expect(row.locator('.profile-service-test.stale')).toHaveText('YT');
  await expect(row.locator('.profile-service-test.ok')).toHaveCount(0);
  await page.request.post('/__fixture/reset');
});

test('subscription check selects results order by passed services, fresh ping, and unreachable last', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  const fixtureProfiles = await page.request.get('/api/profiles').then(response => response.json());
  const subscription = fixtureProfiles.profiles.find(profile => profile.id === 101);
  const cases = [
    {id:201,passed:0,ping:null},
    {id:202,passed:2,ping:80},
    {id:203,passed:0,ping:45},
    {id:204,passed:1,ping:10},
    {id:205,passed:3,ping:120},
    {id:206,passed:2,ping:20},
    {id:207,passed:0,ping:1,stale:true},
  ];
  const now = Math.floor(Date.now()/1000);
  const profiles = cases.map(item => ({
    id:item.id,server_ref:`srv-v2-fixture-rank-${item.id}`,name:`Rank ${item.id}`,
    group:subscription.group,protocol:'VLESS',transport:'tcp',address:'example.test',port:443,active:false,dead:false,
  }));
  const results = cases.map(item => ({
    profile_id:item.id,server_ref:`srv-v2-fixture-rank-${item.id}`,timestamp:item.stale ? now-7*3600 : now,
    method:'availability_full',success:item.passed === 3,resource_tests:[
      {id:'ping_proxy',contract_version:7,attempts:1,successes:item.ping === null ? 0 : 1,
        reachable:item.ping !== null,avg_ttfb_ms:item.ping || 0},
      ...['youtube_thumbnails','telegram','ai'].map((id,index) => ({id,contract_version:index === 0 ? 1 : 7,
        attempts:1,successes:index < item.passed ? 1 : 0,stable:index < item.passed})),
    ],
  }));
  await page.route('**/api/profiles',route => route.fulfill({json:{profiles:[...fixtureProfiles.profiles,...profiles]}}));
  await page.route('**/api/stats',route => route.fulfill({json:{stats:results.map(result => ({
    profile_id:result.profile_id,server_ref:result.server_ref,last_service_test_unix:result.timestamp,
    last_latency_ms:result.profile_id === 201 ? 1 : 300,last_service_test_success:result.success,
    resource_tests:result.resource_tests,
  }))}}));
  await page.addInitScript(() => { if (!localStorage.getItem('hr_profile_sort')) localStorage.setItem('hr_profile_sort','import'); });
  await openFixture(page);
  await navigateTo(page,'profiles');
  const group = page.locator('#profilesBody tr[data-profile-group]').filter({hasText:'Fixture VPN'});
  const groupKey = await group.getAttribute('data-profile-group');
  const visibleIds = () => page.locator('#profilesBody').evaluate((body,key) => [...body.querySelectorAll('tr[data-profile-row]')]
    .filter(row => row.dataset.profileRow === key).map(row => Number(row.querySelector('td[data-profile-metric="id"]')?.textContent))
    .filter(id => id >= 201 && id <= 207),groupKey);
  expect(await visibleIds()).toEqual([201,202,203,204,205,206,207]);
  await group.locator('[data-bench-scope="subscription"]').click();
  await expect(page.locator('#profileSort')).toHaveValue('results');
  await expect(page.locator('#profileSort').locator('xpath=..').locator('.custom-select-trigger')).toContainText('По результатам');
  const posted = await page.request.get('/__fixture/requests').then(response => response.json());
  const request = posted.requests.filter(item => item.path === '/api/bench/start').at(-1).body;
  expect(request.subscription_url).toBe(subscription.group);
  expect(request.service_checks).toEqual({required_services:'all',fail_fast:false});
  await page.request.post('/__fixture/bench-status',{data:{running:false,method:'availability_full',total:7,completed:7,results:results.filter(result => result.profile_id !== 207)}});
  await page.evaluate(() => pollBenchStatus());
  await expect.poll(visibleIds).toEqual([205,206,202,204,203,207,201]);
  const latency = await page.locator('#profilesBody').evaluate((body,key) => [...body.querySelectorAll('tr[data-profile-row]')]
    .filter(row => row.dataset.profileRow === key).map(row => [Number(row.querySelector('td[data-profile-metric="id"]')?.textContent),row.querySelector('td[data-profile-metric="latency"]')?.textContent.trim()])
    .filter(([id]) => id >= 201 && id <= 207),groupKey);
  expect(latency).toEqual([[205,'120ms'],[206,'20ms'],[202,'80ms'],[204,'10ms'],[203,'45ms'],[207,'—'],[201,'—']]);
  await page.reload();
  await expect(page.locator('#profilesBody tr[data-profile-row]')).not.toHaveCount(0);
  await expect(page.locator('#profileSort')).toHaveValue('results');
  await expect.poll(visibleIds).toEqual([205,206,202,204,203,207,201]);
  await page.evaluate(() => sortProfiles('import'));
  await page.reload();
  await expect(page.locator('#profileSort')).toHaveValue('import');
  await expect.poll(visibleIds).toEqual([201,202,203,204,205,206,207]);
  await page.request.post('/__fixture/reset');
});

test('fresh page defaults to results order for previously completed service checks', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page,'profiles');
  await expect(page.locator('#profileSort')).toHaveValue('results');
  await expect(page.locator('#profileSort').locator('xpath=..').locator('.custom-select-trigger')).toContainText('По результатам');
  await page.request.post('/__fixture/reset');
});

test('pending benchmark response cannot bind evidence after ID reuse and unchanged polls keep row nodes', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const profiles = await page.request.get('/api/profiles').then(response => response.json());
  const status = { running: false, method: 'availability_quick', total: 1, completed: 1, results: [{
    profile_id: 102, server_ref: 'srv-v2-fixture-manual', timestamp: serviceEpoch+200, method: 'search_availability', success: true,
    resource_tests: [{ id: 'youtube_thumbnails', contract_version: 1, stable: true, attempts: 1, successes: 1 }],
  }] };
  let release, dispatched;
  const gate = new Promise(resolve => { release = resolve; });
  const requested = new Promise(resolve => { dispatched = resolve; });
  await page.route('**/api/bench/status', async route => {
    dispatched();
    await gate;
    await route.fulfill({ json: status });
  });
  await page.evaluate(() => { benchWasRunning = false; });
  const pending = page.evaluate(() => pollBenchStatus());
  await requested;
  profiles.profiles.find(profile => profile.id === 102).server_ref = 'srv-v2-fixture-pending-replacement';
  await page.route('**/api/profiles', route => route.fulfill({ json: profiles }));
  await page.evaluate(() => loadProfiles());
  release();
  await pending;
  const row = page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' });
  await expect(row.locator('.profile-service-test.skipped')).toHaveText(['YT', 'TG', 'AI']);
  await expect(row.locator('.profile-service-test.ok, .profile-service-test.bad')).toHaveCount(0);
  const name = await row.locator('.profile-name').elementHandle();
  await page.evaluate(() => pollBenchStatus());
  expect(await name.evaluate(node => node.isConnected)).toBe(true);
  await page.request.post('/__fixture/reset');
});

test('service-check labels are uniform and scope titles are short in RU and EN', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await page.locator('#testPanel > summary').click();
  await expect(page.locator('#benchSemanticsHelp')).toContainText('Сервисы, стоп после сбоя и параллелизм общие');
  await expect(page.locator('#benchNativePostActionsLabel')).toHaveText('Нативные пост-действия (совместимость)');
  await expect(page.locator('#benchPostActionsHelp')).toContainText('относятся к прежним нативным тестам; проверка превью их не запускает');
  await expect(page.locator('#benchPostActionsHelp')).toContainText('как всей области, так и N серверов');
  await expect(page.locator('#benchPostActionsHelp')).toContainText('не запускает поднятие серверов, перенос в Dead Servers или AutoSelect');
  await expect(page.locator('#benchSearchHelp')).toContainText('только для расширенного поиска');
  await expect(page.locator('#benchYouTubeHelp')).toContainText('не воспроизведение видео');
  await expect(page.locator('label[for="benchSearchFailFast"]')).toHaveText('Стоп после сбоя YT/TG');
  await expect(page.locator('#benchPromoteSuccessful').locator('xpath=ancestor::div[contains(@class,"field")]')).toContainText('Поднимать серверы');
  await expect(page.locator('[data-bench-scope="single"]').first()).toHaveAttribute('title', 'Для этого сервера');
  await expect(page.locator('#benchSearchAll')).toHaveText('Проверить сервисы');
  await expect(page.locator('[data-bench-scope="group"]').first()).toHaveText('⚡ Проверить сервисы');
  await expect(page.locator('[data-bench-scope="subscription"]').first()).toHaveAttribute('title','Для всех серверов подписки');

  await page.evaluate(() => toggleLang());
  await expect(page.locator('#benchSemanticsHelp')).toContainText('Services, stop after failure, and concurrency are shared');
  await expect(page.locator('label[for="benchSearchFailFast"]')).toHaveText('Stop after YT/TG failure');
  await expect(page.locator('#benchSearchHelp')).toContainText('only to advanced search');
  await expect(page.locator('#benchYouTubeHelp')).toContainText('not video playback');
  await expect(page.locator('#benchNativePostActionsLabel')).toHaveText('Native post-actions (compatibility)');
  await expect(page.locator('#benchPostActionsHelp')).toContainText('settings apply to legacy native tests; thumbnail checks do not trigger them');
  await expect(page.locator('#benchPostActionsHelp')).toContainText('both complete scope and N servers, never triggers server promotion, movement to Dead Servers, or AutoSelect');
  await expect(page.locator('#benchPromoteSuccessful').locator('xpath=ancestor::div[contains(@class,"field")]')).toContainText('Promote servers');
  await expect(page.locator('#benchConcurrency')).toHaveAttribute('title', 'From 1 to 6; a row test always checks one server');
  await expect(page.locator('#benchSearchAll')).toHaveText('Check services');
  await expect(page.locator('[data-bench-scope="single"]').first()).toHaveAttribute('title', 'For this server');
});

test('normal service UI keeps diagnostics collapsed in Profiles and the sidebar contains progress only', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page,'profiles');
  await expect(page.locator('#benchDetails > summary')).toHaveText('Подробности проверки');
  expect(await page.locator('#benchDetails').evaluate(element => element.open)).toBe(false);
  await page.locator('#testPanel > summary').click();
  await expect(page.locator('#benchConcurrency')).toBeVisible();
  await expect(page.locator('#benchSearchStopMode')).toBeHidden();
  await expect(page.locator('#benchSearchServices')).toBeVisible();
  await expect(page.locator('#benchSearchFailFast')).toBeEnabled();
  await expect(page.locator('#benchPromoteSuccessful')).toBeHidden();
  await expect(page.locator('#benchConcurrencyHelp')).toBeHidden();
  const status = {running:true,method:'availability_full',total:2,completed:0,current_profile_name:'Fixture Manual',results:[],
    concurrency_status:{requested:4,effective:2,active:1,admission_limit:2,limit_reasons:['candidate_count']}};
  await page.request.post('/__fixture/bench-status',{data:status});
  await page.evaluate(() => pollBenchStatus());
  await expect(page.locator('#benchProgress #benchCurrent')).toHaveText('Fixture Manual');
  await expect(page.locator('#benchProgress #benchStop')).toBeVisible();
  await expect(page.locator('#benchProgress p')).toHaveCount(0);
  for (const id of ['benchSearchStatus','benchConcurrencyStatus','benchSearchPartialHelp','benchInconclusiveStatus','benchSummary','benchPreflightDiagnostics']) {
    await expect(page.locator(`#benchDetails #${id}`)).toHaveCount(1);
    await expect(page.locator(`#${id}`)).toBeHidden();
  }
  const help = page.locator('#benchDetails #benchConcurrencyHelp');
  await expect(page.locator('#benchProgress #benchConcurrencyHelp')).toHaveCount(0);
  await page.locator('#benchDetails > summary').click();
  await expect(help).toBeVisible();
  await expect(help).toContainText('отдельное экономное ядро на кандидата');
  await expect(help).toContainText('128 МиБ доступной памяти, включая резерв 80 МиБ');
  await expect(help).toContainText('Telegram и нативное видео остаются последовательными');
  await expect(help).toContainText('ядра завершаются и память освобождается');
  await expect(help).toContainText('HTTP 503');
  await page.evaluate(() => toggleLang());
  await expect(help).toContainText('private economical core per candidate');
  await expect(help).toContainText('Three workers need an estimated 128 MiB available');
  await expect(help).toContainText('Telegram and native video remain serialized');
  await expect(help).toContainText('reaps cores and releases memory');
  await expect(help).toContainText('HTTP 503');
  await page.locator('#benchDetails > summary').click();
  await expect(help).toBeHidden();
  await page.request.post('/__fixture/reset');
});

test('saved YouTube policy survives refresh without Find N and leaves unrequested row services gray', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.addInitScript(() => {
    localStorage.setItem('hr_search_stop_mode','"find_n"');
    localStorage.setItem('hr_search_target_good','5');
    localStorage.setItem('hr_search_required_services','"youtube"');
    localStorage.setItem('hr_search_fail_fast','true');
    localStorage.setItem('hr_bench_concurrency','4');
  });
  await openFixture(page);
  await navigateTo(page,'profiles');
  const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start');
  await page.evaluate(() => benchGroup([102,104]));
  expect((await posted).postDataJSON()).toEqual({method:'availability_full',concurrency:4,test_download:false,test_upload:false,profile_ids:[102,104],service_checks:{required_services:'youtube',fail_fast:true}});
  const replay = await page.request.post('/__fixture/bench-full').then(response => response.json());
  expect(replay.results.every(result => result.server_ref && result.resource_tests.length === 3 && result.resource_tests[0].attempts === 1 && result.resource_tests.slice(1).every(test => test.attempts === 0))).toBe(true);
  await page.evaluate(() => pollBenchStatus());
  await page.evaluate(() => loadProfiles());
  await page.evaluate(() => pollBenchStatus());
  const pass = page.locator('#profilesBody tr').filter({hasText:'Fixture Manual'});
  const fail = page.locator('#profilesBody tr').filter({hasText:'Fixture Second Subscription'});
  await expect(pass.locator('.profile-service-test.ok')).toHaveText('YT');
  await expect(fail.locator('.profile-service-test.bad')).toHaveText('YT');
  await expect(fail.locator('.profile-service-test.ok')).toHaveCount(0);
  await expect(pass.locator('.profile-service-test.skipped')).toHaveText(['TG','AI']);
  await expect(fail.locator('.profile-service-test.skipped')).toHaveText(['TG','AI']);
  await expect(pass.locator('.profile-service-test.stale')).toHaveCount(0);
  await expect(fail.locator('.profile-service-test.stale')).toHaveCount(0);
  await expect(page.locator('#benchResultStatus')).toHaveText('Проверено: 2/2');
  expect(await page.locator('#benchDetails').evaluate(element => element.open)).toBe(false);
  expect(await page.evaluate(() => MOCK.profiles.filter(profile => [102,104].includes(profile.id)).every(profile => !profile.active))).toBe(true);
  const recorded = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(recorded.requests.filter(request => request.method === 'POST' && ['/api/bench/settings','/api/trash/move','/api/profiles/select'].includes(request.path))).toHaveLength(0);
  await page.request.post('/__fixture/reset');
});

for (const failFast of [false,true]) {
  test(`all-service policy ${failFast ? 'stops after YouTube failure' : 'defaults to full checks and continues after failure'}`, async ({ page }) => {
    await page.request.post('/__fixture/reset');
    await openFixture(page);
    await navigateTo(page,'profiles');
    await page.evaluate(failFast => { document.getElementById('benchSearchFailFast').checked = failFast; },failFast);
    const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start');
    await page.locator('#benchSearchAll').click();
    expect((await posted).postDataJSON()).toEqual({method:'availability_full',concurrency:1,test_download:false,test_upload:false,service_checks:{required_services:'all',fail_fast:failFast}});
    const replay = await page.request.post('/__fixture/bench-full').then(response => response.json());
    expect(replay.results[0].resource_tests.map(test => test.attempts)).toEqual([1,1,1]);
    expect(replay.results[1].resource_tests.map(test => test.attempts)).toEqual(failFast ? [1,0,0] : [1,1,1]);
    await page.evaluate(() => pollBenchStatus());
    const pass = page.locator('#profilesBody tr').filter({hasText:'Fixture Manual'});
    const fail = page.locator('#profilesBody tr').filter({hasText:'Fixture Second Subscription'});
    await expect(pass.locator('.profile-service-test.ok')).toHaveText(['YT','TG','AI']);
    await expect(fail.locator('.profile-service-test.bad')).toHaveText(failFast ? ['YT'] : ['YT','AI']);
    await expect(fail.locator('.profile-service-test.ok')).toHaveText(failFast ? [] : ['TG']);
    await expect(fail.locator('.profile-service-test.skipped')).toHaveText(failFast ? ['TG','AI'] : []);
    await page.request.post('/__fixture/reset');
  });
}

test('fixture validates exact service and discovery policies and preserves missing-policy defaults', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  const base = {method:'availability_full',concurrency:4,test_download:false,test_upload:false};
  expect((await page.request.post('/api/bench/start',{data:base})).status()).toBe(200);
  let status = await page.request.get('/api/bench/status').then(response => response.json());
  expect(status.service_checks).toEqual({required_services:'all',fail_fast:false});
  expect(status.concurrency_status).toMatchObject({requested:4,effective:3,limit_reasons:['memory_cap','candidate_count']});
  for (const method of ['availability_full','availability_quick']) {
    for (const optional of [{service_checks:null},{search:null,service_checks:null}]) {
      expect((await page.request.post('/api/bench/start',{data:{...base,method,...optional}})).status()).toBe(200);
      status = await page.request.get('/api/bench/status').then(response => response.json());
      expect(status.service_checks).toEqual({required_services:'all',fail_fast:method === 'availability_quick'});
      expect(status.search).toBeNull();
    }
  }
  const legacySearch = {...base,method:'availability_quick',search:{target_good:5,required_services:'youtube'}};
  expect((await page.request.post('/api/bench/start',{data:legacySearch})).status()).toBe(200);
  status = await page.request.get('/api/bench/status').then(response => response.json());
  expect(status.search.fail_fast).toBe(true);
  for (const required_services of ['all','youtube','telegram','ai']) {
    for (const fail_fast of [false,true]) {
      const service_checks = {required_services,fail_fast};
      for (const method of ['availability_full','availability_quick']) {
        expect((await page.request.post('/api/bench/start',{data:{...base,method,profile_ids:[202],search:null,service_checks}})).status()).toBe(200);
        status = await page.request.get('/api/bench/status').then(response => response.json());
        expect(status.service_checks).toEqual(service_checks);
        expect(status.method).toBe(method);
        expect(status.search).toBeNull();
      }
      expect((await page.request.post('/api/bench/start',{data:{...legacySearch,search:{target_good:5,...service_checks}}})).status()).toBe(200);
    }
  }
  for (const method of ['quick','availability_quick']) {
    for (const fail_fast of [undefined,true,false]) {
      const search = {target_good:5,required_services:'all',...(fail_fast === undefined ? {} : {fail_fast})};
      const response = await page.request.post('/api/bench/start',{data:{...base,method,search,service_checks:null}});
      expect(response.status()).toBe(method === 'quick' && fail_fast === false ? 400 : 200);
      if (response.ok()) {
        status = await page.request.get('/api/bench/status').then(response => response.json());
        expect(status.search.fail_fast).toBe(fail_fast ?? true);
        expect(status.service_checks).toBeNull();
      }
    }
  }
  for (const service_checks of [[],{},'all',{required_services:'all'},{required_services:'invalid',fail_fast:false},{required_services:'all',fail_fast:'false'},{required_services:'all',fail_fast:false,extra:true}]) {
    expect((await page.request.post('/api/bench/start',{data:{...base,service_checks}})).status()).toBe(400);
  }
  for (const search of [[],{},'all',{target_good:0,required_services:'all'},{target_good:21,required_services:'all'},{target_good:5,required_services:'invalid'},{target_good:5,required_services:'all',fail_fast:'false'},{target_good:5,required_services:'all',extra:true}]) {
    expect((await page.request.post('/api/bench/start',{data:{...legacySearch,search}})).status()).toBe(400);
  }
  for (const body of [
    {...legacySearch,profile_ids:[102]}, {...legacySearch,profile_ids:[202]},
    {...legacySearch,subscription_url:'https://provider.example/sub/fixture-token'},
    {...legacySearch,service_checks:{required_services:'all',fail_fast:false}},
    {...base,search:legacySearch.search},
    ...['quick','full'].map(method => ({...base,method,service_checks:{required_services:'all',fail_fast:false}})),
  ]) expect((await page.request.post('/api/bench/start',{data:body})).status()).toBe(400);
  await page.request.post('/__fixture/reset');
});

test('exact worker admission preserves the accepted job, progress and Stop on insufficient or unknown memory', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  for (const max_workers of [-1,7,1.5,'4',false]) {
    expect((await page.request.post('/__fixture/bench-memory',{data:{max_workers}})).status()).toBe(400);
  }
  expect((await page.request.post('/__fixture/bench-memory',{data:{max_workers:4}})).status()).toBe(200);
  await openFixture(page);
  await navigateTo(page,'profiles');
  const profile_ids = [101,102,104,202];
  const base = {method:'availability_full',concurrency:4,test_download:false,test_upload:false,profile_ids};
  const service_checks = {required_services:'all',fail_fast:false};
  await page.evaluate(ids => { saveBenchConcurrency(4); benchGroup(ids); },profile_ids);
  await expect(page.locator('#benchProgress')).toBeVisible();
  await expect.poll(async () => (await page.request.get('/api/bench/status').then(response => response.json())).concurrency_status.effective).toBe(4);
  const accepted = await page.request.get('/api/bench/status').then(response => response.json());
  expect(accepted.service_checks).toEqual(service_checks);
  expect(accepted.concurrency_status).toEqual({requested:4,effective:4,active:1,admission_limit:4,limit_reasons:[]});
  const progress = {...accepted,completed:1,current_profile_name:'Fixture Manual'};
  await page.request.post('/__fixture/bench-status',{data:progress});
  await page.evaluate(() => pollBenchStatus());
  await expect(page.locator('#benchCounter')).toHaveText('1/4');
  for (const max_workers of [3,0,null]) {
    expect((await page.request.post('/__fixture/bench-memory',{data:{max_workers}})).status()).toBe(200);
    const rejected = page.waitForResponse(response => new URL(response.url()).pathname === '/api/bench/start' && response.status() === 503);
    await page.evaluate(ids => benchGroup(ids),profile_ids);
    expect(await (await rejected).json()).toEqual({error:`Requested 4 workers, memory permits ${max_workers ?? 0}; reduce parallelism or free memory`});
    await expect(page.locator('#msgBar')).toContainText('memory permits');
    expect(await page.request.get('/api/bench/status').then(response => response.json())).toEqual(progress);
    await expect(page.locator('#benchProgress')).toBeVisible();
    await expect(page.locator('#benchCounter')).toHaveText('1/4');
    await expect(page.locator('#benchCurrent')).toHaveText('Fixture Manual');
    await expect(page.locator('#benchStop')).toBeVisible();
    await expect(page.locator('#benchStop')).toBeEnabled();
    expect(await page.evaluate(() => window.benchIsGroup)).toBe(true);
  }
  for (const max_workers of [0,null]) {
    await page.request.post('/__fixture/bench-memory',{data:{max_workers}});
    for (const optional of [{},{service_checks:null},{service_checks}]) {
      expect((await page.request.post('/api/bench/start',{data:{...base,profile_ids:[102],...optional}})).status()).toBe(503);
      expect(await page.request.get('/api/bench/status').then(response => response.json())).toEqual(progress);
    }
  }
  await page.request.post('/__fixture/bench-memory',{data:{max_workers:1}});
  expect((await page.request.post('/api/bench/start',{data:{...base,profile_ids:[102],service_checks}})).status()).toBe(200);
  const single = await page.request.get('/api/bench/status').then(response => response.json());
  expect(single.concurrency_status).toMatchObject({requested:4,effective:1});
  expect((await page.request.post('/api/bench/start',{data:{...base,profile_ids:[102,104],service_checks}})).status()).toBe(503);
  expect(await page.request.get('/api/bench/status').then(response => response.json())).toEqual(single);
  await page.request.post('/__fixture/bench-memory',{data:{max_workers:3}});
  for (const optional of [{},{service_checks:null}]) {
    expect((await page.request.post('/api/bench/start',{data:{...base,...optional}})).status()).toBe(200);
    expect((await page.request.get('/api/bench/status').then(response => response.json())).concurrency_status).toMatchObject({requested:4,effective:3});
  }
  await page.request.post('/__fixture/reset');
  expect((await page.request.post('/api/bench/start',{data:{...base,service_checks}})).status()).toBe(503);
  await page.request.post('/__fixture/reset');
});

test('primary global Check Services uses shared policy but ignores saved Find N and invalid advanced parameters', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.addInitScript(() => {
    localStorage.setItem('hr_search_stop_mode','"find_n"');
    localStorage.setItem('hr_search_target_good','5');
    localStorage.setItem('hr_search_required_services','"ai"');
    localStorage.setItem('hr_search_fail_fast','true');
    localStorage.setItem('hr_bench_concurrency','4');
  });
  await openFixture(page);
  await navigateTo(page,'profiles');
  await expect(page.locator('#benchAdvancedSearch')).toBeHidden();
  for (const mode of ['saved','find_n','complete_scope','unsupported']) {
    if (mode !== 'saved') await page.evaluate(mode => {
      document.getElementById('benchSearchStopMode').value = mode;
      document.getElementById('benchSearchTarget').value = '0';
      document.getElementById('benchSearchFailFast').checked = true;
    },mode);
    const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start');
    await page.locator('#benchSearchAll').click();
    expect((await posted).postDataJSON()).toEqual({method:'availability_full',concurrency:4,test_download:false,test_upload:false,service_checks:{required_services:'ai',fail_fast:true}});
    await expect(page.locator('#benchSearchStatus')).toBeHidden();
    const status = await page.request.get('/api/bench/status').then(response => response.json());
    expect(status.method).toBe('availability_full');
    expect(status.search).toBeNull();
    expect(status.preflight_failures).toEqual([]);
  }
  await page.request.post('/__fixture/reset');
});

test('advanced search has one collapsed opt-in action and rejects every scoped or malformed advanced flag', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page,'profiles');
  await expect(page.locator('#benchAdvancedParameters #benchAdvancedSearch')).toHaveCount(1);
  await expect(page.locator('#benchAdvancedSearch')).toBeHidden();
  await openAdvancedParameters(page);
  await expect(page.locator('#benchAdvancedSearch')).toHaveText('Запустить расширенный поиск');
  await page.evaluate(() => {
    for (const scope of [{profile_ids:[102]},{subscription_url:'https://provider.example/sub/fixture-token'},
      {selected:true},{selected:false},{diagnostic:true},{diagnostic:false}]) startServerSearch({...scope,advanced:true});
    for (const advanced of [false,'true',1,null]) startServerSearch({advanced});
  });
  const recorded = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(recorded.requests.filter(request => request.path === '/api/bench/start')).toHaveLength(0);
  await page.evaluate(() => toggleLang());
  await expect(page.locator('#benchAdvancedSearch')).toHaveText('Start advanced search');
  await expect(page.locator('#benchAdvancedParameters > summary')).toHaveText('Advanced search (all servers)');
});

test('benchmark sidebar renders only the current profile name and progress count', async ({ page }) => {
  await openFixture(page);
  await page.request.post('/__fixture/bench-status', { data: {
    running: true,
    method: 'availability_quick',
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

  await expect(page.locator('#benchCurrent')).toHaveText('Worker Four');
  await expect(page.locator('#benchCounter')).toHaveText('2/6');
});

test('minimal Ping is default and full Ping persists independently of rejection and fail-fast', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page,'profiles');
  await page.evaluate(() => { document.getElementById('testPanel').open = true; saveBenchConcurrency(1); });
  await expect(page.locator('#benchFullPing')).not.toBeChecked();
  let posted = page.waitForRequest(r => r.method() === 'POST' && new URL(r.url()).pathname === '/api/bench/start');
  await page.locator('#benchSearchAll').click();
  expect((await posted).postDataJSON().service_checks).toEqual({required_services:'all',fail_fast:false});
  await page.locator('label.toggle').filter({has:page.locator('#benchFullPing')}).click();
  await page.reload();
  await navigateTo(page,'profiles');
  await page.evaluate(() => { document.getElementById('testPanel').open = true; });
  await expect(page.locator('#benchFullPing')).toBeChecked();
  await expect(page.locator('#benchRejectNoPing')).not.toBeChecked();
  await expect(page.locator('#benchSearchFailFast')).not.toBeChecked();
  posted = page.waitForRequest(r => r.method() === 'POST' && new URL(r.url()).pathname === '/api/bench/start');
  await page.locator('#benchSearchAll').click();
  expect((await posted).postDataJSON().service_checks).toEqual({required_services:'all',fail_fast:false,full_ping:true});
  await page.locator('label.toggle').filter({has:page.locator('#benchFullPing')}).click();
  await page.reload();
  await navigateTo(page,'profiles');
  await expect(page.locator('#benchFullPing')).not.toBeChecked();
  await page.request.post('/__fixture/reset');
});

test('Ping rejection is optional, persisted and independent of service fail-fast', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page,'profiles');
  await page.evaluate(() => { document.getElementById('testPanel').open = true; saveBenchConcurrency(1); });
  await expect(page.locator('#benchRejectNoPing')).not.toBeChecked();
  await page.locator('label.toggle').filter({has:page.locator('#benchRejectNoPing')}).click();
  await page.reload();
  await navigateTo(page,'profiles');
  await page.evaluate(() => { document.getElementById('testPanel').open = true; });
  await expect(page.locator('#benchRejectNoPing')).toBeChecked();
  await expect(page.locator('#benchSearchFailFast')).not.toBeChecked();
  for (const prefix of ['all','youtube','telegram','ai']) {
    await page.locator('#benchSearchServices').selectOption(prefix);
    const posted = page.waitForRequest(r => r.method() === 'POST' && new URL(r.url()).pathname === '/api/bench/start');
    await page.locator('#benchSearchAll').click();
    expect((await posted).postDataJSON().service_checks).toEqual({required_services:prefix,fail_fast:false,reject_no_ping:true});
  }
  await page.setViewportSize({width:390,height:844});
  await expect(page.locator('#benchPingGateHelp')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.request.post('/__fixture/reset');
});

test('one adapter sends shared service policies for every scope and separate global discovery policies', async ({ page }) => {
  test.setTimeout(90_000);
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await expect(page.locator('#benchSearchTarget')).toHaveValue('5');
  await openAdvancedParameters(page);
  await openCheckDetails(page);
  await expect(page.locator('#benchSearchServices option')).toHaveText(['Все: Ping+YT+TG+AI', 'YT', 'YT+TG', 'YT+TG+AI']);
  await page.evaluate(() => saveBenchConcurrency(4));
  await page.locator('.profile-select[data-server-ref="srv-v2-fixture-manual"]').check();
  await page.locator('.profile-select[data-server-ref="srv-v2-fixture-dead"]').check();
  const scopes = [
    { action: page.locator('#benchSearchAll'), body: {} },
    { action: page.locator('#benchAdvancedSearch'), body: {}, advanced:true },
    { action: page.locator('#benchSearchSelected'), body: { profile_ids: [102,202] } },
    { action: page.locator('.profile-group-row').filter({ hasText: 'Fixture VPN' }).locator('[data-bench-scope="subscription"]'), body: { subscription_url: 'https://provider.example/sub/fixture-token' } },
    { action: page.locator('.profile-group-row').filter({ hasText: 'Без группы' }).locator('[data-bench-scope="group"]'), body: { profile_ids: [102] } },
    { action: page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' }).locator('[data-bench-scope="single"]'), body: { profile_ids: [102] } },
    { action: page.locator('#favoritesBody tr').filter({ hasText: 'Fixture Profile' }).locator('[data-bench-scope="single"]'), body: { profile_ids: [101] }, favorite:true },
    { action: page.locator('.profile-group-row').filter({ hasText: 'Дохлые серверы' }).locator('[data-bench-scope="dead"]'), body: { profile_ids: [202] } },
    { action: page.locator('#trashList [data-bench-scope="single"]'), body: { profile_ids: [202] }, section:'trash' },
    { action: page.locator('#trashSearchAll'), body: { profile_ids: [202] }, section:'trash' },
  ];
  for (const params of [
    ...['complete_scope','find_n'].flatMap(mode => ['all','youtube','telegram','ai'].flatMap(services => [false,true].map(failFast => ({mode,services,failFast,target:services === 'ai' ? 20 : services === 'telegram' ? 1 : 5})))),
  ]) {
    await navigateTo(page,'profiles');
    await page.locator('#benchSearchStopMode').selectOption(params.mode);
    await expect(page.locator('#benchSearchServices')).toBeEnabled();
    await expect(page.locator('#benchSearchFailFast')).toBeEnabled();
    await page.locator('#benchSearchServices').selectOption(params.services);
    await page.locator('#benchSearchFailFast').evaluate((input, checked) => { input.checked = checked; input.dispatchEvent(new Event('change', { bubbles: true })); }, params.failFast);
    await page.locator('#benchRejectNoPing').evaluate((input, checked) => { input.checked = checked; input.dispatchEvent(new Event('change', { bubbles: true })); }, params.failFast);
    await page.locator('#benchFullPing').evaluate((input, checked) => { input.checked = checked; input.dispatchEvent(new Event('change', { bubbles: true })); }, params.failFast);
    if (params.mode === 'find_n') {
      await page.locator('#benchSearchTarget').fill(String(params.target));
      await expect(page.locator('#benchSelectionSearchHelp')).toHaveText('Все выбранные, включая Dead Servers');
    }
    for (const scope of scopes) {
      await navigateTo(page,scope.section || 'profiles');
      if (scope.favorite) await page.evaluate(() => {
        MOCK.profiles.find(profile => profile.id === 101).favorite = true;
        renderFavorites(MOCK.profiles);
      });
      const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start');
      await scope.action.click();
      expect((await posted).postDataJSON()).toEqual({
        method: scope.advanced && params.mode === 'find_n' ? 'availability_quick' : 'availability_full', concurrency: 4, test_download: false, test_upload: false,
        ...scope.body,
        ...(params.mode === 'find_n' && scope.advanced ? { search: { target_good: params.target, required_services: params.services, fail_fast:params.failFast } } : {service_checks:{required_services:params.services,fail_fast:params.failFast,...(params.failFast ? {reject_no_ping:true,full_ping:true} : {})}}),
      });
      await expect.poll(async () => (await page.request.get('/api/bench/status').then(response => response.json())).concurrency_status.requested).toBe(4);
      if (params.mode === 'find_n' && scope.advanced) {
        await expect(page.locator('#benchSearchStatus')).toContainText(`0/${params.target}`);
        await expect(page.locator('#benchSearchPartialHelp')).toBeVisible();
        await expect(page.locator('#benchSummary')).toBeHidden();
      } else await expect(page.locator('#benchSearchStatus')).toBeHidden();
    }
  }
  const recorded = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(recorded.requests.filter(request => ['/api/bench/settings', '/api/trash/move'].includes(request.path) && request.method === 'POST')).toHaveLength(0);
  await page.request.post('/__fixture/reset');
});

for (const delayed of [false, true]) {
  test(`rejected single search preserves accepted group progress, Stop, and summary${delayed ? ' after a later accepted job' : ''}`, async ({ page }) => {
    await page.request.post('/__fixture/reset');
    await openFixture(page);
    await navigateTo(page, 'profiles');
    await page.evaluate(() => benchGroup([101,104]));
    await expect(page.locator('#benchProgress')).toBeVisible();
    await expect(page.locator('#benchStop')).toBeVisible();
    expect(await page.evaluate(() => window.benchIsGroup)).toBe(true);
    let release;
    const rejectionGate = delayed ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
    await page.route('**/api/bench/start', async route => {
      if (route.request().postDataJSON()?.profile_ids?.join(',') === '102') {
        await rejectionGate;
        await route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ error: 'Fixture benchmark busy' }) });
      } else await route.continue();
    });
    const singleRequest = page.waitForRequest(request => new URL(request.url()).pathname === '/api/bench/start' && request.postDataJSON()?.profile_ids?.join(',') === '102');
    const rejection = page.waitForResponse(response => new URL(response.url()).pathname === '/api/bench/start' && response.status() === 409);
    await page.locator('#profilesBody tr').filter({ hasText: 'Fixture Manual' }).locator('[data-bench-scope="single"]').click();
    await singleRequest;
    const terminal = { running: false, method: 'availability_quick', search: null, total: 2, completed: 2,
      results: [{ profile_id: 101, server_ref: 'srv-v2-fixture-subscription', timestamp: serviceEpoch+200, method: 'availability_quick', success: true, latency_ms: 100, resource_tests: [{ contract_version: 1, id: 'youtube_thumbnails', stable: true, attempts: 1, successes: 1 }] }, { profile_id: 104, server_ref: 'srv-v2-fixture-second-subscription', timestamp: serviceEpoch+200, method: 'availability_quick', success: false, latency_ms: 100 }] };
    if (delayed) {
      expect(await page.evaluate(() => window.benchIsGroup)).toBe(true);
      await expect(page.locator('#benchStop')).toBeVisible();
      await page.request.post('/__fixture/bench-status', { data: terminal });
      await page.evaluate(() => pollBenchStatus());
      await expect(page.locator('#benchSummary')).toHaveCSS('display', 'grid');
      await page.evaluate(() => { saveBenchConcurrency(4); benchGroup([101,104]); });
      await expect(page.locator('#benchConcurrencyStatus')).toHaveText('Запрошено 4 / доступно 2 / в работе 1; лимит допуска 2; резерв памяти, число кандидатов');
      release();
    }
    await rejection;
    await expect(page.locator('#msgBar')).toHaveText('Fixture benchmark busy');
    await expect(page.locator('#benchProgress')).toBeVisible();
    await expect(page.locator('#benchStop')).toBeVisible();
    await expect(page.locator('#benchStop')).toBeEnabled();
    expect(await page.evaluate(() => window.benchIsGroup)).toBe(true);
    await page.request.post('/__fixture/bench-status', { data: terminal });
    await page.evaluate(() => pollBenchStatus());
    await expect(page.locator('#benchSummary')).toHaveCSS('display', 'grid');
    await expect(page.locator('#benchPassed')).toHaveText('1');
    await expect(page.locator('#benchFailed')).toHaveText('1');
    await page.request.post('/__fixture/reset');
  });
}

test('search concurrency shows actual admission, workers, and bounded reasons in RU and EN', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await page.evaluate(() => saveBenchConcurrency(4));
  await page.locator('#benchSearchAll').click();
  await expect(page.locator('#benchConcurrencyStatus')).toHaveText('Запрошено 4 / доступно 3 / в работе 1; лимит допуска 3; резерв памяти, число кандидатов');
  await openAdvancedParameters(page);
  await page.locator('#benchSearchStopMode').selectOption('find_n');
  for (const [target, admission, reasons] of [[5,3,['memory_cap','candidate_count']], [1,1,['memory_cap','candidate_count','target_slots']]]) {
    await page.locator('#benchSearchTarget').fill(String(target));
    await page.locator('#benchAdvancedSearch').click();
    await expect(page.locator('#benchSearchStatus')).toContainText(`0/${target}`);
    await expect(page.locator('#benchConcurrencyStatus')).toHaveText(`Запрошено 4 / доступно 3 / в работе 1; лимит допуска ${admission}; резерв памяти, число кандидатов${target === 1 ? ', оставшиеся места цели' : ''}`);
    const actual = await page.request.get('/api/bench/status').then(response => response.json());
    expect(actual.concurrency_status).toEqual({ requested: 4, effective: 3, active: 1, admission_limit: admission, limit_reasons: reasons });
  }
  const status = { running: true, method: 'availability_quick', total: 2, completed: 0, results: [],
    search: { target_good: 1, required_services: 'youtube', found_good: 0, preflight_completed: 0, preflight_rejected: 0, quick_completed: 0, finish_reason: null },
    concurrency_status: { requested: 4, effective: 2, active: 1, admission_limit: 1, limit_reasons: ['memory_cap','candidate_count','target_slots'] } };
  await page.request.post('/__fixture/bench-status', { data: status });
  await page.evaluate(() => pollBenchStatus());
  await expect(page.locator('#benchConcurrencyStatus')).toHaveText('Запрошено 4 / доступно 2 / в работе 1; лимит допуска 1; резерв памяти, число кандидатов, оставшиеся места цели');
  await page.evaluate(() => toggleLang());
  await expect(page.locator('#benchConcurrencyStatus')).toHaveText('Requested 4 / available 2 / active 1; admission limit 1; memory reserve, candidate count, remaining target slots');
  await page.request.post('/__fixture/bench-status', { data: { ...status, concurrency_status: { ...status.concurrency_status, limit_reasons: ['target_slots','unrecognized','candidate_count','memory_cap'] } } });
  await page.evaluate(() => pollBenchStatus());
  await expect(page.locator('#benchConcurrencyStatus')).toHaveText('Requested 4 / available 2 / active 1; admission limit 1; remaining target slots, candidate count');
  await page.evaluate(() => renderBenchConcurrencyStatus({ requested_concurrency: 4, concurrency: 3 }));
  await expect(page.locator('#benchConcurrencyStatus')).toHaveText('Requested 4 / available 3');
  await page.request.post('/__fixture/reset');
});

test('corrupt persisted search parameters are bounded and explicit dead selection stays complete', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.addInitScript(() => {
    localStorage.setItem('hr_search_stop_mode', '"unsupported"');
    localStorage.setItem('hr_search_target_good', '21');
    localStorage.setItem('hr_search_required_services', JSON.stringify('x'.repeat(1000)));
    localStorage.setItem('hr_search_fail_fast', '"false"');
    localStorage.setItem('hr_bench_concurrency', '99');
  });
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await openAdvancedParameters(page);
  await expect(page.locator('#benchSearchStopMode')).toHaveValue('complete_scope');
  await expect(page.locator('#benchSearchTarget')).toHaveValue('5');
  await expect(page.locator('#benchSearchFailFast')).not.toBeChecked();
  await expect(page.locator('#benchConcurrency')).toHaveValue('6');
  await page.locator('#benchSearchStopMode').selectOption('find_n');
  await expect(page.locator('#benchSearchServices')).toHaveValue('all');
  await expect(page.locator('#benchSearchServices option[value="all"]')).toBeEnabled();
  await page.locator('.profile-select[data-server-ref="srv-v2-fixture-dead"]').check();
  await expect(page.locator('#benchSelectionSearchHelp')).toHaveText('Все выбранные, включая Dead Servers');
  await page.locator('#benchSearchSelected').click();
  const recorded = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(recorded.requests.filter(request => request.path === '/api/bench/start').at(-1).body).toEqual({method:'availability_full',concurrency:6,test_download:false,test_upload:false,profile_ids:[202],service_checks:{required_services:'all',fail_fast:false}});
});

test('navigation cannot steal focus from a discovery input on the next frame', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  const focused = await page.evaluate(() => {
    navTo('profiles');
    document.getElementById('testPanel').open = true;
    document.getElementById('benchAdvancedParameters').open = true;
    document.getElementById('benchSearchStopMode').value = 'find_n';
    syncServerSearchParameters('stop_mode');
    document.getElementById('benchSearchTarget').focus();
    return new Promise(resolve => requestAnimationFrame(() => resolve(document.activeElement.id)));
  });
  expect(focused).toBe('benchSearchTarget');
});

test('discovery rejects invalid targets and services before posting', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await openAdvancedParameters(page);
  await page.locator('#benchSearchStopMode').selectOption('find_n');
  for (const value of ['', '0', '21', '1.5', '-1']) {
    await page.locator('#benchSearchTarget').fill(value);
    await expect(page.locator('#benchSearchTarget')).toHaveValue(value);
    await page.locator('#benchAdvancedSearch').click();
    await expect(page.locator('#msgBar')).toHaveText('Укажите целое число серверов от 1 до 20');
  }
  await page.locator('#benchSearchTarget').fill('5');
  await page.locator('#benchSearchServices').evaluate(select => { select.value = ''; });
  await page.locator('#benchAdvancedSearch').click();
  await expect(page.locator('#msgBar')).toHaveText('Выберите нужные сервисы');
  await page.evaluate(() => startServerSearch({selected:true}));
  const recorded = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(recorded.requests.filter(request => request.path === '/api/bench/start')).toHaveLength(0);
});

test('discovery controls and help stay readable on mobile and bilingual', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await openAdvancedParameters(page);
  await expect(page.locator('#benchSearchAll')).toBeVisible();
  await expect(page.locator('#benchPostActionsHelp')).toContainText('как всей области, так и N серверов, не запускает поднятие серверов');
  expect(await page.locator('#benchSearchParameters').evaluate(element => element.getBoundingClientRect().right <= window.innerWidth)).toBe(true);
  await page.evaluate(() => toggleLang());
  await expect(page.locator('label[for="benchSearchTarget"]')).toHaveText('Servers to find');
  await expect(page.locator('label[for="benchSearchServices"]')).toHaveText('Required services');
  await expect(page.locator('#testPanel > summary')).toHaveText('Service check parameters');
  await expect(page.locator('#benchSearchAll')).toHaveText('Check services');
  await expect(page.locator('#benchSearchSelected')).toHaveText('Check services');
  await expect(page.locator('[data-bench-scope="subscription"]').first()).toHaveText('⚡ Check services');
  await expect(page.locator('#benchSearchHelp')).toContainText('only to advanced search');
  await page.evaluate(() => toggleLang());
  await expect(page.locator('#benchSearchAll')).toHaveText('Проверить сервисы');
});

for (const scenario of [
  { reason: 'target_reached', found: 2, completed: 3, rejects: 1, quick: 2, ru: 'Поиск: цель достигнута', en: 'Discovery: target reached' },
  { reason: 'exhausted', found: 1, completed: 8, rejects: 6, quick: 2, ru: 'Поиск: кандидаты исчерпаны', en: 'Discovery: candidates exhausted' },
  { reason: 'cancelled', found: 0, completed: 2, rejects: 2, quick: 0, ru: 'Поиск отменён', en: 'Discovery cancelled' },
]) {
  test(`discovery status distinguishes preflight and service tests when ${scenario.reason}`, async ({ page }) => {
    await page.request.post('/__fixture/reset');
    await openFixture(page);
    await openCheckDetails(page);
    const status = {
      running: true, method: 'availability_quick', total: 8, completed: 0, results: [],
      search: { target_good: 2, required_services: 'telegram', found_good: 0, preflight_completed: 0, preflight_rejected: 0, quick_completed: 0, finish_reason: null },
    };
    await page.request.post('/__fixture/bench-status', { data: status });
    await page.evaluate(() => pollBenchStatus());
    await expect(page.locator('#benchSearchStatus')).toHaveText('Найдено: 0/2 (YT+TG) · Предпроверено: 0 · Отсеяно предпроверкой: 0 · Сервисы проверены: 0');
    await expect(page.locator('#benchStop')).toBeVisible();
    if (scenario.reason === 'cancelled') {
      await page.request.post('/__fixture/bench-status', { data: { ...status, cancel_requested: true } });
      await page.evaluate(() => pollBenchStatus());
      await expect(page.locator('#benchCurrent')).toHaveText('Останавливается…');
      await expect(page.locator('#benchStop')).toBeDisabled();
    }
    const terminal = {
      ...status, running: false, completed: scenario.completed,
      results: Array.from({ length: scenario.quick }, (_, index) => ({ profile_id: 900 + index, server_ref: 'srv-v2-'+String(index+1).padStart(32,'0'), timestamp: serviceEpoch+200, method: 'search_availability', success: index < scenario.found, latency_ms: 100 })),
      search: { ...status.search, found_good: scenario.found, preflight_completed: scenario.completed, preflight_rejected: scenario.rejects, quick_completed: scenario.quick, finish_reason: scenario.reason },
    };
    const untested = await page.evaluate(() => MOCK.profiles.find(profile => profile.id === 102));
    await page.request.post('/__fixture/bench-status', { data: terminal });
    await page.evaluate(() => pollBenchStatus());
    await expect(page.locator('#benchCurrent')).toHaveText('Проверка завершена');
    await expect(page.locator('#benchCurrent')).toHaveCSS('white-space', 'nowrap');
    await expect(page.locator('#benchCounter')).toHaveText(`${scenario.completed}/8`);
    await expect(page.locator('#benchResultStatus')).toHaveText(`Проверено: ${scenario.quick}/8 · Найдено: ${scenario.found}/2`);
    await expect(page.locator('#benchSearchStatus')).toHaveText(`Найдено: ${scenario.found}/2 (YT+TG) · Предпроверено: ${scenario.completed} · Отсеяно предпроверкой: ${scenario.rejects} · Сервисы проверены: ${scenario.quick}`);
    await expect(page.locator('#benchSummary')).toBeHidden();
    await expect(page.locator('#benchStop')).toBeHidden();
    await page.waitForTimeout(1400);
    await expect(page.locator('#benchProgress')).toBeVisible();
    expect(await page.evaluate(() => MOCK.profiles.find(profile => profile.id === 102))).toEqual(untested);
    await page.evaluate(() => toggleLang());
    await expect(page.locator('#benchCurrent')).toHaveText('Check complete');
    await expect(page.locator('#benchSearchStatus')).toContainText(`Found: ${scenario.found}/2`);
    await expect(page.locator('#benchSearchStatus')).toContainText(`Preflight rejected: ${scenario.rejects}`);
    await expect(page.locator('#benchSearchStatus')).toContainText(`Services tested: ${scenario.quick}`);
    await page.request.post('/__fixture/bench-status', { data: { running: false, search: null, results: [] } });
    await page.evaluate(() => pollBenchStatus());
    await expect(page.locator('#benchSearchStatus')).toBeHidden();
    await page.request.post('/__fixture/reset');
  });
}

test('discovery status polling remains single-flight', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  let inFlight = 0;
  let maximum = 0;
  await page.route('**/api/bench/status', async route => {
    maximum = Math.max(maximum, ++inFlight);
    await new Promise(resolve => setTimeout(resolve, 200));
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ running: false, results: [], search: { target_good: 5, required_services: 'youtube', found_good: 0, preflight_completed: 0, preflight_rejected: 0, quick_completed: 0, finish_reason: 'cancelled' } }) });
    inFlight -= 1;
  });
  await page.evaluate(() => Promise.all([pollBenchStatus(), pollBenchStatus(), pollBenchStatus()]));
  expect(maximum).toBe(1);
  await expect(page.locator('#benchCurrent')).toHaveText('—');
});

test('Dead Servers supports single and bulk diagnostics, restore, and clear', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  await openAdvancedParameters(page);
  await page.locator('#benchSearchFailFast').locator('xpath=..').click();
  await expect(page.locator('#benchSearchFailFast')).toBeChecked();
  await page.locator('#benchSearchStopMode').selectOption('find_n');
  await page.locator('#benchSearchServices').selectOption('ai');
  await page.locator('#benchSearchTarget').fill('0');
  for (const action of [
    page.locator('#profilesBody tr').filter({ hasText: 'Fixture Dead' }).locator('[data-bench-scope="single"]'),
    page.locator('.profile-group-row').filter({ hasText: 'Дохлые серверы' }).locator('[data-bench-scope="dead"]'),
  ]) {
    const posted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start');
    await action.click();
    expect((await posted).postDataJSON()).toEqual({ profile_ids: [202], method: 'availability_full', concurrency: 1, test_download: false, test_upload: false, service_checks:{required_services:'ai',fail_fast:true} });
  }
  await navigateTo(page, 'trash');
  const list = page.locator('#trashList');
  await expect(list).toContainText('Fixture Dead');

  const singleQuick = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start'
  );
  await list.locator('[data-bench-scope="single"]').click();
  expect((await singleQuick).postDataJSON()).toEqual({
    profile_ids: [202],
    method: 'availability_full', concurrency: 1,
    test_download: false,
    test_upload: false,
    service_checks:{required_services:'ai',fail_fast:true},
  });

  const bulkQuick = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start'
  );
  await page.locator('#trashSearchAll').click();
  expect((await bulkQuick).postDataJSON()).toEqual({
    profile_ids: [202],
    method: 'availability_full', concurrency: 1,
    test_download: false,
    test_upload: false,
    service_checks:{required_services:'ai',fail_fast:true},
  });
  const recorded = await page.request.get('/__fixture/requests').then(response => response.json());
  expect(recorded.requests.filter(request => request.method === 'POST' && ['/api/trash/restore','/api/trash/move'].includes(request.path))).toHaveLength(0);
  await page.getByRole('button', { name: 'Параметры проверки сервисов' }).click();
  await expect(page.locator('#testPanel')).toHaveAttribute('open', '');
  await page.locator('#benchSearchStopMode').selectOption('complete_scope');
  await expect(page.locator('#benchSearchFailFast')).toBeChecked();
  await page.locator('#benchSearchStopMode').selectOption('find_n');
  await navigateTo(page, 'trash');
  const failFast = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/bench/start');
  await page.locator('#trashSearchAll').click();
  expect((await failFast).postDataJSON()).toEqual({ profile_ids: [202], method: 'availability_full', concurrency: 1, test_download: false, test_upload: false,service_checks:{required_services:'ai',fail_fast:true} });

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
  await page.locator('#testPanel > summary').click();
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

test('synthetic Mihomo fake IP cannot be persisted as a routing resource', async ({ page }) => {
  await openFixture(page);
  const result = await page.evaluate(() => ({
    fake18: isMihomoFakeIp('198.18.42.7'),
    fake19: isMihomoFakeIp('198.19.255.255'),
    real: isMihomoFakeIp('198.20.0.1'),
    resource: connectionRoutingResource({site:'198.18.42.7:443'}),
    recovered: visualRoutingSite({recovered_host:'api.example.ai',destination_ip:'198.18.42.7'}),
  }));
  expect(result).toEqual({
    fake18: true,
    fake19: true,
    real: false,
    resource: '',
    recovered: 'api.example.ai',
  });
});

test('fail-closed connection and proxy status remain visibly unhealthy', async ({ page }) => {
  await openFixture(page);
  const result = await page.evaluate(() => ({
    route: describeConnectionRoute(
      {chain_list:['REJECT','srv-route-deadbeef','proxy']},
      new Map([['deadbeef',{ref:'srv-v1-deadbeef',name:'Pinned'}]]),
      {active_profile_name:'Fixture active',active_profile_protocol:'VLESS'},
    ),
    groups: normalizeProxyGroups({proxies:{
      missing:{type:'Fallback',now:'REJECT'},
      healthy:{type:'Fallback',now:'proxy-active',alive:true},
      'proxy-active':{type:'Vless',alive:false,extra:{
        'https://www.gstatic.com/generate_204?hincyray=main':{alive:true,history:[{delay:137}]},
      }},
      proxy:{type:'Selector',now:'proxy-active'},
      'proxy-health':{type:'Fallback',now:'proxy-active',alive:true,hidden:true},
    }}),
    rejectedGroups: normalizeProxyGroups({proxies:{
      'proxy-active':{type:'Vless',extra:{
        'https://www.gstatic.com/generate_204?hincyray=main':{alive:true,history:[{delay:137}]},
      }},
      proxy:{type:'Selector',now:'REJECT',alive:true},
    }}),
  }));
  expect(result.route).toMatchObject({kind:'reject',badge:'bad',label:'REJECT'});
  expect(result.groups.find(group => group.name === 'missing')?.alive).toBe(false);
  expect(result.groups.find(group => group.name === 'healthy')?.alive).toBe(true);
  expect(result.groups.find(group => group.name === 'proxy')).toMatchObject({alive:true,delay:137});
  expect(result.rejectedGroups.find(group => group.name === 'proxy')?.alive).toBe(false);
  expect(result.groups.some(group => group.name === 'proxy-health')).toBe(false);
});

test('refreshing every subscription also invalidates the routing server catalog', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'import');
  const routingReload = page.waitForRequest(request =>
    request.method() === 'GET' && new URL(request.url()).pathname === '/api/routing'
  );
  await page.getByRole('button', { name: '↻ Обновить все' }).click();
  await routingReload;
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

test('connection action uses a wide searchable grouped target picker and posts the resource route', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'connections-table');
  await page.locator('#connectionsTableSearch').fill('🇷🇺 chatgpt.com');

  const action = page.getByTestId('connections-action');
  await expect(action).toHaveCount(1);
  await expect(action).toHaveAttribute('data-custom-select-enhanced', '1');
  await expect(action).not.toHaveAttribute('data-native-select', '1');
  const shell = action.locator('xpath=..');
  await shell.locator('.custom-select-trigger').click();
  await expect(shell).toHaveClass(/open/);
  const dialog = page.locator('.routing-target-dialog');
  const dialogBox = await dialog.boundingBox();
  expect(dialogBox.width).toBeGreaterThanOrEqual(700);
  expect(Math.abs(dialogBox.x + dialogBox.width / 2 - 640)).toBeLessThan(2);
  await expect(dialog.locator('.custom-select-group')).toHaveCount(2);
  const search = dialog.locator('.custom-select-search');
  await search.fill('Very long unavailable');
  await expect(dialog.locator('.custom-select-option', {hasText:'Very long unavailable route target'})).toBeVisible();
  await page.evaluate(() => window.refreshConnectionsTable({auto:true}));
  await expect(shell).toHaveClass(/open/);
  await search.fill('DIRECT');

  const posted = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/resource-route'
  );
  await dialog.locator('.custom-select-option[data-value="direct"]').click();

  const request = await posted;
  expect(request.postDataJSON()).toEqual({
    resource: 'chatgpt.com',
    target: 'direct',
    close_connections: true,
  });
});

test('resource reconnect applies pending routing before closing and warns about Dead Servers fallback', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'connections-table');
  await page.locator('#connectionsTableSearch').fill('🇷🇺 chatgpt.com');
  const requests = [];
  page.on('request', request => {
    const path = new URL(request.url()).pathname;
    if (request.method() === 'POST' && path === '/api/routing/resource-reload') requests.push({path,body:request.postDataJSON()});
  });
  await page.locator('#connectionsRoutingBody tr').filter({hasText:'chatgpt.com'}).getByRole('button', {name:/Применить правило и переподключить/}).click();
  await expect(page.locator('#msgBar')).toContainText('Dead Servers');
  await expect.poll(() => requests).toEqual([{path:'/api/routing/resource-reload',body:{resource:'chatgpt.com',source_ip:'192.0.2.10',port:443,network:'tcp'}}]);
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

test('routing rule target uses the same wide searchable server picker', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  const select = page.locator('#ruleTarget');
  const shell = select.locator('xpath=..');
  await shell.locator('.custom-select-trigger').click();
  const dialog = page.locator('.routing-target-dialog');
  expect((await dialog.boundingBox()).width).toBeGreaterThanOrEqual(700);
  await dialog.locator('.custom-select-search').fill('Fixture Wagon');
  await dialog.locator('.custom-select-option[data-value="server:srv-v1-wagon"]').click();
  await expect(select).toHaveValue('server:srv-v1-wagon');
  await expect(shell.locator('.custom-select-trigger')).toContainText('#');
});

test('routing save is single-flight and a failed edit remains an edit on retry', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.request.post('/api/routing/rules',{data:{rules:[{enabled:true,name:'Original',target:'direct',domains:[],ips:[],ports:['443'],network:'tcp',port_mode:'include'}]}});
  await openFixture(page);
  await navigateTo(page,'routing');
  await page.locator('#routingRulesBody tr').first().getByRole('button',{name:'Редактировать правило',exact:true}).click();
  await page.locator('#ruleName').fill('Retry draft');
  let attempts=0, release;
  const held=new Promise(resolve=>release=resolve);
  await page.route('**/api/routing/rules',async route=>{
    if(route.request().method()!=='POST') return route.continue();
    attempts++;
    if(attempts===1) { await held; return route.fulfill({status:500,contentType:'application/json',body:JSON.stringify({error:'fixture activation failure'})}); }
    await route.continue();
  });
  await page.locator('#ruleSubmitBtn').click();
  await expect(page.locator('#ruleSubmitBtn')).toBeDisabled();
  await page.evaluate(()=>{submitRoutingRule();moveRoutingRule(0,1);toggleRoutingRule(0,false);});
  expect(attempts).toBe(1);
  release();
  await expect(page.locator('#ruleSubmitBtn')).toBeEnabled();
  await expect(page.locator('#ruleName')).toHaveValue('Retry draft');
  await expect(page.locator('#ruleFormTitle')).toContainText('Редактировать');
  const retry=page.waitForRequest(request=>request.method()==='POST'&&new URL(request.url()).pathname==='/api/routing/rules');
  await page.locator('#ruleSubmitBtn').click();
  expect((await retry).postDataJSON().rules).toHaveLength(1);
  await expect(page.locator('#routingRulesBody')).toContainText('Retry draft');
  expect(attempts).toBe(2);
  await page.request.post('/__fixture/reset');
});

test('stale routing save preserves draft and refreshes revision without losing another writer', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.request.post('/api/routing/rules',{data:{rules:[{enabled:true,name:'Original',target:'direct',ports:['443'],network:'tcp'}]}});
  await openFixture(page);
  await navigateTo(page,'routing');
  await page.locator('#ruleName').fill('Local draft');
  await page.locator('#rulePorts').fill('3724');
  const other=(await (await page.request.get('/api/routing')).json()).rules;
  other.push({enabled:true,name:'Other window',target:'direct',ports:['1119'],network:'tcp'});
  await page.request.post('/api/routing/rules',{data:{rules:other}});
  const rejected=page.waitForResponse(response=>response.request().method()==='POST'&&new URL(response.url()).pathname==='/api/routing/rules'&&response.status()===409);
  await page.locator('#ruleSubmitBtn').click();
  await rejected;
  await expect(page.locator('#ruleSubmitBtn')).toBeEnabled();
  await expect(page.locator('#ruleName')).toHaveValue('Local draft');
  await expect(page.locator('#routingRulesBody')).toContainText('Other window');
  await page.locator('#ruleSubmitBtn').click();
  await expect(page.locator('#routingRulesBody')).toContainText('Local draft');
  const saved=(await (await page.request.get('/api/routing')).json()).rules;
  expect(saved.map(rule=>rule.name)).toEqual(['Original','Other window','Local draft']);
  await page.request.post('/__fixture/reset');
});

test('global port rules validate ranges, preserve protocol and reorder above address rules', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await page.request.post('/api/routing/rules', {data:{rules:[{enabled:true,name:'Existing address rule',target:'active',domains:['example.test'],ips:[],ports:[],network:'any',port_mode:'include'}]}});
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#ruleName').fill('Global game UDP');
  await page.locator('#ruleTarget').selectOption('direct');
  await page.locator('#ruleNetwork').selectOption('udp');
  await page.locator('#rulePorts').fill('3478-3479, 5060/5062, 6250, 12000 - 64000');
  await page.locator('#rulePosition').selectOption('first');
  const post = page.waitForRequest(request => request.method()==='POST' && new URL(request.url()).pathname==='/api/routing/rules');
  await page.locator('#ruleSubmitBtn').click();
  const body = (await post).postDataJSON();
  expect(body.rules[0]).toMatchObject({name:'Global game UDP',target:'direct',network:'udp',port_mode:'include',
    ports:['3478-3479','5060','5062','6250','12000-64000'],domains:[],ips:[]});
  expect(body.apply).toBe(true);
  const row = page.locator('#routingRulesBody tr').filter({hasText:'Global game UDP'});
  await expect(row).toContainText('Глобально (все адреса)');
  await expect(row.getByRole('button',{name:'Выше по приоритету'})).toBeDisabled();
  await expect(page.locator('#routingRulesBody tr').last()).toContainText('MATCH');
  const reordered = page.waitForRequest(request => request.method()==='POST' && new URL(request.url()).pathname==='/api/routing/rules');
  await row.getByRole('button',{name:'Ниже по приоритету'}).click();
  expect((await reordered).postDataJSON().rules[1].name).toBe('Global game UDP');
  await page.reload();
  await navigateTo(page, 'routing');
  await expect(page.locator('#routingRulesBody tr').nth(1)).toContainText('Global game UDP');
  await row.getByRole('button',{name:'Редактировать правило',exact:true}).click();
  await expect(page.locator('#rulePorts')).toHaveValue('3478-3479,5060,5062,6250,12000-64000');
  await expect(page.locator('#ruleNetwork')).toHaveValue('udp');
  await expect(page.locator('#rulePositionField')).toBeHidden();
  await page.locator('#rulePortMode').selectOption('exclude');
  const edited = page.waitForRequest(request => request.method()==='POST' && new URL(request.url()).pathname==='/api/routing/rules');
  await page.locator('#ruleSubmitBtn').click();
  expect((await edited).postDataJSON().rules[1]).toMatchObject({name:'Global game UDP',network:'udp',port_mode:'exclude'});
  await expect(row).toContainText('[кроме]');
  await row.locator('td').nth(4).locator('.cell-edit').click();
  const inline = row.locator('td').nth(4).locator('input');
  await inline.fill('65536');
  await inline.press('Enter');
  expect(await inline.evaluate(input=>input.checkValidity())).toBe(false);
  await inline.fill('12000-54000');
  const inlinePost = page.waitForRequest(request => request.method()==='POST' && new URL(request.url()).pathname==='/api/routing/rules');
  await inline.press('Enter');
  expect((await inlinePost).postDataJSON().rules[1]).toMatchObject({ports:['12000-54000'],network:'udp',port_mode:'exclude'});
  await page.request.post('/__fixture/reset');
});

test('invalid destination ports do not post or replace the routing draft', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'routing');
  let posts = 0;
  page.on('request', request => { if (request.method()==='POST' && new URL(request.url()).pathname==='/api/routing/rules') posts++; });
  await page.locator('#ruleName').fill('Invalid draft');
  for (const invalid of ['0','65536','64000-12000','443,DIRECT','80-81-82','443,///']) {
    await page.locator('#rulePorts').fill(invalid);
    await page.locator('#ruleSubmitBtn').click();
    await expect(page.locator('#rulePorts')).toHaveAttribute('aria-invalid','true');
    await expect(page.locator('#rulePortsError')).toBeVisible();
    await expect(page.locator('#ruleName')).toHaveValue('Invalid draft');
  }
  expect(posts).toBe(0);
  await page.locator('#rulePorts').fill('1119,3724,6113');
  await page.locator('#ruleNetwork').selectOption('tcp');
  await page.locator('#ruleTarget').selectOption('direct');
  await expect(page.locator('#rulePortsError')).toBeHidden();
  const post = page.waitForRequest(request => request.method()==='POST' && new URL(request.url()).pathname==='/api/routing/rules');
  await page.locator('#ruleSubmitBtn').click();
  expect((await post).postDataJSON().rules.at(-1)).toMatchObject({network:'tcp',ports:['1119','3724','6113']});
  await page.request.post('/__fixture/reset');
});

test('port editor works on mobile and keeps pending ranges across refreshes', async ({ page }) => {
  await page.setViewportSize({width:390,height:844});
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#ruleName').fill('Voice ports');
  await page.locator('#rulePorts').fill('12000-54000');
  await page.locator('#ruleNetwork').selectOption('udp');
  await page.evaluate(() => window.loadRouting());
  await expect(page.locator('#rulePorts')).toHaveValue('12000-54000');
  await expect(page.locator('#ruleNetwork')).toHaveValue('udp');
  const dimensions = await page.evaluate(() => ({width:innerWidth,scroll:document.documentElement.scrollWidth}));
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.width);
  const box = await page.locator('#rulePorts').boundingBox();
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x+box.width).toBeLessThanOrEqual(390);
});

test('routing draft and server dialog survive a late dashboard response without losing selection', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#ruleName').fill('Unsaved edit');
  await page.locator('#ruleEntries').fill('draft.example');
  const select = page.locator('#ruleTarget');
  await select.locator('xpath=..').locator('.custom-select-trigger').click();
  const dialog = page.locator('.routing-target-dialog');
  await dialog.locator('.custom-select-search').fill('Fixture Wagon');
  await page.evaluate(() => window.loadRouting());
  await expect(dialog.locator('.custom-select-search')).toHaveValue('Fixture Wagon');
  await dialog.locator('.custom-select-option[data-value="server:srv-v1-wagon"]').click();
  await expect(select).toHaveValue('server:srv-v1-wagon');
  await expect(page.locator('#ruleName')).toHaveValue('Unsaved edit');
  await page.evaluate(() => window.refreshDashboard());
  await expect(select).toHaveValue('server:srv-v1-wagon');
  await expect(page.locator('#ruleEntries')).toHaveValue('draft.example');
});

test('unsaved routing settings and Torrent SOCKS target survive background refresh', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#splitRoutingSection summary').click();
  await page.locator('#rTorrentSocksListen').fill('192.168.2.1');
  await page.locator('#rTorrentSocksTarget').locator('xpath=..').locator('.custom-select-trigger').click();
  await page.locator('.routing-target-dialog .custom-select-search').fill('Fixture Wagon');
  await page.evaluate(() => window.loadRouting());
  await expect(page.locator('.routing-target-dialog .custom-select-search')).toHaveValue('Fixture Wagon');
  await page.locator('.routing-target-dialog .custom-select-option[data-value="server:srv-v1-wagon"]').click();
  await page.evaluate(() => window.refreshDashboard());
  await expect(page.locator('#rTorrentSocksListen')).toHaveValue('192.168.2.1');
  await expect(page.locator('#rTorrentSocksTarget')).toHaveValue('server:srv-v1-wagon');
  await page.evaluate(() => window.loadRouting({force:true}));
  await expect(page.locator('#rTorrentSocksListen')).toHaveValue('192.168.2.1');
  await expect(page.locator('#rTorrentSocksTarget')).toHaveValue('server:srv-v1-wagon');
});

test('server dialog closes when navigating or its inline editor disappears', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#ruleTarget').locator('xpath=..').locator('.custom-select-trigger').click();
  await expect(page.locator('.routing-target-dialog')).toBeVisible();
  await navigateTo(page, 'devices');
  await expect(page.locator('.routing-target-dialog, .routing-target-backdrop')).toHaveCount(0);
  await navigateTo(page, 'routing');
  await page.evaluate(() => {
    MOCK.routing_rules = [{enabled:true,name:'Transient',target:'active',domains:['example.test'],ips:[],services:[],ports:[],network:'any',port_mode:'include'}];
    renderRoutingRules(MOCK.routing_rules);
  });
  await page.locator('#routingRulesBody .cell-edit').filter({hasText:'Текущий активный VPN'}).click();
  await expect(page.locator('.routing-target-dialog')).toBeVisible();
  await page.evaluate(() => document.getElementById('routingRulesBody').replaceChildren());
  await expect(page.locator('.routing-target-dialog, .routing-target-backdrop')).toHaveCount(0);
});

test('routing table exposes deletion and undo without removed experimental controls', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  await expect(page.locator('#rParovozikConsist')).toHaveCount(0);
  await expect(page.locator('#routingRulesBody .managed-routing-rule')).toHaveCount(0);
  await page.locator('#ruleName').fill('<unsafe> sample');
  await page.locator('#ruleEntries').fill('delete.example');
  await page.locator('#ruleSubmitBtn').click();
  const row = page.locator('#routingRulesBody tr').filter({hasText:'<unsafe> sample'});
  await expect(row).toHaveCount(1);
  const deleted = page.waitForRequest(request => request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/rules' && !request.postDataJSON()?.rules?.some(rule => rule.name === '<unsafe> sample'));
  await row.getByRole('button',{name:'Удалить'}).click();
  expect((await deleted).postDataJSON().rules).not.toContainEqual(expect.objectContaining({name:'<unsafe> sample'}));
  await expect(page.locator('#routingUndo')).toContainText('<unsafe> sample');
  await expect(page.locator('#routingUndo b')).toHaveCount(1);
  await page.locator('#routingUndo button').click();
  await expect(row).toHaveCount(1);
});

test('server target dialog is centered above the page on narrow screens', async ({ page }) => {
  await page.setViewportSize({width:390,height:844});
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#ruleTarget').locator('xpath=..').locator('.custom-select-trigger').click();
  const box = await page.locator('.routing-target-dialog').boundingBox();
  expect(box.width).toBeGreaterThan(350);
  expect(Math.abs(box.x + box.width / 2 - 195)).toBeLessThan(2);
  expect(Math.abs(box.y + box.height / 2 - 422)).toBeLessThan(2);
  expect(await page.evaluate(() => document.elementFromPoint(195,422)?.closest('.routing-target-dialog') !== null)).toBe(true);
  await page.keyboard.press('Escape');
  await expect(page.locator('.routing-target-dialog')).toHaveCount(0);
});

test('a late connection refresh cannot replace a target dialog or connection rule editor', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'connections-table');
  await page.locator('#connectionsTableSearch').fill('🇷🇺 chatgpt.com');
  const action = page.getByTestId('connections-action');
  await expect(action).toHaveCount(1);
  await action.locator('xpath=..').locator('.custom-select-trigger').click();
  const dialog = page.locator('.routing-target-dialog');
  await dialog.locator('.custom-select-search').fill('Fixture Wagon');
  await page.evaluate(() => window.refreshConnectionsTable({auto:true}));
  await page.waitForTimeout(100);
  await expect(dialog.locator('.custom-select-search')).toHaveValue('Fixture Wagon');
  await page.keyboard.press('Escape');
  const row = page.locator('#connectionsRoutingBody tr').filter({hasText:'chatgpt.com'});
  await row.getByRole('button',{name:/Создать\/изменить правило/}).click();
  await expect(page.locator('#resultModal')).toBeVisible();
  await page.evaluate(() => window.refreshConnectionsTable({auto:true}));
  await expect(page.locator('#connectionRuleTarget')).toBeAttached();
  await page.locator('#connectionRuleTarget').selectOption('direct');
  await expect(page.locator('#connectionRuleTarget')).toHaveValue('direct');
});

test('torrent SOCKS uses authenticated private settings and a grouped route picker', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#splitRoutingSection summary').click();
  await expect(page.locator('#rTorrentSocksEnabled')).toBeChecked();
  await expect(page.locator('#rTorrentSocksPort')).toHaveValue('10812');
  await expect(page.locator('#rTorrentSocksListen')).toHaveValue('192.168.1.1');
  await expect(page.locator('#rTorrentSocksUsername')).toHaveValue('fixture-torrent');
  await expect(page.locator('#rTorrentSocksPassword')).toHaveValue('');
  await expect(page.locator('#rTorrentSocksPasswordStatus')).toContainText('Пароль настроен');
  await expect(page.locator('#rTorrentSocksTarget')).toHaveValue('server:srv-v1-wagon');
  await expect(page.locator('#torrentSocksCard .hint').last()).toContainText('авторизация панели не требуется');

  const targetShell = page.locator('#rTorrentSocksTarget').locator('xpath=..');
  await targetShell.locator('.custom-select-trigger').click();
  await page.locator('.routing-target-dialog .custom-select-search').fill('Fixture Profile');
  await page.locator('.routing-target-dialog .custom-select-option[data-value="server:srv-v1-fixture"]').click();
  await page.locator('#rTorrentSocksPassword').fill('new-private-password');
  const posted = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/settings'
  );
  await page.locator('#splitRoutingSection button').filter({hasText:'Сохранить настройки'}).click();
  const body = (await posted).postDataJSON();
  expect(body.torrent_socks).toEqual({
    enabled:true,
    listen:'192.168.1.1',
    port:10812,
    username:'fixture-torrent',
    password:'new-private-password',
    target:'server:srv-v1-fixture',
  });
  await expect(page.locator('#rTorrentSocksPassword')).toHaveValue('');

  const secondPost = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/settings'
  );
  await page.locator('#splitRoutingSection button').filter({hasText:'Сохранить настройки'}).click();
  expect((await secondPost).postDataJSON().torrent_socks).not.toHaveProperty('password');

  const clearPost = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/settings'
      && request.postDataJSON()?.torrent_socks?.clear_credentials === true
  );
  await page.locator('#rTorrentSocksClear').click();
  expect((await clearPost).postDataJSON()).toEqual({
    apply:true,
    torrent_socks:{enabled:false,clear_credentials:true},
  });
  await expect(page.locator('#rTorrentSocksEnabled')).not.toBeChecked();
  await expect(page.locator('#rTorrentSocksUsername')).toHaveValue('');
  await expect(page.locator('#rTorrentSocksPasswordStatus')).toContainText('Пароль не настроен');
});

test('Torrent SOCKS5 connections are visibly labeled alongside ordinary connections', async ({ page }) => {
  await openFixture(page);
  const rows = await page.evaluate(() => {
    const ordinary = {id:'ordinary', metadata:{host:'ordinary.example',network:'tcp',inboundName:'redir-in'},chains:['proxy-active']};
    const torrent = {id:'torrent', metadata:{host:'peer.example',network:'tcp',inboundName:'torrent-socks-in'},chains:['srv-out-example']};
    const normalized = normalizeConnections({connections:[ordinary,torrent]}, null);
    renderActiveConns(normalized);
    const visual = buildVisualRoutingRows(normalized, {servers:[]}, {});
    connectionsTableRows = visual;
    renderConnectionsTableRows();
    return {
      active:[...document.querySelectorAll('#activeConnsBody tr')].map(row=>row.textContent),
      visual:[...document.querySelectorAll('#connectionsRoutingBody tr')].map(row=>row.textContent),
    };
  });
  expect(rows.active[0]).not.toContain('Torrent SOCKS5');
  expect(rows.active[1]).toContain('Torrent SOCKS5');
  expect(rows.visual.find(row=>row.includes('peer.example'))).toContain('Torrent SOCKS5');
  expect(rows.visual.find(row=>row.includes('ordinary.example'))).not.toContain('Torrent SOCKS5');
});

test('torrent SOCKS first password is validated in bytes before saving, including after a refresh', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  const settingsPosts = [];
  page.on('request', request => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/routing/settings') settingsPosts.push(request);
  });
  await page.route('**/api/routing', async route => {
    if (route.request().method() !== 'GET') return route.continue();
    const response = await route.fetch();
    const body = await response.json();
    body.settings.torrent_socks = {
      enabled:false, listen:'127.0.0.1', port:10812,
      username:'', password_set:false, target:'direct',
    };
    await route.fulfill({response, json:body});
  });
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.locator('#splitRoutingSection summary').click();
  await page.locator('#rTorrentSocksEnabled').locator('xpath=..').click();
  await page.locator('#rTorrentSocksUsername').fill('torrent');
  const password = page.locator('#rTorrentSocksPassword');
  const save = page.locator('#splitRoutingSection button').filter({hasText:'Сохранить настройки'});
  await save.click();
  await expect(page.locator('#msgBar')).toContainText('Введите пароль SOCKS5 длиной от 12 до 512 байт');
  expect(settingsPosts).toHaveLength(0);
  await password.fill('12345678901');
  await expect(page.locator('#rTorrentSocksPasswordLength')).toContainText('11 байт (минимум 12)');
  await save.click();
  await expect(page.locator('#msgBar')).toContainText('Введите пароль SOCKS5 длиной от 12 до 512 байт');
  expect(settingsPosts).toHaveLength(0);
  await password.fill('🔒'.repeat(3));
  await expect(page.locator('#rTorrentSocksPasswordLength')).toContainText('12 байт (минимум 12)');
  await password.fill('123456789012');
  await expect(page.locator('#rTorrentSocksPasswordLength')).toContainText('12 байт (минимум 12)');
  await page.evaluate(() => loadRouting({force:true}));
  await expect(password).toHaveValue('123456789012');
  const posted = page.waitForRequest(request => request.method() === 'POST'
    && new URL(request.url()).pathname === '/api/routing/settings');
  await save.click();
  const body = (await posted).postDataJSON();
  expect(body.torrent_socks).toMatchObject({enabled:true,username:'torrent',password:'123456789012'});
  await expect(password).toHaveValue('');
  await expect(page.locator('#rTorrentSocksPasswordLength')).toBeEmpty();
});

test('inline existing-rule target uses the wide picker without blur cancellation', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await page.evaluate(() => {
    MOCK.routing_rules = [{enabled:true,name:'Existing',target:'active',domains:['existing.example'],ips:[],services:[],ports:[],network:'any',port_mode:'include'}];
    renderRoutingRules(MOCK.routing_rules);
  });
  await navigateTo(page, 'routing');
  await page.locator('#routingRulesBody .cell-edit').filter({hasText:'Текущий активный VPN'}).click();
  const shell = page.locator('#routingRulesBody .routing-target-select');
  await expect(shell).toHaveClass(/open/);
  await page.locator('.routing-target-dialog .custom-select-search').fill('Fixture Wagon');
  await page.waitForTimeout(150);
  await expect(shell).toHaveClass(/open/);
  const posted = page.waitForRequest(request => request.method()==='POST' && new URL(request.url()).pathname==='/api/routing/rules');
  await page.locator('.routing-target-dialog .custom-select-option[data-value="server:srv-v1-wagon"]').click();
  expect((await posted).postDataJSON().rules[0].target).toBe('server:srv-v1-wagon');
});

test('removed experimental routing target is absent after status refresh', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  await page.evaluate(() => window.refreshStatus());
  await page.waitForTimeout(100);
  await expect(page.locator('option[value="parovozik"]')).toHaveCount(0);
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
  await page.evaluate(() => {
    const schedule = window.requestAnimationFrame.bind(window);
    window.requestAnimationFrame = callback => String(callback).includes('profileEditorName') ? 0 : schedule(callback);
  });
  const modal = page.getByTestId('profile-editor-modal');
  await page.evaluate(() => openProfileEditor(103));
  await expect(modal).toBeVisible();
  await expect(modal.locator('#profileEditorXhttpTuning')).toBeVisible();
  await expect(modal.locator('#profileEditorScMaxEachPostBytes')).toHaveValue('2048');
  await expect(modal.locator('#profileEditorName')).toBeFocused();
  await expect(modal.locator('#profileEditorScMaxEachPostBytes option')).toHaveText([
    '2048 bytes (текущее)', '4 КБ', '8 КБ', '16 КБ', '32 КБ',
  ]);
  await modal.locator('#profileEditorScMaxEachPostBytes').selectOption('32768');
  await modal.locator('#profileEditorScMinPostsIntervalMs').fill('15-15');
  await expect(modal.locator('#profileEditorScMinPostsIntervalMs')).toHaveValue('15-15');
  const updateRequest = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/profiles/update'
  );
  await modal.locator('#profileEditorSave').click();
  expect((await updateRequest).postDataJSON()).toMatchObject({
    profile_id: 103,
    expected_server_ref: 'srv-v2-fixture-xhttp',
    xhttp_tuning: {
      sc_max_each_post_bytes: '32768',
      sc_min_posts_interval_ms: '15-15',
    },
  });
});

test('subscription arrows persist a bounded group move request', async ({ page }) => {
  await page.request.post('/__fixture/reset');
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const group = page.locator('#profilesBody .profile-group-row').filter({ hasText: 'Fixture Second VPN' });
  const moved = page.waitForRequest(request =>
    request.method() === 'POST' && new URL(request.url()).pathname === '/api/subscriptions/move'
  );
  await group.getByTitle('Переместить подписку выше').click();
  expect((await moved).postDataJSON()).toEqual({
    url: 'https://provider.example/sub/second-token',
    adjacent_url: 'https://provider.example/sub/fixture-token',
    direction: 'up',
  });
  await expect(page.locator('#profilesBody tr').filter({ hasText:'Fixture Manual' }).getByTitle('Переместить подписку выше')).toHaveCount(0);
});

test('profile groups follow subscription order instead of profile insertion order', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'profiles');
  const order = await page.locator('#profilesBody .profile-group-row').evaluateAll(rows => rows.map(row => row.textContent));
  expect(order.findIndex(text => text.includes('Fixture VPN'))).toBeLessThan(order.findIndex(text => text.includes('Fixture Second VPN')));
  await page.evaluate(() => {
    MOCK.subscriptions.reverse();
    renderProfiles(MOCK.profiles);
  });
  const reversed = await page.locator('#profilesBody .profile-group-row').evaluateAll(rows => rows.map(row => row.textContent));
  expect(reversed.findIndex(text => text.includes('Fixture Second VPN'))).toBeLessThan(reversed.findIndex(text => text.includes('Fixture VPN')));
});

test('sidebar operation navigates to its owning section', async ({ page }) => {
  await openFixture(page);
  await page.evaluate(() => beginLongOperation('/api/geobases/sync', 'Обработка GeoBase…'));
  await page.locator('#longOperationProgress').click();
  await expect(page.locator('.section-panel[data-section="routing"]')).toHaveClass(/open/);
});

test('routing keeps GeoBase and collapsed Split Routing at the bottom', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'routing');
  await expect(page.locator('#splitRoutingSection')).not.toHaveAttribute('open', '');
  const order = await page.locator('.section-panel[data-section="routing"] .section-body').evaluate(body => {
    const children = [...body.children];
    return {
      geo: children.indexOf(document.querySelector('#geoBaseSection')),
      split: children.indexOf(document.querySelector('#splitRoutingSection')),
      total: children.length,
      geoHasConstructor: document.querySelector('#geoBaseSectionBody')?.contains(document.querySelector('#geobaseConstructor')),
    };
  });
  expect(order.geo).toBe(order.total - 2);
  expect(order.split).toBe(order.total - 1);
  expect(order.geoHasConstructor).toBe(true);
});

test('proxy status omits raw EC controls and DNS diagnostics renders structured listener result', async ({ page }) => {
  await openFixture(page);
  await navigateTo(page, 'ov-proxy');
  await expect(page.locator('.section-panel[data-section="ov-proxy"]')).not.toContainText('EC API');
  await page.route('**/api/dns/diagnostics', route => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({
      split_routing_enabled: true,
      dns_listener_port: 1053,
      local_dns: { ok:true, rcode:0, answers:['93.184.216.34'] },
      direct_dns: { stdout:'Name: example.com' },
      proxy_trace_sample: [],
    }),
  }));
  await page.evaluate(() => dnsDiagnostics());
  await expect(page.locator('#resultModal')).toContainText('93.184.216.34');
  await expect(page.locator('#resultModal')).not.toContainText('Mihomo API');
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
  await expect(options).toHaveCount(4);
  await expect(options.nth(3)).toBeDisabled();
  await expect(options.nth(3)).toContainText('Fixture Dead (#202)');
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
