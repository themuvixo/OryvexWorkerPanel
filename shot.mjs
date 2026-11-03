#!/usr/bin/env node
/**
 * NIGHTLINE v2.5.2 — Automated Screenshot Generator for GitHub Documentation (`docs/screenshots/`)
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import { chromium } from 'playwright';

const OUT_DIR = 'docs/screenshots';
fs.mkdirSync(OUT_DIR, { recursive: true });

const PORT = 19420 + Math.floor(Math.random() * 250);
const MOCK_PORT = 19720 + Math.floor(Math.random() * 200);
const BASE = `http://127.0.0.1:${PORT}`;
const MOCK_BASE = `http://127.0.0.1:${MOCK_PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const mockSrv = http.createServer((req, res) => {
  const u = new URL(req.url, MOCK_BASE);
  res.setHeader('content-type', 'application/json');
  if (u.pathname === '/official-ips') {
    return res.end(fs.readFileSync(new URL('./fixtures/cloudflare-ips.json', import.meta.url)));
  }
  if (u.pathname === '/cf/user/tokens/verify') {
    return res.end(JSON.stringify({ success: true, result: { status: 'active' } }));
  }
  if (u.pathname === '/cf/accounts') {
    return res.end(JSON.stringify({ success: true, result: [{ id: 'acc_demo', name: 'Cloudflare Edge' }] }));
  }
  if (u.pathname === '/cf/accounts/acc_demo/workers/scripts') {
    return res.end(JSON.stringify({ success: true, result: [{ id: 'nightline' }] }));
  }
  if (u.pathname === '/cf/accounts/acc_demo/workers/scripts/nightline/settings') {
    return res.end(JSON.stringify({ success: true, result: { bindings: [] } }));
  }
  if (u.pathname === '/cf/graphql') {
    return res.end(
      JSON.stringify({
        data: {
          viewer: {
            accounts: [
              {
                workersInvocationsAdaptive: [
                  { dimensions: { scriptName: 'nightline' }, sum: { requests: 18420, subrequests: 4100, errors: 0 } },
                ],
              },
            ],
          },
        },
      })
    );
  }
  res.statusCode = 404;
  res.end('{}');
});

await new Promise((resolve) => mockSrv.listen(MOCK_PORT, '127.0.0.1', resolve));

const proc = spawn(
  'npx',
  [
    'wrangler',
    'dev',
    '--local',
    '--port',
    String(PORT),
    '--persist-to',
    `/tmp/nl-shot-kv-${Date.now()}`,
    '--var',
    `NL_CF_API_BASE:${MOCK_BASE}/cf`,
    '--var',
    `NL_CF_IP_RANGES_TEST_URL:${MOCK_BASE}/official-ips`,
  ],
  { stdio: 'ignore' }
);

try {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) break;
    } catch {}
    await sleep(300);
  }

  const setupRes = await fetch(`${BASE}/api/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'DemoPassword2026!', firstUserName: 'Primary admin' }),
  });
  const cookie = (setupRes.headers.get('set-cookie') || '').split(';')[0];

  // Configure demo Cloudflare token so compact daily request bar renders live quota
  await fetch(`${BASE}/api/cf/config`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ action: 'save', token: 'cf_demo_token_for_screenshot_123456', dailyLimit: 100000 }),
  });

  // Seed realistic traffic on User 1 (12.4 GB / 50 GB) while adding User 2 with 0 B / ∞ (verifying 0% bar!)
  const backupData = await (await fetch(`${BASE}/api/backup`, { headers: { cookie } })).json();
  backupData.settings.cleanIPs = ['www.speedtest.net#Speedtest', '172.67.73.163#US|CF-Scan'];
  backupData.users[0].trafficLimitGB = 50;
  backupData.users[0].usedDownBytes = Math.round(12.4 * 1073741824);
  backupData.users[0].connections = 38;
  await fetch(`${BASE}/api/restore`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify(backupData),
  });

  await fetch(`${BASE}/api/users`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({
      name: 'Mobile user',
      note: 'New subscriber · no usage yet',
      trafficLimitGB: 0,
      expiryDays: 30,
      startOnFirstUse: true,
    }),
  });

  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1360, height: 920 }, deviceScaleFactor: 1.5 });
  await context.route('https://speed.cloudflare.com/meta', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        clientIp: '198.51.100.42',
        country: 'IR',
        city: 'Tehran',
        asn: 197207,
        asOrganization: 'Mobile Communication Company of Iran PLC',
        colo: 'FRA',
      }),
    });
  });
  const page = await context.newPage();

  await page.goto(`${BASE}/panel`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(450);

  // 1) Free & Non-Commercial Popup Modal screenshot
  await page.screenshot({ path: `${OUT_DIR}/06-free-notice-popup.png` });
  await page.click('#btn-free-close');

  // Login has no sponsor; the animated Telegram dock appears only inside the admin panel
  await page.waitForSelector('#v-login:not([hidden])');
  await page.screenshot({ path: `${OUT_DIR}/08-login-light-fa.png`, fullPage: true });
  await page.click('#lang');
  await page.click('.t-pick[data-th="dark"]');
  await page.waitForTimeout(240);
  await page.screenshot({ path: `${OUT_DIR}/09-login-dark-en.png`, fullPage: true });
  await page.click('#lang');
  await page.click('.t-pick[data-th="light"]');

  // Login
  await page.fill('#login-pass', 'DemoPassword2026!');
  await page.click('#f-login button[type="submit"]');
  await page.waitForSelector('#v-admin:not([hidden])');
  await page.click('#btn-speed-burst');
  await page.waitForTimeout(900);
  await page.evaluate(() => { const t = document.getElementById('toast'); if (t) t.hidden = true; });

  // 2) Dashboard (FA Light) — Compact CF Daily Quota Bar + GitHub Updater + Custom Legend Icons!
  await page.screenshot({ path: `${OUT_DIR}/01-dashboard-light-fa.png`, fullPage: true });

  // 3) Dashboard (EN Dark) — IP Blurred + Subscriber Usage Hatched Bar Chart (12.4 GB vs 0 B)!
  await page.click('#lang');
  await page.click('.t-pick[data-th="dark"]');
  await page.click('#btn-ip-blur');
  await page.click('#chart-mode-usage');
  await page.waitForTimeout(500);
  await page.screenshot({ path: `${OUT_DIR}/02-dashboard-dark-en.png`, fullPage: true });

  // Restore FA Light & capture Smart ISP Advisor (`07-smart-isp-advisor.png`) — verifying clean Tab 05 spacing!
  await page.click('#lang');
  await page.click('.t-pick[data-th="light"]');
  await page.click('#btn-ip-blur');

  await page.click('.tab-btn[data-tab="advisor"]');
  await page.waitForSelector('#pane-advisor:not([hidden])');
  await page.click('#btn-adv-run');
  await page.waitForSelector('#adv-recs:not([hidden])', { timeout: 15000 });
  await page.waitForTimeout(350);
  await page.screenshot({ path: `${OUT_DIR}/07-smart-isp-advisor.png`, fullPage: true });

  await page.click('.tab-btn[data-tab="net"]');
  await page.waitForSelector('#pane-net:not([hidden])');
  await context.route('https://ipwho.is/**', (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    headers: { 'access-control-allow-origin': '*' },
    body: JSON.stringify({ success: true, country_code: 'US' }),
  }));
  await page.click('#btn-scan-clean');
  await page.waitForSelector('#cf-ranges-panel:not([hidden])');
  await page.locator('.range-samples').evaluateAll((inputs) => {
    inputs.forEach((x, i) => { x.value = i === 0 ? '1' : '0'; });
  });
  await page.click('#btn-scan-ranges');
  await page.waitForSelector('#scan-results .range-result', { timeout: 12000 });
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${OUT_DIR}/03-network-scanner-tgproxy.png`, fullPage: true });

  // 4) Subscriber Press Pass (/sub/<token>)
  await page.click('.tab-btn[data-tab="sub"]');
  const subHref = await page.getAttribute('#open-pass', 'href');
  const subToken = subHref.split('/sub/')[1];

  const subPage = await context.newPage();
  await subPage.goto(`${BASE}/sub/${subToken}`, { waitUntil: 'networkidle' });
  await subPage.click('#sub-free-ok');
  await page.waitForTimeout(350);
  await subPage.screenshot({ path: `${OUT_DIR}/04-subscriber-press-pass.png`, fullPage: true });

  // 5) Private DoH Guide (/dns-query/<token>)
  const dohPage = await context.newPage();
  await dohPage.goto(`${BASE}/dns-query/${subToken}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  await dohPage.screenshot({ path: `${OUT_DIR}/05-private-doh-guide.png`, fullPage: true });

  await browser.close();
  console.log('✓ Generated all 9 high-resolution v2.5.2 screenshots in docs/screenshots/');
} catch (err) {
  console.error('SHOT FAILED:', err);
  proc.kill('SIGTERM');
  mockSrv.close();
  process.exit(1);
} finally {
  proc.kill('SIGTERM');
  mockSrv.close();
}
process.exit(0);
