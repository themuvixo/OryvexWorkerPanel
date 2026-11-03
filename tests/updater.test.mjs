// Unit tests for the release-based update check (no network, no workerd). Run: node --test tests/
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  _resetUpdateCache, bundleVersion, checkForUpdate, compareSemver, downloadReleaseBundle,
  isRepoConfigured, normalizeVersionString, tagFromReleaseLocation,
} from '../src/updater.js';

const REPO = 'acme/OryvexWorkerPanel';
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const redirect = (loc) => new Response(null, { status: 302, headers: { location: loc } });
const bundle = (v) => `// OryvexWorkerPanel v${v} · https://github.com/${REPO}\n` + 'x'.repeat(20000) + '\nexport{a as default};';

function fakeFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    for (const [match, handler] of routes) if (String(url).includes(match)) return handler(init);
    return new Response('nope', { status: 404 });
  };
  fn.calls = calls;
  return fn;
}

test('semver helpers', () => {
  assert.equal(normalizeVersionString('v1.2'), '1.2.0');
  assert.equal(normalizeVersionString('V2.0.1-beta.3'), '2.0.1');
  assert.equal(compareSemver('v1.10.0', '1.9.9'), 1);
  assert.equal(compareSemver('1.2.0', 'v1.2.0'), 0);
  assert.equal(compareSemver('1.2.0', '1.3.0'), -1);
  assert.equal(isRepoConfigured('OWNER/OryvexWorkerPanel'), false);
  assert.equal(isRepoConfigured(REPO), true);
  assert.equal(tagFromReleaseLocation(`https://github.com/${REPO}/releases/tag/v1.4.0`), 'v1.4.0');
  assert.equal(bundleVersion(bundle('3.1.4')), '3.1.4');
});

test('placeholder repo is reported as not configured, without any request', async () => {
  _resetUpdateCache();
  const f = fakeFetch([]);
  const r = await checkForUpdate({ repo: 'OWNER/OryvexWorkerPanel', currentVersion: '1.2.0', fetchImpl: f });
  assert.equal(r.ok, true);
  assert.equal(r.configured, false);
  assert.equal(f.calls.length, 0);
});

test('API path: newer release with asset', async () => {
  _resetUpdateCache();
  const f = fakeFetch([[`/repos/${REPO}/releases/latest`, () => json(200, {
    tag_name: 'v1.3.0', html_url: 'https://github.com/x/releases/tag/v1.3.0', body: 'notes', published_at: '2026-11-01T00:00:00Z',
    assets: [{ name: 'worker-single-file.js', browser_download_url: 'https://dl/worker-single-file.js' }],
  })]]);
  const r = await checkForUpdate({ repo: REPO, currentVersion: '1.2.0', fetchImpl: f });
  assert.equal(r.updateAvailable, true);
  assert.equal(r.latestVersion, '1.3.0');
  assert.equal(r.scriptUrl, 'https://dl/worker-single-file.js');
  assert.equal(r.source, 'api');
});

test('rate-limited API falls back to the github.com redirect', async () => {
  _resetUpdateCache();
  const f = fakeFetch([
    ['/releases/latest', (init) => (init.method === 'HEAD' ? redirect(`https://github.com/${REPO}/releases/tag/v1.2.0`) : json(403, { message: 'rate limit' }))],
  ]);
  const r = await checkForUpdate({ repo: REPO, currentVersion: '1.2.0', fetchImpl: f });
  assert.equal(r.ok, true);
  assert.equal(r.source, 'web');
  assert.equal(r.updateAvailable, false);
  assert.match(r.scriptUrl, /releases\/download\/v1\.2\.0\/worker-single-file\.js$/);
});

test('no release yet is not an error and never "update available"', async () => {
  _resetUpdateCache();
  const f = fakeFetch([
    ['/releases/latest', (init) => (init.method === 'HEAD' ? redirect(`https://github.com/${REPO}/releases`) : json(404, {}))],
  ]);
  const r = await checkForUpdate({ repo: REPO, currentVersion: '1.2.0', fetchImpl: f });
  assert.equal(r.ok, true);
  assert.equal(r.notPublishedYet, true);
  assert.equal(r.updateAvailable, false);
});

test('network failure is a clear error and is cached briefly; force bypasses cache', async () => {
  _resetUpdateCache();
  const f = fakeFetch([['/releases/latest', () => { throw new Error('boom'); }]]);
  const r = await checkForUpdate({ repo: REPO, currentVersion: '1.2.0', fetchImpl: f });
  assert.equal(r.ok, false);
  assert.match(r.error, /Could not reach GitHub/);
  const n = f.calls.length;
  await checkForUpdate({ repo: REPO, currentVersion: '1.2.0', fetchImpl: f });
  assert.equal(f.calls.length, n, 'second call served from cache');
  await checkForUpdate({ repo: REPO, currentVersion: '1.2.0', fetchImpl: f, force: true });
  assert.ok(f.calls.length > n, 'force re-checks');
});

test('download validates the bundle version against the tag', async () => {
  const info = { repo: REPO, tag: 'v1.3.0', latestVersion: '1.3.0', currentVersion: '1.2.0', scriptUrl: 'https://dl/w.js' };
  const good = await downloadReleaseBundle({ info, fetchImpl: fakeFetch([['dl/w.js', () => new Response(bundle('1.3.0'))]]) });
  assert.equal(good.ok, true);
  assert.equal(good.version, '1.3.0');
  const wrong = await downloadReleaseBundle({ info, fetchImpl: fakeFetch([['dl/w.js', () => new Response(bundle('1.1.0'))]]) });
  assert.equal(wrong.ok, false);
  const junk = await downloadReleaseBundle({ info, fetchImpl: fakeFetch([['dl/w.js', () => new Response('<html>404</html>')]]) });
  assert.equal(junk.ok, false);
});
