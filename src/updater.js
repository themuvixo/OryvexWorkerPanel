/**
 * OryvexWorkerPanel: release-based update check.
 *
 * Source of truth is the GitHub *Release* of the repository the Worker was built from
 * (injected at build time). The Release workflow attaches `worker-single-file.js` to every
 * `vX.Y.Z` tag, so a Release is the only place a deployable bundle actually exists.
 *
 * Why not `main/package.json` any more: `worker-single-file.js` is git-ignored, so a version
 * bump on `main` used to show "update available" for a file that could never be downloaded.
 *
 * Resolution order (first hit wins):
 *   1. api.github.com/repos/<repo>/releases/latest      (rich: notes, date, asset URL)
 *      Authenticated when a GITHUB_TOKEN / GH_TOKEN secret is bound (5000 req/h instead of 60).
 *   2. github.com/<repo>/releases/latest  302 -> /releases/tag/<tag>
 *      Not API rate-limited, so it keeps working when the shared Cloudflare egress IP is throttled.
 * The bundle is then fetched from github.com/<repo>/releases/download/<tag>/worker-single-file.js.
 */

export const UPDATE_ASSET_NAME = 'worker-single-file.js';
const CACHE_TTL_MS = 10 * 60 * 1000;
const FAIL_TTL_MS = 60 * 1000;
let memo = null; // { key, at, ttl, value }

export function normalizeVersionString(v) {
  const m = String(v || '').trim().match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return '';
  return `${parseInt(m[1], 10)}.${parseInt(m[2] || '0', 10)}.${parseInt(m[3] || '0', 10)}`;
}

/** 1 when a > b, -1 when a < b, 0 when equal. Pre-release suffixes are ignored. */
export function compareSemver(a, b) {
  const pa = normalizeVersionString(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = normalizeVersionString(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

export function isRepoConfigured(repo) {
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(repo || '')) && !/^OWNER\//i.test(String(repo));
}

/** Pulls the tag out of `/owner/repo/releases/tag/<tag>` (absolute or relative). */
export function tagFromReleaseLocation(location) {
  const m = String(location || '').match(/\/releases\/tag\/([^/?#]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

/** Reads the version stamped on line 1 of a built bundle: `// OryvexWorkerPanel v1.2.3 · ...`. */
export function bundleVersion(code) {
  const m = String(code || '').slice(0, 300).match(/OryvexWorkerPanel v(\d+\.\d+\.\d+)/);
  return m ? m[1] : '';
}

export function looksLikeWorkerBundle(code) {
  const s = String(code || '');
  return s.length > 15000 && /\bexport\s*(default|\{)/.test(s);
}

async function getWithTimeout(fetchImpl, url, init, timeoutMs) {
  const ctrl = new AbortController();
  const tid = setTimeout(() => {
    try { ctrl.abort(); } catch {}
  }, timeoutMs);
  try {
    const res = await fetchImpl(url, { ...init, signal: ctrl.signal });
    return { res, error: '' };
  } catch (err) {
    return { res: null, error: err?.name === 'AbortError' ? 'timeout' : err?.message || String(err) };
  } finally {
    clearTimeout(tid);
  }
}

function ghToken(env) {
  return String(env?.GITHUB_TOKEN || env?.GH_TOKEN || '').trim();
}

/**
 * @param {object} o
 * @param {string} o.repo            owner/name injected at build time
 * @param {string} o.currentVersion  version of the running Worker
 * @param {object} [o.env]           Worker env (NL_GH_API_BASE / NL_GH_WEB_BASE overrides for tests, GITHUB_TOKEN)
 * @param {boolean} [o.force]        bypass the 10-minute cache
 * @param {Function} [o.fetchImpl]
 */
export async function checkForUpdate({ repo, currentVersion, env = {}, force = false, fetchImpl = fetch }) {
  const repoUrl = `https://github.com/${repo}`;
  const base = { repo, repoUrl, currentVersion, releasesUrl: `${repoUrl}/releases` };

  if (!isRepoConfigured(repo)) {
    return {
      ok: true,
      ...base,
      configured: false,
      latestVersion: '',
      updateAvailable: false,
      message:
        'This build has no update repository. Build it in GitHub Actions (set automatically) or set ORYVEX_UPDATE_REPO=owner/repo.',
    };
  }

  const key = `${repo}@${currentVersion}`;
  if (!force && memo && memo.key === key && Date.now() - memo.at < memo.ttl) {
    return { ...memo.value, cached: true };
  }

  const apiBase = String(env.NL_GH_API_BASE || 'https://api.github.com').replace(/\/+$/, '');
  const webBase = String(env.NL_GH_WEB_BASE || 'https://github.com').replace(/\/+$/, '');
  const ua = `OryvexWorkerPanel-Updater/${currentVersion}`;
  const apiHeaders = { accept: 'application/vnd.github+json', 'user-agent': ua, 'x-github-api-version': '2022-11-28' };
  const tok = ghToken(env);
  if (tok) apiHeaders.authorization = `Bearer ${tok}`;

  let tag = '';
  let releaseUrl = '';
  let releaseNotes = '';
  let publishedAt = '';
  let assetUrl = '';
  let source = '';
  let noRelease = false;
  let lastError = '';

  // 1) REST API
  const api = await getWithTimeout(fetchImpl, `${apiBase}/repos/${repo}/releases/latest`, { headers: apiHeaders }, 9000);
  if (api.res && api.res.ok) {
    const data = await api.res.json().catch(() => null);
    if (data && data.tag_name) {
      tag = String(data.tag_name).trim();
      releaseUrl = String(data.html_url || '');
      releaseNotes = String(data.body || '').slice(0, 4000);
      publishedAt = String(data.published_at || '');
      const asset = Array.isArray(data.assets) ? data.assets.find((a) => a && a.name === UPDATE_ASSET_NAME) : null;
      if (asset && asset.browser_download_url) assetUrl = String(asset.browser_download_url);
      source = 'api';
    }
  } else if (api.res && api.res.status === 404) {
    // Either no release yet, or the repo is private / renamed. The web fallback tells them apart.
    noRelease = true;
  } else {
    lastError = api.res ? `GitHub API HTTP ${api.res.status}` : `GitHub API ${api.error}`;
  }

  // 2) Web redirect fallback (rate-limit proof)
  if (!tag) {
    const web = await getWithTimeout(
      fetchImpl,
      `${webBase}/${repo}/releases/latest`,
      { method: 'HEAD', redirect: 'manual', headers: { 'user-agent': ua } },
      8000
    );
    const loc = web.res ? web.res.headers.get('location') || '' : '';
    const t = tagFromReleaseLocation(loc) || (web.res ? tagFromReleaseLocation(web.res.url) : '');
    if (t) {
      tag = t;
      noRelease = false;
      releaseUrl = `${repoUrl}/releases/tag/${encodeURIComponent(t)}`;
      source = 'web';
    } else if (web.res && (web.res.status === 404 || /\/releases\/?$/.test(loc))) {
      // github.com redirects /releases/latest -> /releases when nothing is published.
      noRelease = true;
    } else if (!lastError) {
      lastError = web.res ? `github.com HTTP ${web.res.status}` : `github.com ${web.error}`;
    }
  }

  let value;
  if (tag) {
    const latestVersion = normalizeVersionString(tag);
    if (!assetUrl) assetUrl = `${webBase}/${repo}/releases/download/${encodeURIComponent(tag)}/${UPDATE_ASSET_NAME}`;
    value = {
      ok: true,
      ...base,
      configured: true,
      tag,
      latestVersion,
      updateAvailable: compareSemver(latestVersion, currentVersion) > 0,
      aheadOfRelease: compareSemver(currentVersion, latestVersion) > 0,
      releaseUrl: releaseUrl || `${repoUrl}/releases/tag/${encodeURIComponent(tag)}`,
      releaseNotes,
      publishedAt,
      scriptUrl: assetUrl,
      source,
      checkedAt: Date.now(),
    };
  } else if (noRelease) {
    value = {
      ok: true,
      ...base,
      configured: true,
      notPublishedYet: true,
      latestVersion: '',
      updateAvailable: false,
      releaseUrl: `${repoUrl}/releases`,
      releaseNotes: '',
      publishedAt: '',
      scriptUrl: '',
      message: `No release has been published in ${repo} yet. Push to main and the Release workflow tags one.`,
      checkedAt: Date.now(),
    };
  } else {
    value = {
      ok: false,
      ...base,
      configured: true,
      error: `Could not reach GitHub to check for updates (${lastError || 'unknown error'}). Try again in a minute.`,
      checkedAt: Date.now(),
    };
  }

  memo = { key, at: Date.now(), ttl: value.ok ? CACHE_TTL_MS : FAIL_TTL_MS, value };
  return value;
}

/** Downloads and validates the release bundle. Returns { ok, code, version } or { ok:false, error }. */
export async function downloadReleaseBundle({ info, env = {}, fetchImpl = fetch }) {
  const urls = [info.scriptUrl].filter(Boolean);
  const ua = `OryvexWorkerPanel-Updater/${info.currentVersion}`;
  for (const url of urls) {
    const r = await getWithTimeout(fetchImpl, url, { headers: { 'user-agent': ua }, redirect: 'follow' }, 20000);
    if (!r.res || !r.res.ok) continue;
    const code = await r.res.text().catch(() => '');
    if (!looksLikeWorkerBundle(code)) continue;
    const v = bundleVersion(code);
    if (v && info.latestVersion && compareSemver(v, info.latestVersion) !== 0) {
      return { ok: false, error: `Release ${info.tag} ships a v${v} bundle, expected v${info.latestVersion}. Re-run the Release workflow.` };
    }
    return { ok: true, code, version: v || info.latestVersion };
  }
  return {
    ok: false,
    error: `${UPDATE_ASSET_NAME} is not attached to release ${info.tag || '(none)'} in ${info.repo}. Re-run the Release workflow.`,
  };
}

export function _resetUpdateCache() {
  memo = null;
}
