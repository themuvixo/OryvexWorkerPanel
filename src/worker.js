/**
 * OryvexWorkerPanel: Cloudflare Worker & Pages entrypoint (Free-plan CPU optimized).
 */

import {
  hashPassword,
  PBKDF2_DEFAULT_ITER,
  randomPassword,
  randomToken,
  randomUUID,
  safeDecodeURIComponent,
  safeJsonParse,
  signSession,
  verifyPassword,
  verifySession,
} from './crypto.js';
import {
  appendLog,
  checkLoginRateLimit,
  clearLoginFailures,
  clearPendingUsage,
  enrichUserView,
  GITHUB_REPO,
  GITHUB_REPO_URL,
  initializePanelState,
  loadRuntimeState,
  normalizeUser,
  PANEL_BRAND,
  PANEL_VERSION,
  recordLoginFailure,
  sanitizeSettings,
  saveRuntimeState,
} from './storage.js';
import {
  handlePrivateDoH,
  handleTunnelWS,
  handleTunnelXHTTP,
  isXhttpPath,
  probeOutboundEndpoint,
} from './protocols.js';
import {
  buildTgProxyLinks,
  generateTgSecret,
  handleTgSessionApi,
  handleTgWebSocket,
  maybeHandleTgBridgePage,
} from './tgproxy.js';
import {
  buildClashYaml,
  buildNodeDescriptors,
  buildSingboxConfig,
  buildXrayConfigs,
  computeQuickUserNodeMeta,
  renderDecoyGazette,
  serveSubscription,
} from './sub.js';
import { getInlineAssets, getPanelHtml } from './generated/ui.js';
import { detectStrayKvBindings, errorResponse, wantsHtml } from './errors.js';
import { checkForUpdate, downloadReleaseBundle } from './updater.js';

/* global __ORYVEX_DOCS_URL__ */
const DOCS_URL = typeof __ORYVEX_DOCS_URL__ === 'string' ? __ORYVEX_DOCS_URL__ : '';

const SESSION_COOKIE = 'nl_sess';
const SESSION_TTL_MS = 7 * 86_400_000;
const MAX_JSON_BODY_BYTES = 2 * 1024 * 1024;
const CF_IP_RANGES_URL = 'https://api.cloudflare.com/client/v4/ips';
let cfIpRangesCache = null;
const FAVICON_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" fill="#141311"/><rect x="4" y="4" width="56" height="56" fill="none" stroke="#f2ede3" stroke-width="2"/><text x="32" y="45" text-anchor="middle" font-family="monospace" font-weight="700" font-size="36" fill="#f2ede3">N</text></svg>';

function extractColo(request) {
  const direct = request.cf && request.cf.colo ? String(request.cf.colo).trim() : '';
  if (direct && direct.toUpperCase() !== 'EDGE') return direct.toUpperCase();
  const ray = request.headers.get('cf-ray') || '';
  const dash = ray.lastIndexOf('-');
  if (dash > 0 && ray.length - dash <= 5) {
    const code = ray.slice(dash + 1).trim().toUpperCase();
    if (/^[A-Z]{3}$/.test(code)) return code;
  }
  return 'CF-GLOBAL';
}

const ISP_FRIENDLY_MAP = [
  [/mobile communication company of iran|mci\b|hamrah/i, 'MCI (Hamrah-e Aval)', 'MCI (Hamrah-e Aval)'],
  [/irancell|mtn irancell/i, 'MTN Irancell', 'MTN Irancell'],
  [/iran telecommunication|tci\b|mokhaberat/i, 'TCI (Mokhaberat)', 'TCI (Mokhaberat)'],
  [/rightel|tamin telecom/i, 'Rightel', 'Rightel'],
  [/aria shatel|shatel/i, 'Shatel', 'Shatel'],
  [/asiatech/i, 'Asiatech', 'Asiatech'],
  [/mobinnet/i, 'Mobinnet', 'Mobinnet'],
  [/hiweb|danehe|novin net/i, 'HiWEB', 'HiWEB'],
  [/pars online|parsonline/i, 'ParsOnline', 'ParsOnline'],
  [/zitel/i, 'Zitel', 'Zitel'],
  [/pishgaman/i, 'Pishgaman', 'Pishgaman'],
  [/afranet/i, 'Afranet', 'Afranet'],
  [/respina/i, 'Respina', 'Respina'],
  [/fanava/i, 'Fanava', 'Fanava'],
  [/aptel|samantel|lotustel/i, 'Iran MVNO', 'Iran MVNO'],
];

function classifyIsp(rawOrg = '', asn = '') {
  const org = String(rawOrg || '').trim();
  for (const [rx, fa, en] of ISP_FRIENDLY_MAP) {
    if (rx.test(org)) return { fa, en, isIranIsp: true };
  }
  if (org) {
    return { fa: org, en: org, isIranIsp: false };
  }
  if (asn) {
    return { fa: `AS${asn}`, en: `AS${asn}`, isIranIsp: false };
  }
  return { fa: 'Local / Direct Network', en: 'Local / Direct Network', isIranIsp: false };
}

const COUNTRY_MAP = {
  IR: ['Iran', 'Iran'],
  NL: ['Netherlands', 'Netherlands'],
  DE: ['Germany', 'Germany'],
  US: ['United States', 'United States'],
  GB: ['United Kingdom', 'United Kingdom'],
  FR: ['France', 'France'],
  TR: ['Turkey', 'Turkey'],
  AE: ['UAE', 'UAE'],
  FI: ['Finland', 'Finland'],
  SE: ['Sweden', 'Sweden'],
  CA: ['Canada', 'Canada'],
  SG: ['Singapore', 'Singapore'],
  JP: ['Japan', 'Japan'],
  RU: ['Russia', 'Russia'],
  CN: ['China', 'China'],
};

function extractClientInfo(request, url) {
  const cf = request.cf || {};
  const rawIp =
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-real-ip') ||
    (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() ||
    '127.0.0.1';
  const hdrCountry = String(request.headers.get('cf-ipcountry') || '').trim().toUpperCase();
  const isLoopback = rawIp === '127.0.0.1' || rawIp === '::1';
  const country = hdrCountry || (isLoopback ? 'XX' : String(cf.country || 'XX').trim().toUpperCase());
  const cNames = COUNTRY_MAP[country] || [country === 'XX' ? 'Local' : country, country === 'XX' ? 'Local' : country];
  const city = isLoopback && !hdrCountry ? '' : String(cf.city || '').trim();
  const region = isLoopback && !hdrCountry ? '' : String(cf.region || '').trim();
  const asnNum = isLoopback && !hdrCountry ? 0 : (Number(cf.asn) || 0);
  const asOrg = isLoopback && !hdrCountry ? '' : String(cf.asOrganization || '').trim();
  const isp = classifyIsp(asOrg, asnNum ? String(asnNum) : '');
  return {
    host: url.host,
    origin: url.origin,
    colo: extractColo(request),
    clientIp: rawIp,
    country,
    countryNameFa: cNames[0],
    countryNameEn: cNames[1],
    city,
    region,
    asn: asnNum,
    ispRaw: asOrg,
    asOrganization: asOrg,
    ispFa: isp.fa,
    ispEn: isp.en,
    isIranIsp: isp.isIranIsp || country === 'IR',
    httpProtocol: cf.httpProtocol || 'HTTP/2',
    tlsVersion: cf.tlsVersion || 'TLSv1.3',
  };
}

/* Error and DoH guide pages share the panel's embedded fonts (no network fetches). */
let fontFaceCssCache = null;
async function sharedFontFaceCss() {
  if (fontFaceCssCache !== null) return fontFaceCssCache;
  try {
    const assets = await getInlineAssets();
    const blocks = String(assets.style || '').match(/@font-face\{[^}]*\}/g) || [];
    fontFaceCssCache = blocks.join('');
  } catch {
    fontFaceCssCache = '';
  }
  return fontFaceCssCache;
}

async function withSharedFonts(responseOrPromise) {
  const res = await responseOrPromise;
  try {
    const type = (res && res.headers && res.headers.get('content-type')) || '';
    if (!type.includes('text/html') || res.status === 101) return res;
    const body = await res.text();
    if (!body.includes('/*__OX_FONTS__*/')) {
      return new Response(body, { status: res.status, statusText: res.statusText, headers: res.headers });
    }
    const fonts = await sharedFontFaceCss();
    return new Response(body.replace('/*__OX_FONTS__*/', () => fonts), {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
    });
  } catch {
    return res;
  }
}

let speedBuf64K = null;
function getSpeedBuffer(byteLen) {
  if (!speedBuf64K) {
    speedBuf64K = new Uint8Array(65536);
    for (let i = 0; i < 65536; i++) speedBuf64K[i] = (i * 73 + 19) & 0xff;
  }
  const clamped = Math.max(1024, Math.min(262144, Number(byteLen) || 32768));
  if (clamped <= 65536) return speedBuf64K.subarray(0, clamped);
  const out = new Uint8Array(clamped);
  for (let off = 0; off < clamped; off += 65536) {
    const slice = speedBuf64K.subarray(0, Math.min(65536, clamped - off));
    out.set(slice, off);
  }
  return out;
}

export default {
  async fetch(request, env = {}, ctx = {}) {
    try {
      const url = new URL(request.url);
      const path = url.pathname || '/';
      const upgradeHeader = (request.headers.get('upgrade') || '').toLowerCase();

      // 0) Fast zero-KV favicon response
      if (upgradeHeader !== 'websocket' && path === '/favicon.ico') {
        return new Response(FAVICON_SVG, {
          status: 200,
          headers: {
            'content-type': 'image/svg+xml; charset=utf-8',
            'cache-control': 'public, max-age=86400',
          },
        });
      }

      const runtime = await loadRuntimeState(env);

      // 0b) Hosted setup error: no KV namespace and no stateless UUID configured
      if (
        !runtime.kvBound &&
        !runtime.envUuid &&
        upgradeHeader !== 'websocket' &&
        wantsHtml(request) &&
        path !== '/health' &&
        !path.startsWith('/api/')
      ) {
        const stray = detectStrayKvBindings(env);
        return withSharedFonts(errorResponse(request, 'KV_MISSING', {
          host: url.host,
          version: PANEL_VERSION,
          docsUrl: DOCS_URL ? `${DOCS_URL}troubleshooting.html#kv-missing` : '',
          facts: [['Bindings found', stray.length ? stray.join(', ') : 'none']],
          extraNote: stray.length
            ? `A KV namespace is bound as <code>${stray[0].replace(/[^\w-]/g, '')}</code>. Rename that binding to <code>KV</code> and redeploy.`
            : '',
        }));
      }

      // 1) WebSocket Upgrade: Official Telegram Web Proxy (`/api/v1/ws`) OR VLESS/Trojan Tunnel
      if (upgradeHeader === 'websocket') {
        const wsProto = request.headers.get('sec-websocket-protocol') || '';
        if (path === '/api/v1/ws' && wsProto.includes('tproxy-lane-v1.')) {
          return await handleTgWebSocket(request, url, runtime.settings);
        }
        return await handleTunnelWS(request, env, ctx, runtime);
      }

      // 1a) XHTTP (stream-one) tunnel: a long-lived POST on the configured XHTTP path
      if (
        request.method === 'POST' &&
        runtime.settings?.enableXhttp &&
        isXhttpPath(path, runtime.settings.xhttpPath)
      ) {
        return await handleTunnelXHTTP(request, env, ctx, runtime);
      }

      // 1b) Official Telegram Web Proxy HTTP Bridge & Session Lease endpoints
      if (path === '/api/v1/session') {
        return await handleTgSessionApi(request, runtime.settings);
      }
      if (path === '/' && url.search.startsWith('?bridge=')) {
        const tgBridge = await maybeHandleTgBridgePage(request, url, runtime.settings);
        if (tgBridge) return tgBridge;
      }

      // 2) Health probe (`/health` & `/api/ping`)
      if (path === '/api/ping' || path === '/health') {
        return json(
          {
            ok: true,
            version: PANEL_VERSION,
            kvBound: runtime.kvBound,
            initialized: runtime.initialized,
            ts: Date.now(),
            colo: extractColo(request),
            country: request.cf?.country || '',
          },
          200,
          { 'access-control-allow-origin': '*' }
        );
      }

      // 3) Admin Panel REST API
      if (path.startsWith('/api/')) {
        return await handleApi(request, url, env, runtime);
      }

      // 4) Private DoH endpoint: /dns-query/:subToken
      if (path.startsWith('/dns-query/')) {
        const token = safeDecodeURIComponent(path.slice('/dns-query/'.length).split('/')[0], '').trim();
        const matched = findActiveTokenUser(runtime, token);
        if (!matched) {
          return new Response('Forbidden DoH token', { status: 403 });
        }
        return await withSharedFonts(handlePrivateDoH(request, runtime.settings.upstreamDoH));
      }

      // 5) Subscription endpoints: /sub/:token  OR /sub?uuid=...
      if (path === '/sub' || path.startsWith('/sub/')) {
        const rawTok = path.startsWith('/sub/')
          ? path.slice('/sub/'.length).split('/')[0]
          : (url.searchParams.get('token') || url.searchParams.get('uuid') || '');
        const token = safeDecodeURIComponent(rawTok, '').trim();
        const matched = findSubscriptionUser(runtime, token);
        if (!matched) {
          if (wantsHtml(request)) {
            return withSharedFonts(errorResponse(request, 'SUB_NOT_FOUND', { host: url.host, version: PANEL_VERSION }));
          }
          return json({ ok: false, error: 'This subscription link is invalid or has expired.' }, 404);
        }
        return await serveSubscription(request, matched, runtime.settings, await getInlineAssets());
      }

      // 6) Explicit Admin Panel route (/panel)
      if (path === '/panel' || path === '/panel/') {
        return await servePanelShell(request, env);
      }

      // 7) Camouflage / Root mode handling on `/`
      if (path === '/' && runtime.initialized) {
        if (runtime.settings.rootMode === 'gazette') {
          return new Response(renderDecoyGazette(await getInlineAssets()), {
            status: 200,
            headers: { 'content-type': 'text/html; charset=utf-8' },
          });
        }
        if (runtime.settings.fallbackDomain) {
          if (runtime.settings.rootMode === 'fallback') {
            return await proxyFallbackDomain(request, runtime.settings.fallbackDomain, await getInlineAssets());
          }
        }
      }

      // 8) Fallback reverse-proxy for non-panel paths when fallbackDomain is configured
      if (
        runtime.initialized &&
        runtime.settings.rootMode === 'fallback' &&
        runtime.settings.fallbackDomain &&
        !path.startsWith('/panel')
      ) {
        return await proxyFallbackDomain(request, runtime.settings.fallbackDomain, await getInlineAssets());
      }

      // 9) Default: serve Admin Panel UI
      return await servePanelShell(request, env);
    } catch (err) {
      const detail = err && err.message ? err.message : String(err);
      const isKv = /\bKV\b|kv namespace|storage/i.test(detail);
      let host = '';
      try { host = new URL(request.url).host; } catch {}
      if (wantsHtml(request)) {
        return withSharedFonts(errorResponse(request, isKv ? 'KV_UNAVAILABLE' : 'INTERNAL', {
          host,
          version: PANEL_VERSION,
          detail,
          docsUrl: DOCS_URL ? `${DOCS_URL}troubleshooting.html` : '',
        }));
      }
      return json(
        {
          ok: false,
          code: isKv ? 'E_KV_UNAVAILABLE' : 'E_INTERNAL',
          error: 'Internal server error. The request was stopped safely.',
          detail,
        },
        500
      );
    }
  },
};

/* --------------------------------------------------------- REST API Router */

async function handleApi(request, url, env, runtime) {
  const path = url.pathname;
  const method = request.method.toUpperCase();
  const cfInfo = extractClientInfo(request, url);
  const clientIp = cfInfo.clientIp;

  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'access-control-allow-origin': url.origin,
        'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'access-control-allow-headers': 'content-type',
      },
    });
  }

  // ---- GET /api/client-info ----
  if (path === '/api/client-info' && method === 'GET') {
    return json({ ok: true, cf: cfInfo, ts: Date.now() }, 200, { 'access-control-allow-origin': '*' });
  }

  // ---- GET /api/speed-probe ----
  if (path === '/api/speed-probe' && method === 'GET') {
    const reqBytes = Number(url.searchParams.get('bytes')) || 32768;
    const payload = getSpeedBuffer(reqBytes);
    return new Response(payload, {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'cache-control': 'no-store, no-transform',
        'content-length': String(payload.byteLength),
        'access-control-allow-origin': '*',
      },
    });
  }

  // ---- POST /api/speed-probe (bounded same-origin upload observation) ----
  if (path === '/api/speed-probe' && method === 'POST') {
    const maxBytes = 131072;
    const declared = Number(request.headers.get('content-length') || 0);
    if (declared > maxBytes) return json({ ok: false, error: 'Probe too large' }, 413);
    const reader = request.body?.getReader();
    if (!reader) return json({ ok: false, error: 'Empty upload probe' }, 400);
    let received = 0;
    try {
      while (received <= maxBytes) {
        const { value, done } = await reader.read();
        if (done) return json({ ok: true, receivedBytes: received });
        received += value?.byteLength || 0;
      }
      await reader.cancel();
      return json({ ok: false, error: 'Probe too large' }, 413);
    } catch {
      return json({ ok: false, error: 'Upload probe failed' }, 400);
    } finally {
      try { reader.releaseLock(); } catch {}
    }
  }

  // ---- GET /api/bootstrap ----
  if (path === '/api/bootstrap' && method === 'GET') {
    const authed = await isAuthenticated(request, runtime);

    if (!runtime.kvBound) {
      return json({
        ok: true,
        version: PANEL_VERSION,
        state: runtime.initialized ? 'stateless' : 'needs_kv',
        mode: 'stateless',
        kvBound: false,
        hasEnvUuid: Boolean(runtime.envUuid),
        authenticated: false,
        host: url.host,
        edge: cfInfo.colo,
        cf: cfInfo,
        tgProxy:
          runtime.settings.enableTgProxy !== false
            ? buildTgProxyLinks(url.host, runtime.settings.tgProxySecret, runtime.settings.tgProxyDomain)
            : null,
        statelessUser: runtime.users[0]
          ? buildAdminUserSummary(runtime.users[0], runtime.settings, url.host)
          : null,
      });
    }

    if (!runtime.initialized) {
      return json({
        ok: true,
        version: PANEL_VERSION,
        state: 'needs_setup',
        mode: 'setup',
        kvBound: true,
        kvName: runtime.kvName,
        authenticated: false,
        host: url.host,
        edge: cfInfo.colo,
        cf: cfInfo,
      });
    }

    if (!authed) {
      return json({
        ok: true,
        version: PANEL_VERSION,
        state: 'locked',
        mode: 'login',
        kvBound: true,
        kvName: runtime.kvName,
        authenticated: false,
        host: url.host,
        edge: cfInfo.colo,
        cf: cfInfo,
      });
    }

    const fresh = await loadRuntimeState(env, true);
    return json(buildFullAdminPayload(fresh, url.host, cfInfo));
  }

  // ---- POST /api/setup ----
  if (path === '/api/setup' && method === 'POST') {
    if (!runtime.kvBound) {
      return json(
        {
          ok: false,
          error: 'Bind a KV namespace named KV first (Worker Settings → Bindings).',
        },
        400
      );
    }
    if (runtime.initialized) {
      return json({ ok: false, error: 'The panel is already set up. Please sign in.' }, 403);
    }

    const body = await readJsonBody(request);
    if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);

    const password = String(body.password || '');
    if (password.length < 6) {
      return json({ ok: false, error: 'The admin password must be at least 6 characters.' }, 400);
    }

    const created = await initializePanelState(env, {
      password,
      firstUserName: body.firstUserName || 'Primary admin',
      preferredUuid: body.preferredUuid || body.uuid || '',
    });

    const token = await signSession(
      { sub: 'admin', ver: created.auth.ver, exp: Date.now() + SESSION_TTL_MS },
      created.auth.secret
    );

    return json(buildFullAdminPayload(created, url.host, cfInfo), 200, {
      'set-cookie': formatSessionCookie(token, url.protocol === 'https:'),
    });
  }

  // ---- POST /api/login ----
  if (path === '/api/login' && method === 'POST') {
    if (!runtime.initialized || !runtime.auth) {
      return json({ ok: false, error: 'The panel has not been set up yet.' }, 400);
    }

    const limit = checkLoginRateLimit(clientIp);
    if (!limit.allowed) {
      return json(
        { ok: false, error: `Too many failed attempts. Wait ${limit.retrySec} seconds and try again.` },
        429
      );
    }

    const body = await readJsonBody(request);
    if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);

    const rawPw = String(body.password || '');
    const valid = await verifyPassword(rawPw, runtime.auth);
    if (!valid) {
      recordLoginFailure(clientIp);
      return json({ ok: false, error: 'Incorrect password.' }, 401);
    }

    clearLoginFailures(clientIp);
    let fresh = await loadRuntimeState(env, true);

    // Auto-migrate legacy high-iteration PBKDF2 records down to Free-Tier-safe 10,000 iterations
    if ((fresh.auth?.iter || 0) > PBKDF2_DEFAULT_ITER) {
      const upgraded = await hashPassword(rawPw, null, PBKDF2_DEFAULT_ITER);
      fresh.auth = { ...fresh.auth, ...upgraded };
      fresh = await saveRuntimeState(env, fresh);
    }

    const token = await signSession(
      { sub: 'admin', ver: fresh.auth.ver, exp: Date.now() + SESSION_TTL_MS },
      fresh.auth.secret
    );

    return json(buildFullAdminPayload(fresh, url.host, cfInfo), 200, {
      'set-cookie': formatSessionCookie(token, url.protocol === 'https:'),
    });
  }

  // ---- POST /api/logout ----
  if (path === '/api/logout' && method === 'POST') {
    return json({ ok: true }, 200, {
      'set-cookie': `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`,
    });
  }

  // =========================================================================
  // Authenticated admin endpoints below
  // =========================================================================
  if (!(await isAuthenticated(request, runtime))) {
    return json({ ok: false, error: 'Your admin session expired or you are not signed in.' }, 401);
  }

  const state = await loadRuntimeState(env, true);

  // ---- GET /api/cf/ip-ranges: official public Cloudflare CIDRs, no CF token ----
  if (path === '/api/cf/ip-ranges' && method === 'GET') {
    if (cfIpRangesCache && Date.now() - cfIpRangesCache.fetchedAt < 6 * 3600_000) {
      return json({ ok: true, ...cfIpRangesCache, cached: true });
    }
    // Only the local E2E harness sets this override; production uses Cloudflare's public API.
    const feedUrl = env?.NL_CF_IP_RANGES_TEST_URL || CF_IP_RANGES_URL;
    const upstream = await fetchJsonWithTimeout(feedUrl, {}, 6500);
    const raw = upstream.data?.result;
    const ipv4 = Array.isArray(raw?.ipv4_cidrs) ? raw.ipv4_cidrs.filter((cidr) => {
      const parts = String(cidr).split('/');
      const bytes = parts[0].split('.').map(Number);
      return parts.length === 2 && bytes.length === 4 && bytes.every((x) => Number.isInteger(x) && x >= 0 && x < 256) &&
        /^(?:[0-9]|[12][0-9]|3[0-2])$/.test(parts[1]);
    }).slice(0, 48) : [];
    const ipv6 = Array.isArray(raw?.ipv6_cidrs) ? raw.ipv6_cidrs.filter((cidr) =>
      /^[0-9a-f:]+\/(?:\d{1,2}|1[01]\d|12[0-8])$/i.test(String(cidr)) && String(cidr).includes(':')
    ).slice(0, 32) : [];
    if (!upstream.ok || upstream.data?.success !== true || !ipv4.length || !ipv6.length) {
      if (cfIpRangesCache) return json({ ok: true, ...cfIpRangesCache, cached: true, stale: true });
      return json({ ok: false, error: 'The official Cloudflare IP range source is unavailable. No guessed ranges were substituted.' }, 502);
    }
    cfIpRangesCache = { ipv4, ipv6, source: feedUrl, etag: String(raw.etag || ''), fetchedAt: Date.now() };
    return json({ ok: true, ...cfIpRangesCache, cached: false });
  }

  // ---- POST /api/killswitch ----
  if (path === '/api/killswitch' && method === 'POST') {
    const body = await readJsonBody(request);
    const nextKill =
      !body.__parseError && typeof body.killSwitch === 'boolean'
        ? body.killSwitch
        : !state.settings.killSwitch;
    state.settings = sanitizeSettings(
      { ...state.settings, killSwitch: nextKill },
      state.settings
    );
    appendLog(
      state,
      'killswitch',
      state.settings.killSwitch ? 'Kill switch enabled' : 'Kill switch disabled'
    );
    const saved = await saveRuntimeState(env, state);
    return json(buildFullAdminPayload(saved, url.host, cfInfo));
  }

  // ---- PUT /api/settings ----
  if (path === '/api/settings' && (method === 'PUT' || method === 'POST')) {
    const patch = await readJsonBody(request);
    if (patch.__parseError) return json({ ok: false, error: patch.__parseError }, 400);

    state.settings = sanitizeSettings(patch, state.settings);
    appendLog(state, 'settings', 'Core and routing settings updated');
    const saved = await saveRuntimeState(env, state);
    return json(buildFullAdminPayload(saved, url.host, cfInfo));
  }

  // ---- POST /api/password ----
  if (path === '/api/password' && method === 'POST') {
    const body = await readJsonBody(request);
    if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);

    const currentOk = await verifyPassword(String(body.currentPassword || ''), state.auth);
    if (!currentOk) {
      return json({ ok: false, error: 'The current password is incorrect.' }, 400);
    }
    const nextPw = String(body.newPassword || '');
    if (nextPw.length < 6) {
      return json({ ok: false, error: 'The new password must be at least 6 characters.' }, 400);
    }
    const pwRec = await hashPassword(nextPw, null, PBKDF2_DEFAULT_ITER);
    state.auth = {
      ...state.auth,
      ...pwRec,
      ver: (state.auth.ver || 1) + 1,
      updatedAt: Date.now(),
    };
    appendLog(state, 'security', 'Admin password changed');
    const saved = await saveRuntimeState(env, state);
    const token = await signSession(
      { sub: 'admin', ver: saved.auth.ver, exp: Date.now() + SESSION_TTL_MS },
      saved.auth.secret
    );
    return json({ ok: true }, 200, {
      'set-cookie': formatSessionCookie(token, url.protocol === 'https:'),
    });
  }

  // ---- POST /api/users ----
  if (path === '/api/users' && method === 'POST') {
    if (state.users.length >= 200) {
      return json({ ok: false, error: 'A single Worker supports up to 200 subscribers.' }, 400);
    }
    const body = await readJsonBody(request);
    if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);

    const requestedUuid = String(body.uuid || '').trim().toLowerCase();
    const requestedTrojan = String(body.trojanPassword || '').trim();
    if (requestedUuid && state.users.some((u) => String(u.uuid || '').toLowerCase() === requestedUuid)) {
      return json({ ok: false, error: 'This UUID is already assigned to another subscriber.' }, 400);
    }
    if (requestedTrojan && state.users.some((u) => String(u.trojanPassword || '') === requestedTrojan)) {
      return json({ ok: false, error: 'This Trojan password is already assigned to another subscriber.' }, 400);
    }

    let candidateUuid = requestedUuid || randomUUID();
    while (state.users.some((u) => String(u.uuid || '').toLowerCase() === candidateUuid.toLowerCase())) {
      candidateUuid = randomUUID();
    }
    let candidateTrojan = requestedTrojan || randomPassword(14);
    while (state.users.some((u) => String(u.trojanPassword || '') === candidateTrojan)) {
      candidateTrojan = randomPassword(14);
    }
    let candidateSubToken = randomToken(16);
    while (state.users.some((u) => u.subToken === candidateSubToken)) {
      candidateSubToken = randomToken(16);
    }

    const newUser = normalizeUser({
      id: '',
      name: body.name || `Subscriber ${state.users.length + 1}`,
      note: body.note || '',
      uuid: candidateUuid,
      trojanPassword: candidateTrojan,
      subToken: candidateSubToken,
      trafficLimitGB: Number(body.trafficLimitGB || 0),
      usedUpBytes: 0,
      usedDownBytes: 0,
      connections: 0,
      firstConnectedAt: 0,
      lastSeenAt: 0,
      expiryDays: Number(body.expiryDays || 0),
      startOnFirstUse: Boolean(body.startOnFirstUse),
      enabled: body.enabled !== false,
    });
    clearPendingUsage(newUser.id);
    state.users = [...state.users, newUser];
    appendLog(state, 'user:add', `Subscriber created: ${newUser.name}`);
    const saved = await saveRuntimeState(env, state);
    return json({ ...buildFullAdminPayload(saved, url.host, cfInfo), createdId: newUser.id });
  }

  // ---- GET /api/users/:id/nodes ----
  const userNodesMatch = path.match(/^\/api\/users\/([^/]+)\/nodes$/);
  if (userNodesMatch && method === 'GET') {
    const uid = safeDecodeURIComponent(userNodesMatch[1], '');
    const target = state.users.find((u) => u.id === uid);
    if (!target) return json({ ok: false, error: 'Subscriber not found.' }, 404);
    const uView = enrichUserView(target);
    return json({
      ok: true,
      user: buildAdminUserSummary(target, state.settings, url.host),
      nodes: buildNodeDescriptors(uView, state.settings, url.host),
      xrayPreview: buildXrayConfigs(uView, state.settings, url.host)[0] || null,
      singboxPreview: buildSingboxConfig(uView, state.settings, url.host),
      clashPreview: buildClashYaml(uView, state.settings, url.host),
    });
  }

  // ---- PUT / DELETE / POST actions on /api/users/:id ----
  const userMatch = path.match(/^\/api\/users\/([^/]+)$/);
  if (userMatch) {
    const uid = safeDecodeURIComponent(userMatch[1], '');
    const idx = state.users.findIndex((u) => u.id === uid);
    if (idx === -1) return json({ ok: false, error: 'Subscriber not found.' }, 404);

    if (method === 'DELETE') {
      if (state.users.length <= 1) {
        return json({ ok: false, error: 'At least one subscriber must remain in the panel.' }, 400);
      }
      const nextUsers = [...state.users];
      const removed = nextUsers.splice(idx, 1)[0];
      clearPendingUsage(removed.id);
      state.users = nextUsers;
      appendLog(state, 'user:del', `Subscriber removed: ${removed.name}`);
      const saved = await saveRuntimeState(env, state);
      return json(buildFullAdminPayload(saved, url.host, cfInfo));
    }

    if (method === 'PUT' || method === 'POST') {
      const body = await readJsonBody(request);
      if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);

      const cur = { ...state.users[idx] };
      const nextUsers = [...state.users];
      const doReset = body.action === 'reset_traffic' || Boolean(body.resetTraffic);
      const doRotate = body.action === 'rotate_keys' || Boolean(body.rotateKeys);

      if (doReset) {
        clearPendingUsage(cur.id);
        cur.usedUpBytes = 0;
        cur.usedDownBytes = 0;
        cur.connections = 0;
        nextUsers[idx] = normalizeUser(cur, true);
        state.users = nextUsers;
        appendLog(state, 'user:reset', `Traffic usage reset: ${cur.name}`);
      } else if (doRotate) {
        cur.uuid = randomUUID();
        cur.trojanPassword = randomPassword(14);
        cur.subToken = randomToken(16);
        nextUsers[idx] = normalizeUser(cur);
        state.users = nextUsers;
        appendLog(state, 'user:rotate', `Credentials rotated: ${cur.name}`);
      } else {
        const nextUuid = String(body.uuid || cur.uuid || '').trim().toLowerCase();
        const nextTrojan = String(body.trojanPassword || cur.trojanPassword || '').trim();
        if (nextUuid && state.users.some((u, i) => i !== idx && String(u.uuid || '').toLowerCase() === nextUuid)) {
          return json({ ok: false, error: 'This UUID belongs to another subscriber.' }, 400);
        }
        if (nextTrojan && state.users.some((u, i) => i !== idx && String(u.trojanPassword || '') === nextTrojan)) {
          return json({ ok: false, error: 'This Trojan password belongs to another subscriber.' }, 400);
        }

        const expiryDays = body.expiryDays !== undefined ? Math.max(0, Number(body.expiryDays) || 0) : cur.expiryDays;
        const startOnFirstUse = body.startOnFirstUse !== undefined ? Boolean(body.startOnFirstUse) : cur.startOnFirstUse;
        let expiresAt = cur.expiresAt;

        if (body.expiryDays !== undefined || body.startOnFirstUse !== undefined) {
          if (expiryDays === 0) expiresAt = 0;
          else if (startOnFirstUse) expiresAt = 0;
          else expiresAt = Date.now() + expiryDays * 86_400_000;
        }

        const pwUnchanged = !body.trojanPassword || body.trojanPassword === cur.trojanPassword;
        nextUsers[idx] = normalizeUser(
          {
            ...cur,
            name: body.name !== undefined ? body.name : cur.name,
            note: body.note !== undefined ? body.note : cur.note,
            enabled: body.enabled !== undefined ? Boolean(body.enabled) : cur.enabled,
            uuid: body.uuid || cur.uuid,
            trojanPassword: body.trojanPassword || cur.trojanPassword,
            trafficLimitGB: body.trafficLimitGB !== undefined ? Number(body.trafficLimitGB) : cur.trafficLimitGB,
            expiryDays,
            startOnFirstUse,
            expiresAt,
            clearExpiry: expiryDays === 0,
          },
          pwUnchanged
        );
        state.users = nextUsers;
        appendLog(state, 'user:edit', `Subscriber edited: ${state.users[idx].name}`);
      }

      const saved = await saveRuntimeState(env, state);
      return json(buildFullAdminPayload(saved, url.host, cfInfo));
    }
  }

  // ---- POST /api/tgproxy/rotate ----
  if (path === '/api/tgproxy/rotate' && method === 'POST') {
    state.settings = sanitizeSettings(
      { ...state.settings, tgProxySecret: generateTgSecret() },
      state.settings
    );
    appendLog(state, 'tgproxy', 'Telegram proxy secret regenerated');
    const saved = await saveRuntimeState(env, state);
    return json(buildFullAdminPayload(saved, url.host, cfInfo));
  }

  // ---- POST /api/tools/probe-proxy & /api/test-proxyip ----
  if ((path === '/api/tools/probe-proxy' || path === '/api/test-proxyip') && method === 'POST') {
    const body = await readJsonBody(request);
    if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);
    const result = await probeOutboundEndpoint(body.target || '');
    return json(result);
  }

  // ---- GET /api/backup ----
  if (path === '/api/backup' && method === 'GET') {
    return new Response(
      JSON.stringify(
        {
          ok: true,
          version: 2,
          nightlineBackupVersion: 2,
          oryvexBackupVersion: 1,
          exportedAt: new Date().toISOString(),
          settings: state.settings,
          users: state.users,
        },
        null,
        2
      ),
      {
        status: 200,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'content-disposition': `attachment; filename="oryvex-backup-${new Date().toISOString().slice(0, 10)}.json"`,
        },
      }
    );
  }

  // ---- POST /api/restore ----
  if (path === '/api/restore' && method === 'POST') {
    const body = await readJsonBody(request);
    if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);
    if (!body || (!body.settings && !Array.isArray(body.users))) {
      return json({ ok: false, error: 'The backup file is not valid.' }, 400);
    }
    if (body.settings && typeof body.settings === 'object') {
      state.settings = sanitizeSettings(body.settings, state.settings);
    }
    if (Array.isArray(body.users) && body.users.length > 0) {
      state.users = body.users.slice(0, 200).map((u) => normalizeUser(u));
    }
    appendLog(state, 'restore', 'Backup restored successfully');
    const saved = await saveRuntimeState(env, state);
    return json(buildFullAdminPayload(saved, url.host, cfInfo));
  }

  // ---- POST /api/cf/config (Verify / Save / Clear Cloudflare API Token) ----
  if (path === '/api/cf/config' && method === 'POST') {
    const body = await readJsonBody(request);
    if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);

    if (body.action === 'clear') {
      state.cfApi = {
        token: '',
        accountId: '',
        accountName: '',
        scriptName: '',
        dailyLimit: 100000,
        canEditWorkers: false,
        updatedAt: Date.now(),
      };
      cfUsageMemCache = null;
      appendLog(state, 'cf:clear', 'Cloudflare API token removed from the panel');
      const saved = await saveRuntimeState(env, state);
      return json({
        ok: true,
        cleared: true,
        cfIntegration: sanitizeCfPublicInfo(saved.cfApi, url.host),
      });
    }

    const rawInputToken = String(body.token || '').trim();
    const effectiveToken =
      rawInputToken && rawInputToken !== '__SAVED__'
        ? rawInputToken
        : String(state.cfApi?.token || '').trim();

    if (!effectiveToken || effectiveToken.length < 20) {
      return json(
        {
          ok: false,
          error: 'Enter a valid Cloudflare API token.',
        },
        400
      );
    }

    const preferredAccountId = String(body.accountId || state.cfApi?.accountId || '').trim();
    const preferredScript =
      String(body.scriptName || state.cfApi?.scriptName || '').trim() || inferWorkerNameFromHost(url.host);
    const dailyLimit = Math.max(1000, Math.min(100_000_000, Number(body.dailyLimit) || state.cfApi?.dailyLimit || 100000));

    const check = await verifyAndProbeCloudflareToken({
      token: effectiveToken,
      accountId: preferredAccountId,
      scriptName: preferredScript,
      dailyLimit,
      env,
    });

    if (!check.ok) {
      return json(check, 400);
    }

    const shouldSave = body.action !== 'verify';
    let cfPublic = sanitizeCfPublicInfo(
      {
        token: effectiveToken,
        accountId: check.accountId,
        accountName: check.accountName,
        scriptName: check.scriptName,
        dailyLimit,
        canEditWorkers: check.canEditWorkers,
        updatedAt: Date.now(),
      },
      url.host
    );

    if (shouldSave) {
      state.cfApi = {
        token: effectiveToken,
        accountId: check.accountId,
        accountName: check.accountName,
        scriptName: check.scriptName,
        dailyLimit,
        canEditWorkers: check.canEditWorkers,
        updatedAt: Date.now(),
      };
      cfUsageMemCache = check.usage ? { at: Date.now(), accountId: check.accountId, data: check.usage } : null;
      appendLog(state, 'cf:token', `Cloudflare token connected (${check.accountName || check.accountId})`);
      const saved = await saveRuntimeState(env, state);
      cfPublic = sanitizeCfPublicInfo(saved.cfApi, url.host);
    }

    return json({
      ok: true,
      saved: shouldSave,
      verified: true,
      tokenStatus: check.tokenStatus,
      accountId: check.accountId,
      accountName: check.accountName,
      scriptName: check.scriptName,
      availableScripts: check.availableScripts || [],
      canReadAnalytics: check.canReadAnalytics,
      canEditWorkers: check.canEditWorkers,
      cfIntegration: cfPublic,
      usage: check.usage || null,
    });
  }

  // ---- GET /api/cf/usage (Daily Request Limit Telemetry) ----
  if (path === '/api/cf/usage' && method === 'GET') {
    const cfApi = state.cfApi || {};
    if (!cfApi.token || !cfApi.accountId) {
      return json({
        ok: false,
        needsToken: true,
        cfIntegration: sanitizeCfPublicInfo(cfApi, url.host),
      });
    }
    const forceFresh = url.searchParams.get('fresh') === '1';
    if (
      !forceFresh &&
      cfUsageMemCache &&
      cfUsageMemCache.accountId === cfApi.accountId &&
      Date.now() - cfUsageMemCache.at < 45_000
    ) {
      return json({
        ok: true,
        cached: true,
        cfIntegration: sanitizeCfPublicInfo(cfApi, url.host),
        usage: {
          ...cfUsageMemCache.data,
          dailyLimit: cfApi.dailyLimit || 100000,
          pct: Math.min(
            100,
            Math.round(((cfUsageMemCache.data.usedToday || 0) / Math.max(1, cfApi.dailyLimit || 100000)) * 1000) / 10
          ),
        },
      });
    }

    const usageRes = await queryCloudflareDailyRequests({
      token: cfApi.token,
      accountId: cfApi.accountId,
      scriptName: cfApi.scriptName || inferWorkerNameFromHost(url.host),
      dailyLimit: cfApi.dailyLimit || 100000,
      env,
    });
    if (!usageRes.ok) {
      return json(
        {
          ok: false,
          error: usageRes.error,
          cfIntegration: sanitizeCfPublicInfo(cfApi, url.host),
        },
        400
      );
    }
    cfUsageMemCache = { at: Date.now(), accountId: cfApi.accountId, data: usageRes.usage };
    return json({
      ok: true,
      cached: false,
      cfIntegration: sanitizeCfPublicInfo(cfApi, url.host),
      usage: usageRes.usage,
    });
  }

  // ---- GET /api/update/check (GitHub repository injected at build time) ----
  if (path === '/api/update/check' && method === 'GET') {
    const force = url.searchParams.get('force') === '1';
    const info = await checkForUpdate({ repo: GITHUB_REPO, currentVersion: PANEL_VERSION, env, force });
    const cfApi = state.cfApi || {};
    return json(
      {
        ...info,
        cfConfigured: Boolean(cfApi.token),
        canEditWorkers: Boolean(cfApi.canEditWorkers),
        scriptName: String(cfApi.scriptName || '').trim() || inferWorkerNameFromHost(url.host),
      },
      info.ok ? 200 : 502
    );
  }

  // ---- POST /api/update/apply (in-panel self-update from the configured GitHub repository) ----
  if (path === '/api/update/apply' && method === 'POST') {
    const body = await readJsonBody(request);
    if (body.__parseError) return json({ ok: false, error: body.__parseError }, 400);

    const token =
      body.token && String(body.token).trim() && String(body.token).trim() !== '__SAVED__'
        ? String(body.token).trim()
        : String(state.cfApi?.token || '').trim();
    const accountId = String(body.accountId || state.cfApi?.accountId || '').trim();
    const scriptName =
      String(body.scriptName || state.cfApi?.scriptName || '').trim() || inferWorkerNameFromHost(url.host);

    if (!token) {
      return json(
        {
          ok: false,
          needsToken: true,
          error:
            'To update from inside the panel, first save a Cloudflare API token with the Workers Scripts: Edit permission.',
        },
        400
      );
    }

    const result = await applyOfficialGitHubSelfUpdate({
      token,
      accountId,
      scriptName,
      env,
      force: body.force === true,
    });
    if (!result.ok) {
      return json(result, 400);
    }

    state.cfApi = {
      ...(state.cfApi || {}),
      token,
      accountId: result.accountId,
      accountName: result.accountName || state.cfApi?.accountName || '',
      scriptName: result.scriptName,
      dailyLimit: state.cfApi?.dailyLimit || 100000,
      canEditWorkers: true,
      updatedAt: Date.now(),
    };
    appendLog(
      state,
      'system:update',
      `Worker ${result.scriptName} updated to v${result.targetVersion} from the configured repository`
    );
    await saveRuntimeState(env, state);
    return json(result);
  }

  return json({ ok: false, error: 'API route not found.' }, 404);
}

/* --------------------------------------------------------------- Utilities */

function buildAdminUserSummary(user, settings, host) {
  const v = enrichUserView(user);
  const subBase = `https://${host}/sub/${encodeURIComponent(v.subToken)}`;
  const quickMeta = computeQuickUserNodeMeta(v, settings, host);
  return {
    id: v.id,
    name: v.name,
    note: v.note,
    enabled: v.enabled,
    status: v.status,
    uuid: v.uuid,
    trojanPassword: v.trojanPassword,
    subToken: v.subToken,
    trafficLimitGB: v.trafficLimitGB,
    usedUpBytes: v.usedUpBytes,
    usedDownBytes: v.usedDownBytes,
    usedBytes: v.usedBytes,
    limitBytes: v.limitBytes,
    connections: v.connections,
    expiryDays: v.expiryDays,
    expiresAt: v.expiresAt,
    effectiveExpiresAt: v.effectiveExpiresAt,
    remainingDays: v.remainingDays,
    startOnFirstUse: v.startOnFirstUse,
    firstConnectedAt: v.firstConnectedAt,
    lastSeenAt: v.lastSeenAt,
    nodeCount: quickMeta.nodeCount,
    urls: {
      pressPass: subBase,
      normalSub: `${subBase}?format=b64`,
      rawSub: `${subBase}?format=raw`,
      xrayFragmentSub: `${subBase}?format=xray`,
      singboxSub: `${subBase}?format=singbox`,
      clashSub: `${subBase}?format=clash`,
      privateDoH: `https://${host}/dns-query/${encodeURIComponent(v.subToken)}`,
      primaryVless: quickMeta.primaryVless,
      primaryTrojan: quickMeta.primaryTrojan,
    },
  };
}

function buildFullAdminPayload(state, host, cf = null) {
  const users = (state.users || []).map((u) => buildAdminUserSummary(u, state.settings, host));
  const totals = users.reduce(
    (acc, u) => {
      acc.totalUsedBytes += u.usedBytes;
      acc.totalConnections += u.connections;
      if (u.status === 'active') acc.activeUsers += 1;
      return acc;
    },
    { totalUsedBytes: 0, totalConnections: 0, activeUsers: 0 }
  );

  const firstRaw = state.users && state.users[0] ? enrichUserView(state.users[0]) : null;
  const initialNodes = firstRaw ? buildNodeDescriptors(firstRaw, state.settings, host) : [];
  const tgProxy =
    state.settings.enableTgProxy !== false && state.settings.tgProxySecret
      ? buildTgProxyLinks(host, state.settings.tgProxySecret, state.settings.tgProxyDomain)
      : null;

  return {
    ok: true,
    version: PANEL_VERSION,
    state: 'ready',
    mode: 'admin',
    host,
    edge: cf?.colo || 'CF-GLOBAL',
    kvBound: state.kvBound,
    kvName: state.kvName,
    authenticated: true,
    brand: PANEL_BRAND,
    settings: state.settings,
    cfIntegration: sanitizeCfPublicInfo(state.cfApi, host),
    updater: {
      repo: GITHUB_REPO,
      repoUrl: GITHUB_REPO_URL,
      currentVersion: PANEL_VERSION,
    },
    tgProxy,
    users,
    initialNodes,
    totals,
    logs: state.logs || [],
    ...(cf ? { cf } : {}),
  };
}

function findSubscriptionUser(runtime, token) {
  if (!token || !Array.isArray(runtime?.users)) return null;
  const low = token.toLowerCase();
  return (
    runtime.users.find(
      (u) => u && (u.subToken === token || String(u.uuid || '').toLowerCase() === low)
    ) || null
  );
}

function findActiveTokenUser(runtime, token) {
  const u = findSubscriptionUser(runtime, token);
  if (!u) return null;
  return enrichUserView(u).status === 'active' ? u : null;
}

async function isAuthenticated(request, runtime) {
  if (!runtime || !runtime.initialized || !runtime.auth || !runtime.auth.secret) return false;
  const cookie = readCookie(request.headers.get('cookie') || '', SESSION_COOKIE);
  if (!cookie) return false;
  const session = await verifySession(cookie, runtime.auth.secret, runtime.auth.ver || 1);
  return Boolean(session && session.sub === 'admin');
}

function readCookie(cookieHeader, name) {
  if (!cookieHeader || typeof cookieHeader !== 'string') return '';
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    if (k === name) return safeDecodeURIComponent(part.slice(idx + 1).trim(), '');
  }
  return '';
}

function formatSessionCookie(token, isHttps) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${isHttps ? '; Secure' : ''}`;
}

async function readJsonBody(request) {
  try {
    const lenHeader = Number(request.headers.get('content-length') || 0);
    if (lenHeader > MAX_JSON_BODY_BYTES) {
      return { __parseError: 'The request body is too large.' };
    }
    const text = await request.text();
    if (!text || !text.trim()) return {};
    if (text.length > MAX_JSON_BODY_BYTES) {
      return { __parseError: 'The request body is too large.' };
    }
    const parsed = safeJsonParse(text, undefined);
    if (parsed === undefined || typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { __parseError: 'The request body is not valid JSON.' };
    }
    return parsed;
  } catch {
    return { __parseError: 'Could not read the request body.' };
  }
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...extraHeaders,
    },
  });
}

async function proxyFallbackDomain(request, fallbackDomain, inlineAssets) {
  const ctrl = new AbortController();
  const tid = setTimeout(() => {
    try { ctrl.abort(); } catch {}
  }, 8000);
  try {
    const srcUrl = new URL(request.url);
    const targetUrl = new URL(`https://${fallbackDomain}${srcUrl.pathname}${srcUrl.search}`);
    const headers = new Headers(request.headers);
    headers.set('host', targetUrl.host);
    headers.delete('cookie');
    const resp = await fetch(targetUrl.toString(), {
      method: request.method,
      headers,
      body: ['GET', 'HEAD'].includes(request.method.toUpperCase()) ? undefined : request.body,
      redirect: 'manual',
      signal: ctrl.signal,
    });
    return new Response(resp.body, {
      status: resp.status,
      headers: new Headers(resp.headers),
    });
  } catch {
    return new Response(renderDecoyGazette(inlineAssets), {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  } finally {
    clearTimeout(tid);
  }
}

async function servePanelShell(request, env) {
  if (env && env.ASSETS && typeof env.ASSETS.fetch === 'function') {
    try {
      const assetUrl = new URL(request.url);
      assetUrl.pathname = '/index.html';
      const assetResp = await env.ASSETS.fetch(new Request(assetUrl.toString(), request));
      if (assetResp && assetResp.ok) return assetResp;
    } catch {}
  }
  const html = await getPanelHtml();
  if (typeof html === 'string' && html.length > 0) {
    return new Response(html, {
      status: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-cache',
      },
    });
  }
  return errorResponse(request, 'UI_BUNDLE_MISSING', {
    version: PANEL_VERSION,
    docsUrl: DOCS_URL ? `${DOCS_URL}troubleshooting.html#ui-bundle` : '',
  });
}

/* ---------------- Cloudflare Daily Quota & Hardcoded GitHub Self-Updater ---------------- */

let cfUsageMemCache = null;

function inferWorkerNameFromHost(host) {
  const clean = String(host || '').split(':')[0].trim().toLowerCase();
  if (clean.endsWith('.workers.dev')) {
    const parts = clean.split('.');
    if (parts.length >= 4) return parts[0];
  }
  return '';
}

function sanitizeCfPublicInfo(cfApi, host) {
  const raw = cfApi && typeof cfApi === 'object' ? cfApi : {};
  const tok = String(raw.token || '').trim();
  const inferredScript = String(raw.scriptName || '').trim() || inferWorkerNameFromHost(host);
  return {
    hasToken: Boolean(tok),
    maskedToken: tok ? `••••••••${tok.slice(-4)}` : '',
    accountId: String(raw.accountId || '').trim(),
    accountName: String(raw.accountName || '').trim(),
    scriptName: inferredScript,
    dailyLimit: Math.max(1000, Number(raw.dailyLimit) || 100000),
    canEditWorkers: Boolean(raw.canEditWorkers),
    updatedAt: Number(raw.updatedAt) || 0,
    tokensDashboardUrl: 'https://dash.cloudflare.com/profile/api-tokens',
  };
}

async function fetchJsonWithTimeout(urlStr, options = {}, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const tid = setTimeout(() => {
    try { ctrl.abort(); } catch {}
  }, timeoutMs);
  try {
    const res = await fetch(urlStr, { ...options, signal: ctrl.signal });
    const text = await res.text();
    const data = safeJsonParse(text, null);
    return { ok: res.ok, status: res.status, data, text };
  } catch (err) {
    return { ok: false, status: 0, data: null, text: '', error: err?.message || String(err) };
  } finally {
    clearTimeout(tid);
  }
}

async function resolveCloudflareAccount(cfBase, token, preferredAccountId = '') {
  const headers = {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
  };
  if (preferredAccountId) {
    const accRes = await fetchJsonWithTimeout(
      `${cfBase}/accounts/${encodeURIComponent(preferredAccountId)}`,
      { headers }
    );
    if (accRes.ok && accRes.data?.success && accRes.data?.result?.id) {
      return {
        ok: true,
        accountId: accRes.data.result.id,
        accountName: accRes.data.result.name || '',
      };
    }
  }
  const listRes = await fetchJsonWithTimeout(`${cfBase}/accounts?per_page=10`, { headers });
  if (listRes.ok && listRes.data?.success && Array.isArray(listRes.data.result) && listRes.data.result.length > 0) {
    const chosen = preferredAccountId
      ? listRes.data.result.find((a) => a.id === preferredAccountId) || listRes.data.result[0]
      : listRes.data.result[0];
    return {
      ok: true,
      accountId: chosen.id,
      accountName: chosen.name || '',
    };
  }
  const cfErr = listRes.data?.errors?.[0]?.message || '';
  return {
    ok: false,
    error: cfErr
      ? `Cloudflare account access denied: ${cfErr}`
      : 'The token is invalid or lacks account read access (Account Settings / Analytics: Read).',
  };
}

async function verifyAndProbeCloudflareToken({ token, accountId, scriptName, dailyLimit = 100000, env }) {
  const cfBase = String(env?.NL_CF_API_BASE || 'https://api.cloudflare.com/client/v4').replace(/\/+$/, '');
  const headers = {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
  };

  let tokenStatus = 'unknown';
  const userVerify = await fetchJsonWithTimeout(`${cfBase}/user/tokens/verify`, { headers });
  if (userVerify.ok && userVerify.data?.success) {
    tokenStatus = userVerify.data?.result?.status || 'active';
    if (tokenStatus && tokenStatus !== 'active') {
      return { ok: false, error: `The Cloudflare token is not active (${tokenStatus}).` };
    }
  }

  const accInfo = await resolveCloudflareAccount(cfBase, token, accountId);
  if (!accInfo.ok) {
    if (!userVerify.ok) {
      const msg = userVerify.data?.errors?.[0]?.message || accInfo.error;
      return { ok: false, error: `Cloudflare token verification failed: ${msg}` };
    }
    if (!accountId) {
      return {
        ok: false,
        error:
          'The token is valid, but the account ID could not be detected. Grant Account Settings: Read or enter the Account ID.',
      };
    }
  }

  const resolvedAccountId = accInfo.ok ? accInfo.accountId : accountId;
  const resolvedAccountName = accInfo.ok ? accInfo.accountName : '';

  if (tokenStatus === 'unknown' && resolvedAccountId) {
    const accVerify = await fetchJsonWithTimeout(
      `${cfBase}/accounts/${encodeURIComponent(resolvedAccountId)}/tokens/verify`,
      { headers }
    );
    if (accVerify.ok && accVerify.data?.success) {
      tokenStatus = accVerify.data?.result?.status || 'active';
    } else if (accInfo.ok) {
      tokenStatus = 'active';
    }
  }

  let availableScripts = [];
  let resolvedScript = scriptName || '';
  let canEditWorkers = false;
  if (resolvedAccountId) {
    const scriptsRes = await fetchJsonWithTimeout(
      `${cfBase}/accounts/${encodeURIComponent(resolvedAccountId)}/workers/scripts`,
      { headers }
    );
    if (scriptsRes.ok && scriptsRes.data?.success && Array.isArray(scriptsRes.data.result)) {
      availableScripts = scriptsRes.data.result.map((s) => s.id).filter(Boolean).slice(0, 30);
      if (!resolvedScript && availableScripts.length === 1) {
        resolvedScript = availableScripts[0];
      } else if (resolvedScript && !availableScripts.includes(resolvedScript)) {
        const ci = availableScripts.find((s) => s.toLowerCase() === resolvedScript.toLowerCase());
        if (ci) resolvedScript = ci;
      }
      const probeTarget = resolvedScript || availableScripts[0] || '';
      if (probeTarget) {
        const setRes = await fetchJsonWithTimeout(
          `${cfBase}/accounts/${encodeURIComponent(resolvedAccountId)}/workers/scripts/${encodeURIComponent(probeTarget)}/settings`,
          { headers }
        );
        if (setRes.ok && setRes.data?.success) {
          canEditWorkers = true;
        }
      } else {
        canEditWorkers = true;
      }
    }
  }

  const usageRes = await queryCloudflareDailyRequests({
    token,
    accountId: resolvedAccountId,
    scriptName: resolvedScript,
    dailyLimit,
    env,
  });

  if (!usageRes.ok) {
    return {
      ok: false,
      error:
        usageRes.error ||
        'The token was recognized, but Account Analytics: Read is not enabled on it.',
    };
  }

  return {
    ok: true,
    tokenStatus: tokenStatus || 'active',
    accountId: resolvedAccountId,
    accountName: resolvedAccountName,
    scriptName: resolvedScript,
    availableScripts,
    canReadAnalytics: true,
    canEditWorkers,
    usage: usageRes.usage,
  };
}

async function queryCloudflareDailyRequests({ token, accountId, scriptName = '', dailyLimit = 100000, env }) {
  const cfBase = String(env?.NL_CF_API_BASE || 'https://api.cloudflare.com/client/v4').replace(/\/+$/, '');
  const now = new Date();
  const startOfUtcDay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
  const nextUtcMidnight = new Date(startOfUtcDay.getTime() + 86_400_000);

  const gqlQuery = `
    query OryvexDailyQuota($accountTag: string!, $since: Time!, $until: Time!) {
      viewer {
        accounts(filter: { accountTag: $accountTag }) {
          workersInvocationsAdaptive(limit: 200, filter: { datetime_geq: $since, datetime_leq: $until }) {
            dimensions { scriptName }
            sum { requests subrequests errors }
          }
        }
      }
    }
  `;

  const res = await fetchJsonWithTimeout(
    `${cfBase}/graphql`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        query: gqlQuery,
        variables: {
          accountTag: accountId,
          since: startOfUtcDay.toISOString(),
          until: now.toISOString(),
        },
      }),
    },
    10000
  );

  if (!res.ok || !res.data) {
    return {
      ok: false,
      error: 'No response from Cloudflare GraphQL. Check that the token has Account Analytics: Read.',
    };
  }

  if (Array.isArray(res.data.errors) && res.data.errors.length > 0 && !res.data.data) {
    return {
      ok: false,
      error: `Cloudflare analytics error: ${res.data.errors[0]?.message || 'GraphQL Error'}`,
    };
  }

  const accounts = res.data?.data?.viewer?.accounts;
  if (!Array.isArray(accounts) || accounts.length === 0) {
    return {
      ok: false,
      error: 'Access to Cloudflare account analytics was denied (Account Analytics: Read is required).',
    };
  }

  const rows = Array.isArray(accounts[0]?.workersInvocationsAdaptive)
    ? accounts[0].workersInvocationsAdaptive
    : [];

  let usedToday = 0;
  let subrequestsToday = 0;
  let errorsToday = 0;
  let scriptRequests = 0;

  for (const row of rows) {
    const reqs = Math.max(0, Number(row?.sum?.requests) || 0);
    const subs = Math.max(0, Number(row?.sum?.subrequests) || 0);
    const errs = Math.max(0, Number(row?.sum?.errors) || 0);
    usedToday += reqs;
    subrequestsToday += subs;
    errorsToday += errs;
    if (scriptName && row?.dimensions?.scriptName === scriptName) {
      scriptRequests += reqs;
    }
  }

  const safeLimit = Math.max(1000, Number(dailyLimit) || 100000);
  const pct = Math.min(100, Math.round((usedToday / safeLimit) * 1000) / 10);

  return {
    ok: true,
    usage: {
      usedToday,
      scriptRequests,
      subrequestsToday,
      errorsToday,
      dailyLimit: safeLimit,
      remainingToday: Math.max(0, safeLimit - usedToday),
      pct,
      sinceUtc: startOfUtcDay.toISOString(),
      resetAtUtc: nextUtcMidnight.toISOString(),
      resetInSec: Math.max(0, Math.floor((nextUtcMidnight.getTime() - now.getTime()) / 1000)),
      fetchedAt: Date.now(),
    },
  };
}

async function applyOfficialGitHubSelfUpdate({ token, accountId, scriptName, env, force = false }) {
  const cfBase = String(env?.NL_CF_API_BASE || 'https://api.cloudflare.com/client/v4').replace(/\/+$/, '');

  // 1. Resolve Cloudflare Account
  const accInfo = await resolveCloudflareAccount(cfBase, token, accountId);
  if (!accInfo.ok) {
    return { ok: false, error: accInfo.error };
  }
  const resolvedAccountId = accInfo.accountId;

  // 2. Resolve Worker Script Name
  const cfHeaders = { authorization: `Bearer ${token}` };
  let targetScript = String(scriptName || '').trim();
  if (!targetScript) {
    const listRes = await fetchJsonWithTimeout(
      `${cfBase}/accounts/${encodeURIComponent(resolvedAccountId)}/workers/scripts`,
      { headers: cfHeaders }
    );
    if (listRes.ok && Array.isArray(listRes.data?.result) && listRes.data.result.length === 1) {
      targetScript = listRes.data.result[0].id;
    }
  }
  if (!targetScript) {
    return {
      ok: false,
      error: 'The Worker name is unknown. Enter the exact Worker name from Cloudflare.',
    };
  }

  // 3. Resolve the latest GitHub Release and download its validated worker bundle
  const updateInfo = await checkForUpdate({ repo: GITHUB_REPO, currentVersion: PANEL_VERSION, env, force: true });
  if (!updateInfo.ok) {
    return { ok: false, error: updateInfo.error || 'Could not read release information from GitHub.' };
  }
  if (updateInfo.configured === false) {
    return { ok: false, error: updateInfo.message };
  }
  if (updateInfo.notPublishedYet) {
    return { ok: false, error: updateInfo.message || `No release published in ${GITHUB_REPO} yet.` };
  }
  if (!updateInfo.updateAvailable && !force) {
    return {
      ok: false,
      upToDate: true,
      error: `Already on v${PANEL_VERSION}, the latest release. Nothing to install.`,
    };
  }
  const bundle = await downloadReleaseBundle({ info: updateInfo, env });
  if (!bundle.ok) {
    return { ok: false, error: bundle.error };
  }
  const workerCode = bundle.code;

  // 4. Read existing Worker settings so KV bindings, vars & compatibility flags are 100% preserved
  const settingsUrl = `${cfBase}/accounts/${encodeURIComponent(resolvedAccountId)}/workers/scripts/${encodeURIComponent(targetScript)}/settings`;
  const curSettingsRes = await fetchJsonWithTimeout(settingsUrl, { headers: cfHeaders }, 10000);
  if (!curSettingsRes.ok || !curSettingsRes.data?.success) {
    const cfMsg = curSettingsRes.data?.errors?.[0]?.message || '';
    return {
      ok: false,
      error: cfMsg
        ? `Cannot read Worker settings (${targetScript}): ${cfMsg}. Check the Worker name and that the token has Workers Scripts: Edit.`
        : `Worker "${targetScript}" was not found, or the token lacks Workers Scripts: Edit.`,
    };
  }

  const existing = curSettingsRes.data.result || {};
  const preservedBindings = Array.isArray(existing.bindings)
    ? existing.bindings
        .filter((b) => b && b.name)
        .map((b) => (b.type === 'secret_text' || b.type === 'secret_key' ? { type: 'inherit', name: b.name } : b))
    : [];

  const metadata = {
    main_module: 'worker.js',
    compatibility_date: existing.compatibility_date || '2025-09-01',
    compatibility_flags: Array.isArray(existing.compatibility_flags) && existing.compatibility_flags.length > 0
      ? existing.compatibility_flags
      : ['nodejs_compat'],
    bindings: preservedBindings,
    keep_bindings: ['secret_text', 'secret_key'],
  };
  if (existing.usage_model) metadata.usage_model = existing.usage_model;
  if (existing.placement && typeof existing.placement === 'object') metadata.placement = existing.placement;

  // 5. Upload new ES Module Worker bundle via Cloudflare Workers API
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
  form.append(
    'worker.js',
    new Blob([workerCode], { type: 'application/javascript+module' }),
    'worker.js'
  );

  const uploadUrl = `${cfBase}/accounts/${encodeURIComponent(resolvedAccountId)}/workers/scripts/${encodeURIComponent(targetScript)}`;
  const uploadRes = await fetchJsonWithTimeout(
    uploadUrl,
    {
      method: 'PUT',
      headers: { authorization: `Bearer ${token}` },
      body: form,
    },
    20000
  );

  if (!uploadRes.ok || !uploadRes.data?.success) {
    const errMsg = uploadRes.data?.errors?.[0]?.message || 'Uploading the new code to Cloudflare failed.';
    return {
      ok: false,
      error: `Worker update failed: ${errMsg}`,
    };
  }

  return {
    ok: true,
    updated: true,
    previousVersion: PANEL_VERSION,
    targetVersion: bundle.version || updateInfo.latestVersion || PANEL_VERSION,
    tag: updateInfo.tag,
    scriptName: targetScript,
    accountId: resolvedAccountId,
    accountName: accInfo.accountName || '',
    repoUrl: GITHUB_REPO_URL,
    reloadAfterMs: 2200,
  };
}
