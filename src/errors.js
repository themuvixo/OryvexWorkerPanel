/**
 * OryvexWorkerPanel: hosted error pages.
 *
 * Self-contained HTML (no external requests) shown by the Worker when something
 * in the deployment is misconfigured, e.g. the KV namespace is not bound.
 * Browsers get the HTML page; API clients and apps get a JSON body instead.
 */

export const ERROR_CATALOG = {
  KV_MISSING: {
    status: 503,
    title: "Storage isn't connected yet",
    message:
      'This Worker is running, but no KV namespace is bound to it. The panel stores admins, subscribers and settings in KV, so it cannot start without one.',
    steps: [
      'Open the Cloudflare dashboard and go to <b>Storage &amp; Databases → KV</b>. Create a namespace, for example <code>oryvex-kv</code>.',
      'Open this Worker, then <b>Settings → Bindings → Add → KV namespace</b>.',
      'Set the variable name to exactly <code>KV</code> (uppercase) and pick the namespace you created.',
      'Save, wait a few seconds for the deployment, then press <b>Check again</b>.',
    ],
  },
  KV_UNAVAILABLE: {
    status: 503,
    title: 'Storage is temporarily unavailable',
    message:
      'The KV namespace is bound, but reading or writing it failed. This usually means the daily KV write limit on the Free plan was reached, or Cloudflare had a short storage hiccup.',
    steps: [
      'Wait a minute and press <b>Check again</b>.',
      'In Cloudflare, open <b>Workers &amp; Pages → this Worker → Metrics</b> and look for KV errors or exhausted limits.',
      'If the daily write limit is exhausted, it resets at 00:00 UTC. Reads keep working in the meantime.',
    ],
  },
  UI_BUNDLE_MISSING: {
    status: 500,
    title: 'The panel UI is missing from this build',
    message:
      'The Worker code was deployed without its bundled interface. This happens when <code>src/worker.js</code> is deployed directly instead of the built single-file Worker.',
    steps: [
      'Run <code>npm ci &amp;&amp; npm run build</code>, or download <code>worker-single-file.js</code> from the latest GitHub Actions build or Release.',
      'Paste the whole file into the Cloudflare editor (or deploy it with Wrangler) and deploy again.',
    ],
  },
  SUB_NOT_FOUND: {
    status: 404,
    title: 'This subscription link is not valid',
    message:
      'The link may have been mistyped, rotated by the administrator, or the subscriber was removed.',
    steps: [
      'Copy the link again from the panel or ask your administrator for a fresh one.',
      'If you changed the panel domain, update the link in your client app.',
    ],
  },
  NOT_FOUND: {
    status: 404,
    title: 'Nothing lives at this address',
    message: 'The page you asked for does not exist on this Worker.',
    steps: ['Check the address, or go back to the panel home.'],
  },
  INTERNAL: {
    status: 500,
    title: 'Something went wrong on the Worker',
    message:
      'The request was stopped safely before anything was changed. Reloading usually fixes a one-off failure.',
    steps: [
      'Reload the page.',
      'If it keeps happening, open <b>Workers &amp; Pages → this Worker → Logs</b> in Cloudflare and look for the reference ID below.',
    ],
  },
};

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function refId() {
  try {
    const b = new Uint8Array(5);
    crypto.getRandomValues(b);
    return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();
  } catch {
    return String(Date.now()).slice(-8);
  }
}

/** True when the client is a browser that prefers an HTML page. */
export function wantsHtml(request) {
  try {
    if (!request || request.method === 'POST') return false;
    const accept = (request.headers.get('accept') || '').toLowerCase();
    return accept.includes('text/html');
  } catch {
    return false;
  }
}

/** Names of bindings that look like KV namespaces but are not named `KV`. */
export function detectStrayKvBindings(env) {
  const out = [];
  try {
    for (const key of Object.keys(env || {})) {
      const v = env[key];
      if (v && typeof v === 'object' && typeof v.get === 'function' && typeof v.put === 'function' && typeof v.list === 'function') {
        out.push(key);
      }
    }
  } catch {}
  return out;
}

/**
 * Render a complete, self-contained error page.
 * @param {keyof ERROR_CATALOG} code
 * @param {{host?:string, version?:string, detail?:string, docsUrl?:string, facts?:Array<[string,string]>, extraNote?:string}} opts
 */
export function renderErrorPage(code, opts = {}) {
  const entry = ERROR_CATALOG[code] || ERROR_CATALOG.INTERNAL;
  const ref = opts.ref || refId();
  const facts = [
    ['Error code', `E_${code}`],
    ['HTTP status', String(entry.status)],
    ...(opts.host ? [['Host', opts.host]] : []),
    ...(opts.version ? [['Panel version', `v${opts.version}`]] : []),
    ['Reference', ref],
    ...(Array.isArray(opts.facts) ? opts.facts : []),
  ];
  const steps = entry.steps.map((s) => `<li>${s}</li>`).join('');
  const docs = opts.docsUrl
    ? `<a class="btn ghost" href="${esc(opts.docsUrl)}" target="_blank" rel="noopener">Read the docs</a>`
    : '';
  const detail = opts.detail
    ? `<details><summary>Technical detail</summary><pre>${esc(opts.detail).slice(0, 1200)}</pre></details>`
    : '';
  const note = opts.extraNote ? `<p class="callout">${opts.extraNote}</p>` : '';

  return `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta name="color-scheme" content="dark light">
<title>${esc(entry.title)} · OryvexWorkerPanel</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3CradialGradient id='g' cx='.35' cy='.3' r='.8'%3E%3Cstop offset='0' stop-color='%238cc2ff'/%3E%3Cstop offset='.45' stop-color='%230a6cff'/%3E%3Cstop offset='1' stop-color='%23002a8a'/%3E%3C/radialGradient%3E%3C/defs%3E%3Ccircle cx='16' cy='16' r='14' fill='url(%23g)'/%3E%3C/svg%3E">
<style>/*__OX_FONTS__*/
:root{--ink:#06080c;--tile:#0e1218;--tile-2:#141922;--line:#1c222c;--line-2:#273040;--text:#f4f6fa;--muted:#a7b0bf;--dim:#8a94a6;--blue:#0a6cff;--ice:#8cc2ff;--warn:#ffb547;--bad:#ff6b6b;color-scheme:dark}
@media (prefers-color-scheme:light){:root{--ink:#f4f6fa;--tile:#ffffff;--tile-2:#eef2f8;--line:#dde3ec;--line-2:#cbd3df;--text:#0b1220;--muted:#4a5568;--dim:#64708a;--ice:#0046d5;color-scheme:light}}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{min-height:100vh;display:flex;flex-direction:column;background:var(--ink);color:var(--text);font:16px/1.65 "Inter",system-ui,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{flex:1;display:grid;place-items:center;padding:48px 20px}
.box{width:100%;max-width:720px}
.top{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.orb{width:44px;height:44px;flex:none;border-radius:50%;background:radial-gradient(circle at 35% 30%,var(--ice),var(--blue) 42%,#0046d5 76%,#002a8a 100%);box-shadow:0 0 50px #0a6cff66;animation:breathe 4.5s ease-in-out infinite}
.orb.warn{background:radial-gradient(circle at 35% 30%,#ffe2a8,#ffb547 45%,#c26a00 100%);box-shadow:0 0 50px #ffb54755}
@keyframes breathe{50%{transform:scale(1.06);box-shadow:0 0 80px #0a6cff88}}
.brand{font-weight:600;letter-spacing:-.01em}
.code{margin-left:auto;font:13px/1 "JetBrains Mono",ui-monospace,Consolas,monospace;color:var(--muted);background:var(--tile);border:1px solid var(--line);border-radius:99px;padding:7px 12px}
h1{font:700 clamp(32px,6vw,52px)/1.05 "Inter Display",Inter,system-ui,sans-serif;letter-spacing:-.03em;margin:0 0 14px}
.lead{color:var(--muted);font-size:clamp(17px,2.2vw,19px);margin:0 0 28px;max-width:62ch}
.card{background:var(--tile);border:1px solid var(--line);border-radius:22px;padding:24px 26px;margin-bottom:16px}
.card h2{font-size:15px;font-weight:600;margin:0 0 12px;color:var(--text)}
ol{counter-reset:s;list-style:none;margin:0;padding:0;display:grid;gap:12px}
ol li{counter-increment:s;position:relative;padding-left:44px;color:var(--muted)}
ol li:before{content:counter(s);position:absolute;left:0;top:0;width:28px;height:28px;border-radius:50%;background:var(--blue);color:#fff;display:grid;place-items:center;font-weight:600;font-size:14px}
ol li b{color:var(--text)}
code{font:.88em "JetBrains Mono",ui-monospace,Consolas,monospace;background:var(--tile-2);border:1px solid var(--line);border-radius:7px;padding:1px 6px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:8px 18px;margin:0;font-size:14px}
dt{color:var(--dim)}dd{margin:0;font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
.callout{background:#0a6cff14;border:1px solid #0a6cff40;border-radius:14px;padding:12px 16px;margin:0 0 16px;font-size:15px}
.actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:24px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:var(--blue);color:#fff;text-decoration:none;font:600 16px/1 Inter,system-ui,sans-serif;padding:14px 24px;border-radius:99px;border:1px solid transparent;cursor:pointer;transition:background .2s,transform .2s}
.btn:hover{background:#2a80ff}.btn:active{transform:scale(.98)}
.btn.ghost{background:var(--tile);border-color:var(--line-2);color:var(--text)}.btn.ghost:hover{background:var(--tile-2)}
details{margin-top:14px;color:var(--muted);font-size:14px}summary{cursor:pointer}
pre{white-space:pre-wrap;background:var(--tile-2);border:1px solid var(--line);border-radius:12px;padding:12px 14px;font:13px/1.6 "JetBrains Mono",ui-monospace,monospace;color:var(--text)}
:focus-visible{outline:2px solid var(--ice);outline-offset:3px;border-radius:6px}
.maker{position:fixed;left:16px;bottom:16px;display:inline-flex;align-items:center;gap:8px;padding:7px 12px 7px 9px;border-radius:99px;background:color-mix(in srgb,var(--tile) 88%,transparent);border:1px solid var(--line);color:var(--muted);font-size:13px;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
.maker i{width:10px;height:10px;border-radius:50%;background:radial-gradient(circle at 35% 30%,var(--ice),var(--blue))}
.maker b{color:var(--text);font-weight:600}
@media (max-width:560px){.card{padding:20px}.code{display:none}dl{grid-template-columns:1fr}dt{margin-top:6px}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<main>
  <div class="box">
    <div class="top">
      <div class="orb${entry.status >= 500 ? ' warn' : ''}" aria-hidden="true"></div>
      <span class="brand">OryvexWorkerPanel</span>
      <span class="code">E_${esc(code)} · ${entry.status}</span>
    </div>
    <h1>${esc(entry.title)}</h1>
    <p class="lead">${entry.message}</p>
    ${note}
    <section class="card">
      <h2>How to fix it</h2>
      <ol>${steps}</ol>
    </section>
    <section class="card">
      <h2>Diagnostics</h2>
      <dl>${facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      ${detail}
    </section>
    <div class="actions">
      <button class="btn" type="button" onclick="location.reload()">Check again</button>
      ${docs}
    </div>
  </div>
</main>
</body>
</html>`;
}

/**
 * Build an error Response: an HTML page for browsers, JSON for everything else.
 */
export function errorResponse(request, code, opts = {}) {
  const entry = ERROR_CATALOG[code] || ERROR_CATALOG.INTERNAL;
  const ref = refId();
  if (wantsHtml(request)) {
    return new Response(renderErrorPage(code, { ...opts, ref }), {
      status: entry.status,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-oryvex-error': `E_${code}`,
      },
    });
  }
  return new Response(
    JSON.stringify({
      ok: false,
      code: `E_${code}`,
      error: entry.title,
      message: entry.message.replace(/<[^>]+>/g, ''),
      ref,
      ...(opts.detail ? { detail: String(opts.detail).slice(0, 600) } : {}),
    }),
    {
      status: entry.status,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    }
  );
}
