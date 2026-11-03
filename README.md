# OryvexWorkerPanel

**v1.2.0** · Cloudflare Workers & Pages · VLESS + Trojan over WebSocket · Telegram Web Proxy · Private DoH · 

Run a multi-user subscription panel from a single Cloudflare Worker. No server to rent.

> Free for personal, educational and non-commercial use. Selling the software, deployments, or the links it generates is prohibited. See [LICENSE](LICENSE).

## Features
- **Subscribers** in Cloudflare KV: traffic limits, expiry, start-on-first-connect, pause, reset, key rotation (up to 200).
- **One link for every client**: v2rayNG, v2rayN, Hiddify, Sing-box, Clash Meta / Mihomo, Streisand, Shadowrocket.
- **XHTTP** (VLESS stream-one over HTTP/2) as an optional extra transport, plus a node-name prefix.
- **Telegram Web Proxy** (`tg://webproxy`) and **private DoH** at `/dns-query/<token>`.
- **Browser network advisor**, clean-IP scanner, live telemetry and an optional Cloudflare usage meter.
- **Display options**: SF Pro / Google Sans / Inter typeface, round / soft / square corners, dark / light / system theme, 5 accents, compact density, large text, reduced motion, and more.
- **Hosted error pages** that explain exactly what to fix (for example, a missing KV binding).

## Get a build
Download `worker-single-file.js` (Workers) or `oryvex-worker-panel-pages.zip` (Pages) from the latest **Release**.

### Checks and releases run automatically
- `.github/workflows/auto.yml` runs the shared CI checks on every branch push and pull request.
- `.github/workflows/release.yml` builds and publishes releases from `main`; `.github/workflows/pages.yml` deploys the docs site when its content changes or a release is published.
- Push code to `main` → the **Release** workflow builds, tests, bumps the patch version, tags `vX.Y.Z` and publishes a Release with both files and `SHA256SUMS.txt`. Docs-only pushes don't release.
- Bumped `package.json` yourself (`npm run release:minor`)? That exact version ships.
- **Actions → Release → Run workflow** for minor / major / exact version / pre-release.
- Repo variable `AUTO_BUMP` = `patch` (default), `minor` or `none`. Protected `main`? Add secret `RELEASE_TOKEN` (fine-grained PAT, Contents: write).
- Panels built from the repo detect the new Release and can install it in one click (KV, vars and secrets kept).

Build locally:
```bash
npm ci
pip install fonttools brotli   # optional, enables font subsetting
npm run build && npm test
```

## Install on Cloudflare Workers
1. **Storage & Databases → KV → Create**, e.g. `oryvex-kv`.
2. **Workers & Pages → Create → Start with Hello World → Deploy → Edit code**. Replace everything with `worker-single-file.js`, then deploy.
3. **Settings → Bindings → Add → KV namespace**, variable name exactly `KV`.
4. Open the Worker URL and set your admin password.

If KV is missing, the Worker shows an **E_KV_MISSING** page with these steps (and tells you if you bound KV under a different name).

## Install on Cloudflare Pages
Upload `oryvex-worker-panel-pages.zip` via **Workers & Pages → Create → Pages → Upload assets**, bind KV as `KV` and set compatibility date `2024-09-23` or later in **Settings → Functions**, then redeploy the zip.

## Docs site (GitHub Pages)
`/site` holds the docs: `_layout.html` + `pages/*.html`. `npm run build:site` renders them (plus the changelog, error-page previews, search index, sitemap and `/data.json`) into `_site/`. `src/data.json` is the checked-in source/default. The JSON endpoint auto-detects the repository owner in GitHub Actions and emits the owner, repository, Pages URL and GitHub API URLs at `/data.json`. The **Docs** workflow deploys it on changes and after every release. Enable it once in **Settings → Pages → Source: GitHub Actions**.

## Configuration
| Name | Type | Purpose |
| --- | --- | --- |
| `KV` | KV binding | Required. Stores admins, subscribers and settings. |
| `UUID` | variable | Optional single-user stateless mode without KV. |
| `PROXYIP` | variable | Optional fallback proxy IPs. |
| `GITHUB_TOKEN` | secret | Optional read-only token so update checks avoid GitHub's shared rate limit. |
| `ORYVEX_UPDATE_REPO` | build env | Repository for the updater and links. Set automatically in GitHub Actions. |

## Project layout
- `src/` Worker source (`worker.js`, `errors.js`, `sub.js`, `protocols.js`, `storage.js`, `tgproxy.js`) and `src/ui/` panel (`index.html`, `style.css`, `app.js`, `prefs.js`).
- `build.mjs` build pipeline (`--lite` for quick local previews into `.lite/`, never for production).
- `site/` docs, `scripts/build-site.mjs` docs builder, `.github/workflows/` CI.
- `panel-preview.html` offline preview of the panel UI.

Based on NightLine v2.5.2. 
