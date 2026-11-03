# Changelog

## v1.2.0
- New: fully automatic releases. Every code push to `main` is built, tested, version-bumped, tagged and published as a GitHub Release with `worker-single-file.js`, the Pages zip and `SHA256SUMS.txt`. Manual runs pick patch / minor / major or an exact version.
- New: docs site rebuilt to match the panel (same surfaces, signal-lime accent, signal-bar mark, ticker), with a light / system / dark theme toggle, search (press `/`), page sections rail, copy buttons, prev / next, changelog page, Clients, Updates and FAQ pages, 404, sitemap.
- New: redesigned Update dialog: installed → latest, release date, notes, last-checked time; quiet background check lights the NEW badge.
- Fix: update check only trusts published Releases (no more "update available" for a file that doesn't exist), survives GitHub API rate limits via the github.com redirect, caches for 10 minutes, supports an optional `GITHUB_TOKEN` secret, and verifies the downloaded bundle's version before deploying.
- Fix: version comes from `package.json` only (was hardcoded in two places; preview showed v1.0.0).
- CI: `ci.yml` for PRs, `release.yml` for main and tags, docs redeploy after each release; unit tests for the updater.

## v1.1.0
- New: VLESS over XHTTP (stream-one) transport with configurable path; Xray JSON + URI subscriptions.
- New: node name prefix, typeface option (SF Pro / Google Sans / Inter), corner style option.
- Redesigned panel: Apple-style surfaces, SF Pro / Google Sans type, pill controls, iOS switches, cleaner labels.
- Docs site restyled to match the panel; XHTTP docs.
- Fix: split UDP/DNS frames and split headers on streaming transports.

## v1.0.0 · Relay Rack redesign
- Brand-new "Relay Rack" interface for the panel and subscriber page: every card is a rack module with a faceplate header, recessed inputs, keycap buttons and LED-segment meters.
- New default accent "Signal lime" (blue, violet, emerald, amber and rose still available in Display options); retuned dark and light themes with a perforated dot-grid background.
- Admin layout: sticky left section rail on desktop (horizontal scroll strip on tablet/phone), status bar across the top, sticky save bar at the end of each settings tab.
- New masthead: oversized mono wordmark, animated signal-bar mark, LED-board feature ticker.
- Motion rewritten to six movements only: scale-in / scale-out, fade-in / fade-out, slide-in / slide-out. Buttons and cards never move on the X or Y axis (hover = scale up, press = scale down). Dialogs scale in/out, Display options is a slide-in/slide-out side sheet, toasts slide in/out from the bottom.
- Reduced-motion preference still disables all animation.

## v1.0.0 (Current Release)
- Finalized initial standalone release of OryvexWorkerPanel (unified package version `1.0.0`).
- White-label polish: Removed BlueKnight Telegram badge and creator watermark from panel, subscriber page, DoH page, error pages, and docs.
- Fixed panel crash "Cannot set properties of null (setting 'textContent')" that stopped generated nodes from rendering; all element writes are now null-safe.
- Connectivity: ALPN locked to http/1.1 for WebSocket (h2/h3 broke the WS handshake and showed -1 ping), early data processed synchronously, IPv6 targets dialed without brackets.
- Xray JSON: replaced geosite:ir/cn/ru (missing in many geosite.dat files, crashing the core) with domain rules.
- Interface & Polish: unified cards, pill tabs, refined controls, ambient dot grid, smooth animations, correct font weight mappings.
- Reconciled code reliability: eliminated silent empty catch blocks across proxy/UI modules and deduplicated subscription expiry formatting logic.

## v2.6.0 · Legacy Oryvex Edition (Pre-1.0 Fork)
- Initial Oryvex fork/redesign from upstream NightLine v2.5.2: dark-first design, Inter typography, one accent color, breathing orb mark, sticky top bar, segmented tabs.
- Display options (top bar → Display): theme dark / light / system, five accent colors, compact density, large text, reduced motion, hide ticker, blur IP on load, confirm before sign-out.
- Added Muvixo creator attribution watermark across panel and subscriber pages (later removed in v1.0.0 for white-labeling).
- Hosted error pages: missing KV, storage failure, missing UI bundle, invalid subscription link, internal error.
- Fully English UI and server messages; Persian fonts removed for smaller bundle footprint.
- GitHub Actions: `build.yml` and `pages.yml` workflow automation.

## v2.5.x (Upstream Base)
Inherited from NightLine v2.5.2: Cloudflare daily quota meter, token guide, Worker self-updater, bug fixes.

