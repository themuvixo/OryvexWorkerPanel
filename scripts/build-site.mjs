#!/usr/bin/env node
// Builds the GitHub Pages docs into /_site:
//   site/_layout.html + site/pages/*.html  -> one HTML file per page (shared header, footer, theme toggle)
//   CHANGELOG.md                            -> changelog.html
//   src/errors.js                           -> errors/*.html live previews
//   + search-index.json, sitemap.xml, robots.txt, 404.html, .nojekyll
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderErrorPage } from '../src/errors.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const P = (...p) => path.join(root, ...p);
const pkg = JSON.parse(fs.readFileSync(P('package.json'), 'utf8'));
const dataTemplate = JSON.parse(fs.readFileSync(P('src/data.json'), 'utf8'));
const repoCandidate = String(process.env.GITHUB_REPOSITORY || process.env.ORYVEX_UPDATE_REPO || pkg.oryvex?.updateRepo || 'themuvixo/OryvexWorkerPanel').trim();
const repo = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repoCandidate) && !/^OWNER\//i.test(repoCandidate)
  ? repoCandidate
  : 'themuvixo/OryvexWorkerPanel';
const [owner, name] = repo.split('/');
const siteUrl = String(
  process.env.ORYVEX_DOCS_URL || pkg.oryvex?.docsUrl ||
  (name.toLowerCase() === `${owner.toLowerCase()}.github.io` ? `https://${name.toLowerCase()}/` : `https://${owner.toLowerCase()}.github.io/${name}/`)
);
const out = P('_site');
const SRC = P('site');

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
fs.cpSync(path.join(SRC, 'assets'), path.join(out, 'assets'), { recursive: true });

const layout = fs.readFileSync(path.join(SRC, '_layout.html'), 'utf8');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const strip = (s) => String(s).replace(/<svg[\s\S]*?<\/svg>/g, '').replace(/<code class="tag">[\s\S]*?<\/code>/g, '').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/\s+/g, ' ').trim();

/* --------------------------------------------------------------- pages */
function readPage(file) {
  const raw = fs.readFileSync(path.join(SRC, 'pages', file), 'utf8');
  const m = raw.match(/^<!--(\{[\s\S]*?\})-->\s*/);
  const meta = m ? JSON.parse(m[1]) : {};
  return { file, slug: file.replace(/\.html$/, ''), meta, body: m ? raw.slice(m[0].length) : raw };
}

/* minimal, safe Markdown for CHANGELOG.md: headings, bullets, paragraphs, **bold**, `code`, [links](url) */
function inlineMd(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\[([^\]]+)\]\((https?:[^)\s]+|[\w./#-]+)\)/g, '<a href="$2">$1</a>');
}
function changelogPage() {
  const md = fs.existsSync(P('CHANGELOG.md')) ? fs.readFileSync(P('CHANGELOG.md'), 'utf8') : '';
  const blocks = [];
  let cur = null;
  for (const line of md.split('\n')) {
    const h = line.match(/^##\s+(.+)$/);
    if (h) {
      cur = { title: h[1].trim(), items: [], paras: [] };
      blocks.push(cur);
      continue;
    }
    if (!cur) continue;
    const li = line.match(/^\s*[-*]\s+(.+)$/);
    if (li) cur.items.push(li[1]);
    else if (line.trim() && !/^#/.test(line)) cur.paras.push(line.trim());
  }
  let seenCurrent = false;
  const body = blocks.map((b) => {
    const ver = (b.title.match(/v?(\d+\.\d+\.\d+)/) || [])[1] || '';
    const id = ver ? `v${ver.replace(/\./g, '-')}` : b.title.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const rest = b.title.replace(/^v?\d+\.\d+\.\d+\s*[·:-]?\s*/, '').replace(/^\(|\)$/g, '');
    const isCurrent = ver === pkg.version && !seenCurrent;
    if (isCurrent) seenCurrent = true;
    const tag = ver
      ? `<a class="tag" href="https://github.com/${repo}/releases/tag/v${ver}">v${ver}</a>`
      : '';
    return `<section class="card rel-card" id="${id}">
  <h2 class="kicker"><svg class="ic"><use href="#i-tag"/></svg>${ver ? `v${ver}` : inlineMd(b.title)}${rest && ver ? ` <span class="rel-name">${inlineMd(rest)}</span>` : ''}${isCurrent ? '<span class="badge inv">Current</span>' : ''}</h2>
  ${b.paras.map((p) => `<p>${inlineMd(p)}</p>`).join('\n  ')}
  ${b.items.length ? `<ul class="rel-list">${b.items.map((i) => {
      const k = (i.match(/^(New|Fix|Fixed|Changed|Removed|Security|Docs|CI)\b:?\s*/i) || [])[1];
      const txt = k ? i.slice(i.indexOf(k) + k.length).replace(/^:?\s*/, '') : i;
      return `<li>${k ? `<span class="chg chg-${k.toLowerCase()}">${esc(k)}</span>` : ''}<span>${inlineMd(txt)}</span></li>`;
    }).join('')}</ul>` : ''}
  ${tag ? `<p class="rel-foot">${tag}</p>` : ''}
</section>`;
  }).join('\n');
  return {
    file: 'changelog.html', slug: 'changelog',
    meta: { title: 'Changelog', nav: 'Changelog', order: 8, layout: 'doc', lead: 'Every release, newest first.', description: 'OryvexWorkerPanel release history.' },
    body,
  };
}

const pages = fs.readdirSync(path.join(SRC, 'pages')).filter((f) => f.endsWith('.html')).map(readPage);
pages.push(changelogPage());
const navPages = pages.filter((p) => p.meta.nav).sort((a, b) => (a.meta.order || 99) - (b.meta.order || 99));

const stamp = (s, rootRel = '') => s
  .replaceAll('{{VERSION}}', pkg.version)
  .replaceAll('{{REPO_URL}}', `https://github.com/${repo}`)
  .replaceAll('{{RELEASES_URL}}', `https://github.com/${repo}/releases/latest`)
  .replaceAll('{{REPO_SLUG}}', repo)
  .replaceAll('{{ROOT}}', rootRel);

function sectionsOf(body) {
  const re = /<section[^>]*\bid="([^"]+)"[^>]*>\s*<h2[^>]*>([\s\S]*?)<\/h2>/g;
  const list = [];
  let m;
  while ((m = re.exec(body))) list.push({ id: m[1], title: strip(m[2]) });
  return list;
}

const searchIndex = [];

function render(page) {
  const { meta, slug, file } = page;
  const kind = meta.layout || 'doc';
  const rootRel = '';
  const nav = navPages.map((p) => `<a href="{{ROOT}}${p.file}"${p.file === file ? ' aria-current="page"' : ''}>${esc(p.meta.nav)}</a>`).join('');
  const footNav = navPages.map((p) => `<a href="{{ROOT}}${p.file}">${esc(p.meta.nav)}</a>`).join('');
  let body = page.body;

  if (kind === 'doc') {
    const secs = sectionsOf(body);
    const i = navPages.findIndex((p) => p.file === file);
    const prev = navPages[i - 1];
    const next = navPages[i + 1];
    const editUrl = file === 'changelog.html'
      ? `https://github.com/${repo}/edit/main/CHANGELOG.md`
      : `https://github.com/${repo}/edit/main/site/pages/${file}`;
    body = `<section class="page-head">
  <p class="crumb"><a href="index.html">Docs</a><span>/</span>${esc(meta.nav || meta.title)}</p>
  <h1 class="page-title">${esc(meta.title)}</h1>
  ${meta.lead ? `<p class="lead">${esc(meta.lead)}</p>` : ''}
</section>
<div class="doc">
  <nav class="side" aria-label="On this page">
    <p class="side-h">On this page</p>
    ${secs.map((s) => `<a href="#${s.id}">${esc(s.title)}</a>`).join('\n    ')}
  </nav>
  <div class="doc-body">
${body}
    <nav class="pager" aria-label="Pages">
      ${prev ? `<a class="card pager-a" href="${prev.file}"><span><svg class="ic ic-sm"><use href="#i-arrow-l"/></svg>Previous</span><b>${esc(prev.meta.nav)}</b></a>` : '<span></span>'}
      ${next ? `<a class="card pager-a next" href="${next.file}"><span>Next<svg class="ic ic-sm"><use href="#i-arrow"/></svg></span><b>${esc(next.meta.nav)}</b></a>` : '<span></span>'}
    </nav>
    <p class="edit-link"><a href="${editUrl}">Edit this page on GitHub</a></p>
  </div>
</div>`;
    for (const s of secs) {
      const block = (body.match(new RegExp(`<section[^>]*id="${s.id}"[\\s\\S]*?</section>`)) || [''])[0];
      searchIndex.push({ page: meta.nav || meta.title, title: s.title, url: `${file}#${s.id}`, text: strip(block).slice(0, 600) });
    }
  } else if (kind === 'home') {
    searchIndex.push({ page: 'Overview', title: 'OryvexWorkerPanel', url: 'index.html', text: strip(body).slice(0, 600) });
  }

  const title = slug === 'index' ? 'OryvexWorkerPanel · Cloudflare Workers panel' : `${meta.title} · OryvexWorkerPanel`;
  const html = stamp(
    layout
      .replace('{{BODY}}', () => body)
      .replace('{{NAV}}', () => nav)
      .replace('{{FOOT_NAV}}', () => footNav)
      .replaceAll('{{PAGE_TITLE}}', esc(title))
      .replaceAll('{{DESCRIPTION}}', esc(meta.description || ''))
      .replaceAll('{{SLUG}}', slug)
      .replace('{{CANONICAL}}', siteUrl && slug !== '404' ? `<link rel="canonical" href="${siteUrl}${slug === 'index' ? '' : file}">` : ''),
    // 404.html is served from any depth, so it needs absolute asset paths
    slug === '404' && siteUrl ? new URL(siteUrl).pathname : rootRel
  );
  fs.writeFileSync(path.join(out, file), html);
}

for (const p of pages) render(p);

/* ------------------------------------------------------ error previews */
fs.mkdirSync(path.join(out, 'errors'), { recursive: true });
const previews = { 'kv-missing': 'KV_MISSING', 'kv-unavailable': 'KV_UNAVAILABLE', 'ui-bundle-missing': 'UI_BUNDLE_MISSING', 'sub-not-found': 'SUB_NOT_FOUND', internal: 'INTERNAL' };
for (const [file, code] of Object.entries(previews)) {
  fs.writeFileSync(path.join(out, 'errors', `${file}.html`), renderErrorPage(code, { host: 'your-worker.workers.dev', version: pkg.version, ref: 'PREVIEW', docsUrl: '../troubleshooting.html' }));
}

/* ------------------------------------------------- search, sitemap, misc */
fs.writeFileSync(path.join(out, 'assets', 'search-index.json'), JSON.stringify(searchIndex));
if (siteUrl) {
  const urls = navPages.map((p) => `  <url><loc>${siteUrl}${p.file === 'index.html' ? '' : p.file}</loc></url>`).join('\n');
  fs.writeFileSync(path.join(out, 'sitemap.xml'), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`);
  fs.writeFileSync(path.join(out, 'robots.txt'), `User-agent: *\nAllow: /\nSitemap: ${siteUrl}sitemap.xml\n`);
}
const apiBase = `https://api.github.com/repos/${repo}`;
const siteData = {
  ...dataTemplate,
  username: owner,
  owner,
  repo: name,
  repository: repo,
  repositoryUrl: `https://github.com/${repo}`,
  pagesUrl: siteUrl || null,
  api: {
    ...dataTemplate.api,
    owner: `https://api.github.com/users/${owner}`,
    repository: apiBase,
    releases: `${apiBase}/releases`,
    latestRelease: `${apiBase}/releases/latest`,
    tags: `${apiBase}/tags`,
  },
};
fs.writeFileSync(path.join(out, 'data.json'), `${JSON.stringify(siteData, null, 2)}\n`);
fs.writeFileSync(path.join(out, '.nojekyll'), '');
console.log(`docs built into _site/ for ${repo} · ${pages.length} pages · ${searchIndex.length} search entries`);
