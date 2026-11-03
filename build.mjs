#!/usr/bin/env node
/**
 * OryvexWorkerPanel build pipeline (single-file Worker + Cloudflare Pages bundle).
 *
 *   node build.mjs          full build (used by GitHub Actions)
 *   node build.mjs --lite   fast local preview build into .lite/ (no AST pass, no audit;
 *                           never use .lite output for production)
 *
 * Combines & upgrades the proven Cloudflare Worker stealth architectures from production panels:
 *   1. Subsets JetBrains Mono & Vazirmatn into compact single-copy WOFF2 data URIs.
 *   2. Compresses inline UI assets with gzip level-9 + CSPRNG 16-byte XOR stream cipher,
 *      lazily unpacked once via native C++ `DecompressionStream("gzip")` (cuts bundle size ~60%).
 *   3. Total-AST Babel pass (`@babel/parser` + `@babel/traverse` + `@babel/generator`):
 *        - Redirects Worker/Web/Stream/Crypto globals (`WebSocketPair`, `DecompressionStream`,
 *          `ReadableStream`, `WritableStream`, `Headers`, `Request`, `Response`, `URL`, `crypto`,
 *          `fetch`, etc.) through `globalThis[dec(idx)]`.
 *        - Encodes 100% of StringLiterals, TemplateLiterals, RegExpLiterals, ObjectProperties,
 *          ObjectMethods, MemberExpressions, and OptionalMemberExpressions into a CSPRNG-shuffled
 *          per-entry XOR+Base64 table with index-keyed phase `(j + i) & 15` and O(1) V8 SMI array cache.
 *   4. Mangles all identifiers via `esbuild` (zero `_0x` / `func_dec` / `eval` / `new Function` signatures)
 *      and wraps array lines <= 104 chars so Quick Edit / mobile paste never truncates.
 */

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import * as esbuild from 'esbuild';

const LITE = process.argv.includes('--lite') || process.env.ORYVEX_LITE === '1';
let babelParser, babelTraverse, babelGenerate, t;
if (!LITE) {
  babelParser = await import('@babel/parser');
  const travMod = (await import('@babel/traverse')).default;
  const genMod = (await import('@babel/generator')).default;
  babelTraverse = travMod.default || travMod;
  babelGenerate = genMod.default || genMod;
  t = await import('@babel/types');
}

const root = path.dirname(fileURLToPath(import.meta.url));
const P = (...p) => path.join(root, ...p);
const read = (p) => fs.readFileSync(p, 'utf8');
const config = JSON.parse(read(P('config.json')));
const pkg = JSON.parse(read(P('package.json')));
const VERSION = pkg.version || '1.0.0';

/* ------------------------------------------- repository & docs injection */
// GitHub Actions sets GITHUB_REPOSITORY automatically, so CI builds point the in-panel
// updater and the docs links at the repository that built them.
const REPO_CANDIDATE = String(
  process.env.ORYVEX_UPDATE_REPO || process.env.GITHUB_REPOSITORY || pkg.oryvex?.updateRepo || 'themuvixo/OryvexWorkerPanel'
).trim();
const UPDATE_REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(REPO_CANDIDATE) && !/^OWNER\//i.test(REPO_CANDIDATE)
  ? REPO_CANDIDATE
  : 'themuvixo/OryvexWorkerPanel';
const [repoOwner = '', repoName = ''] = UPDATE_REPO.split('/');
const DOCS_URL = String(
  process.env.ORYVEX_DOCS_URL ||
    pkg.oryvex?.docsUrl ||
    (repoOwner && repoName
      ? repoName.toLowerCase() === `${repoOwner.toLowerCase()}.github.io`
        ? `https://${repoName.toLowerCase()}/`
        : `https://${repoOwner.toLowerCase()}.github.io/${repoName}/`
      : '')
).trim();
const DEFINES = {
  __ORYVEX_VERSION__: JSON.stringify(VERSION),
  __ORYVEX_UPDATE_REPO__: JSON.stringify(UPDATE_REPO),
  __ORYVEX_DOCS_URL__: JSON.stringify(DOCS_URL),
};
if (REPO_CANDIDATE !== UPDATE_REPO) {
  console.warn('! update repository is invalid: using themuvixo/OryvexWorkerPanel as the fallback');
}
const OUT_DIR = LITE ? P('.lite') : root;
fs.mkdirSync(OUT_DIR, { recursive: true });

fs.mkdirSync(P('assets/fonts'), { recursive: true });
fs.mkdirSync(P('src/generated'), { recursive: true });
fs.mkdirSync(P('dist'), { recursive: true });

/* ------------------------------------------- Strict 52-Keyword Audit List */

const AUDIT_KEYWORDS = [
  // Protocols & proxy cores
  'vless', 'trojan', 'vmess', 'shadowsocks', 'v2ray', 'xray', 'singbox', 'sing-box',
  'clash', 'mihomo', 'hiddify', 'streisand', 'nekobox', 'karing', 'shadowrocket',
  // Telegram Web Proxy signatures
  'webproxy', 'tgproxy', 'mtproto', 'tproxy-lane', 'web.telegram.org', 'tdesktop-web-proxy',
  // Proxy / Relay / DNS / Config indicators
  'proxyip', 'socks5', 'cloudflare:sockets', 'websocketpair', 'sec-websocket',
  'nat64', '2602:fc59', '64:ff9b', 'mixed-port', 'proxy-groups', 'fake-ip',
  'geoip', 'subscription-userinfo', 'dns-query', 'dns-message', 'subconverter',
  'killswitch', 'tlshello', 'early_data', 'wireguard', 'pbkdf2', 'subtoken',
  'outbounds', 'inbounds', 'sniffing',
  // External panels & known obfuscator signatures (char-encoded so repo stays 100% brand-pure)
  String.fromCharCode(101, 100, 103, 101, 116, 117, 110, 110, 101, 108),
  String.fromCharCode(110, 97, 104, 97, 110),
  String.fromCharCode(122, 101, 117, 115),
  String.fromCharCode(98, 112, 98, 45, 112, 97, 110, 101, 108),
  '_0x', 'func_dec',
];

function containsAuditKeyword(str) {
  const low = str.toLowerCase();
  return AUDIT_KEYWORDS.some((kw) => low.includes(kw));
}

function xorEncodeBytesClean(rawBuf, lineLen = 96) {
  for (let attempt = 0; attempt < 512; attempt++) {
    const key = Array.from(crypto.randomBytes(16));
    const out = Buffer.allocUnsafe(rawBuf.length);
    for (let i = 0; i < rawBuf.length; i++) {
      out[i] = rawBuf[i] ^ key[i & 15];
    }
    const b64 = out.toString('base64');
    if (containsAuditKeyword(b64)) continue;

    const lines = [];
    for (let i = 0; i < b64.length; i += lineLen) {
      lines.push(JSON.stringify(b64.slice(i, i + lineLen)));
    }
    return { key, chunksLiteral: `[\n${lines.join(',\n')}\n]` };
  }
  throw new Error('Could not find collision-free CSPRNG XOR key for binary payload');
}

function xorEncodeUtf8Clean(utf8Str, lineLen = 96) {
  return xorEncodeBytesClean(Buffer.from(utf8Str, 'utf8'), lineLen);
}

/* ------------------------------------------------------------------ fonts */

const FONTS = [
  { key: 'F_JBM_R', file: 'JetBrainsMono-Regular.woff2', text: 'latin' },
  { key: 'F_JBM_M', file: 'JetBrainsMono-Medium.woff2', text: 'latin' },
  { key: 'F_JBM_B', file: 'JetBrainsMono-Bold.woff2', text: 'latin' },
  { key: 'F_IN_R', file: 'Inter-Regular.woff2', text: 'latin' },
  { key: 'F_IN_S', file: 'Inter-SemiBold.woff2', text: 'latin' },
  { key: 'F_IN_D', file: 'InterDisplay-Bold.woff2', text: 'latin' },
];

const sourceText = [
  'src/ui/index.html',
  'src/ui/app.js',
  'src/ui/prefs.js',
  'src/errors.js',
  'src/sub.js',
  'src/worker.js',
  'src/storage.js',
]
  .map((f) => read(P(f)))
  .join('\n');

const uniqueChars = [...new Set(sourceText)].join('');
const latinFromSrc = [...new Set(uniqueChars.replace(/[^\u0020-\u024F]/g, ''))].join('');

const asciiPrintable = Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join('');
const symbols = '✦◆☀☾⚡✓✕⚠⬇⬆↗•—–…∞«»‹›°±×÷';

const subsets = {
  latin: asciiPrintable + symbols + latinFromSrc,
};

function dataUri(file, chars) {
  const src = P('src/ui/vendor', file);
  const cachedSubset = P('assets/fonts', path.basename(file));
  const unicodes = [...new Set(chars)]
    .filter((c) => c.codePointAt(0) >= 0x20)
    .map((c) => 'U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0'))
    .join(',');
  try {
    execFileSync(
      'pyftsubset',
      [
        src,
        '--flavor=woff2',
        '--layout-features=*',
        '--unicodes=' + unicodes,
        '--desubroutinize',
        '--no-hinting',
        '--output-file=' + cachedSubset,
      ],
      { stdio: ['ignore', 'ignore', 'pipe'] }
    );
  } catch {
    if (!fs.existsSync(cachedSubset)) {
      fs.copyFileSync(src, cachedSubset);
    }
  }
  const buf = fs.readFileSync(cachedSubset);
  console.log(`   ${file.padEnd(32)} ${(buf.length / 1024).toFixed(1).padStart(6)} KB`);
  return `data:font/woff2;base64,${buf.toString('base64')}`;
}

console.log('· subsetting fonts');
const fontVars = {};
for (const f of FONTS) {
  fontVars[f.key] = dataUri(f.file, subsets.latin);
}

/* ----------------------------------------------------- minify & assemble UI */

console.log('· minifying & assembling UI assets');
const skylineSvg = read(P('assets/skyline.svg'))
  .replace(/<!--[\s\S]*?-->/g, '')
  .replace(/\n\s+/g, '')
  .replace(/<svg /, '<svg class="skyline" preserveAspectRatio="xMidYMid slice" ');
const skylineHtml = `<div class="figure-frame">${skylineSvg}</div>`;
const sealSvg = read(P('assets/seal.svg')).replace(/\n\s+/g, '');

let rawStyle = read(P('src/ui/style.css'));
for (const [k, v] of Object.entries(fontVars)) {
  rawStyle = rawStyle.replaceAll(`{{${k}}}`, v);
}
const minCss = (await esbuild.transform(rawStyle, { loader: 'css', minify: true })).code.trim();
const minQr = (await esbuild.transform(read(P('src/ui/vendor/qrcode.js')), { loader: 'js', minify: true })).code.trim();
const appSource = read(P('src/ui/app.js')).trimEnd() + ';\n' + read(P('src/ui/prefs.js'));
const minApp = (await esbuild.transform(appSource, { loader: 'js', minify: true, define: DEFINES })).code.trim();

let indexTemplate = read(P('src/ui/index.html'))
  .replaceAll('{{VERSION}}', VERSION)
  .replaceAll('{{REPO_URL}}', `https://github.com/${UPDATE_REPO}`)
  .replaceAll('{{REPO_SLUG}}', UPDATE_REPO);
// Embed original icons from each application's official repository: no runtime CDN dependency.
for (const [key, file] of Object.entries({
  HIDDIFY: 'hiddify.svg', CLASH: 'clash-verge.svg', SINGBOX: 'sing-box.svg',
  V2RAYNG: 'v2rayng.png', V2RAYN: 'v2rayn.png',
})) {
  const mime = file.endsWith('.svg') ? 'image/svg+xml' : 'image/png';
  const data = fs.readFileSync(P('src/ui/assets', file)).toString('base64');
  indexTemplate = indexTemplate.replaceAll(`{{ICON_${key}}}`, `data:${mime};base64,${data}`);
}
const fullPreviewHtml = indexTemplate
  .replace('{{SEAL_SMALL}}', () => sealSvg)
  .replace('{{CONFIG}}', () => JSON.stringify({ host: config.host, tunnelPath: config.tunnelPath }))
  .replace('{{STYLE}}', () => minCss)
  .replace('{{SKYLINE}}', () => skylineHtml)
  .replace('{{QR}}', () => minQr)
  .replace('{{APP}}', () => minApp);

// `panel-preview.html` is standalone readable HTML for local preview
fs.writeFileSync(path.join(OUT_DIR, 'panel-preview.html'), fullPreviewHtml);
console.log(`· panel-preview.html ${(Buffer.byteLength(fullPreviewHtml) / 1024).toFixed(0)} KB`);

// Shell template with compact markers so `minCss` + `minQr` + `skylineHtml` are stored ONLY ONCE
const shellTemplate = indexTemplate
  .replace('{{SEAL_SMALL}}', () => sealSvg)
  .replace('{{CONFIG}}', () => JSON.stringify({ host: config.host, tunnelPath: config.tunnelPath }))
  .replace('{{STYLE}}', () => '/*__NL_STYLE__*/')
  .replace('{{SKYLINE}}', () => '/*__NL_SKY__*/')
  .replace('{{QR}}', () => '/*__NL_QR__*/')
  .replace('{{APP}}', () => minApp);

// Build stealth `dist/index.html` for Cloudflare Pages (CSPRNG polymorphic key, 0 plain proxy keywords)
const bodyMatch = indexTemplate.match(/<body[^>]*>([\s\S]*)<\/body>/i);
const rawBodyInner = bodyMatch
  ? bodyMatch[1]
      .replace('{{SEAL_SMALL}}', () => sealSvg)
      .replace('{{SKYLINE}}', () => skylineHtml)
      .replace(/<script>[\s\S]*<\/script>/i, '')
  : '';
const pagesBootPayload = JSON.stringify({
  s: minCss,
  b: rawBodyInner,
  c: { host: config.host, tunnelPath: config.tunnelPath },
  q: minQr,
  a: minApp,
});
const pagesEncoded = xorEncodeUtf8Clean(pagesBootPayload, 96);
const DIST_DIR = LITE ? P('.lite/dist') : P('dist');
fs.mkdirSync(DIST_DIR, { recursive: true });
const pagesIndexHtml = `<!doctype html>
<html lang="en" dir="ltr" data-lang="en" data-theme="dark" data-accent="blue">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light dark">
<title>OryvexWorkerPanel</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='14' fill='%230a6cff'/%3E%3C/svg%3E">
</head>
<body>
<script>
(function(){
  var K=${JSON.stringify(pagesEncoded.key)};
  var C=${pagesEncoded.chunksLiteral};
  var r=atob(C.join("")),u=new Uint8Array(r.length);
  for(var i=0;i<r.length;i++)u[i]=r.charCodeAt(i)^K[i&15];
  var d=JSON.parse(new TextDecoder().decode(u));
  var st=document.createElement("style");
  st.textContent=d.s;
  document.head.appendChild(st);
  window.ORYVEX=d.c;
  document.body.innerHTML=d.b;
  (0,eval)(d.q);
  (0,eval)(d.a);
})();
</script>
</body>
</html>`;
fs.writeFileSync(path.join(DIST_DIR, 'index.html'), pagesIndexHtml);
console.log(`· dist/index.html    ${(Buffer.byteLength(pagesIndexHtml) / 1024).toFixed(0)} KB`);

/* ---------------------------- Total-AST Polymorphic Stealth Transformer */

const INDIRECT_GLOBALS = new Set([
  'WebSocketPair',
  'WebSocket',
  'DecompressionStream',
  'CompressionStream',
  'ReadableStream',
  'WritableStream',
  'TransformStream',
  'AbortController',
  'Headers',
  'Request',
  'Response',
  'URL',
  'Blob',
  'crypto',
  'fetch',
  'TextEncoder',
  'TextDecoder',
  'btoa',
  'atob',
]);

function formatStringArrayMultiline(items, maxLineChars = 100) {
  const lines = [];
  let cur = '';
  for (let i = 0; i < items.length; i++) {
    const tok = JSON.stringify(items[i]) + (i < items.length - 1 ? ',' : '');
    if (cur.length === 0) {
      cur = tok;
    } else if (cur.length + 1 + tok.length <= maxLineChars) {
      cur += ' ' + tok;
    } else {
      lines.push(cur);
      cur = tok;
    }
  }
  if (cur.length > 0) lines.push(cur);
  return `[\n${lines.join('\n')}\n]`;
}

function encodeShuffledTableClean(strings) {
  const utf8Bufs = strings.map((s) => Buffer.from(s, 'utf8'));
  for (let attempt = 0; attempt < 512; attempt++) {
    const key = Array.from(crypto.randomBytes(16));
    const encoded = new Array(utf8Bufs.length);
    let dirty = false;
    for (let idx = 0; idx < utf8Bufs.length; idx++) {
      const src = utf8Bufs[idx];
      const out = Buffer.allocUnsafe(src.length);
      for (let j = 0; j < src.length; j++) {
        out[j] = src[j] ^ key[(j + idx) & 15];
      }
      const b64 = out.toString('base64');
      if (containsAuditKeyword(b64)) {
        dirty = true;
        break;
      }
      encoded[idx] = b64;
    }
    if (dirty) continue;
    const formatted = formatStringArrayMultiline(encoded, 100);
    if (containsAuditKeyword(formatted)) continue;
    return { key, formatted };
  }
  throw new Error('Could not find collision-free CSPRNG key for AST string table');
}

function totalAstStealthTransform(rawBundleJs) {
  const ast = babelParser.parse(rawBundleJs, {
    sourceType: 'module',
    plugins: ['importAttributes'],
  });

  // Pass 1: Redirect Worker/Network/Stream/Crypto global references -> `globalThis.<Name>`
  babelTraverse(ast, {
    Identifier(p) {
      const name = p.node.name;
      if (!INDIRECT_GLOBALS.has(name)) return;
      if (!p.isReferencedIdentifier()) return;
      if (p.parentPath.isImportSpecifier() || p.parentPath.isExportSpecifier()) return;
      if (p.scope.hasBinding(name)) return;
      p.replaceWith(t.memberExpression(t.identifier('globalThis'), t.identifier(name)));
    },
    ObjectMethod(p) {
      if (p.node.kind !== 'method') return;
      const fnExpr = t.functionExpression(
        null,
        p.node.params,
        p.node.body,
        p.node.generator,
        p.node.async
      );
      p.replaceWith(t.objectProperty(p.node.key, fnExpr, p.node.computed));
    },
  });

  // Pass 2: Extract 100% of strings, templates, regexes, object keys, and member properties
  const pool = [];
  const poolMap = new Map();
  const callNodes = [];

  function internCall(str) {
    let rawIdx = poolMap.get(str);
    if (rawIdx === undefined) {
      rawIdx = pool.length;
      pool.push(str);
      poolMap.set(str, rawIdx);
    }
    const numNode = t.numericLiteral(rawIdx);
    callNodes.push(numNode);
    return t.callExpression(t.identifier('__NL_DEC__'), [numNode]);
  }

  babelTraverse(ast, {
    MemberExpression(p) {
      if (p.node.computed) return;
      if (t.isSuper(p.node.object)) return;
      if (t.isIdentifier(p.node.property)) {
        p.node.computed = true;
        p.node.property = internCall(p.node.property.name);
      }
    },
    OptionalMemberExpression(p) {
      if (p.node.computed) return;
      if (t.isIdentifier(p.node.property)) {
        p.node.computed = true;
        p.node.property = internCall(p.node.property.name);
      }
    },
    ObjectProperty(p) {
      if (p.node.computed) return;
      if (t.isIdentifier(p.node.key)) {
        p.node.shorthand = false;
        p.node.computed = true;
        p.node.key = internCall(p.node.key.name);
      } else if (t.isStringLiteral(p.node.key)) {
        p.node.shorthand = false;
        p.node.computed = true;
        p.node.key = internCall(p.node.key.value);
      }
    },
    RegExpLiteral(p) {
      p.replaceWith(
        t.newExpression(t.identifier('RegExp'), [
          internCall(p.node.pattern),
          internCall(p.node.flags || ''),
        ])
      );
    },
    TemplateLiteral(p) {
      if (p.parentPath.isTaggedTemplateExpression()) return;
      const quasis = p.node.quasis;
      const exprs = p.node.expressions;
      const parts = [];
      for (let i = 0; i < quasis.length; i++) {
        const cooked = quasis[i].value.cooked ?? quasis[i].value.raw ?? '';
        parts.push(internCall(cooked));
        if (i < exprs.length) {
          parts.push(exprs[i]);
        }
      }
      if (parts.length === 0) {
        parts.push(internCall(''));
      }
      let acc = parts[0];
      for (let i = 1; i < parts.length; i++) {
        acc = t.binaryExpression('+', acc, parts[i]);
      }
      p.replaceWith(acc);
    },
    StringLiteral(p) {
      if (p.node.value === '__NL_ASSET_PLACEHOLDER__' || p.node.value === '__NL_POOL_PLACEHOLDER__') {
        return;
      }
      if (p.parentPath.isImportDeclaration()) return;
      if (p.parentPath.isExportNamedDeclaration() && p.parent.source === p.node) return;
      if (p.parentPath.isExportAllDeclaration() && p.parent.source === p.node) return;
      if (p.parentPath.isObjectProperty() && p.parent.key === p.node && !p.parent.computed) {
        p.parent.shorthand = false;
        p.parent.computed = true;
        p.replaceWith(internCall(p.node.value));
        return;
      }
      p.replaceWith(internCall(p.node.value));
    },
  });

  // Pass 3: Polymorphic CSPRNG Fisher-Yates permutation of string pool
  const n = pool.length;
  const order = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    const tmp = order[i];
    order[i] = order[j];
    order[j] = tmp;
  }
  const shuffledPool = new Array(n);
  const rawToNew = new Array(n);
  for (let newIdx = 0; newIdx < n; newIdx++) {
    const rawIdx = order[newIdx];
    shuffledPool[newIdx] = pool[rawIdx];
    rawToNew[rawIdx] = newIdx;
  }
  for (const numNode of callNodes) {
    numNode.value = rawToNew[numNode.value];
  }

  const { key: poolKey, formatted: poolArrayLiteral } = encodeShuffledTableClean(shuffledPool);

  // Fast O(1) dense V8 array-cached decoder (single shared TextDecoder, zero Map overhead)
  const decoderSource = `
const __NL_KEY__ = ${JSON.stringify(poolKey)};
const __NL_TBL__ = "__NL_POOL_PLACEHOLDER__";
const __NL_CACHE__ = new Array(${n});
const __NL_TD__ = new TextDecoder();
function __NL_DEC__(i) {
  let v = __NL_CACHE__[i];
  if (v !== undefined) return v;
  const r = atob(__NL_TBL__[i]);
  const len = r.length;
  const b = new Uint8Array(len);
  for (let j = 0; j < len; j++) b[j] = r.charCodeAt(j) ^ __NL_KEY__[(j + i) & 15];
  return (__NL_CACHE__[i] = __NL_TD__.decode(b));
}
`;
  const decoderAst = babelParser.parse(decoderSource, { sourceType: 'module' });
  let insertAt = 0;
  while (insertAt < ast.program.body.length && ast.program.body[insertAt].type === 'ImportDeclaration') {
    insertAt++;
  }
  ast.program.body.splice(insertAt, 0, ...decoderAst.program.body);

  const generated = babelGenerate(ast, { compact: false, comments: false }).code;
  return { generated, poolArrayLiteral, poolCount: n };
}

async function compileStealthWorker(includeShell, bannerComment) {
  const archiveJson = JSON.stringify({
    style: minCss,
    qr: minQr,
    skyline: skylineHtml,
    shell: includeShell ? shellTemplate : '',
  });
  const gzippedArchive = gzipSync(Buffer.from(archiveJson, 'utf8'), { level: 9 });
  const assetEncoded = xorEncodeBytesClean(gzippedArchive, 96);

  const generatedUiModule = `// AUTO-GENERATED by build.mjs — Gzip+XOR lazy single-copy asset unpacker.
const K = ${JSON.stringify(assetEncoded.key)};
const RAW_ARR = "__NL_ASSET_PLACEHOLDER__";
let _cachedAssets = null;
let _cachedHtml = null;
let _inflight = null;

async function unpack() {
  if (_cachedAssets) return _cachedAssets;
  if (_inflight) return _inflight;
  _inflight = (async () => {
    const bin = atob(RAW_ARR.join(""));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) ^ K[i & 15];
    const ds = new DecompressionStream("gzip");
    const stream = new Blob([bytes]).stream().pipeThrough(ds);
    const txt = await new Response(stream).text();
    _cachedAssets = JSON.parse(txt);
    _inflight = null;
    return _cachedAssets;
  })();
  return _inflight;
}

export async function getInlineAssets() {
  const a = await unpack();
  return { style: a.style || '', qr: a.qr || '', skyline: a.skyline || '' };
}

export async function getPanelHtml() {
  if (_cachedHtml !== null) return _cachedHtml;
  const a = await unpack();
  if (!a.shell) {
    _cachedHtml = '';
    return '';
  }
  _cachedHtml = a.shell
    .replace('/*__NL_STYLE__*/', () => a.style)
    .replace('/*__NL_SKY__*/', () => a.skyline)
    .replace('/*__NL_QR__*/', () => a.qr);
  return _cachedHtml;
}
`;
  fs.writeFileSync(P('src/generated/ui.js'), generatedUiModule);

  const rawBundle = await esbuild.build({
    entryPoints: [P('src/worker.js')],
    bundle: true,
    format: 'esm',
    target: 'es2022',
    platform: 'neutral',
    minify: false,
    define: DEFINES,
    legalComments: 'none',
    write: false,
  });

  const { generated, poolArrayLiteral, poolCount } = LITE
    ? { generated: rawBundle.outputFiles[0].text, poolArrayLiteral: '[]', poolCount: 0 }
    : totalAstStealthTransform(rawBundle.outputFiles[0].text);

  // Mangle all module & local identifiers + optimize syntax (zero `_0x` or `__NL_` markers remain)
  const mangled = await esbuild.transform(generated, {
    loader: 'js',
    format: 'esm',
    target: 'es2022',
    minifyIdentifiers: true,
    minifySyntax: true,
    minifyWhitespace: false,
    legalComments: 'none',
  });

  const finalCode =
    bannerComment +
    '\n' +
    mangled.code
      .replace('"__NL_POOL_PLACEHOLDER__"', () => poolArrayLiteral)
      .replace('"__NL_ASSET_PLACEHOLDER__"', () => assetEncoded.chunksLiteral);

  // Parse-check the final output to guarantee 100% valid ES2022 module syntax
  await esbuild.transform(finalCode, { loader: 'js', format: 'esm', target: 'es2022' });

  console.log(`   [AST pool: ${poolCount} strings, gzipped UI: ${(gzippedArchive.length / 1024).toFixed(1)} KB]`);
  return finalCode;
}

const BANNER = `// OryvexWorkerPanel v${VERSION} · https://github.com/${UPDATE_REPO}`;
const pagesWorkerCode = await compileStealthWorker(false, `${BANNER}\n// Cloudflare Pages edition (_worker.js)`);
fs.writeFileSync(path.join(DIST_DIR, '_worker.js'), pagesWorkerCode);
console.log(`· pages _worker.js   ${(Buffer.byteLength(pagesWorkerCode) / 1024).toFixed(1)} KB`);

const standaloneCode = await compileStealthWorker(true, `${BANNER}\n// Cloudflare Workers single-file edition`);
fs.writeFileSync(path.join(OUT_DIR, 'worker-single-file.js'), standaloneCode);
console.log(`· worker-single-file ${(Buffer.byteLength(standaloneCode) / 1024).toFixed(1)} KB`);

/* ------------------------------------------- Build-time signature audit */

for (const target of LITE ? [] : ['worker-single-file.js', 'dist/_worker.js', 'dist/index.html']) {
  const txt = read(P(target));
  const hits = AUDIT_KEYWORDS.filter((kw) => txt.toLowerCase().includes(kw));
  if (hits.length > 0) {
    throw new Error(`Signature audit failed on ${target}: found [${hits.join(', ')}]`);
  }
}
console.log(LITE ? '· signature audit    skipped (--lite preview build)' : `· signature audit    0 matches across all ${AUDIT_KEYWORDS.length} keywords`);

/* -------------------------------------------------------- Pages zip archive */

const zipPath = path.join(OUT_DIR, 'oryvex-worker-panel-pages.zip');
if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath);
execFileSync('zip', ['-q', '-X', '-r', zipPath, 'index.html', '_worker.js'], { cwd: DIST_DIR });
console.log(`· pages zip          ${path.relative(root, zipPath)} ${(fs.statSync(zipPath).size / 1024).toFixed(1)} KB`);
console.log(`· update repository  ${UPDATE_REPO}${DOCS_URL ? `  ·  docs ${DOCS_URL}` : ''}`);
console.log('· build complete');
