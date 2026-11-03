#!/usr/bin/env node
// Post-build gate used by CI and the Release workflow: the bundle must parse, carry the
// package.json version on line 1 and point at the repository that built it.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { bundleVersion, looksLikeWorkerBundle } from '../src/updater.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = process.argv[2] ? path.resolve(process.argv[2]) : root;
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const fail = (m) => { console.error(`✗ ${m}`); process.exit(1); };

const worker = path.join(dir, 'worker-single-file.js');
const zip = path.join(dir, 'oryvex-worker-panel-pages.zip');
for (const f of [worker, zip]) if (!fs.existsSync(f) || fs.statSync(f).size === 0) fail(`missing ${path.basename(f)}`);

const code = fs.readFileSync(worker, 'utf8');
if (!looksLikeWorkerBundle(code)) fail('worker-single-file.js does not look like an ES module Worker');
const v = bundleVersion(code);
if (v !== pkg.version) fail(`bundle says v${v || '?'} but package.json says v${pkg.version}`);
const repo = process.env.GITHUB_REPOSITORY || process.env.ORYVEX_UPDATE_REPO;
if (repo && !code.slice(0, 300).includes(`github.com/${repo}`)) fail(`bundle banner does not point at ${repo}`);
try { execFileSync(process.execPath, ['--check', worker], { stdio: 'pipe' }); }
catch (e) {
  // `node --check` cannot parse ESM imports of `cloudflare:*`; fall back to a syntax-only parse.
  try { new Function(code.replace(/^\s*(import|export)\b.*$/gm, '')); } catch (err) { fail(`syntax error: ${err.message}`); }
}
console.log(`✓ worker-single-file.js v${v} · ${(code.length / 1024).toFixed(0)} KB · ${path.basename(zip)} ${(fs.statSync(zip).size / 1024).toFixed(0)} KB`);
