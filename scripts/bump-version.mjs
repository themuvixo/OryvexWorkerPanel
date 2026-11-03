#!/usr/bin/env node
// node scripts/bump-version.mjs <patch|minor|major|X.Y.Z>
// Updates package.json, package-lock.json and the dev fallback in src/storage.js, and adds a
// CHANGELOG.md section (from commit subjects since the last tag) when one does not exist yet.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const P = (f) => path.join(root, f);
const arg = String(process.argv[2] || 'patch').trim();
const pkg = JSON.parse(fs.readFileSync(P('package.json'), 'utf8'));
const [ma, mi, pa] = pkg.version.split('.').map((n) => parseInt(n, 10) || 0);
const next =
  arg === 'major' ? `${ma + 1}.0.0` :
  arg === 'minor' ? `${ma}.${mi + 1}.0` :
  arg === 'patch' ? `${ma}.${mi}.${pa + 1}` :
  /^\d+\.\d+\.\d+$/.test(arg.replace(/^v/, '')) ? arg.replace(/^v/, '') : null;
if (!next) { console.error(`unknown bump "${arg}"`); process.exit(1); }

pkg.version = next;
fs.writeFileSync(P('package.json'), JSON.stringify(pkg, null, 2) + '\n');
if (fs.existsSync(P('package-lock.json'))) {
  const lock = JSON.parse(fs.readFileSync(P('package-lock.json'), 'utf8'));
  lock.version = next;
  if (lock.packages && lock.packages['']) lock.packages[''].version = next;
  fs.writeFileSync(P('package-lock.json'), JSON.stringify(lock, null, 2) + '\n');
}
const st = fs.readFileSync(P('src/storage.js'), 'utf8')
  .replace(/(__ORYVEX_VERSION__ : ')\d+\.\d+\.\d+(')/, `$1${next}$2`);
fs.writeFileSync(P('src/storage.js'), st);

const log = fs.existsSync(P('CHANGELOG.md')) ? fs.readFileSync(P('CHANGELOG.md'), 'utf8') : '# Changelog\n';
if (!new RegExp(`^##\\s+v?${next.replace(/\./g, '\\.')}(\\s|$)`, 'm').test(log)) {
  let lines = '';
  try {
    const prev = execFileSync('git', ['describe', '--tags', '--abbrev=0', '--match', 'v*'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    lines = execFileSync('git', ['log', `${prev}..HEAD`, '--no-merges', '--pretty=format:- %s'], { cwd: root, encoding: 'utf8' })
      .split('\n').filter((l) => l && !/\[skip ci\]|chore\(release\)/i.test(l)).join('\n');
  } catch {}
  const section = `## v${next}\n${lines || '- Maintenance release.'}\n\n`;
  const out = log.replace(/^(# Changelog\s*\n+)/, `$1${section}`);
  fs.writeFileSync(P('CHANGELOG.md'), out === log ? `# Changelog\n\n${section}${log}` : out);
}
console.log(next);
