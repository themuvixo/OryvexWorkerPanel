#!/usr/bin/env node
// Prints the CHANGELOG.md section for a version (default: package.json version) as release notes.
// Falls back to the commit subjects since the previous tag when the CHANGELOG has no section.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const version = String(process.argv[2] || pkg.version).replace(/^v/i, '');
const log = fs.existsSync(path.join(root, 'CHANGELOG.md')) ? fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8') : '';

export function sectionFor(md, v) {
  const lines = md.split('\n');
  const esc = v.replace(/\./g, '\\.');
  const start = lines.findIndex((l) => new RegExp(`^##\\s+v?${esc}(\\s|$)`).test(l));
  if (start < 0) return '';
  let end = lines.findIndex((l, i) => i > start && /^##\s/.test(l));
  if (end < 0) end = lines.length;
  return lines.slice(start + 1, end).join('\n').trim();
}

function git(...args) {
  try { return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return ''; }
}

let body = sectionFor(log, version);
if (!body) {
  const prev = git('describe', '--tags', '--abbrev=0', '--match', 'v*', 'HEAD^');
  const range = prev ? `${prev}..HEAD` : 'HEAD';
  body = git('log', range, '--no-merges', '--pretty=format:- %s', '-n', '60')
    .split('\n').filter((l) => l && !/\[skip ci\]|chore\(release\)/i.test(l)).join('\n') || '- Maintenance release.';
}
const repo = process.env.GITHUB_REPOSITORY || pkg.oryvex?.updateRepo || '';
const footer = [
  '',
  '### Install',
  '- **Workers:** paste `worker-single-file.js` into the Worker editor (or use **Update** inside the panel).',
  '- **Pages:** upload `oryvex-worker-panel-pages.zip`.',
  '- Verify downloads with `SHA256SUMS.txt`.',
  repo ? `\nDocs: https://${repo.split('/')[0].toLowerCase()}.github.io/${repo.split('/')[1]}/` : '',
].join('\n');
process.stdout.write(`${body}\n${footer}\n`);
