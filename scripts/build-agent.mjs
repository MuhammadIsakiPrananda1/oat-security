#!/usr/bin/env node
/**
 * Cross-compiles the Go endpoint agent (agent/) for every supported platform
 * into agent/dist/ and regenerates agent/dist/SHA256SUMS.
 *
 *   npm run agent:build
 *
 * Requires the Go toolchain (see agent/go.mod, go 1.22).
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const AGENT_DIR = path.join(ROOT, 'agent');
const DIST_DIR = path.join(AGENT_DIR, 'dist');

const TARGETS = [
  { goos: 'linux', goarch: 'amd64', out: 'oat-agent-linux-amd64' },
  { goos: 'linux', goarch: 'arm64', out: 'oat-agent-linux-arm64' },
  { goos: 'windows', goarch: 'amd64', out: 'oat-agent-windows-amd64.exe' },
  { goos: 'windows', goarch: 'arm64', out: 'oat-agent-windows-arm64.exe' }
];

const MANIFEST = 'SHA256SUMS';

// Preflight — verify the toolchain before touching dist/ so an aborted run
// leaves the previously published artifacts intact.
for (const tool of ['go']) {
  const probe = spawnSync(tool, ['version'], { stdio: 'ignore' });
  if (probe.error || probe.status !== 0) {
    console.error('[agent:build] The Go toolchain is required but was not found on PATH.');
    process.exit(1);
  }
}

// Fresh staging area — every artifact is rebuilt from the current source.
rmSync(DIST_DIR, { recursive: true, force: true });
mkdirSync(DIST_DIR, { recursive: true });

// The installer scripts are platform-agnostic; agent/dist is where the
// console serves them for download by enrolled endpoints.
copyFileSync(path.join(AGENT_DIR, 'install.sh'), path.join(DIST_DIR, 'install.sh'));
copyFileSync(path.join(AGENT_DIR, 'install.ps1'), path.join(DIST_DIR, 'install.ps1'));

for (const { goos, goarch, out } of TARGETS) {
  const res = spawnSync('go', ['build', '-trimpath', '-o', path.join(DIST_DIR, out), '.'], {
    cwd: AGENT_DIR,
    env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: '0' },
    stdio: 'inherit'
  });
  if (res.status !== 0) {
    console.error(`[agent:build] Command failed for ${goos}/${goarch} (exit ${res.status}).`);
    process.exit(res.status ?? 1);
  }
}

// Released manifest layout: the manifest hashes the installers and each agent
// binary. (It must not list itself — a file cannot contain its own hash.)
const entries = [
  'install.ps1',
  'install.sh',
  ...TARGETS.map(t => t.out)
];

const manifest = path.join(DIST_DIR, MANIFEST);
const lines = entries.map(
  name => `${createHash('sha256').update(readFileSync(path.join(DIST_DIR, name))).digest('hex')}  ${name}\n`
);
writeFileSync(manifest, lines.join(''));

console.log(`[agent:build] Wrote ${entries.length} artifacts to agent/dist — SHA256SUMS refreshed.`);
