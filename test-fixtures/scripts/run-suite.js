const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const fixturesRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(fixturesRoot, '..');
const cliPath = path.join(repoRoot, 'dist', 'cli.js');
const generatedManifestFixture = 'npm-registry-signals';

const suites = {
  core: [
    { name: 'license-edge-cases', manager: 'npm', offline: true },
    { name: 'execution-signals', manager: 'npm', offline: true },
    { name: 'usage-classification', manager: 'npm', offline: true },
    { name: 'pnpm-license-resolution', manager: 'pnpm', offline: true },
    { name: 'pnpm-installed-only', manager: 'pnpm', offline: true },
    { name: 'pnpm-workspace', manager: 'pnpm', offline: true },
    { name: 'pnpm-workspace-hoisted', manager: 'pnpm', offline: true },
    { name: 'yarn-workspace', manager: 'yarn', offline: true },
    { name: 'no-node-modules', manager: null, offline: true }
  ],
  online: [
    { name: 'npm-registry-signals', manager: 'npm', offline: false }
  ]
};

function run(cmd, args, cwd, allowFailure = false) {
  const label = `${cmd} ${args.join(' ')}`;
  console.log(`\n> [${path.basename(cwd)}] ${label}`);
  const result = spawnSync(cmd, args, {
    cwd,
    stdio: 'inherit',
    env: process.env,
    shell: false
  });
  const code = typeof result.status === 'number' ? result.status : 1;
  if (!allowFailure && code !== 0) {
    throw new Error(`Command failed (${code}): ${label}`);
  }
  return code;
}

function usage() {
  console.error('Usage: node scripts/run-suite.js <install|scan> <core|online>');
  process.exit(1);
}

function materializeFixtureManifest(fixtureName, fixtureDir) {
  if (fixtureName !== generatedManifestFixture) return;
  const source = path.join(fixtureDir, 'fixture-manifest.json');
  const target = path.join(fixtureDir, 'package.json');
  fs.copyFileSync(source, target);
}

const action = process.argv[2];
const suiteName = process.argv[3] || 'core';
if (!action || !['install', 'scan'].includes(action)) usage();
const fixtures = suites[suiteName];
if (!fixtures) usage();

for (const fixture of fixtures) {
  const fixtureDir = path.join(fixturesRoot, fixture.name);
  materializeFixtureManifest(fixture.name, fixtureDir);
  if (action === 'install') {
    if (!fixture.manager) {
      console.log(`\n> [${fixture.name}] install skipped`);
      continue;
    }
    run(fixture.manager, ['install'], fixtureDir);
    continue;
  }

  const outPath = path.join(fixtureDir, 'dependency-radar.json');
  const args = [
    cliPath,
    'scan',
    '--project',
    fixtureDir,
    '--out',
    outPath,
    '--json',
    '--keep-temp'
  ];
  if (fixture.offline) args.push('--offline');

  if (fs.existsSync(outPath)) {
    fs.rmSync(outPath, { recursive: true, force: true });
  }

  run('node', args, repoRoot);
}

console.log(`\n✔ Suite action complete: ${action} (${suiteName})`);
