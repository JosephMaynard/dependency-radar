const fs = require('fs');
const path = require('path');

const fixturesRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(fixturesRoot, '..');
const cliPath = path.join(repoRoot, 'dist', 'cli.js');

const suites = {
  core: [
    'license-edge-cases',
    'execution-signals',
    'usage-classification',
    'pnpm-license-resolution',
    'pnpm-installed-only',
    'pnpm-workspace',
    'pnpm-workspace-hoisted',
    'yarn-workspace',
    'no-node-modules'
  ],
  online: ['npm-registry-signals']
};

const failures = [];

function assert(condition, message) {
  if (!condition) failures.push(message);
}

function loadReport(fixtureName) {
  const reportPath = path.join(fixturesRoot, fixtureName, 'dependency-radar.json');
  if (!fs.existsSync(reportPath)) {
    failures.push(`[${fixtureName}] missing report: ${reportPath}`);
    return null;
  }
  try {
    const reportRaw = fs.readFileSync(reportPath, 'utf8');
    return JSON.parse(reportRaw);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    failures.push(`[${fixtureName}] invalid report: ${errorMessage}`);
    return null;
  }
}

function getDependencies(report) {
  return Object.values((report && report.dependencies) || {});
}

function checkPnpmLicenseResolution() {
  const fixtureName = 'pnpm-license-resolution';
  const report = loadReport(fixtureName);
  if (!report) return;
  const deps = getDependencies(report);
  const zustand = deps.filter((entry) => entry && entry.package && entry.package.name === 'zustand');
  assert(zustand.length > 0, `[${fixtureName}] expected zustand to be present`);
  for (const entry of zustand) {
    const license = entry && entry.compliance && entry.compliance.license;
    const declared = license && license.declared;
    assert(Boolean(license), `[${fixtureName}] zustand is missing compliance.license`);
    assert(license && license.status !== 'unknown', `[${fixtureName}] zustand license unexpectedly unknown`);
    assert(declared && declared.valid === true, `[${fixtureName}] zustand declared license is not valid SPDX`);
    assert(declared && declared.spdxId === 'MIT', `[${fixtureName}] zustand declared SPDX expected MIT`);
  }
}

function checkPnpmInstalledOnly() {
  const fixtureName = 'pnpm-installed-only';
  const report = loadReport(fixtureName);
  if (!report) return;
  const deps = getDependencies(report);
  const esbuildDeps = deps.filter((entry) => entry?.package?.name?.startsWith('@esbuild/'));
  const linuxDeps = esbuildDeps.filter((entry) => entry.package.name.startsWith('@esbuild/linux-'));
  const darwinDeps = esbuildDeps.filter((entry) => entry.package.name === '@esbuild/darwin-arm64');
  assert(esbuildDeps.length > 0, `[${fixtureName}] expected @esbuild/* dependencies`);
  assert(linuxDeps.length === 0, `[${fixtureName}] found non-installed linux @esbuild packages in report`);
  assert(darwinDeps.length > 0, `[${fixtureName}] expected installed @esbuild/darwin-arm64 package in report`);
}

function checkLicenseEdgeCases() {
  const fixtureName = 'license-edge-cases';
  const report = loadReport(fixtureName);
  if (!report) return;
  const deps = getDependencies(report);
  assert(report.summary?.directCount === 4, `[${fixtureName}] expected four direct file dependencies`);
  assert(deps.every((entry) => entry?.usage?.direct === true), `[${fixtureName}] every declared file dependency should remain direct`);
  const statuses = new Set(
    deps
      .filter((entry) => entry?.package?.name?.startsWith('@dr-license/'))
      .map((entry) => entry?.compliance?.license?.status)
      .filter(Boolean)
  );
  assert(statuses.has('match'), `[${fixtureName}] expected a match license status`);
  assert(statuses.has('invalid-spdx'), `[${fixtureName}] expected an invalid-spdx license status`);
  assert(statuses.has('mismatch'), `[${fixtureName}] expected a mismatch license status`);
  assert(statuses.has('inferred-only'), `[${fixtureName}] expected an inferred-only license status`);
}

function checkExecutionSignals() {
  const fixtureName = 'execution-signals';
  const report = loadReport(fixtureName);
  if (!report) return;
  const deps = getDependencies(report);
  assert(report.summary?.directCount === 2, `[${fixtureName}] expected two direct file dependencies`);
  const hasNative = deps.some((entry) => entry?.execution?.native === true);
  const hasInstallHooks = deps.some((entry) => Array.isArray(entry?.execution?.scripts?.hooks) && entry.execution.scripts.hooks.length > 0);
  assert(hasNative, `[${fixtureName}] expected at least one dependency with native execution surface`);
  assert(hasInstallHooks, `[${fixtureName}] expected at least one dependency with install hooks`);
}

function checkUsageClassification() {
  const fixtureName = 'usage-classification';
  const report = loadReport(fixtureName);
  if (!report) return;
  const deps = getDependencies(report);
  assert(report.summary?.directCount === 5, `[${fixtureName}] expected five direct file dependencies`);
  const runtimeImpacts = new Set(deps.map((entry) => entry?.usage?.runtimeImpact).filter(Boolean));
  const introductions = new Set(deps.map((entry) => entry?.usage?.introduction).filter(Boolean));
  assert(runtimeImpacts.has('runtime'), `[${fixtureName}] expected runtime runtimeImpact`);
  assert(runtimeImpacts.has('build'), `[${fixtureName}] expected build runtimeImpact`);
  assert(runtimeImpacts.has('testing'), `[${fixtureName}] expected testing runtimeImpact`);
  assert(runtimeImpacts.has('tooling'), `[${fixtureName}] expected tooling runtimeImpact`);
  assert(introductions.has('tooling'), `[${fixtureName}] expected tooling introduction classification`);
  assert(introductions.has('testing'), `[${fixtureName}] expected testing introduction classification`);
}

function checkWorkspaceFixture(fixtureName, expectedType) {
  const report = loadReport(fixtureName);
  if (!report) return;
  const workspaces = report.workspaces || {};
  assert(workspaces.enabled === true, `[${fixtureName}] expected workspace scan mode`);
  assert(workspaces.type === expectedType, `[${fixtureName}] expected workspace type ${expectedType}`);
  assert(typeof workspaces.packageCount === 'number' && workspaces.packageCount >= 2, `[${fixtureName}] expected packageCount >= 2`);
  const deps = getDependencies(report);
  const hasLocalWorkspacePackage = deps.some((entry) => entry?.package?.name === '@dr/pkg-a' || entry?.package?.name === '@dr-yarn/pkg-a');
  assert(!hasLocalWorkspacePackage, `[${fixtureName}] workspace-local package should not be reported as external dependency`);
}

function checkNoNodeModulesResult() {
  const fixtureName = 'no-node-modules';
  const report = loadReport(fixtureName);
  if (!report) return;
  assert(report.summary?.dependencyCount === 0, `[${fixtureName}] expected zero resolved dependencies`);
  assert(report.scanStatus?.complete === false, `[${fixtureName}] expected incomplete scan status`);
  assert(report.scanStatus?.collectors?.dependencyTree === 'partial', `[${fixtureName}] expected partial dependency-tree evidence`);
  assert(Array.isArray(report.scanStatus?.warnings) && report.scanStatus.warnings.length > 0, `[${fixtureName}] expected scan warnings`);
}

function checkOnlineRegistrySignals() {
  const fixtureName = 'npm-registry-signals';
  const report = loadReport(fixtureName);
  if (!report) return;
  const deps = getDependencies(report);
  const targetDeps = deps.filter((entry) => ['minimist', 'lodash'].includes(entry?.package?.name));
  assert(targetDeps.length > 0, `[${fixtureName}] expected minimist/lodash in report`);

  const hasVulns = targetDeps.some((entry) => {
    const s = entry?.security?.summary;
    if (!s) return false;
    return (s.critical || 0) + (s.high || 0) + (s.moderate || 0) + (s.low || 0) > 0;
  });
  assert(hasVulns, `[${fixtureName}] expected at least one known vulnerability in target deps`);

  const hasOutdated = targetDeps.some((entry) => {
    const installed = entry?.package?.version;
    const latest = entry?.upgrade?.latestVersion;
    const status = entry?.upgrade?.outdatedStatus;
    const hasUpdateStatus = typeof status === 'string' && ['patch', 'minor', 'major'].includes(status);
    return (typeof latest === 'string' && latest.length > 0 && latest !== installed) || hasUpdateStatus;
  });
  assert(hasOutdated, `[${fixtureName}] expected outdated data to mark at least one target dependency`);
}

function runCoreAssertions() {
  checkPnpmLicenseResolution();
  checkPnpmInstalledOnly();
  checkLicenseEdgeCases();
  checkExecutionSignals();
  checkUsageClassification();
  checkWorkspaceFixture('pnpm-workspace', 'pnpm');
  checkWorkspaceFixture('pnpm-workspace-hoisted', 'pnpm');
  checkWorkspaceFixture('yarn-workspace', 'yarn');
  checkNoNodeModulesResult();
}

function runOnlineAssertions() {
  checkOnlineRegistrySignals();
}

function usage() {
  console.error('Usage: node scripts/assert-suite.js <core|online>');
  process.exit(1);
}

const suiteName = process.argv[2] || 'core';
if (!suites[suiteName]) usage();

if (suiteName === 'core') runCoreAssertions();
if (suiteName === 'online') runOnlineAssertions();

if (failures.length > 0) {
  console.error('\nFixture assertions failed:');
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log(`✔ Fixture assertions passed (${suiteName})`);
