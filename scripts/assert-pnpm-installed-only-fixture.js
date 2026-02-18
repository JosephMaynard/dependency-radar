const fs = require('fs');
const path = require('path');

const fixtureDir = path.join(__dirname, '..', 'test-fixtures', 'pnpm-installed-only');
const reportPath = path.join(fixtureDir, 'dependency-radar.json');
const virtualStoreDir = path.join(fixtureDir, 'node_modules', '.pnpm');

if (!fs.existsSync(reportPath)) {
  console.error(`Missing fixture report: ${reportPath}`);
  console.error('Run `npm run fixtures:scan:pnpm-installed-only` first.');
  process.exit(1);
}

if (!fs.existsSync(virtualStoreDir)) {
  console.error(`Missing pnpm virtual store: ${virtualStoreDir}`);
  console.error('Run `npm run fixtures:install:pnpm-installed-only` first.');
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
const dependencies = Object.values(report.dependencies || {});
const reportEsbuildEntries = dependencies
  .map((entry) => entry && entry.package)
  .filter((pkg) => pkg && typeof pkg.name === 'string' && pkg.name.startsWith('@esbuild/') && typeof pkg.version === 'string')
  .map((pkg) => `${pkg.name}@${pkg.version}`);

if (reportEsbuildEntries.length === 0) {
  console.error('Fixture assertion failed: expected at least one @esbuild/* package in dependency report.');
  process.exit(1);
}

const installedIds = new Set();
for (const dirent of fs.readdirSync(virtualStoreDir, { withFileTypes: true })) {
  if (!dirent.isDirectory()) continue;
  const encoded = dirent.name.split('(')[0].split('_')[0];
  const lastAt = encoded.lastIndexOf('@');
  if (lastAt <= 0) continue;
  const encodedName = encoded.slice(0, lastAt);
  const version = encoded.slice(lastAt + 1);
  if (!encodedName.startsWith('@esbuild+')) continue;
  const name = encodedName.replace('@esbuild+', '@esbuild/');
  installedIds.add(`${name}@${version}`);
}

const unexpected = reportEsbuildEntries.filter((id) => !installedIds.has(id));
if (unexpected.length > 0) {
  console.error('Fixture assertion failed: report contains @esbuild entries that are not installed.');
  for (const id of unexpected) {
    console.error(`- ${id}`);
  }
  process.exit(1);
}

console.log(`Fixture assertion passed for ${reportEsbuildEntries.length} @esbuild package(s).`);
