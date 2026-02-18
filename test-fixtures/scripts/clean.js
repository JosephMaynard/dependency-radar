const fs = require('fs');
const path = require('path');

const fixturesRoot = path.resolve(__dirname, '..');
const ignore = new Set(['scripts', 'package.json', '.DS_Store']);

for (const entry of fs.readdirSync(fixturesRoot, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  if (ignore.has(entry.name)) continue;
  const fixtureDir = path.join(fixturesRoot, entry.name);
  const targets = [
    path.join(fixtureDir, 'node_modules'),
    path.join(fixtureDir, '.dependency-radar'),
    path.join(fixtureDir, 'dependency-radar.json'),
    path.join(fixtureDir, 'dependency-radar.html'),
    path.join(fixtureDir, 'package-lock.json'),
    path.join(fixtureDir, 'pnpm-lock.yaml')
  ];
  for (const target of targets) {
    try {
      fs.rmSync(target, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors for missing files
    }
  }
}

console.log('✔ Fixture outputs cleaned');
