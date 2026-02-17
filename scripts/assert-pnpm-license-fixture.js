const fs = require('fs');
const path = require('path');

const reportPath = path.join(
  __dirname,
  '..',
  'test-fixtures',
  'pnpm-license-resolution',
  'dependency-radar.json'
);

if (!fs.existsSync(reportPath)) {
  console.error(`Missing fixture report: ${reportPath}`);
  console.error('Run `npm run fixtures:scan:pnpm-license` first.');
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
const dependencies = Object.values(report.dependencies || {});
const zustandEntries = dependencies.filter((entry) => entry?.package?.name === 'zustand');

if (zustandEntries.length === 0) {
  console.error('Fixture assertion failed: zustand was not found in dependency report.');
  process.exit(1);
}

const failures = zustandEntries.filter((entry) => {
  const license = entry?.compliance?.license;
  const declared = license?.declared;
  return (
    !license ||
    license.status === 'unknown' ||
    !declared ||
    declared.valid !== true ||
    declared.spdxId !== 'MIT'
  );
});

if (failures.length > 0) {
  console.error('Fixture assertion failed: expected zustand to have a valid declared MIT license.');
  for (const entry of failures) {
    console.error(`- ${entry?.package?.id || 'unknown'}: ${JSON.stringify(entry?.compliance?.license || {})}`);
  }
  process.exit(1);
}

console.log(`Fixture assertion passed for ${zustandEntries.length} zustand entry(ies).`);
