import { spawnSync } from 'child_process';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';

const ANSI_ESCAPE_REGEX = new RegExp('\\x1b\\[[0-9;]*[A-Za-z]', 'g');
const FILENAME_TIMESTAMP = '\\d{4}-\\d{2}-\\d{2}_\\d{2}-\\d{2}-\\d{2}';
const tempDirs: string[] = [];

function stripAnsi(value: string): string {
  return value.replace(ANSI_ESCAPE_REGEX, '');
}

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), `${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

function runCli(args: string[], cwd?: string) {
  const repoRoot = path.resolve(__dirname, '..');
  const tsNodeBin = path.join(
    repoRoot,
    'node_modules',
    'ts-node',
    'dist',
    'bin.js',
  );
  const cliPath = path.join(repoRoot, 'src', 'cli.ts');

  return spawnSync(process.execPath, [tsNodeBin, cliPath, ...args], {
    cwd: cwd || repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      NO_COLOR: '1',
    },
  });
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })),
  );
});

describe('cli summary output', () => {
  it('fails fast for unknown options without scanning', () => {
    const repoRoot = path.resolve(__dirname, '..');
    const result = runCli(['scan', '--definitely-not-real'], repoRoot);

    expect(result.status).toBe(1);
    expect(stripAnsi(result.stderr)).toContain('Unknown option: "--definitely-not-real".');
    expect(stripAnsi(result.stdout)).not.toContain('Summary:');
  });

  it('fails fast when an option value is missing', () => {
    const repoRoot = path.resolve(__dirname, '..');
    const result = runCli(['scan', '--project'], repoRoot);

    expect(result.status).toBe(1);
    expect(stripAnsi(result.stderr)).toContain('Missing value for --project.');
    expect(stripAnsi(result.stdout)).not.toContain('Summary:');
  });

  it(
    'keeps the default scan command working without explicitly passing scan',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const result = runCli(['--project', repoRoot, '--offline', '--no-report']);

      expect(result.status).toBe(0);

      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      const stdoutOutput = stripAnsi(result.stdout).replace(/\r/g, '');

      expect(output).toContain('Summary:');
      expect(output).toMatch(/• Direct dependencies scanned: \d+/);
      expect(output).toMatch(/• Transitive dependencies scanned: \d+/);
      expect(output).toMatch(/• Vulnerable packages: \d+ \(\d+ reachable\)/);
      expect(output).toMatch(/• Dependencies with no static import reference: \d+/);
      expect(output).toMatch(/• License mismatches: \d+/);
      expect(output).toMatch(/• Major upgrade blockers: \d+/);

      const blockerTotalMatch = output.match(/• Major upgrade blockers: (\d+)/);
      const blockerTotal = blockerTotalMatch
        ? Number.parseInt(blockerTotalMatch[1], 10)
        : 0;
      if (blockerTotal > 0) {
        expect(output).toMatch(/^\s{3}- \d+ .+/m);
      }

      expect(output).toContain(
        'Enrich this scan with maintenance signals, upgrade readiness, and risk modelling at https://www.dependency-radar.com',
      );
      expect(stdoutOutput.trim().endsWith(
        'Enrich this scan with maintenance signals, upgrade readiness, and risk modelling at https://www.dependency-radar.com',
      )).toBe(true);
    },
  );

  it(
    'exits non-zero and prints policy violations when --fail-on is triggered',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(
        repoRoot,
        'test-fixtures',
        'license-edge-cases',
      );

      const result = runCli(
        [
          'scan',
          '--project',
          fixtureProject,
          '--offline',
          '--no-report',
          '--fail-on',
          'licence-mismatch',
        ],
        repoRoot,
      );

      expect(result.status).toBe(1);

      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('Policy violations detected');
      expect(output).toContain('licence mismatch');
    },
  );

  it(
    'prints a focused terminal explanation and does not write a report file',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(
        repoRoot,
        'test-fixtures',
        'license-edge-cases',
      );
      const outputDir = await makeTempDir('dr-cli-explain');
      const projectCopy = path.join(outputDir, 'project');
      await fs.cp(fixtureProject, projectCopy, { recursive: true });

      const result = runCli(
        ['explain', '@dr-license/mismatch', '--project', projectCopy, '--offline'],
        repoRoot,
      );

      expect(result.status).toBe(0);

      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('@dr-license/mismatch');
      expect(output).toContain('License:');
      expect(output).toMatch(/mismatch \(declared .+, inferred .+\)/);
      expect(output).toContain('Vulnerabilities:\n  not available (--offline)');
      expect(output).not.toContain('Summary:');
      expect(output).not.toContain('Enrich this scan with maintenance signals');
      await expect(
        fs.access(path.join(projectCopy, 'dependency-radar.html')),
      ).rejects.toThrow();
    },
  );

  it(
    'suppresses progress/info logs in quiet mode but still prints the summary',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const result = runCli(
        ['scan', '--project', repoRoot, '--offline', '--no-report', '--open', '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);

      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('Summary:');
      expect(output).not.toContain('Single project detected');
      expect(output).not.toContain('Scan complete:');
      expect(output).not.toContain('Report output disabled');
      expect(output).not.toContain('Skipping auto-open because --no-report is enabled.');
      expect(output).not.toContain('Enrich this scan with maintenance signals');
    },
  );

  it(
    'still prints policy failures in quiet mode',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(
        repoRoot,
        'test-fixtures',
        'license-edge-cases',
      );
      const result = runCli(
        [
          'scan',
          '--project',
          fixtureProject,
          '--offline',
          '--no-report',
          '--quiet',
          '--fail-on',
          'licence-mismatch',
        ],
        repoRoot,
      );

      expect(result.status).toBe(1);

      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('Summary:');
      expect(output).toContain('Policy violations detected');
      expect(output).toContain('licence mismatch');
      expect(output).not.toContain('Single project detected');
      expect(output).not.toContain('Enrich this scan with maintenance signals');
    },
  );

  it(
    'returns exit code 1 when explain cannot find the package',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(
        repoRoot,
        'test-fixtures',
        'license-edge-cases',
      );
      const result = runCli(
        ['explain', 'definitely-not-present', '--project', fixtureProject, '--offline'],
        repoRoot,
      );

      expect(result.status).toBe(1);
      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('✖ Package not found: definitely-not-present');
    },
  );

  it(
    'writes SARIF output with dependency findings',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'license-edge-cases');
      const outputDir = await makeTempDir('dr-cli-sarif');
      const outPath = path.join(outputDir, 'report.sarif');

      const result = runCli(
        ['scan', '--project', fixtureProject, '--offline', '--format', 'sarif', '--out', outPath, '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const sarif = JSON.parse(await fs.readFile(outPath, 'utf8'));
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs[0].tool.driver.name).toBe('Dependency Radar');
      expect(sarif.runs[0].results.length).toBeGreaterThan(0);
    },
  );

  it(
    'adds a timestamp to the default HTML report filename',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'license-edge-cases');
      const outputDir = await makeTempDir('dr-cli-timestamp-html');
      const projectCopy = path.join(outputDir, 'project');
      await fs.cp(fixtureProject, projectCopy, { recursive: true });

      const result = runCli(
        ['scan', '--project', projectCopy, '--offline', '--timestamp', '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const reports = (await fs.readdir(projectCopy)).filter((name) =>
        new RegExp(`^dependency-radar\\.${FILENAME_TIMESTAMP}\\.html$`).test(name),
      );
      expect(reports).toHaveLength(1);
      await fs.access(path.join(projectCopy, reports[0]));
    },
  );

  it(
    'adds a timestamp to the default JSON report filename',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'license-edge-cases');
      const outputDir = await makeTempDir('dr-cli-timestamp-json');
      const projectCopy = path.join(outputDir, 'project');
      await fs.cp(fixtureProject, projectCopy, { recursive: true });

      const result = runCli(
        ['scan', '--project', projectCopy, '--offline', '--timestamp', '--json', '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const reports = (await fs.readdir(projectCopy)).filter((name) =>
        new RegExp(`^dependency-radar\\.${FILENAME_TIMESTAMP}\\.json$`).test(name),
      );
      expect(reports).toHaveLength(1);
      const report = JSON.parse(await fs.readFile(path.join(projectCopy, reports[0]), 'utf8'));
      expect(report.schemaVersion).toBe('1.4');
    },
  );

  it(
    'adds a timestamp to a custom report filename',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'license-edge-cases');
      const outputDir = await makeTempDir('dr-cli-timestamp-out');
      const projectCopy = path.join(outputDir, 'project');
      const outPath = path.join(outputDir, 'robert.html');
      await fs.cp(fixtureProject, projectCopy, { recursive: true });

      const result = runCli(
        ['scan', '--project', projectCopy, '--offline', '--timestamp', '--out', outPath, '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const reports = (await fs.readdir(outputDir)).filter((name) =>
        new RegExp(`^robert\\.${FILENAME_TIMESTAMP}\\.html$`).test(name),
      );
      expect(reports).toHaveLength(1);
      await fs.access(path.join(outputDir, reports[0]));
      await expect(fs.access(outPath)).rejects.toThrow();
    },
  );

  it(
    'writes CycloneDX SBOM output',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'license-edge-cases');
      const outputDir = await makeTempDir('dr-cli-cdx');
      const outPath = path.join(outputDir, 'bom.json');

      const result = runCli(
        ['scan', '--project', fixtureProject, '--offline', '--sbom', 'cyclonedx', '--out', outPath, '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const bom = JSON.parse(await fs.readFile(outPath, 'utf8'));
      expect(bom.bomFormat).toBe('CycloneDX');
      expect(Array.isArray(bom.components)).toBe(true);
      expect(bom.components.length).toBeGreaterThan(0);
    },
  );

  it(
    'prints dependency paths with the why command',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'license-edge-cases');
      const result = runCli(
        ['why', '@dr-license/mismatch', '--project', fixtureProject, '--offline', '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('Dependency paths for @dr-license/mismatch');
      expect(output).toContain('@dr-license/mismatch@1.0.0');
    },
  );

  it(
    'compares against a previous JSON report',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'license-edge-cases');
      const outputDir = await makeTempDir('dr-cli-compare');
      const previousPath = path.join(outputDir, 'previous.json');
      await fs.writeFile(previousPath, JSON.stringify({
        schemaVersion: '1.4',
        generatedAt: new Date(0).toISOString(),
        dependencyRadarVersion: 'test',
        git: { branch: '' },
        project: { projectDir: '/fixture' },
        environment: { nodeVersion: '0.0.0', runtimeVersion: 'v0.0.0', minRequiredMajor: 0 },
        workspaces: { enabled: false },
        summary: { dependencyCount: 0, directCount: 0, transitiveCount: 0 },
        dependencies: {},
        findings: []
      }), 'utf8');

      const result = runCli(
        ['compare', previousPath, '--project', fixtureProject, '--offline', '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('Dependency Radar comparison');
      expect(output).toContain('Added dependencies');
    },
  );

  it(
    'fails compare when a selected risky delta rule is introduced',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'execution-signals');
      const outputDir = await makeTempDir('dr-cli-compare-fail-on');
      const previousPath = path.join(outputDir, 'previous.json');
      await fs.writeFile(previousPath, JSON.stringify({
        schemaVersion: '1.4',
        generatedAt: new Date(0).toISOString(),
        dependencyRadarVersion: 'test',
        git: { branch: '' },
        project: { projectDir: '/fixture' },
        environment: { nodeVersion: '0.0.0', runtimeVersion: 'v0.0.0', minRequiredMajor: 0 },
        workspaces: { enabled: false },
        summary: { dependencyCount: 2, directCount: 0, transitiveCount: 2 },
        dependencies: {
          '@dr-exec/scripted@1.0.0': {
            package: {
              id: '@dr-exec/scripted@1.0.0',
              name: '@dr-exec/scripted',
              version: '1.0.0',
              deprecated: false,
              links: { npm: 'https://www.npmjs.com/package/@dr-exec/scripted' }
            },
            compliance: { license: { status: 'declared-only' }, licenseRisk: 'green' },
            security: { summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' } },
            upgrade: { nodeEngine: null },
            usage: {
              direct: false,
              scope: 'runtime',
              depth: 1,
              origins: { rootPackageCount: 0, topRootPackages: [], parentPackageCount: 0, topParentPackages: [] },
              tsTypes: 'unknown'
            },
            graph: { fanIn: 0, fanOut: 0 }
          },
          '@dr-exec/surface-native@1.0.0': {
            package: {
              id: '@dr-exec/surface-native@1.0.0',
              name: '@dr-exec/surface-native',
              version: '1.0.0',
              deprecated: false,
              links: { npm: 'https://www.npmjs.com/package/@dr-exec/surface-native' }
            },
            compliance: { license: { status: 'declared-only' }, licenseRisk: 'green' },
            security: { summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' } },
            upgrade: { nodeEngine: null },
            usage: {
              direct: false,
              scope: 'runtime',
              depth: 1,
              origins: { rootPackageCount: 0, topRootPackages: [], parentPackageCount: 0, topParentPackages: [] },
              tsTypes: 'unknown'
            },
            graph: { fanIn: 0, fanOut: 0 }
          }
        },
        findings: []
      }), 'utf8');

      const result = runCli(
        ['compare', previousPath, '--project', fixtureProject, '--offline', '--quiet', '--fail-on', 'new-install-script,new-native-binding'],
        repoRoot,
      );

      expect(result.status).toBe(1);
      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('Dependency Radar comparison');
      expect(output).toContain('Policy violations detected');
      expect(output).toContain('@dr-exec/scripted@1.0.0 introduced install hooks: install, postinstall, prepare');
      expect(output).toContain('@dr-exec/surface-native@1.0.0 introduced native build/binary surface');
    },
  );

  it(
    'fails compare when local execution and packaging signals are introduced',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const outputDir = await makeTempDir('dr-cli-local-signal-delta');
      const projectPath = path.join(outputDir, 'project');
      const depDir = path.join(projectPath, 'node_modules', 'local-signal');
      const previousPath = path.join(outputDir, 'previous.json');
      await fs.mkdir(depDir, { recursive: true });
      await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
        name: 'local-signal-project',
        version: '1.0.0',
        dependencies: { 'local-signal': '1.0.0' }
      }), 'utf8');
      await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
        name: 'local-signal-project',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'local-signal-project',
            version: '1.0.0',
            dependencies: { 'local-signal': '1.0.0' }
          },
          'node_modules/local-signal': {
            name: 'local-signal',
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/local-signal/-/local-signal-1.0.0.tgz',
            integrity: 'sha512-test'
          }
        }
      }), 'utf8');
      await fs.writeFile(path.join(depDir, 'package.json'), JSON.stringify({
        name: 'local-signal',
        version: '1.0.0',
        license: 'MIT',
        main: 'index.js',
        bin: { 'local-signal': 'cli.js' },
        bundledDependencies: ['vendored-child']
      }), 'utf8');
      await fs.writeFile(path.join(depDir, 'index.js'), 'module.exports = 1;', 'utf8');
      await fs.writeFile(path.join(depDir, 'cli.js'), "require('child_process').exec('git status'); console.log(process.env.TOKEN);", 'utf8');
      await fs.writeFile(path.join(depDir, 'npm-shrinkwrap.json'), '{}', 'utf8');
      await fs.writeFile(previousPath, JSON.stringify({
        schemaVersion: '1.4',
        generatedAt: new Date(0).toISOString(),
        dependencyRadarVersion: 'test',
        git: { branch: '' },
        project: { projectDir: '/fixture' },
        environment: { nodeVersion: '0.0.0', runtimeVersion: 'v0.0.0', minRequiredMajor: 0 },
        workspaces: { enabled: false },
        summary: { dependencyCount: 1, directCount: 1, transitiveCount: 0 },
        dependencies: {
          'local-signal@1.0.0': {
            package: {
              id: 'local-signal@1.0.0',
              name: 'local-signal',
              version: '1.0.0',
              deprecated: false,
              links: { npm: 'https://www.npmjs.com/package/local-signal' }
            },
            compliance: { license: { status: 'declared-only' }, licenseRisk: 'green' },
            security: { summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' } },
            upgrade: { nodeEngine: null },
            usage: {
              direct: true,
              scope: 'runtime',
              depth: 0,
              origins: { rootPackageCount: 1, topRootPackages: [{ name: 'local-signal', version: '1.0.0' }], parentPackageCount: 0, topParentPackages: [] },
              tsTypes: 'unknown'
            },
            graph: { fanIn: 0, fanOut: 0 }
          }
        },
        findings: []
      }), 'utf8');

      const result = runCli(
        ['compare', previousPath, '--project', projectPath, '--offline', '--quiet', '--fail-on', 'new-child-process,new-env-access,new-bundled-dependencies,new-shrinkwrap'],
        repoRoot,
      );

      expect(result.status).toBe(1);
      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('local-signal@1.0.0 introduced execution signal: child-process');
      expect(output).toContain('local-signal@1.0.0 introduced execution signal: reads-env');
      expect(output).toContain('local-signal@1.0.0 introduced packaging signal: bundled-dependencies');
      expect(output).toContain('local-signal@1.0.0 introduced packaging signal: embedded-shrinkwrap');
    },
  );

  it(
    'adds targeted registry enrichment for suspicious packages during online scans',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const outputDir = await makeTempDir('dr-cli-registry-enrichment');
      const binDir = path.join(outputDir, 'bin');
      const projectPath = path.join(outputDir, 'project');
      const depDir = path.join(projectPath, 'node_modules', 'local-registry-risk');
      const outPath = path.join(outputDir, 'report.json');
      await fs.mkdir(binDir, { recursive: true });
      await fs.mkdir(depDir, { recursive: true });
      const fakeNpmPath = path.join(binDir, 'npm');
      await fs.writeFile(fakeNpmPath, [
        '#!/usr/bin/env node',
        'const args = process.argv.slice(2);',
        'if (args.includes("--version")) { console.log("10.9.2"); process.exit(0); }',
        'if (args[0] === "audit") { console.log(JSON.stringify({ vulnerabilities: {} })); process.exit(0); }',
        'if (args[0] === "outdated") { console.log(JSON.stringify({})); process.exit(0); }',
        'if (args[0] === "view") {',
        '  const recent = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();',
        '  console.log(JSON.stringify({',
        '    time: { created: recent, modified: recent, "1.0.0": recent },',
        '    "dist-tags": { latest: "1.0.0" },',
        '    versions: ["1.0.0"]',
        '  }));',
        '  process.exit(0);',
        '}',
        'console.error("unexpected npm args " + args.join(" "));',
        'process.exit(1);'
      ].join('\n'), 'utf8');
      await fs.chmod(fakeNpmPath, 0o755);
      await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
        name: 'registry-enrichment-project',
        version: '1.0.0',
        dependencies: { 'local-registry-risk': '1.0.0' }
      }), 'utf8');
      await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
        name: 'registry-enrichment-project',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'registry-enrichment-project',
            version: '1.0.0',
            dependencies: { 'local-registry-risk': '1.0.0' }
          },
          'node_modules/local-registry-risk': {
            name: 'local-registry-risk',
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/local-registry-risk/-/local-registry-risk-1.0.0.tgz',
            integrity: 'sha512-test'
          }
        }
      }), 'utf8');
      await fs.writeFile(path.join(depDir, 'package.json'), JSON.stringify({
        name: 'local-registry-risk',
        version: '1.0.0',
        license: 'MIT',
        bin: { risk: 'cli.js' }
      }), 'utf8');
      await fs.writeFile(path.join(depDir, 'cli.js'), 'console.log("risk");', 'utf8');

      const previousPath = process.env.PATH;
      process.env.PATH = `${binDir}${path.delimiter}${previousPath || ''}`;
      try {
        const result = runCli(
          ['scan', '--project', projectPath, '--json', '--out', outPath, '--quiet'],
          repoRoot,
        );

        expect(result.status).toBe(0);
      } finally {
        process.env.PATH = previousPath;
      }

      const report = JSON.parse(await fs.readFile(outPath, 'utf8'));
      expect(report.dependencies['local-registry-risk@1.0.0'].supplyChain.registry).toEqual(
        expect.objectContaining({
          attempted: true,
          ok: true,
          candidateReasons: ['bin'],
          versionCount: 1,
          signals: expect.arrayContaining(['recent-package', 'recent-version', 'low-release-history'])
        })
      );
      expect(report.findings).toEqual(expect.arrayContaining([
        expect.objectContaining({
          packageId: 'local-registry-risk@1.0.0',
          id: expect.stringContaining('registry-recent-version')
        })
      ]));
    },
  );

  it('prints the JSON schema without scanning', () => {
    const repoRoot = path.resolve(__dirname, '..');
    const result = runCli(['--schema', '--quiet'], repoRoot);

    expect(result.status).toBe(0);
    const schema = JSON.parse(result.stdout);
    expect(schema.title).toBe('Dependency Radar Report');
    expect(schema.properties.schemaVersion.const).toBe('1.4');
  });

  it('writes the JSON schema to --out without scanning', async () => {
    const repoRoot = path.resolve(__dirname, '..');
    const outputDir = await makeTempDir('dr-cli-schema-out');
    const outPath = path.join(outputDir, 'dependency-radar.schema.json');
    const result = runCli(['--schema', '--out', outPath, '--quiet'], repoRoot);

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
    const schema = JSON.parse(await fs.readFile(outPath, 'utf8'));
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.properties.schemaVersion.const).toBe('1.4');
    expect(schema.properties.supplyChain.properties.signals.items.required).toEqual(['type', 'source', 'detail']);
    expect(schema.properties.findings.items.required).toContain('packageId');
  });

  it(
    'skips audit signatures when offline',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const fixtureProject = path.join(repoRoot, 'test-fixtures', 'license-edge-cases');
      const result = runCli(
        ['scan', '--project', fixtureProject, '--offline', '--audit-signatures', '--no-report', '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('Summary:');
    },
  );

  it(
    'fails on supply-chain-source policy violations',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const outputDir = await makeTempDir('dr-cli-supply-policy');
      const projectPath = path.join(outputDir, 'project');
      await fs.mkdir(projectPath, { recursive: true });
      await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
        name: 'supply-policy-fixture',
        version: '1.0.0',
        dependencies: { 'git-dep': 'github:example/git-dep' }
      }), 'utf8');
      await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'supply-policy-fixture',
            version: '1.0.0',
            dependencies: { 'git-dep': 'github:example/git-dep' }
          },
          'node_modules/git-dep': {
            version: '1.0.0',
            resolved: 'git+https://github.com/example/git-dep.git'
          }
        }
      }), 'utf8');

      const result = runCli(
        ['scan', '--project', projectPath, '--offline', '--no-report', '--quiet', '--fail-on', 'supply-chain-source'],
        repoRoot,
      );

      expect(result.status).toBe(1);
      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('supply-chain source');
    },
  );

  it(
    'writes supply-chain source signals and findings to JSON output',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const outputDir = await makeTempDir('dr-cli-supply-json');
      const projectPath = path.join(outputDir, 'project');
      const outPath = path.join(outputDir, 'report.json');
      await fs.mkdir(projectPath, { recursive: true });
      await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
        name: 'supply-json-fixture',
        version: '1.0.0',
        dependencies: { 'git-dep': 'github:example/git-dep' }
      }), 'utf8');
      await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'supply-json-fixture',
            version: '1.0.0',
            dependencies: { 'git-dep': 'github:example/git-dep' }
          },
          'node_modules/git-dep': {
            version: '1.0.0',
            resolved: 'git+https://github.com/example/git-dep.git'
          }
        }
      }), 'utf8');

      const result = runCli(
        ['scan', '--project', projectPath, '--offline', '--json', '--out', outPath, '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const report = JSON.parse(await fs.readFile(outPath, 'utf8'));
      expect(report.supplyChain.signals).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type: 'git-dependency', packageName: 'git-dep' })
        ])
      );
      expect(report.findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ category: 'supply-chain', title: 'Git dependency source' })
        ])
      );
    },
  );

  it(
    'scans text bun.lock projects through the CLI',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const outputDir = await makeTempDir('dr-cli-bun');
      const projectPath = path.join(outputDir, 'project');
      const outPath = path.join(outputDir, 'bun-report.json');
      await fs.mkdir(projectPath, { recursive: true });
      await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
        name: 'bun-cli-fixture',
        version: '1.0.0',
        packageManager: 'bun@1.2.0',
        dependencies: { a: '1.0.0' }
      }), 'utf8');
      await fs.writeFile(path.join(projectPath, 'bun.lock'), `{
        // Bun text lockfiles are JSONC-like in the wild.
        "lockfileVersion": 1,
        "packages": {
          "a@1.0.0": {
            "version": "1.0.0",
            "dependencies": { "b": "1.0.0" },
          },
          "b@1.0.0": {
            "version": "2.0.0",
          },
        },
      }`, 'utf8');

      const result = runCli(
        ['scan', '--project', projectPath, '--offline', '--json', '--out', outPath, '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const report = JSON.parse(await fs.readFile(outPath, 'utf8'));
      expect(report.environment.packageManager).toBe('bun');
      expect(report.dependencies['a@1.0.0']).toBeDefined();
      expect(report.dependencies['b@2.0.0']).toBeDefined();
    },
  );

  it(
    'uses lockfile-derived graph data instead of hard-failing Yarn PnP projects',
    { timeout: 30000 },
    async () => {
      const repoRoot = path.resolve(__dirname, '..');
      const outputDir = await makeTempDir('dr-cli-yarn-pnp');
      const projectPath = path.join(outputDir, 'project');
      const outPath = path.join(outputDir, 'yarn-report.json');
      await fs.mkdir(projectPath, { recursive: true });
      await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
        name: 'yarn-pnp-cli-fixture',
        version: '1.0.0',
        packageManager: 'yarn@4.0.0',
        dependencies: { a: '1.0.0' }
      }), 'utf8');
      await fs.writeFile(path.join(projectPath, '.pnp.cjs'), 'module.exports = {};', 'utf8');
      await fs.writeFile(path.join(projectPath, 'yarn.lock'), [
        '# yarn lockfile v1',
        '',
        'a@1.0.0:',
        '  version "1.0.0"',
        '  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz"',
        '  integrity sha512-a'
      ].join('\n'), 'utf8');

      const result = runCli(
        ['scan', '--project', projectPath, '--offline', '--json', '--out', outPath, '--quiet'],
        repoRoot,
      );

      expect(result.status).toBe(0);
      const report = JSON.parse(await fs.readFile(outPath, 'utf8'));
      expect(report.environment.packageManager).toBe('yarn');
      expect(report.dependencies['a@1.0.0']).toBeDefined();
    },
  );
});
