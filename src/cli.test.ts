import { spawnSync } from 'child_process';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';

const ANSI_ESCAPE_REGEX = new RegExp('\\x1b\\[[0-9;]*[A-Za-z]', 'g');
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

  it('prints the JSON schema without scanning', () => {
    const repoRoot = path.resolve(__dirname, '..');
    const result = runCli(['--schema', '--quiet'], repoRoot);

    expect(result.status).toBe(0);
    const schema = JSON.parse(result.stdout);
    expect(schema.title).toBe('Dependency Radar Report');
    expect(schema.properties.schemaVersion.const).toBe('1.4');
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
});
