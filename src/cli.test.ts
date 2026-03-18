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
      expect(output).toMatch(/• Direct deps scanned: \d+/);
      expect(output).toMatch(/• Transitive deps scanned: \d+/);
      expect(output).toMatch(/• Vulnerable packages: \d+ \(\d+ reachable\)/);
      expect(output).toMatch(/• Unused installed deps: \d+/);
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
});
