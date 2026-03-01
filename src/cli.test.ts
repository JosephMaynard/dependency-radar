import { spawnSync } from 'child_process';
import path from 'path';
import { describe, expect, it } from 'vitest';

function stripAnsi(value: string): string {
  return value.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '');
}

describe('cli summary output', () => {
  it(
    'prints summary bullets and keeps CTA as the final line',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const tsNodeBin = path.join(
        repoRoot,
        'node_modules',
        'ts-node',
        'dist',
        'bin.js',
      );
      const cliPath = path.join(repoRoot, 'src', 'cli.ts');

      const result = spawnSync(
        process.execPath,
        [tsNodeBin, cliPath, 'scan', '--project', repoRoot, '--offline', '--no-report'],
        {
          cwd: repoRoot,
          encoding: 'utf8',
          env: {
            ...process.env,
            NO_COLOR: '1',
          },
        },
      );

      expect(result.status).toBe(0);

      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');

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
        'Enrich this scan with maintenance signals, upgrade readiness, and risk modelling at dependency-radar.com',
      );
      expect(output.trim().endsWith(
        'Enrich this scan with maintenance signals, upgrade readiness, and risk modelling at dependency-radar.com',
      )).toBe(true);
    },
  );

  it(
    'exits non-zero and prints policy violations when --fail-on is triggered',
    { timeout: 30000 },
    () => {
      const repoRoot = path.resolve(__dirname, '..');
      const tsNodeBin = path.join(
        repoRoot,
        'node_modules',
        'ts-node',
        'dist',
        'bin.js',
      );
      const cliPath = path.join(repoRoot, 'src', 'cli.ts');
      const fixtureProject = path.join(
        repoRoot,
        'test-fixtures',
        'license-edge-cases',
      );

      const result = spawnSync(
        process.execPath,
        [
          tsNodeBin,
          cliPath,
          'scan',
          '--project',
          fixtureProject,
          '--offline',
          '--no-report',
          '--fail-on',
          'licence-mismatch',
        ],
        {
          cwd: repoRoot,
          encoding: 'utf8',
          env: {
            ...process.env,
            NO_COLOR: '1',
          },
        },
      );

      expect(result.status).not.toBe(0);

      const output = stripAnsi(`${result.stdout}\n${result.stderr}`).replace(/\r/g, '');
      expect(output).toContain('Policy violations detected');
      expect(output).toContain('licence mismatch');
    },
  );
});
