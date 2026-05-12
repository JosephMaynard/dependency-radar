import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { aggregateData, collectPackageExecutionSignals, detectLocalExecutionSignals } from './aggregator';

const tempDirs: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), `${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe('aggregateData', () => {
  it('detects conservative local execution signals from text', () => {
    expect(detectLocalExecutionSignals(`
      const child_process = require('child_process');
      child_process.exec('git status');
      fetch('https://example.test');
      console.log(process.env.TOKEN);
      console.log(os.homedir());
      console.log('.ssh/id_rsa');
    `)).toEqual(expect.arrayContaining([
      'network-access',
      'child-process',
      'reads-env',
      'reads-home',
      'uses-ssh'
    ]));
  });

  it('keeps package execution signal scanning bounded', async () => {
    const projectPath = await makeTempDir('dr-agg-bounded-signals');
    for (let i = 0; i < 6; i += 1) {
      await fs.writeFile(path.join(projectPath, `file-${i}.js`), i === 5
        ? "require('child_process').exec('late')"
        : 'module.exports = 1;');
    }
    await fs.writeFile(path.join(projectPath, 'index.js'), 'module.exports = 1;');

    const signals = await collectPackageExecutionSignals(
      { main: 'index.js' },
      projectPath,
      { maxFiles: 3, maxPackageFiles: 3 }
    );

    expect(signals).not.toContain('child-process');
  });

  it('inspects extensionless JavaScript-like bin targets', async () => {
    const projectPath = await makeTempDir('dr-agg-extensionless-bin');
    await fs.writeFile(path.join(projectPath, 'cli'), [
      '#!/usr/bin/env node',
      "require('child_process').exec('git status');"
    ].join('\n'));

    const signals = await collectPackageExecutionSignals(
      { bin: { fixture: 'cli' } },
      projectPath,
      { maxFiles: 3, maxPackageFiles: 3 }
    );

    expect(signals).toContain('child-process');
  });

  it('records local execution and packaging signals in aggregated dependencies', async () => {
    const projectPath = await makeTempDir('dr-agg-local-signals');
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { 'risky-local': '1.0.0' }
    }));
    const depDir = path.join(projectPath, 'node_modules', 'risky-local');
    await fs.mkdir(depDir, { recursive: true });
    await fs.writeFile(path.join(depDir, 'package.json'), JSON.stringify({
      name: 'risky-local',
      version: '1.0.0',
      license: 'MIT',
      main: 'index.js',
      bin: { risky: 'cli.js' },
      bundledDependencies: ['vendored-child']
    }));
    await fs.writeFile(path.join(depDir, 'index.js'), 'module.exports = 1;');
    await fs.writeFile(path.join(depDir, 'cli.js'), [
      "const cp = require('child_process');",
      "cp.exec('git status');",
      "console.log(process.env.HOME);"
    ].join('\n'));
    await fs.writeFile(path.join(depDir, 'npm-shrinkwrap.json'), '{}');

    const data = await aggregateData({
      projectPath,
      pkgOverride: {
        name: 'fixture-root',
        version: '1.0.0',
        dependencies: { 'risky-local': '1.0.0' }
      },
      projectPackageJson: {
        name: 'fixture-root',
        version: '1.0.0',
        dependencies: { 'risky-local': '1.0.0' }
      },
      npmLsResult: {
        ok: true,
        data: {
          dependencies: {
            'risky-local': {
              name: 'risky-local',
              version: '1.0.0'
            }
          }
        }
      },
      auditResult: { ok: true, data: {} },
      importGraphResult: { ok: true, data: {} },
      outdatedResult: { entries: [], unknownNames: [] },
      workspaceEnabled: false,
      workspaceType: 'none',
      workspacePackageCount: 1,
      resolvePaths: [projectPath]
    });

    const dep = data.dependencies['risky-local@1.0.0'];
    expect(dep.execution?.signals).toEqual(expect.arrayContaining(['child-process', 'reads-env']));
    expect(dep.packaging?.signals).toEqual(['bundled-dependencies', 'embedded-shrinkwrap']);
    expect(dep.packaging?.bundledDependencies).toEqual(['vendored-child']);
    expect(data.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ category: 'execution', evidence: expect.stringContaining('child-process') }),
      expect.objectContaining({ category: 'supply-chain', evidence: expect.stringContaining('bundled-dependencies') })
    ]));
  });

  it('merges workspace usage metadata into dependency origins', async () => {
    const projectPath = await makeTempDir('dr-agg-workspace');
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({ name: 'fixture-root', version: '1.0.0' }));
    const depDir = path.join(projectPath, 'node_modules', 'left-pad');
    await fs.mkdir(depDir, { recursive: true });
    await fs.writeFile(path.join(depDir, 'package.json'), JSON.stringify({
      name: 'left-pad',
      version: '1.3.0',
      license: 'MIT'
    }));

    const projectPackageJson = {
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { 'left-pad': '1.3.0' }
    };

    const data = await aggregateData({
      projectPath,
      pkgOverride: projectPackageJson,
      projectPackageJson,
      npmLsResult: {
        ok: true,
        data: {
          dependencies: {
            'left-pad': {
              name: 'left-pad',
              version: '1.3.0'
            }
          }
        }
      },
      auditResult: { ok: true, data: {} },
      importGraphResult: { ok: true, data: {} },
      outdatedResult: { entries: [], unknownNames: [] },
      workspaceUsage: new Map([['left-pad', ['apps/site-a', 'apps/site-b']]]),
      workspaceEnabled: true,
      workspaceType: 'pnpm',
      workspacePackageCount: 2,
      resolvePaths: [projectPath],
      environment: {
        packageManager: 'pnpm',
        packageManagerVersion: '9.5.0'
      }
    });

    const dep = Object.values(data.dependencies).find((entry) => entry.package.name === 'left-pad');
    expect(dep).toBeDefined();
    expect(dep?.usage.origins.workspaces).toEqual(['apps/site-a', 'apps/site-b']);
    expect(data.workspaces.enabled).toBe(true);
    expect(data.workspaces.type).toBe('pnpm');
  });
});
