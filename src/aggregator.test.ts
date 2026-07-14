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

  it('inspects deeply nested and array package export targets', async () => {
    const projectPath = await makeTempDir('dr-agg-nested-exports');
    await fs.mkdir(path.join(projectPath, 'dist'), { recursive: true });
    await fs.writeFile(path.join(projectPath, 'dist', 'safe.js'), 'module.exports = 1;');
    await fs.writeFile(path.join(projectPath, 'dist', 'signal.js'), [
      "const cp = require('child_process');",
      "cp.exec('git status');"
    ].join('\n'));

    const signals = await collectPackageExecutionSignals(
      {
        exports: {
          '.': {
            import: ['./dist/safe.js', { node: './dist/signal.js' }]
          }
        }
      },
      projectPath,
      { maxFiles: 6, maxPackageFiles: 6 }
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

  it('records boolean bundledDependencies as a packaging signal', async () => {
    const projectPath = await makeTempDir('dr-agg-bundle-all');
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { 'bundle-all': '1.0.0' }
    }));
    const depDir = path.join(projectPath, 'node_modules', 'bundle-all');
    await fs.mkdir(depDir, { recursive: true });
    await fs.writeFile(path.join(depDir, 'package.json'), JSON.stringify({
      name: 'bundle-all',
      version: '1.0.0',
      license: 'MIT',
      bundleDependencies: true
    }));

    const data = await aggregateData({
      projectPath,
      pkgOverride: {
        name: 'fixture-root',
        version: '1.0.0',
        dependencies: { 'bundle-all': '1.0.0' }
      },
      projectPackageJson: {
        name: 'fixture-root',
        version: '1.0.0',
        dependencies: { 'bundle-all': '1.0.0' }
      },
      npmLsResult: {
        ok: true,
        data: {
          dependencies: {
            'bundle-all': {
              name: 'bundle-all',
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

    expect(data.dependencies['bundle-all@1.0.0'].packaging).toEqual({
      signals: ['bundled-dependencies'],
      bundledDependencies: ['*']
    });
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

  it('only marks the resolved direct version as direct when multiple versions are installed', async () => {
    const projectPath = await makeTempDir('dr-agg-dup-versions');
    const pkg = {
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { uuid: '^9.0.0', 'lib-a': '^1.0.0' }
    };
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify(pkg));

    const data = await aggregateData({
      projectPath,
      pkgOverride: pkg,
      projectPackageJson: pkg,
      npmLsResult: {
        ok: true,
        data: {
          dependencies: {
            uuid: { name: 'uuid', version: '9.0.1' },
            'lib-a': {
              name: 'lib-a',
              version: '1.0.0',
              dependencies: {
                uuid: { name: 'uuid', version: '3.4.0' }
              }
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

    expect(data.dependencies['uuid@9.0.1'].usage.direct).toBe(true);
    expect(data.dependencies['uuid@3.4.0'].usage.direct).toBe(false);
    expect(data.dependencies['uuid@3.4.0'].usage.introduction).toBe('transitive');
    expect(data.dependencies['uuid@3.4.0'].usage.origins.topRootPackages).toEqual([
      { name: 'lib-a', version: '1.0.0' }
    ]);
    expect(data.summary.directCount).toBe(2);
    expect(data.summary.transitiveCount).toBe(1);
  });

  it('associates npm audit findings with the affected installed path, not every version of a package', async () => {
    const projectPath = await makeTempDir('dr-agg-vuln-paths');
    const directPath = path.join(projectPath, 'node_modules', 'uuid');
    const parentPath = path.join(projectPath, 'node_modules', 'lib-a');
    const vulnerablePath = path.join(parentPath, 'node_modules', 'uuid');
    const pkg = {
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { uuid: '^9.0.0', 'lib-a': '^1.0.0' }
    };
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify(pkg));

    const data = await aggregateData({
      projectPath,
      pkgOverride: pkg,
      projectPackageJson: pkg,
      npmLsResult: {
        ok: true,
        data: {
          dependencies: {
            uuid: { name: 'uuid', version: '9.0.1', path: directPath },
            'lib-a': {
              name: 'lib-a',
              version: '1.0.0',
              path: parentPath,
              dependencies: {
                uuid: { name: 'uuid', version: '3.4.0', path: vulnerablePath }
              }
            }
          }
        }
      },
      auditResult: {
        ok: true,
        data: {
          vulnerabilities: {
            uuid: {
              name: 'uuid',
              severity: 'high',
              range: '<7.0.0',
              nodes: [vulnerablePath],
              via: [{ source: 1234, name: 'uuid', title: 'Predictable values', severity: 'high', range: '<7.0.0', url: 'https://example.test/advisory' }]
            }
          }
        }
      },
      importGraphResult: { ok: true, data: {} },
      outdatedResult: { entries: [], unknownNames: [] },
      workspaceEnabled: false,
      workspaceType: 'none',
      workspacePackageCount: 1,
      resolvePaths: [projectPath]
    });

    expect(data.dependencies['uuid@9.0.1'].security.summary.high).toBe(0);
    expect(data.dependencies['uuid@3.4.0'].security.summary.high).toBe(1);
    expect(data.dependencies['uuid@3.4.0'].security.advisories?.[0].vulnerableRange).toBe('<7.0.0');
  });

  it('does not turn a low-confidence licence guess into a mismatch', async () => {
    const projectPath = await makeTempDir('dr-agg-license-confidence');
    const depPath = path.join(projectPath, 'node_modules', 'low-confidence');
    const pkg = { name: 'fixture-root', version: '1.0.0', dependencies: { 'low-confidence': '1.0.0' } };
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify(pkg));
    await fs.mkdir(depPath, { recursive: true });
    await fs.writeFile(path.join(depPath, 'package.json'), JSON.stringify({
      name: 'low-confidence', version: '1.0.0', license: 'ISC'
    }));
    await fs.writeFile(path.join(depPath, 'LICENSE'), 'THE SOFTWARE IS PROVIDED "AS IS"');

    const data = await aggregateData({
      projectPath,
      pkgOverride: pkg,
      projectPackageJson: pkg,
      npmLsResult: { ok: true, data: { dependencies: { 'low-confidence': { name: 'low-confidence', version: '1.0.0', path: depPath } } } },
      auditResult: { ok: true, data: {} },
      importGraphResult: { ok: true, data: {} },
      outdatedResult: { entries: [], unknownNames: [] },
      workspaceEnabled: false,
      workspaceType: 'none',
      workspacePackageCount: 1,
      resolvePaths: [projectPath]
    });

    expect(data.dependencies['low-confidence@1.0.0'].compliance.license.status).toBe('declared-only');
    expect(data.dependencies['low-confidence@1.0.0'].compliance.license.inferred?.confidence).toBe('low');
  });

  it('drops unsafe package metadata links and strips URL credentials', async () => {
    const projectPath = await makeTempDir('dr-agg-safe-links');
    const depPath = path.join(projectPath, 'node_modules', 'unsafe-links');
    const pkg = { name: 'fixture-root', version: '1.0.0', dependencies: { 'unsafe-links': '1.0.0' } };
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify(pkg));
    await fs.mkdir(depPath, { recursive: true });
    await fs.writeFile(path.join(depPath, 'package.json'), JSON.stringify({
      name: 'unsafe-links',
      version: '1.0.0',
      license: 'MIT',
      repository: 'javascript:alert(1)',
      homepage: 'https://user:secret@example.test/project',
      bugs: 'data:text/html,unsafe'
    }));

    const data = await aggregateData({
      projectPath,
      pkgOverride: pkg,
      projectPackageJson: pkg,
      npmLsResult: { ok: true, data: { dependencies: { 'unsafe-links': { name: 'unsafe-links', version: '1.0.0', path: depPath } } } },
      auditResult: { ok: true, data: {} },
      importGraphResult: { ok: true, data: {} },
      outdatedResult: { entries: [], unknownNames: [] },
      workspaceEnabled: false,
      workspaceType: 'none',
      workspacePackageCount: 1,
      resolvePaths: [projectPath]
    });

    const links = data.dependencies['unsafe-links@1.0.0'].package.links;
    expect(links.repository).toBeUndefined();
    expect(links.bugs).toBeUndefined();
    expect(links.homepage).toBe('https://example.test/project');
  });

  it('classifies duplicate versions correctly in combined workspace graphs', async () => {
    const projectPath = await makeTempDir('dr-agg-workspace-dup');
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({ name: 'fixture-root', version: '1.0.0' }));
    const mergedPkg = {
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { uuid: '^9.0.0', 'lib-a': '^1.0.0' }
    };

    const data = await aggregateData({
      projectPath,
      pkgOverride: mergedPkg,
      projectPackageJson: { name: 'fixture-root', version: '1.0.0' },
      npmLsResult: {
        ok: true,
        data: {
          dependencies: {
            'workspace-a': {
              name: 'workspace-a',
              version: '1.0.0',
              dependencies: {
                uuid: { name: 'uuid', version: '9.0.1' },
                'lib-a': {
                  name: 'lib-a',
                  version: '1.0.0',
                  dependencies: {
                    uuid: { name: 'uuid', version: '3.4.0' }
                  }
                }
              }
            }
          }
        }
      },
      auditResult: { ok: true, data: {} },
      importGraphResult: { ok: true, data: {} },
      outdatedResult: { entries: [], unknownNames: [] },
      workspaceEnabled: true,
      workspaceType: 'pnpm',
      workspacePackageCount: 1,
      workspacePackageIds: new Set(['workspace-a@1.0.0']),
      workspacePackageNames: new Set(['workspace-a']),
      resolvePaths: [projectPath]
    });

    expect(data.dependencies['workspace-a@1.0.0']).toBeUndefined();
    expect(data.dependencies['uuid@9.0.1'].usage.direct).toBe(true);
    expect(data.dependencies['uuid@3.4.0'].usage.direct).toBe(false);
    expect(data.dependencies['uuid@3.4.0'].usage.origins.topRootPackages).toEqual([
      { name: 'lib-a', version: '1.0.0' }
    ]);
    expect(data.summary.directCount).toBe(2);
  });

  it('keeps a package direct when the same version is also reachable transitively', async () => {
    const projectPath = await makeTempDir('dr-agg-direct-and-transitive');
    const pkg = {
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { uuid: '^9.0.0', 'lib-a': '^1.0.0' }
    };
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify(pkg));

    const data = await aggregateData({
      projectPath,
      pkgOverride: pkg,
      projectPackageJson: pkg,
      npmLsResult: {
        ok: true,
        data: {
          dependencies: {
            uuid: { name: 'uuid', version: '9.0.1' },
            'lib-a': {
              name: 'lib-a',
              version: '1.0.0',
              dependencies: {
                uuid: { name: 'uuid', version: '9.0.1' }
              }
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

    const uuid = data.dependencies['uuid@9.0.1'];
    expect(uuid.usage.direct).toBe(true);
    expect(uuid.usage.depth).toBe(1);
    expect(uuid.graph.fanIn).toBe(1);
    expect(data.summary.directCount).toBe(2);
  });

  it('does not mark undeclared top-level tree entries as direct (flat/hoisted trees)', async () => {
    const projectPath = await makeTempDir('dr-agg-flat-tree');
    const pkg = {
      name: 'fixture-root',
      version: '1.0.0',
      dependencies: { 'lib-a': '^1.0.0' }
    };
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify(pkg));

    const data = await aggregateData({
      projectPath,
      pkgOverride: pkg,
      projectPackageJson: pkg,
      npmLsResult: {
        ok: true,
        data: {
          // Legacy npm lockfile v1 / `yarn list` fallbacks emit hoisted
          // transitives at the top level of the tree.
          dependencies: {
            'lib-a': { name: 'lib-a', version: '1.0.0' },
            'hoisted-transitive': { name: 'hoisted-transitive', version: '2.0.0' }
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

    expect(data.dependencies['lib-a@1.0.0'].usage.direct).toBe(true);
    expect(data.dependencies['hoisted-transitive@2.0.0'].usage.direct).toBe(false);
    expect(data.summary.directCount).toBe(1);
  });
});
