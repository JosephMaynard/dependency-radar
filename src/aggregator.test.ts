import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { aggregateData } from './aggregator';

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
