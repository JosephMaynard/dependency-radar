import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { parseJsonOutput, readLicenseFromPackageDir, resolvePackageJsonPath } from './utils';

const tempDirs: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), `${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe('parseJsonOutput', () => {
  it('parses JSONL output', () => {
    const raw = '{"type":"one"}\n{"type":"two"}';
    const parsed = parseJsonOutput(raw);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
  });
});

describe('readLicenseFromPackageDir', () => {
  it('reads LICENSE.md files and package license fields', async () => {
    const dir = await makeTempDir('dr-license-md');
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0', license: 'MIT' }));
    await fs.writeFile(path.join(dir, 'LICENSE.md'), 'Permission is hereby granted');

    const result = await readLicenseFromPackageDir(dir);
    expect(result?.license).toBe('MIT');
    expect(result?.licenseFile?.endsWith('LICENSE.md')).toBe(true);
    expect(result?.licenseText?.includes('Permission is hereby granted')).toBe(true);
  });

  it('detects LICENCE files when package.json has no license field', async () => {
    const dir = await makeTempDir('dr-licence');
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0' }));
    await fs.writeFile(path.join(dir, 'LICENCE'), 'MIT License');

    const result = await readLicenseFromPackageDir(dir);
    expect(result?.license).toBeUndefined();
    expect(result?.licenseFile?.endsWith('LICENCE')).toBe(true);
  });
});

describe('resolvePackageJsonPath', () => {
  it('resolves package.json from pnpm virtual store entries', async () => {
    const root = await makeTempDir('dr-pnpm-path');
    const pkgJsonPath = path.join(
      root,
      'node_modules',
      '.pnpm',
      '@scope+demo@1.2.3',
      'node_modules',
      '@scope',
      'demo',
      'package.json'
    );
    await fs.mkdir(path.dirname(pkgJsonPath), { recursive: true });
    await fs.writeFile(pkgJsonPath, JSON.stringify({ name: '@scope/demo', version: '1.2.3' }));

    const resolved = await resolvePackageJsonPath('@scope/demo', [root], '1.2.3');
    expect(resolved).toBe(pkgJsonPath);
  });

  it('falls back to standard node_modules resolution', async () => {
    const root = await makeTempDir('dr-node-path');
    const pkgDir = path.join(root, 'node_modules', 'plain-demo');
    await fs.mkdir(pkgDir, { recursive: true });
    await fs.writeFile(path.join(pkgDir, 'package.json'), JSON.stringify({ name: 'plain-demo', version: '0.1.0', main: 'index.js' }));
    await fs.writeFile(path.join(pkgDir, 'index.js'), 'module.exports = 1;');

    const resolved = await resolvePackageJsonPath('plain-demo', [root]);
    expect(resolved?.endsWith(path.join('node_modules', 'plain-demo', 'package.json'))).toBe(true);
  });
});
