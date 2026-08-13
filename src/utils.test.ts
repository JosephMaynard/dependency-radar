import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { findLockDir, parseJsonOutput, readLicenseFromPackageDir, resolvePackageJsonPath, writeJsonFile } from './utils';

const tempDirs: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), `${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  vi.restoreAllMocks();
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

describe('writeJsonFile', () => {
  it('falls back to compact JSON when pretty serialization overflows', async () => {
    const dir = await makeTempDir('dr-write-json');
    const filePath = path.join(dir, 'large.json');
    const originalStringify = JSON.stringify.bind(JSON);
    vi.spyOn(JSON, 'stringify').mockImplementation((value: any, replacer?: any, space?: any) => {
      if (space === 2) {
        throw new RangeError('Invalid string length');
      }
      return originalStringify(value, replacer, space);
    });

    await writeJsonFile(filePath, { hello: 'world' });
    const content = await fs.readFile(filePath, 'utf8');
    expect(content).toBe('{"hello":"world"}');
  });
});

describe('findLockDir', () => {
  it('returns the project directory when it holds a lockfile', async () => {
    const dir = await makeTempDir('dr-lockdir-self');
    await fs.writeFile(path.join(dir, 'package-lock.json'), '{}', 'utf8');
    expect(await findLockDir(dir, ['package-lock.json'])).toBe(dir);
  });

  it('accepts an ancestor lockfile when the ancestor is a workspace root', async () => {
    const root = await makeTempDir('dr-lockdir-ws');
    const child = path.join(root, 'packages', 'child');
    await fs.mkdir(child, { recursive: true });
    await fs.writeFile(path.join(root, 'package-lock.json'), '{}', 'utf8');
    await fs.writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ name: 'root', workspaces: ['packages/*'] }),
      'utf8',
    );
    expect(await findLockDir(child, ['package-lock.json'])).toBe(root);
  });

  it('accepts an ancestor lockfile when the ancestor is a pnpm workspace root', async () => {
    const root = await makeTempDir('dr-lockdir-pnpm');
    const child = path.join(root, 'packages', 'child');
    await fs.mkdir(child, { recursive: true });
    await fs.writeFile(path.join(root, 'pnpm-lock.yaml'), '', 'utf8');
    await fs.writeFile(path.join(root, 'pnpm-workspace.yaml'), "packages:\n  - 'packages/*'\n", 'utf8');
    expect(await findLockDir(child, ['pnpm-lock.yaml'])).toBe(root);
  });

  it('rejects an unrelated ancestor lockfile from a non-workspace project', async () => {
    const outer = await makeTempDir('dr-lockdir-unrelated');
    const nested = path.join(outer, 'examples', 'standalone');
    await fs.mkdir(nested, { recursive: true });
    await fs.writeFile(path.join(outer, 'package-lock.json'), '{}', 'utf8');
    await fs.writeFile(
      path.join(outer, 'package.json'),
      JSON.stringify({ name: 'unrelated-standalone' }),
      'utf8',
    );
    expect(await findLockDir(nested, ['package-lock.json'])).toBeUndefined();
  });

  it('rejects an ancestor whose workspace patterns do not cover the scanned path', async () => {
    const root = await makeTempDir('dr-lockdir-nonmember');
    const nested = path.join(root, 'examples', 'standalone');
    await fs.mkdir(nested, { recursive: true });
    await fs.writeFile(path.join(root, 'package-lock.json'), '{}', 'utf8');
    await fs.writeFile(
      path.join(root, 'package.json'),
      JSON.stringify({ name: 'root', workspaces: ['packages/*'] }),
      'utf8',
    );
    expect(await findLockDir(nested, ['package-lock.json'])).toBeUndefined();
  });
});
