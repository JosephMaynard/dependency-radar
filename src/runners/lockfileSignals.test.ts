import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const { runCommandMock, writeJsonFileMock } = vi.hoisted(() => ({
  runCommandMock: vi.fn(),
  writeJsonFileMock: vi.fn(async () => undefined)
}));

vi.mock('../utils', async () => {
  const actual = await vi.importActual<typeof import('../utils')>('../utils');
  return {
    ...actual,
    runCommand: runCommandMock,
    writeJsonFile: writeJsonFileMock
  };
});

import { runLockfileSupplyChainSignals } from './lockfileSignals';

const tempDirs: string[] = [];

async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), `${prefix}-`));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  runCommandMock.mockReset();
  writeJsonFileMock.mockReset();
  await Promise.all(tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe('lockfile supply-chain signals', () => {
  it('detects non-registry sources and missing integrity in package-lock.json', async () => {
    const projectPath = await makeTempDir('dr-lockfile-signals');
    const tempDir = await makeTempDir('dr-lockfile-signals-out');
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/git-dep': {
          version: '1.0.0',
          resolved: 'git+https://github.com/example/git-dep.git'
        },
        'node_modules/tarball-dep': {
          version: '2.0.0',
          resolved: 'https://downloads.example.com/tarball-dep-2.0.0.tgz'
        },
        'node_modules/plain-dep': {
          version: '3.0.0',
          resolved: 'https://registry.npmjs.org/plain-dep/-/plain-dep-3.0.0.tgz'
        }
      }
    }));

    const result = await runLockfileSupplyChainSignals(projectPath, tempDir, { persistToDisk: false });
    expect(result.ok).toBe(true);
    const types = new Set(result.data?.signals.map((signal) => signal.type));
    expect(types.has('git-dependency')).toBe(true);
    expect(types.has('non-registry-tarball')).toBe(true);
    expect(types.has('missing-integrity')).toBe(true);
  });

  it('detects file dependencies and unexpected registry hosts', async () => {
    const projectPath = await makeTempDir('dr-lockfile-sources');
    const tempDir = await makeTempDir('dr-lockfile-sources-out');
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/local-dep': {
          version: '1.0.0',
          resolved: 'file:../local-dep',
          integrity: 'sha512-local'
        },
        'node_modules/custom-registry-dep': {
          version: '2.0.0',
          resolved: 'https://registry.company.test/custom-registry-dep',
          integrity: 'sha512-custom'
        }
      }
    }));

    const result = await runLockfileSupplyChainSignals(projectPath, tempDir, { persistToDisk: false });

    expect(result.ok).toBe(true);
    expect(result.data?.signals.map((signal) => signal.type)).toEqual(
      expect.arrayContaining(['file-dependency', 'unexpected-registry-host'])
    );
    expect(result.data?.signals.find((signal) => signal.type === 'unexpected-registry-host')?.detail)
      .toContain('registry.company.test');
  });

  it('allows configured registry hosts without unexpected-host findings', async () => {
    const projectPath = await makeTempDir('dr-lockfile-expected-host');
    const tempDir = await makeTempDir('dr-lockfile-expected-host-out');
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/custom-registry-dep': {
          version: '2.0.0',
          resolved: 'https://registry.company.test/custom-registry-dep',
          integrity: 'sha512-custom'
        }
      }
    }));

    const result = await runLockfileSupplyChainSignals(projectPath, tempDir, {
      persistToDisk: false,
      expectedRegistryHosts: ['registry.company.test']
    });

    expect(result.ok).toBe(true);
    expect(result.data?.signals.some((signal) => signal.type === 'unexpected-registry-host')).toBe(false);
  });

  it('normalizes scoped package names from text lockfile selectors', async () => {
    const projectPath = await makeTempDir('dr-lockfile-scoped');
    const tempDir = await makeTempDir('dr-lockfile-scoped-out');
    await fs.writeFile(path.join(projectPath, 'yarn.lock'), [
      '"@scope/pkg@^1.0.0":',
      '  version "1.2.3"',
      '  resolved "https://downloads.example.com/scope-pkg-1.2.3.tgz"',
      '  integrity sha512-scoped'
    ].join('\n'));

    const result = await runLockfileSupplyChainSignals(projectPath, tempDir, { persistToDisk: false });

    expect(result.ok).toBe(true);
    expect(result.data?.signals).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'non-registry-tarball',
          packageName: '@scope/pkg',
          packageVersion: '1.2.3'
        })
      ])
    );
  });

  it('normalizes package names from nested package-lock paths', async () => {
    const projectPath = await makeTempDir('dr-lockfile-nested');
    const tempDir = await makeTempDir('dr-lockfile-nested-out');
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        'node_modules/parent/node_modules/@scope/nested': {
          version: '4.5.6',
          resolved: 'https://downloads.example.com/scope-nested-4.5.6.tgz',
          integrity: 'sha512-nested'
        }
      }
    }));

    const result = await runLockfileSupplyChainSignals(projectPath, tempDir, { persistToDisk: false });

    expect(result.ok).toBe(true);
    expect(result.data?.signals).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'non-registry-tarball',
          packageName: '@scope/nested',
          packageVersion: '4.5.6'
        })
      ])
    );
  });

  it('skips npm audit signatures in offline mode', async () => {
    const projectPath = await makeTempDir('dr-lockfile-signatures');
    const tempDir = await makeTempDir('dr-lockfile-signatures-out');
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {} }));

    const result = await runLockfileSupplyChainSignals(projectPath, tempDir, {
      persistToDisk: false,
      auditSignatures: true,
      offline: true
    });

    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.signatureAudit?.ok).toBe(false);
    expect(result.data?.signatureAudit?.status).toBe('skipped');
    expect(result.data?.signatureAudit?.error).toBe('skipped (--offline)');
  });

  it('runs npm audit signatures when requested online', async () => {
    const projectPath = await makeTempDir('dr-lockfile-signatures-online');
    const tempDir = await makeTempDir('dr-lockfile-signatures-online-out');
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {} }));
    runCommandMock.mockResolvedValue({ code: 0, stdout: 'verified registry signatures', stderr: '' });

    const result = await runLockfileSupplyChainSignals(projectPath, tempDir, {
      persistToDisk: false,
      auditSignatures: true
    });

    expect(result.ok).toBe(true);
    expect(runCommandMock).toHaveBeenCalledWith('npm', ['audit', 'signatures'], { cwd: projectPath });
    expect(result.data?.signatureAudit?.ok).toBe(true);
  });
});
