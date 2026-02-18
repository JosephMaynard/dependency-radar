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

import { runNpmLs } from './npmLs';

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

function buildPnpmTreePayload() {
  return [
    {
      dependencies: {
        esbuild: {
          name: 'esbuild',
          version: '0.25.4',
          dependencies: {
            '@esbuild/darwin-arm64': {
              name: '@esbuild/darwin-arm64',
              version: '0.25.4'
            },
            '@esbuild/linux-arm64': {
              name: '@esbuild/linux-arm64',
              version: '0.25.4'
            }
          }
        }
      }
    }
  ];
}

describe('runNpmLs pnpm normalization', () => {
  it('keeps only installed pnpm optional platform packages', async () => {
    const projectPath = await makeTempDir('dr-pnpm-installed-filter');
    const tempDir = await makeTempDir('dr-pnpm-installed-filter-out');

    await fs.mkdir(path.join(projectPath, 'node_modules', '.pnpm', '@esbuild+darwin-arm64@0.25.4'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'node_modules', '.pnpm', 'esbuild@0.25.4'), { recursive: true });

    runCommandMock.mockResolvedValue({
      code: 0,
      stdout: JSON.stringify(buildPnpmTreePayload()),
      stderr: ''
    });

    const result = await runNpmLs(projectPath, tempDir, 'pnpm');
    expect(result.ok).toBe(true);

    const deps = result.data?.dependencies || {};
    expect(deps.esbuild).toBeDefined();
    expect(deps.esbuild.dependencies['@esbuild/darwin-arm64']).toBeDefined();
    expect(deps.esbuild.dependencies['@esbuild/linux-arm64']).toBeUndefined();
  });

  it('includes workspace-linked packages found in node_modules', async () => {
    const projectPath = await makeTempDir('dr-pnpm-linked-include');
    const tempDir = await makeTempDir('dr-pnpm-linked-include-out');

    const linkedPackageDir = path.join(projectPath, 'node_modules', '@scope', 'linked');
    await fs.mkdir(linkedPackageDir, { recursive: true });
    await fs.writeFile(path.join(linkedPackageDir, 'package.json'), JSON.stringify({ name: '@scope/linked', version: '1.0.0' }));

    runCommandMock.mockResolvedValue({
      code: 0,
      stdout: JSON.stringify([
        {
          dependencies: {
            '@scope/linked': { name: '@scope/linked', version: '1.0.0' }
          }
        }
      ]),
      stderr: ''
    });

    const result = await runNpmLs(projectPath, tempDir, 'pnpm');
    expect(result.ok).toBe(true);
    expect(result.data?.dependencies['@scope/linked']).toBeDefined();
  });

  it('excludes mismatched fallback node_modules versions', async () => {
    const projectPath = await makeTempDir('dr-pnpm-linked-mismatch');
    const tempDir = await makeTempDir('dr-pnpm-linked-mismatch-out');

    const linkedPackageDir = path.join(projectPath, 'node_modules', '@scope', 'linked');
    await fs.mkdir(linkedPackageDir, { recursive: true });
    await fs.writeFile(path.join(linkedPackageDir, 'package.json'), JSON.stringify({ name: '@scope/linked', version: '2.0.0' }));

    runCommandMock.mockResolvedValue({
      code: 0,
      stdout: JSON.stringify([
        {
          dependencies: {
            '@scope/linked': { name: '@scope/linked', version: '1.0.0' }
          }
        }
      ]),
      stderr: ''
    });

    const result = await runNpmLs(projectPath, tempDir, 'pnpm');
    expect(result.ok).toBe(true);
    expect(result.data?.dependencies['@scope/linked']).toBeUndefined();
  });
});
