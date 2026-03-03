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

type PnpmTreeNode = {
  name: string;
  version: string;
  dependencies?: Record<string, PnpmTreeNode>;
};

type PnpmTreePayload = Array<{
  dependencies: Record<string, PnpmTreeNode>;
}>;

function buildPnpmTreePayload(): PnpmTreePayload {
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

describe('runNpmLs lockfile-first parsing', () => {
  it('builds pnpm tree from pnpm-lock.yaml without running pnpm list', async () => {
    const projectPath = await makeTempDir('dr-lock-pnpm');
    const tempDir = await makeTempDir('dr-lock-pnpm-out');

    await fs.mkdir(path.join(projectPath, 'node_modules', '.pnpm', 'a@1.0.0'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'node_modules', '.pnpm', 'b@1.0.0'), { recursive: true });
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-pnpm',
      version: '1.0.0',
      dependencies: { a: '1.0.0' }
    }));
    await fs.writeFile(path.join(projectPath, 'pnpm-lock.yaml'), `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: 1.0.0
packages:
  a@1.0.0: {}
  b@1.0.0: {}
snapshots:
  a@1.0.0:
    dependencies:
      b: 1.0.0
  b@1.0.0: {}
`.trim());

    const result = await runNpmLs(projectPath, tempDir, 'pnpm');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies.a).toBeDefined();
    expect(result.data?.dependencies.a?.dependencies?.b).toBeDefined();
  });

  it('keeps resolved pnpm dependencies when peer ranges declare the same package', async () => {
    const projectPath = await makeTempDir('dr-lock-pnpm-peer-range');
    const tempDir = await makeTempDir('dr-lock-pnpm-peer-range-out');

    await fs.mkdir(path.join(projectPath, 'node_modules', '.pnpm', 'a@1.0.0'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'node_modules', '.pnpm', 'b@1.0.0'), { recursive: true });
    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-pnpm-peer-range',
      version: '1.0.0',
      dependencies: { a: '1.0.0' }
    }));
    await fs.writeFile(path.join(projectPath, 'pnpm-lock.yaml'), `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: 1.0.0
packages:
  a@1.0.0: {}
  b@1.0.0: {}
snapshots:
  a@1.0.0:
    dependencies:
      b: 1.0.0
    peerDependencies:
      b: ^1.0.0
  b@1.0.0: {}
`.trim());

    const result = await runNpmLs(projectPath, tempDir, 'pnpm');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies.a).toBeDefined();
    expect(result.data?.dependencies.a?.dependencies?.b).toBeDefined();
  });

  it('builds npm tree from package-lock.json without running npm ls', async () => {
    const projectPath = await makeTempDir('dr-lock-npm');
    const tempDir = await makeTempDir('dr-lock-npm-out');

    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-npm',
      version: '1.0.0',
      dependencies: { a: '1.0.0' }
    }));
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
      name: 'lock-npm',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'lock-npm',
          version: '1.0.0',
          dependencies: { a: '1.0.0' }
        },
        'node_modules/a': {
          version: '1.0.0',
          dependencies: { b: '1.0.0' }
        },
        'node_modules/b': {
          version: '1.0.0'
        }
      }
    }));

    const result = await runNpmLs(projectPath, tempDir, 'npm');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies.a).toBeDefined();
    expect(result.data?.dependencies.a?.path).toBe(path.join(projectPath, 'node_modules', 'a'));
    expect(result.data?.dependencies.a?.dependencies?.b).toBeDefined();
    expect(result.data?.dependencies.a?.dependencies?.b?.path).toBe(path.join(projectPath, 'node_modules', 'b'));
  });

  it('filters npm optional platform packages that are not installed', async () => {
    const projectPath = await makeTempDir('dr-lock-npm-installed-only');
    const tempDir = await makeTempDir('dr-lock-npm-installed-only-out');

    await fs.mkdir(path.join(projectPath, 'node_modules', 'esbuild'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'node_modules', '@esbuild', 'darwin-arm64'), { recursive: true });

    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-npm-installed-only',
      version: '1.0.0',
      dependencies: { esbuild: '0.21.5' }
    }));
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
      name: 'lock-npm-installed-only',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'lock-npm-installed-only',
          version: '1.0.0',
          dependencies: { esbuild: '0.21.5' }
        },
        'node_modules/esbuild': {
          version: '0.21.5',
          optionalDependencies: {
            '@esbuild/darwin-arm64': '0.21.5',
            '@esbuild/linux-arm64': '0.21.5'
          }
        },
        'node_modules/@esbuild/darwin-arm64': {
          version: '0.21.5'
        },
        'node_modules/@esbuild/linux-arm64': {
          version: '0.21.5'
        }
      }
    }));

    const result = await runNpmLs(projectPath, tempDir, 'npm');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies.esbuild).toBeDefined();
    expect(result.data?.dependencies.esbuild?.dependencies?.['@esbuild/darwin-arm64']).toBeDefined();
    expect(result.data?.dependencies.esbuild?.dependencies?.['@esbuild/linux-arm64']).toBeUndefined();
  });

  it('does not resolve lockfile package paths that traverse outside lock dir', async () => {
    const projectPath = await makeTempDir('dr-lock-npm-traversal-path');
    const tempDir = await makeTempDir('dr-lock-npm-traversal-path-out');

    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-npm-traversal-path',
      version: '1.0.0',
      dependencies: { '../evil': '1.0.0' }
    }));
    await fs.writeFile(path.join(projectPath, 'package-lock.json'), JSON.stringify({
      name: 'lock-npm-traversal-path',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'lock-npm-traversal-path',
          version: '1.0.0',
          dependencies: { '../evil': '1.0.0' }
        },
        'node_modules/../evil': {
          version: '1.0.0'
        }
      }
    }));

    const result = await runNpmLs(projectPath, tempDir, 'npm');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies['../evil']).toBeDefined();
    expect(result.data?.dependencies['../evil']?.path).toBeUndefined();
  });

  it('builds yarn tree from yarn.lock without running yarn list', async () => {
    const projectPath = await makeTempDir('dr-lock-yarn');
    const tempDir = await makeTempDir('dr-lock-yarn-out');

    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-yarn',
      version: '1.0.0',
      dependencies: { a: '1.0.0' }
    }));
    await fs.writeFile(path.join(projectPath, 'yarn.lock'), `
# yarn lockfile v1

a@1.0.0:
  version "1.0.0"
  dependencies:
    b "1.0.0"

b@1.0.0:
  version "1.0.0"
`.trim());

    const result = await runNpmLs(projectPath, tempDir, 'yarn');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies.a).toBeDefined();
    expect(result.data?.dependencies.a?.dependencies?.b).toBeDefined();
  });

  it('builds yarn v1 tree when selector keys include quoted ranges', async () => {
    const projectPath = await makeTempDir('dr-lock-yarn-v1-quoted');
    const tempDir = await makeTempDir('dr-lock-yarn-v1-quoted-out');

    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-yarn-v1-quoted',
      version: '1.0.0',
      dependencies: { through: '^2.3.6' }
    }));
    await fs.writeFile(path.join(projectPath, 'yarn.lock'), `
# yarn lockfile v1

# Yarn v1 can merge selectors into one key and quote individual selector entries.
"through@>=2.2.7 <3", through@^2.3.6:
  version "2.3.8"
`.trim());

    const result = await runNpmLs(projectPath, tempDir, 'yarn');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies.through).toBeDefined();
    expect(result.data?.dependencies.through?.version).toBe('2.3.8');
  });

  it('builds yarn v1 tree when all selector aliases are individually quoted', async () => {
    const projectPath = await makeTempDir('dr-lock-yarn-v1-all-quoted');
    const tempDir = await makeTempDir('dr-lock-yarn-v1-all-quoted-out');

    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-yarn-v1-all-quoted',
      version: '1.0.0',
      dependencies: { through: '^2.3.6' }
    }));
    await fs.writeFile(path.join(projectPath, 'yarn.lock'), `
# yarn lockfile v1

# Some lockfiles quote each alias separately.
"through@>=2.2.7 <3", "through@^2.3.6":
  version "2.3.8"
`.trim());

    const result = await runNpmLs(projectPath, tempDir, 'yarn');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies.through).toBeDefined();
    expect(result.data?.dependencies.through?.version).toBe('2.3.8');
  });

  it('builds yarn berry tree from combined selectors with npm-prefixed ranges', async () => {
    const projectPath = await makeTempDir('dr-lock-yarn-berry');
    const tempDir = await makeTempDir('dr-lock-yarn-berry-out');

    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'lock-yarn-berry',
      version: '1.0.0',
      dependencies: { chalk: '^4.1.1' }
    }));
    await fs.writeFile(path.join(projectPath, 'yarn.lock'), `
__metadata:
  version: 8
  cacheKey: 10c0

# Berry keys are often emitted as one quoted selector list with npm:-prefixed ranges.
"chalk@npm:^4.1.0, chalk@npm:^4.1.1":
  version: 4.1.2
  dependencies:
    ansi-styles: "npm:^4.1.0"

# Child entries use the same selector-list pattern and should still resolve correctly.
"ansi-styles@npm:^4.0.0, ansi-styles@npm:^4.1.0":
  version: 4.3.0
`.trim());

    const result = await runNpmLs(projectPath, tempDir, 'yarn');
    expect(result.ok).toBe(true);
    expect(runCommandMock).not.toHaveBeenCalled();
    expect(result.data?.dependencies.chalk).toBeDefined();
    expect(result.data?.dependencies.chalk?.version).toBe('4.1.2');
    expect(result.data?.dependencies.chalk?.dependencies?.['ansi-styles']).toBeDefined();
    expect(result.data?.dependencies.chalk?.dependencies?.['ansi-styles']?.version).toBe('4.3.0');
  });

  it('does not read lockfiles above the project path boundary', async () => {
    const rootPath = await makeTempDir('dr-lock-boundary-root');
    const projectPath = path.join(rootPath, 'project');
    const tempDir = await makeTempDir('dr-lock-boundary-out');
    await fs.mkdir(projectPath, { recursive: true });

    await fs.writeFile(path.join(rootPath, 'package-lock.json'), JSON.stringify({
      name: 'outside-root',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'outside-root',
          version: '1.0.0',
          dependencies: { outside: '1.0.0' }
        },
        'node_modules/outside': {
          version: '1.0.0'
        }
      }
    }));

    runCommandMock.mockResolvedValue({
      code: 0,
      stdout: JSON.stringify({
        dependencies: {
          inside: {
            version: '1.0.0'
          }
        }
      }),
      stderr: ''
    });

    const result = await runNpmLs(projectPath, tempDir, 'npm');
    expect(result.ok).toBe(true);
    expect(runCommandMock).toHaveBeenCalledTimes(1);
    expect(result.data?.dependencies.inside).toBeDefined();
    expect(result.data?.dependencies.outside).toBeUndefined();
  });

  it('falls back to npm ls when workspace package key is missing in lockfile packages map', async () => {
    const rootPath = await makeTempDir('dr-lock-workspace-root');
    const projectPath = path.join(rootPath, 'packages', 'app');
    const tempDir = await makeTempDir('dr-lock-workspace-out');
    await fs.mkdir(projectPath, { recursive: true });

    await fs.writeFile(path.join(projectPath, 'package.json'), JSON.stringify({
      name: 'workspace-app',
      version: '1.0.0'
    }));
    await fs.writeFile(path.join(rootPath, 'package-lock.json'), JSON.stringify({
      name: 'workspace-root',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'workspace-root',
          version: '1.0.0',
          dependencies: { outside: '1.0.0' }
        },
        'node_modules/outside': {
          version: '1.0.0'
        }
      }
    }));

    runCommandMock.mockResolvedValue({
      code: 0,
      stdout: JSON.stringify({
        dependencies: {
          inside: {
            version: '1.0.0'
          }
        }
      }),
      stderr: ''
    });

    const result = await runNpmLs(projectPath, tempDir, 'npm', {
      lockfileSearchRoot: rootPath
    });
    expect(result.ok).toBe(true);
    expect(runCommandMock).toHaveBeenCalledTimes(1);
    expect(result.data?.dependencies.inside).toBeDefined();
    expect(result.data?.dependencies.outside).toBeUndefined();
  });
});
