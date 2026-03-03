import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from 'vitest';

type ProjectPackageManifest = {
  dependencies?: Record<string, string>;
  packageManager?: string;
};

/**
 * Load the repository root package manifest used for publishing the CLI.
 */
async function loadRootPackageManifest(): Promise<ProjectPackageManifest> {
  const packageJsonPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    'package.json'
  );
  const raw = await fs.readFile(packageJsonPath, 'utf8');
  return JSON.parse(raw) as ProjectPackageManifest;
}

describe('package manifest policy', () => {
  it('does not declare runtime dependencies', async () => {
    const manifest = await loadRootPackageManifest();
    // Runtime deps would force installs during `npx dependency-radar`.
    const dependencyKeys = Object.keys(manifest.dependencies || {});
    expect(dependencyKeys).toEqual([]);
  });

  it('pins packageManager to npm', async () => {
    const manifest = await loadRootPackageManifest();
    // Explicit npm pin avoids Corepack auto-pinning pnpm/yarn during tooling runs.
    expect(typeof manifest.packageManager).toBe('string');
    expect(manifest.packageManager).toMatch(/^npm@/);
  });
});
