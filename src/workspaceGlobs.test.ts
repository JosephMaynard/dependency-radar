import { describe, expect, it } from 'vitest';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach } from 'vitest';
import {
  expandWorkspacePatterns,
  matchesWorkspacePatterns,
} from './workspaceGlobs';

const tempDirs: string[] = [];
async function makeTempDir(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), `${prefix}-`));
  tempDirs.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((d) => fs.rm(d, { recursive: true, force: true })));
});

describe('matchesWorkspacePatterns', () => {
  it('matches one-level, nested, and recursive globs', () => {
    expect(matchesWorkspacePatterns(['packages/*'], 'packages/a')).toBe(true);
    expect(matchesWorkspacePatterns(['packages/*'], 'packages/a/b')).toBe(false);
    expect(matchesWorkspacePatterns(['packages/*/plugins/*'], 'packages/a/plugins/p1')).toBe(true);
    expect(matchesWorkspacePatterns(['packages/**'], 'packages/a/b/c')).toBe(true);
    expect(matchesWorkspacePatterns(['packages/**'], 'other/a')).toBe(false);
  });

  it('honours negated patterns', () => {
    const patterns = ['packages/*', '!packages/internal'];
    expect(matchesWorkspacePatterns(patterns, 'packages/app')).toBe(true);
    expect(matchesWorkspacePatterns(patterns, 'packages/internal')).toBe(false);
  });
});

describe('expandWorkspacePatterns', () => {
  it('expands nested wildcard patterns to real directories', async () => {
    const root = await makeTempDir('dr-globs-nested');
    for (const rel of ['packages/a/plugins/p1', 'packages/a/plugins/p2', 'packages/b', 'packages/a/src']) {
      await fs.mkdir(path.join(root, rel), { recursive: true });
    }
    const dirs = await expandWorkspacePatterns(root, ['packages/*/plugins/*']);
    expect(dirs.map((d) => path.relative(root, d)).sort()).toEqual([
      path.join('packages', 'a', 'plugins', 'p1'),
      path.join('packages', 'a', 'plugins', 'p2'),
    ]);
  });

  it('applies exclusions and skips node_modules', async () => {
    const root = await makeTempDir('dr-globs-excl');
    for (const rel of ['packages/app', 'packages/internal', 'packages/node_modules/dep']) {
      await fs.mkdir(path.join(root, rel), { recursive: true });
    }
    const dirs = await expandWorkspacePatterns(root, ['packages/*', '!packages/internal']);
    expect(dirs.map((d) => path.relative(root, d))).toEqual([path.join('packages', 'app')]);
  });
});
