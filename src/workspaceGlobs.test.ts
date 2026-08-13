import { describe, expect, it } from 'vitest';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach } from 'vitest';
import {
  expandWorkspacePatterns,
  matchesWorkspacePatterns,
  rangeSatisfies,
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

describe('rangeSatisfies', () => {
  it('evaluates relational comparators', () => {
    expect(rangeSatisfies('>=1.11.0', '1.10.0')).toBe(false);
    expect(rangeSatisfies('>=1.11.0', '1.11.21')).toBe(true);
    expect(rangeSatisfies('<2.0.0', '1.9.9')).toBe(true);
    expect(rangeSatisfies('>1.2', '1.2.9')).toBe(false);
    expect(rangeSatisfies('>1.2', '1.3.0')).toBe(true);
    expect(rangeSatisfies('<=1.2', '1.2.9')).toBe(true);
  });

  it('evaluates compounds, unions, and hyphen ranges', () => {
    expect(rangeSatisfies('>=1.0.0 <2.0.0', '1.5.0')).toBe(true);
    expect(rangeSatisfies('>=1.0.0 <2.0.0', '2.1.0')).toBe(false);
    expect(rangeSatisfies('1.x || 3.x', '3.2.1')).toBe(true);
    expect(rangeSatisfies('1.x || 3.x', '2.0.0')).toBe(false);
    expect(rangeSatisfies('1.2.3 - 2.0.0', '1.5.0')).toBe(true);
    expect(rangeSatisfies('1.2.3 - 2.0.0', '2.0.1')).toBe(false);
  });

  it('keeps caret/tilde/exact semantics and stays undecided on odd forms', () => {
    expect(rangeSatisfies('~1.11.0', '1.10.0')).toBe(false);
    expect(rangeSatisfies('^0.1.2', '0.2.0')).toBe(false);
    expect(rangeSatisfies('^0.1.2', '0.1.9')).toBe(true);
    expect(rangeSatisfies('1.2.3', '1.2.3')).toBe(true);
    expect(rangeSatisfies('latest', '1.2.3')).toBeUndefined();
    expect(rangeSatisfies('^1.0.0', '1.0.0-beta.1')).toBeUndefined();
  });
});

describe('deep recursive expansion', () => {
  it('finds workspaces nine segments deep under **', async () => {
    const root = await makeTempDir('dr-globs-deep');
    const deep = 'a/b/c/d/e/f/g/h/i';
    await fs.mkdir(path.join(root, 'packages', deep), { recursive: true });
    const dirs = await expandWorkspacePatterns(root, ['packages/**']);
    expect(dirs.some((d) => d.endsWith(path.join('packages', ...deep.split('/'))))).toBe(true);
  });
});
