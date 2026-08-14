import { describe, expect, it } from 'vitest';
import type { GraphDataset } from './graphView';
import { buildVizModel } from './vizModel';

function chainDataset(length: number): GraphDataset {
  const dependencies: GraphDataset['dependencies'] = {};
  for (let i = 0; i < length; i += 1) {
    const slug = `pkg-${i}@1.0.0`;
    dependencies[slug] = {
      slug,
      name: `pkg-${i}`,
      version: '1.0.0',
      dependencies: i + 1 < length ? [`pkg-${i + 1}@1.0.0`] : [],
      license: 'MIT',
      vulnerabilityCount: 0,
      vulnerabilitySeverity: 'none',
      isDevOnly: false,
      workspaceOrigins: ['root'],
    };
  }
  return {
    workspaces: [
      {
        name: 'root',
        directDependencies: ['pkg-0@1.0.0'],
        directDevDependencies: [],
      },
    ],
    dependencies,
  };
}

describe('buildVizModel', () => {
  // Dependency chains thousands of packages deep must not overflow the call
  // stack (sizeOf/occOf were recursive before v1.1.1).
  it('handles an 8000-package dependency chain', () => {
    const model = buildVizModel(chainDataset(8000), 'root', 'chain-project');
    expect(model.count).toBe(8000);
    const root = model.indexOfSlug.get('pkg-0@1.0.0');
    expect(root).toBeDefined();
    expect(model.subSize[root as number]).toBe(8000);
    expect(model.totalSize).toBe(8000);
    expect(model.uniqueCount(root as number)).toBe(8000);
    const tail = model.indexOfSlug.get('pkg-7999@1.0.0');
    expect(model.domTree().exclusiveCount[root as number]).toBe(8000);
    expect(model.domTree().exclusiveCount[tail as number]).toBe(1);
  });

  it('counts paths and unique packages separately on diamond graphs', () => {
    const dependencies: GraphDataset['dependencies'] = {};
    const add = (name: string, deps: string[]): void => {
      const slug = `${name}@1.0.0`;
      dependencies[slug] = {
        slug,
        name,
        version: '1.0.0',
        dependencies: deps.map((d) => `${d}@1.0.0`),
        license: 'MIT',
        vulnerabilityCount: 0,
        vulnerabilitySeverity: 'none',
        isDevOnly: false,
        workspaceOrigins: ['root'],
      };
    };
    // root -> a, b; a -> shared; b -> shared: 4 unique packages, but the
    // path-expanded size counts `shared` twice.
    add('top', ['a', 'b']);
    add('a', ['shared']);
    add('b', ['shared']);
    add('shared', []);
    const dataset: GraphDataset = {
      workspaces: [
        {
          name: 'root',
          directDependencies: ['top@1.0.0'],
          directDevDependencies: [],
        },
      ],
      dependencies,
    };

    const model = buildVizModel(dataset, 'root', 'diamond');
    const top = model.indexOfSlug.get('top@1.0.0') as number;
    const shared = model.indexOfSlug.get('shared@1.0.0') as number;
    expect(model.uniqueCount(top)).toBe(4);
    expect(model.subSize[top]).toBe(5);
    // Shared sits under top in the dominator tree (all routes pass through
    // top), so top's removal frees everything.
    expect(model.domTree().exclusiveCount[top]).toBe(4);
    expect(model.domTree().idom[shared]).toBe(top);
  });

  it('matches the recursive semantics on cyclic graphs', () => {
    const dependencies: GraphDataset['dependencies'] = {};
    const add = (name: string, deps: string[]): void => {
      const slug = `${name}@1.0.0`;
      dependencies[slug] = {
        slug,
        name,
        version: '1.0.0',
        dependencies: deps.map((d) => `${d}@1.0.0`),
        license: 'MIT',
        vulnerabilityCount: 0,
        vulnerabilitySeverity: 'none',
        isDevOnly: false,
        workspaceOrigins: ['root'],
      };
    };
    // root -> a -> b -> c -> a (cycle), plus b -> leaf.
    add('entry', ['a']);
    add('a', ['b']);
    add('b', ['c', 'leaf']);
    add('c', ['a']);
    add('leaf', []);
    const dataset: GraphDataset = {
      workspaces: [
        { name: 'root', directDependencies: ['entry@1.0.0'], directDevDependencies: [] },
      ],
      dependencies,
    };

    const model = buildVizModel(dataset, 'root', 'cyclic');
    const idx = (n: string): number => model.indexOfSlug.get(`${n}@1.0.0`) as number;
    // Hand-computed with the original recursive algorithm (memo checked
    // before the cycle cut): c contributes 1 (a is on the path), so
    // b = 1 + c(1) + leaf(1) = 3, a = 4, entry = 5.
    expect(model.subSize[idx('c')]).toBe(1);
    expect(model.subSize[idx('b')]).toBe(3);
    expect(model.subSize[idx('a')]).toBe(4);
    expect(model.subSize[idx('entry')]).toBe(5);
    expect(model.totalSize).toBe(5);
    expect(model.uniqueCount(idx('entry'))).toBe(5);
    expect(model.uniqueCount(idx('a'))).toBe(4);
    // Dominators through the cycle: entry owns everything.
    expect(model.domTree().exclusiveCount[idx('entry')]).toBe(5);
  });
});
