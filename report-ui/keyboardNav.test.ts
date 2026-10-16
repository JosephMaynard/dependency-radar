import { describe, expect, it } from 'vitest';
import type { GraphDataset } from './graphView';
import { buildVizModel, type VizModel } from './vizModel';
import {
  describeNode,
  keyToAction,
  pathTo,
  siblingsOf,
  stepPath,
  type NavTree,
} from './keyboardNav';

/**
 * project -> a, b
 * a -> c, d
 * b -> d      (d is shared: a DAG, not a tree)
 * d -> e
 */
function dataset(): GraphDataset {
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
  add('a', ['c', 'd']);
  add('b', ['d']);
  add('c', []);
  add('d', ['e']);
  add('e', []);
  return {
    workspaces: [
      { name: 'root', directDependencies: ['a@1.0.0', 'b@1.0.0'], directDevDependencies: [] },
    ],
    dependencies,
  };
}

const idx = (m: VizModel, name: string): number => m.indexOfSlug.get(`${name}@1.0.0`) as number;
const names = (m: VizModel, path: number[]): string[] => path.map((i) => m.refs[i].name);

/** Spanning-tree navigation, as the hyperbolic view uses it. */
function spanningTree(m: VizModel): NavTree {
  return {
    roots: m.roots,
    children: (i) => m.children[i],
    parent: (i) => (m.parent[i] >= 0 ? m.parent[i] : -1),
    pkg: (i) => i,
    nodeOf: (i) => i,
  };
}

/** Dependency-graph navigation sorted by name, as the classic view uses it. */
function graphTree(m: VizModel): NavTree {
  const byName = (a: number, b: number): number => m.refs[a].name.localeCompare(m.refs[b].name);
  return {
    roots: [...m.roots].sort(byName),
    children: (i) => [...m.depsOut[i]].sort(byName),
    parent: (i) => (m.parent[i] >= 0 ? m.parent[i] : -1),
    pkg: (i) => i,
    nodeOf: (i) => i,
  };
}

describe('keyboard navigation over the VizModel', () => {
  const m = buildVizModel(dataset(), 'root', 'demo');

  it('moves down to the first child and back up to the project root', () => {
    const tree = spanningTree(m);
    let step = stepPath(tree, [], 'child');
    expect(step.moved).toBe(true);
    expect(step.path).toEqual([tree.roots[0]]);
    step = stepPath(tree, step.path, 'child');
    expect(step.path).toHaveLength(2);
    expect(tree.parent(step.path[1])).toBe(step.path[0]);
    step = stepPath(tree, step.path, 'parent');
    step = stepPath(tree, step.path, 'parent');
    expect(step.path).toEqual([]);
    const atRoot = stepPath(tree, step.path, 'parent');
    expect(atRoot.moved).toBe(false);
  });

  it('stays put on a leaf instead of jumping elsewhere', () => {
    const tree = spanningTree(m);
    const leaf = pathTo(tree, idx(m, 'c'));
    const step = stepPath(tree, leaf, 'child');
    expect(step.moved).toBe(false);
    expect(step.path).toEqual(leaf);
  });

  it('walks siblings without wrapping', () => {
    const tree = graphTree(m);
    const first = stepPath(tree, [], 'child').path;
    expect(names(m, first)).toEqual(['a']);
    const second = stepPath(tree, first, 'next');
    expect(second.moved).toBe(true);
    expect(names(m, second.path)).toEqual(['b']);
    expect(stepPath(tree, second.path, 'next').moved).toBe(false);
    expect(names(m, stepPath(tree, second.path, 'prev').path)).toEqual(['a']);
    expect(stepPath(tree, first, 'prev').moved).toBe(false);
    // The project root has no siblings.
    expect(stepPath(tree, [], 'next').moved).toBe(false);
  });

  it('remembers the route taken through a shared dependency', () => {
    const tree = graphTree(m);
    // b -> d, although d's spanning-tree parent is a.
    let path = stepPath(tree, [], 'child').path; // a
    path = stepPath(tree, path, 'next').path; // b
    path = stepPath(tree, path, 'child').path; // d
    expect(names(m, path)).toEqual(['b', 'd']);
    expect(names(m, siblingsOf(tree, path) as number[])).toEqual(['d']);
    path = stepPath(tree, path, 'parent').path;
    expect(names(m, path)).toEqual(['b']);
  });

  it('rebuilds a path from the parent chain for clicks and searches', () => {
    const tree = spanningTree(m);
    expect(names(m, pathTo(tree, idx(m, 'e')))).toEqual(['a', 'd', 'e']);
    expect(pathTo(tree, -1)).toEqual([]);
    // Home returns to the project root from anywhere.
    const home = stepPath(tree, pathTo(tree, idx(m, 'e')), 'root');
    expect(home).toEqual({ path: [], moved: true });
  });

  it('navigates the dominator tree the flame and treemap views draw', () => {
    const dom = m.domTree();
    const tree: NavTree = {
      roots: dom.rootChildren,
      children: (i) => dom.children[i],
      parent: (i) => (dom.idom[i] >= 0 ? dom.idom[i] : -1),
      pkg: (i) => i,
      nodeOf: (i) => i,
    };
    // d is kept by both a and b, so it sits at the top level next to them.
    expect(names(m, [...tree.roots]).sort()).toEqual(['a', 'b', 'd']);
    expect(names(m, pathTo(tree, idx(m, 'e')))).toEqual(['d', 'e']);
    const aPath = pathTo(tree, idx(m, 'a'));
    expect(names(m, stepPath(tree, aPath, 'child').path)).toEqual(['a', 'c']);
  });

  it('survives a cyclic parent chain', () => {
    const tree: NavTree = {
      roots: [0],
      children: () => [],
      parent: (i) => (i === 0 ? 1 : 0),
      pkg: (i) => i,
      nodeOf: (i) => i,
    };
    expect(pathTo(tree, 0)).toEqual([1, 0]);
  });

  it('never mutates the input path', () => {
    const tree = spanningTree(m);
    const path = pathTo(tree, idx(m, 'd'));
    const copy = [...path];
    stepPath(tree, path, 'parent');
    stepPath(tree, path, 'child');
    stepPath(tree, path, 'next');
    expect(path).toEqual(copy);
  });
});

describe('keyToAction', () => {
  it('maps the documented keys', () => {
    expect(keyToAction({ key: 'ArrowDown' })).toBe('child');
    expect(keyToAction({ key: 'ArrowRight' })).toBe('child');
    expect(keyToAction({ key: 'ArrowUp' })).toBe('parent');
    expect(keyToAction({ key: 'ArrowLeft' })).toBe('parent');
    expect(keyToAction({ key: 'ArrowRight', shiftKey: true })).toBe('next');
    expect(keyToAction({ key: 'ArrowLeft', shiftKey: true })).toBe('prev');
    expect(keyToAction({ key: ']' })).toBe('next');
    expect(keyToAction({ key: '[' })).toBe('prev');
    expect(keyToAction({ key: 'Home' })).toBe('root');
    expect(keyToAction({ key: 'Enter' })).toBe('select');
    expect(keyToAction({ key: ' ' })).toBe('select');
    expect(keyToAction({ key: 'Escape' })).toBe('clear');
    expect(keyToAction({ key: '/' })).toBe('search');
    expect(keyToAction({ key: '?', shiftKey: true })).toBe('help');
    expect(keyToAction({ key: 'f' })).toBe('fit');
    expect(keyToAction({ key: '+', shiftKey: true })).toBe('zoomIn');
    expect(keyToAction({ key: '-' })).toBe('zoomOut');
  });

  it('leaves browser shortcuts and unknown keys alone', () => {
    expect(keyToAction({ key: 'f', metaKey: true })).toBeNull();
    expect(keyToAction({ key: 'ArrowLeft', altKey: true })).toBeNull();
    expect(keyToAction({ key: 'ArrowDown', ctrlKey: true })).toBeNull();
    expect(keyToAction({ key: 'ArrowDown', shiftKey: true })).toBeNull();
    expect(keyToAction({ key: 'Tab' })).toBeNull();
    expect(keyToAction({ key: 'a' })).toBeNull();
  });
});

describe('describeNode', () => {
  it('reads name, dependencies, depth and position', () => {
    expect(describeNode('lodash', '4.17.21', 3, 2, 1, 4)).toBe(
      'lodash@4.17.21, 3 dependencies, depth 2, 1 of 4',
    );
    expect(describeNode('a', '1.0.0', 1, 1, 2, 2)).toBe('a@1.0.0, 1 dependency, depth 1, 2 of 2');
    expect(describeNode('leaf', '', 0, 3, 1, 1)).toBe('leaf, no dependencies, depth 3, 1 of 1');
  });

  it('never uses em or en dashes', () => {
    expect(describeNode('x', '1', 2, 1, 1, 1)).not.toMatch(/[\u2013\u2014]/);
  });
});
