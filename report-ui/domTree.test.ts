import { describe, expect, it } from 'vitest';
import { buildDomTree, computeReachCounts } from './domTree';

// Small helper: edges as arrays keyed by index.
function tree(count: number, edges: Record<number, number[]>, roots: number[]) {
  const out: number[][] = Array.from({ length: count }, (_, i) => edges[i] || []);
  return buildDomTree(count, out, roots);
}

describe('buildDomTree', () => {
  it('computes a plain chain: everything exclusive to its parent', () => {
    // 0 -> 1 -> 2
    const t = tree(3, { 0: [1], 1: [2] }, [0]);
    expect(Array.from(t.idom)).toEqual([-1, 0, 1]);
    expect(Array.from(t.exclusiveCount)).toEqual([3, 2, 1]);
    expect(t.rootChildren).toEqual([0]);
  });

  it('assigns shared packages to the virtual root, not either sharer', () => {
    // roots 0 and 1 both depend on 2 (the classic diamond bottom).
    const t = tree(3, { 0: [2], 1: [2] }, [0, 1]);
    expect(t.idom[2]).toBe(-1);
    expect(t.rootChildren.sort()).toEqual([0, 1, 2]);
    // Neither sharer gets credit for the shared package.
    expect(t.exclusiveCount[0]).toBe(1);
    expect(t.exclusiveCount[1]).toBe(1);
    expect(t.exclusiveCount[2]).toBe(1);
  });

  it('keeps a package exclusive when all its routes pass through one owner', () => {
    // 0 -> 1 -> 3, 0 -> 2 -> 3: both routes to 3 pass through 0.
    const t = tree(4, { 0: [1, 2], 1: [3], 2: [3] }, [0]);
    expect(t.idom[3]).toBe(0);
    expect(t.exclusiveCount[0]).toBe(4);
    expect(t.exclusiveCount[1]).toBe(1);
    expect(t.exclusiveCount[2]).toBe(1);
  });

  it('single-entry cycles: the entry dominates the other members', () => {
    // 0 -> 1 <-> 2 (cycle entered only via 1), 2 -> 3
    const t = tree(4, { 0: [1], 1: [2], 2: [1, 3] }, [0]);
    expect(Array.from(t.idom)).toEqual([-1, 0, 1, 2]);
    expect(Array.from(t.exclusiveCount)).toEqual([4, 3, 2, 1]);
    expect(t.cycleWith[1]).toEqual([2]);
    expect(t.cycleWith[2]).toEqual([1]);
  });

  it('mutually-dependent direct deps do not own each other', () => {
    // Direct deps 0 <-> 1: removing either leaves the other installed.
    const t = tree(2, { 0: [1], 1: [0] }, [0, 1]);
    expect(Array.from(t.idom)).toEqual([-1, -1]);
    expect(Array.from(t.exclusiveCount)).toEqual([1, 1]);
    expect(t.rootChildren.sort()).toEqual([0, 1]);
  });

  it('multi-entry cycle members are dominated by the root, their private deps by the true owner', () => {
    // root -> 0, root -> 1; cycle 0 <-> 1; 1 -> 2 (only via 1).
    const t = tree(3, { 0: [1], 1: [0, 2] }, [0, 1]);
    expect(t.idom[0]).toBe(-1);
    expect(t.idom[1]).toBe(-1);
    expect(t.idom[2]).toBe(1);
    expect(Array.from(t.exclusiveCount)).toEqual([1, 2, 1]);
  });

  it('shared band can hold several independent dominator subtrees', () => {
    // roots 0,1 both -> 2 and both -> 3; 2 -> 4 (only via 2).
    const t = tree(5, { 0: [2, 3], 1: [2, 3], 2: [4] }, [0, 1]);
    expect(t.idom[2]).toBe(-1);
    expect(t.idom[3]).toBe(-1);
    expect(t.idom[4]).toBe(2);
    expect(t.rootChildren.sort()).toEqual([0, 1, 2, 3]);
    expect(t.exclusiveCount[2]).toBe(2);
  });

  it('survives an 8000-node chain without recursion', () => {
    const edges: Record<number, number[]> = {};
    for (let i = 0; i < 7999; i += 1) edges[i] = [i + 1];
    const t = tree(8000, edges, [0]);
    expect(t.exclusiveCount[0]).toBe(8000);
    expect(t.exclusiveCount[7999]).toBe(1);
  });

  it('marks unreachable packages and skips them in counts', () => {
    const t = tree(3, { 0: [1] }, [0]);
    expect(t.idom[2]).toBe(-2);
    expect(t.exclusiveCount[2]).toBe(0);
  });

  it('computes unique reach counts, shared packages counted once', () => {
    // 0 -> {1, 2}; 1 -> 3; 2 -> 3 (diamond)
    const out = [[1, 2], [3], [3], []];
    const counts = computeReachCounts(4, out);
    expect(Array.from(counts)).toEqual([4, 2, 2, 1]);
  });

  it('reach counts include whole cycles for every member', () => {
    // 0 -> 1 <-> 2
    const out = [[1], [2], [1]];
    const counts = computeReachCounts(3, out);
    expect(Array.from(counts)).toEqual([3, 2, 2]);
  });
});
