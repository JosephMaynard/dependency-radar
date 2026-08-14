// Dominator analysis over the dependency graph.
//
// A package X *dominates* package Y when every route from the project's
// direct dependencies down to Y passes through X. The set X dominates is
// exactly what leaves node_modules if X is removed — the honest answer to
// "what does this dependency cost me?".
//
// The dominator relation forms a tree in which every package appears exactly
// once and subtree sizes are additive, which is what makes it safe to build
// flame and treemap layouts on: widths/areas are real unique packages and
// children always sum into their parents.
//
// Cycles are handled by collapsing strongly connected components first
// (Tarjan, iterative) — a cycle's members share one fate, so they act as a
// single node whose weight is the member count. Dominators are then computed
// on the resulting DAG with the Cooper–Harvey–Kennedy iterative algorithm
// over a virtual root that points at the workspace's direct dependencies.

export interface DomTree {
  /** Immediate dominator per package index; -1 = virtual root, -2 = unreachable. */
  idom: Int32Array;
  /** Dominator-tree children (package indices) per package index; roots of the forest are idom === -1. */
  children: number[][];
  /** Packages dominated by each index, INCLUDING itself (SCC members each count once). */
  exclusiveCount: Int32Array;
  /** Packages whose immediate dominator is the virtual root. */
  rootChildren: number[];
  /** Other members of the index's cycle (empty when acyclic). */
  cycleWith: number[][];
}

interface Condensation {
  /** Component id per node. */
  comp: Int32Array;
  /** Node indices per component. */
  members: number[][];
  /** Component DAG edges (deduplicated). */
  compOut: number[][];
}

/** Iterative Tarjan SCC. `out[i]` lists node i's dependency edges. */
function condense(count: number, out: number[][]): Condensation {
  const comp = new Int32Array(count).fill(-1);
  const low = new Int32Array(count);
  const disc = new Int32Array(count).fill(-1);
  const onStack = new Uint8Array(count);
  const stack: number[] = [];
  const members: number[][] = [];
  let time = 0;

  interface Frame {
    node: number;
    edge: number;
  }
  for (let start = 0; start < count; start += 1) {
    if (disc[start] !== -1) continue;
    const frames: Frame[] = [{ node: start, edge: 0 }];
    disc[start] = low[start] = time;
    time += 1;
    stack.push(start);
    onStack[start] = 1;
    while (frames.length > 0) {
      const frame = frames[frames.length - 1];
      const edges = out[frame.node];
      if (frame.edge < edges.length) {
        const next = edges[frame.edge];
        frame.edge += 1;
        if (disc[next] === -1) {
          disc[next] = low[next] = time;
          time += 1;
          stack.push(next);
          onStack[next] = 1;
          frames.push({ node: next, edge: 0 });
        } else if (onStack[next]) {
          low[frame.node] = Math.min(low[frame.node], disc[next]);
        }
        continue;
      }
      frames.pop();
      const parent = frames[frames.length - 1];
      if (parent) {
        low[parent.node] = Math.min(low[parent.node], low[frame.node]);
      }
      if (low[frame.node] === disc[frame.node]) {
        const componentId = members.length;
        const component: number[] = [];
        while (true) {
          const popped = stack.pop() as number;
          onStack[popped] = 0;
          comp[popped] = componentId;
          component.push(popped);
          if (popped === frame.node) break;
        }
        members.push(component);
      }
    }
  }

  const compOut: number[][] = Array.from({ length: members.length }, () => []);
  const seen = new Set<number>();
  for (let componentId = 0; componentId < members.length; componentId += 1) {
    seen.clear();
    for (const node of members[componentId]) {
      for (const next of out[node]) {
        const target = comp[next];
        if (target === componentId || seen.has(target)) continue;
        seen.add(target);
        compOut[componentId].push(target);
      }
    }
  }
  return { comp, members, compOut };
}

/**
 * Build the dominator tree for a workspace graph.
 *
 * @param count   number of packages
 * @param out     dependency edges per package index
 * @param roots   the workspace's direct dependencies (virtual root's edges)
 */
export function buildDomTree(count: number, out: number[][], roots: number[]): DomTree {
  const idom = new Int32Array(count).fill(-2);
  const children: number[][] = Array.from({ length: count }, () => []);
  const exclusiveCount = new Int32Array(count).fill(0);
  const cycleWith: number[][] = Array.from({ length: count }, () => []);
  const result: DomTree = { idom, children, exclusiveCount, rootChildren: [], cycleWith };
  if (count === 0) return result;

  const { comp, members, compOut } = condense(count, out);
  const compCount = members.length;

  // Virtual root = component index compCount; reverse-postorder over the
  // component DAG from it.
  const ROOT = compCount;
  const rootEdges = Array.from(new Set(roots.map((r) => comp[r])));
  const outOf = (component: number): number[] => (component === ROOT ? rootEdges : compOut[component]);

  const order: number[] = [];
  const state = new Int32Array(compCount + 1).fill(0);
  {
    interface Frame {
      node: number;
      edge: number;
    }
    const frames: Frame[] = [{ node: ROOT, edge: 0 }];
    state[ROOT] = 1;
    while (frames.length > 0) {
      const frame = frames[frames.length - 1];
      const edges = outOf(frame.node);
      if (frame.edge < edges.length) {
        const next = edges[frame.edge];
        frame.edge += 1;
        if (state[next] === 0) {
          state[next] = 1;
          frames.push({ node: next, edge: 0 });
        }
        continue;
      }
      frames.pop();
      order.push(frame.node);
    }
  }
  order.reverse(); // reverse postorder, ROOT first
  const rpoIndex = new Int32Array(compCount + 1).fill(-1);
  order.forEach((component, index) => {
    rpoIndex[component] = index;
  });

  // Predecessors within the reachable component DAG.
  const preds: number[][] = Array.from({ length: compCount + 1 }, () => []);
  for (const component of order) {
    for (const next of outOf(component)) {
      preds[next].push(component);
    }
  }

  // Cooper–Harvey–Kennedy iterative dominators.
  const compIdom = new Int32Array(compCount + 1).fill(-1);
  compIdom[ROOT] = ROOT;
  const intersect = (a: number, b: number): number => {
    let fingerA = a;
    let fingerB = b;
    while (fingerA !== fingerB) {
      while (rpoIndex[fingerA] > rpoIndex[fingerB]) fingerA = compIdom[fingerA];
      while (rpoIndex[fingerB] > rpoIndex[fingerA]) fingerB = compIdom[fingerB];
    }
    return fingerA;
  };
  let changed = true;
  while (changed) {
    changed = false;
    for (const component of order) {
      if (component === ROOT) continue;
      let newIdom = -1;
      for (const pred of preds[component]) {
        if (compIdom[pred] === -1) continue;
        newIdom = newIdom === -1 ? pred : intersect(pred, newIdom);
      }
      if (newIdom !== -1 && compIdom[component] !== newIdom) {
        compIdom[component] = newIdom;
        changed = true;
      }
    }
  }

  // Project back to packages. Each SCC's representative carries the
  // component; other members hang off the representative so every package
  // still appears exactly once in the tree.
  const representative = members.map((component) => Math.min(...component));
  for (let componentId = 0; componentId < compCount; componentId += 1) {
    if (compIdom[componentId] === -1) continue; // unreachable
    const rep = representative[componentId];
    const parentComponent = compIdom[componentId];
    if (parentComponent === ROOT) {
      idom[rep] = -1;
      result.rootChildren.push(rep);
    } else {
      const parentRep = representative[parentComponent];
      idom[rep] = parentRep;
      children[parentRep].push(rep);
    }
    for (const member of members[componentId]) {
      if (member === rep) continue;
      idom[member] = rep;
      children[rep].push(member);
      cycleWith[member] = members[componentId].filter((other) => other !== member);
    }
    if (members[componentId].length > 1) {
      cycleWith[rep] = members[componentId].filter((other) => other !== rep);
    }
  }

  // Exclusive counts: dominator-tree subtree sizes, iteratively (chains can
  // be thousands deep).
  {
    interface Frame {
      node: number;
      childIndex: number;
    }
    for (const root of result.rootChildren) {
      const frames: Frame[] = [{ node: root, childIndex: 0 }];
      while (frames.length > 0) {
        const frame = frames[frames.length - 1];
        const kids = children[frame.node];
        if (frame.childIndex < kids.length) {
          const next = kids[frame.childIndex];
          frame.childIndex += 1;
          frames.push({ node: next, childIndex: 0 });
          continue;
        }
        frames.pop();
        let total = 1;
        for (const kid of kids) total += exclusiveCount[kid];
        exclusiveCount[frame.node] = total;
      }
    }
  }

  // Deterministic ordering: heaviest first, then index.
  const byWeight = (a: number, b: number): number =>
    exclusiveCount[b] - exclusiveCount[a] || a - b;
  for (const list of children) list.sort(byWeight);
  result.rootChildren.sort(byWeight);

  return result;
}

/**
 * Unique reachable-package count per node ("how many packages live under
 * it", including itself). Bitset DP over the SCC condensation in the reverse
 * topological order Tarjan already emits — fast enough to run over a whole
 * report (~1.5M word-ops for 5k packages) rather than per-workspace.
 */
export function computeReachCounts(count: number, out: number[][]): Int32Array {
  const counts = new Int32Array(count).fill(0);
  if (count === 0) return counts;
  const { comp, members, compOut } = condense(count, out);
  const words = Math.ceil(count / 32);
  const bits: Int32Array[] = new Array(members.length);
  // Tarjan emits components callee-first: every edge from component i targets
  // a component with a smaller id, so a single forward pass is a valid
  // topological DP.
  for (let componentId = 0; componentId < members.length; componentId += 1) {
    const set = new Int32Array(words);
    for (const node of members[componentId]) {
      set[node >> 5] |= 1 << (node & 31);
    }
    for (const next of compOut[componentId]) {
      const other = bits[next];
      for (let word = 0; word < words; word += 1) set[word] |= other[word];
    }
    bits[componentId] = set;
    let total = 0;
    for (let word = 0; word < words; word += 1) {
      let value = set[word];
      value = value - ((value >> 1) & 0x55555555);
      value = (value & 0x33333333) + ((value >> 2) & 0x33333333);
      total += (((value + (value >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
    }
    for (const node of members[componentId]) counts[node] = total;
  }
  return counts;
}
