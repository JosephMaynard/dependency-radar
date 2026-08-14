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
// Dominators are computed with the Cooper–Harvey–Kennedy iterative algorithm
// directly on the (possibly cyclic) graph over a virtual root that points at
// the workspace's direct dependencies — per-node, NOT on the SCC
// condensation: members of a multi-entry cycle do not share one fate, and
// each gets its true immediate dominator. Tarjan SCCs are still computed for
// cycle annotations and for computeReachCounts' topological bitset DP.

export interface DomTree {
  /** Immediate dominator per package index; -1 = virtual root, -2 = unreachable. */
  idom: Int32Array;
  /** Dominator-tree children (package indices) per package index; roots of the forest are idom === -1. */
  children: number[][];
  /** Packages dominated by each index, INCLUDING itself. */
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
 * The Cooper–Harvey–Kennedy iterative algorithm runs directly on the (possibly
 * cyclic) package graph — it needs only a DFS reverse-postorder, not a DAG.
 * Running it per-node (rather than on the SCC condensation) matters: members
 * of a cycle entered from more than one place do NOT share one fate, and each
 * gets its true immediate dominator (possibly the virtual root).
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

  // Cycle membership is informational (dossier annotations) — the dominator
  // computation itself never uses it.
  const { members } = condense(count, out);
  for (const component of members) {
    if (component.length < 2) continue;
    for (const member of component) {
      cycleWith[member] = component.filter((other) => other !== member);
    }
  }

  // Reverse-postorder DFS over the raw graph from a virtual root (index
  // `count`) whose edges are the direct dependencies.
  const ROOT = count;
  const rootEdges = Array.from(new Set(roots));
  const outOf = (node: number): number[] => (node === ROOT ? rootEdges : out[node]);

  const order: number[] = [];
  const state = new Uint8Array(count + 1);
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
  const rpoIndex = new Int32Array(count + 1).fill(-1);
  order.forEach((node, index) => {
    rpoIndex[node] = index;
  });

  // Predecessors within the reachable graph.
  const preds: number[][] = Array.from({ length: count + 1 }, () => []);
  for (const node of order) {
    for (const next of outOf(node)) {
      if (rpoIndex[next] !== -1) preds[next].push(node);
    }
  }

  // Cooper–Harvey–Kennedy iteration to fixpoint (cycles converge naturally).
  const nodeIdom = new Int32Array(count + 1).fill(-1);
  nodeIdom[ROOT] = ROOT;
  const intersect = (a: number, b: number): number => {
    let fingerA = a;
    let fingerB = b;
    while (fingerA !== fingerB) {
      while (rpoIndex[fingerA] > rpoIndex[fingerB]) fingerA = nodeIdom[fingerA];
      while (rpoIndex[fingerB] > rpoIndex[fingerA]) fingerB = nodeIdom[fingerB];
    }
    return fingerA;
  };
  let changed = true;
  while (changed) {
    changed = false;
    for (const node of order) {
      if (node === ROOT) continue;
      let newIdom = -1;
      for (const pred of preds[node]) {
        if (nodeIdom[pred] === -1) continue;
        newIdom = newIdom === -1 ? pred : intersect(pred, newIdom);
      }
      if (newIdom !== -1 && nodeIdom[node] !== newIdom) {
        nodeIdom[node] = newIdom;
        changed = true;
      }
    }
  }

  for (let node = 0; node < count; node += 1) {
    if (rpoIndex[node] === -1 || nodeIdom[node] === -1) continue; // unreachable
    if (nodeIdom[node] === ROOT) {
      idom[node] = -1;
      result.rootChildren.push(node);
    } else {
      idom[node] = nodeIdom[node];
      children[nodeIdom[node]].push(node);
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
