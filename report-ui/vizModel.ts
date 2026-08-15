import type { GraphDataset, GraphDependency } from "./graphView";
import type { DomTree } from "./domTree";
import { buildDomTree, computeReachCounts } from "./domTree";

/** Display filters shared by all graph layouts. */
export interface GraphFilters {
  runtime: boolean;
  dev: boolean;
  sub: boolean;
  /** Max depth below the direct ring; null = unlimited. Ignored when sub=false. */
  maxDepth: number | null;
}

export const DEFAULT_GRAPH_FILTERS: GraphFilters = {
  runtime: true,
  dev: true,
  sub: true,
  maxDepth: null,
};

// Shared derivation layer for the alternative graph views (flame, balloon,
// hyperbolic). Everything is index-based over the packages reachable from the
// selected workspace's direct dependencies, with cycle guards throughout —
// real npm graphs contain cycles.

export interface VizModel {
  projectName: string;
  workspaceName: string;
  /** Package index -> dataset slug / record. */
  slugs: string[];
  refs: GraphDependency[];
  /** Lowercased names, for search and name-filter dimming. */
  lowerNames: string[];
  indexOfSlug: Map<string, number>;
  count: number;
  depsOut: number[][];
  depsIn: number[][];
  isRoot: boolean[];
  isDev: boolean[];
  roots: number[];
  /** Roots sorted heaviest-first. */
  rootsSorted: number[];
  /** Path-expanded subtree size (profiler semantics, memoised, cycle-cut). */
  subSize: Float64Array;
  totalSize: number;
  /** Children sorted heaviest-first. */
  kidsOf: number[][];
  /**
   * Dominator tree over this workspace's graph (lazy, memoised): idom,
   * exclusive counts ("what deleting frees"), shared band = rootChildren
   * that are not direct roots.
   */
  domTree: () => DomTree;
  /** BFS spanning tree (hyperbolic + balloon focus paths). */
  parent: Int32Array;
  children: number[][];
  leaves: Float32Array;
  depth: Int32Array;
  order: number[];
  /** Lineage hue per root subtree. */
  rootHue: Map<number, number>;
  hueOf: (index: number) => number;
  /**
   * Unique packages in the subtree rooted at the index (including itself) —
   * the deduped counterpart to `subSize`'s path counting. Memoised.
   */
  uniqueCount: (index: number) => number;
  /**
   * Removal-impact facts computed over the UNFILTERED workspace graph.
   * Display filters change what renders, never what a package costs.
   */
  impact: (index: number) => PackageImpact;
  /** True when display filters are at their defaults, i.e. the filtered
   *  graph IS the full graph and on-canvas counts equal true impact. */
  filtersAreDefault: boolean;
  /**
   * Full removal preview over the UNFILTERED workspace graph: exactly which
   * packages leave, which of its subtree survives and who keeps each one,
   * and (for a direct dep others still pull in) who blocks the removal.
   */
  simulateRemoval: (index: number) => RemovalSim;
}

export interface RemovalSimEntry {
  slug: string;
  name: string;
}

export interface RemovalSim {
  /** Packages that leave node_modules (includes the package itself). */
  freed: RemovalSimEntry[];
  /** Subtree members that survive, each with one example keeper. */
  retained: Array<RemovalSimEntry & { keptBy: string }>;
  /** Direct dep only: dependents that make the manifest removal a no-op. */
  blockedBy: string[];
  /** True when the package is a direct dependency (manifest semantics). */
  isDirect: boolean;
}

export interface PackageImpact {
  /** Unique packages in its subtree, including itself (full graph). */
  subtreeCount: number;
  /** Packages that leave node_modules if the package itself ceased to exist
   *  (its dominator footprint in the full graph). */
  exclusiveCount: number;
  /**
   * Direct dependencies only: what deleting the package.json entry actually
   * frees. 0 when other packages still pull it in (the entry is redundant);
   * equal to exclusiveCount otherwise. null for sub-dependencies, which have
   * no manifest entry to delete.
   */
  manifestFrees: number | null;
  /** Names of the packages that keep it installed after a manifest removal. */
  keptBy: string[];
  /** Names of the other members of its dependency cycle, if any. */
  cycleWith: string[];
}

const HUES = [28, 152, 268, 322, 82, 8, 232, 55, 190, 300];

/**
 * Build the derivation model for one workspace selection.
 *
 * Includes only packages reachable from the workspace's direct dependencies
 * (matching the classic graph view's scoping). Unreachable packages are
 * simply absent rather than promoted to roots.
 */
export function buildVizModel(
  dataset: GraphDataset,
  workspaceName: string,
  projectName: string,
  filters: GraphFilters = DEFAULT_GRAPH_FILTERS,
): VizModel {
  const workspace =
    dataset.workspaces.find((w) => w.name === workspaceName) ||
    dataset.workspaces[0];
  const unfilteredCount = workspace
    ? workspace.directDependencies.length + workspace.directDevDependencies.length
    : 0;
  const rootSlugsFor = (includeRuntime: boolean, includeDev: boolean): string[] => {
    const list = (
      workspace
        ? [
            ...(includeRuntime ? workspace.directDependencies : []),
            ...(includeDev ? workspace.directDevDependencies : []),
          ]
        : []
    ).filter((slug) => Boolean(dataset.dependencies[slug]));
    if (list.length === 0 && unfilteredCount === 0) {
      // Parity with the classic graph view: a workspace with no direct deps
      // (e.g. a hoisting-only monorepo root) falls back to parentless packages.
      const hasParent = new Set<string>();
      for (const dep of Object.values(dataset.dependencies)) {
        for (const child of dep.dependencies || []) {
          if (child !== dep.slug) hasParent.add(child);
        }
      }
      return Object.keys(dataset.dependencies)
        .filter((slug) => !hasParent.has(slug))
        .slice(0, 40);
    }
    return list;
  };
  const rootSlugs = rootSlugsFor(filters.runtime, filters.dev);
  const rootSet = new Set(rootSlugs);

  // Reachability sweep gives the index space; BFS depth enforces the
  // depth filter (sub=false means the direct ring only).
  const maxDepth = filters.sub
    ? filters.maxDepth === null
      ? Number.POSITIVE_INFINITY
      : filters.maxDepth
    : 0;
  const slugs: string[] = [];
  const indexOfSlug = new Map<string, number>();
  const queue: string[] = [];
  const sweepDepth: number[] = [];
  const pushSlug = (slug: string, depthValue: number): void => {
    if (indexOfSlug.has(slug) || !dataset.dependencies[slug]) return;
    indexOfSlug.set(slug, slugs.length);
    slugs.push(slug);
    queue.push(slug);
    sweepDepth.push(depthValue);
  };
  rootSlugs.forEach((slug) => pushSlug(slug, 0));
  for (let head = 0; head < queue.length; head += 1) {
    if (sweepDepth[head] >= maxDepth) continue;
    const dep = dataset.dependencies[queue[head]];
    for (const child of dep.dependencies || []) pushSlug(child, sweepDepth[head] + 1);
  }

  const count = slugs.length;
  const refs = slugs.map((slug) => dataset.dependencies[slug]);
  const depsOut: number[][] = Array.from({ length: count }, () => []);
  const depsIn: number[][] = Array.from({ length: count }, () => []);
  for (let i = 0; i < count; i += 1) {
    for (const childSlug of refs[i].dependencies || []) {
      const j = indexOfSlug.get(childSlug);
      if (j === undefined || j === i) continue;
      depsOut[i].push(j);
      depsIn[j].push(i);
    }
  }

  const isRoot = slugs.map((slug) => rootSet.has(slug));
  const isDev = refs.map((ref) => Boolean(ref.isDevOnly));
  const roots: number[] = [];
  for (let i = 0; i < count; i += 1) if (isRoot[i]) roots.push(i);

  // (a) path-expanded subtree size. Memoisation makes cycle-adjacent counts
  // approximate — fine for widths. Iterative DFS with an explicit stack:
  // dependency chains can be thousands of packages deep, which overflows the
  // call stack when done recursively.
  const subSize = new Float64Array(count).fill(0);
  interface SizeFrame {
    id: number;
    next: number;
    acc: number;
  }
  const sizeOf = (start: number): void => {
    if (subSize[start] > 0) return;
    const onPath = new Set<number>([start]);
    const stack: SizeFrame[] = [{ id: start, next: 0, acc: 1 }];
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const deps = depsOut[frame.id];
      if (frame.next < deps.length) {
        const dep = deps[frame.next];
        frame.next += 1;
        if (subSize[dep] > 0) {
          frame.acc += subSize[dep];
        } else if (!onPath.has(dep)) {
          onPath.add(dep);
          stack.push({ id: dep, next: 0, acc: 1 });
        }
        continue;
      }
      onPath.delete(frame.id);
      subSize[frame.id] = frame.acc;
      stack.pop();
      const parentFrame = stack[stack.length - 1];
      if (parentFrame) parentFrame.acc += frame.acc;
    }
  };
  for (const r of roots) sizeOf(r);
  for (let i = 0; i < count; i += 1) if (subSize[i] === 0) sizeOf(i);
  const totalSize = roots.reduce((s, r) => s + subSize[r], 0);

  // (b) children heaviest-first.
  const kidsOf = depsOut.map((list) =>
    [...list].sort((a, b) => subSize[b] - subSize[a] || a - b),
  );
  const rootsSorted = [...roots].sort(
    (a, b) => subSize[b] - subSize[a] || a - b,
  );

  // Dominator tree, built on first use (flame/treemap/dossier need it;
  // classic graph does not).
  let domTreeMemo: DomTree | undefined;
  const domTree = (): DomTree => {
    if (!domTreeMemo) domTreeMemo = buildDomTree(count, depsOut, roots);
    return domTreeMemo;
  };

  // (c) BFS spanning tree from roots; first claimer wins.
  const parent = new Int32Array(count).fill(-2);
  for (const r of roots) parent[r] = -1;
  const order = [...roots];
  for (let head = 0; head < order.length; head += 1) {
    for (const dep of kidsOf[order[head]]) {
      if (parent[dep] !== -2) continue;
      parent[dep] = order[head];
      order.push(dep);
    }
  }
  for (let i = 0; i < count; i += 1) {
    if (parent[i] === -2) {
      parent[i] = -1;
      order.push(i);
    }
  }
  const children: number[][] = Array.from({ length: count }, () => []);
  for (const id of order) if (parent[id] >= 0) children[parent[id]].push(id);
  const leaves = new Float32Array(count).fill(1);
  for (let i = order.length - 1; i >= 0; i -= 1) {
    const id = order[i];
    if (children[id].length) {
      leaves[id] = children[id].reduce((s, c) => s + leaves[c], 0);
    }
  }
  const depth = new Int32Array(count);
  for (const id of order) if (parent[id] >= 0) depth[id] = depth[parent[id]] + 1;
  const byLeaves = (a: number, b: number): number =>
    leaves[b] - leaves[a] || a - b;
  for (const list of children) list.sort(byLeaves);

  const rootHue = new Map(
    rootsSorted.map((r, i) => [r, HUES[i % HUES.length]]),
  );
  const hueOf = (index: number): number => {
    // Walk the spanning tree up to the owning root for lineage colour.
    let cur = index;
    let guard = 0;
    while (parent[cur] >= 0 && guard < 128) {
      cur = parent[cur];
      guard += 1;
    }
    return rootHue.get(cur) ?? 210;
  };

  // Unique reach per package (itself + everything beneath), computed once
  // for the whole workspace with the bitset DP — cheap enough that views can
  // size every node by it.
  let reachMemo: Int32Array | undefined;
  const uniqueCount = (index: number): number => {
    if (index < 0 || index >= count) return 0;
    if (!reachMemo) reachMemo = computeReachCounts(count, depsOut);
    return reachMemo[index];
  };

  // ----- removal impact over the UNFILTERED workspace graph ---------------
  // Display filters (runtime/dev/sub/depth) narrow what renders; they must
  // never change what removing a package would actually free. When filters
  // are at their defaults the filtered graph IS the full graph, so the
  // already-built structures are reused as-is.
  const filtersAreDefault =
    filters.runtime && filters.dev && filters.sub && filters.maxDepth === null;

  interface ImpactGraph {
    /** Filtered-model index -> full-graph index (-1 when absent). */
    toFull: Int32Array;
    refsF: GraphDependency[];
    slugsF: string[];
    depsOutF: number[][];
    depsInF: number[][];
    isRootF: boolean[];
    dom: DomTree;
    reach: Int32Array;
  }
  let impactGraphMemo: ImpactGraph | undefined;
  const impactGraph = (): ImpactGraph => {
    if (impactGraphMemo) return impactGraphMemo;
    if (filtersAreDefault) {
      if (!reachMemo) reachMemo = computeReachCounts(count, depsOut);
      const toFull = new Int32Array(count);
      for (let i = 0; i < count; i += 1) toFull[i] = i;
      impactGraphMemo = {
        toFull,
        refsF: refs,
        slugsF: slugs,
        depsOutF: depsOut,
        depsInF: depsIn,
        isRootF: isRoot,
        dom: domTree(),
        reach: reachMemo,
      };
      return impactGraphMemo;
    }
    const fullRootSlugs = rootSlugsFor(true, true);
    const fullRootSet = new Set(fullRootSlugs);
    const slugsF: string[] = [];
    const indexF = new Map<string, number>();
    const queueF: string[] = [];
    const pushF = (slug: string): void => {
      if (indexF.has(slug) || !dataset.dependencies[slug]) return;
      indexF.set(slug, slugsF.length);
      slugsF.push(slug);
      queueF.push(slug);
    };
    fullRootSlugs.forEach(pushF);
    for (let head = 0; head < queueF.length; head += 1) {
      const dep = dataset.dependencies[queueF[head]];
      for (const child of dep.dependencies || []) pushF(child);
    }
    const countF = slugsF.length;
    const refsF = slugsF.map((slug) => dataset.dependencies[slug]);
    const depsOutF: number[][] = Array.from({ length: countF }, () => []);
    const depsInF: number[][] = Array.from({ length: countF }, () => []);
    for (let i = 0; i < countF; i += 1) {
      for (const childSlug of refsF[i].dependencies || []) {
        const j = indexF.get(childSlug);
        if (j === undefined || j === i) continue;
        depsOutF[i].push(j);
        depsInF[j].push(i);
      }
    }
    const isRootF = slugsF.map((slug) => fullRootSet.has(slug));
    const rootsF: number[] = [];
    isRootF.forEach((flag, i) => {
      if (flag) rootsF.push(i);
    });
    const toFull = new Int32Array(count).fill(-1);
    for (let i = 0; i < count; i += 1) {
      const j = indexF.get(slugs[i]);
      if (j !== undefined) toFull[i] = j;
    }
    impactGraphMemo = {
      toFull,
      refsF,
      slugsF,
      depsOutF,
      depsInF,
      isRootF,
      dom: buildDomTree(countF, depsOutF, rootsF),
      reach: computeReachCounts(countF, depsOutF),
    };
    return impactGraphMemo;
  };

  const EMPTY_SIM: RemovalSim = { freed: [], retained: [], blockedBy: [], isDirect: false };
  const simMemo = new Map<number, RemovalSim>();
  const simulateRemoval = (index: number): RemovalSim => {
    if (index < 0 || index >= count) return EMPTY_SIM;
    const g = impactGraph();
    const full = g.toFull[index];
    if (full < 0) return EMPTY_SIM;
    const cached = simMemo.get(full);
    if (cached) return cached;
    // Freed = the dominator subtree (everything only it keeps installed).
    const dominated = new Set<number>([full]);
    const stack = [full];
    while (stack.length > 0) {
      const cur = stack.pop() as number;
      for (const kid of g.dom.children[cur]) {
        dominated.add(kid);
        stack.push(kid);
      }
    }
    // Subtree = everything reachable from it; survivors are kept by a
    // dependent outside the freed set (or by the project manifest itself).
    const reachable = new Set<number>([full]);
    const queue = [full];
    while (queue.length > 0) {
      const cur = queue.pop() as number;
      for (const next of g.depsOutF[cur]) {
        if (!reachable.has(next)) {
          reachable.add(next);
          queue.push(next);
        }
      }
    }
    const entry = (i: number): RemovalSimEntry => ({ slug: g.slugsF[i], name: g.refsF[i].name });
    const retained: RemovalSim["retained"] = [];
    for (const node of reachable) {
      if (dominated.has(node)) continue;
      const keeper = g.depsInF[node].find((pred) => !dominated.has(pred));
      retained.push({
        ...entry(node),
        keptBy: keeper !== undefined ? g.refsF[keeper].name : "the project manifest",
      });
    }
    retained.sort((a, b) => a.name.localeCompare(b.name));
    const isDirect = g.isRootF[full];
    const blockedBy = isDirect
      ? (() => {
          const chainHits = (node: number): boolean => {
            let cur = node;
            let guard = 0;
            while (cur >= 0 && guard < 100_000) {
              if (cur === full) return true;
              cur = g.dom.idom[cur];
              guard += 1;
            }
            return false;
          };
          return g.depsInF[full]
            .filter((pred) => !chainHits(pred))
            .map((pred) => g.refsF[pred].name);
        })()
      : [];
    const freed = [...dominated]
      .map(entry)
      .sort((a, b) => a.name.localeCompare(b.name));
    const result: RemovalSim = { freed, retained, blockedBy, isDirect };
    simMemo.set(full, result);
    return result;
  };

  const EMPTY_IMPACT: PackageImpact = {
    subtreeCount: 0,
    exclusiveCount: 0,
    manifestFrees: null,
    keptBy: [],
    cycleWith: [],
  };
  const impact = (index: number): PackageImpact => {
    if (index < 0 || index >= count) return EMPTY_IMPACT;
    const g = impactGraph();
    const full = g.toFull[index];
    if (full < 0) return EMPTY_IMPACT;
    let manifestFrees: number | null = null;
    let keptBy: string[] = [];
    if (g.isRootF[full]) {
      // A predecessor whose idom-chain does NOT pass through this package has
      // a route from the project that survives the manifest removal — it
      // keeps the package (and therefore its whole subtree) installed.
      const dominatedByTarget = (node: number): boolean => {
        let cur = node;
        let guard = 0;
        while (cur >= 0 && guard < 100_000) {
          if (cur === full) return true;
          cur = g.dom.idom[cur];
          guard += 1;
        }
        return false;
      };
      keptBy = g.depsInF[full]
        .filter((p) => !dominatedByTarget(p))
        .map((p) => g.refsF[p].name);
      manifestFrees = keptBy.length > 0 ? 0 : g.dom.exclusiveCount[full];
    }
    return {
      subtreeCount: g.reach[full],
      exclusiveCount: g.dom.exclusiveCount[full],
      manifestFrees,
      keptBy,
      cycleWith: (g.dom.cycleWith[full] || []).map((other) => g.refsF[other].name),
    };
  };

  return {
    projectName,
    workspaceName: workspace ? workspace.name : workspaceName,
    slugs,
    refs,
    lowerNames: refs.map((ref) => ref.name.toLowerCase()),
    indexOfSlug,
    count,
    depsOut,
    depsIn,
    isRoot,
    isDev,
    roots,
    rootsSorted,
    subSize,
    totalSize,
    kidsOf,
    domTree,
    parent,
    children,
    leaves,
    depth,
    order,
    rootHue,
    hueOf,
    uniqueCount,
    impact,
    filtersAreDefault,
    simulateRemoval,
  };
}

/** Resolved theme tokens for canvas drawing, from the report's CSS variables. */
export interface VizTheme {
  isDark: boolean;
  ink: string;
  muted: string;
  faint: string;
  line: string;
  accent: string;
  vulnHigh: string;
  vulnModerate: string;
  panelText: string;
}

function cssVar(name: string, fallback: string): string {
  const value = getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return value || fallback;
}

let themeCache: { key: string; value: VizTheme } | null = null;

export function resolveVizTheme(): VizTheme {
  const key = document.documentElement.getAttribute("data-theme") || "dark";
  if (themeCache && themeCache.key === key) return themeCache.value;
  const isDark = key !== "light";
  const value: VizTheme = {
    isDark,
    ink: cssVar("--text-primary", isDark ? "#c9d6e2" : "#1e293b"),
    muted: cssVar("--text-secondary", isDark ? "#6c7f92" : "#64748b"),
    faint: isDark ? "rgba(120, 140, 160, 0.45)" : "rgba(100, 116, 139, 0.5)",
    line: cssVar("--border-color", isDark ? "#1a2836" : "#e2e8f0"),
    accent: cssVar("--graph-highlight", "#22d3ee"),
    vulnHigh: cssVar("--graph-vuln-high", "#ef4444"),
    vulnModerate: cssVar("--graph-vuln-medium", "#f59e0b"),
    panelText: cssVar("--text-primary", isDark ? "#e6eef8" : "#0f172a"),
  };
  themeCache = { key, value };
  return value;
}

/** Shared handle every alternative view implements. */
export interface VizHandle {
  destroy(): void;
  resize(): void;
  /** Bring a package into view / focus it (search + dossier chips). */
  focusIndex(index: number): void;
  /** Reset the viewport/layout to its initial fitted state, if supported. */
  resetView?(): void;
}

export interface VizCallbacks {
  /** Hover trail as package indices from root to hovered node; null = none. */
  onHoverTrail(trail: number[] | null): void;
  /** Selection changed; -1 = cleared. */
  onSelect(index: number): void;
  theme(): VizTheme;
  /** Horizontal space covered by the floating side panel; keep fit clear of it. */
  insetRight(): number;
  /** Vertical space covered by the floating toolbar at the top. */
  insetTop(): number;
  /** True when the package should render dimmed (name filter active, no match). */
  isDimmed(index: number): boolean;
  /** A view with an internal zoom state entered/left it (treemap drill). */
  onZoomChanged?(zoomed: boolean): void;
}

/** Node fill hue/lightness helper shared by views: dev deps render dimmer. */
export function lineageFill(
  theme: VizTheme,
  hue: number,
  depthIdx: number,
  dev: boolean,
  highlight: boolean,
): string {
  if (theme.isDark) {
    const l = Math.max(22, 44 - depthIdx * 2.6) + (highlight ? 10 : 0);
    const s = (depthIdx === 0 ? 46 : Math.max(20, 36 - depthIdx * 1.5)) * (dev ? 0.6 : 1);
    return `hsl(${hue} ${s}% ${l}%)`;
  }
  const l = Math.min(88, 62 + depthIdx * 2.2) - (highlight ? 12 : 0);
  const s = (depthIdx === 0 ? 52 : Math.max(26, 44 - depthIdx * 1.5)) * (dev ? 0.55 : 1);
  return `hsl(${hue} ${s}% ${l}%)`;
}
