import type { GraphDataset, GraphDependency } from "./graphView";

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
  /** Distinct root->package paths ("appears in N places"). */
  occ: Float64Array;
  /** BFS spanning tree (hyperbolic + balloon focus paths). */
  parent: Int32Array;
  children: number[][];
  leaves: Float32Array;
  depth: Int32Array;
  order: number[];
  /** Lineage hue per root subtree. */
  rootHue: Map<number, number>;
  hueOf: (index: number) => number;
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
): VizModel {
  const workspace =
    dataset.workspaces.find((w) => w.name === workspaceName) ||
    dataset.workspaces[0];
  let rootSlugs = (
    workspace
      ? [...workspace.directDependencies, ...workspace.directDevDependencies]
      : []
  ).filter((slug) => Boolean(dataset.dependencies[slug]));
  if (rootSlugs.length === 0) {
    // Parity with the classic graph view: a workspace with no direct deps
    // (e.g. a hoisting-only monorepo root) falls back to parentless packages.
    const hasParent = new Set<string>();
    for (const dep of Object.values(dataset.dependencies)) {
      for (const child of dep.dependencies || []) {
        if (child !== dep.slug) hasParent.add(child);
      }
    }
    rootSlugs = Object.keys(dataset.dependencies)
      .filter((slug) => !hasParent.has(slug))
      .slice(0, 40);
  }
  const rootSet = new Set(rootSlugs);

  // Reachability sweep gives the index space.
  const slugs: string[] = [];
  const indexOfSlug = new Map<string, number>();
  const queue: string[] = [];
  const pushSlug = (slug: string): void => {
    if (indexOfSlug.has(slug) || !dataset.dependencies[slug]) return;
    indexOfSlug.set(slug, slugs.length);
    slugs.push(slug);
    queue.push(slug);
  };
  rootSlugs.forEach(pushSlug);
  for (let head = 0; head < queue.length; head += 1) {
    const dep = dataset.dependencies[queue[head]];
    for (const child of dep.dependencies || []) pushSlug(child);
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
  // approximate — fine for widths.
  const subSize = new Float64Array(count).fill(0);
  const sizeOf = (id: number, path: Set<number>): number => {
    if (subSize[id] > 0) return subSize[id];
    if (path.has(id)) return 0;
    path.add(id);
    let n = 1;
    for (const dep of depsOut[id]) n += sizeOf(dep, path);
    path.delete(id);
    subSize[id] = n;
    return n;
  };
  for (const r of roots) sizeOf(r, new Set());
  for (let i = 0; i < count; i += 1) if (subSize[i] === 0) sizeOf(i, new Set());
  const totalSize = roots.reduce((s, r) => s + subSize[r], 0);

  // (b) children heaviest-first.
  const kidsOf = depsOut.map((list) =>
    [...list].sort((a, b) => subSize[b] - subSize[a] || a - b),
  );
  const rootsSorted = [...roots].sort(
    (a, b) => subSize[b] - subSize[a] || a - b,
  );

  // (d) number of distinct root->package paths.
  const occ = new Float64Array(count).fill(0);
  const occOf = (id: number, path: Set<number>): number => {
    if (occ[id] > 0) return occ[id];
    if (path.has(id)) return 0;
    path.add(id);
    // A root appears once at top level PLUS once per path through each
    // dependent — direct deps that are also transitive deps are common.
    let n = isRoot[id] ? 1 : 0;
    for (const from of depsIn[id]) n += occOf(from, path) || 0;
    path.delete(id);
    occ[id] = Math.max(n, 1);
    return occ[id];
  };
  for (let i = 0; i < count; i += 1) occOf(i, new Set());

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

  return {
    projectName,
    workspaceName: workspace ? workspace.name : workspaceName,
    slugs,
    refs,
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
    occ,
    parent,
    children,
    leaves,
    depth,
    order,
    rootHue,
    hueOf,
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
