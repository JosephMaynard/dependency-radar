import type { AggregatedData, DependencyRecord } from "./types";

type GraphWorkspace = {
  name: string;
  directDependencies: string[];
  directDevDependencies: string[];
};

type GraphDependency = {
  slug: string;
  name: string;
  version: string;
  dependencies: string[];
  license: string;
  vulnerabilityCount: number;
  vulnerabilitySeverity: "high" | "moderate" | "none";
  isDevOnly: boolean;
  workspaceOrigins: string[];
};

type GraphDataset = {
  workspaces: GraphWorkspace[];
  dependencies: Record<string, GraphDependency>;
};

type GraphNodeKind = "direct-runtime" | "direct-dev" | "transitive";

type GraphNode = {
  slug: string;
  ref: GraphDependency;
  parents: Set<string>;
  children: Set<string>;
  depth: number;
  order: number;
  amplification: number;
  kind: GraphNodeKind;
  baseX: number;
  baseY: number;
  targetX: number;
  targetY: number;
  renderX: number;
  renderY: number;
  radius: number;
};

type GraphEdge = {
  from: string;
  to: string;
  direct: boolean;
};

type WorkspaceGraph = {
  workspaceName: string;
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
  layers: string[][];
  directRuntime: Set<string>;
  directDev: Set<string>;
  directAll: Set<string>;
  bounds: {
    minX: number;
    maxX: number;
    minY: number;
    maxY: number;
  };
};

export type GraphViewOptions = {
  report: AggregatedData;
  knownDepKeys: Set<string>;
  resolveDepKey: (depKey: string) => string | null;
  workspaceSelect: HTMLSelectElement;
  workspaceWrap: HTMLElement;
  controlsRoot: HTMLElement;
  canvas: HTMLCanvasElement;
  canvasHost: HTMLElement;
  popover: HTMLElement;
  popoverName: HTMLElement;
  popoverVersion: HTMLElement;
  popoverLicense: HTMLElement;
  popoverVulns: HTMLElement;
  popoverAmplification: HTMLElement;
  popoverOpenButton: HTMLButtonElement;
  onOpenList: (slug: string) => void;
};

export type GraphViewHandle = {
  initGraphView: () => void;
  buildWorkspaceGraph: (name: string) => WorkspaceGraph | null;
  computeAmplification: (graph: WorkspaceGraph) => void;
  layoutGraph: (graph: WorkspaceGraph) => void;
  renderLoop: () => void;
  applyFocus: (slug: string) => void;
  clearFocus: () => void;
  showPopover: (slug: string) => void;
  hidePopover: () => void;
  switchWorkspace: (name: string) => void;
  setActive: (active: boolean) => void;
  requestRender: () => void;
};

declare global {
  interface Window {
    __DEPENDENCY_DATA__?: unknown;
  }
}

const LAYER_GAP = 240;
const ROW_GAP = 43;
const PADDING_X = 96;
const PADDING_Y = 64;
const PUSH_RADIUS = 120;
const MAX_ZOOM = 2.8;
const MIN_ZOOM_FIT_RATIO = 0.86;
const EDGE_CURVE = 0.2;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function getCssColor(name: string): string {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
}

function getDepKey(name: string, version: string): string {
  return `${name}@${version}`;
}

function edgeKey(from: string, to: string): string {
  return `${from}->${to}`;
}

function isGraphDataset(value: unknown): value is GraphDataset {
  if (!value || typeof value !== "object") return false;
  const input = value as Record<string, unknown>;
  if (!Array.isArray(input.workspaces)) return false;
  if (!input.dependencies || typeof input.dependencies !== "object")
    return false;
  return true;
}

function primaryLicense(dep: DependencyRecord): string {
  const declared = dep.compliance.license.declared?.valid
    ? dep.compliance.license.declared.spdxId
    : undefined;
  if (declared) return declared;
  return dep.compliance.license.inferred?.spdxId || "Unknown";
}

function vulnerabilityCount(dep: DependencyRecord): number {
  const summary = dep.security?.summary;
  if (!summary) return 0;
  return (
    Number(summary.critical || 0) +
    Number(summary.high || 0) +
    Number(summary.moderate || 0) +
    Number(summary.low || 0)
  );
}

function vulnerabilitySeverityFromRecord(
  dep: DependencyRecord,
): "high" | "moderate" | "none" {
  const highest = dep.security?.summary?.highest;
  if (highest === "critical" || highest === "high") return "high";
  if (highest === "moderate") return "moderate";
  return "none";
}

function collectAncestors(graph: WorkspaceGraph, slug: string): Set<string> {
  const result = new Set<string>();
  const stack = [slug];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    const node = graph.nodes.get(current);
    if (!node) continue;
    node.parents.forEach((parent) => {
      if (result.has(parent)) return;
      result.add(parent);
      stack.push(parent);
    });
  }
  return result;
}

function collectDescendants(graph: WorkspaceGraph, slug: string): Set<string> {
  const result = new Set<string>();
  const stack = [slug];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    const node = graph.nodes.get(current);
    if (!node) continue;
    node.children.forEach((child) => {
      if (result.has(child)) return;
      result.add(child);
      stack.push(child);
    });
  }
  return result;
}

function adaptDataset(
  report: AggregatedData,
  knownDepKeys: Set<string>,
  resolveDepKey: (depKey: string) => string | null,
): GraphDataset {
  const globalData = window.__DEPENDENCY_DATA__;
  if (isGraphDataset(globalData)) {
    const normalizedDependencies: Record<string, GraphDependency> = {};
    Object.entries(globalData.dependencies).forEach(([slug, rawDep]) => {
      const dep = rawDep as Record<string, unknown>;
      const rawSeverity =
        (dep.vulnerabilitySeverity as string | undefined) ||
        (dep.vulnerabilityHighest as string | undefined) ||
        (dep.highestSeverity as string | undefined) ||
        "none";
      let vulnerabilitySeverity: "high" | "moderate" | "none" = "none";
      if (rawSeverity === "critical" || rawSeverity === "high") {
        vulnerabilitySeverity = "high";
      } else if (rawSeverity === "moderate" || rawSeverity === "medium") {
        vulnerabilitySeverity = "moderate";
      }

      normalizedDependencies[slug] = {
        slug: String(dep.slug || slug),
        name: String(dep.name || slug),
        version: String(dep.version || ""),
        dependencies: Array.isArray(dep.dependencies)
          ? dep.dependencies.map((value) => String(value))
          : [],
        license: String(dep.license || "Unknown"),
        vulnerabilityCount: Number(dep.vulnerabilityCount || 0),
        vulnerabilitySeverity,
        isDevOnly: Boolean(dep.isDevOnly),
        workspaceOrigins: Array.isArray(dep.workspaceOrigins)
          ? dep.workspaceOrigins.map((value) => String(value))
          : [],
      };
    });

    return {
      workspaces: globalData.workspaces,
      dependencies: normalizedDependencies,
    };
  }

  const dependencies: Record<string, GraphDependency> = {};
  const records = Object.values(report.dependencies || {});

  records.forEach((dep) => {
    const slug = getDepKey(dep.package.name, dep.package.version);
    dependencies[slug] = {
      slug,
      name: dep.package.name,
      version: dep.package.version,
      dependencies: [],
      license: primaryLicense(dep),
      vulnerabilityCount: vulnerabilityCount(dep),
      vulnerabilitySeverity: vulnerabilitySeverityFromRecord(dep),
      isDevOnly: dep.usage.scope === "dev",
      workspaceOrigins: dep.usage.origins.workspaces || [],
    };
  });

  records.forEach((dep) => {
    const slug = getDepKey(dep.package.name, dep.package.version);
    const subDeps = dep.graph.subDeps;
    if (!subDeps) return;
    const next = new Set<string>();
    (["dep", "dev", "opt", "peer"] as const).forEach((bucket) => {
      const entries = subDeps[bucket];
      if (!entries) return;
      Object.values(entries).forEach((tuple) => {
        const resolved = (tuple as [string, string | null])[1];
        if (!resolved) return;
        const normalized = resolveDepKey(resolved);
        if (!normalized) return;
        if (!knownDepKeys.has(normalized)) return;
        if (!dependencies[normalized]) return;
        if (normalized === slug) return;
        next.add(normalized);
      });
    });
    dependencies[slug].dependencies = [...next];
  });

  const workspaceMap = new Map<
    string,
    { directDependencies: Set<string>; directDevDependencies: Set<string> }
  >();

  const ensureWorkspace = (
    name: string,
  ): {
    directDependencies: Set<string>;
    directDevDependencies: Set<string>;
  } => {
    const existing = workspaceMap.get(name);
    if (existing) return existing;
    const created = {
      directDependencies: new Set<string>(),
      directDevDependencies: new Set<string>(),
    };
    workspaceMap.set(name, created);
    return created;
  };

  ensureWorkspace("root");
  (report.workspaces.workspacePackages || []).forEach((workspace) => {
    ensureWorkspace(workspace.name);
  });

  records.forEach((dep) => {
    if (!dep.usage.direct) return;
    const slug = getDepKey(dep.package.name, dep.package.version);
    const origins = dep.usage.origins.workspaces?.length
      ? dep.usage.origins.workspaces
      : ["root"];
    origins.forEach((workspaceName) => {
      const workspace = ensureWorkspace(workspaceName);
      if (dep.usage.scope === "dev") {
        workspace.directDevDependencies.add(slug);
      } else {
        workspace.directDependencies.add(slug);
      }
    });
  });

  const workspaces: GraphWorkspace[] = [...workspaceMap.entries()]
    .map(([name, deps]) => ({
      name,
      directDependencies: [...deps.directDependencies],
      directDevDependencies: [...deps.directDevDependencies],
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return { workspaces, dependencies };
}

export function initGraphView(options: GraphViewOptions): GraphViewHandle {
  const dataset = adaptDataset(
    options.report,
    options.knownDepKeys,
    options.resolveDepKey,
  );

  const workspaceByName = new Map(
    dataset.workspaces.map((workspace) => [workspace.name, workspace]),
  );

  const parentsBySlug = new Map<string, string[]>();
  const childrenBySlug = new Map<string, string[]>();

  Object.values(dataset.dependencies).forEach((dep) => {
    const children = (dep.dependencies || []).filter(
      (slug) => slug !== dep.slug && Boolean(dataset.dependencies[slug]),
    );
    childrenBySlug.set(dep.slug, children);
    children.forEach((child) => {
      const current = parentsBySlug.get(child) || [];
      current.push(dep.slug);
      parentsBySlug.set(child, current);
    });
  });

  let currentGraph: WorkspaceGraph | null = null;
  let currentWorkspace = "";

  let focusSlug: string | null = null;
  let hoverSlug: string | null = null;
  let focusNodes = new Set<string>();
  let focusEdges = new Set<string>();
  let focusPushNodes = new Set<string>();
  let hoverNodes = new Set<string>();
  let hoverEdges = new Set<string>();
  let popoverSlug: string | null = null;

  let zoom = 1;
  let panX = 0;
  let panY = 0;
  let fitZoom = 1;
  let minZoom = 0.1;
  let defaultPanX = 0;
  let defaultPanY = 0;

  let active = false;
  let dirty = true;
  let frameId = 0;

  let dpr = Math.max(1, Math.floor(window.devicePixelRatio || 1));
  let width = 1;
  let height = 1;

  const panState = {
    down: false,
    moved: false,
    startX: 0,
    startY: 0,
    startPanX: 0,
    startPanY: 0,
  };

  const touchState = {
    active: false,
    startX1: 0,
    startY1: 0,
    startX2: 0,
    startY2: 0,
    startPanX: 0,
    startPanY: 0,
    startDist: 0,
    startZoom: 0,
  };

  const context = options.canvas.getContext("2d");
  const hasCanvas = Boolean(context);
  let interactionsBound = false;
  let fallbackShown = false;

  function showCanvasFallback(): void {
    if (fallbackShown) return;
    fallbackShown = true;
    console.warn(
      "Dependency Radar: unable to initialize 2D canvas; graph rendering disabled.",
    );
    options.controlsRoot.classList.add("hidden");
    options.workspaceWrap.classList.add("hidden");
    options.canvas.style.display = "none";
    const fallback = document.createElement("div");
    fallback.className = "empty-state";
    const text = document.createElement("div");
    text.className = "empty-state-text";
    text.textContent = "Graph view is unavailable in this browser context.";
    fallback.appendChild(text);
    options.canvasHost.appendChild(fallback);
  }

  function worldX(screenX: number): number {
    return (screenX - panX) / zoom;
  }

  function worldY(screenY: number): number {
    return (screenY - panY) / zoom;
  }

  function applyZoom(nextZoom: number, anchorX: number, anchorY: number): void {
    const clamped = clamp(nextZoom, minZoom, MAX_ZOOM);
    const wx = worldX(anchorX);
    const wy = worldY(anchorY);
    zoom = clamped;
    panX = anchorX - wx * zoom;
    panY = anchorY - wy * zoom;
    dirty = true;
    requestRender();
  }

  function panBy(dx: number, dy: number): void {
    panX += dx;
    panY += dy;
    dirty = true;
    requestRender();
  }

  function updateCanvasSize(): void {
    const rect = options.canvasHost.getBoundingClientRect();
    width = Math.max(1, Math.floor(rect.width));
    height = Math.max(1, Math.floor(rect.height));
    dpr = Math.max(1, Math.floor(window.devicePixelRatio || 1));
    options.canvas.width = width * dpr;
    options.canvas.height = height * dpr;
    options.canvas.style.width = `${width}px`;
    options.canvas.style.height = `${height}px`;
    dirty = true;
    requestRender();
  }

  function updateFitMetrics(): void {
    if (!currentGraph) return;
    const bounds = currentGraph.bounds;
    const graphWidth = Math.max(1, bounds.maxX - bounds.minX);
    const graphHeight = Math.max(1, bounds.maxY - bounds.minY);
    const fitZoomX = width / graphWidth;
    const fitZoomY = height / graphHeight;
    fitZoom = clamp(Math.min(fitZoomX, fitZoomY), 0.05, MAX_ZOOM);
    minZoom = clamp(fitZoom * MIN_ZOOM_FIT_RATIO, 0.05, MAX_ZOOM);
    defaultPanX = (width - graphWidth * fitZoom) * 0.5 - bounds.minX * fitZoom;
    defaultPanY =
      (height - graphHeight * fitZoom) * 0.5 - bounds.minY * fitZoom;
  }

  function fitGraph(): void {
    if (!currentGraph) return;
    updateFitMetrics();
    zoom = fitZoom;
    panX = defaultPanX;
    panY = defaultPanY;
  }

  function findNode(clientX: number, clientY: number): GraphNode | null {
    if (!currentGraph) return null;
    const rect = options.canvas.getBoundingClientRect();
    const x = worldX(clientX - rect.left);
    const y = worldY(clientY - rect.top);

    let hit: GraphNode | null = null;
    currentGraph.nodes.forEach((node) => {
      const dx = x - node.renderX;
      const dy = y - node.renderY;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist <= node.radius + 5) hit = node;
    });
    return hit;
  }

  function buildWorkspaceGraph(name: string): WorkspaceGraph | null {
    const workspace = workspaceByName.get(name);
    if (!workspace) return null;

    const directRuntime = new Set(
      workspace.directDependencies.filter((slug) =>
        Boolean(dataset.dependencies[slug]),
      ),
    );
    const directDev = new Set(
      workspace.directDevDependencies.filter((slug) =>
        Boolean(dataset.dependencies[slug]),
      ),
    );

    const roots = new Set<string>([...directRuntime, ...directDev]);
    if (roots.size === 0) {
      Object.keys(dataset.dependencies)
        .filter((slug) => (parentsBySlug.get(slug) || []).length === 0)
        .slice(0, 40)
        .forEach((slug) => {
          roots.add(slug);
        });
    }

    const included = new Set<string>();
    const queue = [...roots];
    let queueIndex = 0;
    while (queueIndex < queue.length) {
      const slug = queue[queueIndex++];
      if (!slug) continue;
      if (included.has(slug)) continue;
      if (!dataset.dependencies[slug]) continue;
      included.add(slug);
      (childrenBySlug.get(slug) || []).forEach((child) => {
        if (included.has(child)) return;
        queue.push(child);
      });
    }

    if (included.size === 0) return null;

    const nodes = new Map<string, GraphNode>();
    included.forEach((slug) => {
      const kind: GraphNodeKind = directRuntime.has(slug)
        ? "direct-runtime"
        : directDev.has(slug)
          ? "direct-dev"
          : "transitive";
      nodes.set(slug, {
        slug,
        ref: dataset.dependencies[slug],
        parents: new Set<string>(),
        children: new Set<string>(),
        depth: Number.POSITIVE_INFINITY,
        order: 0,
        amplification: 0,
        kind,
        baseX: 0,
        baseY: 0,
        targetX: 0,
        targetY: 0,
        renderX: 0,
        renderY: 0,
        radius: 8,
      });
    });

    nodes.forEach((node) => {
      (parentsBySlug.get(node.slug) || []).forEach((parent) => {
        if (!nodes.has(parent)) return;
        node.parents.add(parent);
      });
      (childrenBySlug.get(node.slug) || []).forEach((child) => {
        if (!nodes.has(child)) return;
        node.children.add(child);
      });
    });

    const depthQueue: string[] = [];
    roots.forEach((root) => {
      const node = nodes.get(root);
      if (!node) return;
      node.depth = 0;
      depthQueue.push(root);
    });

    while (depthQueue.length > 0) {
      const slug = depthQueue.shift();
      if (!slug) continue;
      const node = nodes.get(slug);
      if (!node) continue;
      node.children.forEach((childSlug) => {
        const child = nodes.get(childSlug);
        if (!child) return;
        const nextDepth = node.depth + 1;
        if (nextDepth >= child.depth) return;
        child.depth = nextDepth;
        depthQueue.push(childSlug);
      });
    }

    nodes.forEach((node) => {
      if (Number.isFinite(node.depth)) return;
      let minDepth = Number.POSITIVE_INFINITY;
      node.parents.forEach((parentSlug) => {
        const parent = nodes.get(parentSlug);
        if (!parent || !Number.isFinite(parent.depth)) return;
        minDepth = Math.min(minDepth, parent.depth + 1);
      });
      node.depth = Number.isFinite(minDepth) ? minDepth : 0;
    });

    const maxDepth = [...nodes.values()].reduce(
      (max, node) => Math.max(max, node.depth),
      0,
    );
    const layers = Array.from({ length: maxDepth + 1 }, () => [] as string[]);
    nodes.forEach((node) => {
      layers[node.depth].push(node.slug);
    });

    const edges: GraphEdge[] = [];
    nodes.forEach((node) => {
      node.children.forEach((childSlug) => {
        edges.push({
          from: node.slug,
          to: childSlug,
          direct: node.depth === 0,
        });
      });
    });

    const graph: WorkspaceGraph = {
      workspaceName: name,
      nodes,
      edges,
      layers,
      directRuntime,
      directDev,
      directAll: new Set([...directRuntime, ...directDev]),
      bounds: { minX: 0, maxX: 1, minY: 0, maxY: 1 },
    };

    computeAmplification(graph);
    layoutGraph(graph);
    return graph;
  }

  function computeAmplification(graph: WorkspaceGraph): void {
    graph.nodes.forEach((node) => {
      node.amplification = 0;
    });

    graph.nodes.forEach((rootNode) => {
      if (rootNode.depth !== 0) return;
      if (!graph.directAll.has(rootNode.slug)) return;
      const visited = new Set<string>();
      const stack = [...rootNode.children];
      while (stack.length > 0) {
        const current = stack.pop();
        if (!current) continue;
        if (current === rootNode.slug) continue;
        if (visited.has(current)) continue;
        visited.add(current);
        const currentNode = graph.nodes.get(current);
        if (!currentNode) continue;
        currentNode.children.forEach((child) => {
          if (visited.has(child)) return;
          stack.push(child);
        });
      }
      rootNode.amplification = visited.size;
    });
  }

  function layoutGraph(graph: WorkspaceGraph): void {
    const layerOrder = new Map<string, number>();

    graph.layers.forEach((layer, depth) => {
      if (depth === 0) {
        layer.sort((a, b) => {
          const nodeA = graph.nodes.get(a);
          const nodeB = graph.nodes.get(b);
          if (!nodeA && !nodeB) return 0;
          if (!nodeA) return 1;
          if (!nodeB) return -1;
          if (nodeA.amplification !== nodeB.amplification) {
            return nodeB.amplification - nodeA.amplification;
          }
          if (nodeA.kind !== nodeB.kind) {
            if (nodeA.kind === "direct-runtime") return -1;
            if (nodeB.kind === "direct-runtime") return 1;
          }
          return nodeA.ref.name.localeCompare(nodeB.ref.name);
        });
      } else {
        layer.sort((a, b) => {
          const nodeA = graph.nodes.get(a);
          const nodeB = graph.nodes.get(b);
          if (!nodeA && !nodeB) return 0;
          if (!nodeA) return 1;
          if (!nodeB) return -1;
          const baryA = (() => {
            let count = 0;
            let sum = 0;
            nodeA.parents.forEach((parent) => {
              const index = layerOrder.get(parent);
              if (typeof index !== "number") return;
              count += 1;
              sum += index;
            });
            return count > 0 ? sum / count : Number.MAX_SAFE_INTEGER;
          })();
          const baryB = (() => {
            let count = 0;
            let sum = 0;
            nodeB.parents.forEach((parent) => {
              const index = layerOrder.get(parent);
              if (typeof index !== "number") return;
              count += 1;
              sum += index;
            });
            return count > 0 ? sum / count : Number.MAX_SAFE_INTEGER;
          })();
          if (baryA !== baryB) return baryA - baryB;
          return nodeA.ref.name.localeCompare(nodeB.ref.name);
        });
      }
      layer.forEach((slug, index) => {
        layerOrder.set(slug, index);
      });
    });

    const maxRows = graph.layers.reduce(
      (max, layer) => Math.max(max, layer.length),
      1,
    );

    graph.bounds = {
      minX: Number.POSITIVE_INFINITY,
      maxX: Number.NEGATIVE_INFINITY,
      minY: Number.POSITIVE_INFINITY,
      maxY: Number.NEGATIVE_INFINITY,
    };

    graph.layers.forEach((layer, depth) => {
      const columnHeight = Math.max(0, (layer.length - 1) * ROW_GAP);
      const top = PADDING_Y + (maxRows * ROW_GAP - columnHeight) * 0.5;
      layer.forEach((slug, index) => {
        const node = graph.nodes.get(slug);
        if (!node) return;
        node.order = index;
        node.baseX = PADDING_X + depth * LAYER_GAP;
        node.baseY = top + index * ROW_GAP;
        node.targetX = node.baseX;
        node.targetY = node.baseY;
        node.renderX = node.baseX;
        node.renderY = node.baseY;

        const relationshipFactor =
          Math.log(node.children.size + node.parents.size + 1) * 0.55;
        const amplificationFactor =
          node.depth === 0 && graph.directAll.has(node.slug)
            ? Math.log(node.amplification + 1) * 1.05
            : 0;
        node.radius = 6.7 + relationshipFactor + amplificationFactor;

        graph.bounds.minX = Math.min(graph.bounds.minX, node.baseX);
        graph.bounds.maxX = Math.max(graph.bounds.maxX, node.baseX);
        graph.bounds.minY = Math.min(graph.bounds.minY, node.baseY);
        graph.bounds.maxY = Math.max(graph.bounds.maxY, node.baseY);
      });
    });

    if (!Number.isFinite(graph.bounds.minX)) {
      graph.bounds = { minX: 0, maxX: 1, minY: 0, maxY: 1 };
    }
  }

  function applyFocus(slug: string): void {
    if (!currentGraph || !currentGraph.nodes.has(slug)) return;
    focusSlug = slug;
    const ancestors = collectAncestors(currentGraph, slug);
    const descendants = collectDescendants(currentGraph, slug);

    focusNodes = new Set([slug]);
    ancestors.forEach((nodeSlug) => {
      focusNodes.add(nodeSlug);
    });
    descendants.forEach((nodeSlug) => {
      focusNodes.add(nodeSlug);
    });

    focusEdges = new Set<string>();

    const ancestorStack = [slug];
    const ancestorSeen = new Set<string>([slug]);
    while (ancestorStack.length > 0) {
      const current = ancestorStack.pop();
      if (!current) continue;
      const node = currentGraph.nodes.get(current);
      if (!node) continue;
      node.parents.forEach((parent) => {
        focusEdges.add(edgeKey(parent, current));
        if (ancestorSeen.has(parent)) return;
        ancestorSeen.add(parent);
        ancestorStack.push(parent);
      });
    }

    const descendantStack = [slug];
    const descendantSeen = new Set<string>([slug]);
    while (descendantStack.length > 0) {
      const current = descendantStack.pop();
      if (!current) continue;
      const node = currentGraph.nodes.get(current);
      if (!node) continue;
      node.children.forEach((child) => {
        focusEdges.add(edgeKey(current, child));
        if (descendantSeen.has(child)) return;
        descendantSeen.add(child);
        descendantStack.push(child);
      });
    }

    focusPushNodes = new Set(focusNodes);
    const selected = currentGraph.nodes.get(slug)!;
    selected.parents.forEach((nodeSlug) => {
      focusPushNodes.add(nodeSlug);
    });
    selected.children.forEach((nodeSlug) => {
      focusPushNodes.add(nodeSlug);
    });

    dirty = true;
    requestRender();
  }

  function clearFocus(): void {
    focusSlug = null;
    focusNodes = new Set();
    focusEdges = new Set();
    focusPushNodes = new Set();
    dirty = true;
    requestRender();
  }

  function updateTargets(): void {
    if (!currentGraph) return;
    const selected = focusSlug
      ? currentGraph.nodes.get(focusSlug) || null
      : null;

    currentGraph.nodes.forEach((node) => {
      if (!selected || !focusPushNodes.has(node.slug)) {
        node.targetX = node.baseX;
        node.targetY = node.baseY;
        return;
      }
      const dx = node.baseX - selected.baseX;
      const dy = node.baseY - selected.baseY;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const scale = 1 + PUSH_RADIUS / (dist + 1);
      node.targetX = selected.baseX + dx * scale;
      node.targetY = selected.baseY + dy * scale;
    });
  }

  function animateNodes(): boolean {
    if (!currentGraph) return false;
    let moving = false;
    currentGraph.nodes.forEach((node) => {
      node.renderX += (node.targetX - node.renderX) * 0.15;
      node.renderY += (node.targetY - node.renderY) * 0.15;
      const settled =
        Math.abs(node.targetX - node.renderX) < 0.06 &&
        Math.abs(node.targetY - node.renderY) < 0.06;
      if (!settled) moving = true;
    });
    return moving;
  }

  function updateHover(slug: string | null): void {
    if (focusSlug) return;
    hoverSlug = slug;
    hoverNodes = new Set();
    hoverEdges = new Set();
    if (!currentGraph || !slug || !currentGraph.nodes.has(slug)) {
      dirty = true;
      requestRender();
      return;
    }

    const ancestors = collectAncestors(currentGraph, slug);
    const descendants = collectDescendants(currentGraph, slug);
    hoverNodes = new Set([slug]);
    ancestors.forEach((nodeSlug) => {
      hoverNodes.add(nodeSlug);
    });
    descendants.forEach((nodeSlug) => {
      hoverNodes.add(nodeSlug);
    });

    const node = currentGraph.nodes.get(slug);
    if (node) {
      node.parents.forEach((parent) => {
        hoverNodes.add(parent);
      });
      node.children.forEach((child) => {
        hoverNodes.add(child);
      });
    }

    currentGraph.edges.forEach((edge) => {
      if (!hoverNodes.has(edge.from) || !hoverNodes.has(edge.to)) return;
      hoverEdges.add(edgeKey(edge.from, edge.to));
    });

    dirty = true;
    requestRender();
  }

  function showPopover(slug: string): void {
    if (!currentGraph) return;
    const node = currentGraph.nodes.get(slug);
    if (!node) return;
    const isDirect = node.depth === 0 && currentGraph.directAll.has(node.slug);
    popoverSlug = slug;
    options.popoverName.textContent = node.ref.name;
    options.popoverVersion.textContent = `Version: ${node.ref.version}`;
    options.popoverLicense.textContent = `License: ${node.ref.license || "Unknown"}`;
    options.popoverVulns.textContent = `Vulnerabilities: ${node.ref.vulnerabilityCount || 0}`;
    if (isDirect) {
      options.popoverAmplification.textContent = `Amplification: ${node.amplification}`;
    } else {
      options.popoverAmplification.textContent = `Dependencies: ${node.children.size} • Dependents: ${node.parents.size}`;
    }
    options.popover.hidden = false;
    updatePopoverPosition();
  }

  function hidePopover(): void {
    popoverSlug = null;
    options.popover.hidden = true;
  }

  function updatePopoverPosition(): void {
    if (!currentGraph || !popoverSlug || options.popover.hidden) return;
    const node = currentGraph.nodes.get(popoverSlug);
    if (!node) {
      hidePopover();
      return;
    }

    const x = node.renderX * zoom + panX;
    const y = node.renderY * zoom + panY;

    const hostRect = options.canvasHost.getBoundingClientRect();
    const popoverRect = options.popover.getBoundingClientRect();
    const maxLeft = Math.max(8, hostRect.width - popoverRect.width - 8);
    const maxTop = Math.max(8, hostRect.height - popoverRect.height - 8);

    const left = clamp(x + 14, 8, maxLeft);
    const top = clamp(y + 14, 8, maxTop);

    options.popover.style.left = `${left}px`;
    options.popover.style.top = `${top}px`;
  }

  function nodeOpacity(slug: string): number {
    if (focusSlug) return focusNodes.has(slug) ? 1 : 0.14;
    if (hoverSlug) return hoverNodes.has(slug) ? 1 : 0.16;
    return 0.95;
  }

  function renderedNodeRadius(node: GraphNode): number {
    const selected = focusSlug === node.slug;
    const inFocus = focusNodes.has(node.slug);
    let radius = node.radius;
    if (selected) radius *= 1.85;
    else if (focusSlug && inFocus) radius *= 1.22;
    else if (focusSlug && !inFocus) radius *= 0.84;
    else if (hoverSlug && hoverNodes.has(node.slug)) radius *= 1.1;
    else if (hoverSlug) radius *= 0.9;
    return radius;
  }

  function mutedEdgeOpacity(): number {
    if (focusSlug || hoverSlug) {
      const zoomFactor = clamp((zoom - 0.35) / 0.9, 0.75, 1);
      return 0.04 * zoomFactor;
    }
    const zoomFactor = clamp((zoom - 0.35) / 0.9, 0.2, 1);
    return 0.25 * zoomFactor;
  }

  function highlightedEdgeOpacity(): number {
    const zoomFactor = clamp((zoom - 0.35) / 0.9, 0.2, 1);
    return 0.36 * zoomFactor;
  }

  function vulnerabilityRingOpacity(slug: string): number {
    if (focusSlug) return focusNodes.has(slug) ? 0.78 : 0.11;
    if (hoverSlug) return hoverNodes.has(slug) ? 0.76 : 0.12;
    return 0.8;
  }

  function renderGraph(): void {
    if (!context) return;
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    context.clearRect(0, 0, width, height);
    if (!currentGraph) return;
    const graph = currentGraph;

    const worldMinX = worldX(0) - 80;
    const worldMaxX = worldX(width) + 80;
    const worldMinY = worldY(0) - 80;
    const worldMaxY = worldY(height) + 80;

    context.setTransform(dpr * zoom, 0, 0, dpr * zoom, dpr * panX, dpr * panY);

    const colorRuntime = getCssColor("--graph-direct-runtime") || "#10b981";
    const colorDev = getCssColor("--graph-direct-dev") || "#f59e0b";
    const colorTransitive = getCssColor("--graph-transitive") || "#06b6d4";
    const colorEdge = getCssColor("--graph-edge") || "#64748b";
    const colorHighlight = getCssColor("--graph-highlight") || "#22d3ee";
    const colorMuted = getCssColor("--graph-muted") || "#64748b";
    const colorRingHigh = getCssColor("--graph-vuln-high") || "#ef4444";
    const colorRingModerate = getCssColor("--graph-vuln-medium") || "#f59e0b";
    const labelColor = getCssColor("--text-primary") || "#e8edf5";

    const visible = new Set<string>();
    graph.nodes.forEach((node) => {
      if (
        node.renderX + node.radius >= worldMinX &&
        node.renderX - node.radius <= worldMaxX &&
        node.renderY + node.radius >= worldMinY &&
        node.renderY - node.radius <= worldMaxY
      ) {
        visible.add(node.slug);
      }
    });

    const maxDepth = Math.max(0, graph.layers.length - 1);
    const SAME_COLUMN_X_THRESHOLD = 6;
    const MIN_DETOUR_VERTICAL_SPAN = 80;
    const DETOUR_INSET = 14;
    const DETOUR_NODE_CLEARANCE = 26;

    const drawSmoothedPolyline = (
      points: Array<{ x: number; y: number }>,
      cornerRadius: number,
    ): void => {
      if (points.length === 0) return;
      context.moveTo(points[0].x, points[0].y);
      if (points.length === 1) return;
      if (points.length === 2) {
        context.lineTo(points[1].x, points[1].y);
        return;
      }

      for (let i = 1; i < points.length - 1; i += 1) {
        const prev = points[i - 1];
        const curr = points[i];
        const next = points[i + 1];

        const inDx = curr.x - prev.x;
        const inDy = curr.y - prev.y;
        const outDx = next.x - curr.x;
        const outDy = next.y - curr.y;
        const inLen = Math.hypot(inDx, inDy);
        const outLen = Math.hypot(outDx, outDy);

        if (inLen < 0.001 || outLen < 0.001) {
          context.lineTo(curr.x, curr.y);
          continue;
        }

        const cut = Math.min(cornerRadius, inLen * 0.45, outLen * 0.45);
        const startX = curr.x - (inDx / inLen) * cut;
        const startY = curr.y - (inDy / inLen) * cut;
        const endX = curr.x + (outDx / outLen) * cut;
        const endY = curr.y + (outDy / outLen) * cut;

        context.lineTo(startX, startY);
        context.quadraticCurveTo(curr.x, curr.y, endX, endY);
      }

      const last = points[points.length - 1];
      context.lineTo(last.x, last.y);
    };

    const drawRoutedEdge = (from: GraphNode, to: GraphNode): void => {
      const sourceX = from.renderX;
      const sourceY = from.renderY;
      const targetX = to.renderX;
      const targetY = to.renderY;
      const depthDelta = to.depth - from.depth;
      const span = Math.abs(depthDelta);

      context.beginPath();
      context.moveTo(sourceX, sourceY);

      if (span === 0) {
        const sameColumn =
          Math.abs(sourceX - targetX) < SAME_COLUMN_X_THRESHOLD;
        const verticalSpan = Math.abs(sourceY - targetY);
        const hasRightCorridor = from.depth < maxDepth;

        if (
          sameColumn &&
          verticalSpan > MIN_DETOUR_VERTICAL_SPAN &&
          hasRightCorridor
        ) {
          const currentColumnX = PADDING_X + from.depth * LAYER_GAP;
          const nextColumnX = PADDING_X + (from.depth + 1) * LAYER_GAP;
          const corridorCenterX = (currentColumnX + nextColumnX) * 0.5;
          let detourX = corridorCenterX + DETOUR_INSET;

          const minY = Math.min(sourceY, targetY) - 12;
          const maxY = Math.max(sourceY, targetY) + 12;
          let crowded = false;
          graph.nodes.forEach((node) => {
            if (crowded) return;
            if (node.depth !== from.depth + 1) return;
            if (node.renderY < minY || node.renderY > maxY) return;
            if (Math.abs(node.renderX - detourX) < DETOUR_NODE_CLEARANCE) {
              crowded = true;
            }
          });
          if (crowded) detourX += 12;

          const detourMinX = corridorCenterX + 8;
          const detourMaxX = nextColumnX - 24;
          detourX = clamp(detourX, detourMinX, detourMaxX);

          const outSpan = Math.max(1, detourX - sourceX);
          const cornerRadius = clamp(
            Math.min(outSpan, verticalSpan) * 0.42,
            16,
            52,
          );
          drawSmoothedPolyline(
            [
              { x: sourceX, y: sourceY },
              { x: detourX, y: sourceY },
              { x: detourX, y: targetY },
              { x: targetX, y: targetY },
            ],
            cornerRadius,
          );
          context.stroke();
          return;
        }

        const cx = sourceX + (targetX - sourceX) * 0.5;
        const cy = sourceY + (targetY - sourceY) * EDGE_CURVE;
        context.quadraticCurveTo(cx, cy, targetX, targetY);
        context.stroke();
        return;
      }

      if (span === 1) {
        const leftDepth = Math.min(from.depth, to.depth);
        const corridorCenterX =
          PADDING_X + leftDepth * LAYER_GAP + LAYER_GAP * 0.5;
        context.bezierCurveTo(
          corridorCenterX,
          sourceY,
          corridorCenterX,
          targetY,
          targetX,
          targetY,
        );
        context.stroke();
        return;
      }

      const direction = Math.sign(depthDelta);
      const yDelta = targetY - sourceY;
      const points: Array<{ x: number; y: number }> = [
        { x: sourceX, y: sourceY },
      ];

      const firstCorridorX =
        PADDING_X + from.depth * LAYER_GAP + direction * (LAYER_GAP * 0.5);
      points.push({ x: firstCorridorX, y: sourceY });

      for (let step = 1; step < span; step += 1) {
        const depth = from.depth + direction * step;
        const corridorX =
          PADDING_X + depth * LAYER_GAP + direction * (LAYER_GAP * 0.5);
        const t = step / span;
        points.push({ x: corridorX, y: sourceY + yDelta * t });
      }

      const preTargetCorridorX =
        PADDING_X + to.depth * LAYER_GAP - direction * (LAYER_GAP * 0.5);
      points.push({ x: preTargetCorridorX, y: targetY });
      points.push({ x: targetX, y: targetY });

      drawSmoothedPolyline(points, 14);
      context.stroke();
    };

    type RenderEdge = {
      from: GraphNode;
      to: GraphNode;
      highlighted: boolean;
      span: number;
    };

    const renderEdges: RenderEdge[] = [];
    graph.edges.forEach((edge) => {
      const from = graph.nodes.get(edge.from);
      const to = graph.nodes.get(edge.to);
      if (!from || !to) return;
      if (!visible.has(from.slug) && !visible.has(to.slug)) return;
      const key = edgeKey(edge.from, edge.to);
      renderEdges.push({
        from,
        to,
        highlighted: focusEdges.has(key) || (!focusSlug && hoverEdges.has(key)),
        span: Math.abs(to.depth - from.depth),
      });
    });

    renderEdges.sort((a, b) => b.span - a.span);

    context.globalCompositeOperation = "source-over";
    context.strokeStyle = focusSlug || hoverSlug ? colorMuted : colorEdge;
    context.lineWidth = 1.05;
    context.globalAlpha = mutedEdgeOpacity();
    renderEdges.forEach((edge) => {
      if (edge.highlighted) return;
      drawRoutedEdge(edge.from, edge.to);
    });

    context.globalCompositeOperation = "lighter";
    context.strokeStyle = colorHighlight;
    context.lineWidth = 1.2;
    context.globalAlpha = highlightedEdgeOpacity();
    renderEdges.forEach((edge) => {
      if (!edge.highlighted) return;
      drawRoutedEdge(edge.from, edge.to);
    });

    context.globalCompositeOperation = "source-over";

    graph.nodes.forEach((node) => {
      if (!visible.has(node.slug)) return;
      const selected = focusSlug === node.slug;
      const radius = renderedNodeRadius(node);

      context.globalAlpha = nodeOpacity(node.slug);

      const grad = context.createRadialGradient(
        node.renderX - radius * 0.3,
        node.renderY - radius * 0.3,
        0,
        node.renderX,
        node.renderY,
        radius * 1.2,
      );

      if (node.kind === "direct-runtime") {
        grad.addColorStop(0, "#34d399");
        grad.addColorStop(1, colorRuntime);
      } else if (node.kind === "direct-dev") {
        grad.addColorStop(0, "#fcd34d");
        grad.addColorStop(1, colorDev);
      } else {
        grad.addColorStop(0, "#67e8f9");
        grad.addColorStop(1, colorTransitive);
      }

      context.fillStyle = grad;

      context.beginPath();
      context.arc(node.renderX, node.renderY, radius, 0, Math.PI * 2);
      context.fill();

      if (selected) {
        context.globalAlpha = 0.95;
        context.strokeStyle = colorHighlight;
        context.lineWidth = 1.5;
        context.beginPath();
        context.arc(node.renderX, node.renderY, radius + 4, 0, Math.PI * 2);
        context.stroke();
      }
    });

    currentGraph.nodes.forEach((node) => {
      if (!visible.has(node.slug)) return;
      if (!node.ref.vulnerabilityCount || node.ref.vulnerabilityCount <= 0)
        return;
      if (node.ref.vulnerabilitySeverity === "none") return;
      const radius = renderedNodeRadius(node);
      context.globalAlpha = vulnerabilityRingOpacity(node.slug);
      context.lineWidth = 2;
      context.strokeStyle =
        node.ref.vulnerabilitySeverity === "high"
          ? colorRingHigh
          : colorRingModerate;
      context.beginPath();
      context.arc(node.renderX, node.renderY, radius + 4, 0, Math.PI * 2);
      context.stroke();
    });

    context.textBaseline = "middle";
    context.font =
      '500 11.5px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    context.fillStyle = labelColor;
    graph.nodes.forEach((node) => {
      if (!visible.has(node.slug)) return;
      context.globalAlpha = nodeOpacity(node.slug);
      context.fillText(
        node.ref.name,
        node.renderX + renderedNodeRadius(node) + 6,
        node.renderY,
      );
    });

    context.globalAlpha = 1;
    updatePopoverPosition();
  }

  function tick(): void {
    if (!active) {
      frameId = 0;
      return;
    }

    updateTargets();
    const moving = animateNodes();

    if (dirty || moving) {
      renderGraph();
      dirty = false;
      if (active && (dirty || moving)) {
        frameId = window.requestAnimationFrame(tick);
      } else {
        frameId = 0;
      }
      return;
    }

    frameId = 0;
  }

  function renderLoop(): void {
    if (!active || frameId || !dirty) return;
    frameId = window.requestAnimationFrame(tick);
  }

  function requestRender(): void {
    dirty = true;
    if (active) renderLoop();
  }

  function switchWorkspace(name: string): void {
    const graph = buildWorkspaceGraph(name);
    if (!graph) return;
    currentWorkspace = name;
    currentGraph = graph;
    clearFocus();
    hidePopover();
    hoverSlug = null;
    hoverNodes = new Set();
    hoverEdges = new Set();
    fitGraph();
    dirty = true;
    requestRender();
  }

  function handleCanvasMouseDown(event: MouseEvent): void {
    if (event.button !== 0) return;
    panState.down = true;
    panState.moved = false;
    panState.startX = event.clientX;
    panState.startY = event.clientY;
    panState.startPanX = panX;
    panState.startPanY = panY;
    options.canvas.classList.add("is-panning");
  }

  function handleWindowMouseMove(event: MouseEvent): void {
    if (!panState.down) {
      const node = findNode(event.clientX, event.clientY);
      updateHover(node ? node.slug : null);
      return;
    }

    const dx = event.clientX - panState.startX;
    const dy = event.clientY - panState.startY;
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) panState.moved = true;
    panX = panState.startPanX + dx;
    panY = panState.startPanY + dy;
    requestRender();
  }

  function handleWindowMouseUp(event: MouseEvent): void {
    if (!panState.down) return;
    options.canvas.classList.remove("is-panning");
    const moved = panState.moved;
    panState.down = false;
    panState.moved = false;

    if (moved) return;

    const node = findNode(event.clientX, event.clientY);
    if (!node) {
      clearFocus();
      hidePopover();
      return;
    }

    applyFocus(node.slug);
    showPopover(node.slug);
  }

  function handleWheel(event: WheelEvent): void {
    if (!options.canvasHost.contains(event.target as Node)) return;
    event.preventDefault();
    const rect = options.canvas.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // Zoom sensitivity adjustments based on device type (trackpad vs wheel)
    const delta =
      event.ctrlKey || event.metaKey
        ? event.deltaY * 0.015
        : event.deltaY * 0.002;
    const factor = Math.exp(-delta);

    applyZoom(zoom * factor, x, y);
  }

  function handleTouchStart(event: TouchEvent): void {
    if (event.touches.length === 0) return;
    event.preventDefault();

    const rect = options.canvas.getBoundingClientRect();

    if (event.touches.length === 1) {
      touchState.active = true;
      panState.moved = false;
      touchState.startX1 = event.touches[0].clientX;
      touchState.startY1 = event.touches[0].clientY;
      touchState.startPanX = panX;
      touchState.startPanY = panY;
      options.canvas.classList.add("is-panning");
    } else if (event.touches.length === 2) {
      touchState.active = true;
      panState.moved = false;
      touchState.startX1 = event.touches[0].clientX;
      touchState.startY1 = event.touches[0].clientY;
      touchState.startX2 = event.touches[1].clientX;
      touchState.startY2 = event.touches[1].clientY;

      const dx = touchState.startX2 - touchState.startX1;
      const dy = touchState.startY2 - touchState.startY1;
      touchState.startDist = Math.sqrt(dx * dx + dy * dy);
      touchState.startZoom = zoom;

      const cx = (touchState.startX1 + touchState.startX2) / 2;
      const cy = (touchState.startY1 + touchState.startY2) / 2;

      // Convert center to world coordinates relative to canvas
      const screenX = cx - rect.left;
      const screenY = cy - rect.top;

      // Temporarily store these for the move event relative anchoring
      (touchState as any).anchorX = screenX;
      (touchState as any).anchorY = screenY;
    }
  }

  function handleTouchMove(event: TouchEvent): void {
    if (!touchState.active) return;
    event.preventDefault();

    if (event.touches.length === 1) {
      const dx = event.touches[0].clientX - touchState.startX1;
      const dy = event.touches[0].clientY - touchState.startY1;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) panState.moved = true;
      panX = touchState.startPanX + dx;
      panY = touchState.startPanY + dy;
      requestRender();
    } else if (event.touches.length === 2) {
      panState.moved = true;
      const x1 = event.touches[0].clientX;
      const y1 = event.touches[0].clientY;
      const x2 = event.touches[1].clientX;
      const y2 = event.touches[1].clientY;

      const dx = x2 - x1;
      const dy = y2 - y1;
      const dist = Math.sqrt(dx * dx + dy * dy);

      if (touchState.startDist > 0) {
        const factor = dist / touchState.startDist;
        const newZoom = touchState.startZoom * factor;
        const anchorX = (touchState as any).anchorX || width / 2;
        const anchorY = (touchState as any).anchorY || height / 2;
        applyZoom(newZoom, anchorX, anchorY);
      }
    }
  }

  function handleTouchEnd(event: TouchEvent): void {
    if (!touchState.active) return;
    event.preventDefault();

    if (event.touches.length === 0) {
      options.canvas.classList.remove("is-panning");
      touchState.active = false;

      if (!panState.moved && event.changedTouches.length === 1) {
        const node = findNode(
          event.changedTouches[0].clientX,
          event.changedTouches[0].clientY,
        );
        if (!node) {
          clearFocus();
          hidePopover();
        } else {
          applyFocus(node.slug);
          showPopover(node.slug);
        }
      }
      panState.moved = false;
    } else if (event.touches.length === 1) {
      // Transition from pinch back to pan
      touchState.startX1 = event.touches[0].clientX;
      touchState.startY1 = event.touches[0].clientY;
      touchState.startPanX = panX;
      touchState.startPanY = panY;
    }
  }

  function handleCanvasMouseLeave(): void {
    updateHover(null);
  }

  function handleDocumentMouseDown(event: MouseEvent): void {
    if (!active) return;
    const target = event.target as Node;
    if (options.popover.hidden) return;
    if (options.popover.contains(target)) return;
    if (options.canvasHost.contains(target)) return;
    hidePopover();
  }

  function bindInteractionListeners(): void {
    if (interactionsBound || !hasCanvas) return;
    options.canvas.addEventListener("mousedown", handleCanvasMouseDown);
    window.addEventListener("mousemove", handleWindowMouseMove);
    window.addEventListener("mouseup", handleWindowMouseUp);
    options.canvas.addEventListener("wheel", handleWheel, { passive: false });

    // Add touch listeners
    options.canvas.addEventListener("touchstart", handleTouchStart, {
      passive: false,
    });
    window.addEventListener("touchmove", handleTouchMove, { passive: false });
    window.addEventListener("touchend", handleTouchEnd, { passive: false });
    window.addEventListener("touchcancel", handleTouchEnd, { passive: false });

    options.canvas.addEventListener("mouseleave", handleCanvasMouseLeave);
    document.addEventListener("mousedown", handleDocumentMouseDown);
    interactionsBound = true;
  }

  function unbindInteractionListeners(): void {
    if (!interactionsBound) return;
    options.canvas.removeEventListener("mousedown", handleCanvasMouseDown);
    window.removeEventListener("mousemove", handleWindowMouseMove);
    window.removeEventListener("mouseup", handleWindowMouseUp);
    options.canvas.removeEventListener("wheel", handleWheel);

    // Remove touch listeners
    options.canvas.removeEventListener("touchstart", handleTouchStart);
    window.removeEventListener("touchmove", handleTouchMove);
    window.removeEventListener("touchend", handleTouchEnd);
    window.removeEventListener("touchcancel", handleTouchEnd);

    options.canvas.removeEventListener("mouseleave", handleCanvasMouseLeave);
    document.removeEventListener("mousedown", handleDocumentMouseDown);
    options.canvas.classList.remove("is-panning");
    panState.down = false;
    panState.moved = false;
    touchState.active = false;
    interactionsBound = false;
  }

  function setupControls(): void {
    options.controlsRoot.addEventListener("click", (event) => {
      const target = event.target as HTMLElement;
      const button = target.closest<HTMLButtonElement>("button[data-action]");
      if (!button) return;
      const action = button.dataset.action;
      if (!action) return;
      if (action === "zoom-in") {
        applyZoom(zoom * 1.18, width * 0.5, height * 0.5);
        return;
      }
      if (action === "zoom-out") {
        applyZoom(zoom / 1.18, width * 0.5, height * 0.5);
        return;
      }
      if (action === "pan-left") {
        panBy(-52, 0);
        return;
      }
      if (action === "pan-right") {
        panBy(52, 0);
        return;
      }
      if (action === "pan-up") {
        panBy(0, -52);
        return;
      }
      if (action === "pan-down") {
        panBy(0, 52);
        return;
      }
      if (action === "reset") {
        zoom = fitZoom;
        panX = defaultPanX;
        panY = defaultPanY;
        clearFocus();
        hidePopover();
        requestRender();
      }
    });

    options.popoverOpenButton.addEventListener("click", () => {
      if (!popoverSlug) return;
      options.onOpenList(popoverSlug);
    });
  }

  function initGraphViewInternal(): void {
    const workspaces = dataset.workspaces.length
      ? dataset.workspaces
      : [
          {
            name: "root",
            directDependencies: [],
            directDevDependencies: [],
          },
        ];

    options.workspaceSelect.textContent = "";
    workspaces.forEach((workspace) => {
      const option = document.createElement("option");
      option.value = workspace.name;
      option.textContent = workspace.name;
      options.workspaceSelect.appendChild(option);
    });

    options.workspaceWrap.classList.toggle("hidden", workspaces.length <= 1);

    if (!workspaceByName.has("root") && workspaces.length === 1) {
      workspaceByName.set("root", workspaces[0]);
    }

    currentWorkspace = workspaces[0].name;
    options.workspaceSelect.value = currentWorkspace;

    options.workspaceSelect.addEventListener("change", () => {
      switchWorkspace(options.workspaceSelect.value);
    });

    const observer = new MutationObserver(() => requestRender());
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class", "data-theme"],
    });

    if (typeof ResizeObserver !== "undefined") {
      const resizeObserver = new ResizeObserver(() => {
        if (!active) return;
        updateCanvasSize();
        if (width <= 1 || height <= 1) return;
        updateFitMetrics();
        zoom = clamp(zoom, minZoom, MAX_ZOOM);
        requestRender();
      });
      resizeObserver.observe(options.canvasHost);
    } else {
      window.addEventListener("resize", () => {
        if (!active) return;
        updateCanvasSize();
        if (width <= 1 || height <= 1) return;
        updateFitMetrics();
        zoom = clamp(zoom, minZoom, MAX_ZOOM);
        requestRender();
      });
    }

    setupControls();
    if (!hasCanvas) {
      showCanvasFallback();
      return;
    }
    updateCanvasSize();
    switchWorkspace(currentWorkspace);
  }

  function setActive(next: boolean): void {
    active = next;
    if (active) {
      if (!hasCanvas) {
        showCanvasFallback();
        return;
      }
      bindInteractionListeners();
      updateCanvasSize();
      if (width > 1 && height > 1) {
        updateFitMetrics();
        zoom = clamp(zoom, minZoom, MAX_ZOOM);
      }
      renderLoop();
      requestRender();
      return;
    }
    unbindInteractionListeners();
    if (frameId) {
      window.cancelAnimationFrame(frameId);
      frameId = 0;
    }
  }

  return {
    initGraphView: initGraphViewInternal,
    buildWorkspaceGraph,
    computeAmplification,
    layoutGraph,
    renderLoop,
    applyFocus,
    clearFocus,
    showPopover,
    hidePopover,
    switchWorkspace,
    setActive,
    requestRender,
  };
}
