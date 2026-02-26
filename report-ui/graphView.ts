import type { AggregatedData, DependencyRecord } from './types';

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
  isDevOnly: boolean;
  workspaceOrigins: string[];
  sourceRef?: DependencyRecord;
};

type GraphDataset = {
  workspaces: GraphWorkspace[];
  dependencies: Record<string, GraphDependency>;
};

type GraphNodeKind = 'direct-runtime' | 'direct-dev' | 'transitive';

type GraphNode = {
  slug: string;
  ref: GraphDependency;
  parents: Set<string>;
  children: Set<string>;
  depth: number;
  order: number;
  baseX: number;
  baseY: number;
  renderX: number;
  renderY: number;
  radius: number;
  kind: GraphNodeKind;
};

type GraphEdge = {
  from: string;
  to: string;
  direct: boolean;
};

type WorkspaceGraph = {
  workspaceName: string;
  nodes: Map<string, GraphNode>;
  layers: string[][];
  edges: GraphEdge[];
  directRuntime: Set<string>;
  directDev: Set<string>;
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
  canvas: HTMLCanvasElement;
  canvasHost: HTMLElement;
  onOpenList: (slug: string) => void;
};

export type GraphViewHandle = {
  initGraphView: () => void;
  buildWorkspaceGraph: (workspaceName: string) => WorkspaceGraph | null;
  layoutGraph: (graph: WorkspaceGraph) => void;
  renderGraph: () => void;
  applyFocus: (slug: string) => void;
  resetFocus: () => void;
  switchWorkspace: (workspaceName: string) => void;
  setActive: (active: boolean) => void;
  requestRender: () => void;
};

const GRAPH_LAYER_GAP = 250;
const GRAPH_ROW_GAP = 74;
const GRAPH_PADDING_X = 110;
const GRAPH_PADDING_Y = 70;
const GRAPH_NODE_BASE_RADIUS = 8;
const GRAPH_NODE_RADIUS_SCALE = 2.2;
const GRAPH_PUSH_RADIUS = 115;
const GRAPH_ANIMATION_EASE = 0.18;
const GRAPH_MIN_ZOOM = 0.32;
const GRAPH_MAX_ZOOM = 2.8;

declare global {
  interface Window {
    __DEPENDENCY_DATA__?: unknown;
  }
}

function clamp(value: number, min: number, max: number): number {
  if (value < min) return min;
  if (value > max) return max;
  return value;
}

function getDepKey(name: string, version: string): string {
  return `${name}@${version}`;
}

function getPrimaryLicense(dep: DependencyRecord): string {
  const declared = dep.compliance.license.declared?.valid
    ? dep.compliance.license.declared.spdxId
    : undefined;
  if (declared) return declared;
  const inferred = dep.compliance.license.inferred?.spdxId;
  return inferred || 'Unknown';
}

function getVulnerabilityCount(dep: DependencyRecord): number {
  const summary = dep.security?.summary;
  if (!summary) return 0;
  return (
    Number(summary.critical || 0) +
    Number(summary.high || 0) +
    Number(summary.moderate || 0) +
    Number(summary.low || 0)
  );
}

function isGraphDatasetLike(value: unknown): value is GraphDataset {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Record<string, unknown>;
  if (!Array.isArray(candidate.workspaces)) return false;
  if (!candidate.dependencies || typeof candidate.dependencies !== 'object') {
    return false;
  }
  return true;
}

function edgeKey(from: string, to: string): string {
  return `${from}->${to}`;
}

function collectAncestors(
  graph: WorkspaceGraph | null,
  slug: string,
): Set<string> {
  const result = new Set<string>();
  if (!graph) return result;
  const stack: string[] = [slug];
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

function collectDescendants(
  graph: WorkspaceGraph | null,
  slug: string,
): Set<string> {
  const result = new Set<string>();
  if (!graph) return result;
  const stack: string[] = [slug];
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

function getCssColor(varName: string): string {
  return (
    getComputedStyle(document.documentElement)
      .getPropertyValue(varName)
      .trim() || 'currentColor'
  );
}

function buildGraphDataset(
  report: AggregatedData,
  knownDepKeys: Set<string>,
  resolveDepKey: (depKey: string) => string | null,
): GraphDataset {
  const globalData = window.__DEPENDENCY_DATA__;
  if (isGraphDatasetLike(globalData)) {
    const dependencies = globalData.dependencies as Record<string, GraphDependency>;
    Object.values(dependencies).forEach((dep) => {
      if (!Array.isArray(dep.dependencies)) dep.dependencies = [];
    });
    return {
      workspaces: globalData.workspaces as GraphWorkspace[],
      dependencies,
    };
  }

  const dependencies: Record<string, GraphDependency> = {};
  const allDependencies = Object.values(report.dependencies || {});

  allDependencies.forEach((dep) => {
    const slug = getDepKey(dep.package.name, dep.package.version);
    dependencies[slug] = {
      slug,
      name: dep.package.name,
      version: dep.package.version,
      dependencies: [],
      license: getPrimaryLicense(dep),
      vulnerabilityCount: getVulnerabilityCount(dep),
      isDevOnly: dep.usage.scope === 'dev',
      workspaceOrigins: dep.usage.origins.workspaces
        ? [...dep.usage.origins.workspaces]
        : [],
      sourceRef: dep,
    };
  });

  allDependencies.forEach((dep) => {
    const slug = getDepKey(dep.package.name, dep.package.version);
    const childSet = new Set<string>();
    const subDeps = dep.graph.subDeps;
    if (!subDeps) return;
    (['dep', 'dev', 'opt', 'peer'] as const).forEach((bucket) => {
      const entries = subDeps[bucket];
      if (!entries) return;
      Object.values(entries).forEach((entry) => {
        const tuple = entry as [string, string | null];
        const resolved = tuple[1];
        if (!resolved) return;
        const normalized = resolveDepKey(resolved);
        if (!normalized) return;
        if (!knownDepKeys.has(normalized)) return;
        if (normalized === slug) return;
        childSet.add(normalized);
      });
    });
    dependencies[slug].dependencies = [...childSet];
  });

  const workspaceStore = new Map<
    string,
    { directDependencies: Set<string>; directDevDependencies: Set<string> }
  >();

  const ensureWorkspace = (
    name: string,
  ): { directDependencies: Set<string>; directDevDependencies: Set<string> } => {
    const existing = workspaceStore.get(name);
    if (existing) return existing;
    const next = {
      directDependencies: new Set<string>(),
      directDevDependencies: new Set<string>(),
    };
    workspaceStore.set(name, next);
    return next;
  };

  const declaredWorkspaces = report.workspaces.workspacePackages || [];
  declaredWorkspaces.forEach((workspace) => ensureWorkspace(workspace.name));
  ensureWorkspace('root');

  allDependencies.forEach((dep) => {
    if (!dep.usage.direct) return;
    const slug = getDepKey(dep.package.name, dep.package.version);
    const origins =
      dep.usage.origins.workspaces && dep.usage.origins.workspaces.length > 0
        ? dep.usage.origins.workspaces
        : ['root'];
    origins.forEach((workspaceName) => {
      const workspace = ensureWorkspace(workspaceName);
      if (dep.usage.scope === 'dev') {
        workspace.directDevDependencies.add(slug);
        return;
      }
      workspace.directDependencies.add(slug);
    });
  });

  const workspaces: GraphWorkspace[] = [...workspaceStore.entries()]
    .map(([name, data]) => ({
      name,
      directDependencies: [...data.directDependencies].sort(),
      directDevDependencies: [...data.directDevDependencies].sort(),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return {
    workspaces,
    dependencies,
  };
}

export function initGraphView(options: GraphViewOptions): GraphViewHandle {
  const dataset = buildGraphDataset(
    options.report,
    options.knownDepKeys,
    options.resolveDepKey,
  );
  const workspaceByName = new Map(
    dataset.workspaces.map((workspace) => [workspace.name, workspace]),
  );

  const childrenBySlug = new Map<string, string[]>();
  const parentsBySlug = new Map<string, string[]>();

  Object.values(dataset.dependencies).forEach((dep) => {
    const validChildren = dep.dependencies.filter(
      (child) => child !== dep.slug && Boolean(dataset.dependencies[child]),
    );
    childrenBySlug.set(dep.slug, validChildren);
    validChildren.forEach((child) => {
      const existingParents = parentsBySlug.get(child) || [];
      existingParents.push(dep.slug);
      parentsBySlug.set(child, existingParents);
    });
  });

  let currentGraph: WorkspaceGraph | null = null;
  let currentWorkspaceName = '';
  let focusSlug: string | null = null;
  let hoverSlug: string | null = null;
  let focusAncestors = new Set<string>();
  let focusDescendants = new Set<string>();
  let focusNodes = new Set<string>();
  let focusEdges = new Set<string>();
  let hoverNodes = new Set<string>();
  let hoverEdges = new Set<string>();
  let pushNodes = new Set<string>();
  let lockedFocus = false;
  let active = false;

  let zoom = 1;
  let panX = 0;
  let panY = 0;
  let needsRender = true;

  let rafId = 0;
  let canvasWidth = 0;
  let canvasHeight = 0;
  let dpr = Math.max(1, Math.floor(window.devicePixelRatio || 1));

  const panState = {
    pointerDown: false,
    moved: false,
    startClientX: 0,
    startClientY: 0,
    startPanX: 0,
    startPanY: 0,
  };

  const context = options.canvas.getContext('2d');
  if (!context) {
    throw new Error('Unable to initialize graph canvas context');
  }

  const updateCanvasSize = (): void => {
    const rect = options.canvasHost.getBoundingClientRect();
    canvasWidth = Math.max(1, Math.floor(rect.width));
    canvasHeight = Math.max(1, Math.floor(rect.height));
    dpr = Math.max(1, Math.floor(window.devicePixelRatio || 1));
    options.canvas.width = canvasWidth * dpr;
    options.canvas.height = canvasHeight * dpr;
    options.canvas.style.width = `${canvasWidth}px`;
    options.canvas.style.height = `${canvasHeight}px`;
    needsRender = true;
    requestRender();
  };

  const toWorldX = (screenX: number): number => (screenX - panX) / zoom;
  const toWorldY = (screenY: number): number => (screenY - panY) / zoom;

  const findNodeAt = (clientX: number, clientY: number): GraphNode | null => {
    if (!currentGraph) return null;
    const rect = options.canvas.getBoundingClientRect();
    const localX = clientX - rect.left;
    const localY = clientY - rect.top;
    const worldX = toWorldX(localX);
    const worldY = toWorldY(localY);
    let hit: GraphNode | null = null;
    currentGraph.nodes.forEach((node) => {
      const dx = worldX - node.renderX;
      const dy = worldY - node.renderY;
      const distance = Math.sqrt(dx * dx + dy * dy);
      if (distance <= node.radius + 5) hit = node;
    });
    return hit;
  };

  const fitGraphToViewport = (): void => {
    if (!currentGraph) return;
    const bounds = currentGraph.bounds;
    const width = Math.max(1, bounds.maxX - bounds.minX);
    const height = Math.max(1, bounds.maxY - bounds.minY);
    const horizontalScale = (canvasWidth - 120) / width;
    const verticalScale = (canvasHeight - 100) / height;
    zoom = clamp(Math.min(horizontalScale, verticalScale, 1.08), GRAPH_MIN_ZOOM, GRAPH_MAX_ZOOM);
    panX = (canvasWidth - width * zoom) * 0.5 - bounds.minX * zoom;
    panY = (canvasHeight - height * zoom) * 0.5 - bounds.minY * zoom;
    needsRender = true;
  };

  const updateHoverState = (slug: string | null): void => {
    if (lockedFocus) return;
    hoverSlug = slug;
    hoverNodes = new Set<string>();
    hoverEdges = new Set<string>();
    if (!currentGraph || !slug || !currentGraph.nodes.has(slug)) {
      needsRender = true;
      requestRender();
      return;
    }
    const ancestors = collectAncestors(currentGraph, slug);
    const descendants = collectDescendants(currentGraph, slug);
    hoverNodes = new Set<string>([slug]);
    ancestors.forEach((nodeSlug) => hoverNodes.add(nodeSlug));
    descendants.forEach((nodeSlug) => hoverNodes.add(nodeSlug));
    const node = currentGraph.nodes.get(slug);
    if (node) {
      node.parents.forEach((parent) => hoverNodes.add(parent));
      node.children.forEach((child) => hoverNodes.add(child));
    }
    currentGraph.edges.forEach((edge) => {
      if (!hoverNodes.has(edge.from) || !hoverNodes.has(edge.to)) return;
      hoverEdges.add(edgeKey(edge.from, edge.to));
    });
    needsRender = true;
    requestRender();
  };

  const updateFocusEdgeSet = (): void => {
    focusEdges = new Set<string>();
    if (!currentGraph || !focusSlug) return;
    currentGraph.edges.forEach((edge) => {
      if (!focusNodes.has(edge.from) || !focusNodes.has(edge.to)) return;
      focusEdges.add(edgeKey(edge.from, edge.to));
    });
  };

  const updateNodePositions = (): boolean => {
    if (!currentGraph) return false;
    const selectedNode =
      focusSlug && currentGraph.nodes.has(focusSlug)
        ? currentGraph.nodes.get(focusSlug) || null
        : null;
    let animating = false;
    currentGraph.nodes.forEach((node) => {
      let targetX = node.baseX;
      let targetY = node.baseY;
      if (selectedNode && pushNodes.has(node.slug)) {
        const dx = node.baseX - selectedNode.baseX;
        const dy = node.baseY - selectedNode.baseY;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const scale = 1 + GRAPH_PUSH_RADIUS / (dist + 1);
        targetX = selectedNode.baseX + dx * scale;
        targetY = selectedNode.baseY + dy * scale;
      }
      node.renderX += (targetX - node.renderX) * GRAPH_ANIMATION_EASE;
      node.renderY += (targetY - node.renderY) * GRAPH_ANIMATION_EASE;
      const xSettled = Math.abs(targetX - node.renderX) < 0.08;
      const ySettled = Math.abs(targetY - node.renderY) < 0.08;
      if (!xSettled || !ySettled) animating = true;
    });
    return animating;
  };

  const getNodeOpacity = (slug: string): number => {
    if (lockedFocus && focusSlug) {
      return focusNodes.has(slug) ? 1 : 0.14;
    }
    if (hoverSlug) {
      return hoverNodes.has(slug) ? 1 : 0.16;
    }
    return 0.96;
  };

  const getEdgeOpacity = (key: string, highlighted: boolean): number => {
    if (highlighted) return 0.95;
    if (lockedFocus && focusSlug) return 0.08;
    if (hoverSlug) return 0.09;
    return 0.34;
  };

  const isVisible = (
    node: GraphNode,
    worldMinX: number,
    worldMaxX: number,
    worldMinY: number,
    worldMaxY: number,
  ): boolean =>
    node.renderX + node.radius >= worldMinX &&
    node.renderX - node.radius <= worldMaxX &&
    node.renderY + node.radius >= worldMinY &&
    node.renderY - node.radius <= worldMaxY;

  const renderGraph = (): void => {
    if (!active) return;
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    context.clearRect(0, 0, canvasWidth, canvasHeight);

    if (!currentGraph) return;
    const worldMinX = toWorldX(0) - 60;
    const worldMaxX = toWorldX(canvasWidth) + 60;
    const worldMinY = toWorldY(0) - 60;
    const worldMaxY = toWorldY(canvasHeight) + 60;

    context.setTransform(dpr * zoom, 0, 0, dpr * zoom, dpr * panX, dpr * panY);

    const directRuntimeColor = getCssColor('--graph-direct-runtime');
    const directDevColor = getCssColor('--graph-direct-dev');
    const transitiveColor = getCssColor('--graph-transitive');
    const edgeColor = getCssColor('--graph-edge');
    const highlightColor = getCssColor('--graph-highlight');

    const visibleNodes = new Set<string>();
    currentGraph.nodes.forEach((node, slug) => {
      if (isVisible(node, worldMinX, worldMaxX, worldMinY, worldMaxY)) {
        visibleNodes.add(slug);
      }
    });

    currentGraph.edges.forEach((edge) => {
      const from = currentGraph.nodes.get(edge.from);
      const to = currentGraph.nodes.get(edge.to);
      if (!from || !to) return;
      if (!visibleNodes.has(from.slug) && !visibleNodes.has(to.slug)) return;
      const key = edgeKey(edge.from, edge.to);
      const highlighted =
        focusEdges.has(key) || (!lockedFocus && hoverEdges.has(key));
      context.globalAlpha = getEdgeOpacity(key, highlighted);
      context.strokeStyle = highlighted ? highlightColor : edgeColor;
      context.lineWidth = edge.direct ? 2.25 : 1.25;
      if (highlighted) context.lineWidth += 0.8;

      const controlX = from.renderX + (to.renderX - from.renderX) * 0.52;
      const controlY = from.renderY + (to.renderY - from.renderY) * 0.18;
      context.beginPath();
      context.moveTo(from.renderX, from.renderY);
      context.quadraticCurveTo(controlX, controlY, to.renderX, to.renderY);
      context.stroke();
    });

    currentGraph.nodes.forEach((node) => {
      if (!visibleNodes.has(node.slug)) return;
      const opacity = getNodeOpacity(node.slug);
      context.globalAlpha = opacity;
      if (node.kind === 'direct-runtime') context.fillStyle = directRuntimeColor;
      else if (node.kind === 'direct-dev') context.fillStyle = directDevColor;
      else context.fillStyle = transitiveColor;

      context.beginPath();
      context.arc(node.renderX, node.renderY, node.radius, 0, Math.PI * 2);
      context.fill();

      const selected = focusSlug === node.slug;
      if (selected) {
        context.globalAlpha = 1;
        context.strokeStyle = highlightColor;
        context.lineWidth = 2.4;
        context.beginPath();
        context.arc(node.renderX, node.renderY, node.radius + 3, 0, Math.PI * 2);
        context.stroke();
      }
    });

    if (zoom > 0.62) {
      context.textBaseline = 'middle';
      context.font = '11px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
      currentGraph.nodes.forEach((node) => {
        if (!visibleNodes.has(node.slug)) return;
        context.globalAlpha = getNodeOpacity(node.slug);
        context.fillStyle = getCssColor('--text-primary');
        const label = node.ref.name;
        context.fillText(label, node.renderX + node.radius + 6, node.renderY);
      });
    }

    context.globalAlpha = 1;
  };

  const frame = (): void => {
    rafId = 0;
    const animating = updateNodePositions();
    if (needsRender || animating) {
      renderGraph();
      needsRender = false;
    }
    if ((active && currentGraph) || animating) {
      requestRender();
    }
  };

  const requestRender = (): void => {
    if (rafId !== 0) return;
    rafId = window.requestAnimationFrame(frame);
  };

  const resetFocus = (): void => {
    focusSlug = null;
    lockedFocus = false;
    focusAncestors = new Set<string>();
    focusDescendants = new Set<string>();
    focusNodes = new Set<string>();
    focusEdges = new Set<string>();
    pushNodes = new Set<string>();
    needsRender = true;
    requestRender();
  };

  const applyFocus = (slug: string): void => {
    if (!currentGraph || !currentGraph.nodes.has(slug)) return;
    focusSlug = slug;
    lockedFocus = true;
    focusAncestors = collectAncestors(currentGraph, slug);
    focusDescendants = collectDescendants(currentGraph, slug);
    focusNodes = new Set<string>([slug]);
    focusAncestors.forEach((nodeSlug) => focusNodes.add(nodeSlug));
    focusDescendants.forEach((nodeSlug) => focusNodes.add(nodeSlug));
    pushNodes = new Set<string>(focusNodes);
    const selected = currentGraph.nodes.get(slug);
    if (selected) {
      selected.parents.forEach((nodeSlug) => pushNodes.add(nodeSlug));
      selected.children.forEach((nodeSlug) => pushNodes.add(nodeSlug));
    }
    updateFocusEdgeSet();
    needsRender = true;
    requestRender();
  };

  const layoutGraph = (graph: WorkspaceGraph): void => {
    const maxLayerSize = graph.layers.reduce(
      (max, layer) => Math.max(max, layer.length),
      1,
    );

    const depthOrder = [...graph.layers.keys()];
    const layerOrderIndex = new Map<string, number>();
    depthOrder.forEach((depth) => {
      const layer = graph.layers[depth];
      if (!layer || layer.length === 0) return;
      if (depth === 0) {
        layer.sort((a, b) => {
          const aRuntime = graph.directRuntime.has(a);
          const bRuntime = graph.directRuntime.has(b);
          if (aRuntime !== bRuntime) return aRuntime ? -1 : 1;
          const aDev = graph.directDev.has(a);
          const bDev = graph.directDev.has(b);
          if (aDev !== bDev) return aDev ? -1 : 1;
          return graph.nodes.get(a)!.ref.name.localeCompare(graph.nodes.get(b)!.ref.name);
        });
      } else {
        layer.sort((a, b) => {
          const nodeA = graph.nodes.get(a);
          const nodeB = graph.nodes.get(b);
          if (!nodeA || !nodeB) return 0;
          const centerA = (() => {
            let count = 0;
            let sum = 0;
            nodeA.parents.forEach((parent) => {
              const pos = layerOrderIndex.get(parent);
              if (typeof pos !== 'number') return;
              sum += pos;
              count += 1;
            });
            return count > 0 ? sum / count : Number.MAX_SAFE_INTEGER;
          })();
          const centerB = (() => {
            let count = 0;
            let sum = 0;
            nodeB.parents.forEach((parent) => {
              const pos = layerOrderIndex.get(parent);
              if (typeof pos !== 'number') return;
              sum += pos;
              count += 1;
            });
            return count > 0 ? sum / count : Number.MAX_SAFE_INTEGER;
          })();
          if (centerA !== centerB) return centerA - centerB;
          return nodeA.ref.name.localeCompare(nodeB.ref.name);
        });
      }

      layer.forEach((slug, index) => {
        layerOrderIndex.set(slug, index);
      });
    });

    graph.bounds = {
      minX: Number.POSITIVE_INFINITY,
      maxX: Number.NEGATIVE_INFINITY,
      minY: Number.POSITIVE_INFINITY,
      maxY: Number.NEGATIVE_INFINITY,
    };

    graph.layers.forEach((layer, depth) => {
      const columnHeight = (layer.length - 1) * GRAPH_ROW_GAP;
      const centeredTop =
        GRAPH_PADDING_Y + (maxLayerSize * GRAPH_ROW_GAP - columnHeight) * 0.5;
      layer.forEach((slug, order) => {
        const node = graph.nodes.get(slug);
        if (!node) return;
        node.order = order;
        node.baseX = GRAPH_PADDING_X + depth * GRAPH_LAYER_GAP;
        node.baseY = centeredTop + order * GRAPH_ROW_GAP;
        if (!Number.isFinite(node.renderX)) {
          node.renderX = node.baseX;
          node.renderY = node.baseY;
        }
        node.radius =
          GRAPH_NODE_BASE_RADIUS +
          Math.log(node.parents.size + 1) * GRAPH_NODE_RADIUS_SCALE;
        graph.bounds.minX = Math.min(graph.bounds.minX, node.baseX - node.radius);
        graph.bounds.maxX = Math.max(graph.bounds.maxX, node.baseX + node.radius);
        graph.bounds.minY = Math.min(graph.bounds.minY, node.baseY - node.radius);
        graph.bounds.maxY = Math.max(graph.bounds.maxY, node.baseY + node.radius);
      });
    });

    if (!Number.isFinite(graph.bounds.minX)) {
      graph.bounds = { minX: 0, maxX: 1, minY: 0, maxY: 1 };
    }
  };

  const buildWorkspaceGraph = (workspaceName: string): WorkspaceGraph | null => {
    const workspace = workspaceByName.get(workspaceName);
    if (!workspace) return null;
    const directRuntime = new Set(
      workspace.directDependencies.filter((slug) => Boolean(dataset.dependencies[slug])),
    );
    const directDev = new Set(
      workspace.directDevDependencies.filter((slug) => Boolean(dataset.dependencies[slug])),
    );
    const roots = new Set<string>([...directRuntime, ...directDev]);
    if (roots.size === 0) {
      Object.keys(dataset.dependencies)
        .filter((slug) => (parentsBySlug.get(slug) || []).length === 0)
        .slice(0, 24)
        .forEach((slug) => roots.add(slug));
    }

    const included = new Set<string>();
    const queue = [...roots];
    while (queue.length > 0) {
      const current = queue.shift();
      if (!current) continue;
      if (included.has(current)) continue;
      if (!dataset.dependencies[current]) continue;
      included.add(current);
      const children = childrenBySlug.get(current) || [];
      children.forEach((child) => {
        if (included.has(child)) return;
        queue.push(child);
      });
    }

    if (included.size === 0) return null;

    const nodes = new Map<string, GraphNode>();
    included.forEach((slug) => {
      const dependency = dataset.dependencies[slug];
      const kind: GraphNodeKind = directRuntime.has(slug)
        ? 'direct-runtime'
        : directDev.has(slug)
          ? 'direct-dev'
          : 'transitive';
      nodes.set(slug, {
        slug,
        ref: dependency,
        parents: new Set<string>(),
        children: new Set<string>(),
        depth: Number.POSITIVE_INFINITY,
        order: 0,
        baseX: Number.NaN,
        baseY: Number.NaN,
        renderX: Number.NaN,
        renderY: Number.NaN,
        radius: GRAPH_NODE_BASE_RADIUS,
        kind,
      });
    });

    nodes.forEach((node) => {
      const parents = parentsBySlug.get(node.slug) || [];
      const children = childrenBySlug.get(node.slug) || [];
      parents.forEach((parent) => {
        if (!nodes.has(parent)) return;
        node.parents.add(parent);
      });
      children.forEach((child) => {
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
      node.children.forEach((child) => {
        const childNode = nodes.get(child);
        if (!childNode) return;
        const nextDepth = node.depth + 1;
        if (nextDepth >= childNode.depth) return;
        childNode.depth = nextDepth;
        depthQueue.push(child);
      });
    }

    nodes.forEach((node) => {
      if (Number.isFinite(node.depth)) return;
      let minDepth = Number.POSITIVE_INFINITY;
      node.parents.forEach((parent) => {
        const parentNode = nodes.get(parent);
        if (!parentNode || !Number.isFinite(parentNode.depth)) return;
        minDepth = Math.min(minDepth, parentNode.depth + 1);
      });
      node.depth = Number.isFinite(minDepth) ? minDepth : 0;
    });

    const maxDepth = [...nodes.values()].reduce(
      (max, node) => Math.max(max, node.depth),
      0,
    );
    const layers = Array.from({ length: maxDepth + 1 }, () => [] as string[]);
    nodes.forEach((node) => {
      if (!layers[node.depth]) layers[node.depth] = [];
      layers[node.depth].push(node.slug);
    });

    const edges: GraphEdge[] = [];
    nodes.forEach((node) => {
      node.children.forEach((child) => {
        edges.push({
          from: node.slug,
          to: child,
          direct: node.depth === 0,
        });
      });
    });

    const graph: WorkspaceGraph = {
      workspaceName,
      nodes,
      layers,
      edges,
      directRuntime,
      directDev,
      bounds: {
        minX: 0,
        maxX: 1,
        minY: 0,
        maxY: 1,
      },
    };
    layoutGraph(graph);
    return graph;
  };

  const switchWorkspace = (workspaceName: string): void => {
    const built = buildWorkspaceGraph(workspaceName);
    if (!built) return;
    currentWorkspaceName = workspaceName;
    currentGraph = built;
    resetFocus();
    updateHoverState(null);
    fitGraphToViewport();
    needsRender = true;
    requestRender();
  };

  const handlePointerDown = (event: MouseEvent): void => {
    if (event.button !== 0) return;
    panState.pointerDown = true;
    panState.moved = false;
    panState.startClientX = event.clientX;
    panState.startClientY = event.clientY;
    panState.startPanX = panX;
    panState.startPanY = panY;
    options.canvas.classList.add('is-panning');
  };

  const handlePointerMove = (event: MouseEvent): void => {
    if (!panState.pointerDown) {
      const node = findNodeAt(event.clientX, event.clientY);
      updateHoverState(node ? node.slug : null);
      return;
    }
    const dx = event.clientX - panState.startClientX;
    const dy = event.clientY - panState.startClientY;
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) {
      panState.moved = true;
    }
    panX = panState.startPanX + dx;
    panY = panState.startPanY + dy;
    needsRender = true;
    requestRender();
  };

  const handlePointerUp = (event: MouseEvent): void => {
    if (!panState.pointerDown) return;
    options.canvas.classList.remove('is-panning');
    const wasMoved = panState.moved;
    panState.pointerDown = false;
    panState.moved = false;
    if (wasMoved) return;
    const node = findNodeAt(event.clientX, event.clientY);
    if (!node) {
      resetFocus();
      return;
    }
    applyFocus(node.slug);
  };

  const handleWheel = (event: WheelEvent): void => {
    event.preventDefault();
    const rect = options.canvas.getBoundingClientRect();
    const localX = event.clientX - rect.left;
    const localY = event.clientY - rect.top;
    const worldX = toWorldX(localX);
    const worldY = toWorldY(localY);
    const factor = Math.exp(-event.deltaY * 0.0012);
    const nextZoom = clamp(zoom * factor, GRAPH_MIN_ZOOM, GRAPH_MAX_ZOOM);
    zoom = nextZoom;
    panX = localX - worldX * zoom;
    panY = localY - worldY * zoom;
    needsRender = true;
    requestRender();
  };

  const handleDoubleClick = (event: MouseEvent): void => {
    const node = findNodeAt(event.clientX, event.clientY);
    if (!node) return;
    event.preventDefault();
    options.onOpenList(node.slug);
  };

  const setActive = (next: boolean): void => {
    active = next;
    if (!active) return;
    needsRender = true;
    requestRender();
  };

  const initGraphViewInternal = (): void => {
    options.workspaceSelect.innerHTML = dataset.workspaces
      .map(
        (workspace) =>
          `<option value="${workspace.name.replace(/"/g, '&quot;')}">${workspace.name}</option>`,
      )
      .join('');

    if (!dataset.workspaces.length) {
      options.workspaceSelect.innerHTML =
        '<option value="root">root</option>';
      workspaceByName.set('root', {
        name: 'root',
        directDependencies: [],
        directDevDependencies: [],
      });
    }

    const initialWorkspace =
      dataset.workspaces[0]?.name ||
      options.workspaceSelect.value ||
      'root';
    options.workspaceSelect.value = initialWorkspace;

    options.workspaceSelect.addEventListener('change', () => {
      switchWorkspace(options.workspaceSelect.value);
    });

    options.canvas.addEventListener('mousedown', handlePointerDown);
    window.addEventListener('mousemove', handlePointerMove);
    window.addEventListener('mouseup', handlePointerUp);
    options.canvas.addEventListener('wheel', handleWheel, { passive: false });
    options.canvas.addEventListener('dblclick', handleDoubleClick);
    options.canvas.addEventListener('mouseleave', () => updateHoverState(null));

    const themeObserver = new MutationObserver(() => {
      needsRender = true;
      requestRender();
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class', 'data-theme'],
    });

    if (typeof ResizeObserver !== 'undefined') {
      const observer = new ResizeObserver(() => {
        updateCanvasSize();
      });
      observer.observe(options.canvasHost);
    } else {
      window.addEventListener('resize', updateCanvasSize);
    }

    updateCanvasSize();
    switchWorkspace(initialWorkspace);
  };

  return {
    initGraphView: initGraphViewInternal,
    buildWorkspaceGraph,
    layoutGraph,
    renderGraph,
    applyFocus,
    resetFocus,
    switchWorkspace,
    setActive,
    requestRender: () => {
      needsRender = true;
      requestRender();
    },
  };
}
