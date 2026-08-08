import type { AggregatedData, DependencyRecord } from "./types";

export type GraphWorkspace = {
  name: string;
  directDependencies: string[];
  directDevDependencies: string[];
};

export type GraphDependency = {
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

export type GraphDataset = {
  workspaces: GraphWorkspace[];
  dependencies: Record<string, GraphDependency>;
};

type GraphNodeKind = "direct-runtime" | "direct-dev" | "transitive";

type GraphNode = {
  slug: string;
  ref: GraphDependency;
  labelGraphemes: string[];
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
  targetRadius: number;
  renderRadius: number;
  targetLabelChars: number;
  renderLabelChars: number;
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
  // Fired whenever the selected node changes (null on deselect), so the
  // docked side panel can render its dossier for the classic graph view too.
  onSelect?: (slug: string | null) => void;
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

type TouchState = {
  active: boolean;
  startX1: number;
  startY1: number;
  startX2: number;
  startY2: number;
  startPanX: number;
  startPanY: number;
  startDist: number;
  startZoom: number;
  anchorX: number | null;
  anchorY: number | null;
};

type InertiaState = {
  active: boolean;
  velocityX: number;
  velocityY: number;
  lastSampleX: number;
  lastSampleY: number;
  lastSampleTime: number;
  lastFrameTime: number;
};

type ThemeColors = {
  runtime: string;
  runtimeHighlight: string;
  dev: string;
  devHighlight: string;
  transitive: string;
  transitiveHighlight: string;
  edge: string;
  highlight: string;
  muted: string;
  ringHigh: string;
  ringModerate: string;
  label: string;
  backgroundPrimary: string;
};

type GraphPoint = {
  x: number;
  y: number;
};

type DepthNodeIndex = Map<number, GraphNode[]>;

type EdgeRoutingConfig = {
  depthNodeIndex: DepthNodeIndex;
  maxDepth: number;
  sameColumnXThreshold: number;
  minDetourVerticalSpan: number;
  detourInset: number;
  detourNodeClearance: number;
  paddingX: number;
  layerGap: number;
  edgeCurve: number;
};

type FocusLayoutPoint = {
  x: number;
  y: number;
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
const MIN_ZOOM_FIT_RATIO = 0.64;
const EDGE_CURVE = 0.2;
const INERTIA_START_SPEED = 0.08;
const INERTIA_STOP_SPEED = 0.02;
const INERTIA_FRICTION = 0.0042;
const INERTIA_MAX_FRAME_MS = 32;
const INERTIA_SMOOTHING = 0.22;
const LABEL_MAX_CHARS = 34;
const LABEL_ANIMATION_EASING = 0.32;
const GRAPH_LABEL_GAP = 6;
const GRAPH_LABEL_FONT =
  '500 11.5px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
const PAN_BOUNDS_X_PADDING = 120;
const PAN_BOUNDS_Y_PADDING = 90;
const FOCUS_LAYER_GAP = 170;
const FOCUS_ROW_GAP = 54;
const FOCUS_MIN_ROW_GAP = 34;
const FOCUS_MAX_COLUMN_SPREAD = 760;
const VIEWPORT_ANIMATION_EASING = 0.12;
const FOCUS_LAYOUT_EASING = 0.18;

/**
 * Constrains a number to lie within the inclusive range [min, max].
 *
 * @param value - The number to clamp
 * @param min - Lower bound (inclusive)
 * @param max - Upper bound (inclusive)
 * @returns The input constrained to be no less than `min` and no greater than `max`
 */
function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/**
 * Determine how many label graphemes should be rendered for a node.
 *
 * @param labelGraphemes - The node label split into grapheme clusters.
 * @param expanded - If true, allow the full label length; otherwise apply the configured maximum.
 * @returns The target number of graphemes to render: the full count when expanded, or at most `LABEL_MAX_CHARS` otherwise.
 */
function targetGraphLabelChars(
  labelGraphemes: string[],
  expanded = false,
): number {
  return expanded
    ? labelGraphemes.length
    : Math.min(labelGraphemes.length, LABEL_MAX_CHARS);
}

/**
 * Compute the initial number of characters to display for a node label.
 *
 * @param labelGraphemes - The label split into grapheme strings (one entry per visible character)
 * @returns The initial count of characters to render from the label, at least 1
 */
function initialGraphLabelChars(labelGraphemes: string[]): number {
  const target = targetGraphLabelChars(labelGraphemes);
  if (labelGraphemes.length <= LABEL_MAX_CHARS) return target;
  return Math.max(1, target - 6);
}

/**
 * Produce the display label for a graph node, truncating with an ellipsis when it exceeds the maximum allowed characters.
 *
 * @param node - The graph node whose label should be formatted
 * @returns The node's full name if it fits within limits; otherwise a truncated label ending with an ellipsis
 */
function formatGraphLabel(node: GraphNode): string {
  const { labelGraphemes } = node;
  if (labelGraphemes.length <= LABEL_MAX_CHARS) {
    return node.ref.name;
  }

  const visibleChars = clamp(Math.round(node.renderLabelChars), 1, labelGraphemes.length);
  if (visibleChars >= labelGraphemes.length) {
    return node.ref.name;
  }
  return `${labelGraphemes.slice(0, visibleChars - 1).join("")}…`;
}

/**
 * Parse a CSS color string and return its RGB components.
 *
 * @param value - A CSS color in `#RGB`, `#RRGGBB`, `rgb(...)`, or `rgba(...)` form. RGB channels may be numeric (0–255) or percentages (e.g., `50%`). `rgba` alpha is ignored; space-or-comma separators and the `/` alpha separator are supported.
 * @returns The parsed `{ r, g, b }` values (each 0–255) if the input is valid, or `null` if parsing fails.
 */
function parseCssColor(
  value: string,
): { r: number; g: number; b: number } | null {
  const normalized = value.trim();
  const hexMatch = normalized.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (hexMatch) {
    const hex = hexMatch[1];
    if (hex.length === 3) {
      return {
        r: parseInt(hex[0] + hex[0], 16),
        g: parseInt(hex[1] + hex[1], 16),
        b: parseInt(hex[2] + hex[2], 16),
      };
    }
    return {
      r: parseInt(hex.slice(0, 2), 16),
      g: parseInt(hex.slice(2, 4), 16),
      b: parseInt(hex.slice(4, 6), 16),
    };
  }

  const rgbMatch = normalized.match(/^rgba?\(([^)]+)\)$/i);
  if (!rgbMatch) return null;
  const channels = rgbMatch[1]
    .replace(/\//g, " ")
    .split(/[\s,]+/)
    .filter(Boolean)
    .slice(0, 3);
  if (channels.length !== 3) return null;

  const parseChannel = (channel: string): number | null => {
    if (channel.endsWith("%")) {
      const pct = Number(channel.slice(0, -1));
      if (!Number.isFinite(pct)) return null;
      return clamp(Math.round((pct / 100) * 255), 0, 255);
    }
    const value = Number(channel);
    if (!Number.isFinite(value)) return null;
    return clamp(Math.round(value), 0, 255);
  };

  const r = parseChannel(channels[0]);
  const g = parseChannel(channels[1]);
  const b = parseChannel(channels[2]);
  if (r === null || g === null || b === null) return null;
  return { r, g, b };
}

function tintColor(color: string, amount: number, fallback: string): string {
  const rgb = parseCssColor(color);
  if (!rgb) return fallback;
  const t = clamp(amount, 0, 1);
  const r = Math.round(rgb.r + (255 - rgb.r) * t);
  const g = Math.round(rgb.g + (255 - rgb.g) * t);
  const b = Math.round(rgb.b + (255 - rgb.b) * t);
  return `rgb(${r}, ${g}, ${b})`;
}

function getCssColor(name: string): string {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
}

function drawSmoothedPolyline(
  context: CanvasRenderingContext2D,
  points: GraphPoint[],
  cornerRadius: number,
): void {
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
}

function buildDepthNodeIndex(graph: WorkspaceGraph): DepthNodeIndex {
  const index: DepthNodeIndex = new Map();
  graph.nodes.forEach((node) => {
    const bucket = index.get(node.depth);
    if (bucket) bucket.push(node);
    else index.set(node.depth, [node]);
  });
  index.forEach((bucket) => {
    bucket.sort((a, b) => a.renderY - b.renderY);
  });
  return index;
}

function lowerBoundByRenderY(nodes: GraphNode[], minY: number): number {
  let low = 0;
  let high = nodes.length;
  while (low < high) {
    const mid = low + ((high - low) >> 1);
    if (nodes[mid].renderY < minY) low = mid + 1;
    else high = mid;
  }
  return low;
}

function isDetourCrowded(
  config: EdgeRoutingConfig,
  depth: number,
  minY: number,
  maxY: number,
  detourX: number,
): boolean {
  const nodesAtDepth = config.depthNodeIndex.get(depth);
  if (!nodesAtDepth || nodesAtDepth.length === 0) return false;
  const startIndex = lowerBoundByRenderY(nodesAtDepth, minY);
  for (
    let i = startIndex;
    i < nodesAtDepth.length && nodesAtDepth[i].renderY <= maxY;
    i += 1
  ) {
    if (Math.abs(nodesAtDepth[i].renderX - detourX) < config.detourNodeClearance) {
      return true;
    }
  }
  return false;
}

/**
 * Appends a routed connection path between two graph nodes to the provided canvas context.
 *
 * The routing adapts to the nodes' depths and positions using the supplied routing
 * configuration: same-depth edges may detour through an intermediate corridor or use
 * a quadratic curve, single-layer spans use a cubic bezier through a corridor center,
 * and multi-layer spans are routed as a smoothed polyline through intermediate corridors.
 *
 * @param context - Canvas 2D rendering context to which the path is added
 * @param from - Source graph node; its `renderX`/`renderY` and `depth` determine the start point
 * @param to - Target graph node; its `renderX`/`renderY` and `depth` determine the end point
 * @param config - Edge routing parameters (layer gaps, paddings, detour thresholds, curve factors) that control corridor positions, detour insets, and corner radii
 */
function drawRoutedEdge(
  context: CanvasRenderingContext2D,
  from: GraphNode,
  to: GraphNode,
  config: EdgeRoutingConfig,
): void {
  const sourceX = from.renderX;
  const sourceY = from.renderY;
  const targetX = to.renderX;
  const targetY = to.renderY;
  const depthDelta = to.depth - from.depth;
  const span = Math.abs(depthDelta);

  if (span === 0) {
    const sameColumn = Math.abs(sourceX - targetX) < config.sameColumnXThreshold;
    const verticalSpan = Math.abs(sourceY - targetY);
    const hasRightCorridor = from.depth < config.maxDepth;

    if (sameColumn && verticalSpan > config.minDetourVerticalSpan && hasRightCorridor) {
      const currentColumnX = config.paddingX + from.depth * config.layerGap;
      const nextColumnX = config.paddingX + (from.depth + 1) * config.layerGap;
      const corridorCenterX = (currentColumnX + nextColumnX) * 0.5;
      let detourX = corridorCenterX + config.detourInset;

      const minY = Math.min(sourceY, targetY) - 12;
      const maxY = Math.max(sourceY, targetY) + 12;
      if (isDetourCrowded(config, from.depth + 1, minY, maxY, detourX)) {
        detourX += 12;
      }

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
        context,
        [
          { x: sourceX, y: sourceY },
          { x: detourX, y: sourceY },
          { x: detourX, y: targetY },
          { x: targetX, y: targetY },
        ],
        cornerRadius,
      );
      return;
    }

    context.moveTo(sourceX, sourceY);
    const cx = sourceX + (targetX - sourceX) * 0.5;
    const cy = sourceY + (targetY - sourceY) * config.edgeCurve;
    context.quadraticCurveTo(cx, cy, targetX, targetY);
    return;
  }

  if (span === 1) {
    const leftDepth = Math.min(from.depth, to.depth);
    const corridorCenterX =
      config.paddingX + leftDepth * config.layerGap + config.layerGap * 0.5;
    context.moveTo(sourceX, sourceY);
    context.bezierCurveTo(
      corridorCenterX,
      sourceY,
      corridorCenterX,
      targetY,
      targetX,
      targetY,
    );
    return;
  }

  const direction = Math.sign(depthDelta);
  const yDelta = targetY - sourceY;
  const points: GraphPoint[] = [{ x: sourceX, y: sourceY }];

  const firstCorridorX =
    config.paddingX + from.depth * config.layerGap + direction * (config.layerGap * 0.5);
  points.push({ x: firstCorridorX, y: sourceY });

  for (let step = 1; step < span; step += 1) {
    const depth = from.depth + direction * step;
    const corridorX =
      config.paddingX + depth * config.layerGap + direction * (config.layerGap * 0.5);
    const t = step / span;
    points.push({ x: corridorX, y: sourceY + yDelta * t });
  }

  const preTargetCorridorX =
    config.paddingX + to.depth * config.layerGap - direction * (config.layerGap * 0.5);
  points.push({ x: preTargetCorridorX, y: targetY });
  points.push({ x: targetX, y: targetY });

  drawSmoothedPolyline(context, points, 14);
}

/**
 * Draws a highlighted edge path between two graph nodes onto the canvas context.
 *
 * The path is a smooth bezier curve that visually emphasizes the edge when a node is focused;
 * for nearly-vertical alignments the curve detours to one side to maintain clear separation.
 *
 * @param context - Canvas 2D rendering context to draw into
 * @param from - Source node whose rendered coordinates define the path start
 * @param to - Target node whose rendered coordinates define the path end
 */
function drawFocusedEdge(
  context: CanvasRenderingContext2D,
  from: GraphNode,
  to: GraphNode,
): void {
  const sourceX = from.renderX;
  const sourceY = from.renderY;
  const targetX = to.renderX;
  const targetY = to.renderY;
  const dx = targetX - sourceX;
  const dy = targetY - sourceY;

  context.moveTo(sourceX, sourceY);
  if (Math.abs(dx) < 18) {
    const side = sourceX + (sourceY <= targetY ? 26 : -26);
    context.bezierCurveTo(side, sourceY, side, targetY, targetX, targetY);
    return;
  }

  const curve = clamp(Math.abs(dx) * 0.44, 42, 150);
  const direction = Math.sign(dx);
  const verticalBias = clamp(Math.abs(dy) * 0.12, 0, 24);
  context.bezierCurveTo(
    sourceX + direction * curve,
    sourceY + verticalBias * Math.sign(dy),
    targetX - direction * curve,
    targetY - verticalBias * Math.sign(dy),
    targetX,
    targetY,
  );
}

/**
 * Selects and draws the appropriate path for a graph edge based on focus state and routing config.
 *
 * @param context - The 2D canvas rendering context to draw into.
 * @param edge - Object containing `from` and `to` nodes and a `highlighted` flag; when `highlighted` is true and `focused` is true the edge is drawn using the focused routing style.
 * @param config - Edge routing configuration used for non-focused (standard routed) drawing.
 * @param focused - Whether the graph is currently in a focused state that enables focused-edge rendering.
 */
function drawGraphEdge(
  context: CanvasRenderingContext2D,
  edge: { from: GraphNode; to: GraphNode; highlighted: boolean },
  config: EdgeRoutingConfig,
  focused: boolean,
): void {
  if (focused && edge.highlighted) {
    drawFocusedEdge(context, edge.from, edge.to);
    return;
  }
  drawRoutedEdge(context, edge.from, edge.to, config);
}

/**
 * Create a normalized dependency key from a package name and version.
 *
 * @param name - The package name (e.g., `"lodash"`)
 * @param version - The package version (e.g., `"4.17.21"`)
 * @returns A dependency key in the form `name@version`
 */
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

  const isWorkspace = (workspace: unknown): workspace is GraphWorkspace => {
    if (!workspace || typeof workspace !== "object") return false;
    const candidate = workspace as Record<string, unknown>;
    if (typeof candidate.name !== "string") return false;
    if (!Array.isArray(candidate.directDependencies)) return false;
    if (!Array.isArray(candidate.directDevDependencies)) return false;
    return true;
  };

  const hasValidStringArray = (value: unknown): boolean =>
    Array.isArray(value) && value.every((item) => typeof item === "string");

  if (!input.workspaces.every((workspace) => isWorkspace(workspace))) {
    return false;
  }

  if (
    !input.workspaces.every(
      (workspace) =>
        hasValidStringArray(workspace.directDependencies) &&
        hasValidStringArray(workspace.directDevDependencies),
    )
  ) {
    return false;
  }

  const dependencyEntries = Object.entries(
    input.dependencies as Record<string, unknown>,
  );
  if (
    !dependencyEntries.every(([, dependencyValue]) => {
      if (!dependencyValue || typeof dependencyValue !== "object") return false;
      const dependency = dependencyValue as Record<string, unknown>;
      if (
        dependency.dependencies !== undefined &&
        !Array.isArray(dependency.dependencies)
      ) {
        return false;
      }
      if (
        dependency.workspaceOrigins !== undefined &&
        !Array.isArray(dependency.workspaceOrigins)
      ) {
        return false;
      }
      return true;
    })
  ) {
    return false;
  }

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

/**
 * Collects all descendant node slugs reachable from a given node within a workspace graph.
 *
 * Performs a depth-first traversal following `children` links and returns every visited slug
 * except the starting `slug`.
 *
 * @param graph - The workspace graph to traverse
 * @param slug - The starting node slug whose descendants will be collected
 * @returns A set of descendant slugs reachable from `slug`, excluding `slug` itself
 */
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

/**
 * Compute the shortest directed distance (in edge count) from a starting node to reachable nodes following either parent or child links.
 *
 * @param graph - The workspace graph to traverse
 * @param slug - The starting node slug
 * @param direction - Which adjacency set to follow: `"parents"` walks toward ancestors, `"children"` walks toward descendants
 * @returns A map from each reachable node slug to its distance (number of edges) from the starting slug; the starting slug itself is not included
 */
function collectDirectedDistances(
  graph: WorkspaceGraph,
  slug: string,
  direction: "parents" | "children",
): Map<string, number> {
  const distances = new Map<string, number>();
  const queue: Array<{ slug: string; distance: number }> = [
    { slug, distance: 0 },
  ];
  let index = 0;
  while (index < queue.length) {
    const current = queue[index++];
    const node = graph.nodes.get(current.slug);
    if (!node) continue;
    node[direction].forEach((nextSlug) => {
      if (distances.has(nextSlug)) return;
      distances.set(nextSlug, current.distance + 1);
      queue.push({ slug: nextSlug, distance: current.distance + 1 });
    });
  }
  return distances;
}

/**
 * Converts aggregated dependency report data into a normalized GraphDataset suitable for the graph view.
 *
 * When a valid pre-normalized dataset exists at `window.__DEPENDENCY_DATA__`, that dataset is normalized and returned.
 * Otherwise the function constructs a dataset from `report`, resolving dependency keys, extracting licenses and
 * vulnerability summaries, enumerating each dependency's direct child slugs, and building workspace direct dependency sets
 * (including an implicit "root" workspace for packages without workspace origins).
 *
 * @param report - The aggregated dependency report to adapt when no pre-normalized dataset is present
 * @param knownDepKeys - A set of dependency keys that are considered valid/known; sub-dependencies not in this set are omitted
 * @param resolveDepKey - A callback that maps a raw dependency key from the report to a normalized dependency key, or returns `null` if it cannot be resolved
 * @returns A GraphDataset containing `workspaces` and a `dependencies` map with normalized GraphDependency records
 */
export function adaptDataset(
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
      const normalizedSeverity = String(rawSeverity).trim().toLowerCase();
      let vulnerabilitySeverity: "high" | "moderate" | "none" = "none";
      if (normalizedSeverity === "critical" || normalizedSeverity === "high") {
        vulnerabilitySeverity = "high";
      } else if (
        normalizedSeverity === "moderate" ||
        normalizedSeverity === "medium"
      ) {
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

/**
 * Create and wire up an interactive dependency graph view bound to the provided canvas, controls, and dataset.
 *
 * Initializes internal dataset adaptation, event handlers, rendering loop, and UI bindings and returns a handle
 * that allows programmatic control of the view and its lifecycle.
 *
 * @param options - Configuration and DOM element references required to render and control the graph view (canvas, host, controls, popover elements, dataset/report and related callbacks).
 * @returns A GraphViewHandle exposing methods to initialize and control the view (for example: `initGraphView`, `buildWorkspaceGraph`, `computeAmplification`, `layoutGraph`, `renderLoop`, `applyFocus`, `clearFocus`, `showPopover`, `hidePopover`, `switchWorkspace`, `setActive`, `requestRender`).
 */
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
  let focusLayoutTargets = new Map<string, FocusLayoutPoint>();
  let focusCenterX: number | null = null;
  let focusCenterY: number | null = null;
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
  let targetPanX: number | null = null;
  let targetPanY: number | null = null;

  let active = false;
  let dirty = true;
  let frameId = 0;

  let dpr = Math.max(1, Math.floor(window.devicePixelRatio || 1));
  let width = 1;
  let height = 1;
  let toolbarHeight = 50;

  const panState = {
    down: false,
    moved: false,
    startX: 0,
    startY: 0,
    startPanX: 0,
    startPanY: 0,
  };

  const touchState: TouchState = {
    active: false,
    startX1: 0,
    startY1: 0,
    startX2: 0,
    startY2: 0,
    startPanX: 0,
    startPanY: 0,
    startDist: 0,
    startZoom: 0,
    anchorX: null,
    anchorY: null,
  };

  const inertiaState: InertiaState = {
    active: false,
    velocityX: 0,
    velocityY: 0,
    lastSampleX: 0,
    lastSampleY: 0,
    lastSampleTime: 0,
    lastFrameTime: 0,
  };

  const context = options.canvas.getContext("2d");
  const hasCanvas = Boolean(context);
  let interactionsBound = false;
  let controlsBound = false;
  let workspaceSelectBound = false;
  let themeObserver: MutationObserver | null = null;
  let hostResizeObserver: ResizeObserver | null = null;
  let windowResizeHandler: (() => void) | null = null;
  let fallbackShown = false;
  const reducedMotionQuery =
    typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-reduced-motion: reduce)")
      : null;
  let themeColors: ThemeColors = {
    runtime: "#10b981",
    runtimeHighlight: "#34d399",
    dev: "#f59e0b",
    devHighlight: "#fcd34d",
    transitive: "#06b6d4",
    transitiveHighlight: "#67e8f9",
    edge: "#64748b",
    highlight: "#22d3ee",
    muted: "#64748b",
    ringHigh: "#ef4444",
    ringModerate: "#f59e0b",
    label: "#e8edf5",
    backgroundPrimary: "#0c1222",
  };

  function updateThemeColors(): void {
    const runtime = getCssColor("--graph-direct-runtime") || "#10b981";
    const dev = getCssColor("--graph-direct-dev") || "#f59e0b";
    const transitive = getCssColor("--graph-transitive") || "#06b6d4";

    themeColors = {
      runtime,
      runtimeHighlight: tintColor(runtime, 0.2, "#34d399"),
      dev,
      devHighlight: tintColor(dev, 0.28, "#fcd34d"),
      transitive,
      transitiveHighlight: tintColor(transitive, 0.38, "#67e8f9"),
      edge: getCssColor("--graph-edge") || "#64748b",
      highlight: getCssColor("--graph-highlight") || "#22d3ee",
      muted: getCssColor("--graph-muted") || "#64748b",
      ringHigh: getCssColor("--graph-vuln-high") || "#ef4444",
      ringModerate: getCssColor("--graph-vuln-medium") || "#f59e0b",
      label: getCssColor("--text-primary") || "#e8edf5",
      backgroundPrimary: getCssColor("--bg-primary") || "#0c1222",
    };
  }

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

  /**
   * Convert a Y coordinate from screen space into world space.
   *
   * @param screenY - The Y coordinate in screen pixels
   * @returns The Y coordinate in world space corresponding to `screenY`
   */
  function worldY(screenY: number): number {
    return (screenY - panY) / zoom;
  }

  /**
   * Constrains a proposed pan position so the visible graph stays within allowed bounds.
   *
   * @param nextPanX - Proposed horizontal pan offset in pixels.
   * @param nextPanY - Proposed vertical pan offset in pixels.
   * @returns An object with `x` and `y` pan offsets clamped so the graph remains visible; if the graph bounds are smaller than the viewport, returns a centered pan for that axis.
   */
  function clampPanToGraph(nextPanX: number, nextPanY: number): {
    x: number;
    y: number;
  } {
    if (!currentGraph) {
      return { x: nextPanX, y: nextPanY };
    }

    const paddedMinX = currentGraph.bounds.minX - PAN_BOUNDS_X_PADDING;
    const paddedMaxX = currentGraph.bounds.maxX + PAN_BOUNDS_X_PADDING;
    const paddedMinY = currentGraph.bounds.minY - PAN_BOUNDS_Y_PADDING;
    const paddedMaxY = currentGraph.bounds.maxY + PAN_BOUNDS_Y_PADDING;

    const minVisibleX = Math.min(width * 0.22, 220);
    const minVisibleY = Math.min(height * 0.22, 180);

    const minPanX = minVisibleX - paddedMaxX * zoom;
    const maxPanX = width - minVisibleX - paddedMinX * zoom;
    const minPanY = minVisibleY - paddedMaxY * zoom;
    const maxPanY = height - minVisibleY - paddedMinY * zoom;

    const x =
      minPanX > maxPanX
        ? (minPanX + maxPanX) * 0.5
        : clamp(nextPanX, minPanX, maxPanX);
    const y =
      minPanY > maxPanY
        ? (minPanY + maxPanY) * 0.5
        : clamp(nextPanY, minPanY, maxPanY);

    return { x, y };
  }

  /**
   * Update the current pan offset, constraining it to the graph's allowed bounds.
   *
   * @param nextPanX - Desired horizontal pan offset in world pixels
   * @param nextPanY - Desired vertical pan offset in world pixels
   */
  function setPan(nextPanX: number, nextPanY: number): void {
    const clamped = clampPanToGraph(nextPanX, nextPanY);
    panX = clamped.x;
    panY = clamped.y;
  }

  /**
   * Sets the animated viewport pan target, clamping the requested coordinates to the graph's allowable pan bounds.
   *
   * @param nextPanX - Desired pan X coordinate in world space
   * @param nextPanY - Desired pan Y coordinate in world space
   */
  function setViewportTarget(nextPanX: number, nextPanY: number): void {
    const clamped = clampPanToGraph(nextPanX, nextPanY);
    targetPanX = clamped.x;
    targetPanY = clamped.y;
  }

  /**
   * Clears any pending viewport pan target so the view stops animating toward a stored pan position.
   */
  function clearViewportTarget(): void {
    targetPanX = null;
    targetPanY = null;
  }

  /**
   * Animates the viewport pan toward the current pan target.
   *
   * If the user has requested reduced motion, the pan snaps directly to the target and the target is cleared. When the pan reaches within a small threshold of the target the function snaps to the final target, clears the target, and marks the view dirty.
   *
   * @returns `true` if the viewport is still animating toward a pan target, `false` if no target existed or animation has completed
   */
  function animateViewport(): boolean {
    if (targetPanX === null || targetPanY === null) return false;
    if (reducedMotionQuery?.matches) {
      setPan(targetPanX, targetPanY);
      clearViewportTarget();
      dirty = true;
      return false;
    }

    panX += (targetPanX - panX) * VIEWPORT_ANIMATION_EASING;
    panY += (targetPanY - panY) * VIEWPORT_ANIMATION_EASING;
    setPan(panX, panY);

    const settled =
      Math.abs((targetPanX ?? panX) - panX) < 0.35 &&
      Math.abs((targetPanY ?? panY) - panY) < 0.35;
    if (settled) {
      setPan(targetPanX, targetPanY);
      clearViewportTarget();
      dirty = true;
      return false;
    }

    dirty = true;
    return true;
  }

  /**
   * Set the view zoom level around a given screen anchor point and update pan accordingly.
   *
   * This stops any ongoing inertial pan, constrains `nextZoom` to the allowed range, updates the internal zoom,
   * recenters the view so the world point under (`anchorX`, `anchorY`) remains fixed, marks the view dirty,
   * and schedules a render.
   *
   * @param nextZoom - Desired zoom factor; will be clamped to the configured minimum and maximum zoom.
   * @param anchorX - X coordinate in client/canvas space to hold stationary during zoom.
   * @param anchorY - Y coordinate in client/canvas space to hold stationary during zoom.
   */
  function applyZoom(nextZoom: number, anchorX: number, anchorY: number): void {
    stopInertia();
    clearViewportTarget();
    const clamped = clamp(nextZoom, minZoom, MAX_ZOOM);
    const wx = worldX(anchorX);
    const wy = worldY(anchorY);
    zoom = clamped;
    setPan(anchorX - wx * zoom, anchorY - wy * zoom);
    dirty = true;
    requestRender();
  }

  /**
   * Shift the current view by the given horizontal and vertical offsets.
   *
   * Stops any ongoing inertial panning, applies the pan delta (in pixels), marks the view dirty, and requests a render.
   *
   * @param dx - Horizontal pan delta in pixels (positive moves content right)
   * @param dy - Vertical pan delta in pixels (positive moves content down)
   */
  function panBy(dx: number, dy: number): void {
    stopInertia();
    clearViewportTarget();
    setPan(panX + dx, panY + dy);
    dirty = true;
    requestRender();
  }

  /**
   * Determines whether inertial panning (throw) effects may be used given user motion preferences.
   *
   * @returns `true` if the user has not requested reduced motion and inertia can be used, `false` otherwise.
   */
  function isInertiaAllowed(): boolean {
    return !reducedMotionQuery?.matches;
  }

  /**
   * Deactivates any ongoing inertial panning and resets inertia velocity and timing state.
   */
  function stopInertia(): void {
    inertiaState.active = false;
    inertiaState.velocityX = 0;
    inertiaState.velocityY = 0;
    inertiaState.lastFrameTime = 0;
  }

  /**
   * Record the most recent pointer sample used to seed or reset inertial panning.
   *
   * @param clientX - Pointer client X coordinate in pixels.
   * @param clientY - Pointer client Y coordinate in pixels.
   * @param timestamp - Event timestamp in milliseconds (DOM event time origin).
   */
  function resetInertiaSample(
    clientX: number,
    clientY: number,
    timestamp: number,
  ): void {
    inertiaState.lastSampleX = clientX;
    inertiaState.lastSampleY = clientY;
    inertiaState.lastSampleTime = timestamp;
  }

  /**
   * Record a pan motion sample and update the inertial velocity estimate.
   *
   * Updates the global inertiaState velocity components using a smoothed sample
   * computed from the change in client coordinates since the last sample. If the
   * provided timestamp is not later than the last sample time, the sample is
   * reset and velocities are not updated.
   *
   * @param clientX - Pointer X coordinate in client (pixel) space
   * @param clientY - Pointer Y coordinate in client (pixel) space
   * @param timestamp - High-resolution timestamp for the sample (milliseconds)
   */
  function recordPanVelocity(
    clientX: number,
    clientY: number,
    timestamp: number,
  ): void {
    const dt = timestamp - inertiaState.lastSampleTime;
    if (dt <= 0) {
      resetInertiaSample(clientX, clientY, timestamp);
      return;
    }

    const sampleVX = (clientX - inertiaState.lastSampleX) / dt;
    const sampleVY = (clientY - inertiaState.lastSampleY) / dt;

    inertiaState.velocityX +=
      (sampleVX - inertiaState.velocityX) * INERTIA_SMOOTHING;
    inertiaState.velocityY +=
      (sampleVY - inertiaState.velocityY) * INERTIA_SMOOTHING;

    resetInertiaSample(clientX, clientY, timestamp);
  }

  /**
   * Activates inertial panning if allowed and the current pan velocity exceeds the start threshold.
   *
   * If inertia is not permitted or the velocity is below the configured threshold, inertia is stopped.
   * When inertia starts, internal inertia timing state is initialized, any hover state is cleared,
   * and a render is requested.
   */
  function startInertia(): void {
    if (!isInertiaAllowed()) {
      stopInertia();
      return;
    }

    const speed = Math.hypot(inertiaState.velocityX, inertiaState.velocityY);
    if (speed < INERTIA_START_SPEED) {
      stopInertia();
      return;
    }

    inertiaState.active = true;
    inertiaState.lastFrameTime = performance.now();
    clearHover(false);
    requestRender();
  }

  /**
   * Advances inertial panning by one animation frame, updating pan position and velocity.
   *
   * @param timestamp - Current high-resolution timestamp for this animation frame.
   * @returns `true` if inertia remains active after this update, `false` if inertia stopped (for example because motion fell below the stop threshold or inertia is no longer allowed).
   */
  function animateInertia(timestamp: number): boolean {
    if (!inertiaState.active) return false;
    if (!isInertiaAllowed()) {
      stopInertia();
      return false;
    }

    const elapsed = timestamp - inertiaState.lastFrameTime;
    const dt = clamp(elapsed || 16, 1, INERTIA_MAX_FRAME_MS);
    inertiaState.lastFrameTime = timestamp;

    setPan(panX + inertiaState.velocityX * dt, panY + inertiaState.velocityY * dt);

    const decay = Math.exp(-INERTIA_FRICTION * dt);
    inertiaState.velocityX *= decay;
    inertiaState.velocityY *= decay;
    dirty = true;

    if (
      Math.hypot(inertiaState.velocityX, inertiaState.velocityY) <
      INERTIA_STOP_SPEED
    ) {
      stopInertia();
      return false;
    }

    return true;
  }

  /**
   * Update the canvas dimensions and related layout metrics to match the host element and device pixel ratio.
   *
   * Resizes the canvas drawing buffer and CSS size, updates internal width/height/device-pixel-ratio values, updates the host CSS variable for the toolbar/overlay height, marks the graph as needing a redraw, and requests a render.
   */
  function updateCanvasSize(): void {
    const rect = options.canvasHost.getBoundingClientRect();
    width = Math.max(1, Math.floor(rect.width));
    height = Math.max(1, Math.floor(rect.height));
    dpr = Math.max(1, Math.floor(window.devicePixelRatio || 1));
    options.canvas.width = width * dpr;
    options.canvas.height = height * dpr;
    options.canvas.style.width = `${width}px`;
    options.canvas.style.height = `${height}px`;
    const overlayTop =
      options.canvasHost.querySelector<HTMLElement>(".graph-overlay-top");
    toolbarHeight = overlayTop
      ? Math.ceil(overlayTop.getBoundingClientRect().height)
      : 50;
    options.canvasHost.style.setProperty(
      "--graph-toolbar-height",
      `${toolbarHeight}px`,
    );
    dirty = true;
    requestRender();
  }

  /**
   * Recomputes zoom and pan defaults to fit the current graph into the canvas.
   *
   * Uses the active graph's bounds (and measured label widths when a 2D context is available)
   * to calculate and update `fitZoom`, `minZoom`, `defaultPanX`, and `defaultPanY` so the graph
   * is centered and scaled to fit within the current canvas `width` and `height`.
   */
  function updateFitMetrics(): void {
    if (!currentGraph) return;
    const bounds = currentGraph.bounds;
    let contentMaxX = bounds.maxX;
    if (context) {
      context.save();
      context.font = GRAPH_LABEL_FONT;
      currentGraph.nodes.forEach((node) => {
        const label = formatGraphLabel(node);
        if (!label) return;
        const labelWidth = context.measureText(label).width;
        contentMaxX = Math.max(
          contentMaxX,
          node.baseX + node.radius + GRAPH_LABEL_GAP + labelWidth,
        );
      });
      context.restore();
    }
    const graphHeight = Math.max(1, bounds.maxY - bounds.minY);
    const horizontalPadding = 32;
    const verticalPadding = 24;
    // Space reserved by the floating side panel, so fit-to-view centres the
    // graph within the uncovered region.
    const panelSpace =
      parseFloat(
        getComputedStyle(options.canvasHost).getPropertyValue(
          "--graph-panel-space",
        ),
      ) || 0;
    const usableWidth = Math.max(1, width - horizontalPadding - panelSpace);
    const usableHeight = Math.max(1, height - toolbarHeight - verticalPadding);
    const fitZoomX = usableWidth / Math.max(1, contentMaxX - bounds.minX);
    const fitZoomY = usableHeight / graphHeight;
    fitZoom = clamp(Math.min(fitZoomX, fitZoomY), 0.05, MAX_ZOOM);
    minZoom = clamp(fitZoom * MIN_ZOOM_FIT_RATIO, 0.05, MAX_ZOOM);
    defaultPanX =
      horizontalPadding * 0.5 +
      (usableWidth - Math.max(1, contentMaxX - bounds.minX) * fitZoom) * 0.5 -
      bounds.minX * fitZoom;
    defaultPanY =
      toolbarHeight + verticalPadding * 0.5 +
      (usableHeight - graphHeight * fitZoom) * 0.5 - bounds.minY * fitZoom;
  }

  /**
   * Fits the current graph to the canvas viewport.
   *
   * Recomputes fit metrics, stops any ongoing inertial panning, clears a pending viewport target,
   * sets the zoom to the computed fit value, and centers the view using the default pan values.
   * No action is taken if no graph is loaded.
   */
  function fitGraph(): void {
    if (!currentGraph) return;
    stopInertia();
    clearViewportTarget();
    updateFitMetrics();
    zoom = fitZoom;
    setPan(defaultPanX, defaultPanY);
  }

  /**
   * Hit-tests the canvas at viewport coordinates and returns the nearest node within its hit radius.
   *
   * @param clientX - Horizontal viewport coordinate (e.g., MouseEvent.clientX)
   * @param clientY - Vertical viewport coordinate (e.g., MouseEvent.clientY)
   * @returns The nearest `GraphNode` whose rendered circle is within 5px of the point, or `null` if none is hit or the point lies outside the canvas.
   */
  function findNode(clientX: number, clientY: number): GraphNode | null {
    if (!currentGraph) return null;
    const rect = options.canvas.getBoundingClientRect();
    if (
      clientX < rect.left ||
      clientX > rect.right ||
      clientY < rect.top ||
      clientY > rect.bottom
    ) {
      return null;
    }
    const x = worldX(clientX - rect.left);
    const y = worldY(clientY - rect.top);

    let hit: GraphNode | null = null;
    let minDist = Infinity;
    currentGraph.nodes.forEach((node) => {
      const dx = x - node.renderX;
      const dy = y - node.renderY;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist <= node.renderRadius + 5 && dist < minDist) {
        minDist = dist;
        hit = node;
      }
    });
    return hit;
  }

  function setCanvasClickableCursor(clickable: boolean): void {
    options.canvas.classList.toggle(
      "is-clickable",
      clickable && !panState.down && !touchState.active,
    );
  }

  function resetInteractionVisualState(clearPanningCursor = false): void {
    setCanvasClickableCursor(false);
    if (clearPanningCursor) {
      options.canvas.classList.remove("is-panning");
    }
  }

  function updateHoverFromClientPosition(
    clientX: number,
    clientY: number,
  ): GraphNode | null {
    const node = findNode(clientX, clientY);
    updateHover(node ? node.slug : null);
    setCanvasClickableCursor(Boolean(node));
    return node;
  }

  /**
   * Builds the dependency graph for a named workspace, preparing nodes, edges, depth layers, and layout.
   *
   * Constructs a WorkspaceGraph containing node and edge maps, layer grouping by depth, sets of direct runtime/dev dependencies, and computed layout and amplification. The resulting graph is ready for rendering and interaction.
   *
   * @param name - The workspace name to build the graph for
   * @returns The constructed `WorkspaceGraph`, or `null` if the workspace does not exist or no dependencies are included
   */
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
      const labelGraphemes = Array.from(dataset.dependencies[slug].name);
      nodes.set(slug, {
        slug,
        ref: dataset.dependencies[slug],
        labelGraphemes,
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
        targetRadius: 8,
        renderRadius: 8,
        targetLabelChars: targetGraphLabelChars(labelGraphemes),
        renderLabelChars: initialGraphLabelChars(labelGraphemes),
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

  /**
   * Computes and assigns layout metrics for a WorkspaceGraph, including node order, positions, radii, label character targets, and overall graph bounds.
   *
   * This function mutates the provided graph and its nodes: it sorts each layer, sets per-node order, base/target/render positions (X/Y), radius/targetRadius/renderRadius, targetLabelChars/renderLabelChars, and updates graph.bounds (falling back to a default box if no finite bounds are produced).
   *
   * @param graph - The workspace graph to layout; nodes and layers are updated in-place.
   */
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
        node.targetRadius = node.radius;
        node.renderRadius = node.radius;
        node.targetLabelChars = targetGraphLabelChars(node.labelGraphemes);
        node.renderLabelChars = initialGraphLabelChars(node.labelGraphemes);

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

  /**
   * Computes target positions for nodes when a specific node is focused, arranging ancestors to the left and descendants to the right of a given center point.
   *
   * Positions are assigned per node slug; the focused node is placed at (centerX, centerY). Ancestors and descendants are grouped into discrete left/right columns based on directed distance from the focused node, ordered within each column by distance and vertical position, and vertically spaced to fit within configured row/column gaps.
   *
   * @param graph - The workspace graph containing nodes and their layout base coordinates.
   * @param slug - The slug of the node to focus.
   * @param centerX - The world-space x coordinate to place the focused node.
   * @param centerY - The world-space y coordinate to place the focused node.
   * @returns A map from node slug to target { x, y } coordinates for focus layout; includes an entry for the focused node at the provided center.
   */
  function buildFocusLayoutTargets(
    graph: WorkspaceGraph,
    slug: string,
    centerX: number,
    centerY: number,
  ): Map<string, FocusLayoutPoint> {
    const targets = new Map<string, FocusLayoutPoint>();
    const ancestorDistances = collectDirectedDistances(graph, slug, "parents");
    const descendantDistances = collectDirectedDistances(graph, slug, "children");
    const columns = new Map<number, GraphNode[]>();

    targets.set(slug, { x: centerX, y: centerY });

    focusNodes.forEach((nodeSlug) => {
      if (nodeSlug === slug) return;
      const node = graph.nodes.get(nodeSlug);
      if (!node) return;
      const ancestorDistance = ancestorDistances.get(nodeSlug);
      const descendantDistance = descendantDistances.get(nodeSlug);
      let column = 0;
      if (
        typeof ancestorDistance === "number" &&
        (typeof descendantDistance !== "number" ||
          ancestorDistance <= descendantDistance)
      ) {
        column = -ancestorDistance;
      } else if (typeof descendantDistance === "number") {
        column = descendantDistance;
      }
      if (column === 0) column = node.baseX < centerX ? -1 : 1;
      const bucket = columns.get(column) || [];
      bucket.push(node);
      columns.set(column, bucket);
    });

    columns.forEach((nodes, column) => {
      nodes.sort((a, b) => {
        const distanceA =
          column < 0
            ? ancestorDistances.get(a.slug) || 0
            : descendantDistances.get(a.slug) || 0;
        const distanceB =
          column < 0
            ? ancestorDistances.get(b.slug) || 0
            : descendantDistances.get(b.slug) || 0;
        if (distanceA !== distanceB) return distanceA - distanceB;
        if (a.baseY !== b.baseY) return a.baseY - b.baseY;
        return a.ref.name.localeCompare(b.ref.name);
      });

      const rowGap = clamp(
        FOCUS_MAX_COLUMN_SPREAD / Math.max(1, nodes.length - 1),
        FOCUS_MIN_ROW_GAP,
        FOCUS_ROW_GAP,
      );
      const top = centerY - ((nodes.length - 1) * rowGap) * 0.5;
      nodes.forEach((node, index) => {
        const columnDistance = Math.abs(column);
        const columnGap = FOCUS_LAYER_GAP * (1 + Math.max(0, columnDistance - 1) * 0.78);
        targets.set(node.slug, {
          x: centerX + Math.sign(column) * columnGap,
          y: top + index * rowGap,
        });
      });
    });

    return targets;
  }

  /**
   * Move the viewport to center the given world coordinates and adjust zoom toward a focused fit.
   *
   * Calculates a desired zoom as the larger of the current zoom and 1.35× the fit zoom (clamped to allowed limits),
   * eases the current zoom toward that value (snapping when reduced-motion is requested), and sets a pan target so
   * the provided world point appears near the center of the canvas.
   *
   * @param centerX - World-space x coordinate to center in the viewport
   * @param centerY - World-space y coordinate to center in the viewport
   */
  function focusViewportOn(centerX: number, centerY: number): void {
    if (!currentGraph) return;
    const desiredZoom = clamp(Math.max(zoom, fitZoom * 1.35), minZoom, MAX_ZOOM);
    zoom += (desiredZoom - zoom) * (reducedMotionQuery?.matches ? 1 : 0.35);
    setViewportTarget(width * 0.46 - centerX * zoom, height * 0.5 - centerY * zoom);
  }

  /**
   * Sets the given node as the focused node and computes all focus-related state and layout targets.
   *
   * Stops any inertia, builds the sets of focused nodes (ancestors, descendants, and the node itself),
   * focused edges (ancestor and descendant edge chains), and focus push nodes (focused set plus direct
   * neighbors). Preserves the existing focus center when the previously opened popover node remains
   * within the new focus set; otherwise centers on the selected node. Computes focus layout targets,
   * requests a viewport pan/zoom toward the focus center, marks the view dirty, and requests a render.
   *
   * @param slug - The dependency node slug to focus; if the current graph is missing or the slug is not present, this function is a no-op.
   */
  function applyFocus(slug: string): void {
    if (!currentGraph || !currentGraph.nodes.has(slug)) return;
    stopInertia();
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

    const firstFocus = focusCenterX === null || focusCenterY === null;
    const previousFocusStillConnected =
      !firstFocus && popoverSlug !== null && focusNodes.has(popoverSlug);
    if (firstFocus || !previousFocusStillConnected) {
      focusCenterX = selected.renderX;
      focusCenterY = selected.renderY;
    }
    focusLayoutTargets = buildFocusLayoutTargets(
      currentGraph,
      slug,
      focusCenterX ?? selected.renderX,
      focusCenterY ?? selected.renderY,
    );
    focusViewportOn(
      focusCenterX ?? selected.renderX,
      focusCenterY ?? selected.renderY,
    );

    dirty = true;
    requestRender();
  }

  /**
   * Clears any active focus on the graph and resets all focus-related state.
   *
   * This resets the focused slug, visible focused node/edge sets, push-node set,
   * focus layout targets, and focus center coordinates; it also clears any
   * pending viewport pan target and schedules a render.
   */
  function clearFocus(): void {
    focusSlug = null;
    focusNodes = new Set();
    focusEdges = new Set();
    focusPushNodes = new Set();
    focusLayoutTargets = new Map();
    focusCenterX = null;
    focusCenterY = null;
    clearViewportTarget();
    dirty = true;
    requestRender();
  }

  function clearHover(shouldRender = true): void {
    hoverSlug = null;
    hoverNodes = new Set();
    hoverEdges = new Set();
    if (!shouldRender) return;
    dirty = true;
    requestRender();
  }

  /**
   * Updates each node's target visual properties (radius, visible label characters, and target position) for the active graph.
   *
   * If there is no active graph, the function is a no-op.
   *
   * For each node:
   * - Sets the node's target radius according to current sizing rules.
   * - Sets the node's target label character count based on focus/hover state.
   * - Sets targetX/targetY to the node's base position unless a node is focused and this node is part of the focus push set, in which case the node is displaced outward from the focused node to produce a radial push effect.
   */
  function updateTargets(): void {
    if (!currentGraph) return;
    const selected = focusSlug
      ? currentGraph.nodes.get(focusSlug) || null
      : null;

    currentGraph.nodes.forEach((node) => {
      node.targetRadius = targetNodeRadius(node);
      node.targetLabelChars = targetGraphLabelChars(
        node.labelGraphemes,
        (Boolean(focusSlug) && focusNodes.has(node.slug)) ||
          (!focusSlug && Boolean(hoverSlug) && hoverNodes.has(node.slug)),
      );
      const focusTarget = focusLayoutTargets.get(node.slug);
      if (selected && focusTarget) {
        node.targetX = focusTarget.x;
        node.targetY = focusTarget.y;
        return;
      }
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

  /**
   * Progresses per-node animated properties toward their target values for the current graph.
   *
   * When the user's reduced-motion preference is enabled, node render properties snap immediately to their targets.
   *
   * @returns `true` if at least one node is still animating (not yet settled), `false` otherwise.
   */
  function animateNodes(): boolean {
    if (!currentGraph) return false;
    let moving = false;
    const reducedMotion = reducedMotionQuery?.matches;
    currentGraph.nodes.forEach((node) => {
      if (reducedMotion) {
        node.renderX = node.targetX;
        node.renderY = node.targetY;
        node.renderRadius = node.targetRadius;
        node.renderLabelChars = node.targetLabelChars;
        return;
      }
      const positionEasing = focusSlug ? FOCUS_LAYOUT_EASING : 0.15;
      node.renderX += (node.targetX - node.renderX) * positionEasing;
      node.renderY += (node.targetY - node.renderY) * positionEasing;
      node.renderRadius += (node.targetRadius - node.renderRadius) * 0.18;
      node.renderLabelChars +=
        (node.targetLabelChars - node.renderLabelChars) *
        LABEL_ANIMATION_EASING;
      const settled =
        Math.abs(node.targetX - node.renderX) < 0.06 &&
        Math.abs(node.targetY - node.renderY) < 0.06 &&
        Math.abs(node.targetRadius - node.renderRadius) < 0.04 &&
        Math.abs(node.targetLabelChars - node.renderLabelChars) < 0.12;
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
    options.onSelect?.(slug);
  }

  function hidePopover(): void {
    const hadSelection = popoverSlug !== null;
    popoverSlug = null;
    options.popover.hidden = true;
    if (hadSelection) options.onSelect?.(null);
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

  function targetNodeRadius(node: GraphNode): number {
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

  /**
   * Renders the active workspace dependency graph onto the canvas using the current pan, zoom, theme, and interaction state.
   *
   * Clears the canvas, culls nodes outside the viewport, sorts and routes edges, and draws muted and highlighted edges, node bodies, vulnerability rings, and labels in the correct visual stacking order. Also updates the popover position after drawing.
   */
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

    const colorRuntime = themeColors.runtime;
    const colorDev = themeColors.dev;
    const colorTransitive = themeColors.transitive;
    const colorEdge = themeColors.edge;
    const colorHighlight = themeColors.highlight;
    const colorMuted = themeColors.muted;
    const colorRingHigh = themeColors.ringHigh;
    const colorRingModerate = themeColors.ringModerate;
    const labelColor = themeColors.label;
    const bgPrimary = themeColors.backgroundPrimary;

    const visible = new Set<string>();
    graph.nodes.forEach((node) => {
      const extent = Math.max(node.radius, node.renderRadius);
      if (
        node.renderX + extent >= worldMinX &&
        node.renderX - extent <= worldMaxX &&
        node.renderY + extent >= worldMinY &&
        node.renderY - extent <= worldMaxY
      ) {
        visible.add(node.slug);
      }
    });

    type RenderNode = {
      node: GraphNode;
      priority: number;
      order: number;
    };

    const renderNodes: RenderNode[] = [];
    let renderOrder = 0;
    graph.nodes.forEach((node) => {
      if (!visible.has(node.slug)) return;
      let priority = 0;
      if (focusSlug === node.slug) priority = 2;
      else if (focusNodes.has(node.slug) || hoverNodes.has(node.slug))
        priority = 1;
      renderNodes.push({
        node,
        priority,
        order: renderOrder++,
      });
    });

    renderNodes.sort((a, b) => a.priority - b.priority || a.order - b.order);

    const maxDepth = Math.max(0, graph.layers.length - 1);
    const SAME_COLUMN_X_THRESHOLD = 6;
    const MIN_DETOUR_VERTICAL_SPAN = 80;
    const DETOUR_INSET = 14;
    const DETOUR_NODE_CLEARANCE = 26;
    const depthNodeIndex = buildDepthNodeIndex(graph);
    const edgeRoutingConfig: EdgeRoutingConfig = {
      depthNodeIndex,
      maxDepth,
      sameColumnXThreshold: SAME_COLUMN_X_THRESHOLD,
      minDetourVerticalSpan: MIN_DETOUR_VERTICAL_SPAN,
      detourInset: DETOUR_INSET,
      detourNodeClearance: DETOUR_NODE_CLEARANCE,
      paddingX: PADDING_X,
      layerGap: LAYER_GAP,
      edgeCurve: EDGE_CURVE,
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
    context.beginPath();
    renderEdges.forEach((edge) => {
      if (edge.highlighted) return;
      drawGraphEdge(context, edge, edgeRoutingConfig, Boolean(focusSlug));
    });
    context.stroke();

    context.globalCompositeOperation = "lighter";
    context.strokeStyle = colorHighlight;
    context.lineWidth = 1.2;
    context.globalAlpha = highlightedEdgeOpacity();
    context.beginPath();
    renderEdges.forEach((edge) => {
      if (!edge.highlighted) return;
      drawGraphEdge(context, edge, edgeRoutingConfig, Boolean(focusSlug));
    });
    context.stroke();

    context.globalCompositeOperation = "source-over";

    const drawNodeBody = (node: GraphNode): void => {
      const selected = focusSlug === node.slug;
      const radius = node.renderRadius;

      // Draw an opaque background to occlude lines passing underneath
      context.globalAlpha = 1;
      context.fillStyle = bgPrimary;
      context.beginPath();
      context.arc(node.renderX, node.renderY, radius, 0, Math.PI * 2);
      context.fill();

      // Draw the slightly transparent node fill
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
        grad.addColorStop(0, themeColors.runtimeHighlight);
        grad.addColorStop(1, colorRuntime);
      } else if (node.kind === "direct-dev") {
        grad.addColorStop(0, themeColors.devHighlight);
        grad.addColorStop(1, colorDev);
      } else {
        grad.addColorStop(0, themeColors.transitiveHighlight);
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
    };

    const drawVulnerabilityRings = (node: GraphNode): void => {
      if (!node.ref.vulnerabilityCount || node.ref.vulnerabilityCount <= 0)
        return;
      if (node.ref.vulnerabilitySeverity === "none") return;

      const radius = node.renderRadius;
      const isHigh = node.ref.vulnerabilitySeverity === "high";
      const color = isHigh ? colorRingHigh : colorRingModerate;

      context.save();
      context.translate(node.renderX, node.renderY);

      context.globalAlpha = vulnerabilityRingOpacity(node.slug);
      context.strokeStyle = color;

      // Calculate scale factor relative to unselected base radius
      const scaleFactor = radius / node.radius;

      // User request: 1.2x bigger than last time
      const extraSpace = (radius / 3) * 1.2;
      const unit = extraSpace / 12;

      // Spreads out more when selected
      const gap = unit * 1.2 + (scaleFactor - 1) * 3;

      const lw0 = Math.max(unit * 0.5, 0.15);
      const lw1 = Math.max(unit * 1.0, 0.3);
      const lw2 = Math.max(unit * 3.0, 0.8);
      const lw3 = Math.max(unit * 1.0, 0.3);
      const lw4 = Math.max(unit * 0.5, 0.15);

      // Selection ring is at radius + 4. Ensure r0 starts past that.
      const initialOffset = 2 + (scaleFactor - 1) * 6;

      const r0 = radius + initialOffset + lw0 / 2;
      const r1 = r0 + lw0 / 2 + gap + lw1 / 2;
      const r2 = r1 + lw1 / 2 + gap + lw2 / 2;
      const r3 = r2 + lw2 / 2 + gap + lw3 / 2;
      const r4 = r3 + lw3 / 2 + gap + lw4 / 2;

      // Outer ring
      context.setLineDash([]);

      context.lineWidth = lw4;
      context.beginPath();
      context.arc(0, 0, r4, 0, Math.PI * 2);
      context.stroke();

      // Ring 3
      context.lineWidth = lw3;
      context.beginPath();
      context.arc(0, 0, r3, 0, Math.PI * 2);
      context.stroke();

      // Ring 2 (Middle)
      context.lineWidth = lw2;
      context.beginPath();
      context.arc(0, 0, r2, 0, Math.PI * 2);
      context.stroke();

      // Ring 1
      context.lineWidth = lw1;
      context.beginPath();
      context.arc(0, 0, r1, 0, Math.PI * 2);
      context.stroke();

      // Ring 0 (Inner)
      context.lineWidth = lw0;
      context.beginPath();
      context.arc(0, 0, r0, 0, Math.PI * 2);
      context.stroke();

      context.restore();
    };

    const drawNodeLabel = (node: GraphNode): void => {
      const label = formatGraphLabel(node);
      if (!label) return;
      context.globalAlpha = nodeOpacity(node.slug);
      context.fillText(
        label,
        node.renderX + node.renderRadius + GRAPH_LABEL_GAP,
        node.renderY,
      );
    };

    for (const priority of [0, 1, 2]) {
      renderNodes.forEach(({ node, priority: nodePriority }) => {
        if (nodePriority !== priority) return;
        drawNodeBody(node);
      });

      renderNodes.forEach(({ node, priority: nodePriority }) => {
        if (nodePriority !== priority) return;
        drawVulnerabilityRings(node);
      });
    }

    context.textBaseline = "middle";
    context.font = GRAPH_LABEL_FONT;
    context.fillStyle = labelColor;
    renderNodes.forEach(({ node }) => {
      drawNodeLabel(node);
    });

    context.globalAlpha = 1;
    updatePopoverPosition();
  }

  /**
   * Drives a single tick of the view's animation loop: updates animation targets, advances node and inertia animations, triggers a render when needed, and schedules the next tick while the view is active.
   */
  function tick(): void {
    if (!active) {
      frameId = 0;
      return;
    }

    updateTargets();
    const moving = animateNodes();
    const inertial = animateInertia(performance.now());
    const viewportMoving = animateViewport();

    if (dirty || moving || inertial || viewportMoving) {
      renderGraph();
      dirty = false;
      if (active && (dirty || moving || inertial || viewportMoving)) {
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

  /**
   * Activate the workspace with the given name and update the view to reflect it.
   *
   * Stops any active inertia, rebuilds the workspace graph, resets focus and hover state, hides the popover,
   * fits the graph to the viewport, and schedules a render for the newly active workspace.
   *
   * @param name - The workspace name to switch to
   */
  function switchWorkspace(name: string): void {
    const graph = buildWorkspaceGraph(name);
    if (!graph) return;
    stopInertia();
    currentWorkspace = name;
    currentGraph = graph;
    clearFocus();
    hidePopover();
    hoverSlug = null;
    hoverNodes = new Set();
    hoverEdges = new Set();
    resetInteractionVisualState(true);
    fitGraph();
    dirty = true;
    requestRender();
  }

  /**
   * Begin a canvas pan interaction when the primary mouse button is pressed.
   *
   * Records the initial pointer and pan positions, stops any ongoing inertial pan,
   * resets interaction visuals, and marks the canvas with the `is-panning` CSS class.
   *
   * @param event - The mouse down event from the canvas that initiated the interaction
   */
  function handleCanvasMouseDown(event: MouseEvent): void {
    if (event.button !== 0) return;
    stopInertia();
    clearViewportTarget();
    panState.down = true;
    panState.moved = false;
    panState.startX = event.clientX;
    panState.startY = event.clientY;
    panState.startPanX = panX;
    panState.startPanY = panY;
    resetInertiaSample(event.clientX, event.clientY, event.timeStamp);
    resetInteractionVisualState();
    options.canvas.classList.add("is-panning");
  }

  /**
   * Handles mousemove events to update hover state when not dragging, or to pan the graph while dragging.
   *
   * When a drag is active, updates the pan position, records pan velocity for inertia, marks the pointer as
   * moved once displacement exceeds 2 pixels, and schedules a render. When no drag is active, updates hover
   * state from the event coordinates.
   *
   * @param event - The mousemove event from the window
   */
  function handleWindowMouseMove(event: MouseEvent): void {
    if (!panState.down) {
      updateHoverFromClientPosition(event.clientX, event.clientY);
      return;
    }

    const dx = event.clientX - panState.startX;
    const dy = event.clientY - panState.startY;
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) panState.moved = true;
    setPan(panState.startPanX + dx, panState.startPanY + dy);
    recordPanVelocity(event.clientX, event.clientY, event.timeStamp);
    requestRender();
  }

  /**
   * Finalize a window-level mouseup: end a pan (starting inertia when moved) or treat it as a click to update hover, focus, and the popover.
   *
   * @param event - The MouseEvent from the window used to determine client coordinates and whether the interaction was a pan or a click
   */
  function handleWindowMouseUp(event: MouseEvent): void {
    if (!panState.down) return;
    options.canvas.classList.remove("is-panning");
    const moved = panState.moved;
    panState.down = false;
    panState.moved = false;

    if (moved) {
      startInertia();
      if (inertiaState.active) {
        setCanvasClickableCursor(false);
        return;
      }
      updateHoverFromClientPosition(event.clientX, event.clientY);
      return;
    }

    const node = updateHoverFromClientPosition(event.clientX, event.clientY);
    if (!node) {
      clearHover(false);
      clearFocus();
      hidePopover();
      return;
    }

    applyFocus(node.slug);
    showPopover(node.slug);
  }

  /**
   * Handles mouse wheel and trackpad scroll to adjust the view zoom centered at the pointer.
   *
   * If the event target is outside the canvas host the event is ignored. The handler prevents default scrolling, stops any inertial panning, and updates the zoom level using sensitivity that varies when the Ctrl or Meta key is pressed.
   */
  function handleWheel(event: WheelEvent): void {
    if (!options.canvasHost.contains(event.target as Node)) return;
    event.preventDefault();
    stopInertia();
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

  /**
   * Begin a touch interaction on the canvas to initiate one-finger panning or two-finger pinch-zoom.
   *
   * Stops any active inertia, clears pending viewport targets, prevents the default touch behavior, and records initial touch positions, pan/zoom state, distance, and anchor coordinates used by subsequent touch-move handling.
   *
   * @param event - The originating TouchEvent that started the touch interaction
   */
  function handleTouchStart(event: TouchEvent): void {
    if (event.touches.length === 0) return;
    event.preventDefault();
    stopInertia();
    clearViewportTarget();
    resetInteractionVisualState();

    const rect = options.canvas.getBoundingClientRect();

    if (event.touches.length === 1) {
      touchState.active = true;
      panState.moved = false;
      touchState.startX1 = event.touches[0].clientX;
      touchState.startY1 = event.touches[0].clientY;
      touchState.startPanX = panX;
      touchState.startPanY = panY;
      resetInertiaSample(
        event.touches[0].clientX,
        event.touches[0].clientY,
        event.timeStamp,
      );
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
      touchState.anchorX = screenX;
      touchState.anchorY = screenY;
    }
  }

  /**
   * Handle touch-move input to pan or pinch-zoom the graph.
   *
   * Prevents the default touch behavior and, for a single touch, pans the view by updating pan state, records pan velocity for inertia, and requests a render. For two touches, cancels inertia and performs pinch-zoom by computing a scale factor from the current distance relative to the initial distance and applying zoom around the stored anchor (or canvas center).
   *
   * @param event - The touch event containing one or more touch points
   */
  function handleTouchMove(event: TouchEvent): void {
    if (!touchState.active) return;
    event.preventDefault();

    if (event.touches.length === 1) {
      const dx = event.touches[0].clientX - touchState.startX1;
      const dy = event.touches[0].clientY - touchState.startY1;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) panState.moved = true;
      setPan(touchState.startPanX + dx, touchState.startPanY + dy);
      recordPanVelocity(
        event.touches[0].clientX,
        event.touches[0].clientY,
        event.timeStamp,
      );
      requestRender();
    } else if (event.touches.length === 2) {
      stopInertia();
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
        const anchorX = touchState.anchorX ?? width / 2;
        const anchorY = touchState.anchorY ?? height / 2;
        applyZoom(newZoom, anchorX, anchorY);
      }
    }
  }

  /**
   * Handle the end of a touch interaction, finalizing gesture state and triggering appropriate follow-up actions.
   *
   * If the touch sequence was canceled, stops any inertial panning, resets interaction visuals, and clears touch anchors.
   * If all touches ended: resets interaction visuals and anchors; if no pan movement occurred and a single touch ended,
   * performs a hit test to either focus and show the node popover or clear hover/focus/popover; if pan movement occurred,
   * initiates inertial panning.
   * If the interaction transitions from a multi-touch pinch to a single-touch pan, updates the touch start/pan anchors
   * and resets the inertia sampling for continued panning.
   */
  function handleTouchEnd(event: TouchEvent): void {
    if (!touchState.active) return;
    event.preventDefault();
    const canceled = event.type === "touchcancel";

    if (canceled) {
      stopInertia();
      resetInteractionVisualState(true);
      touchState.active = false;
      touchState.anchorX = null;
      touchState.anchorY = null;
      panState.moved = false;
      return;
    }

    if (event.touches.length === 0) {
      resetInteractionVisualState(true);
      touchState.active = false;
      touchState.anchorX = null;
      touchState.anchorY = null;

      if (!panState.moved && event.changedTouches.length === 1) {
        const node = findNode(
          event.changedTouches[0].clientX,
          event.changedTouches[0].clientY,
        );
        if (!node) {
          clearHover(false);
          clearFocus();
          hidePopover();
        } else {
          applyFocus(node.slug);
          showPopover(node.slug);
        }
      } else if (panState.moved) {
        startInertia();
      }
      panState.moved = false;
    } else if (event.touches.length === 1) {
      // Transition from pinch back to pan
      touchState.startX1 = event.touches[0].clientX;
      touchState.startY1 = event.touches[0].clientY;
      touchState.startPanX = panX;
      touchState.startPanY = panY;
      resetInertiaSample(
        event.touches[0].clientX,
        event.touches[0].clientY,
        event.timeStamp,
      );
    }
  }

  function handleCanvasMouseLeave(): void {
    updateHover(null);
    resetInteractionVisualState();
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

  /**
   * Detaches all pointer and touch event listeners from the canvas and window and resets interaction state.
   *
   * Removes mouse, wheel, touch, and document event handlers registered for graph interaction, clears
   * pan and touch flags, resets interaction visuals, stops any ongoing inertial panning, and marks
   * interactions as unbound.
   */
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
    resetInteractionVisualState(true);
    panState.down = false;
    panState.moved = false;
    touchState.active = false;
    touchState.anchorX = null;
    touchState.anchorY = null;
    stopInertia();
    interactionsBound = false;
  }

  /**
   * Handle clicks on the graph control buttons and perform the corresponding action.
   *
   * Recognizes buttons with a `data-action` attribute and performs: "zoom-in", "zoom-out",
   * "pan-left", "pan-right", "pan-up", "pan-down", and "reset" (which restores zoom/pan,
   * clears focus, hides the popover, and stops inertia).
   *
   * @param event - The click MouseEvent originating from the controls container
   */
  function handleControlsClick(event: MouseEvent): void {
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
      stopInertia();
      zoom = fitZoom;
      setPan(defaultPanX, defaultPanY);
      clearFocus();
      hidePopover();
      requestRender();
    }
  }

  function handlePopoverOpenClick(): void {
    if (!popoverSlug) return;
    options.onOpenList(popoverSlug);
  }

  function handleWorkspaceSelectChange(): void {
    switchWorkspace(options.workspaceSelect.value);
  }

  /**
   * Update viewport metrics and schedule a re-render after the display size changes.
   *
   * If the graph view is not active this function is a no-op. It updates the canvas size, recomputes fit
   * metrics, clamps the current zoom to allowed bounds, reapplies pan constraints, and requests a render;
   * if the resulting canvas width or height is <= 1 the update is aborted.
   */
  function handleViewportResize(): void {
    if (!active) return;
    updateCanvasSize();
    if (width <= 1 || height <= 1) return;
    updateFitMetrics();
    zoom = clamp(zoom, minZoom, MAX_ZOOM);
    setPan(panX, panY);
    requestRender();
  }

  function bindPersistentListeners(): void {
    if (!workspaceSelectBound) {
      options.workspaceSelect.addEventListener("change", handleWorkspaceSelectChange);
      workspaceSelectBound = true;
    }
    if (!controlsBound) {
      options.controlsRoot.addEventListener("click", handleControlsClick);
      options.popoverOpenButton.addEventListener("click", handlePopoverOpenClick);
      controlsBound = true;
    }
  }

  function setupGlobalObservers(): void {
    if (themeObserver) {
      themeObserver.disconnect();
    }
    themeObserver = new MutationObserver(() => {
      updateThemeColors();
      requestRender();
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class", "data-theme"],
    });

    if (hostResizeObserver) {
      hostResizeObserver.disconnect();
      hostResizeObserver = null;
    }
    if (windowResizeHandler) {
      window.removeEventListener("resize", windowResizeHandler);
      windowResizeHandler = null;
    }

    if (typeof ResizeObserver !== "undefined") {
      hostResizeObserver = new ResizeObserver(handleViewportResize);
      hostResizeObserver.observe(options.canvasHost);
      return;
    }

    windowResizeHandler = handleViewportResize;
    window.addEventListener("resize", windowResizeHandler);
  }

  function setupControls(): void {
    bindPersistentListeners();
  }

  /**
   * Initialize internal UI, workspace selection, theming, controls, and canvas then activate the initial workspace.
   *
   * Populates the workspace dropdown (including a root separator when present), ensures a root workspace entry if required, sets the active workspace, updates theme colors, registers global observers and control handlers, updates canvas sizing or shows a fallback when canvas is unavailable, and switches to the chosen initial workspace.
   */
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

    const rootWorkspace = workspaces.find((workspace) => workspace.name === "root");
    const orderedWorkspaces = rootWorkspace
      ? [
          rootWorkspace,
          ...workspaces.filter((workspace) => workspace.name !== "root"),
        ]
      : workspaces;

    options.workspaceSelect.textContent = "";
    orderedWorkspaces.forEach((workspace, index) => {
      const option = document.createElement("option");
      option.value = workspace.name;
      option.textContent =
        workspace.name === "root" ? "Workspace root" : workspace.name;
      options.workspaceSelect.appendChild(option);

      if (
        workspace.name === "root" &&
        orderedWorkspaces.length > 1 &&
        index === 0
      ) {
        const divider = document.createElement("option");
        divider.disabled = true;
        divider.textContent = "──────────────";
        options.workspaceSelect.appendChild(divider);
      }
    });

    options.workspaceWrap.classList.toggle("hidden", workspaces.length <= 1);

    if (!workspaceByName.has("root") && workspaces.length === 1) {
      workspaceByName.set("root", workspaces[0]);
    }

    currentWorkspace = orderedWorkspaces[0].name;
    options.workspaceSelect.value = currentWorkspace;

    updateThemeColors();
    setupGlobalObservers();

    setupControls();
    if (!hasCanvas) {
      showCanvasFallback();
      return;
    }
    updateCanvasSize();
    switchWorkspace(currentWorkspace);
  }

  /**
   * Activate or deactivate the graph view.
   *
   * When `next` is `true`, the function sets the view active; if the canvas is unavailable it shows the canvas fallback.
   * Otherwise it binds interaction listeners, updates canvas sizing and fit metrics, clamps zoom/pan, and starts the render loop.
   * When `next` is `false`, it unbinds interaction listeners, stops inertial panning, and cancels any pending animation frame.
   *
   * @param next - `true` to activate the view, `false` to deactivate it
   */
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
        setPan(panX, panY);
      }
      renderLoop();
      requestRender();
      return;
    }
    unbindInteractionListeners();
    stopInertia();
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
