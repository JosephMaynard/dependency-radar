import type { VizCallbacks, VizHandle, VizModel } from "./vizModel";

// Poincaré-disk focus+context view: project at centre, direct deps on the
// first ring, sub-dependencies shrinking toward the (infinitely far) rim.
// Drag performs a Möbius translation. Ported from the hyperbolic-radar
// prototype. CRITICAL invariant: every transform is applied to every point
// INCLUDING the virtual project-hub position — the hub is not a node in the
// array and silently stays pinned at centre otherwise.

interface C {
  x: number;
  y: number;
}

const cAdd = (a: C, b: C): C => ({ x: a.x + b.x, y: a.y + b.y });
const cMul = (a: C, b: C): C => ({ x: a.x * b.x - a.y * b.y, y: a.x * b.y + a.y * b.x });
const cConj = (a: C): C => ({ x: a.x, y: -a.y });
const cAbs2 = (a: C): number => a.x * a.x + a.y * a.y;
const cDiv = (a: C, b: C): C => {
  const d = cAbs2(b) || 1e-12;
  return { x: (a.x * b.x + a.y * b.y) / d, y: (a.y * b.x - a.x * b.y) / d };
};
/** Disk automorphism taking 0 -> a: T_a(z) = (z + a) / (1 + conj(a) z). */
const mobius = (a: C, z: C): C => cDiv(cAdd(z, a), cAdd({ x: 1, y: 0 }, cMul(cConj(a), z)));
const mobiusNeg = (a: C, z: C): C => mobius({ x: -a.x, y: -a.y }, z);

export function mountHyperbolicView(
  host: HTMLElement,
  model: VizModel,
  cb: VizCallbacks,
): VizHandle {
  const canvas = document.createElement("canvas");
  canvas.className = "graph-alt-canvas";
  canvas.setAttribute("role", "img");
  canvas.setAttribute(
    "aria-label",
    "Hyperbolic view of the dependency tree (pointer-driven — the list view offers the same data with keyboard access)",
  );
  host.appendChild(canvas);
  const ctx = canvas.getContext("2d");
  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  const aborter = new AbortController();
  const signal = aborter.signal;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const N = model.count;
  const { parent, children, leaves, depsOut } = model;

  const pos: C[] = Array.from({ length: N }, () => ({ x: 0, y: 0 }));
  let hubPos: C = { x: 0, y: 0 };

  // Small roots get a floor on their wedge share so leafless direct deps
  // don't smear into slivers — but a modest one, so roots with real subtrees
  // get the angular room their fans actually need.
  const rootWeight = (r: number): number => Math.sqrt(leaves[r]) + 0.8;

  // Re-rootable layout. The spanning tree is laid out around ANY node (or
  // the project hub): the focused node sits at the origin, each neighbour —
  // children AND the way back up — takes a wedge proportional to how much of
  // the tree lies in that direction, and the walk proceeds outward. Focusing
  // therefore restructures the picture around what you're looking at while
  // the rest of the graph compresses toward the rim but stays visible.
  const HUB = -1;
  const CAME_NONE = -3;
  const hubKids: number[] = [];
  for (let i = 0; i < N; i += 1) if (parent[i] === -1) hubKids.push(i);
  const totalLeaves = hubKids.reduce((sum, r) => sum + leaves[r], 0) || 1;

  /**
   * Focus context: when the layout is centred on a package, the spanning
   * tree is RE-ROOTED there — a BFS from the focus over the real dependency
   * edges claims everything it can reach, so the focused package's true
   * dependency tree fans out around it (shared deps included), instead of
   * staying wherever the hub-rooted tree's first claimer happened to put
   * them. Everything unreachable from the focus keeps the original
   * structure and hangs off the context wedge via the hub.
   */
  interface FocusCtx {
    center: number;
    inFocus: Uint8Array;
    fKids: number[][];
    fParent: Int32Array;
    fLeaves: Float32Array;
    outsideWeight: number;
  }

  function buildFocusCtx(center: number): FocusCtx {
    const inFocus = new Uint8Array(N);
    const fParent = new Int32Array(N).fill(-2);
    const fKids: number[][] = Array.from({ length: N }, () => []);
    const order: number[] = [center];
    inFocus[center] = 1;
    fParent[center] = -1;
    for (let head = 0; head < order.length; head += 1) {
      const u = order[head];
      for (const v of depsOut[u]) {
        if (inFocus[v]) continue;
        inFocus[v] = 1;
        fParent[v] = u;
        fKids[u].push(v);
        order.push(v);
      }
    }
    const fLeaves = new Float32Array(N).fill(1);
    for (let i = order.length - 1; i >= 0; i -= 1) {
      const u = order[i];
      if (fKids[u].length) {
        fLeaves[u] = fKids[u].reduce((sum, c) => sum + fLeaves[c], 0);
      }
    }
    const byFLeaves = (a: number, b: number): number =>
      fLeaves[b] - fLeaves[a] || a - b;
    for (const list of fKids) if (list.length > 1) list.sort(byFLeaves);
    return {
      center,
      inFocus,
      fKids,
      fParent,
      fLeaves,
      outsideWeight: Math.max(N - order.length, 1),
    };
  }

  function neighborsFrom(
    id: number,
    cameFrom: number,
    fc: FocusCtx | null,
  ): Array<{ next: number; weight: number }> {
    if (id === HUB) {
      return hubKids
        .filter((r) => r !== cameFrom && !(fc && fc.inFocus[r]))
        .map((r) => ({ next: r, weight: rootWeight(r) }));
    }
    const list: Array<{ next: number; weight: number }> = [];
    if (fc && fc.inFocus[id]) {
      for (const kid of fc.fKids[id]) {
        if (kid !== cameFrom) {
          list.push({ next: kid, weight: Math.max(fc.fLeaves[kid], 0.5) });
        }
      }
      // The way out of the focus subtree: the centre connects the rest of
      // the graph through the hub; interior nodes walk up the focus tree.
      const upId = id === fc.center ? HUB : fc.fParent[id];
      if (upId !== cameFrom) {
        list.push({
          next: upId,
          weight:
            id === fc.center
              ? fc.outsideWeight
              : Math.max(fc.fLeaves[fc.center] - fc.fLeaves[id], 1),
        });
      }
      return list;
    }
    for (const kid of children[id]) {
      // Skip children the focus tree already claimed — they are placed.
      if (kid !== cameFrom && !(fc && fc.inFocus[kid])) {
        list.push({ next: kid, weight: Math.max(leaves[kid], 0.5) });
      }
    }
    const upId = parent[id] === -1 ? HUB : parent[id];
    if (upId !== cameFrom) {
      // Everything that is NOT below this node lies in the parent direction.
      list.push({ next: upId, weight: Math.max(totalLeaves - leaves[id], 1) });
    }
    return list;
  }

  interface Layout {
    positions: C[];
    hub: C;
    /** Tree edge per node for drawing: parent index, -1 = hub spoke, -2 = none. */
    parentMap: Int32Array;
  }

  /** Lay the whole tree out around `centerId` (HUB or a package index). */
  function computeLayout(centerId: number): Layout {
    const fc = centerId === HUB ? null : buildFocusCtx(centerId);
    const positions: C[] = Array.from({ length: N }, () => ({ x: 0, y: 0 }));
    const parentMap = new Int32Array(N).fill(-2);
    let hub: C = { x: 0, y: 0 };
    const setP = (id: number, p: C): void => {
      if (id === HUB) hub = p;
      else positions[id] = p;
    };
    const getP = (id: number): C => (id === HUB ? hub : positions[id]);
    setP(centerId, { x: 0, y: 0 });

    const stack: Array<{ id: number; cameFrom: number; mid: number; wedge: number }> = [
      { id: centerId, cameFrom: CAME_NONE, mid: -Math.PI / 2, wedge: Math.PI * 2 },
    ];
    // At the focused node, the way-back-up direction holds nearly the whole
    // graph, so weight-proportional wedges would hand it nearly the whole
    // circle and squeeze the subtree the user actually focused into a
    // sliver. Cap the context's share of the centre ring; the children keep
    // the rest of the space.
    const UP_FRACTION_MAX = 0.4;
    while (stack.length > 0) {
      const frame = stack.pop();
      if (!frame) break;
      const { id, cameFrom, mid, wedge } = frame;
      let around = neighborsFrom(id, cameFrom, fc);
      if (around.length === 0) continue;
      const isCenter = cameFrom === CAME_NONE;
      if (isCenter && id !== HUB && around.length > 1) {
        // neighborsFrom appends the parent-direction entry last.
        const up = around[around.length - 1];
        const childSum = around
          .slice(0, -1)
          .reduce((sum, n) => sum + n.weight, 0);
        const maxUp = (childSum * UP_FRACTION_MAX) / (1 - UP_FRACTION_MAX);
        if (childSum > 0 && up.weight > maxUp) {
          around = [...around.slice(0, -1), { next: up.next, weight: maxUp }];
        }
      }
      // Short links keep systems visually attached to their parents.
      const rhoBase = isCenter
        ? 0.4
        : Math.min(0.58, 0.3 + 0.036 * Math.sqrt(around.length));
      const total = around.reduce((sum, n) => sum + n.weight, 0) || 1;
      let start = mid - wedge / 2;
      let index = 0;
      for (const { next, weight } of around) {
        const share = (weight / total) * wedge;
        const ang = start + share / 2;
        start += share;
        // Large fans of equal-weight leaves crush onto one arc; staggering
        // siblings across three shells triples their angular breathing room.
        const rho =
          !isCenter && around.length > 6
            ? Math.min(0.64, rhoBase + ((index % 3) - 1) * 0.065)
            : rhoBase;
        index += 1;
        const local = { x: rho * Math.cos(ang), y: rho * Math.sin(ang) };
        const g = mobius(getP(id), local);
        setP(next, g);
        if (next === HUB) {
          // The centre's way-out edge renders as its hub spoke.
          if (parentMap[id] === -2) parentMap[id] = -1;
        } else {
          parentMap[next] = id;
        }
        // Outward direction in the neighbour's own frame: away from here.
        const parentLocal = mobiusNeg(g, getP(id));
        const out = Math.atan2(parentLocal.y, parentLocal.x) + Math.PI;
        stack.push({ id: next, cameFrom: id, mid: out, wedge: Math.min(share * 0.95, 2.8) });
      }
    }
    return { positions, hub, parentMap };
  }

  /** Tree edges of the layout currently on screen (drawing follows these). */
  let activeParent: Int32Array = new Int32Array(N).fill(-2);

  function applyLayout(layout: Layout): void {
    for (let i = 0; i < N; i += 1) pos[i] = layout.positions[i];
    hubPos = layout.hub;
    activeParent = layout.parentMap;
  }

  applyLayout(computeLayout(HUB));

  let W = 0;
  let H = 0;
  let CX = 0;
  let CY = 0;
  let R = 0;
  // Widescreen stretch: the disk renders as an ellipse (capped) so it uses
  // the horizontal space. The hyperbolic maths stays circular — the stretch
  // is one final affine step on render, inverted again on input.
  let stretchX = 1;
  // Euclidean magnification of the disk on top of the Möbius navigation:
  // the circle simply gets bigger, anchored at the cursor.
  let viewScale = 1;
  let offX = 0;
  let offY = 0;
  let selected = -1;
  let hovered = -1;
  let animating = false;
  let animFrame = 0;
  let destroyed = false;

  // Flow-pulse animation along the focus paths — ~30fps, running only while
  // something is selected (and never under prefers-reduced-motion).
  let flowPhase = 0;
  let flowFrame = 0;
  let flowRunning = false;
  let flowLast = 0;
  function tickFlow(t: number): void {
    if (destroyed || selected < 0 || reduced) {
      flowRunning = false;
      return;
    }
    if (t - flowLast >= 33) {
      flowLast = t;
      flowPhase = (flowPhase + 0.3) % 26.5;
      // The layout transition already redraws every frame with the fresh
      // phase; drawing twice per frame would just double the work.
      if (!animating) draw();
    }
    flowFrame = requestAnimationFrame(tickFlow);
  }
  function ensureFlow(): void {
    if (flowRunning || reduced || selected < 0) return;
    flowRunning = true;
    flowFrame = requestAnimationFrame(tickFlow);
  }

  const effR = (): number => R * viewScale;
  const toScreen = (z: C): C => ({
    x: CX + offX + z.x * effR() * stretchX,
    y: CY + offY + z.y * effR(),
  });
  const toDisk = (mx: number, my: number): C => {
    const z = {
      x: (mx - CX - offX) / (effR() * stretchX),
      y: (my - CY - offY) / effR(),
    };
    const m = Math.sqrt(cAbs2(z));
    return m > 0.985 ? { x: (z.x / m) * 0.985, y: (z.y / m) * 0.985 } : z;
  };
  const conformal = (z: C): number => Math.max(0, 1 - cAbs2(z));
  const DRAW_MIN_R = 0.4;
  const nodeRadius = (id: number): number => {
    const base = 2.2 + Math.min(6, Math.sqrt(leaves[id]) * 0.7) + (model.isRoot[id] ? 1.2 : 0);
    // Cap the on-screen size: zooming should separate nodes, not inflate
    // them into each other.
    return Math.min(22, Math.max(0.35, base * conformal(pos[id]) * (effR() / 460)));
  };

  /**
   * Geodesic path construction happens in CIRCULAR disk space; the ellipse
   * stretch is applied by the canvas transform below, so arcs stay arcs and
   * the deferred stroke keeps a uniform line width.
   */
  function beginWarpPath(): void {
    if (!ctx) return;
    ctx.save();
    ctx.translate(CX + offX, CY + offY);
    ctx.scale(stretchX, 1);
    ctx.beginPath();
  }

  function strokeWarpPath(): void {
    if (!ctx) return;
    ctx.restore();
    ctx.stroke();
  }

  /** Geodesic between two disk points: arc orthogonal to the rim. Emits into
   * a beginWarpPath() context (centre-origin, unstretched screen units). */
  function geodesic(z1: C, z2: C): void {
    if (!ctx) return;
    const r0 = effR();
    const cross = z1.x * z2.y - z1.y * z2.x;
    if (Math.abs(cross) < 1e-4) {
      ctx.moveTo(z1.x * r0, z1.y * r0);
      ctx.lineTo(z2.x * r0, z2.y * r0);
      return;
    }
    const k1 = (cAbs2(z1) + 1) / 2;
    const k2 = (cAbs2(z2) + 1) / 2;
    const ccx = (k1 * z2.y - k2 * z1.y) / cross;
    const ccy = (k2 * z1.x - k1 * z2.x) / cross;
    const c = { x: ccx, y: ccy };
    const rad = Math.sqrt(Math.max(0, cAbs2(c) - 1));
    const a1 = Math.atan2(z1.y - ccy, z1.x - ccx);
    const a2 = Math.atan2(z2.y - ccy, z2.x - ccx);
    let delta = a2 - a1;
    while (delta > Math.PI) delta -= Math.PI * 2;
    while (delta < -Math.PI) delta += Math.PI * 2;
    ctx.moveTo(z1.x * r0, z1.y * r0);
    ctx.arc(c.x * r0, c.y * r0, rad * r0, a1, a1 + delta, delta < 0);
  }

  function draw(): void {
    if (!ctx || destroyed) return;
    const theme = cb.theme();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    // Disk face + range rings at equal hyperbolic distance (d_h = 2 atanh r).
    // Rendered as an ellipse when the stage is wider than tall.
    const dcx = CX + offX;
    const dcy = CY + offY;
    ctx.beginPath();
    ctx.ellipse(dcx, dcy, effR() * stretchX, effR(), 0, 0, Math.PI * 2);
    ctx.fillStyle = theme.isDark ? "#0a1219" : "#f6f9fc";
    ctx.fill();
    ctx.strokeStyle = theme.line;
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.strokeStyle = theme.isDark ? "#14202c" : "#e3eaf2";
    ctx.lineWidth = 1;
    for (let d = 1; d <= 5; d += 1) {
      const rd = Math.tanh(d * 0.55) * effR();
      ctx.beginPath();
      ctx.ellipse(dcx, dcy, rd * stretchX, rd, 0, 0, Math.PI * 2);
      ctx.stroke();
    }

    // Focus set: selected node, its path to root, and its direct neighbours.
    // The route back to the project and the selection's own dependencies are
    // different questions, so they get different colours (see the key).
    const depEdges: Array<[number, number]> = [];
    const pathEdges: Array<[number, number]> = [];
    let pathTop = -1;
    const focusSet = new Set<number>();
    if (selected >= 0) {
      focusSet.add(selected);
      for (const dep of model.depsOut[selected]) {
        focusSet.add(dep);
        depEdges.push([selected, dep]);
      }
      for (const from of model.depsIn[selected]) focusSet.add(from);
      let walk = selected;
      while (parent[walk] >= 0) {
        pathEdges.push([parent[walk], walk]);
        focusSet.add(parent[walk]);
        walk = parent[walk];
      }
      pathTop = walk;
    }

    // Tree edges of the layout on screen (the focus layout re-parents
    // packages, so drawing must follow the same tree the walk placed).
    // Selection dims the context only gently — keeping the whole tree
    // visible around the focus is the point of this view.
    ctx.lineWidth = 0.7;
    const edgeBase = theme.isDark ? "59, 76, 94" : "148, 163, 184";
    ctx.strokeStyle = `rgba(${edgeBase}, ${selected >= 0 ? 0.32 : 0.45})`;
    beginWarpPath();
    for (let id = 0; id < N; id += 1) {
      const p = activeParent[id];
      if (p < 0) continue;
      if (conformal(pos[id]) < 0.004 && conformal(pos[p]) < 0.004) continue;
      geodesic(pos[p], pos[id]);
    }
    strokeWarpPath();
    // Spokes from the project hub to the first ring.
    ctx.strokeStyle = `rgba(${edgeBase}, ${selected >= 0 ? 0.28 : 0.4})`;
    beginWarpPath();
    for (let id = 0; id < N; id += 1) {
      if (activeParent[id] === -1) geodesic(hubPos, pos[id]);
    }
    strokeWarpPath();

    if (selected >= 0) {
      // What the selection depends on — accent, hair-thin.
      ctx.lineWidth = 0.9;
      ctx.globalAlpha = 0.85;
      ctx.strokeStyle = theme.accent;
      beginWarpPath();
      for (const [a, b] of depEdges) geodesic(pos[a], pos[b]);
      strokeWarpPath();
      // The route that keeps it installed — warm amber, including the last
      // hop from the direct dependency to the project hub.
      ctx.lineWidth = 1.1;
      ctx.strokeStyle = theme.isDark ? "#f59e0b" : "#d97706";
      beginWarpPath();
      for (const [a, b] of pathEdges) geodesic(pos[a], pos[b]);
      if (pathTop >= 0) geodesic(hubPos, pos[pathTop]);
      strokeWarpPath();
      // Gentle flow pulses drifting along the focus paths (skipped under
      // prefers-reduced-motion): outward on the dependency links, homeward
      // on the route to the project.
      if (!reduced) {
        ctx.lineCap = "round";
        ctx.setLineDash([2.5, 24]);
        ctx.lineWidth = 1.7;
        ctx.globalAlpha = 0.8;
        ctx.strokeStyle = theme.accent;
        ctx.lineDashOffset = -flowPhase;
        beginWarpPath();
        for (const [a, b] of depEdges) geodesic(pos[a], pos[b]);
        strokeWarpPath();
        // Route edges are drawn parent→child, so the same negative offset
        // makes the flow arrive FROM the project into the selection —
        // dependencies flow down from the things that require them.
        ctx.strokeStyle = theme.isDark ? "#fbbf24" : "#b45309";
        ctx.lineDashOffset = -flowPhase;
        beginWarpPath();
        for (const [a, b] of pathEdges) geodesic(pos[a], pos[b]);
        if (pathTop >= 0) geodesic(hubPos, pos[pathTop]);
        strokeWarpPath();
        ctx.setLineDash([]);
        ctx.lineCap = "butt";
      }
      ctx.globalAlpha = 1;
    }

    // Nodes, small first so big blips sit on top. Radii cached once per
    // frame: nodeRadius is otherwise recomputed across sorting, rendering,
    // and both label filters.
    const radii = new Float32Array(N);
    for (let i = 0; i < N; i += 1) radii[i] = nodeRadius(i);
    const orderDraw = Array.from({ length: N }, (_, i) => i).sort(
      (a, b) => radii[a] - radii[b],
    );
    for (const id of orderDraw) {
      const r = radii[id];
      if (r < DRAW_MIN_R) continue;
      const p = toScreen(pos[id]);
      const vuln = model.refs[id].vulnerabilitySeverity;
      let fill = model.isRoot[id]
        ? theme.isDark
          ? "#ff9a58"
          : "#f97316"
        : theme.isDark
          ? "#5b7186"
          : "#94a8bc";
      if (vuln === "high") fill = theme.vulnHigh;
      let alpha = (model.isRoot[id] ? 0.95 : 0.8) * (model.isDev[id] ? 0.65 : 1);
      if (selected >= 0 && !focusSet.has(id)) alpha *= 0.45;
      if (cb.isDimmed(id) && id !== selected && id !== hovered) alpha *= 0.2;
      if (id === selected) fill = theme.accent;
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
      ctx.fillStyle = fill;
      ctx.fill();
      if (id === selected || id === hovered) {
        ctx.strokeStyle = theme.accent;
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 2.5, 0, Math.PI * 2);
        ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;

    // Project hub — transformed like everything else, never pinned.
    const hub = toScreen(hubPos);
    const hubR = Math.max(1.2, 5 * conformal(hubPos));
    ctx.beginPath();
    ctx.arc(hub.x, hub.y, hubR, 0, Math.PI * 2);
    ctx.fillStyle = theme.ink;
    ctx.fill();

    // Labels: whatever is currently big enough to matter.
    ctx.font = '10.5px ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace';
    ctx.textBaseline = "middle";
    const forced = orderDraw.filter(
      (id) => focusSet.has(id) || id === hovered || id === selected,
    );
    const sized = orderDraw.filter(
      (id) =>
        radii[id] > 3.4 &&
        !focusSet.has(id) &&
        id !== hovered &&
        id !== selected &&
        // A live name filter hands the label budget to the matches.
        !cb.isDimmed(id),
    );
    // Cap applies to size-qualified labels only; focus/hover/selection always
    // stay in, and lead so collision pruning favours them.
    const labelled = [...forced.reverse(), ...sized.slice(-70).reverse()];
    const placed: Array<[number, number, number, number]> = [];
    for (const id of labelled) {
      const r = radii[id];
      if (r < 1.4 && !focusSet.has(id) && id !== hovered) continue;
      const p = toScreen(pos[id]);
      const name = model.refs[id].name;
      const w = ctx.measureText(name).width;
      const x0 = p.x + r + 4;
      const y0 = p.y - 8;
      const x1 = x0 + w;
      const y1 = p.y + 8;
      let collides = false;
      for (const [ax0, ay0, ax1, ay1] of placed) {
        if (x0 < ax1 && x1 > ax0 && y0 < ay1 && y1 > ay0) {
          collides = true;
          break;
        }
      }
      if (collides && id !== selected && id !== hovered) continue;
      placed.push([x0, y0, x1, y1]);
      ctx.globalAlpha = selected >= 0 && !focusSet.has(id) && id !== hovered ? 0.45 : 0.9;
      ctx.fillStyle = id === selected ? theme.accent : theme.muted;
      ctx.fillText(name, x0, p.y);
    }
    ctx.globalAlpha = 1;
    if (hubR > 1.8) {
      ctx.fillStyle = theme.ink;
      ctx.textAlign = "center";
      ctx.fillText(model.projectName, hub.x, hub.y - hubR - 7);
      ctx.textAlign = "left";
    }
  }

  /** Apply a transform to every point INCLUDING the virtual hub. */
  function applyToAll(fn: (z: C) => C): void {
    for (let i = 0; i < N; i += 1) pos[i] = fn(pos[i]);
    hubPos = fn(hubPos);
  }

  let pendingLayout: Layout | null = null;

  function cancelAnim(): void {
    if (!animating) return;
    cancelAnimationFrame(animFrame);
    animating = false;
    // Never park the view mid-blend: an interpolated frame is not a valid
    // hyperbolic configuration, and every later drag would Mobius-transform
    // the mangled state. Snap to the in-flight target instead.
    if (pendingLayout) {
      applyLayout(pendingLayout);
      offX = 0;
      offY = 0;
      pendingLayout = null;
    }
  }

  /** Which node the current layout is centred on (HUB after a reset). */
  let layoutCenter = HUB;

  /**
   * Rotate a freshly computed layout (an isometry of the disk) so that
   * `anchorId` keeps the bearing it will have on screen after the carry —
   * subtrees stay on the side of the disk they started on instead of the
   * whole picture flipping to a canonical "everything up" orientation.
   */
  function orientLayout(
    layout: Layout,
    carry: C,
    anchorId: number,
  ): void {
    if (anchorId < HUB) return;
    const aEff = geodesicPoint(carry, 1);
    const current = anchorId === HUB ? hubPos : pos[anchorId];
    const from = mobiusNeg(aEff, current); // anchor's position once carried
    const to = anchorId === HUB ? layout.hub : layout.positions[anchorId];
    if (Math.hypot(from.x, from.y) < 1e-4 || Math.hypot(to.x, to.y) < 1e-4) return;
    const delta = Math.atan2(from.y, from.x) - Math.atan2(to.y, to.x);
    const c = Math.cos(delta);
    const s = Math.sin(delta);
    const rot = (z: C): C => ({ x: z.x * c - z.y * s, y: z.x * s + z.y * c });
    for (let i = 0; i < N; i += 1) layout.positions[i] = rot(layout.positions[i]);
    layout.hub = rot(layout.hub);
  }

  function focusOn(target: number): void {
    // Retarget any in-flight transition rather than dropping the request.
    cancelAnim();
    const layout = computeLayout(target);
    // Anchor on the way back up: the parent (or the hub for a direct dep)
    // keeps its bearing, so the focused subtree fans out where it was.
    orientLayout(layout, pos[target], parent[target] >= 0 ? parent[target] : HUB);
    layoutCenter = target;
    startLayoutTransition(pos[target], layout);
  }

  function resetLayout(): void {
    cancelAnim();
    const layout = computeLayout(HUB);
    // Going home: keep the previously focused node on the side it occupied.
    if (layoutCenter !== HUB) orientLayout(layout, hubPos, layoutCenter);
    layoutCenter = HUB;
    startLayoutTransition(hubPos, layout);
  }

  /** Ease-in-out: gentle at both ends — sudden starts read as jarring. */
  const easeInOut = (u: number): number =>
    u < 0.5 ? 2 * u * u : 1 - Math.pow(-2 * u + 2, 2) / 2;

  /** Point along the geodesic 0 → a at fraction u of the hyperbolic distance. */
  function geodesicPoint(a: C, u: number): C {
    const m = Math.sqrt(cAbs2(a));
    if (m < 1e-9) return { x: 0, y: 0 };
    const r = Math.tanh(Math.atanh(Math.min(m, 0.999999)) * u);
    return { x: (a.x / m) * r, y: (a.y / m) * r };
  }

  /**
   * Two-phase transition into a new layout centred on `carry` (the clicked
   * node's current position, or the hub's for a reset). Phase 1 is a pure
   * Möbius translation gliding `carry` to the centre — an isometry, so the
   * whole picture warps exactly as if dragged there, nothing crosses
   * anything. Phase 2 blends the small residual differences into the freshly
   * computed layout (which has the same node at the origin), then snaps.
   */
  function startLayoutTransition(carry: C, layout: Layout): void {
    const fromOffX = offX;
    const fromOffY = offY;
    if (reduced) {
      applyLayout(layout);
      offX = 0;
      offY = 0;
      draw();
      return;
    }
    animating = true;
    pendingLayout = layout;
    const base = pos.map((z) => ({ ...z }));
    const baseHub = { ...hubPos };
    const a = { ...carry };
    const carryDist = Math.sqrt(cAbs2(a));
    // Warped endpoint of phase 1 — computed with the SAME clamped endpoint
    // geodesicPoint(a, 1) that phase 1 converges to, so the phase boundary is
    // seamless even for carries parked at |z| > 0.999999 near the rim.
    const aEff = geodesicPoint(a, 1);
    const warped = base.map((z) => mobiusNeg(aEff, z));
    const warpedHub = mobiusNeg(aEff, baseHub);
    const durCarry = carryDist < 1e-4 ? 0 : 380;
    const durSettle = 300;
    const t0 = performance.now();
    const step = (t: number): void => {
      if (destroyed) return;
      const elapsed = t - t0;
      if (elapsed >= durCarry + durSettle) {
        // Snap exactly onto the computed layout: persisting lerped (let
        // alone clamped) values would flatten rim depth — nodes deep in a
        // chain live at |z| > 0.999 and must keep their true radii.
        applyLayout(layout);
        offX = 0;
        offY = 0;
        animating = false;
        pendingLayout = null;
        draw();
        return;
      }
      if (elapsed < durCarry) {
        const e = easeInOut(elapsed / durCarry);
        const shift = geodesicPoint(a, e);
        for (let i = 0; i < N; i += 1) pos[i] = mobiusNeg(shift, base[i]);
        hubPos = mobiusNeg(shift, baseHub);
        offX = fromOffX * (1 - e);
        offY = fromOffY * (1 - e);
      } else {
        const e = easeInOut((elapsed - durCarry) / durSettle);
        // No clamp needed mid-flight: both endpoints are interior to the
        // disk and the disk is convex.
        for (let i = 0; i < N; i += 1) {
          pos[i] = {
            x: warped[i].x + (layout.positions[i].x - warped[i].x) * e,
            y: warped[i].y + (layout.positions[i].y - warped[i].y) * e,
          };
        }
        hubPos = {
          x: warpedHub.x + (layout.hub.x - warpedHub.x) * e,
          y: warpedHub.y + (layout.hub.y - warpedHub.y) * e,
        };
        // With no carry phase the pan offset decays here instead.
        offX = durCarry === 0 ? fromOffX * (1 - e) : 0;
        offY = durCarry === 0 ? fromOffY * (1 - e) : 0;
      }
      draw();
      animFrame = requestAnimationFrame(step);
    };
    animFrame = requestAnimationFrame(step);
  }

  function pick(mx: number, my: number): number {
    let best = -1;
    let bestD = 12;
    for (let id = 0; id < N; id += 1) {
      if (nodeRadius(id) < DRAW_MIN_R) continue; // invisible => unpickable
      const p = toScreen(pos[id]);
      const d = Math.hypot(p.x - mx, p.y - my) - nodeRadius(id);
      if (d < bestD) {
        bestD = d;
        best = id;
      }
    }
    return best;
  }

  function trailOf(id: number): number[] {
    const ids = [id];
    let walk = id;
    let guard = 0;
    while (parent[walk] >= 0 && guard < 128) {
      walk = parent[walk];
      ids.unshift(walk);
      guard += 1;
    }
    return ids;
  }

  let dragging = false;
  let movedInDrag = false;
  let last: C | null = null;
  let downX = 0;
  let downY = 0;
  /** Hit under the cursor at pointerdown, BEFORE cancelAnim snaps an
   *  in-flight transition: a stationary click must select what was seen. */
  let downHit = -1;
  canvas.addEventListener(
    "pointerdown",
    (e) => {
      downHit = pick(e.offsetX, e.offsetY);
      cancelAnim();
      dragging = true;
      movedInDrag = false;
      downX = e.offsetX;
      downY = e.offsetY;
      last = toDisk(e.offsetX, e.offsetY);
      canvas.classList.add("dragging");
      canvas.setPointerCapture(e.pointerId);
    },
    { signal },
  );
  canvas.addEventListener(
    "pointermove",
    (e) => {
      if (!dragging) {
        const h = pick(e.offsetX, e.offsetY);
        if (h !== hovered) {
          hovered = h;
          canvas.style.cursor = h >= 0 ? "pointer" : "grab";
          cb.onHoverTrail(h >= 0 ? trailOf(h) : null);
          draw();
        }
        return;
      }
      if (!last) return;
      const now = toDisk(e.offsetX, e.offsetY);
      // Cumulative screen-space threshold: slow drags must not read as clicks.
      if (Math.hypot(e.offsetX - downX, e.offsetY - downY) > 3) movedInDrag = true;
      const from = last;
      applyToAll((z) => mobius(now, mobiusNeg(from, z)));
      last = now;
      draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "pointerup",
    () => {
      dragging = false;
      canvas.classList.remove("dragging");
      if (movedInDrag) return;
      const id = downHit;
      selected = id;
      cb.onSelect(id);
      if (id >= 0) {
        focusOn(id);
        ensureFlow();
      } else draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "pointercancel",
    () => {
      dragging = false;
      movedInDrag = false;
      last = null;
      canvas.classList.remove("dragging");
    },
    { signal },
  );
  canvas.addEventListener(
    "pointerleave",
    () => {
      if (hovered < 0) return;
      hovered = -1;
      canvas.style.cursor = "grab";
      cb.onHoverTrail(null);
      draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      const f = Math.exp(-e.deltaY * 0.0016);
      const next = Math.min(12, Math.max(1, viewScale * f));
      if (next === viewScale) return;
      // Keep the disk point under the cursor fixed on screen.
      const pxd = (e.offsetX - CX - offX) / effR();
      const pyd = (e.offsetY - CY - offY) / effR();
      viewScale = next;
      offX = e.offsetX - CX - pxd * effR();
      offY = e.offsetY - CY - pyd * effR();
      draw();
    },
    { signal, passive: false },
  );
  canvas.addEventListener(
    "dblclick",
    (e) => {
      if (pick(e.offsetX, e.offsetY) >= 0) return;
      selected = -1;
      cb.onSelect(-1);
      viewScale = 1;
      resetLayout();
    },
    { signal },
  );

  function resize(): void {
    W = host.clientWidth;
    H = host.clientHeight;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    // Centre the disk in the region not covered by the floating side panel,
    // toolbar, or status line.
    const usable = Math.max(160, W - cb.insetRight());
    const usableH = Math.max(160, H - cb.insetTop() - 30);
    CX = usable / 2;
    CY = cb.insetTop() + usableH / 2;
    R = Math.min(usable, usableH) / 2 - 24;
    // Wider-than-tall stages stretch the disk into an ellipse — capped, so
    // ultrawide windows don't smear the geometry into unreadability.
    stretchX = Math.min(1.45, Math.max(1, (usable / 2 - 24) / Math.max(1, R)));
    draw();
  }
  window.addEventListener("resize", resize, { signal });
  resize();

  return {
    destroy() {
      destroyed = true;
      cancelAnimationFrame(animFrame);
      cancelAnimationFrame(flowFrame);
      aborter.abort();
      canvas.remove();
    },
    resize,
    focusIndex(index: number) {
      if (index < 0 || index >= N) return;
      selected = index;
      focusOn(index);
      ensureFlow();
    },
    resetView() {
      viewScale = 1;
      resetLayout();
    },
  };
}
