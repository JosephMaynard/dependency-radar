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
  host.appendChild(canvas);
  const ctx = canvas.getContext("2d");
  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  const aborter = new AbortController();
  const signal = aborter.signal;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const N = model.count;
  const { parent, children, leaves, roots } = model;

  const pos: C[] = Array.from({ length: N }, () => ({ x: 0, y: 0 }));
  let hubPos: C = { x: 0, y: 0 };

  // Small roots get a floor on their wedge share so leafless direct deps
  // don't smear into slivers.
  const rootWeight = (r: number): number => Math.sqrt(leaves[r]) + 1.5;

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

  function neighborsFrom(
    id: number,
    cameFrom: number,
  ): Array<{ next: number; weight: number }> {
    if (id === HUB) {
      return hubKids
        .filter((r) => r !== cameFrom)
        .map((r) => ({ next: r, weight: rootWeight(r) }));
    }
    const list: Array<{ next: number; weight: number }> = [];
    for (const kid of children[id]) {
      if (kid !== cameFrom) list.push({ next: kid, weight: Math.max(leaves[kid], 0.5) });
    }
    const upId = parent[id] === -1 ? HUB : parent[id];
    if (upId !== cameFrom) {
      // Everything that is NOT below this node lies in the parent direction.
      list.push({ next: upId, weight: Math.max(totalLeaves - leaves[id], 1) });
    }
    return list;
  }

  /** Lay the whole tree out around `centerId` (HUB or a package index). */
  function computeLayout(centerId: number): { positions: C[]; hub: C } {
    const positions: C[] = Array.from({ length: N }, () => ({ x: 0, y: 0 }));
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
    while (stack.length > 0) {
      const frame = stack.pop();
      if (!frame) break;
      const { id, cameFrom, mid, wedge } = frame;
      const around = neighborsFrom(id, cameFrom);
      if (around.length === 0) continue;
      const isCenter = cameFrom === CAME_NONE;
      // 0.8 factor: 20% shorter links keep systems visually attached.
      const rhoBase = isCenter
        ? 0.42
        : Math.min(0.66, 0.34 + 0.04 * Math.sqrt(around.length));
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
            ? Math.min(0.72, rhoBase + ((index % 3) - 1) * 0.072)
            : rhoBase;
        index += 1;
        const local = { x: rho * Math.cos(ang), y: rho * Math.sin(ang) };
        const g = mobius(getP(id), local);
        setP(next, g);
        // Outward direction in the neighbour's own frame: away from here.
        const parentLocal = mobiusNeg(g, getP(id));
        const out = Math.atan2(parentLocal.y, parentLocal.x) + Math.PI;
        stack.push({ id: next, cameFrom: id, mid: out, wedge: Math.min(share * 0.92, 2.4) });
      }
    }
    return { positions, hub };
  }

  function applyLayout(layout: { positions: C[]; hub: C }): void {
    for (let i = 0; i < N; i += 1) pos[i] = layout.positions[i];
    hubPos = layout.hub;
  }

  applyLayout(computeLayout(HUB));

  let W = 0;
  let H = 0;
  let CX = 0;
  let CY = 0;
  let R = 0;
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

  const effR = (): number => R * viewScale;
  const toScreen = (z: C): C => ({ x: CX + offX + z.x * effR(), y: CY + offY + z.y * effR() });
  const toDisk = (mx: number, my: number): C => {
    const z = { x: (mx - CX - offX) / effR(), y: (my - CY - offY) / effR() };
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

  /** Geodesic between two disk points: arc orthogonal to the rim. */
  function geodesic(z1: C, z2: C): void {
    if (!ctx) return;
    const cross = z1.x * z2.y - z1.y * z2.x;
    const p1 = toScreen(z1);
    const p2 = toScreen(z2);
    if (Math.abs(cross) < 1e-4) {
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
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
    const sc = toScreen(c);
    ctx.moveTo(p1.x, p1.y);
    ctx.arc(sc.x, sc.y, rad * effR(), a1, a1 + delta, delta < 0);
  }

  function draw(): void {
    if (!ctx || destroyed) return;
    const theme = cb.theme();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    // Disk face + range rings at equal hyperbolic distance (d_h = 2 atanh r).
    const dcx = CX + offX;
    const dcy = CY + offY;
    ctx.beginPath();
    ctx.arc(dcx, dcy, effR(), 0, Math.PI * 2);
    ctx.fillStyle = theme.isDark ? "#0a1219" : "#f6f9fc";
    ctx.fill();
    ctx.strokeStyle = theme.line;
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.strokeStyle = theme.isDark ? "#14202c" : "#e3eaf2";
    ctx.lineWidth = 1;
    for (let d = 1; d <= 5; d += 1) {
      ctx.beginPath();
      ctx.arc(dcx, dcy, Math.tanh(d * 0.55) * effR(), 0, Math.PI * 2);
      ctx.stroke();
    }

    // Focus set: selected node, its path to root, and its direct neighbours.
    const focusEdges: Array<[number, number]> = [];
    const focusSet = new Set<number>();
    if (selected >= 0) {
      focusSet.add(selected);
      for (const dep of model.depsOut[selected]) {
        focusSet.add(dep);
        focusEdges.push([selected, dep]);
      }
      for (const from of model.depsIn[selected]) focusSet.add(from);
      let walk = selected;
      while (parent[walk] >= 0) {
        focusEdges.push([parent[walk], walk]);
        focusSet.add(parent[walk]);
        walk = parent[walk];
      }
    }

    // Spanning-tree edges.
    ctx.lineWidth = 0.7;
    const edgeBase = theme.isDark ? "59, 76, 94" : "148, 163, 184";
    ctx.strokeStyle = `rgba(${edgeBase}, ${selected >= 0 ? 0.22 : 0.45})`;
    ctx.beginPath();
    for (let id = 0; id < N; id += 1) {
      if (parent[id] < 0) continue;
      if (conformal(pos[id]) < 0.004 && conformal(pos[parent[id]]) < 0.004) continue;
      geodesic(pos[parent[id]], pos[id]);
    }
    ctx.stroke();
    // Spokes from the project hub to the first ring.
    ctx.strokeStyle = `rgba(${edgeBase}, ${selected >= 0 ? 0.18 : 0.4})`;
    ctx.beginPath();
    for (const r of roots) geodesic(hubPos, pos[r]);
    ctx.stroke();

    if (selected >= 0) {
      ctx.lineWidth = 1.4;
      ctx.strokeStyle = theme.accent;
      ctx.beginPath();
      for (const [a, b] of focusEdges) geodesic(pos[a], pos[b]);
      ctx.stroke();
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
      if (selected >= 0 && !focusSet.has(id)) alpha *= 0.25;
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
      ctx.globalAlpha = selected >= 0 && !focusSet.has(id) && id !== hovered ? 0.3 : 0.9;
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

  function cancelAnim(): void {
    if (!animating) return;
    cancelAnimationFrame(animFrame);
    animating = false;
  }

  function focusOn(target: number): void {
    // Retarget any in-flight transition rather than dropping the request.
    cancelAnim();
    startLayoutTransition(computeLayout(target));
  }

  function resetLayout(): void {
    cancelAnim();
    startLayoutTransition(computeLayout(HUB));
  }

  const clampDisk = (z: C): C => {
    const m = Math.sqrt(cAbs2(z));
    return m > 0.995 ? { x: (z.x / m) * 0.995, y: (z.y / m) * 0.995 } : z;
  };

  function startLayoutTransition(layout: { positions: C[]; hub: C }): void {
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
    const base = pos.map((z) => ({ ...z }));
    const baseHub = { ...hubPos };
    const t0 = performance.now();
    const dur = 420;
    const step = (t: number): void => {
      if (destroyed) return;
      const u = Math.min(1, (t - t0) / dur);
      const e = 1 - Math.pow(1 - u, 3);
      for (let i = 0; i < N; i += 1) {
        pos[i] = clampDisk({
          x: base[i].x + (layout.positions[i].x - base[i].x) * e,
          y: base[i].y + (layout.positions[i].y - base[i].y) * e,
        });
      }
      hubPos = clampDisk({
        x: baseHub.x + (layout.hub.x - baseHub.x) * e,
        y: baseHub.y + (layout.hub.y - baseHub.y) * e,
      });
      offX = fromOffX * (1 - e);
      offY = fromOffY * (1 - e);
      draw();
      if (u < 1) animFrame = requestAnimationFrame(step);
      else animating = false;
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
  canvas.addEventListener(
    "pointerdown",
    (e) => {
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
    (e) => {
      dragging = false;
      canvas.classList.remove("dragging");
      if (movedInDrag) return;
      const id = pick(e.offsetX, e.offsetY);
      selected = id;
      cb.onSelect(id);
      if (id >= 0) focusOn(id);
      else draw();
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
    draw();
  }
  window.addEventListener("resize", resize, { signal });
  resize();

  return {
    destroy() {
      destroyed = true;
      cancelAnimationFrame(animFrame);
      aborter.abort();
      canvas.remove();
    },
    resize,
    focusIndex(index: number) {
      if (index < 0 || index >= N) return;
      selected = index;
      focusOn(index);
    },
    resetView() {
      viewScale = 1;
      resetLayout();
    },
  };
}
