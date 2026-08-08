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
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
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

  function placeSubtree(id: number, wedgeMid: number, wedge: number): void {
    const kids = children[id];
    if (!kids.length) return;
    const rho = Math.min(0.82, 0.42 + 0.05 * Math.sqrt(kids.length));
    const total = kids.reduce((s, c) => s + leaves[c], 0);
    let start = wedgeMid - wedge / 2;
    for (const kid of kids) {
      const share = (leaves[kid] / total) * wedge;
      const ang = start + share / 2;
      start += share;
      const local = { x: rho * Math.cos(ang), y: rho * Math.sin(ang) };
      const g = mobius(pos[id], local);
      pos[kid] = g;
      // Outward direction in the kid's own frame: away from its parent.
      const parentLocal = mobiusNeg(g, pos[id]);
      const out = Math.atan2(parentLocal.y, parentLocal.x) + Math.PI;
      placeSubtree(kid, out, Math.min(share * 0.92, 2.4));
    }
  }

  function rebuildPositions(): void {
    hubPos = { x: 0, y: 0 };
    const sorted = [...roots].sort((a, b) => leaves[b] - leaves[a] || a - b);
    const total = sorted.reduce((s, r) => s + rootWeight(r), 0) || 1;
    let start = -Math.PI / 2;
    for (const r of sorted) {
      const share = (rootWeight(r) / total) * Math.PI * 2;
      const ang = start + share / 2;
      start += share;
      const rho = 0.52;
      pos[r] = { x: rho * Math.cos(ang), y: rho * Math.sin(ang) };
      placeSubtree(r, ang, Math.min(share * 0.92, 2.4));
    }
  }
  rebuildPositions();

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
  const nodeRadius = (id: number): number => {
    const base = 2.2 + Math.min(6, Math.sqrt(leaves[id]) * 0.7) + (model.isRoot[id] ? 1.2 : 0);
    return Math.max(0.35, base * conformal(pos[id]) * (effR() / 460));
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

    // Nodes, small first so big blips sit on top.
    const orderDraw = Array.from({ length: N }, (_, i) => i).sort(
      (a, b) => nodeRadius(a) - nodeRadius(b),
    );
    for (const id of orderDraw) {
      const r = nodeRadius(id);
      if (r < 0.4) continue;
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
    const labelled = orderDraw
      .filter((id) => nodeRadius(id) > 3.4 || focusSet.has(id) || id === hovered)
      .slice(-70);
    for (const id of labelled) {
      const r = nodeRadius(id);
      if (r < 1.4 && !focusSet.has(id) && id !== hovered) continue;
      const p = toScreen(pos[id]);
      ctx.globalAlpha = selected >= 0 && !focusSet.has(id) && id !== hovered ? 0.3 : 0.9;
      ctx.fillStyle = id === selected ? theme.accent : theme.muted;
      ctx.fillText(model.refs[id].name, p.x + r + 4, p.y);
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

  function focusOn(target: number): void {
    if (animating) return;
    const a = { ...pos[target] };
    if (Math.sqrt(cAbs2(a)) < 0.01 || reduced) {
      applyToAll((z) => mobiusNeg(a, z));
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
      const at = { x: a.x * e, y: a.y * e };
      for (let i = 0; i < N; i += 1) pos[i] = mobiusNeg(at, base[i]);
      hubPos = mobiusNeg(at, baseHub);
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
  canvas.addEventListener(
    "pointerdown",
    (e) => {
      dragging = true;
      movedInDrag = false;
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
      if (Math.hypot(now.x - last.x, now.y - last.y) > 0.002) movedInDrag = true;
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
      offX = 0;
      offY = 0;
      rebuildPositions();
      draw();
    },
    { signal },
  );

  function resize(): void {
    W = host.clientWidth;
    H = host.clientHeight;
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
      selected = index;
      focusOn(index);
    },
    resetView() {
      viewScale = 1;
      offX = 0;
      offY = 0;
      rebuildPositions();
      draw();
    },
  };
}
