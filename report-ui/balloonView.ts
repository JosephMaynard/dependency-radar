import type { VizCallbacks, VizHandle, VizModel } from "./vizModel";

// Balloon / "constellation" view: project as central body, direct deps
// orbiting, each node's children fanned on an arc facing away from its
// parent, recursively. Ported from the constellation prototype. Every odd
// constant here fixed a real failure — see docs/VIZ-VIEWS-HANDOFF.md §5.2.

const FAN = 3.6; // radians of arc a hub's children may occupy
const SHRINK = 0.52; // each level is a scaled-down copy: series must converge
const CENTER_R = 64;
const CELL = 64; // spatial hash cell, world units
const MAJOR_ENC = 150; // roots at least this enclosing radius arc-pack the outer ring

export function mountBalloonView(
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

  // Sub-linear node size: one monster can't blow out the dynamic range.
  const nodeRadius = (id: number): number =>
    Math.min(70, 2.2 + Math.pow(model.subSize[id], 0.34) * 1.1);

  // Enclosing radius of a subtree's balloon in local units, memoised.
  const encMemo = new Float64Array(model.count).fill(-1);
  const encLocal = (id: number, path: Set<number>): number => {
    if (encMemo[id] >= 0) return encMemo[id];
    const r = nodeRadius(id);
    const kids = model.kidsOf[id];
    if (!kids.length || path.has(id)) {
      if (!path.has(id)) encMemo[id] = r;
      return r;
    }
    path.add(id);
    let arc = 0;
    let maxKid = 0;
    for (const kid of kids) {
      const e = SHRINK * encLocal(kid, path);
      arc += 2 * e * 1.12;
      maxKid = Math.max(maxKid, e);
    }
    path.delete(id);
    const dist = Math.max(r + maxKid + 6, arc / FAN);
    encMemo[id] = dist + maxKid;
    return encMemo[id];
  };
  for (const r of model.rootsSorted) encLocal(r, new Set());

  // Flat placement arrays; `unit` is the world scale of the subtree's level.
  const px: number[] = [];
  const py: number[] = [];
  const pr: number[] = [];
  const pid: number[] = [];
  const pparent: number[] = [];
  const pdepth: number[] = [];
  const phue: number[] = [];
  function place(
    id: number,
    x: number,
    y: number,
    dir: number,
    depthIdx: number,
    parentIdx: number,
    hue: number,
    unit: number,
    path: Set<number>,
  ): number {
    const idx = px.length;
    px.push(x);
    py.push(y);
    pr.push(nodeRadius(id) * unit);
    pid.push(id);
    pparent.push(parentIdx);
    pdepth.push(depthIdx);
    phue.push(hue);
    if (path.has(id)) return idx;
    const kids = model.kidsOf[id];
    if (!kids.length) return idx;
    path.add(id);
    let arc = 0;
    let maxKid = 0;
    for (const kid of kids) {
      const e = SHRINK * encMemo[kid];
      arc += 2 * e * 1.12;
      maxKid = Math.max(maxKid, e);
    }
    const dist = Math.max(nodeRadius(id) + maxKid + 6, arc / FAN) * unit;
    let a = dir - Math.min(FAN, (arc * unit) / dist) / 2;
    for (const kid of kids) {
      const share = (2 * SHRINK * encMemo[kid] * 1.12 * unit) / dist;
      const ang = a + share / 2;
      a += share;
      place(
        kid,
        x + Math.cos(ang) * dist,
        y + Math.sin(ang) * dist,
        ang,
        depthIdx + 1,
        idx,
        hue,
        unit * SHRINK,
        path,
      );
    }
    path.delete(id);
    return idx;
  }

  // Two tiers like a real orrery: heavy systems arc-packed on the outer
  // ring, lightweight deps evenly spaced on a tidy inner orbit.
  {
    const majors = model.rootsSorted.filter((r) => encMemo[r] >= MAJOR_ENC);
    const minors = model.rootsSorted.filter((r) => encMemo[r] < MAJOR_ENC);
    let arc = 0;
    let maxRoot = 0;
    for (const r of majors) {
      arc += 2 * encMemo[r] * 1.1;
      maxRoot = Math.max(maxRoot, encMemo[r]);
    }
    const dist = Math.max(CENTER_R + maxRoot + 30, arc / (Math.PI * 2));
    let a = -Math.PI / 2;
    for (const r of majors) {
      const share = (2 * encMemo[r] * 1.1) / dist;
      const ang = a + share / 2;
      a += share;
      place(r, Math.cos(ang) * dist, Math.sin(ang) * dist, ang, 0, -1, model.rootHue.get(r) ?? 210, 1, new Set());
    }
    // Arc-pack the minor orbit too: each root gets angular share proportional
    // to its enclosing radius (even-by-count spacing let larger minors overlap
    // their neighbours into a solid rope on real monorepos).
    const minorShare = (r: number): number => 2 * Math.max(encMemo[r], 34) * 1.15;
    const minorArc = minors.reduce((s2, r) => s2 + minorShare(r), 0);
    const minorDist = Math.max(
      majors.length ? dist * 0.34 : 0,
      CENTER_R + 120,
      minorArc / (Math.PI * 2),
    );
    let am = -Math.PI / 2;
    for (const r of minors) {
      const share = minorShare(r) / minorDist;
      const ang = am + share / 2;
      am += share;
      place(r, Math.cos(ang) * minorDist, Math.sin(ang) * minorDist, ang, 0, -1, model.rootHue.get(r) ?? 210, 1, new Set());
    }
  }
  const COUNT = px.length;

  // Spatial grid for hover/click (bodies big enough to touch).
  const grid = new Map<string, number[]>();
  for (let i = 0; i < COUNT; i += 1) {
    if (pr[i] < 1.6) continue;
    const key = `${Math.floor(px[i] / CELL)},${Math.floor(py[i] / CELL)}`;
    const list = grid.get(key) ?? [];
    list.push(i);
    grid.set(key, list);
  }
  const firstIdxOf = new Map<number, number>();
  for (let i = 0; i < COUNT; i += 1) {
    if (!firstIdxOf.has(pid[i])) firstIdxOf.set(pid[i], i);
  }

  // With hundreds of direct deps the 9 px hub floor forces ring overlap at
  // fit zoom; relax it as root count grows (still never invisible).
  const hubFloor = model.roots.length > 120 ? 5 : model.roots.length > 60 ? 7 : 9;
  let W = 0;
  let H = 0;
  /** Usable width: canvas width minus the floating panel's cover. */
  const usableW = (): number => Math.max(120, W - cb.insetRight());
  /** Usable height: below the floating toolbar, above the status line. */
  const usableH = (): number => Math.max(120, H - cb.insetTop() - 30);
  const centreY = (): number => cb.insetTop() + usableH() / 2;
  let vx = 0;
  let vy = 0;
  let scale = 1;
  let hovered = -1;
  let selectedIdx = -1;
  let interacting = 0;
  let idleTimer = 0;
  let flyFrame = 0;
  let destroyed = false;

  function fitView(): void {
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (let i = 0; i < COUNT; i += 1) {
      minX = Math.min(minX, px[i] - pr[i]);
      maxX = Math.max(maxX, px[i] + pr[i]);
      minY = Math.min(minY, py[i] - pr[i]);
      maxY = Math.max(maxY, py[i] + pr[i]);
    }
    if (!Number.isFinite(minX)) {
      vx = 0;
      vy = 0;
      scale = 1;
      return;
    }
    vx = (minX + maxX) / 2;
    vy = (minY + maxY) / 2;
    scale = Math.max(
      1e-4,
      Math.min(usableW() / Math.max(1, maxX - minX), usableH() / Math.max(1, maxY - minY)) * 0.94,
    );
  }
  const sx = (x: number): number => (x - vx) * scale + usableW() / 2;
  const sy = (y: number): number => (y - vy) * scale + centreY();

  function draw(): void {
    if (!ctx || destroyed) return;
    const theme = cb.theme();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    const lodMin = interacting ? 0.9 : 0.35;
    const mono = 'ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace';
    const bodyL = theme.isDark ? [30, 20] : [72, 82];
    const strokeL = theme.isDark ? 64 : 38;

    // Edges first — always visible, satellite style.
    ctx.lineWidth = 0.6;
    for (let i = 0; i < COUNT; i += 1) {
      const r = Math.max(pr[i] * scale, pdepth[i] === 0 ? Math.min(hubFloor, 2.4) : pdepth[i] === 1 ? 2.4 : 0);
      if (r < 1.1) continue;
      const x = sx(px[i]);
      const y = sy(py[i]);
      const pIdx = pparent[i];
      const pxs = pIdx < 0 ? sx(0) : sx(px[pIdx]);
      const pys = pIdx < 0 ? sy(0) : sy(py[pIdx]);
      if (
        (x < -60 && pxs < -60) ||
        (x > W + 60 && pxs > W + 60) ||
        (y < -60 && pys < -60) ||
        (y > H + 60 && pys > H + 60)
      ) {
        continue;
      }
      ctx.strokeStyle = `hsla(${phue[i]} 30% ${theme.isDark ? 62 : 45}% / ${Math.min(0.5, 0.16 + r * 0.01)})`;
      ctx.beginPath();
      ctx.moveTo(pxs, pys);
      ctx.lineTo(x, y);
      ctx.stroke();
    }

    // Bodies — hubs keep a minimum screen size like cities on a map, and at
    // idle every node keeps at least a visible dot so the fitted overview
    // shows the whole tree.
    for (let i = 0; i < COUNT; i += 1) {
      const minR = pdepth[i] === 0 ? hubFloor : pdepth[i] === 1 ? 2.4 : interacting ? 0 : 0.85;
      const r = Math.max(pr[i] * scale, minR);
      if (r < lodMin) continue;
      const x = sx(px[i]);
      const y = sy(py[i]);
      if (x < -r - 40 || x > W + r + 40 || y < -r - 40 || y > H + r + 40) continue;
      const hue = phue[i];
      const id = pid[i];
      const dev = model.isDev[id];
      const vuln = model.refs[id].vulnerabilitySeverity;
      const hl = i === hovered || i === selectedIdx;
      if (r < 1.6) {
        ctx.fillStyle = `hsla(${hue} 34% ${theme.isDark ? 58 : 44}% / ${dev ? 0.35 : 0.55})`;
        ctx.fillRect(x - r / 2, y - r / 2, r, r);
        continue;
      }
      ctx.beginPath();
      ctx.arc(x, y, Math.max(0.01, r), 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${hue} 32% ${pdepth[i] === 0 ? bodyL[0] : bodyL[1]}% / ${dev ? 0.62 : 0.9})`;
      ctx.fill();
      ctx.lineWidth = hl ? 1.8 : Math.min(1.4, 0.5 + r * 0.02);
      ctx.strokeStyle = hl
        ? theme.accent
        : vuln === "high"
          ? theme.vulnHigh
          : vuln === "moderate"
            ? theme.vulnModerate
            : `hsla(${hue} 42% ${strokeL - pdepth[i] * 4}% / 0.9)`;
      ctx.stroke();
    }

    // Central body.
    {
      const x = sx(0);
      const y = sy(0);
      const r = Math.max(0.01, CENTER_R * scale);
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = theme.isDark ? "#0d1622" : "#f1f5f9";
      ctx.fill();
      ctx.lineWidth = 1.6;
      ctx.strokeStyle = theme.ink;
      ctx.stroke();
      if (r > 22) {
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.font = `600 ${Math.min(15, r * 0.24)}px ${mono}`;
        ctx.fillStyle = theme.panelText;
        ctx.fillText(model.projectName, x, y - r * 0.1);
        ctx.font = `${Math.min(11, r * 0.16)}px ${mono}`;
        ctx.fillStyle = theme.muted;
        ctx.fillText(`${Math.round(model.totalSize).toLocaleString()} blocks`, x, y + r * 0.2);
        ctx.textAlign = "left";
      }
    }

    // Labels — satellite style, biggest-on-screen-first budget.
    if (!interacting) {
      ctx.textBaseline = "middle";
      const candidates: Array<{ i: number; r: number }> = [];
      for (let i = 0; i < COUNT; i += 1) {
        const r = Math.max(pr[i] * scale, pdepth[i] === 0 ? hubFloor : 0);
        // Roots stay label-eligible even when the adaptive floor dips below
        // the general threshold; collision pruning keeps the count sane.
        if (r < (pdepth[i] === 0 ? Math.min(7.5, hubFloor) : 7.5)) continue;
        const x = sx(px[i]);
        const y = sy(py[i]);
        if (x < -220 || x > W + 40 || y < -40 || y > H + 40) continue;
        candidates.push({ i, r });
      }
      candidates.sort((a, b) => b.r - a.r);
      const placed: Array<[number, number, number, number]> = [];
      let labelsDrawn = 0;
      ctx.font = `600 10.5px ${mono}`;
      for (const { i, r } of candidates) {
        if (labelsDrawn >= 110) break;
        const x = sx(px[i]);
        const y = sy(py[i]);
        const name = model.refs[pid[i]].name;
        const w = ctx.measureText(name).width;
        const x0 = x + r + 5;
        const y0 = y - 14;
        const x1 = x0 + w;
        const y1 = y + 14;
        // Skip labels that would collide with one already placed — the
        // biggest-first order means the important ones win.
        let collides = false;
        for (const [ax0, ay0, ax1, ay1] of placed) {
          if (x0 < ax1 && x1 > ax0 && y0 < ay1 && y1 > ay0) {
            collides = true;
            break;
          }
        }
        if (collides && i !== hovered && i !== selectedIdx) continue;
        placed.push([x0, y0, x1, y1]);
        labelsDrawn += 1;
        ctx.font = `600 10.5px ${mono}`;
        ctx.fillStyle =
          i === hovered || i === selectedIdx
            ? theme.accent
            : theme.isDark
              ? "#aabdd0"
              : "#3f5266";
        ctx.fillText(name, x0, y - 6);
        ctx.font = `10px ${mono}`;
        ctx.fillStyle = theme.muted;
        ctx.fillText(Math.round(model.subSize[pid[i]]).toLocaleString(), x0, y + 7);
      }
    }
  }

  function pickAt(mx: number, my: number): number {
    const wx = (mx - usableW() / 2) / scale + vx;
    const wy = (my - centreY()) / scale + vy;
    const cx = Math.floor(wx / CELL);
    const cyy = Math.floor(wy / CELL);
    let best = -1;
    let bestD = 10 / scale;
    for (let gx = cx - 1; gx <= cx + 1; gx += 1) {
      for (let gy = cyy - 1; gy <= cyy + 1; gy += 1) {
        const list = grid.get(`${gx},${gy}`);
        if (!list) continue;
        for (const i of list) {
          const d = Math.hypot(px[i] - wx, py[i] - wy) - pr[i];
          if (d < bestD) {
            bestD = d;
            best = i;
          }
        }
      }
    }
    return best;
  }

  function trailOf(i: number): number[] {
    const ids: number[] = [];
    let cur = i;
    while (cur >= 0) {
      ids.unshift(pid[cur]);
      cur = pparent[cur];
    }
    return ids;
  }

  function poke(): void {
    interacting = 1;
    window.clearTimeout(idleTimer);
    idleTimer = window.setTimeout(() => {
      interacting = 0;
      draw();
    }, 160);
  }

  let dragging = false;
  let movedInDrag = false;
  let lastX = 0;
  let lastY = 0;
  canvas.addEventListener(
    "pointerdown",
    (e) => {
      dragging = true;
      movedInDrag = false;
      lastX = e.offsetX;
      lastY = e.offsetY;
      canvas.classList.add("dragging");
      canvas.setPointerCapture(e.pointerId);
    },
    { signal },
  );
  canvas.addEventListener(
    "pointermove",
    (e) => {
      if (dragging) {
        const dx = e.offsetX - lastX;
        const dy = e.offsetY - lastY;
        if (Math.abs(dx) + Math.abs(dy) > 2) movedInDrag = true;
        vx -= dx / scale;
        vy -= dy / scale;
        lastX = e.offsetX;
        lastY = e.offsetY;
        poke();
        draw();
        return;
      }
      const h = pickAt(e.offsetX, e.offsetY);
      if (h !== hovered) {
        hovered = h;
        canvas.style.cursor = h >= 0 ? "pointer" : "grab";
        cb.onHoverTrail(h >= 0 ? trailOf(h) : null);
        draw();
      }
    },
    { signal },
  );
  canvas.addEventListener(
    "pointerup",
    (e) => {
      dragging = false;
      canvas.classList.remove("dragging");
      if (movedInDrag) return;
      const i = pickAt(e.offsetX, e.offsetY);
      selectedIdx = i;
      cb.onSelect(i >= 0 ? pid[i] : -1);
      draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      const f = Math.exp(-e.deltaY * 0.0016);
      const wx = (e.offsetX - usableW() / 2) / scale + vx;
      const wy = (e.offsetY - centreY()) / scale + vy;
      scale = Math.min(600, Math.max(0.05, scale * f));
      vx = wx - (e.offsetX - usableW() / 2) / scale;
      vy = wy - (e.offsetY - centreY()) / scale;
      poke();
      draw();
    },
    { signal, passive: false },
  );
  canvas.addEventListener(
    "dblclick",
    (e) => {
      if (pickAt(e.offsetX, e.offsetY) >= 0) return;
      fitView();
      selectedIdx = -1;
      cb.onSelect(-1);
      draw();
    },
    { signal },
  );

  function flyTo(idx: number): void {
    const targetScale = Math.min(24, Math.max(1.2, 42 / pr[idx]));
    const fromX = vx;
    const fromY = vy;
    const fromS = scale;
    const t0 = performance.now();
    const dur = reduced ? 0 : 500;
    const step = (t: number): void => {
      if (destroyed) return;
      const u = dur ? Math.min(1, (t - t0) / dur) : 1;
      const e2 = 1 - Math.pow(1 - u, 3);
      vx = fromX + (px[idx] - fromX) * e2;
      vy = fromY + (py[idx] - fromY) * e2;
      scale = fromS + (targetScale - fromS) * e2;
      draw();
      if (u < 1) flyFrame = requestAnimationFrame(step);
    };
    flyFrame = requestAnimationFrame(step);
  }

  function resize(): void {
    W = host.clientWidth;
    H = host.clientHeight;
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    fitView();
    draw();
  }
  window.addEventListener("resize", resize, { signal });
  resize();

  return {
    destroy() {
      destroyed = true;
      cancelAnimationFrame(flyFrame);
      window.clearTimeout(idleTimer);
      aborter.abort();
      canvas.remove();
    },
    resize,
    focusIndex(index: number) {
      const idx = firstIdxOf.get(index);
      if (idx === undefined) return;
      selectedIdx = idx;
      flyTo(idx);
    },
  };
}
