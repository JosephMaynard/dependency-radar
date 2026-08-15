import type { VizCallbacks, VizHandle, VizModel } from "./vizModel";

// Balloon / "constellation" view: project as central body, direct deps
// orbiting, each node's children fanned on an arc facing away from its
// parent, recursively. Ported from the constellation prototype. Every odd
// constant here fixed a real failure — see docs/VIZ-VIEWS-HANDOFF.md §5.2.

const FAN = 3.6; // radians of arc a hub's children may occupy
const MAX_PLACEMENTS = 250_000; // hard budget: beyond this, subtrees become leaves
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
  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  const aborter = new AbortController();
  const signal = aborter.signal;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Sub-linear node size: one monster can't blow out the dynamic range.
  // Weighted by unique packages beneath (honest reach), not path counts.
  const nodeRadius = (id: number): number =>
    Math.min(70, 2.2 + Math.pow(model.uniqueCount(id), 0.34) * 1.1);

  // Enclosing radius of a subtree's balloon in local units, memoised.
  // Iterative with an explicit stack: dependency chains can be thousands of
  // packages deep, which overflows the call stack when done recursively.
  const encMemo = new Float64Array(model.count).fill(-1);
  interface EncFrame {
    id: number;
    next: number;
    arc: number;
    maxKid: number;
  }
  const encLocal = (start: number): void => {
    if (encMemo[start] >= 0) return;
    if (model.kidsOf[start].length === 0) {
      // Leaf: the recursive version returned the bare node radius.
      encMemo[start] = nodeRadius(start);
      return;
    }
    const onPath = new Set<number>([start]);
    const stack: EncFrame[] = [{ id: start, next: 0, arc: 0, maxKid: 0 }];
    const contribute = (parent: EncFrame | undefined, value: number): void => {
      if (!parent) return;
      const e = SHRINK * value;
      parent.arc += 2 * e * 1.12;
      parent.maxKid = Math.max(parent.maxKid, e);
    };
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const kids = model.kidsOf[frame.id];
      if (frame.next < kids.length) {
        const kid = kids[frame.next];
        frame.next += 1;
        if (encMemo[kid] >= 0) {
          contribute(frame, encMemo[kid]);
        } else if (onPath.has(kid)) {
          // Cycle: the recursive version used the bare node radius without
          // memoising it — mirror that exactly.
          contribute(frame, nodeRadius(kid));
        } else if (model.kidsOf[kid].length === 0) {
          encMemo[kid] = nodeRadius(kid);
          contribute(frame, encMemo[kid]);
        } else {
          onPath.add(kid);
          stack.push({ id: kid, next: 0, arc: 0, maxKid: 0 });
        }
        continue;
      }
      onPath.delete(frame.id);
      const r = nodeRadius(frame.id);
      const dist = Math.max(r + frame.maxKid + 6, frame.arc / FAN);
      encMemo[frame.id] = dist + frame.maxKid;
      stack.pop();
      contribute(stack[stack.length - 1], encMemo[frame.id]);
    }
  };
  for (const r of model.rootsSorted) encLocal(r);

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
    if (!kids.length || px.length >= MAX_PLACEMENTS) return idx;
    path.add(id);
    let arc = 0;
    let maxKid = 0;
    for (const kid of kids) {
      const e = SHRINK * encMemo[kid];
      arc += 2 * e * 1.12;
      maxKid = Math.max(maxKid, e);
    }
    const dist = Math.max(nodeRadius(id) + maxKid + 6, arc / FAN) * unit;
    // Fans whose children only need a fraction of the available arc spread
    // out to use it (capped so a two-child fan doesn't go antipodal):
    // sibling enclosing circles are radial bounds, so widening the angles
    // within FAN never leaks into a neighbouring subtree's space.
    const fanUsed = Math.min(FAN, (arc * unit) / dist);
    const spread = fanUsed > 1e-9 ? Math.min(2.2, FAN / fanUsed) : 1;
    let a = dir - (fanUsed * spread) / 2;
    for (const kid of kids) {
      const share = ((2 * SHRINK * encMemo[kid] * 1.12 * unit) / dist) * spread;
      const ang = a + share / 2;
      a += share;
      // Bound materialisation: skip subtrees whose whole balloon stays below
      // half a pixel even at the wheel's maximum zoom (600x).
      if (SHRINK * unit * encMemo[kid] * 600 < 0.5) continue;
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
    // their neighbours into a solid rope on real monorepos). Minors also
    // stagger across three orbit shells: at fit zoom their on-screen floor
    // size exceeds their world spacing, so a single orbit renders as a solid
    // rope no matter how it is packed — three shells triple the room.
    const minorShare = (r: number): number => 2 * Math.max(encMemo[r], 40) * 1.15;
    const minorArc = minors.reduce((s2, r) => s2 + minorShare(r), 0);
    const minorDist = Math.max(
      majors.length ? dist * 0.34 : 0,
      CENTER_R + 120,
      minorArc / (Math.PI * 2),
    );
    // When the packed minors need less than the full circle, spread them
    // around the whole orbit instead of clumping in one wedge.
    const minorSpread =
      minorArc > 0 ? Math.max(1, (Math.PI * 2 * minorDist) / minorArc) : 1;
    let am = -Math.PI / 2;
    let minorIndex = 0;
    for (const r of minors) {
      const share = (minorShare(r) / minorDist) * minorSpread;
      const ang = am + share / 2;
      am += share;
      const d = minorDist * (1 + (minorIndex % 3) * 0.18);
      minorIndex += 1;
      place(r, Math.cos(ang) * d, Math.sin(ang) * d, ang, 0, -1, model.rootHue.get(r) ?? 210, 1, new Set());
    }
  }
  const COUNT = px.length;

  // Spatial grid for hover/click. Every body is pickable — leaves have tiny
  // WORLD radii but are perfectly clickable once zoomed in.
  const grid = new Map<string, number[]>();
  for (let i = 0; i < COUNT; i += 1) {
    const key = `${Math.floor(px[i] / CELL)},${Math.floor(py[i] / CELL)}`;
    const list = grid.get(key) ?? [];
    list.push(i);
    grid.set(key, list);
  }
  const firstIdxOf = new Map<number, number>();
  let maxBodyR = 0;
  for (let i = 0; i < COUNT; i += 1) {
    if (!firstIdxOf.has(pid[i])) firstIdxOf.set(pid[i], i);
    if (pr[i] > maxBodyR) maxBodyR = pr[i];
  }
  // Grid cells to scan so even the largest body is reachable from any cursor
  // cell (bodies index only the cell containing their centre).
  const PICK_REACH = Math.max(1, Math.ceil(maxBodyR / CELL));

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

  let minScale = 0.05;
  function fitView(): void {
    // Seed with the central project body so it is always in frame.
    let minX = -CENTER_R;
    let minY = -CENTER_R;
    let maxX = CENTER_R;
    let maxY = CENTER_R;
    for (let i = 0; i < COUNT; i += 1) {
      minX = Math.min(minX, px[i] - pr[i]);
      maxX = Math.max(maxX, px[i] + pr[i]);
      minY = Math.min(minY, py[i] - pr[i]);
      maxY = Math.max(maxY, py[i] + pr[i]);
    }
    vx = (minX + maxX) / 2;
    vy = (minY + maxY) / 2;
    scale = Math.max(
      1e-4,
      Math.min(usableW() / Math.max(1, maxX - minX), usableH() / Math.max(1, maxY - minY)) * 0.94,
    );
    minScale = Math.min(0.05, scale);
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
      const dim = !hl && cb.isDimmed(id);
      if (dim) ctx.globalAlpha = 0.16;
      if (r < 1.6) {
        ctx.fillStyle = `hsla(${hue} 34% ${theme.isDark ? 58 : 44}% / ${dev ? 0.35 : 0.55})`;
        ctx.fillRect(x - r / 2, y - r / 2, r, r);
        ctx.globalAlpha = 1;
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
      ctx.globalAlpha = 1;
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
        const titleFont = Math.min(15, r * 0.24);
        const metaFont = Math.min(11, r * 0.16);
        // Line gaps follow the (capped) font size, not the radius — zoomed
        // in, the title and stats stay one tight block instead of drifting
        // toward the poles of the circle.
        const lineGap = metaFont * 1.55;
        ctx.font = `600 ${titleFont}px ${mono}`;
        ctx.fillStyle = theme.panelText;
        ctx.fillText(model.projectName, x, y - lineGap);
        ctx.font = `600 ${metaFont}px ${mono}`;
        ctx.fillStyle = theme.panelText;
        ctx.fillText(
          `${model.count.toLocaleString()} package${model.count === 1 ? "" : "s"}`,
          x,
          y + lineGap * 0.35,
        );

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
        // A live name filter hands the label budget to the matches.
        if (cb.isDimmed(pid[i]) && i !== hovered && i !== selectedIdx) continue;
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
        // Second line: fan-in/fan-out (↑ required by · ↓ depends on) — the
        // circle's size already encodes subtree weight, so the label adds
        // the relationship counts the geometry can't show. Zeros are
        // omitted; leaves with nothing to say get no second line.
        const fanIn = model.depsIn[pid[i]].length;
        const fanOut = model.depsOut[pid[i]].length;
        const countText = [
          ...(fanIn > 0 ? [`\u2191${fanIn.toLocaleString()}`] : []),
          ...(fanOut > 0 ? [`\u2193${fanOut.toLocaleString()}`] : []),
        ].join(" ");
        // The collision box must cover BOTH lines — either can be wider.
        const nameW = ctx.measureText(name).width;
        ctx.font = `10px ${mono}`;
        const countW = countText ? ctx.measureText(countText).width : 0;
        ctx.font = `600 10.5px ${mono}`;
        const w = Math.max(nameW, countW);
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
        if (countText) {
          ctx.font = `10px ${mono}`;
          ctx.fillStyle = theme.muted;
          ctx.fillText(countText, x0, y + 7);
        }
      }
    }
  }

  function pickAt(mx: number, my: number): number {
    const wx = (mx - usableW() / 2) / scale + vx;
    const wy = (my - centreY()) / scale + vy;
    const cx = Math.floor(wx / CELL);
    const cyy = Math.floor(wy / CELL);
    let best = -1;
    let bestD = Math.min(10 / scale, CELL);
    for (let gx = cx - PICK_REACH; gx <= cx + PICK_REACH; gx += 1) {
      for (let gy = cyy - PICK_REACH; gy <= cyy + PICK_REACH; gy += 1) {
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
  let downX = 0;
  let downY = 0;
  canvas.addEventListener(
    "pointerdown",
    (e) => {
      dragging = true;
      movedInDrag = false;
      lastX = e.offsetX;
      lastY = e.offsetY;
      downX = e.offsetX;
      downY = e.offsetY;
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
        // Cumulative from pointerdown: slow pans must not read as clicks.
        if (Math.abs(e.offsetX - downX) + Math.abs(e.offsetY - downY) > 3) movedInDrag = true;
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
    "pointercancel",
    () => {
      dragging = false;
      movedInDrag = false;
      canvas.classList.remove("dragging");
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
      if (i >= 0) flyTo(i);
      else draw();
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
      scale = Math.min(600, Math.max(minScale, scale * f));
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
    cancelAnimationFrame(flyFrame);
    // Zoom in far enough to see the body, but never zoom OUT on selection.
    const targetScale = Math.max(scale, Math.min(24, Math.max(1.2, 42 / pr[idx])));
    const fromS = scale;
    // Animate the TARGET'S SCREEN POSITION on a straight path to centre while
    // the scale eases; interpolating pan and zoom independently can throw the
    // target off screen mid-flight, which reads as a jarring detour.
    const startSX = sx(px[idx]);
    const startSY = sy(py[idx]);
    const t0 = performance.now();
    const dur = reduced ? 0 : 500;
    const step = (t: number): void => {
      if (destroyed) return;
      const u = dur ? Math.min(1, (t - t0) / dur) : 1;
      const e2 = 1 - Math.pow(1 - u, 3);
      const sNow = fromS + (targetScale - fromS) * e2;
      const sxNow = startSX + (usableW() / 2 - startSX) * e2;
      const syNow = startSY + (centreY() - startSY) * e2;
      scale = sNow;
      vx = px[idx] - (sxNow - usableW() / 2) / sNow;
      vy = py[idx] - (syNow - centreY()) / sNow;
      draw();
      if (u < 1) flyFrame = requestAnimationFrame(step);
    };
    flyFrame = requestAnimationFrame(step);
  }

  function resize(): void {
    const w = host.clientWidth;
    const h = host.clientHeight;
    const dimsChanged = w !== W || h !== H;
    W = w;
    H = h;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    // Pure repaints (theme flips, tab re-entry) must not wipe pan/zoom.
    if (dimsChanged) fitView();
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
      // Pruned/budgeted packages have no placement; fly to the nearest
      // placed spanning-tree ancestor instead of ignoring the request.
      let target = index;
      let guard = 0;
      while (!firstIdxOf.has(target) && model.parent[target] >= 0 && guard < 128) {
        target = model.parent[target];
        guard += 1;
      }
      const idx = firstIdxOf.get(target);
      if (idx === undefined) return;
      selectedIdx = idx;
      flyTo(idx);
    },
    resetView() {
      fitView();
      draw();
    },
  };
}
