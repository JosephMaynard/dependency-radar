import type { VizCallbacks, VizHandle, VizModel } from "./vizModel";
import { lineageFill } from "./vizModel";
import { withAlpha } from "./flameView";

// Treemap over the DOMINATOR tree — the disk-usage view of node_modules.
// Rectangle area is the number of packages that leave if the rectangle is
// deleted; every package appears exactly once, so areas are honest and
// additive. Packages no single dependency owns form a grey "shared" block.
// Squarified layout (Bruls, Huizing, van Wijk) keeps aspect ratios readable.

const OUTER_PAD = 3;
const INNER_PAD = 2;
/** Vertical space reserved for a rect's own label before nesting children. */
const HEADER = 16;
const MIN_LABEL_W = 46;
const MIN_LABEL_H = 13;
const MIN_RECT_PX = 2;

/** Sentinel id for the shared block. */
const SHARED_RECT = -2;
/**
 * Sentinel id for a parent's own unit of area inside its children's layout:
 * a parent of weight N holds N-1 children-weight plus itself, so one weight
 * unit of every nest stays empty. Without it, children would be inflated to
 * fill the whole content box and nested areas would stop being proportional
 * to package counts.
 */
const SELF_SPACE = -3;

interface Rect {
  id: number;
  x: number;
  y: number;
  w: number;
  h: number;
  depth: number;
  /** Top-level owner (direct dep) for lineage colour; -2 = shared block. */
  owner: number;
}

interface LayoutItem {
  id: number;
  weight: number;
}

/**
 * Squarified layout (Bruls, Huizing, van Wijk) of items into (x, y, w, h).
 * Pure geometry — the caller decides what the weights mean. Exported for the
 * geometry tests: item areas must stay proportional to weights.
 */
export function squarify(
  items: LayoutItem[],
  x: number,
  y: number,
  w: number,
  h: number,
): Array<{ id: number; x: number; y: number; w: number; h: number }> {
  const out: Array<{ id: number; x: number; y: number; w: number; h: number }> = [];
  const total = items.reduce((sum, item) => sum + item.weight, 0);
  if (total <= 0 || w <= 0 || h <= 0) return out;
  const scale = (w * h) / total;
  let queue = items.filter((item) => item.weight > 0);
  let px = x;
  let py = y;
  let pw = w;
  let ph = h;

  while (queue.length > 0) {
    const horizontal = pw >= ph; // lay the strip along the shorter side
    const side = horizontal ? ph : pw;
    let row: LayoutItem[] = [];
    let rowArea = 0;
    let worst = Infinity;
    let index = 0;
    while (index < queue.length) {
      const candidate = queue[index];
      const candidateArea = candidate.weight * scale;
      const nextArea = rowArea + candidateArea;
      const strip = nextArea / side;
      let nextWorst = 0;
      for (const item of [...row, candidate]) {
        const length = (item.weight * scale) / strip;
        nextWorst = Math.max(nextWorst, Math.max(strip / length, length / strip));
      }
      if (row.length > 0 && nextWorst > worst) break;
      row.push(candidate);
      rowArea = nextArea;
      worst = nextWorst;
      index += 1;
    }
    const strip = rowArea / side;
    let offset = 0;
    for (const item of row) {
      const length = (item.weight * scale) / strip;
      if (horizontal) {
        out.push({ id: item.id, x: px, y: py + offset, w: strip, h: length });
      } else {
        out.push({ id: item.id, x: px + offset, y: py, w: length, h: strip });
      }
      offset += length;
    }
    if (horizontal) {
      px += strip;
      pw -= strip;
    } else {
      py += strip;
      ph -= strip;
    }
    queue = queue.slice(row.length);
  }
  return out;
}

export function mountTreemapView(
  host: HTMLElement,
  model: VizModel,
  cb: VizCallbacks,
): VizHandle {
  const canvas = document.createElement("canvas");
  canvas.className = "graph-alt-canvas";
  canvas.setAttribute("role", "img");
  canvas.setAttribute(
    "aria-label",
    "Treemap of the dependency tree (pointer-driven — the list view offers the same data with keyboard access)",
  );
  host.appendChild(canvas);
  // Cursor tooltip: most rects are too small to carry a label, so the name
  // travels with the pointer instead.
  const tip = document.createElement("div");
  tip.className = "graph-cursor-tip";
  tip.hidden = true;
  host.appendChild(tip);
  const ctx = canvas.getContext("2d");
  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  const aborter = new AbortController();
  const signal = aborter.signal;

  const dom = model.domTree();
  const directRootSet = new Set(model.roots);
  const directTop = dom.rootChildren.filter((id) => directRootSet.has(id));
  const sharedMembers = dom.rootChildren.filter((id) => !directRootSet.has(id));
  const sharedTotal = sharedMembers.reduce(
    (sum, id) => sum + dom.exclusiveCount[id],
    0,
  );

  let W = 0;
  let H = 0;
  const usableW = (): number => Math.max(120, W - cb.insetRight());
  let rects: Rect[] = [];
  let hovered = -1;
  let selected = -1;
  /** Zoom root: a package id, SHARED_RECT, or -1 for the whole project. */
  let zoomRoot = -1;
  let destroyed = false;

  const mono = 'ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace';

  function fillFor(rect: Rect, highlight: boolean): string {
    const theme = cb.theme();
    if (rect.id >= 0 && model.refs[rect.id]?.vulnerabilitySeverity === "high") {
      return highlight ? theme.vulnHigh : withAlpha(theme.vulnHigh, 0.72);
    }
    if (rect.owner === SHARED_RECT) {
      const l = theme.isDark
        ? Math.min(44, 26 + rect.depth * 3)
        : Math.max(64, 88 - rect.depth * 3);
      return `hsl(210 10% ${l}%${highlight ? " / 1" : " / 0.95"})`;
    }
    const hue = model.rootHue.get(rect.owner) ?? 210;
    return lineageFill(theme, hue, rect.depth, rect.id >= 0 && model.isDev[rect.id], highlight);
  }

  /** Lay out the tree iteratively; deep chains must not recurse. */
  function layout(): void {
    rects = [];
    const UW = usableW();
    const top = cb.insetTop();
    const x0 = OUTER_PAD;
    const y0 = top + OUTER_PAD;
    const w0 = UW - OUTER_PAD * 2;
    const h0 = H - top - OUTER_PAD * 2;
    if (w0 <= 0 || h0 <= 0) return;

    interface Job {
      ids: number[];
      x: number;
      y: number;
      w: number;
      h: number;
      depth: number;
      owner: number; // -1 = derive per item (top level)
      /** The parent's own weight unit (0 when the parent is not a package —
       *  the shared block's weight is exactly the sum of its members). */
      selfWeight: number;
    }
    const jobs: Job[] = [];

    if (zoomRoot === SHARED_RECT) {
      jobs.push({
        ids: sharedMembers,
        x: x0,
        y: y0,
        w: w0,
        h: h0,
        depth: 0,
        owner: SHARED_RECT,
        selfWeight: 0,
      });
    } else if (zoomRoot >= 0) {
      rects.push({ id: zoomRoot, x: x0, y: y0, w: w0, h: h0, depth: 0, owner: ownerOf(zoomRoot) });
      jobs.push({
        ids: dom.children[zoomRoot],
        x: x0 + INNER_PAD,
        y: y0 + HEADER,
        w: w0 - INNER_PAD * 2,
        h: h0 - HEADER - INNER_PAD,
        depth: 1,
        owner: ownerOf(zoomRoot),
        selfWeight: 1,
      });
    } else {
      const items: LayoutItem[] = directTop.map((id) => ({ id, weight: dom.exclusiveCount[id] }));
      if (sharedTotal > 0) items.push({ id: SHARED_RECT, weight: sharedTotal });
      for (const placed of squarify(items, x0, y0, w0, h0)) {
        if (placed.w < MIN_RECT_PX || placed.h < MIN_RECT_PX) continue;
        if (placed.id === SHARED_RECT) {
          rects.push({ ...placed, id: SHARED_RECT, depth: 0, owner: SHARED_RECT });
          jobs.push({
            ids: sharedMembers,
            x: placed.x + INNER_PAD,
            y: placed.y + HEADER,
            w: placed.w - INNER_PAD * 2,
            h: placed.h - HEADER - INNER_PAD,
            depth: 1,
            owner: SHARED_RECT,
            selfWeight: 0,
          });
        } else {
          rects.push({ ...placed, depth: 0, owner: placed.id });
          jobs.push({
            ids: dom.children[placed.id],
            x: placed.x + INNER_PAD,
            y: placed.y + HEADER,
            w: placed.w - INNER_PAD * 2,
            h: placed.h - HEADER - INNER_PAD,
            depth: 1,
            owner: placed.id,
            selfWeight: 1,
          });
        }
      }
    }

    while (jobs.length > 0) {
      const job = jobs.pop() as Job;
      if (job.ids.length === 0 || job.w < MIN_RECT_PX * 2 || job.h < MIN_RECT_PX * 2) continue;
      const items = job.ids.map((id) => ({ id, weight: dom.exclusiveCount[id] }));
      // Reserve the parent's own unit so child areas keep meaning "packages":
      // a child of weight w gets w/(children+self) of the parent's box, never
      // an inflated share of it.
      if (job.selfWeight > 0) items.push({ id: SELF_SPACE, weight: job.selfWeight });
      for (const placed of squarify(items, job.x, job.y, job.w, job.h)) {
        if (placed.id === SELF_SPACE) continue; // parent's own unit stays empty
        if (placed.w < MIN_RECT_PX || placed.h < MIN_RECT_PX) continue;
        const owner = job.owner === -1 ? placed.id : job.owner;
        rects.push({ ...placed, depth: job.depth, owner });
        const kids = dom.children[placed.id];
        if (kids.length > 0 && placed.w > MIN_RECT_PX * 3 && placed.h > HEADER + MIN_RECT_PX) {
          jobs.push({
            ids: kids,
            x: placed.x + INNER_PAD,
            y: placed.y + HEADER,
            w: placed.w - INNER_PAD * 2,
            h: placed.h - HEADER - INNER_PAD,
            depth: job.depth + 1,
            owner,
            selfWeight: 1,
          });
        }
      }
    }
  }

  function ownerOf(id: number): number {
    let cur = id;
    let guard = 0;
    while (dom.idom[cur] >= 0 && guard < 100_000) {
      cur = dom.idom[cur];
      guard += 1;
    }
    return directRootSet.has(cur) ? cur : SHARED_RECT;
  }

  function rectLabel(rect: Rect): string {
    // Under non-default filters the counts cover only what is SHOWN; the
    // dossier carries the unfiltered removal cost.
    const suffix = model.filtersAreDefault ? "" : " shown";
    if (rect.id === SHARED_RECT) {
      return `shared · ${sharedTotal.toLocaleString()}${suffix}`;
    }
    const frees = dom.exclusiveCount[rect.id];
    const name = model.refs[rect.id].name;
    return frees > 1 ? `${name} · ${frees.toLocaleString()}${suffix}` : name;
  }

  function draw(): void {
    if (!ctx || destroyed) return;
    const theme = cb.theme();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.textBaseline = "middle";
    ctx.font = `600 10.5px ${mono}`;

    for (let i = 0; i < rects.length; i += 1) {
      const rect = rects[i];
      const hl =
        i === hovered ||
        (rect.id >= 0 && rect.id === selected) ||
        (rect.id === SHARED_RECT && hovered === i);
      const dimmed = rect.id >= 0 && !hl && cb.isDimmed(rect.id);
      ctx.globalAlpha = dimmed ? 0.25 : 1;
      ctx.fillStyle = fillFor(rect, hl);
      ctx.fillRect(rect.x, rect.y, rect.w, rect.h);
      ctx.strokeStyle = theme.isDark ? "rgba(10, 16, 24, 0.85)" : "rgba(255, 255, 255, 0.9)";
      ctx.lineWidth = 1;
      ctx.strokeRect(rect.x + 0.5, rect.y + 0.5, rect.w - 1, rect.h - 1);
      if (hl) {
        ctx.strokeStyle = theme.accent;
        ctx.lineWidth = 1.4;
        ctx.strokeRect(rect.x + 1, rect.y + 1, rect.w - 2, rect.h - 2);
      }
      if (rect.w >= MIN_LABEL_W && rect.h >= MIN_LABEL_H) {
        ctx.save();
        ctx.beginPath();
        ctx.rect(rect.x + 4, rect.y, rect.w - 8, Math.min(rect.h, HEADER + 2));
        ctx.clip();
        ctx.globalAlpha = dimmed ? 0.4 : 0.92;
        ctx.fillStyle = theme.isDark ? "#dfe9f5" : "#22303e";
        ctx.fillText(rectLabel(rect), rect.x + 5, rect.y + Math.min(rect.h / 2, 9.5));
        ctx.restore();
      }
      ctx.globalAlpha = 1;
    }
  }

  function pick(px: number, py: number): number {
    // Last drawn wins: deeper rects are pushed later within a branch.
    for (let i = rects.length - 1; i >= 0; i -= 1) {
      const rect = rects[i];
      if (px >= rect.x && px <= rect.x + rect.w && py >= rect.y && py <= rect.y + rect.h) {
        return i;
      }
    }
    return -1;
  }

  function trailOf(id: number): number[] {
    const path: number[] = [];
    let cur = id;
    let guard = 0;
    while (cur >= 0 && guard < 100_000) {
      path.unshift(cur);
      cur = dom.idom[cur];
      guard += 1;
    }
    return path;
  }

  function moveTip(e: PointerEvent, i: number): void {
    if (i < 0) {
      tip.hidden = true;
      return;
    }
    tip.textContent = rectLabel(rects[i]);
    tip.hidden = false;
    // Measure after content is set; flip to the other side near the edges.
    // The right edge is the USABLE edge — beyond it sits the docked panel.
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    let x = e.offsetX + 14;
    let y = e.offsetY + 18;
    if (x + tw > usableW() - 8) x = e.offsetX - tw - 10;
    if (y + th > H - 34) y = e.offsetY - th - 10;
    tip.style.transform = `translate(${Math.max(4, x)}px, ${Math.max(4, y)}px)`;
  }

  canvas.addEventListener(
    "pointermove",
    (e) => {
      const i = pick(e.offsetX, e.offsetY);
      moveTip(e, i);
      if (i === hovered) return;
      hovered = i;
      canvas.style.cursor = i >= 0 ? "pointer" : "default";
      const rect = i >= 0 ? rects[i] : undefined;
      cb.onHoverTrail(rect && rect.id >= 0 ? trailOf(rect.id) : null);
      draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "pointerleave",
    () => {
      hovered = -1;
      tip.hidden = true;
      cb.onHoverTrail(null);
      draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "click",
    (e) => {
      if (e.detail > 1) return;
      const i = pick(e.offsetX, e.offsetY);
      if (i < 0) return;
      const rect = rects[i];
      // Single click only selects — no relayout, so a following double-click
      // resolves against the geometry the user actually saw.
      if (rect.id >= 0) {
        selected = rect.id;
        cb.onSelect(rect.id);
        draw();
      }
    },
    { signal },
  );
  /** Change the zoom root, notifying the host (it shows Reset while zoomed). */
  function setZoom(next: number): void {
    if (next === zoomRoot) return;
    zoomRoot = next;
    cb.onZoomChanged?.(zoomRoot !== -1);
  }

  /** One level up from the current zoom root. */
  function zoomParent(): number {
    if (zoomRoot === SHARED_RECT || zoomRoot < 0) return -1;
    if (dom.idom[zoomRoot] >= 0) return dom.idom[zoomRoot];
    return ownerOf(zoomRoot) === SHARED_RECT ? SHARED_RECT : -1;
  }

  canvas.addEventListener(
    "dblclick",
    (e) => {
      const i = pick(e.offsetX, e.offsetY);
      if (i < 0) {
        // Empty space: reset.
        setZoom(-1);
        selected = -1;
        cb.onSelect(-1);
        hovered = -1;
        tip.hidden = true;
        layout();
        draw();
        return;
      }
      const rect = rects[i];
      // pick() returns the DEEPEST rect (usually a leaf); the drill target is
      // the ancestor one level below the current zoom, so drilling steps into
      // the box the user sees, not the pixel they hit.
      let target: number;
      if (rect.id === SHARED_RECT || rect.owner === SHARED_RECT) {
        if (zoomRoot === SHARED_RECT && rect.id >= 0) {
          const trail = trailOf(rect.id);
          target = trail.length > 0 ? trail[0] : SHARED_RECT;
        } else {
          target = SHARED_RECT;
        }
      } else {
        const trail = trailOf(rect.id);
        if (zoomRoot >= 0) {
          const at = trail.indexOf(zoomRoot);
          target = at >= 0 && at + 1 < trail.length ? trail[at + 1] : rect.id;
        } else {
          target = trail[0];
        }
      }
      if (target === zoomRoot && zoomRoot !== -1) {
        // Double-clicking the zoomed box itself climbs back out one level.
        setZoom(zoomParent());
      } else if (target === SHARED_RECT || (target >= 0 && dom.children[target].length > 0)) {
        setZoom(target);
      }
      // A childless target keeps the current zoom — losing your place because
      // you double-clicked a leaf reads as a bug, not a reset.
      if (rect.id >= 0) {
        selected = rect.id;
        cb.onSelect(rect.id);
      }
      hovered = -1;
      tip.hidden = true;
      layout();
      draw();
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
    hovered = -1;
    tip.hidden = true;
    layout();
    draw();
  }
  window.addEventListener("resize", resize, { signal });
  resize();

  return {
    destroy() {
      destroyed = true;
      aborter.abort();
      tip.remove();
      canvas.remove();
    },
    resize,
    focusIndex(index: number) {
      if (dom.idom[index] === -2) return;
      // Zoom to the focused package's dominator parent so the package is
      // visible in context; the package itself is selected.
      const parent = dom.idom[index];
      setZoom(parent >= 0 ? parent : ownerOf(index) === SHARED_RECT ? SHARED_RECT : -1);
      selected = index;
      hovered = -1;
      tip.hidden = true;
      layout();
      draw();
    },
    resetView() {
      setZoom(-1);
      if (selected >= 0) {
        selected = -1;
        cb.onSelect(-1); // otherwise the dossier stays open on a reset view
      }
      hovered = -1;
      tip.hidden = true;
      layout();
      draw();
    },
  };
}
