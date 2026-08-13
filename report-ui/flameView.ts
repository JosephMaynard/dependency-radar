import type { VizCallbacks, VizHandle, VizModel } from "./vizModel";
import { lineageFill } from "./vizModel";

// Flame / icicle view: root bar on top, one row per depth, width proportional
// to path-expanded subtree share, children heaviest-first. Ported from the
// dependency-flame prototype; lazy draw-time layout so the multi-hundred-
// thousand-block expansion is never materialised.

const ROW = 26;
const ANC = 20;
const PAD = 1;
const MIN_BLOCK_PX = 0.8;

interface Block {
  id: number;
  parent: number;
  x: number;
  y: number;
  w: number;
  h: number;
  anc?: number;
}

/** Canvas-safe alpha applied to a #rrggbb (or #rgb) colour. */
export function withAlpha(hex: string, alpha: number): string {
  const m = hex.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (!m) return hex;
  const h = m[1].length === 3 ? m[1].split("").map((c) => c + c).join("") : m[1];
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export function mountFlameView(
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

  let W = 0;
  let H = 0;
  /** Usable width: canvas width minus the floating panel's cover. */
  const usableW = (): number => Math.max(120, W - cb.insetRight());
  let focusPath: number[] = [];
  let hoveredBlock = -1;
  let selectedId = -1;
  let blocks: Block[] = [];
  let destroyed = false;

  const monoFont = (): string =>
    `10.5px ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace`;

  function fillFor(id: number, rootId: number, depthIdx: number, highlight: boolean): string {
    const theme = cb.theme();
    if (model.refs[id]?.vulnerabilitySeverity === "high") {
      // Vulnerable packages override lineage hue: this is the product value.
      return highlight ? theme.vulnHigh : withAlpha(theme.vulnHigh, 0.72);
    }
    const hue = model.rootHue.get(rootId) ?? 210;
    return lineageFill(theme, hue, depthIdx, model.isDev[id], highlight);
  }

  function drawBar(
    x: number,
    y: number,
    w: number,
    h: number,
    fill: string,
    label: string,
    labelAlpha: number,
    dimmed = false,
  ): void {
    if (!ctx) return;
    const theme = cb.theme();
    if (dimmed) {
      ctx.globalAlpha = 0.22;
      labelAlpha *= 0.5;
    }
    ctx.fillStyle = fill;
    ctx.fillRect(x + PAD / 2, y, Math.max(0.5, w - PAD), h - 1.5);
    ctx.globalAlpha = 1;
    if (label && w > 34) {
      ctx.save();
      ctx.beginPath();
      ctx.rect(x + 5, y, w - 10, h);
      ctx.clip();
      ctx.globalAlpha = labelAlpha;
      ctx.fillStyle = theme.isDark ? "#e6eef8" : "#1e293b";
      ctx.fillText(label, x + 6, y + h / 2);
      ctx.restore();
      ctx.globalAlpha = 1;
    }
  }

  function drawLevel(
    ids: number[],
    rootFor: number | null,
    x0: number,
    x1: number,
    y: number,
    depthIdx: number,
    parentBlock: number,
    chain: Set<number>,
  ): void {
    if (!ctx || y > H || ids.length === 0) return;
    const total = ids.reduce((s, id) => s + model.subSize[id], 0);
    if (total <= 0) return;
    let x = x0;
    let sprayW = 0;
    for (const id of ids) {
      const w = ((x1 - x0) * model.subSize[id]) / total;
      if (w < MIN_BLOCK_PX) {
        sprayW += w;
        continue;
      }
      const rootId = rootFor ?? id;
      const idx = blocks.length;
      blocks.push({ id, parent: parentBlock, x, y, w, h: ROW });
      const hl = idx === hoveredBlock || id === selectedId;
      drawBar(
        x,
        y,
        w,
        ROW,
        fillFor(id, rootId, depthIdx, hl),
        model.refs[id].name,
        hl ? 1 : 0.82,
        !hl && cb.isDimmed(id),
      );
      if (hl) {
        ctx.strokeStyle = cb.theme().accent;
        ctx.lineWidth = 1.2;
        ctx.strokeRect(x + 0.5, y + 0.5, w - PAD, ROW - 2.5);
      }
      if (!chain.has(id)) {
        chain.add(id);
        drawLevel(model.kidsOf[id], rootId, x, x + w, y + ROW, depthIdx + 1, idx, chain);
        chain.delete(id);
      }
      x += w;
    }
    if (sprayW > 0.4) {
      ctx.fillStyle = "rgba(90, 110, 130, 0.22)";
      ctx.fillRect(x, y + ROW * 0.3, Math.max(0.5, sprayW - PAD / 2), ROW * 0.4);
    }
  }

  function draw(): void {
    if (!ctx || destroyed) return;
    const theme = cb.theme();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.font = monoFont();
    ctx.textBaseline = "middle";
    blocks = [];
    let y = cb.insetTop();

    // Pinned lineage: project bar, then each ancestor of the focus, full width.
    const UW = usableW();
    blocks.push({ id: -1, parent: -1, x: 0, y, w: UW, h: focusPath.length ? ANC : ROW });
    drawBar(
      0,
      y,
      UW,
      focusPath.length ? ANC : ROW,
      theme.isDark ? "#1c2836" : "#dbe4ef",
      `${model.projectName}  —  ${model.count.toLocaleString()} packages (${Math.round(model.totalSize).toLocaleString()} paths)`,
      0.9,
    );
    y += focusPath.length ? ANC : ROW;

    const rootId = focusPath[0];
    for (let i = 0; i < Math.max(0, focusPath.length - 1); i += 1) {
      const id = focusPath[i];
      blocks.push({ id, parent: blocks.length - 1, x: 0, y, w: UW, h: ANC, anc: i });
      drawBar(
        0,
        y,
        UW,
        ANC,
        fillFor(id, rootId, 1, false),
        `${model.refs[id].name}  ↩`,
        0.7,
        cb.isDimmed(id),
      );
      y += ANC;
    }

    const chain = new Set(focusPath.slice(0, -1));
    if (focusPath.length === 0) {
      drawLevel(model.rootsSorted, null, 0, UW, y, 0, 0, chain);
    } else {
      const focus = focusPath[focusPath.length - 1];
      const idx = blocks.length;
      blocks.push({ id: focus, parent: idx - 1, x: 0, y, w: UW, h: ROW });
      const hl = focus === selectedId;
      drawBar(0, y, UW, ROW, fillFor(focus, rootId, 1, true), model.refs[focus].name, 1);
      if (hl) {
        ctx.strokeStyle = theme.accent;
        ctx.lineWidth = 1.2;
        ctx.strokeRect(0.5, y + 0.5, UW - 1, ROW - 2.5);
      }
      chain.add(focus);
      drawLevel(model.kidsOf[focus], rootId, 0, UW, y + ROW, 2, idx, chain);
    }
  }

  function pick(px: number, py: number): number {
    for (let i = blocks.length - 1; i >= 0; i -= 1) {
      const b = blocks[i];
      if (px >= b.x && px <= b.x + b.w && py >= b.y && py <= b.y + b.h) return i;
    }
    return -1;
  }

  function pathOfBlock(i: number): number[] {
    const path: number[] = [];
    let cur = i;
    // Parent indices strictly decrease, so this always terminates.
    while (cur > 0 && blocks[cur]) {
      if (blocks[cur].id >= 0) path.unshift(blocks[cur].id);
      cur = blocks[cur].parent;
    }
    return path;
  }

  canvas.addEventListener(
    "pointermove",
    (e) => {
      const i = pick(e.offsetX, e.offsetY);
      if (i === hoveredBlock) return;
      hoveredBlock = i;
      canvas.style.cursor = i >= 0 ? "pointer" : "default";
      cb.onHoverTrail(i >= 0 && blocks[i].id >= 0 ? pathOfBlock(i) : null);
      draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "pointerleave",
    () => {
      hoveredBlock = -1;
      cb.onHoverTrail(null);
      draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "click",
    (e) => {
      if (e.detail > 1) return; // the dblclick handler owns repeat clicks
      const i = pick(e.offsetX, e.offsetY);
      if (i < 0) return;
      const b = blocks[i];
      hoveredBlock = -1; // relayout invalidates positional hover indices
      cb.onHoverTrail(null);
      if (b.id < 0) {
        focusPath = [];
        selectedId = -1;
        cb.onSelect(-1);
        draw();
        return;
      }
      if (b.anc !== undefined) {
        focusPath = focusPath.slice(0, b.anc + 1);
      } else {
        focusPath = pathOfBlock(i);
      }
      selectedId = b.id;
      cb.onSelect(b.id);
      draw();
    },
    { signal },
  );
  canvas.addEventListener(
    "dblclick",
    () => {
      focusPath = [];
      selectedId = -1;
      hoveredBlock = -1;
      cb.onHoverTrail(null);
      cb.onSelect(-1);
      draw();
    },
    { signal },
  );

  /** Shortest path from any root to the package, for search / chip jumps. */
  function findPath(target: number): number[] | null {
    if (model.isRoot[target]) return [target];
    const prev = new Int32Array(model.count).fill(-2);
    const queue = [...model.roots];
    for (const r of model.roots) prev[r] = -1;
    for (let head = 0; head < queue.length; head += 1) {
      const cur = queue[head];
      for (const dep of model.kidsOf[cur]) {
        if (prev[dep] !== -2) continue;
        prev[dep] = cur;
        if (dep === target) {
          const path = [dep];
          let walk = cur;
          while (walk >= 0) {
            path.unshift(walk);
            walk = prev[walk];
          }
          return path;
        }
        queue.push(dep);
      }
    }
    return null;
  }

  function resize(): void {
    W = host.clientWidth;
    H = host.clientHeight;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    draw();
  }
  window.addEventListener("resize", resize, { signal });
  resize();

  return {
    destroy() {
      destroyed = true;
      aborter.abort();
      canvas.remove();
    },
    resize,
    focusIndex(index: number) {
      const path = findPath(index);
      if (!path) return;
      focusPath = path;
      selectedId = index;
      hoveredBlock = -1;
      draw();
    },
  };
}
