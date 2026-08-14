import type { VizCallbacks, VizHandle, VizModel } from "./vizModel";
import { lineageFill } from "./vizModel";

// Flame / icicle view over the DOMINATOR tree: every package appears exactly
// once, bar width is the number of packages that leave node_modules if the
// bar is deleted (dominator-subtree size), children heaviest-first. Packages
// no single direct dependency owns sit in a "shared" band — deleting one
// dependency never frees them, so no dependency's bar gets credit for them.

const ROW = 26;
const ANC = 20;
const PAD = 1;
const MIN_BLOCK_PX = 0.8;

/** Sentinel ids for synthetic bars. */
const PROJECT_BAR = -1;
const SHARED_BAR = -2;

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

  const dom = model.domTree();
  const directRootSet = new Set(model.roots);
  // Top level: direct dependencies that are dominator roots, heaviest first
  // (dom.rootChildren is already weight-sorted), then the shared band.
  const directTop = dom.rootChildren.filter((id) => directRootSet.has(id));
  const sharedMembers = dom.rootChildren.filter((id) => !directRootSet.has(id));
  const sharedTotal = sharedMembers.reduce(
    (sum, id) => sum + dom.exclusiveCount[id],
    0,
  );

  let W = 0;
  let H = 0;
  /** Usable width: canvas width minus the floating panel's cover. */
  const usableW = (): number => Math.max(120, W - cb.insetRight());
  let focusPath: number[] = [];
  let focusShared = false;
  let hoveredBlock = -1;
  let selectedId = -1;
  let blocks: Block[] = [];
  let destroyed = false;

  const monoFont = (): string =>
    `10.5px ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace`;

  const weightOf = (id: number): number => dom.exclusiveCount[id];

  function fillFor(id: number, rootId: number, depthIdx: number, highlight: boolean): string {
    const theme = cb.theme();
    if (model.refs[id]?.vulnerabilitySeverity === "high") {
      // Vulnerable packages override lineage hue: this is the product value.
      return highlight ? theme.vulnHigh : withAlpha(theme.vulnHigh, 0.72);
    }
    const hue = model.rootHue.get(rootId) ?? 210;
    return lineageFill(theme, hue, depthIdx, model.isDev[id], highlight);
  }

  function sharedFill(highlight: boolean): string {
    const theme = cb.theme();
    return theme.isDark
      ? highlight
        ? "#3d4c5c"
        : "#2a3542"
      : highlight
        ? "#c4d0dc"
        : "#d8e0e8";
  }

  function barLabel(id: number): string {
    const name = model.refs[id].name;
    const frees = weightOf(id);
    return frees > 1 ? `${name} · ${frees.toLocaleString()}` : name;
  }

  function sharedBandLabel(): string {
    return `shared — ${sharedTotal.toLocaleString()} package${sharedTotal === 1 ? "" : "s"} kept by more than one dependency`;
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

  /**
   * Draw a dominator-tree level. `parentWeight` preserves the invariant that
   * width == removal cost: children are normalised by the PARENT's weight
   * (children + the parent itself), so the unallocated sliver at the right of
   * each nest is the parent's own unit. Pass 0 to normalise by the children
   * sum alone (the virtual root has no self weight).
   */
  function drawLevel(
    ids: number[],
    rootFor: number | null,
    x0: number,
    x1: number,
    y: number,
    depthIdx: number,
    parentBlock: number,
    parentWeight: number,
  ): void {
    if (!ctx || y > H || ids.length === 0) return;
    const childSum = ids.reduce((sum, id) => sum + weightOf(id), 0);
    const total = parentWeight > 0 ? parentWeight : childSum;
    if (total <= 0) return;
    let x = x0;
    let sprayW = 0;
    for (const id of ids) {
      const w = ((x1 - x0) * weightOf(id)) / total;
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
        barLabel(id),
        hl ? 1 : 0.82,
        !hl && cb.isDimmed(id),
      );
      if (hl) {
        ctx.strokeStyle = cb.theme().accent;
        ctx.lineWidth = 1.2;
        ctx.strokeRect(x + 0.5, y + 0.5, w - PAD, ROW - 2.5);
      }
      // The dominator tree is a real tree — no cycle guard needed.
      drawLevel(dom.children[id], rootId, x, x + w, y + ROW, depthIdx + 1, idx, weightOf(id));
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

    const pinned = focusPath.length > 0 || focusShared;
    // Pinned lineage: project bar, then each ancestor of the focus, full width.
    const UW = usableW();
    blocks.push({ id: PROJECT_BAR, parent: -1, x: 0, y, w: UW, h: pinned ? ANC : ROW });
    drawBar(
      0,
      y,
      UW,
      pinned ? ANC : ROW,
      theme.isDark ? "#1c2836" : "#dbe4ef",
      `${model.projectName}  —  ${model.count.toLocaleString()} package${model.count === 1 ? "" : "s"}`,
      0.9,
    );
    y += pinned ? ANC : ROW;

    if (focusShared && focusPath.length === 0) {
      // Zoomed into the shared band: its members across the full width.
      const idx = blocks.length;
      blocks.push({ id: SHARED_BAR, parent: idx - 1, x: 0, y, w: UW, h: ROW });
      drawBar(0, y, UW, ROW, sharedFill(true), sharedBandLabel(), 1);
      drawLevel(sharedMembers, null, 0, UW, y + ROW, 1, idx, 0);
      return;
    }

    const rootId = focusPath[0];
    for (let i = 0; i < Math.max(0, focusPath.length - 1); i += 1) {
      const id = focusPath[i];
      blocks.push({ id, parent: blocks.length - 1, x: 0, y, w: UW, h: ANC, anc: i });
      drawBar(
        0,
        y,
        UW,
        ANC,
        fillFor(id, focusShared ? id : rootId, 1, false),
        `${barLabel(id)}  ↩`,
        0.7,
        cb.isDimmed(id),
      );
      y += ANC;
    }

    if (focusPath.length === 0) {
      // Top level: direct dependencies plus the shared band.
      const total = directTop.reduce((sum, id) => sum + weightOf(id), 0) + sharedTotal;
      if (total <= 0) return;
      let x = 0;
      let topSprayW = 0;
      for (const id of directTop) {
        const w = (UW * weightOf(id)) / total;
        if (w < MIN_BLOCK_PX) {
          topSprayW += w;
          continue;
        }
        const idx = blocks.length;
        blocks.push({ id, parent: 0, x, y, w, h: ROW });
        const hl = idx === hoveredBlock || id === selectedId;
        drawBar(x, y, w, ROW, fillFor(id, id, 0, hl), barLabel(id), hl ? 1 : 0.82, !hl && cb.isDimmed(id));
        if (hl) {
          ctx.strokeStyle = theme.accent;
          ctx.lineWidth = 1.2;
          ctx.strokeRect(x + 0.5, y + 0.5, w - PAD, ROW - 2.5);
        }
        drawLevel(dom.children[id], id, x, x + w, y + ROW, 1, idx, weightOf(id));
        x += w;
      }
      if (sharedTotal > 0) {
        const w = (UW * sharedTotal) / total;
        const idx = blocks.length;
        blocks.push({ id: SHARED_BAR, parent: 0, x, y, w, h: ROW });
        const hl = idx === hoveredBlock;
        drawBar(x, y, w, ROW, sharedFill(hl), sharedBandLabel(), hl ? 1 : 0.85);
        drawLevel(sharedMembers, null, x, x + w, y + ROW, 1, idx, 0);
        x += w;
      }
      if (topSprayW > 0.4) {
        ctx.fillStyle = "rgba(90, 110, 130, 0.22)";
        ctx.fillRect(x, y + ROW * 0.3, Math.max(0.5, topSprayW - PAD / 2), ROW * 0.4);
      }
      return;
    }

    const focus = focusPath[focusPath.length - 1];
    const idx = blocks.length;
    blocks.push({ id: focus, parent: idx - 1, x: 0, y, w: UW, h: ROW });
    const hl = focus === selectedId;
    drawBar(0, y, UW, ROW, fillFor(focus, focusShared ? focus : rootId, 1, true), barLabel(focus), 1);
    if (hl) {
      ctx.strokeStyle = theme.accent;
      ctx.lineWidth = 1.2;
      ctx.strokeRect(0.5, y + 0.5, UW - 1, ROW - 2.5);
    }
    drawLevel(dom.children[focus], focusShared ? focus : rootId, 0, UW, y + ROW, 2, idx, weightOf(focus));
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

  function blockInShared(i: number): boolean {
    let cur = i;
    while (cur > 0 && blocks[cur]) {
      if (blocks[cur].id === SHARED_BAR) return true;
      cur = blocks[cur].parent;
    }
    return false;
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
      if (b.id === PROJECT_BAR) {
        focusPath = [];
        focusShared = false;
        selectedId = -1;
        cb.onSelect(-1);
        draw();
        return;
      }
      if (b.id === SHARED_BAR) {
        focusPath = [];
        focusShared = true;
        selectedId = -1;
        cb.onSelect(-1);
        draw();
        return;
      }
      const inShared = blockInShared(i);
      if (b.anc !== undefined) {
        focusPath = focusPath.slice(0, b.anc + 1);
      } else {
        focusPath = pathOfBlock(i);
      }
      focusShared = inShared;
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
      focusShared = false;
      selectedId = -1;
      hoveredBlock = -1;
      cb.onHoverTrail(null);
      cb.onSelect(-1);
      draw();
    },
    { signal },
  );

  /** Dominator-tree ancestor chain, for search / chip jumps. */
  function findPath(target: number): number[] | null {
    if (dom.idom[target] === -2) return null;
    const path: number[] = [];
    let cur = target;
    let guard = 0;
    while (cur >= 0 && guard < 100_000) {
      path.unshift(cur);
      cur = dom.idom[cur];
      guard += 1;
    }
    return path;
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
      focusShared = !directRootSet.has(path[0]);
      selectedId = index;
      hoveredBlock = -1;
      draw();
    },
  };
}
