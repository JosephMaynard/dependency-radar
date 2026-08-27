/**
 * Renders a SlideModel as a standalone 1600x900 SVG dashboard: one bento
 * board a CTO can drop on a slide or a workflow can attach to a PR.
 *
 * The output must stay self-contained: every colour is inlined from the
 * palette (no CSS custom properties), fonts are the system stack with real
 * fallbacks, and icons are embedded path data. That is what lets the same
 * string render inside the report, save as an .svg that opens anywhere, and
 * rasterise to PNG without a stylesheet in reach.
 */

import { iconSvg, type IconName } from "./icons";
import {
  SIZE_BLOCK_LIMIT,
  type SlideMetric,
  type SlideModel,
} from "./slideModel";

export type SlideTheme = "dark" | "light";

interface SlidePalette {
  bg: string;
  bgEdge: string;
  card: string;
  cardLine: string;
  cardTopLight: string;
  ink: string;
  secondary: string;
  muted: string;
  accent: string;
  /** Treemap block fill alpha range endpoints, applied to accent. */
  blockAlphaMin: number;
  blockAlphaMax: number;
  otherBlock: string;
  tones: Record<"green" | "amber" | "red" | "gray", string>;
  toneBg: Record<"green" | "amber" | "red" | "gray", string>;
}

/**
 * Both palettes derive from the report's style.css tokens. The light theme
 * swaps the status hues for their darker text-safe steps (the report's own
 * light theme makes the same trade; #f59e0b measures 1.81:1 on white).
 */
const PALETTES: Record<SlideTheme, SlidePalette> = {
  dark: {
    bg: "#0c1222",
    bgEdge: "#0a0e1b",
    card: "#151d2e",
    cardLine: "rgba(99, 120, 150, 0.24)",
    cardTopLight: "rgba(255, 255, 255, 0.05)",
    ink: "#e8edf5",
    secondary: "#8b99b0",
    muted: "#5c6b82",
    accent: "#22d3ee",
    blockAlphaMin: 0.1,
    blockAlphaMax: 0.32,
    otherBlock: "rgba(100, 116, 139, 0.14)",
    tones: {
      green: "#34d399",
      amber: "#fbbf24",
      red: "#f87171",
      gray: "#8b99b0",
    },
    toneBg: {
      green: "rgba(16, 185, 129, 0.14)",
      amber: "rgba(245, 158, 11, 0.14)",
      red: "rgba(239, 68, 68, 0.14)",
      gray: "rgba(100, 116, 139, 0.16)",
    },
  },
  light: {
    bg: "#f6f8fb",
    bgEdge: "#eef1f6",
    card: "#ffffff",
    cardLine: "rgba(15, 23, 42, 0.1)",
    cardTopLight: "rgba(255, 255, 255, 0.85)",
    ink: "#101828",
    secondary: "#475467",
    muted: "#8a94a6",
    accent: "#0e7490",
    blockAlphaMin: 0.14,
    blockAlphaMax: 0.38,
    otherBlock: "rgba(100, 116, 139, 0.15)",
    tones: {
      green: "#047857",
      amber: "#b45309",
      red: "#b91c1c",
      gray: "#667085",
    },
    toneBg: {
      green: "rgba(4, 120, 87, 0.1)",
      amber: "rgba(180, 83, 9, 0.1)",
      red: "rgba(185, 28, 28, 0.09)",
      gray: "rgba(100, 116, 139, 0.12)",
    },
  },
};

export const SLIDE_WIDTH = 1600;
export const SLIDE_HEIGHT = 900;

const PAD = 56;
const GAP = 20;
const GRID_TOP = 172;
const HERO_WIDTH = 726;
const TILE_RADIUS = 18;

const FONT_STACK =
  "-apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif";

function esc(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function formatSlideBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + " GB";
  }
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  if (bytes >= 1024) return Math.round(bytes / 1024) + " kB";
  return bytes + " B";
}

function formatSlideDate(iso: string): string {
  const date = new Date(iso);
  if (isNaN(date.getTime())) return "";
  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  return (
    date.getUTCDate() + " " + months[date.getUTCMonth()] + " " + date.getUTCFullYear()
  );
}

function text(
  x: number,
  y: number,
  content: string,
  options: {
    size: number;
    fill: string;
    weight?: number;
    anchor?: "start" | "middle" | "end";
    spacing?: string;
    mono?: boolean;
  },
): string {
  return (
    '<text x="' + x + '" y="' + y + '"' +
    ' font-family="' + (options.mono
      ? "ui-monospace, 'SF Mono', Menlo, Consolas, monospace"
      : FONT_STACK) + '"' +
    ' font-size="' + options.size + '"' +
    (options.weight ? ' font-weight="' + options.weight + '"' : "") +
    ' fill="' + options.fill + '"' +
    (options.anchor ? ' text-anchor="' + options.anchor + '"' : "") +
    (options.spacing ? ' letter-spacing="' + options.spacing + '"' : "") +
    ">" + content + "</text>"
  );
}

/** Truncate to an estimated pixel width; SVG has no text-overflow. */
function fitText(value: string, maxWidth: number, fontSize: number): string {
  const avgChar = fontSize * 0.56;
  const maxChars = Math.floor(maxWidth / avgChar);
  if (value.length <= maxChars) return value;
  if (maxChars <= 1) return "";
  return value.slice(0, Math.max(1, maxChars - 1)) + "…";
}

function cardShell(
  x: number,
  y: number,
  w: number,
  h: number,
  p: SlidePalette,
): string {
  // The 0.75px inner line along the top edge reads as a catch-light and is
  // what keeps the tiles from looking flat; it hugs the rounded corners by
  // reusing the same radius.
  return (
    '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '"' +
    ' rx="' + TILE_RADIUS + '" fill="' + p.card + '" stroke="' + p.cardLine + '" stroke-width="1"/>' +
    '<path d="M ' + (x + TILE_RADIUS) + " " + (y + 0.75) +
    " H " + (x + w - TILE_RADIUS) + '"' +
    ' stroke="' + p.cardTopLight + '" stroke-width="1.5" fill="none" stroke-linecap="round"/>'
  );
}

function iconBadge(
  x: number,
  y: number,
  size: number,
  icon: IconName,
  tone: string,
  toneBg: string,
): string {
  const iconSize = Math.round(size * 0.52);
  const inset = Math.round((size - iconSize) / 2);
  return (
    '<rect x="' + x + '" y="' + y + '" width="' + size + '" height="' + size + '"' +
    ' rx="' + Math.round(size * 0.28) + '" fill="' + toneBg + '"/>' +
    iconSvg(icon, {
      size: iconSize,
      x: x + inset,
      y: y + inset,
      stroke: tone,
      strokeWidth: 2,
    })
  );
}

interface TileSpec {
  icon: IconName;
  label: string;
  metric: SlideMetric;
  /** Line shown when the count is zero and healthy. */
  zeroDetail: string;
  /** Informational tiles pin the badge to the accent instead of a tone. */
  accentBadge?: boolean;
}

function metricTile(
  x: number,
  y: number,
  w: number,
  h: number,
  spec: TileSpec,
  p: SlidePalette,
): string {
  const padX = 28;
  const notChecked = spec.metric.count < 0;
  const tone = spec.accentBadge
    ? p.accent
    : notChecked
      ? p.tones.gray
      : p.tones[spec.metric.tone];
  const toneBg =
    spec.accentBadge || notChecked
      ? p.toneBg.gray
      : p.toneBg[spec.metric.tone];
  const parts: string[] = [cardShell(x, y, w, h, p)];
  parts.push(iconBadge(x + padX, y + 26, 44, spec.icon, tone, toneBg));
  parts.push(
    text(x + padX + 44 + 16, y + 26 + 28, spec.label.toUpperCase(), {
      size: 13,
      fill: p.secondary,
      weight: 600,
      spacing: "1.4",
    }),
  );
  if (notChecked) {
    parts.push(
      text(x + padX, y + h - 62, "–", {
        size: 52,
        fill: p.muted,
        weight: 600,
      }),
    );
    parts.push(
      text(x + padX, y + h - 26, "Not checked in this scan", {
        size: 14,
        fill: p.muted,
      }),
    );
  } else {
    parts.push(
      text(x + padX, y + h - 62, String(spec.metric.count), {
        size: 52,
        fill: p.ink,
        weight: 650,
      }),
    );
    const detail = spec.metric.detail ||
      (spec.metric.count === 0 ? spec.zeroDetail : "");
    if (detail) {
      parts.push(
        text(x + padX, y + h - 26, esc(detail), {
          size: 14,
          fill: p.secondary,
        }),
      );
    }
  }
  return parts.join("");
}

interface TreemapRect {
  x: number;
  y: number;
  w: number;
  h: number;
  name: string;
  bytes: number;
  isOther: boolean;
  rank: number;
}

/**
 * Squarified treemap, largest-first. Items must be sorted descending; the
 * algorithm lays rows against the shorter side, which keeps blocks close to
 * square and their labels readable.
 */
function layoutTreemap(
  items: Array<{ name: string; bytes: number; isOther: boolean }>,
  x: number,
  y: number,
  w: number,
  h: number,
): TreemapRect[] {
  const positive = items.filter((item) => item.bytes > 0);
  const total = positive.reduce((sum, item) => sum + item.bytes, 0);
  if (total <= 0 || w <= 0 || h <= 0) return [];
  const scale = (w * h) / total;
  const areas = positive.map((item, index) => ({
    ...item,
    area: item.bytes * scale,
    rank: index,
  }));
  const out: TreemapRect[] = [];
  let rx = x, ry = y, rw = w, rh = h;
  let row: typeof areas = [];
  let queue = areas.slice();

  const worst = (candidates: typeof areas, side: number): number => {
    const sum = candidates.reduce((s, c) => s + c.area, 0);
    let max = 0;
    for (const c of candidates) {
      const ratio = Math.max(
        (side * side * c.area) / (sum * sum),
        (sum * sum) / (side * side * c.area),
      );
      if (ratio > max) max = ratio;
    }
    return max;
  };

  const flushRow = (): void => {
    if (!row.length) return;
    const sum = row.reduce((s, c) => s + c.area, 0);
    const horizontal = rw >= rh;
    const side = horizontal ? rh : rw;
    const thickness = sum / side;
    let offset = 0;
    for (const item of row) {
      const length = item.area / thickness;
      out.push(
        horizontal
          ? { x: rx, y: ry + offset, w: thickness, h: length,
              name: item.name, bytes: item.bytes, isOther: item.isOther, rank: item.rank }
          : { x: rx + offset, y: ry, w: length, h: thickness,
              name: item.name, bytes: item.bytes, isOther: item.isOther, rank: item.rank },
      );
      offset += length;
    }
    if (horizontal) {
      rx += thickness;
      rw -= thickness;
    } else {
      ry += thickness;
      rh -= thickness;
    }
    row = [];
  };

  while (queue.length) {
    const side = Math.min(rw, rh);
    const next = queue[0];
    if (!row.length || worst([...row, next], side) <= worst(row, side)) {
      row.push(next);
      queue = queue.slice(1);
    } else {
      flushRow();
    }
  }
  flushRow();
  return out;
}

function heroTile(
  x: number,
  y: number,
  w: number,
  h: number,
  model: SlideModel,
  p: SlidePalette,
): string {
  const padX = 32;
  const parts: string[] = [cardShell(x, y, w, h, p)];
  const accentBg = p.toneBg.gray;
  parts.push(iconBadge(x + padX, y + 30, 48, "hard-drive", p.accent, accentBg));
  parts.push(
    text(x + padX + 48 + 16, y + 30 + 30, "INSTALL SIZE", {
      size: 13,
      fill: p.secondary,
      weight: 600,
      spacing: "1.4",
    }),
  );

  const measured = model.totalInstallBytes >= 0;
  if (!measured) {
    parts.push(
      text(x + padX, y + 170, "–", { size: 74, fill: p.muted, weight: 600 }),
    );
    parts.push(
      text(x + padX, y + 210, "Not measured · node_modules was not on disk", {
        size: 15,
        fill: p.muted,
      }),
    );
    return parts.join("");
  }

  parts.push(
    text(x + padX, y + 172, esc(formatSlideBytes(model.totalInstallBytes)), {
      size: 74,
      fill: p.ink,
      weight: 650,
    }),
  );
  const coverage =
    model.measuredPackageCount < model.dependencyCount
      ? "measured on disk · " +
        model.measuredPackageCount +
        " of " +
        model.dependencyCount +
        " packages measured"
      : "measured on disk · " + model.dependencyCount + " installed packages";
  parts.push(
    text(x + padX, y + 208, coverage, { size: 15, fill: p.secondary }),
  );

  // Treemap of the largest packages, "everything else" folded into one
  // muted block so the picture always accounts for the whole total.
  const mapX = x + padX;
  const mapY = y + 244;
  const mapW = w - padX * 2;
  const mapH = h - 244 - 64;
  const items = model.sizeBlocks.map((block) => ({
    name: block.name,
    bytes: block.bytes,
    isOther: false,
  }));
  if (model.sizeOtherBytes > 0) {
    items.push({
      name: "everything else",
      bytes: model.sizeOtherBytes,
      isOther: true,
    });
  }
  items.sort((a, b) => b.bytes - a.bytes);
  const rects = layoutTreemap(items, mapX, mapY, mapW, mapH);
  const maxRank = Math.max(1, items.length - 1);
  for (const rect of rects) {
    const gapped = {
      x: rect.x + 1,
      y: rect.y + 1,
      w: Math.max(0, rect.w - 2),
      h: Math.max(0, rect.h - 2),
    };
    const alpha = rect.isOther
      ? 0
      : p.blockAlphaMax -
        ((p.blockAlphaMax - p.blockAlphaMin) * rect.rank) / maxRank;
    const fill = rect.isOther
      ? p.otherBlock
      : hexWithAlpha(p.accent, alpha);
    parts.push(
      '<rect x="' + round2(gapped.x) + '" y="' + round2(gapped.y) +
      '" width="' + round2(gapped.w) + '" height="' + round2(gapped.h) +
      '" rx="8" fill="' + fill + '"' +
      (rect.isOther ? "" : ' stroke="' + hexWithAlpha(p.accent, 0.35) + '" stroke-width="1"') +
      "/>",
    );
    if (gapped.w > 96 && gapped.h > 44) {
      const label = fitText(rect.name, gapped.w - 24, 14);
      if (label) {
        parts.push(
          text(round2(gapped.x + 12), round2(gapped.y + 24), esc(label), {
            size: 14,
            fill: p.ink,
            weight: 600,
          }),
        );
        if (gapped.h > 64) {
          parts.push(
            text(
              round2(gapped.x + 12),
              round2(gapped.y + 43),
              esc(formatSlideBytes(rect.bytes)),
              { size: 12.5, fill: p.secondary },
            ),
          );
        }
      }
    }
  }
  parts.push(
    text(
      mapX,
      y + h - 26,
      "Largest packages by measured size · top " +
        Math.min(SIZE_BLOCK_LIMIT, model.sizeBlocks.length) +
        " shown by name",
      { size: 13, fill: p.muted },
    ),
  );
  return parts.join("");
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

function hexWithAlpha(hex: string, alpha: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return "rgba(" + r + ", " + g + ", " + b + ", " + round2(alpha) + ")";
}

/** Compact radar mark echoing the logo: rings, a sweep, one contact. */
function radarMark(cx: number, cy: number, r: number, p: SlidePalette): string {
  return (
    '<g stroke="' + p.secondary + '" fill="none" stroke-width="1.5">' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '"/>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + round2(r * 0.62) + '" opacity="0.55"/>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + round2(r * 0.3) + '" opacity="0.35"/>' +
    "</g>" +
    '<line x1="' + cx + '" y1="' + cy + '" x2="' + round2(cx + r * 0.83) +
    '" y2="' + round2(cy - r * 0.55) + '" stroke="' + p.accent + '" stroke-width="1.5"/>' +
    '<circle cx="' + round2(cx - r * 0.4) + '" cy="' + round2(cy + r * 0.42) +
    '" r="2.5" fill="' + p.accent + '"/>'
  );
}

export function buildSlideSvg(model: SlideModel, theme: SlideTheme): string {
  const p = PALETTES[theme];
  const parts: string[] = [];

  parts.push(
    '<svg xmlns="http://www.w3.org/2000/svg" width="' + SLIDE_WIDTH +
    '" height="' + SLIDE_HEIGHT + '" viewBox="0 0 ' + SLIDE_WIDTH + " " +
    SLIDE_HEIGHT + '" role="img" aria-label="Dependency health dashboard for ' +
    esc(model.projectName) + '">',
  );
  parts.push(
    "<defs>" +
    '<linearGradient id="slide-bg" x1="0" y1="0" x2="0" y2="1">' +
    '<stop offset="0" stop-color="' + p.bg + '"/>' +
    '<stop offset="1" stop-color="' + p.bgEdge + '"/>' +
    "</linearGradient>" +
    "</defs>",
  );
  parts.push(
    '<rect width="' + SLIDE_WIDTH + '" height="' + SLIDE_HEIGHT +
    '" fill="url(#slide-bg)"/>',
  );

  // Header: project identity left, provenance right.
  parts.push(
    text(PAD, 84, "DEPENDENCY HEALTH", {
      size: 13,
      fill: p.accent,
      weight: 650,
      spacing: "2.2",
    }),
  );
  parts.push(
    text(PAD, 124, esc(fitText(model.projectName, 900, 34)), {
      size: 34,
      fill: p.ink,
      weight: 650,
    }),
  );
  parts.push(radarMark(SLIDE_WIDTH - PAD - 16, 84, 16, p));
  parts.push(
    text(SLIDE_WIDTH - PAD - 44, 89, "dependency-radar", {
      size: 15,
      fill: p.secondary,
      weight: 600,
      anchor: "end",
    }),
  );
  const provenance = [
    model.generatedAt ? "Generated " + formatSlideDate(model.generatedAt) : "",
    model.toolVersion ? "v" + model.toolVersion : "",
  ]
    .filter(Boolean)
    .join(" · ");
  if (provenance) {
    parts.push(
      text(SLIDE_WIDTH - PAD, 124, esc(provenance), {
        size: 13,
        fill: p.muted,
        anchor: "end",
      }),
    );
  }

  // Bento grid: full-height hero left, six tiles in a 2x3 block right.
  const gridHeight = SLIDE_HEIGHT - GRID_TOP - PAD;
  const heroX = PAD;
  parts.push(heroTile(heroX, GRID_TOP, HERO_WIDTH, gridHeight, model, p));

  const tilesX = PAD + HERO_WIDTH + GAP;
  const tileW = (SLIDE_WIDTH - PAD - tilesX - GAP) / 2;
  const tileH = (gridHeight - GAP * 2) / 3;
  const specs: TileSpec[] = [
    // Informational, not a status: the badge pins to the accent so only
    // genuine findings wear warning colours.
    {
      icon: "boxes",
      label: "Dependencies",
      metric: {
        count: model.dependencyCount,
        detail: model.directCount + " direct · " + model.transitiveCount + " transitive",
        tone: "gray",
      },
      zeroDetail: "",
      accentBadge: true,
    },
    {
      icon: "shield-alert",
      label: "Vulnerable packages",
      metric: model.vulnerabilities,
      zeroDetail: "none reported by audit",
    },
    {
      icon: "heart-pulse",
      label: "Maintenance concerns",
      metric: model.maintenance,
      zeroDetail: "all packages look active",
    },
    {
      icon: "scale",
      label: "Licence issues",
      metric: model.licenses,
      zeroDetail: "all licences look permissive",
    },
    {
      icon: "circle-arrow-up",
      label: "Upgrade blockers",
      metric: model.blockers,
      zeroDetail: "nothing pins an upgrade",
    },
    {
      icon: "copy",
      label: "Duplicate versions",
      metric: model.duplicates,
      zeroDetail: "one installed copy each",
    },
  ];
  specs.forEach((spec, index) => {
    const col = index % 2;
    const rowIndex = Math.floor(index / 2);
    const tx = tilesX + col * (tileW + GAP);
    const ty = GRID_TOP + rowIndex * (tileH + GAP);
    parts.push(metricTile(tx, ty, tileW, tileH, spec, p));
  });

  parts.push("</svg>");
  return parts.join("");
}
