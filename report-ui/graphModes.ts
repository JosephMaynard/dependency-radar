import type { GraphDataset, GraphViewHandle } from "./graphView";
import type { GraphFilters, VizHandle, VizModel } from "./vizModel";
import { FINE_PRINT } from "./finePrint";
import {
  buildVizModel,
  DEFAULT_GRAPH_FILTERS,
  resolveVizTheme,
} from "./vizModel";
import { mountFlameView } from "./flameView";
import { mountBalloonView } from "./balloonView";
import { mountHyperbolicView } from "./hyperbolicView";
import { mountTreemapView } from "./treemapView";

// Orchestrates the graph panel's five layout modes (classic graph + flame +
// treemap + balloon + hyperbolic), the shared docked side panel (search +
// dossier), and
// the status line. The classic graph view keeps its own canvas and handle;
// alternative views mount a fresh canvas each and are destroyed on switch
// (reset-on-switch is deliberate — see docs/VIZ-VIEWS-HANDOFF.md).

export type GraphMode = "graph" | "flame" | "treemap" | "balloon" | "hyperbolic";

const GRAPH_MODES: GraphMode[] = ["graph", "flame", "treemap", "balloon", "hyperbolic"];

// Persisted alongside the theme preference (see main.ts).
const MODE_STORE_KEY = "dependency-radar-graph-mode";
const FILTER_STORE_KEY = "dependency-radar-graph-filters";

// Largest depth the toolbar select offers; persisted values are clamped so a
// stored depth always has a matching option.
const MAX_DEPTH_OPTION = 5;

/** Signals worth spotlighting: non-matching packages dim in every view. */
export type HighlightKind =
  | "vuln"
  | "maintenance"
  | "replacement"
  | "license"
  | "blocker"
  | "unused"
  | "duplicate";

const HIGHLIGHT_KINDS: HighlightKind[] = [
  "vuln",
  "maintenance",
  "replacement",
  "license",
  "blocker",
  "unused",
  "duplicate",
];

const MODE_HINTS: Record<GraphMode, string> = {
  graph: "click a node to inspect · drag to pan · scroll to zoom",
  flame:
    "hover a bar · click to zoom in · click a pinned ancestor to climb back out · double-click to reset",
  treemap:
    "click a box to inspect · double-click to drill in · double-click the zoomed box to climb back out",
  balloon: "drag to pan · scroll to zoom · click a body · double-click space to fit",
  hyperbolic: "drag to warp · scroll to zoom · click a blip to focus · double-click space to reset",
};

export interface GraphModesOptions {
  dataset: GraphDataset;
  projectName: string;
  altHost: HTMLElement;
  modeSwitch: HTMLElement;
  statusLine: HTMLElement;
  searchInput: HTMLInputElement;
  searchResults: HTMLElement;
  dossier: HTMLElement;
  sidePanel: HTMLElement;
  /** The toolbar key/legend; its content switches per mode. */
  keyEl: HTMLElement | null;
  workspaceSelect: HTMLSelectElement;
  /** Elements only meaningful for the classic graph (dpad, zoom, key). */
  classicOnly: HTMLElement[];
  /** Kind-filter chips and the depth-cap select in the toolbar. */
  filterRuntime: HTMLButtonElement | null;
  filterDev: HTMLButtonElement | null;
  filterSub: HTMLButtonElement | null;
  filterDepth: HTMLSelectElement | null;
  /** Community replacement suggestion (e18e module-replacements), if any. */
  getReplacement?: (slug: string) => {
    replacements: string[];
    docUrl?: string;
  } | null;
  /** Whether the package matches a highlight signal (from the full report). */
  highlightMatch?: (slug: string, kind: HighlightKind) => boolean;
  /** Extra per-package facts derived from the full report record. */
  getPackageExtras?: (slug: string) => {
    sizeBytes?: number;
    codeBytes?: number;
    platformNote?: string;
    phantom?: boolean;
    importFileCount?: number;
  };
  getClassicHandle: () => GraphViewHandle | null;
  onOpenList: (slug: string) => void;
  /** Shared default-filters model cache (also used by the list view), so
   *  removal-simulation memos are shared across views. */
  getSharedModel?: (workspace: string) => VizModel;
  /** Notify the hash router that user-visible graph state changed. */
  onRouteChange?: () => void;
}

/** Serializable graph state for the hash router. */
export interface GraphRoute {
  mode: GraphMode;
  workspace: string;
  selected: string | null;
  highlights: string[];
  runtime: boolean;
  dev: boolean;
  sub: boolean;
  depth: number | null;
}

export interface GraphModesHandle {
  /** Current mode. */
  mode(): GraphMode;
  /** Current serializable state for the hash router. */
  routeState(): GraphRoute;
  /** Restore a previously serialized state (history navigation). */
  applyRoute(route: GraphRoute): void;
  /** Selection relay from the classic graph view. */
  handleClassicSelect(slug: string | null): void;
  /** Current display filters, shared with the classic graph view. */
  filters(): GraphFilters;
  /** True when a name filter is active and this package does not match. */
  isNameDimmed(slug: string): boolean;
  /** Re-measure the active alternative view (call when the panel shows). */
  refresh(): void;
}

export function initGraphModes(options: GraphModesOptions): GraphModesHandle {
  let mode: GraphMode = "graph";
  let activeView: VizHandle | null = null;
  let model: VizModel | null = null;
  let modelWorkspace = "";
  let modelFilterKey = "";
  // Active name filter (lower-cased search query); dims non-matching nodes.
  let dimQuery = "";

  const filters: GraphFilters = { ...DEFAULT_GRAPH_FILTERS };
  /** Active highlight signals: non-matching packages render dimmed. */
  const highlights = new Set<HighlightKind>();
  /** A highlight can be restored only when its evidence exists — main.ts
   *  disables the chip when a collector was skipped or incomplete. */
  const highlightAvailable = (kind: HighlightKind): boolean =>
    !(document.getElementById(`graph-hl-${kind}`) as HTMLButtonElement | null)
      ?.disabled;
  /** Slug of the package currently in the dossier (for the hash router). */
  let routeSelected: string | null = null;
  try {
    const raw = localStorage.getItem(FILTER_STORE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<GraphFilters> & {
        highlights?: string[];
      };
      if (typeof parsed.runtime === "boolean") filters.runtime = parsed.runtime;
      if (typeof parsed.dev === "boolean") filters.dev = parsed.dev;
      if (typeof parsed.sub === "boolean") filters.sub = parsed.sub;
      if (
        typeof parsed.maxDepth === "number" &&
        Number.isInteger(parsed.maxDepth) &&
        parsed.maxDepth >= 1 &&
        parsed.maxDepth <= MAX_DEPTH_OPTION
      ) {
        filters.maxDepth = parsed.maxDepth;
      }
      if (Array.isArray(parsed.highlights)) {
        for (const kind of parsed.highlights) {
          if (
            HIGHLIGHT_KINDS.includes(kind as HighlightKind) &&
            highlightAvailable(kind as HighlightKind)
          ) {
            highlights.add(kind as HighlightKind);
          }
        }
      }
    }
  } catch {
    // Storage unavailable (private mode / file protocol restrictions).
  }
  if (!filters.runtime && !filters.dev) {
    // Never restore into a rootless graph.
    filters.runtime = true;
    filters.dev = true;
  }

  function persistFilters(): void {
    try {
      localStorage.setItem(
        FILTER_STORE_KEY,
        JSON.stringify({ ...filters, highlights: [...highlights] }),
      );
    } catch {
      // Best-effort persistence only.
    }
  }

  const theme = resolveVizTheme;
  const shell = options.altHost.parentElement as HTMLElement | null;
  const insetRight = (): number => {
    if (!shell) return 0;
    // Fullscreen hides the side panel — the canvas owns the full width.
    if (shell.classList.contains("graph-fullscreen")) return 0;
    return (
      parseFloat(
        getComputedStyle(shell).getPropertyValue("--graph-panel-space"),
      ) || 0
    );
  };
  const insetTop = (): number => {
    if (!shell) return 60;
    // Fullscreen hides the toolbar too.
    if (shell.classList.contains("graph-fullscreen")) return 10;
    const toolbar = parseFloat(
      getComputedStyle(shell).getPropertyValue("--graph-toolbar-height"),
    );
    return (Number.isFinite(toolbar) && toolbar > 0 ? toolbar : 50) + 10;
  };
  // Toolbar dropdowns (Key, Filters): a compact toggle opens a panel;
  // outside-click and Escape close it, and Escape only reclaims focus when
  // it was inside the component — an Escape aimed at the search box must
  // not yank focus across the toolbar.
  const dropdownClosers: Array<() => void> = [];
  function bindDropdown(
    container: HTMLElement | null,
    toggle: HTMLButtonElement | null,
    panel: HTMLElement | null,
  ): void {
    if (!container || !toggle || !panel) return;
    const setOpen = (open: boolean): void => {
      panel.hidden = !open;
      toggle.setAttribute("aria-expanded", String(open));
      toggle.classList.toggle("open", open);
    };
    dropdownClosers.push(() => setOpen(false));
    toggle.addEventListener("click", () => {
      const willOpen = panel.hidden === true;
      // One dropdown at a time — keyboard activation fires no pointerdown,
      // so the outside-click closer alone can't guarantee it.
      if (willOpen) for (const close of dropdownClosers) close();
      setOpen(willOpen);
    });
    document.addEventListener("pointerdown", (event) => {
      if (panel.hidden) return;
      if (container.contains(event.target as Node)) return;
      setOpen(false);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || panel.hidden) return;
      setOpen(false);
      if (container.contains(document.activeElement)) toggle.focus();
    });
  }

  const keyToggle =
    options.keyEl?.querySelector<HTMLButtonElement>(".graph-key-toggle") ?? null;
  const keyPanel =
    options.keyEl?.querySelector<HTMLElement>(".graph-key-panel") ?? null;
  const keyItemsEl =
    options.keyEl?.querySelector<HTMLElement>(".graph-key-items") ?? null;
  const classicKeyNodes = keyItemsEl ? Array.from(keyItemsEl.childNodes) : [];
  bindDropdown(options.keyEl, keyToggle, keyPanel);

  const filterWrap = document.getElementById("graph-filter-wrap");
  bindDropdown(
    filterWrap,
    document.getElementById("graph-filters-toggle") as HTMLButtonElement | null,
    document.getElementById("graph-filters-panel"),
  );
  const filtersBadge = document.getElementById("graph-filters-badge");

  function syncFiltersBadge(): void {
    if (!filtersBadge) return;
    const shown =
      Number(!filters.runtime) +
      Number(!filters.dev) +
      Number(!filters.sub) +
      // The depth cap is inert (and its control disabled) with sub-deps off.
      Number(filters.sub && filters.maxDepth !== null) +
      highlights.size;
    filtersBadge.hidden = shown === 0;
    filtersBadge.textContent = String(shown);
  }

  // Floating reset for the alternative views (flame resets via double-click
  // and its pinned ancestors, so it opts out; the treemap tiles the whole
  // stage, so the button appears only while zoomed — there is no "empty
  // space to double-click" once you have drilled in).
  const resetBtn = document.createElement("button");
  resetBtn.type = "button";
  resetBtn.className = "graph-alt-reset";
  resetBtn.textContent = "Reset view";
  resetBtn.hidden = true;
  resetBtn.addEventListener("click", () => {
    activeView?.resetView?.();
  });
  shell?.appendChild(resetBtn);

  const emptyWsEl = document.createElement("div");
  emptyWsEl.className = "graph-empty-ws";
  emptyWsEl.hidden = true;
  shell?.appendChild(emptyWsEl);
  /** A workspace with no dependencies renders as a lone project dot —
   *  show an explanation and clickable alternatives instead. */
  function syncEmptyState(): void {
    const m = ensureModel();
    if (m.count > 0) {
      emptyWsEl.hidden = true;
      return;
    }
    const wsName = options.workspaceSelect.value || m.workspaceName || "this workspace";
    emptyWsEl.textContent = "";
    const card = el("div", "graph-empty-ws-card");
    // Distinguish a genuinely empty manifest from one the display filters
    // emptied — the fix differs (pick another workspace vs reset filters).
    const wsEntry = options.dataset.workspaces.find((w) => w.name === wsName);
    const declared = wsEntry
      ? wsEntry.directDependencies.length + wsEntry.directDevDependencies.length
      : 0;
    if (declared > 0) {
      card.appendChild(
        el("h2", "graph-empty-ws-title", `Nothing to show in ${wsName}`),
      );
      card.appendChild(
        el(
          "p",
          "graph-empty-ws-note",
          "The current display filters hide every dependency in this workspace.",
        ),
      );
      const reset = el("button", "graph-empty-ws-item", "Reset filters");
      (reset as HTMLButtonElement).type = "button";
      reset.addEventListener("click", () => {
        document.getElementById("graph-filters-reset")?.click();
      });
      card.appendChild(reset);
      emptyWsEl.appendChild(card);
      emptyWsEl.hidden = false;
      return;
    }
    card.appendChild(el("h2", "graph-empty-ws-title", `No dependencies in ${wsName}`));
    const ranked = options.dataset.workspaces
      .map((w) => ({
        name: w.name,
        count: w.directDependencies.length + w.directDevDependencies.length,
      }))
      .filter((w) => w.count > 0 && w.name !== wsName)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    card.appendChild(
      el(
        "p",
        "graph-empty-ws-note",
        ranked.length > 0
          ? "This workspace declares no external dependencies. Workspaces that do:"
          : "This workspace declares no external dependencies.",
      ),
    );
    if (ranked.length > 0) {
      const list = el("div", "graph-empty-ws-list");
      for (const w of ranked) {
        const btn = el(
          "button",
          "graph-empty-ws-item",
          `${w.name === "root" ? "Whole project" : w.name} (${w.count.toLocaleString()})`,
        );
        (btn as HTMLButtonElement).type = "button";
        btn.addEventListener("click", () => {
          options.workspaceSelect.value = w.name;
          options.workspaceSelect.dispatchEvent(new Event("change"));
        });
        list.appendChild(btn);
      }
      card.appendChild(list);
    }
    emptyWsEl.appendChild(card);
    emptyWsEl.hidden = false;
  }

  // Full screen (presentation mode): the shell fullscreens; CSS hides the
  // toolbar and side panel, keeping the canvas, status line, per-view
  // controls, and this button (as the exit affordance).
  const fsBtn = document.createElement("button");
  fsBtn.type = "button";
  fsBtn.className = "graph-fullscreen-btn";
  fsBtn.textContent = "\u26f6 Full screen";
  fsBtn.setAttribute("aria-label", "Show the graph full screen");
  /** True while the fixed-position fallback (no Fullscreen API) is active. */
  let fsFallback = false;
  function setFullscreenUi(active: boolean): void {
    shell?.classList.toggle("graph-fullscreen", active);
    fsBtn.textContent = active ? "\u26f6 Exit full screen" : "\u26f6 Full screen";
    fsBtn.setAttribute(
      "aria-label",
      active ? "Exit full screen" : "Show the graph full screen",
    );
    // The shell's dimensions change; every view sizes off its host. Fire
    // again on the next tick — native fullscreen transitions settle late.
    window.dispatchEvent(new Event("resize"));
    window.setTimeout(() => window.dispatchEvent(new Event("resize")), 120);
  }
  function exitFsFallback(): void {
    fsFallback = false;
    shell?.classList.remove("graph-fullscreen-fallback");
    setFullscreenUi(false);
  }
  fsBtn.addEventListener("click", () => {
    if (document.fullscreenElement) {
      void document.exitFullscreen();
      return;
    }
    if (fsFallback) {
      exitFsFallback();
      return;
    }
    const request = shell?.requestFullscreen
      ? shell.requestFullscreen()
      : Promise.reject(new Error("unsupported"));
    request.catch(() => {
      // No Fullscreen API (iframe without allowfullscreen, permission
      // denied): pin the shell over the viewport instead.
      fsFallback = true;
      shell?.classList.add("graph-fullscreen-fallback");
      setFullscreenUi(true);
    });
  });
  shell?.appendChild(fsBtn);
  document.addEventListener("fullscreenchange", () => {
    setFullscreenUi(document.fullscreenElement === shell);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && fsFallback) exitFsFallback();
  });
  let treemapZoomed = false;
  function syncResetBtn(): void {
    resetBtn.hidden =
      mode === "graph" ||
      mode === "flame" ||
      (mode === "treemap" && !treemapZoomed);
  }

  function keyItem(color: string, label: string, line = false): HTMLElement {
    const item = document.createElement("span");
    item.className = "graph-key-item";
    if (color) {
      const dot = document.createElement("span");
      dot.className = line ? "graph-key-line" : "graph-key-dot";
      dot.style.background = color;
      dot.setAttribute("aria-hidden", "true");
      item.appendChild(dot);
    }
    const text = document.createElement("span");
    text.textContent = label;
    item.appendChild(text);
    return item;
  }

  const LINEAGE_SWATCH =
    "conic-gradient(from 0deg, hsl(28 60% 55%), hsl(152 60% 45%), hsl(268 60% 60%), hsl(322 60% 55%), hsl(28 60% 55%))";

  function updateKey(): void {
    if (!keyItemsEl) return;
    if (mode === "graph") {
      keyItemsEl.replaceChildren(...classicKeyNodes);
      return;
    }
    const items = document.createElement("div");
    items.className = "graph-key-items";
    if (mode === "hyperbolic") {
      items.appendChild(
        keyItem("var(--graph-hyp-direct-swatch, #ff9a58)", "Direct dependency"),
      );
      items.appendChild(
        keyItem("var(--graph-hyp-sub-swatch, #5b7186)", "Sub-dependency"),
      );
      items.appendChild(keyItem("", "Blip size — packages beneath it"));
      items.appendChild(
        keyItem(
          "var(--graph-hyp-route-swatch, #f59e0b)",
          "Selection: route back to the project",
          true,
        ),
      );
      items.appendChild(
        keyItem("var(--accent, #06b6d4)", "Selection: what it depends on", true),
      );
    } else if (mode === "flame" || mode === "treemap") {
      items.appendChild(
        keyItem(
          "",
          mode === "flame"
            ? "Bar width — packages that leave node_modules if you delete it"
            : "Box area — packages that leave node_modules if you delete it",
        ),
      );
      items.appendChild(keyItem(LINEAGE_SWATCH, "One colour per direct dependency"));
      items.appendChild(
        keyItem(
          "var(--graph-shared-swatch, #3d4c5c)",
          "Shared — kept by several dependencies; deleting one frees nothing",
        ),
      );
    } else {
      items.appendChild(
        keyItem(LINEAGE_SWATCH, "One colour per direct dependency's system"),
      );
      items.appendChild(keyItem("", "Circle size — packages in its subtree"));
    }
    if (mode === "balloon") {
      items.appendChild(keyItem("", "\u2191 required by \u00b7 \u2193 depends on"));
      items.appendChild(
        keyItem("var(--graph-vuln-high, #ef4444)", "Vulnerable (red outline)"),
      );
    } else {
      items.appendChild(
        keyItem("var(--graph-vuln-high, #ef4444)", "Vulnerable (high severity)"),
      );
    }
    keyItemsEl.replaceChildren(...Array.from(items.children));
  }

  const DEFAULT_FILTER_KEY = JSON.stringify(DEFAULT_GRAPH_FILTERS);
  function ensureModel(): VizModel {
    const workspace = options.workspaceSelect.value || "";
    const filterKey = JSON.stringify(filters);
    if (!model || modelWorkspace !== workspace || modelFilterKey !== filterKey) {
      // At default filters the model is identical to the list view's — use
      // the shared cache so simulation memos carry across views.
      model =
        filterKey === DEFAULT_FILTER_KEY && options.getSharedModel
          ? options.getSharedModel(workspace)
          : buildVizModel(options.dataset, workspace, options.projectName, {
              ...filters,
            });
      modelWorkspace = workspace;
      modelFilterKey = filterKey;
    }
    return model;
  }

  // Dim = name-filter miss OR (highlights active AND no signal match).
  // Canvas views ask per node per frame — memoise per model index; the
  // cache resets whenever the query, highlights, or model change.
  let dimCache: Int8Array | null = null;
  /** Slug-keyed twin for the classic graph, which redraws per frame. */
  const slugDimCache = new Map<string, boolean>();
  function resetDimCache(): void {
    dimCache = null;
    slugDimCache.clear();
  }

  function matchesHighlights(slug: string): boolean {
    if (highlights.size === 0) return true;
    if (!options.highlightMatch) return true;
    for (const kind of highlights) {
      if (options.highlightMatch(slug, kind)) return true;
    }
    return false;
  }

  function isDimmedIndex(index: number): boolean {
    if (!model) return false;
    if (!dimQuery && highlights.size === 0) return false;
    if (!dimCache || dimCache.length !== model.count) {
      dimCache = new Int8Array(model.count).fill(-1);
    }
    const cached = dimCache[index];
    if (cached >= 0) return cached === 1;
    let dimmed = false;
    if (dimQuery) {
      const name = model.lowerNames[index];
      if (name !== undefined && !name.includes(dimQuery)) dimmed = true;
    }
    if (!dimmed && !matchesHighlights(model.slugs[index])) dimmed = true;
    dimCache[index] = dimmed ? 1 : 0;
    return dimmed;
  }

  function isNameDimmed(slug: string): boolean {
    if (!dimQuery && highlights.size === 0) return false;
    const cached = slugDimCache.get(slug);
    if (cached !== undefined) return cached;
    let dimmed = false;
    if (dimQuery) {
      const ref = options.dataset.dependencies[slug];
      if (ref && !ref.name.toLowerCase().includes(dimQuery)) dimmed = true;
    }
    if (!dimmed) dimmed = !matchesHighlights(slug);
    slugDimCache.set(slug, dimmed);
    return dimmed;
  }

  // ----- status line ---------------------------------------------------
  function statusHint(): void {
    options.statusLine.textContent = MODE_HINTS[mode];
    options.statusLine.classList.add("dim");
  }

  function statusTrail(trail: number[] | null): void {
    if (!trail || trail.length === 0 || !model) {
      statusHint();
      return;
    }
    const m = model;
    const last = trail[trail.length - 1];
    options.statusLine.classList.remove("dim");
    // Impact facts come from the unfiltered graph: hover numbers must not
    // change when display filters do.
    const imp = m.impact(last);
    const freesText =
      imp.manifestFrees !== null
        ? `removing frees ${imp.manifestFrees.toLocaleString()}`
        : `deleting frees ${imp.exclusiveCount.toLocaleString()}`;
    options.statusLine.textContent =
      `${m.projectName} › ${trail.map((id) => m.refs[id].name).join(" › ")}` +
      ` · ${imp.subtreeCount.toLocaleString()} package${imp.subtreeCount === 1 ? "" : "s"} in subtree` +
      ` · ${freesText}`;
  }

  // ----- dossier --------------------------------------------------------
  function el<K extends keyof HTMLElementTagNameMap>(
    tag: K,
    className: string,
    text?: string,
  ): HTMLElementTagNameMap[K] {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // ----- fine print ----------------------------------------------------
  // Measured numbers and static-analysis leads carry caveats; each gets a
  // small (i) affordance opening an anchored note, and the Key panel links
  // a collected "About these numbers" view.
  const finePop = document.createElement("div");
  finePop.className = "graph-fineprint-pop";
  finePop.hidden = true;
  finePop.setAttribute("role", "note");
  finePop.tabIndex = -1;
  shell?.appendChild(finePop);
  /** The (i) button whose note is open — reset/refocused on close. */
  let fineAnchor: HTMLElement | null = null;
  function closeFinePrint(refocus = false): void {
    if (finePop.hidden) return;
    finePop.hidden = true;
    fineAnchor?.setAttribute("aria-expanded", "false");
    if (refocus) fineAnchor?.focus();
    fineAnchor = null;
  }
  document.addEventListener("pointerdown", (event) => {
    if (finePop.hidden) return;
    if (finePop.contains(event.target as Node)) return;
    closeFinePrint();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !finePop.hidden) closeFinePrint(true);
  });
  // The anchors live in the scrollable dossier — an open note would drift
  // away from its (i) on scroll, so close it instead.
  options.dossier.addEventListener("scroll", () => closeFinePrint(), { passive: true });
  function openFinePrint(topic: string, anchorEl: HTMLElement): void {
    const note = FINE_PRINT[topic];
    if (!note || !shell) return;
    if (!finePop.hidden && fineAnchor === anchorEl) {
      closeFinePrint(true);
      return;
    }
    fineAnchor?.setAttribute("aria-expanded", "false");
    fineAnchor = anchorEl;
    anchorEl.setAttribute("aria-expanded", "true");
    finePop.textContent = "";
    finePop.appendChild(el("strong", "", note.title));
    finePop.appendChild(el("p", "", note.body));
    finePop.hidden = false;
    const shellRect = shell.getBoundingClientRect();
    const a = anchorEl.getBoundingClientRect();
    // Below the anchor by default; flip above (and clamp) near the shell
    // bottom so the note stays inside the overflow-hidden shell.
    const popH = finePop.offsetHeight;
    let top = a.bottom - shellRect.top + 6;
    if (top + popH > shell.clientHeight - 8) {
      top = a.top - shellRect.top - popH - 6;
    }
    finePop.style.top = `${Math.max(8, Math.min(top, shell.clientHeight - popH - 8))}px`;
    const left = Math.max(
      8,
      Math.min(a.left - shellRect.left - 140, shell.clientWidth - 296),
    );
    finePop.style.left = `${left}px`;
    finePop.focus({ preventScroll: true });
  }
  function infoButton(topic: string): HTMLElement {
    const btn = el("button", "graph-fineprint-btn", "\u24d8");
    (btn as HTMLButtonElement).type = "button";
    btn.setAttribute("aria-label", `About: ${FINE_PRINT[topic]?.title ?? topic}`);
    btn.setAttribute("aria-haspopup", "true");
    btn.setAttribute("aria-expanded", "false");
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      openFinePrint(topic, btn);
    });
    return btn;
  }
  // "About these numbers" collected view at the foot of the Key panel.
  if (keyPanel) {
    const aboutBtn = el("button", "graph-panel-reset", "About these numbers");
    (aboutBtn as HTMLButtonElement).type = "button";
    aboutBtn.addEventListener("click", () => {
      options.dossier.textContent = "";
      options.dossier.appendChild(el("h2", "graph-dossier-name", "About these numbers"));
      for (const note of Object.values(FINE_PRINT)) {
        options.dossier.appendChild(el("h3", "graph-dossier-subtitle", note.title));
        options.dossier.appendChild(el("p", "graph-dossier-empty", note.body));
      }
    });
    keyPanel.appendChild(aboutBtn);
  }

  const formatBytes = (bytes: number): string => {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    if (bytes >= 1024) return `${Math.round(bytes / 1024)} kB`;
    return `${bytes} B`;
  };

  function chipRow(container: HTMLElement, title: string, ids: number[]): void {
    if (!model || ids.length === 0) return;
    const m = model;
    const block = el("div", "graph-dossier-block");
    block.appendChild(el("h3", "graph-dossier-subtitle", `${title} (${ids.length})`));
    const chips = el("div", "graph-dossier-chips");
    for (const id of ids.slice(0, 30)) {
      const chip = el("button", "graph-dossier-chip", m.refs[id].name);
      chip.type = "button";
      chip.addEventListener("click", () => focusPackage(id));
      chips.appendChild(chip);
    }
    if (ids.length > 30) {
      chips.appendChild(el("span", "graph-dossier-more", `+${ids.length - 30} more`));
    }
    block.appendChild(chips);
    container.appendChild(block);
  }

  function renderDossierEmpty(): void {
    if (routeSelected !== null) {
      routeSelected = null;
      options.onRouteChange?.();
    }
    options.dossier.textContent = "";
    const empty = el(
      "p",
      "graph-dossier-empty",
      mode === "graph"
        ? "Select a node to inspect it."
        : mode === "flame"
          ? "Click a bar. Width is the number of packages that would leave node_modules if you deleted it — each package is counted exactly once. The grey band holds packages shared by several dependencies: deleting any one of them frees nothing there."
          : mode === "treemap"
            ? "Click a box to inspect it; double-click to drill in. Area is the number of packages deleting it would free. The grey block is shared by several dependencies — no single one of them owns it."
          : mode === "balloon"
            ? "Click a body. Each direct dependency is a system orbiting the project; its sub-dependencies fan out behind it."
            : "Click a blip. Drag toward the centre to grow that part of the tree — nothing ever leaves the disk.",
    );
    options.dossier.appendChild(empty);
  }

  function renderDossier(index: number): void {
    const m = ensureModel();
    if (index < 0 || index >= m.count) {
      renderDossierEmpty();
      return;
    }
    if (routeSelected !== m.slugs[index]) {
      routeSelected = m.slugs[index];
      options.onRouteChange?.();
    }
    const ref = m.refs[index];
    options.dossier.textContent = "";

    options.dossier.appendChild(el("h2", "graph-dossier-name", ref.name));

    // Skimmable coloured fact chips instead of plain meta lines.
    const facts = el("div", "graph-dossier-facts");
    const fact = (
      className: string,
      icon: string | null,
      text: string,
      dotColor?: string,
    ): void => {
      const chip = el("span", `graph-dossier-fact ${className}`.trim());
      if (dotColor) {
        const dot = el("span", "fact-dot");
        dot.style.background = dotColor;
        chip.appendChild(dot);
      } else if (icon) {
        chip.appendChild(el("span", "fact-icon", icon));
      }
      chip.appendChild(el("span", "", text));
      facts.appendChild(chip);
    };

    // Impact facts (and the direct/sub kind chip) come from the UNFILTERED
    // workspace graph: hiding dev deps must not relabel a direct dev
    // dependency as a sub-dependency while its removal fact still speaks
    // manifest language.
    const imp = m.impact(index);
    fact("", null, ref.version ? `v${ref.version}` : "version unknown");
    if (imp.manifestFrees !== null) {
      if (m.isDev[index]) {
        fact("fact-dev", null, "direct dev dependency", "var(--graph-direct-dev, #f59e0b)");
      } else {
        fact("fact-runtime", null, "direct dependency", "var(--graph-direct-runtime, #10b981)");
      }
    } else {
      fact("fact-sub", null, "sub-dependency", "var(--graph-transitive, #06b6d4)");
    }
    fact("", "\u00a7", ref.license || "Unknown licence");
    if (ref.vulnerabilityCount > 0) {
      fact(
        "fact-bad",
        "\u26a0\ufe0e",
        `${ref.vulnerabilityCount} ${ref.vulnerabilitySeverity === "high" ? "high-severity " : ""}vulnerabilit${ref.vulnerabilityCount === 1 ? "y" : "ies"}`,
      );
    } else {
      fact("fact-ok", "\u2713", "no known vulnerabilities");
    }
    const rep = options.getReplacement?.(m.slugs[index]);
    if (rep && rep.replacements.length > 0) {
      const swapText = `swap for ${rep.replacements.join(" / ")}`;
      const hint =
        "Community replacement suggestion from the e18e module-replacements catalogue";
      if (rep.docUrl) {
        const chip = document.createElement("a");
        chip.className = "graph-dossier-fact fact-swap";
        chip.href = rep.docUrl;
        chip.target = "_blank";
        chip.rel = "noopener noreferrer";
        chip.title = `${hint} — opens migration guidance`;
        chip.appendChild(el("span", "fact-icon", "\u21c4"));
        chip.appendChild(el("span", "", swapText));
        facts.appendChild(chip);
      } else {
        const chip = el("span", "graph-dossier-fact fact-swap");
        chip.title = hint;
        chip.appendChild(el("span", "fact-icon", "\u21c4"));
        chip.appendChild(el("span", "", swapText));
        facts.appendChild(chip);
      }
    }
    const sim = m.simulateRemoval(index);
    const simSummary = (() => {
      let freedBytes = 0;
      let sized = 0;
      for (const f of sim.freed) {
        const bytes = options.getPackageExtras?.(f.slug)?.sizeBytes;
        if (bytes !== undefined) {
          freedBytes += bytes;
          sized += 1;
        }
      }
      const bytesPart =
        freedBytes > 0
          ? ` \u00b7 ${formatBytes(freedBytes)} on disk${
              sized < sim.freed.length
                ? ` (${sized.toLocaleString()} of ${sim.freed.length.toLocaleString()} measured)`
                : ""
            }`
          : "";
      const detailPart =
        sim.freed.length > 1 || sim.retained.length > 0
          ? " (see list view for more details)"
          : "";
      return `${bytesPart}${detailPart}`;
    })();
    // In the "Whole project" aggregate, a package can be declared by several
    // workspaces' manifests at once — freeing it means removing it from each,
    // and the wording must say so instead of implying one manifest entry.
    const declaringWorkspaces =
      (options.workspaceSelect.value || "root") === "root"
        ? options.dataset.workspaces.reduce(
            (n, w) =>
              w.name !== "root" &&
              (w.directDependencies.includes(m.slugs[index]) ||
                w.directDevDependencies.includes(m.slugs[index]))
                ? n + 1
                : n,
            0,
          )
        : 0;
    const impactChip = (text: string, className = ""): void => {
      const chip = el("span", `graph-dossier-fact ${className}`.trim());
      chip.appendChild(el("span", "fact-icon", "\u2702"));
      chip.appendChild(el("span", "", text));
      chip.appendChild(infoButton("impact"));
      facts.appendChild(chip);
    };
    fact(
      "",
      "\u03a3",
      `${imp.subtreeCount.toLocaleString()} package${imp.subtreeCount === 1 ? "" : "s"} in subtree`,
    );
    if (imp.manifestFrees === null) {
      // Sub-dependency: nothing to uninstall directly; the number answers the
      // what-if of the package itself going away. The removal simulation is
      // memoised on the (shared) model, so summarising it here is free; the
      // full freed/retained preview lives in the list view.
      impactChip(
        imp.exclusiveCount > 1
          ? `deleting frees ${imp.exclusiveCount.toLocaleString()} packages${simSummary}`
          : `deleting frees only itself${simSummary}`,
      );
    } else if (imp.manifestFrees === 0) {
      // Direct dependency that other packages also pull in: removing the
      // package.json entry uninstalls nothing.
      const names = imp.keptBy.slice(0, 2).join(", ");
      const suffix = imp.keptBy.length > 2 ? ` +${imp.keptBy.length - 2}` : "";
      impactChip(
        `removing it frees nothing \u2014 still needed by ${names}${suffix}`,
        "fact-note",
      );
    } else {
      const removePhrase =
        declaringWorkspaces > 1
          ? `removing it from all ${declaringWorkspaces} declaring workspaces frees`
          : "removing it frees";
      impactChip(
        imp.manifestFrees > 1
          ? `${removePhrase} ${imp.manifestFrees.toLocaleString()} packages${simSummary}`
          : `${removePhrase} only itself${simSummary}`,
      );
    }
    if (imp.cycleWith.length > 0) {
      const names = imp.cycleWith.slice(0, 3);
      const suffix = imp.cycleWith.length > 3 ? ` +${imp.cycleWith.length - 3}` : "";
      fact("fact-note", "\u21ba", `in a dependency cycle with ${names.join(", ")}${suffix}`);
    }
    // Measured/derived extras from the full report record.
    const extras = options.getPackageExtras?.(m.slugs[index]);
    if (extras?.sizeBytes !== undefined) {
      const chip = el("span", "graph-dossier-fact");
      chip.appendChild(el("span", "fact-icon", "\u26c1"));
      const codePart =
        extras.codeBytes !== undefined && extras.codeBytes > 0
          ? ` \u00b7 ${formatBytes(extras.codeBytes)} code`
          : "";
      chip.appendChild(
        el("span", "", `${formatBytes(extras.sizeBytes)} on disk${codePart}`),
      );
      chip.appendChild(infoButton("size"));
      facts.appendChild(chip);
    }
    if (imp.manifestFrees !== null && extras?.importFileCount !== undefined) {
      const files = extras.importFileCount;
      const chip = el(
        "span",
        files === 0 ? "graph-dossier-fact fact-dev" : "graph-dossier-fact",
      );
      chip.appendChild(el("span", "fact-icon", "\u2338"));
      chip.appendChild(
        el(
          "span",
          "",
          files > 0
            ? `imported in ${files} file${files === 1 ? "" : "s"}`
            : "no imports found in project source",
        ),
      );
      chip.appendChild(infoButton("imports"));
      facts.appendChild(chip);
    }
    if (extras?.platformNote) {
      fact("fact-dev", "\u26a0\ufe0e", extras.platformNote);
    }
    if (extras?.phantom) {
      fact(
        "fact-note fact-bad",
        "\u26a0\ufe0e",
        "imported by project code but not declared in any workspace manifest",
      );
    }
    options.dossier.appendChild(facts);

    chipRow(options.dossier, "Depends on", m.kidsOf[index]);
    chipRow(options.dossier, "Required by", m.depsIn[index]);

    const open = el("button", "graph-dossier-open", "Open in List");
    open.type = "button";
    open.addEventListener("click", () => options.onOpenList(m.slugs[index]));
    options.dossier.appendChild(open);
  }


  // ----- focus routing --------------------------------------------------
  function focusPackage(index: number): void {
    const m = ensureModel();
    renderDossier(index);
    if (mode === "graph") {
      const handle = options.getClassicHandle();
      handle?.applyFocus(m.slugs[index]);
      handle?.select(m.slugs[index]);
      handle?.requestRender();
      return;
    }
    activeView?.focusIndex(index);
  }

  // ----- alternative view lifecycle ------------------------------------
  function destroyActive(): void {
    activeView?.destroy();
    activeView = null;
  }

  function mountActive(): void {
    // A fresh mount always starts unzoomed — filter and workspace changes
    // remount without passing through setMode, and a stale zoom flag would
    // leave the Reset button showing over an unzoomed treemap.
    treemapZoomed = false;
    syncResetBtn();
    const m = ensureModel();
    const callbacks = {
      onHoverTrail: statusTrail,
      onSelect: (index: number) => {
        if (index >= 0) renderDossier(index);
        else renderDossierEmpty();
      },
      theme,
      insetRight,
      insetTop,
      isDimmed: isDimmedIndex,
      onZoomChanged: (zoomed: boolean) => {
        treemapZoomed = zoomed;
        syncResetBtn();
      },
    };
    if (mode === "flame") activeView = mountFlameView(options.altHost, m, callbacks);
    else if (mode === "treemap") activeView = mountTreemapView(options.altHost, m, callbacks);
    else if (mode === "balloon") activeView = mountBalloonView(options.altHost, m, callbacks);
    else if (mode === "hyperbolic") {
      activeView = mountHyperbolicView(options.altHost, m, callbacks);
    }
  }

  function setMode(next: GraphMode): void {
    if (next === mode) return;
    destroyActive();
    mode = next;
    const classic = mode === "graph";
    options.modeSwitch
      .querySelectorAll<HTMLButtonElement>("[data-graph-mode]")
      .forEach((btn) => {
        const active = btn.dataset.graphMode === mode;
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-pressed", String(active));
      });
    options.altHost.hidden = classic;
    options.altHost.parentElement?.classList.toggle("alt-active", !classic);
    treemapZoomed = false; // fresh mounts start unzoomed
    syncResetBtn();
    for (const elc of options.classicOnly) elc.classList.toggle("hidden", !classic);
    const handle = options.getClassicHandle();
    if (classic) {
      handle?.setActive(true);
      handle?.requestRender();
    } else {
      handle?.clearSelection();
      handle?.setActive(false);
      mountActive();
    }
    updateKey();
    statusHint();
    renderDossierEmpty();
    syncEmptyState();
    try {
      localStorage.setItem(MODE_STORE_KEY, mode);
    } catch {
      // Best-effort persistence only.
    }
    options.onRouteChange?.();
  }

  // ----- wiring ---------------------------------------------------------
  options.modeSwitch.addEventListener("click", (event) => {
    const btn = (event.target as HTMLElement).closest<HTMLButtonElement>(
      "[data-graph-mode]",
    );
    if (!btn) return;
    setMode(btn.dataset.graphMode as GraphMode);
  });

  options.workspaceSelect.addEventListener("change", () => {
    options.onRouteChange?.();
    model = null;
    resetDimCache();
    // Stale results hold closures over the previous model's indices.
    options.searchInput.value = "";
    options.searchResults.textContent = "";
    dimQuery = "";
    renderDossierEmpty();
    if (mode !== "graph") {
      destroyActive();
      mountActive();
      statusHint();
    }
    syncEmptyState();
  });

  // Theme flips repaint the active canvas view.
  const themeObserver = new MutationObserver(() => {
    activeView?.resize();
  });
  themeObserver.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ["data-theme"],
  });

  // Search: incremental results over the current workspace's packages. The
  // query doubles as a live name filter — non-matching nodes render dimmed.
  options.searchResults.setAttribute("aria-live", "polite");
  function repaintForDim(): void {
    if (mode === "graph") {
      options.getClassicHandle()?.requestRender();
      return;
    }
    activeView?.resize();
  }

  function runSearch(): void {
    const q = options.searchInput.value.trim().toLowerCase();
    options.searchResults.textContent = "";
    const nextDim = q.length >= 2 ? q : "";
    const dimChanged = nextDim !== dimQuery;
    dimQuery = nextDim;
    if (dimChanged) resetDimCache();
    if (q.length >= 2) {
      const m = ensureModel();
      const matches: number[] = [];
      for (let i = 0; i < m.count && matches.length < 12; i += 1) {
        if (m.lowerNames[i].includes(q)) matches.push(i);
      }
      for (const index of matches) {
        const li = document.createElement("li");
        const btn = el("button", "", `${m.refs[index].name}@${m.refs[index].version}`);
        btn.type = "button";
        btn.addEventListener("click", () => {
          focusPackage(index);
        });
        li.appendChild(btn);
        options.searchResults.appendChild(li);
      }
    }
    if (dimChanged) repaintForDim();
  }
  options.searchInput.addEventListener("input", runSearch);

  // ----- display filters ------------------------------------------------
  function syncFilterControls(): void {
    options.filterRuntime?.setAttribute("aria-pressed", String(filters.runtime));
    options.filterDev?.setAttribute("aria-pressed", String(filters.dev));
    options.filterSub?.setAttribute("aria-pressed", String(filters.sub));
    if (options.filterDepth) {
      options.filterDepth.value =
        filters.maxDepth === null ? "" : String(filters.maxDepth);
      options.filterDepth.disabled = !filters.sub;
    }
  }

  function applyFilters(): void {
    persistFilters();
    syncFilterControls();
    syncFiltersBadge();
    model = null;
    resetDimCache();
    // The dossier and search results hold indices into the previous model.
    renderDossierEmpty();
    options.getClassicHandle()?.refreshFilters();
    if (mode !== "graph") {
      destroyActive();
      mountActive();
      statusHint();
    }
    runSearch();
    syncEmptyState();
    options.onRouteChange?.();
  }

  function bindKindChip(
    btn: HTMLButtonElement | null,
    kind: "runtime" | "dev" | "sub",
  ): void {
    btn?.addEventListener("click", () => {
      const next = { ...filters, [kind]: !filters[kind] };
      // Keep at least one root kind visible — a rootless graph is empty.
      if (!next.runtime && !next.dev) return;
      filters[kind] = next[kind];
      applyFilters();
    });
  }
  bindKindChip(options.filterRuntime, "runtime");
  bindKindChip(options.filterDev, "dev");
  bindKindChip(options.filterSub, "sub");

  options.filterDepth?.addEventListener("change", () => {
    const value = options.filterDepth ? options.filterDepth.value : "";
    const parsed = Number.parseInt(value, 10);
    filters.maxDepth = Number.isInteger(parsed) && parsed >= 1 ? parsed : null;
    applyFilters();
  });

  // Highlight chips: dimming only — the graph structure never changes, so
  // no model rebuild, just a repaint of whichever view is active.
  function syncHighlightChips(): void {
    for (const kind of HIGHLIGHT_KINDS) {
      document
        .getElementById(`graph-hl-${kind}`)
        ?.setAttribute("aria-pressed", String(highlights.has(kind)));
    }
  }

  function bindHighlightChip(kind: HighlightKind): void {
    const btn = document.getElementById(`graph-hl-${kind}`);
    if (!btn) return;
    btn.addEventListener("click", () => {
      if (highlights.has(kind)) highlights.delete(kind);
      else highlights.add(kind);
      btn.setAttribute("aria-pressed", String(highlights.has(kind)));
      persistFilters();
      syncFiltersBadge();
      resetDimCache();
      repaintForDim();
      options.onRouteChange?.();
    });
  }
  for (const kind of HIGHLIGHT_KINDS) bindHighlightChip(kind);
  syncHighlightChips();

  document.getElementById("graph-filters-reset")?.addEventListener("click", () => {
    Object.assign(filters, DEFAULT_GRAPH_FILTERS);
    highlights.clear();
    syncHighlightChips();
    applyFilters();
  });

  syncFilterControls();
  syncFiltersBadge();

  statusHint();
  renderDossierEmpty();
  syncEmptyState();

  // Restore the last-used layout (persisted in setMode).
  try {
    const storedMode = localStorage.getItem(MODE_STORE_KEY);
    if (storedMode && GRAPH_MODES.includes(storedMode as GraphMode)) {
      setMode(storedMode as GraphMode);
    }
  } catch {
    // Storage unavailable — stay on the default layout.
  }

  return {
    mode: () => mode,
    filters: () => filters,
    isNameDimmed,
    handleClassicSelect(slug: string | null) {
      if (mode !== "graph") return;
      if (!slug) {
        renderDossierEmpty();
        return;
      }
      const m = ensureModel();
      const index = m.indexOfSlug.get(slug);
      if (index === undefined) {
        // Outside the derived reachable set (shouldn't happen for a shared
        // workspace selection) — show a minimal dossier from the dataset.
        const ref = options.dataset.dependencies[slug];
        options.dossier.textContent = "";
        if (ref) {
          options.dossier.appendChild(el("h2", "graph-dossier-name", ref.name));
          options.dossier.appendChild(
            el("p", "graph-dossier-meta", ref.version || "version unknown"),
          );
        }
        return;
      }
      renderDossier(index);
    },
    refresh() {
      activeView?.resize();
    },
    routeState() {
      return {
        mode,
        workspace: options.workspaceSelect.value || "",
        selected: routeSelected,
        highlights: [...highlights],
        runtime: filters.runtime,
        dev: filters.dev,
        sub: filters.sub,
        depth: filters.maxDepth,
      };
    },
    applyRoute(route) {
      // Workspace first — its change handler resets the model and remounts
      // exactly as a user change would (classic view listens on the same
      // select).
      if (
        route.workspace &&
        options.workspaceSelect.value !== route.workspace &&
        Array.from(options.workspaceSelect.options).some(
          (opt) => opt.value === route.workspace,
        )
      ) {
        options.workspaceSelect.value = route.workspace;
        options.workspaceSelect.dispatchEvent(new Event("change"));
      }
      // Display filters (keep at least one root kind, like the chips do).
      let runtime = route.runtime;
      const dev = route.dev;
      if (!runtime && !dev) runtime = true;
      const depth =
        Number.isInteger(route.depth) && (route.depth as number) >= 1
          ? route.depth
          : null;
      const filtersChanged =
        filters.runtime !== runtime ||
        filters.dev !== dev ||
        filters.sub !== route.sub ||
        filters.maxDepth !== depth;
      filters.runtime = runtime;
      filters.dev = dev;
      filters.sub = route.sub;
      filters.maxDepth = depth;
      // Highlights (only kinds whose evidence is available).
      const nextHl = route.highlights.filter(
        (kind) =>
          HIGHLIGHT_KINDS.includes(kind as HighlightKind) &&
          highlightAvailable(kind as HighlightKind),
      ) as HighlightKind[];
      const hlChanged =
        nextHl.length !== highlights.size ||
        nextHl.some((kind) => !highlights.has(kind));
      if (hlChanged) {
        highlights.clear();
        for (const kind of nextHl) highlights.add(kind);
        syncHighlightChips();
      }
      if (filtersChanged) {
        applyFilters();
      } else if (hlChanged) {
        persistFilters();
        syncFiltersBadge();
        resetDimCache();
        repaintForDim();
      }
      // 4) An unknown mode must not reach setMode — it would deactivate
      // every button and mount nothing.
      if (route.mode !== mode && GRAPH_MODES.includes(route.mode)) {
        setMode(route.mode);
      }
      // Selection last, against the final model.
      if (route.selected) {
        const idx = ensureModel().indexOfSlug.get(route.selected);
        if (idx !== undefined) focusPackage(idx);
        else renderDossierEmpty();
      } else if (routeSelected !== null) {
        renderDossierEmpty();
      }
    },
  };
}
