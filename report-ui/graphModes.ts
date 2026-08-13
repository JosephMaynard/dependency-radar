import type { GraphDataset, GraphViewHandle } from "./graphView";
import type { GraphFilters, VizHandle, VizModel } from "./vizModel";
import {
  buildVizModel,
  DEFAULT_GRAPH_FILTERS,
  resolveVizTheme,
} from "./vizModel";
import { mountFlameView } from "./flameView";
import { mountBalloonView } from "./balloonView";
import { mountHyperbolicView } from "./hyperbolicView";

// Orchestrates the graph panel's four layout modes (classic graph + flame +
// balloon + hyperbolic), the shared docked side panel (search + dossier), and
// the status line. The classic graph view keeps its own canvas and handle;
// alternative views mount a fresh canvas each and are destroyed on switch
// (reset-on-switch is deliberate — see docs/VIZ-VIEWS-HANDOFF.md).

export type GraphMode = "graph" | "flame" | "balloon" | "hyperbolic";

const GRAPH_MODES: GraphMode[] = ["graph", "flame", "balloon", "hyperbolic"];

// Persisted alongside the theme preference (see main.ts).
const MODE_STORE_KEY = "dependency-radar-graph-mode";
const FILTER_STORE_KEY = "dependency-radar-graph-filters";

// Largest depth the toolbar select offers; persisted values are clamped so a
// stored depth always has a matching option.
const MAX_DEPTH_OPTION = 5;

const MODE_HINTS: Record<GraphMode, string> = {
  graph: "click a node to inspect · drag to pan · scroll to zoom",
  flame:
    "hover a bar · click to zoom in · click a pinned ancestor to climb back out · double-click to reset",
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
  getClassicHandle: () => GraphViewHandle | null;
  onOpenList: (slug: string) => void;
}

export interface GraphModesHandle {
  /** Current mode. */
  mode(): GraphMode;
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
  try {
    const raw = localStorage.getItem(FILTER_STORE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<GraphFilters>;
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
      localStorage.setItem(FILTER_STORE_KEY, JSON.stringify(filters));
    } catch {
      // Best-effort persistence only.
    }
  }

  const theme = resolveVizTheme;
  const shell = options.altHost.parentElement as HTMLElement | null;
  const insetRight = (): number => {
    if (!shell) return 0;
    return (
      parseFloat(
        getComputedStyle(shell).getPropertyValue("--graph-panel-space"),
      ) || 0
    );
  };
  const insetTop = (): number => {
    if (!shell) return 60;
    const toolbar = parseFloat(
      getComputedStyle(shell).getPropertyValue("--graph-toolbar-height"),
    );
    return (Number.isFinite(toolbar) && toolbar > 0 ? toolbar : 50) + 10;
  };
  const classicKeyNodes = options.keyEl
    ? Array.from(options.keyEl.childNodes)
    : [];

  // Floating reset for the alternative views (flame resets via double-click
  // and its pinned ancestors, so it opts out).
  const resetBtn = document.createElement("button");
  resetBtn.type = "button";
  resetBtn.className = "graph-alt-reset";
  resetBtn.textContent = "Reset view";
  resetBtn.hidden = true;
  resetBtn.addEventListener("click", () => {
    activeView?.resetView?.();
  });
  shell?.appendChild(resetBtn);

  function keyItem(color: string, label: string): HTMLElement {
    const item = document.createElement("span");
    item.className = "graph-key-item";
    const dot = document.createElement("span");
    dot.className = "graph-key-dot";
    dot.style.background = color;
    dot.setAttribute("aria-hidden", "true");
    item.appendChild(dot);
    const text = document.createElement("span");
    text.textContent = label;
    item.appendChild(text);
    return item;
  }

  function updateKey(): void {
    const keyEl = options.keyEl;
    if (!keyEl) return;
    if (mode === "graph") {
      keyEl.replaceChildren(...classicKeyNodes);
      return;
    }
    const label = document.createElement("span");
    label.className = "graph-workspace-label";
    label.textContent = "Key";
    const items = document.createElement("div");
    items.className = "graph-key-items";
    if (mode === "hyperbolic") {
      items.appendChild(keyItem("#ff9a58", "Direct dependency"));
      items.appendChild(keyItem("#5b7186", "Sub-dependency"));
    } else {
      items.appendChild(
        keyItem(
          "conic-gradient(from 0deg, hsl(28 60% 55%), hsl(152 60% 45%), hsl(268 60% 60%), hsl(322 60% 55%), hsl(28 60% 55%))",
          "One colour per direct dependency's subtree",
        ),
      );
    }
    items.appendChild(keyItem("var(--graph-vuln-high, #ef4444)", "Vulnerable"));
    keyEl.replaceChildren(label, items);
  }

  function ensureModel(): VizModel {
    const workspace = options.workspaceSelect.value || "";
    const filterKey = JSON.stringify(filters);
    if (!model || modelWorkspace !== workspace || modelFilterKey !== filterKey) {
      model = buildVizModel(options.dataset, workspace, options.projectName, {
        ...filters,
      });
      modelWorkspace = workspace;
      modelFilterKey = filterKey;
    }
    return model;
  }

  function isDimmedIndex(index: number): boolean {
    if (!dimQuery || !model) return false;
    const name = model.lowerNames[index];
    return name !== undefined && !name.includes(dimQuery);
  }

  function isNameDimmed(slug: string): boolean {
    if (!dimQuery) return false;
    const ref = options.dataset.dependencies[slug];
    if (!ref) return false;
    return !ref.name.toLowerCase().includes(dimQuery);
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
    options.statusLine.textContent =
      `${m.projectName} › ${trail.map((id) => m.refs[id].name).join(" › ")}` +
      ` · ${m.uniqueCount(last).toLocaleString()} packages (${Math.round(m.subSize[last]).toLocaleString()} paths) in subtree` +
      ` · reached via ${Math.round(m.occ[last]).toLocaleString()} path${m.occ[last] === 1 ? "" : "s"}`;
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
    options.dossier.textContent = "";
    const empty = el(
      "p",
      "graph-dossier-empty",
      mode === "graph"
        ? "Select a node to inspect it."
        : mode === "flame"
          ? "Click a bar. Width is the share of the whole dependency tree beneath it — the widest bars in the first row are the direct dependencies that cost you the most. Counts are paths, flame-graph style: a package shared by several parents is counted once per route, so path counts run higher than unique package counts."
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

    fact("", null, ref.version ? `v${ref.version}` : "version unknown");
    if (m.isRoot[index]) {
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
    fact(
      "",
      "\u03a3",
      `${m.uniqueCount(index).toLocaleString()} package${m.uniqueCount(index) === 1 ? "" : "s"} in subtree (${Math.round(m.subSize[index]).toLocaleString()} path${Math.round(m.subSize[index]) === 1 ? "" : "s"})`,
    );
    fact(
      "",
      "\u2295",
      `reached via ${Math.round(m.occ[index]).toLocaleString()} path${m.occ[index] === 1 ? "" : "s"}`,
    );
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
      handle?.showPopover(m.slugs[index]);
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
    };
    if (mode === "flame") activeView = mountFlameView(options.altHost, m, callbacks);
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
    resetBtn.hidden = classic || mode === "flame";
    for (const elc of options.classicOnly) elc.classList.toggle("hidden", !classic);
    const handle = options.getClassicHandle();
    if (classic) {
      handle?.setActive(true);
      handle?.requestRender();
    } else {
      handle?.hidePopover();
      handle?.setActive(false);
      mountActive();
    }
    updateKey();
    statusHint();
    renderDossierEmpty();
    try {
      localStorage.setItem(MODE_STORE_KEY, mode);
    } catch {
      // Best-effort persistence only.
    }
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
    model = null;
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
    model = null;
    // The dossier and search results hold indices into the previous model.
    renderDossierEmpty();
    options.getClassicHandle()?.refreshFilters();
    if (mode !== "graph") {
      destroyActive();
      mountActive();
      statusHint();
    }
    runSearch();
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

  syncFilterControls();

  statusHint();
  renderDossierEmpty();

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
  };
}
