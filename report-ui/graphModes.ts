import type { GraphDataset, GraphViewHandle } from "./graphView";
import type { VizHandle, VizModel } from "./vizModel";
import { buildVizModel, resolveVizTheme } from "./vizModel";
import { mountFlameView } from "./flameView";
import { mountBalloonView } from "./balloonView";
import { mountHyperbolicView } from "./hyperbolicView";

// Orchestrates the graph panel's four layout modes (classic graph + flame +
// balloon + hyperbolic), the shared docked side panel (search + dossier), and
// the status line. The classic graph view keeps its own canvas and handle;
// alternative views mount a fresh canvas each and are destroyed on switch
// (reset-on-switch is deliberate — see docs/VIZ-VIEWS-HANDOFF.md).

export type GraphMode = "graph" | "flame" | "balloon" | "hyperbolic";

const MODE_HINTS: Record<GraphMode, string> = {
  graph: "click a node to inspect · drag to pan · scroll to zoom",
  flame:
    "hover a bar · click to zoom in · click a pinned ancestor to climb back out · double-click to reset",
  balloon: "drag to pan · scroll to zoom · click a body · double-click space to fit",
  hyperbolic: "drag to warp the disk · click a blip to focus · double-click space to reset",
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
  workspaceSelect: HTMLSelectElement;
  /** Elements only meaningful for the classic graph (dpad, zoom, key). */
  classicOnly: HTMLElement[];
  getClassicHandle: () => GraphViewHandle | null;
  onOpenList: (slug: string) => void;
}

export interface GraphModesHandle {
  /** Current mode. */
  mode(): GraphMode;
  /** Selection relay from the classic graph view. */
  handleClassicSelect(slug: string | null): void;
  /** Re-measure the active alternative view (call when the panel shows). */
  refresh(): void;
}

export function initGraphModes(options: GraphModesOptions): GraphModesHandle {
  let mode: GraphMode = "graph";
  let activeView: VizHandle | null = null;
  let model: VizModel | null = null;
  let modelWorkspace = "";

  const theme = resolveVizTheme;

  function ensureModel(): VizModel {
    const workspace = options.workspaceSelect.value || "";
    if (!model || modelWorkspace !== workspace) {
      model = buildVizModel(options.dataset, workspace, options.projectName);
      modelWorkspace = workspace;
    }
    return model;
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
      ` · ${Math.round(m.subSize[last]).toLocaleString()} in subtree` +
      ` · appears in ${Math.round(m.occ[last]).toLocaleString()} place${m.occ[last] === 1 ? "" : "s"}`;
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
          ? "Click a bar. Width is the share of the whole dependency tree beneath it — the widest bars in the first row are the direct dependencies that cost you the most."
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
    const kind = m.isRoot[index]
      ? m.isDev[index]
        ? "direct dev dependency"
        : "direct dependency"
      : "sub-dependency";
    options.dossier.appendChild(
      el("p", "graph-dossier-meta", `${ref.version || "version unknown"} · ${kind}`),
    );
    const vulnText =
      ref.vulnerabilityCount > 0
        ? `${ref.vulnerabilityCount} ${ref.vulnerabilitySeverity === "high" ? "high-severity " : ""}vulnerabilit${ref.vulnerabilityCount === 1 ? "y" : "ies"}`
        : "no known vulnerabilities";
    const licenseLine = el(
      "p",
      "graph-dossier-meta",
      `${ref.license || "Unknown licence"} · ${vulnText}`,
    );
    if (ref.vulnerabilityCount > 0) licenseLine.classList.add("graph-dossier-vuln");
    options.dossier.appendChild(licenseLine);
    options.dossier.appendChild(
      el(
        "p",
        "graph-dossier-meta",
        `${Math.round(m.subSize[index]).toLocaleString()} in subtree · appears in ${Math.round(m.occ[index]).toLocaleString()} place${m.occ[index] === 1 ? "" : "s"}`,
      ),
    );

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
        btn.setAttribute("aria-selected", String(active));
      });
    options.altHost.hidden = classic;
    options.altHost.parentElement?.classList.toggle("alt-active", !classic);
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
    statusHint();
    renderDossierEmpty();
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
    if (mode !== "graph") {
      destroyActive();
      mountActive();
      statusHint();
      renderDossierEmpty();
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

  // Search: incremental results over the current workspace's packages.
  options.searchInput.addEventListener("input", () => {
    const q = options.searchInput.value.trim().toLowerCase();
    options.searchResults.textContent = "";
    if (q.length < 2) return;
    const m = ensureModel();
    const matches: number[] = [];
    for (let i = 0; i < m.count && matches.length < 12; i += 1) {
      if (m.refs[i].name.toLowerCase().includes(q)) matches.push(i);
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
  });

  statusHint();
  renderDossierEmpty();

  return {
    mode: () => mode,
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
