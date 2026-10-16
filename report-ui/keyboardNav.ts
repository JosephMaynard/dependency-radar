// Keyboard navigation for the graph canvas views.
//
// Every view hands over the tree it actually draws (NavTree) plus three
// hooks: show the keyboard cursor on a node, select a node exactly as a click
// would, and clear the selection. Movement is pure tree logic over a root
// first path, so the same keys mean the same thing in all five views:
//
//   Down / Right        first child (a node without children stays put)
//   Up / Left           parent; from a direct dependency, the project root
//   Shift+Right / ]     next sibling (no wrap)
//   Shift+Left / [      previous sibling (no wrap)
//   Home                project root
//   Enter / Space       select (opens the dossier, like a click)
//   Escape              clear the selection
//
// The path remembers how you got somewhere, which matters for the classic
// graph: it is not a tree, and Up must return to the package you came from.

/** The navigable structure a view draws. Node ids are view-defined. */
export interface NavTree {
  /** Top-level nodes (children of the project root), in display order. */
  roots: readonly number[];
  children(node: number): readonly number[];
  /** Tree parent, or -1 for a top-level node. */
  parent(node: number): number;
  /** VizModel package index drawn by this node. */
  pkg(node: number): number;
  /** Nav node drawing this package, or -1 when the view has none. */
  nodeOf(pkg: number): number;
}

/** What a view exposes to the keyboard controller. */
export interface KeyNavTarget {
  tree: NavTree;
  /** Show the keyboard cursor on a node (-1 hides it) and keep it in view. */
  focus(node: number): void;
  /** Select the node exactly as clicking it would. */
  select(node: number): void;
  clearSelection(): void;
}

export type MoveAction = "child" | "parent" | "next" | "prev" | "root";
export type NavAction =
  | MoveAction
  | "select"
  | "clear"
  | "search"
  | "help"
  | "fit"
  | "zoomIn"
  | "zoomOut";

export interface KeyLike {
  key: string;
  shiftKey?: boolean;
  ctrlKey?: boolean;
  metaKey?: boolean;
  altKey?: boolean;
}

/** Map a keydown to a navigation action; null leaves the key alone. */
export function keyToAction(e: KeyLike): NavAction | null {
  if (e.ctrlKey || e.metaKey || e.altKey) return null;
  switch (e.key) {
    case "ArrowDown":
      return e.shiftKey ? null : "child";
    case "ArrowUp":
      return e.shiftKey ? null : "parent";
    case "ArrowRight":
      return e.shiftKey ? "next" : "child";
    case "ArrowLeft":
      return e.shiftKey ? "prev" : "parent";
    case "]":
      return "next";
    case "[":
      return "prev";
    case "Home":
      return "root";
    case "Enter":
    case " ":
      return "select";
    case "Escape":
      return "clear";
    case "/":
      return "search";
    case "?":
      return "help";
    case "f":
    case "F":
      return "fit";
    case "+":
    case "=":
      return "zoomIn";
    case "-":
    case "_":
      return "zoomOut";
    default:
      return null;
  }
}

/** Root first chain of tree parents ending at `node`; [] for -1. */
export function pathTo(tree: NavTree, node: number): number[] {
  const path: number[] = [];
  const seen = new Set<number>();
  let cur = node;
  while (cur >= 0 && !seen.has(cur)) {
    seen.add(cur);
    path.unshift(cur);
    cur = tree.parent(cur);
  }
  return path;
}

/** The level the path's last node sits in (roots for a top-level node). */
export function siblingsOf(tree: NavTree, path: readonly number[]): readonly number[] {
  if (path.length <= 1) return tree.roots;
  return tree.children(path[path.length - 2]);
}

export interface NavStep {
  path: number[];
  moved: boolean;
}

/** Apply one movement to a path. Pure: the input path is never mutated. */
export function stepPath(
  tree: NavTree,
  path: readonly number[],
  action: MoveAction,
): NavStep {
  const stay = { path: [...path], moved: false };
  if (action === "root") return { path: [], moved: path.length > 0 };
  if (action === "parent") {
    return path.length > 0 ? { path: path.slice(0, -1), moved: true } : stay;
  }
  if (action === "child") {
    const kids = path.length > 0 ? tree.children(path[path.length - 1]) : tree.roots;
    return kids.length > 0 ? { path: [...path, kids[0]], moved: true } : stay;
  }
  if (path.length === 0) return stay;
  const level = siblingsOf(tree, path);
  const at = level.indexOf(path[path.length - 1]);
  const next = at + (action === "next" ? 1 : -1);
  if (at < 0 || next < 0 || next >= level.length) return stay;
  return { path: [...path.slice(0, -1), level[next]], moved: true };
}

/** Short screen-reader line for a focused package. */
export function describeNode(
  name: string,
  version: string,
  deps: number,
  depth: number,
  position: number,
  total: number,
): string {
  const id = version ? `${name}@${version}` : name;
  const depText =
    deps === 0 ? "no dependencies" : `${deps} ${deps === 1 ? "dependency" : "dependencies"}`;
  return `${id}, ${depText}, depth ${depth}, ${position} of ${total}`;
}

// ----- DOM controller ------------------------------------------------------

export interface KeyboardNavOptions {
  /** Focusable canvas containers (one per rendering surface). */
  hosts: HTMLElement[];
  /** Graph shell: the overlay mounts here so it survives fullscreen. */
  shell: HTMLElement;
  searchInput: HTMLInputElement;
  target(): KeyNavTarget | null;
  /** Package facts for announcements. */
  info(pkg: number): { name: string; version: string; deps: number } | null;
  rootLabel(): string;
  /** Currently selected package index, -1 for none. */
  selection(): number;
  /** Escape belongs to fullscreen while it is active. */
  fullscreen(): boolean;
  fit(): void;
  /** Zoom by one step; return false when the view has no cheap zoom. */
  zoom(direction: 1 | -1): boolean;
  /** Keyboard focus entered or left a host (status line hint). */
  onFocusChange?(): void;
}

export interface KeyboardNavHandle {
  /** A click or search selected a package: start the cursor from there. */
  syncSelection(pkg: number): void;
  /** Re-label the hosts after a mode change. */
  setLabel(viewName: string): void;
  toggleHelp(): void;
  /** True while a host holds keyboard focus that came from the keyboard. */
  keyboardFocused(): boolean;
}

const SHORTCUTS: Array<[string[], string]> = [
  [["\u2193", "\u2192"], "Move to its first dependency"],
  [["\u2191", "\u2190"], "Move back up a level"],
  [["Shift+\u2192", "]"], "Next package at this level"],
  [["Shift+\u2190", "["], "Previous package at this level"],
  [["Home"], "Back to the project root"],
  [["Enter", "Space"], "Open details"],
  [["Esc"], "Clear the selection"],
  [["/"], "Find a package"],
  [["f"], "Fit or reset the view"],
  [["+", "-"], "Zoom in or out (Graph layout)"],
  [["?"], "Show or hide these shortcuts"],
];

function isEditable(el: Element | null): boolean {
  if (!el) return false;
  const tag = el.tagName;
  return (
    tag === "INPUT" ||
    tag === "TEXTAREA" ||
    tag === "SELECT" ||
    (el as HTMLElement).isContentEditable === true
  );
}

function announcer(): HTMLElement {
  // Shared with the list view's copy feedback (main.ts creates it first).
  let node = document.getElementById("copy-announcer");
  if (!node) {
    node = document.createElement("div");
    node.id = "copy-announcer";
    node.className = "sr-only";
    node.setAttribute("aria-live", "polite");
    document.body.appendChild(node);
  }
  return node;
}

export function initKeyboardNav(options: KeyboardNavOptions): KeyboardNavHandle {
  let path: number[] = [];
  let tree: NavTree | null = null;
  /** Set while the controller itself selects, so the sync echo is ignored. */
  let selecting = false;
  let cursorShown = false;

  const announce = (text: string): void => {
    const node = announcer();
    // Clearing first makes repeated identical messages speak again.
    node.textContent = "";
    window.setTimeout(() => {
      node.textContent = text;
    }, 30);
  };

  /** Current target, resetting the path when the view (tree) changed. */
  function current(): KeyNavTarget | null {
    const t = options.target();
    if (!t) return null;
    if (t.tree !== tree) {
      tree = t.tree;
      path = [];
      const sel = options.selection();
      if (sel >= 0) path = pathTo(tree, tree.nodeOf(sel));
    }
    return t;
  }

  function showCursor(t: KeyNavTarget): void {
    cursorShown = path.length > 0;
    t.focus(cursorShown ? path[path.length - 1] : -1);
  }

  function hideCursor(): void {
    if (!cursorShown) return;
    cursorShown = false;
    options.target()?.focus(-1);
  }

  function describePath(t: KeyNavTarget): string {
    if (path.length === 0) {
      const n = t.tree.roots.length;
      return `${options.rootLabel()}, project root, ${n} ${n === 1 ? "package" : "packages"} below`;
    }
    const node = path[path.length - 1];
    const facts = options.info(t.tree.pkg(node));
    if (!facts) return "";
    const level = siblingsOf(t.tree, path);
    return describeNode(
      facts.name,
      facts.version,
      facts.deps,
      path.length,
      Math.max(1, level.indexOf(node) + 1),
      level.length,
    );
  }

  function nameAt(t: KeyNavTarget): string {
    if (path.length === 0) return options.rootLabel();
    return options.info(t.tree.pkg(path[path.length - 1]))?.name ?? "";
  }

  function move(t: KeyNavTarget, action: MoveAction): void {
    const step = stepPath(t.tree, path, action);
    if (!step.moved) {
      if (action === "child") {
        announce(`No packages below ${nameAt(t)} in this view`);
      } else if (action === "parent" || action === "root") {
        announce("Already at the project root");
      } else if (path.length === 0) {
        announce("Press the down arrow to enter the packages");
      } else {
        const n = siblingsOf(t.tree, path).length;
        announce(action === "next" ? `Last of ${n} at this level` : `First of ${n} at this level`);
      }
      showCursor(t);
      return;
    }
    path = step.path;
    showCursor(t);
    announce(describePath(t));
  }

  // ----- shortcut overlay --------------------------------------------------
  let overlay: HTMLElement | null = null;
  let returnFocus: HTMLElement | null = null;

  function buildOverlay(): HTMLElement {
    const box = document.createElement("div");
    box.className = "graph-keys-dialog";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.setAttribute("aria-label", "Keyboard shortcuts");
    box.hidden = true;
    const title = document.createElement("strong");
    title.className = "graph-keys-title";
    title.textContent = "Keyboard shortcuts";
    box.appendChild(title);
    const list = document.createElement("dl");
    list.className = "graph-keys-list";
    for (const [keys, what] of SHORTCUTS) {
      const dt = document.createElement("dt");
      keys.forEach((part, i) => {
        if (i > 0) dt.appendChild(document.createTextNode(" or "));
        const kbd = document.createElement("kbd");
        kbd.textContent = part;
        dt.appendChild(kbd);
      });
      const dd = document.createElement("dd");
      dd.textContent = what;
      list.append(dt, dd);
    }
    box.appendChild(list);
    const note = document.createElement("p");
    note.className = "graph-keys-note";
    note.textContent = "Tab to the graph first. The list view has the same data as a table.";
    box.appendChild(note);
    const close = document.createElement("button");
    close.type = "button";
    close.className = "graph-panel-reset";
    close.textContent = "Close";
    close.addEventListener("click", () => closeHelp());
    box.appendChild(close);
    box.addEventListener("keydown", (event) => {
      if (event.key === "Escape" || event.key === "?") {
        event.preventDefault();
        event.stopPropagation();
        closeHelp();
      } else if (event.key === "Tab") {
        // One control inside: keep focus in the dialog.
        event.preventDefault();
        close.focus();
      }
    });
    document.addEventListener("pointerdown", (event) => {
      if (!box.hidden && !box.contains(event.target as Node)) closeHelp(false);
    });
    options.shell.appendChild(box);
    return box;
  }

  function openHelp(): void {
    overlay = overlay ?? buildOverlay();
    if (!overlay.hidden) return;
    returnFocus = document.activeElement as HTMLElement | null;
    overlay.hidden = false;
    overlay.querySelector<HTMLButtonElement>("button")?.focus({ preventScroll: true });
  }

  function closeHelp(refocus = true): void {
    if (!overlay || overlay.hidden) return;
    overlay.hidden = true;
    if (refocus) returnFocus?.focus({ preventScroll: true });
    returnFocus = null;
  }

  function toggleHelp(): void {
    if (overlay && !overlay.hidden) closeHelp();
    else openHelp();
  }

  // ----- host wiring -------------------------------------------------------
  function onKeyDown(event: KeyboardEvent): void {
    if (event.target !== event.currentTarget) return;
    const action = keyToAction(event);
    // "/" and "?" are page-level shortcuts, handled below.
    if (!action || action === "search" || action === "help") return;
    const t = current();
    if (!t) return;
    if (action === "clear") {
      // Fullscreen and open popovers own Escape first (existing handlers).
      if (options.fullscreen()) return;
      if (options.shell.querySelector(".graph-key-panel:not([hidden]), .graph-fineprint-pop:not([hidden])")) {
        return;
      }
      event.preventDefault();
      if (options.selection() >= 0) {
        t.clearSelection();
        announce("Selection cleared");
      }
      return;
    }
    if (action === "fit") {
      event.preventDefault();
      options.fit();
      showCursor(t);
      return;
    }
    if (action === "zoomIn" || action === "zoomOut") {
      if (options.zoom(action === "zoomIn" ? 1 : -1)) event.preventDefault();
      return;
    }
    event.preventDefault();
    if (action === "select") {
      if (path.length === 0) {
        announce("Press the down arrow to choose a package first");
        return;
      }
      const node = path[path.length - 1];
      selecting = true;
      try {
        t.select(node);
      } finally {
        selecting = false;
      }
      showCursor(t);
      const facts = options.info(t.tree.pkg(node));
      if (facts) announce(`Selected ${facts.version ? `${facts.name}@${facts.version}` : facts.name}`);
      return;
    }
    move(t, action);
  }

  function keyboardFocused(): boolean {
    return options.hosts.some(
      (host) => document.activeElement === host && host.matches(":focus-visible"),
    );
  }

  for (const host of options.hosts) {
    host.tabIndex = 0;
    host.setAttribute("role", "application");
    host.addEventListener("keydown", onKeyDown);
    host.addEventListener("focus", () => {
      const t = current();
      // Mouse focus waits for the first key; keyboard focus shows the cursor.
      if (t && host.matches(":focus-visible")) showCursor(t);
      options.onFocusChange?.();
    });
    host.addEventListener("blur", () => {
      hideCursor();
      options.onFocusChange?.();
    });
    // Clicking a node lands keyboard focus here, so arrows work right away.
    host.addEventListener("pointerdown", () => {
      if (document.activeElement !== host) host.focus({ preventScroll: true });
    });
  }

  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented) return;
    const action = keyToAction(event);
    if (action !== "search" && action !== "help") return;
    if (isEditable(document.activeElement)) return;
    // Only while the graph view is on screen.
    if (!options.shell.closest(".view-panel.active")) return;
    event.preventDefault();
    if (action === "help") {
      toggleHelp();
      return;
    }
    // In fullscreen the side panel (and the search box) is hidden.
    if (options.searchInput.offsetParent !== null) {
      closeHelp(false);
      options.searchInput.focus();
      options.searchInput.select();
    }
  });

  return {
    syncSelection(pkg: number) {
      if (selecting || pkg < 0) return;
      const t = current();
      if (!t) return;
      const node = t.tree.nodeOf(pkg);
      if (node < 0) return;
      path = pathTo(t.tree, node);
      if (cursorShown) showCursor(t);
    },
    setLabel(viewName: string) {
      for (const host of options.hosts) {
        host.setAttribute(
          "aria-label",
          `${viewName} of the dependencies. Use arrow keys to move between packages, Enter to open details, question mark for all shortcuts.`,
        );
      }
    },
    toggleHelp,
    keyboardFocused,
  };
}
