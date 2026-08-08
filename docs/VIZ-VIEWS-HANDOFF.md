# Graph Views Handoff — Flame, Balloon, Hyperbolic

**For:** a fresh Claude Code (Fable) session implementing three new dependency
visualizations in dependency-radar's report UI.
**From:** the July–August 2026 code-radar/dependency-radar visualization research
sessions with Joseph. Everything below was learned by building working
prototypes and getting Joseph's verdict on each. Trust this document over
first-principles re-derivation — most "obvious" approaches here were tried
and failed in specific, documented ways.

---

## 1. The brief (Joseph's words, condensed)

Implement **three new views** in the report UI alongside the existing graph
view, switchable with **buttons on the toolbar at the top**:

1. **Flame** — icicle/flame graph of the dependency tree.
2. **Balloon** — "constellation" radial balloon tree (satellite-chart style).
3. **Hyperbolic** — Poincaré-disk focus+context view.

The existing graph view stays untouched and remains an option. **View state
may simply reset when the user switches views** — no cross-view state
continuity is required for v1.

Context: this responds to issue **#91** (mindplay-dk, "Graph view UX
improvements"). Their asks, all of which the prototypes honour and the port
should too: information docked in a **sidebar/panel rather than a tooltip
covering the graph**, **search/filter by name**, **depth/kind filters**
(nice-to-have v2), and **no jump-cut zooms** that make you lose your place.

### Explicitly rejected (do not build)

- **Spiral flame** ("interesting to look at, but doesn't really tell me
  anything" — dropped).
- **Fisheye/dome lens** over the balloon ("the distortion across the screen
  is weird" — dropped, MAY return only if reworked as a *continuous gradient
  of zoom across the whole screen* rather than a dome region with a
  compressed shell around it. Do not attempt in this pass.)
- Whole-repo force-directed layouts as a default view (multiple sessions of
  evidence: position from simulation = position without meaning = hairball).

---

## 2. Working prototypes to port from

All four live in **`~/Developer/code-radar/experiments/`** as self-contained
HTML files (vanilla JS + canvas, no dependencies, data inlined). They were
built and screenshot-verified against a real scan of dependency-radar-app:
**901 packages, 2,444 pkg→pkg edges, 44 direct deps, 9 levels deep,
207,307 blocks when path-expanded**. Use them as the reference
implementation — the algorithms and constants in them are tuned.

| File | View | Status |
| --- | --- | --- |
| `hyperbolic-radar.html` | Poincaré disk | port |
| `dependency-flame.html` | flame/icicle | port |
| `constellation.html` | balloon tree | port |
| `constellation-lens.html` | dome lens | do NOT port (see above) |
| `flame-spiral.html` | spiral | do NOT port |

The prototypes' `DATA` global is `{ project, nodes: [{n: name, v: version,
d: declared(0/1), u: usedByFileCount}], edges: flat [from,to,...] }` with
edge direction "from depends on to".

---

## 3. Mapping to dependency-radar's data

The report UI (`report-ui/`, vanilla TS + Vite, bundled into a single HTML
report by `scripts/build-report.ts`) already has everything needed —
richer than the prototypes had:

- `report-ui/graphView.ts` builds a `GraphDataset`:
  - `workspaces: { name, directDependencies, directDevDependencies }[]`
  - `dependencies: Record<slug, GraphDependency>` where `GraphDependency`
    has `slug, name, version, dependencies: string[] (slugs), license,
    vulnerabilityCount, vulnerabilitySeverity, isDevOnly, workspaceOrigins`.
- Prototype field mapping: `n`→`name`, `v`→`version`, `d`→(is in a
  workspace's direct or directDev list), edges→`dependencies` arrays.
  There is no `u` (used-by-file-count); use direct-ness and dependent count
  instead where the prototypes used usage.
- **Bonus data the prototypes lacked — use it**: `vulnerabilitySeverity`
  (badge/ring nodes red — this is dependency-radar's actual product value),
  `isDevOnly` (render dimmer / filterable), `license` (sidebar).
- The existing graph view already supports a per-workspace selector
  (`#graph-workspace`); the new views should respect the same selection
  (roots = that workspace's direct + directDev deps).

### Existing view-switch plumbing (extend, don't replace)

`report-ui/main.ts` toggles `#list-view` / `#graph-view` panels via
`#view-graph-btn` and `#graph-back-btn`; graph DOM ids: `#graph-canvas`,
`#graph-canvas-shell`, `#graph-controls`, `#graph-popover*`,
`#graph-open-list`. `initGraphView(options): GraphViewHandle` at
`graphView.ts:942`.

Recommended integration shape:
- Add a small segmented control to the graph toolbar (`#graph-controls`):
  **Graph | Flame | Balloon | Hyperbolic** (`data-graph-mode` buttons).
- Keep one `<canvas>`; give each mode an init/destroy/render handle with the
  same interface as `GraphViewHandle` (or a slim shared subset:
  `{ mount(canvas, dataset, callbacks), destroy(), resize() }`).
- Switching modes = destroy current handle, init the next with fresh state
  (Joseph explicitly OK'd reset-on-switch).
- Reuse the existing popover/sidebar affordances for selection details
  (name, version, license, vulns, "open in list") — mindplay's sidebar ask.
  The prototypes' right-hand dossier (deps chips / dependents chips /
  subtree count / "appears in N places") is the richer template; chips
  click-through to re-focus is a loved feature, keep it.
- The report is a single self-contained HTML with a strict no-network
  ethos — the prototypes are dependency-free canvas code precisely so they
  drop in. Do not add chart libraries.

---

## 4. Shared derivation layer (build once, used by all three views)

From `dependencies` edge lists, precompute (all with **cycle guards** —
real npm graphs contain cycles; the test set had 4):

```ts
// deps/dependents adjacency from GraphDependency.dependencies
// roots = the selected workspace's direct + directDev slugs

// (a) subSize: path-expanded subtree size (each package counted once per
// path, profiler-style). Memoised DFS; a path-Set guards cycles.
// NOTE: memoisation makes cycle-adjacent counts approximate — fine.
function sizeOf(id, path) {
  if (subSize[id] > 0) return subSize[id];
  if (path.has(id)) return 0;
  path.add(id);
  let n = 1;
  for (const dep of depsOut[id]) n += sizeOf(dep, path);
  path.delete(id);
  subSize[id] = n;
  return n;
}

// (b) kidsOf: children sorted heaviest-first (subSize desc, then stable).
// (c) spanning tree (hyperbolic + balloon): BFS from roots sorted by
//     "most used first"; first claimer wins; unreached nodes become roots.
// (d) occ: number of distinct root→package paths (memoised over dependents,
//     same cycle guard). Displayed as "appears in N places".
```

Two width/size semantics exist — **surface this honestly**:
- *path-expanded* (subSize above): "how much npm traverses". Inflates
  diamond-heavy trees (eslint-config-next owned >50% of the flame for
  dependency-radar-app — a great, shocking, truthful headline).
- *unique packages introduced*: dedup on first occurrence. Joseph found the
  difference interesting; a toggle is a worthwhile v2, default path-expanded.

---

## 5. View specs

### 5.1 Flame (port of `dependency-flame.html`)

Icicle plot, root bar on top, one row per depth, **width ∝ subSize share**,
children heaviest-first left-to-right. React devs read these natively
(Joseph: "I am familiar with flame charts having used the React dev tools a
lot") — zero learning curve is the point of this view.

- **Lazy layout**: never materialise the 200k-block expansion. Recurse at
  draw time through `kidsOf`, pruning blocks narrower than ~0.8 px;
  accumulate pruned width into a dim "spray" strip at the row's end. A
  recursion `chain` Set prevents cycle loops. Visible blocks land in a
  `blocks[]` array (`{id, parent, x, y, w, h}`) used for picking.
- **Zoom**: click a bar → it becomes full-width; **every ancestor stays
  pinned above as a slim full-width bar** (click one to climb back out);
  the project bar is always the topmost. Double-click = reset. This
  ancestors-pinned pattern is what answers "where did it come from" —
  don't replace it with breadcrumb text alone.
- **Colour**: each root subtree keeps one muted hue all the way down
  (lineage!); depth darkens it slightly. Prototype hues:
  `[28,152,268,322,82,8,232,55,190,300]`, `hsl(h, ~36%, 44−2.6·depth%)`.
  Reserve cyan `#35e0ff` strokes for hover/selection only. In
  dependency-radar, consider overriding hue→red for vulnerable subtrees.
- **Readout**: hover shows full path trail `project › a › b › c` plus
  "N in subtree · appears in M places" in a fixed status line (not a
  tooltip on the graph).
- Known truncation: labels only when width > ~34 px, clipped into the bar.

### 5.2 Balloon / "constellation" (port of `constellation.html`)

Radial balloon tree, the structural twin of the SCMP "Satellites network"
infographic Joseph loves. Project = central body; roots orbit it; each
node's children fan on an arc facing away from its parent, recursively.

Critical constants and the reasons they exist (each fixed a real failure):

- `SHRINK = 0.52` — **each level's balloon is a scaled-down copy**. Without
  this the enclosure radii compound and the layout explodes to a bbox so
  large the fit-view renders a single dot (this happened; the geometric
  series must converge).
- Enclosing radius per subtree, memoised, in local units:
  `enc = max(nodeR + SHRINK·maxKidEnc + 6, Σ(2·SHRINK·kidEnc·1.12)/FAN)`,
  `FAN = 3.6` rad. Children get angular shares ∝ their enc.
- `nodeR = min(70, 2.2 + subSize^0.34 · 1.1)` — **sub-linear**, because
  sqrt sizing let one monster (eslint) blow out the dynamic range.
- **Two tiers**: roots with `enc ≥ 150` are arc-packed on the outer ring;
  the rest sit evenly spaced on an inner orbit at 0.34× the major ring
  radius. Without this, the tail of small deps piles into an overlapping
  stack (happened).
- **Minimum screen sizes** (cartographer's rule): depth-0 hubs never render
  below ~9 px, depth-1 below ~2.4 px, regardless of zoom — otherwise the
  fitted overview is empty space with invisible content (happened).
  Same floors apply to edge-draw eligibility.
- **Labels**: satellite style — name, and the subtree count on a second
  line beneath. Budget ~90–120 labels, **allocated biggest-on-screen-first**
  (sort candidates by rendered radius; first-come order starves the region
  the user cares about — happened). Threshold ~7.5 px rendered radius.
- Edges always visible (thin, hue-tinted, alpha rising with node size).
- Interaction: linear pan (drag) + wheel zoom-at-cursor (scale clamp
  ~0.05–600), double-click space = fit, search/chips fly-to with eased
  animation. LOD during interaction: skip bodies under ~0.8 px while
  panning, full redraw ~150 ms after idle.
- Picking: spatial hash grid (cell ~64 world units) built once over bodies
  with radius ≥ ~1.6; hover looks up 3×3 cells.
- Layout is cheap (arithmetic recursion over ~200k placements into flat
  typed-ish arrays `px/py/pr/pid/pparent/pdepth/phue`). Draw all, skip
  invisible.

### 5.3 Hyperbolic disk (port of `hyperbolic-radar.html`)

The Poincaré disk: project at centre, direct deps on the first ring,
sub-dependencies shrinking toward the (infinitely far) rim. The whole tree
in one finite circle; **drag performs a Möbius translation** — whatever you
drag toward the centre grows, everything else compresses to the rim but
never leaves the disk.

Maths (complex numbers as `{x,y}`):
- Disk automorphism `T_a(z) = (z + a)/(1 + conj(a)·z)` maps 0→a.
- **Layout**: spanning tree; root ring at Euclidean radius 0.52 with wedge
  shares (weight floor: `sqrt(leaves)+1.5` so leafless deps don't smear
  into slivers — happened); children placed in the parent's local frame at
  `ρ = min(0.82, 0.42 + 0.05·√childCount)` within a wedge
  `min(share·0.92, 2.4)`, transported to global via `T_parent`; the child's
  outward direction = `arg(T_{−child}(parent)) + π`.
- **Drag** = compose `T_{m1} ∘ T_{−m0}` (grab point m0 follows cursor to
  m1), applied to *baked* positions each move.
- **Click/search focus** = animate `a` from 0 → node position along
  `a·ease(t)`, applying `T_{−a}` to positions captured at animation start;
  bake at the end.
- **THE HUB BUG (do not repeat)**: every transform must be applied to
  *every* point **including the virtual project-hub position** — it is not
  a node in the array and it silently stays pinned at centre otherwise
  (happened; looks bizarre).
- Node size ∝ conformal factor `(1 − |z|²)`; edges are geodesic arcs
  (circle through z1,z2 orthogonal to the unit circle — solve the 2×2
  linear system from `2·Re(z·conj(c)) = |z|²+1`; fall back to a straight
  line when the cross-product is ~0). Range rings at `tanh(d·0.55)` are
  *meaningful* (equal hyperbolic distance) — Joseph's rule: decoration must
  encode something or be cut.
- Selection: focus subtree + direct-dependent edges bright cyan, subtree
  labels on; rest dims. Double-click space = rebuild/reset layout.
- Known accepted weakness (Joseph experienced it): deep focus crushes
  context to the rim. It stays in the lineup because navigation feel is
  unmatched; it is the "explore" view, flame is the "answer" view.

---

## 6. Shared design language (all views)

- Dark scope theme: bg `#060a10`, panel `#0b131c`, line `#1a2836`, ink
  `#c9d6e2`, muted `#6c7f92`, cyan `#35e0ff` **reserved exclusively for
  focus/hover/selection**. Monospace (system stack) for all data/labels;
  nameplate style: small caps, letterspaced, cyan title.
  (Adapt to the report's existing theme system — it has light/dark; the
  prototypes are dark-only. Tokenise rather than hardcode.)
- Hue-per-root lineage colouring is load-bearing information in all views.
- Status line at the bottom shows the hovered path trail + stats — never a
  tooltip covering the visualization (issue #91).
- Sidebar dossier on select: version, kind (direct/dev/sub-dependency),
  subtree size, "appears in N places", Depends-on chips, Required-by chips
  (both clickable to refocus). This pattern got positive feedback every
  single round — it's the constant across all views.
- Search with incremental results; choosing a result focuses/zooms/flies
  in the current view's native way.

## 7. Hard-won general lessons

1. **Dynamic range is the enemy** in npm dep graphs (10⁰–10⁵ subtree
   sizes). Every failure in these sessions was a dynamic-range failure:
   sqrt sizing, single-ring packing, uniform label budgets, polynomial
   lenses. Every fix was curation-as-rules: sub-linear scales, tiering,
   floors/caps, size-sorted budgets.
2. **Overviews don't answer questions; focused views do.** Zoomed-out modes
   exist for orientation and the "which is heaviest" glance; everything
   else is selection-driven. Don't spend effort making the overview do more.
3. **Deterministic layouts beat simulated ones** — stable across renders,
   instant, and positions can be trusted between sessions.
4. **Canvas, flat arrays, draw-time pruning** comfortably handles 200k+
   items; the label budget, not geometry, is the readability ceiling.
5. Path-counted vs unique-package weights differ dramatically on
   diamond-heavy trees; label which one you're showing.

## 8. Suggested build order & acceptance

1. Shared derivation module + mode-switch scaffolding (buttons, handle
   interface, reset-on-switch). Existing graph view untouched.
2. **Flame** first (simplest, most immediately useful, easiest to verify).
3. **Balloon** second (most code, all constants provided above).
4. **Hyperbolic** third (least code, trickiest maths — port faithfully).
5. Wire selection → existing popover/list cross-links; search box per view
   or shared.

Accept each view when, on a real scan (dependency-radar's own repo or any
Next.js app): it renders without console errors; heaviest-root question is
answerable at a glance (flame), lineage is followable during zoom/focus
(all), hover shows the path trail, selection shows the dossier with
clickable chips, and switching modes resets cleanly with no leaked
listeners/rAF loops (destroy() must cancel animation frames and remove
canvas/window listeners — the prototypes attach `wheel` with
`{passive:false}` and pointer capture; leaked handlers across mode
switches will double-fire).

## 9. Provenance

- Prototypes + screenshots: code-radar repo `experiments/` (uncommitted as
  of 2026-08-08) and session artifacts (claude.ai/code/artifacts: disk,
  flame, spiral, constellation, lens).
- Related strategic doc: `~/Developer/code-radar/FINDINGS.md` (why
  whole-codebase 3D overviews were abandoned; the scanner + focused-Q&A
  verdict). Not required reading for this task, but explains the taste
  decisions above.
- Issue driving this: https://github.com/JosephMaynard/dependency-radar/issues/91
