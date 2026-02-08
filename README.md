# Dependency Radar

Dependency Radar is a CLI tool that inspects a Node.js project’s installed dependencies and generates a single, human-readable HTML report. The report highlights dependency structure, usage, licences, vulnerabilities, and other signals that help you understand risk and complexity hidden in your node_modules folder.

The simplest way to get started is:

```bash
npx dependency-radar
```

This runs a scan against the current project and writes a self-contained `dependency-radar.html` report you can open locally, share with teammates, or attach to tickets and documentation.

## What it does

- Analyses installed dependencies by running standard package manager tooling (npm, pnpm, or yarn)
- Combines multiple signals (audit results, dependency graph data, import usage, and heuristics) into a single report
- Shows direct vs transitive dependencies, dependency depth, and parent relationships
- Highlights licences, known vulnerabilities, install-time scripts, native modules, and package footprint (including installed file counts)
- Produces a single self-contained HTML file with no external assets, which you can easily share

## What it is not

- Not a CI service or hosted scanning platform
- Not a replacement for dedicated security scanners
- Not a bundler or build tool
- Not a dependency updater

---

For teams that want deeper analysis, long-term tracking, and additional enrichment (such as ecosystem and maintenance signals), Dependency Radar also offers an optional premium service.  
See https://dependency-radar.com for details.

## How a scan works

When you run `npx dependency-radar` (or `dependency-radar scan`), the CLI executes this pipeline:

1. Parse CLI options (`--project`, `--out`, `--offline`, `--json`, `--keep-temp`, `--open`).
2. Detect workspace/package-manager context:
   - Workspace roots from `pnpm-workspace.yaml` or `package.json#workspaces`
   - Package manager from `packageManager`, lockfiles, and installed metadata
   - Yarn Plug'n'Play detection (`.pnp.cjs`/`.pnp.js` or `.yarnrc.yml nodeLinker: pnp`)
3. Create a temporary `.dependency-radar/` directory inside the scanned project.
4. For each workspace package (or just the project root in single-package mode), run collectors:
   - Dependency tree (`npm ls` / `pnpm list` / `yarn list`)
   - Vulnerabilities (`npm audit` / `pnpm audit` / `yarn audit` or `yarn npm audit`)
   - Version drift (`npm outdated` / `pnpm outdated` / `yarn outdated`, where available)
   - Source import graph (static import/require parsing in `src/` or project root)
5. Normalize tool outputs into one internal shape and merge workspace package results.
6. Aggregate dependency records by enriching each installed package with:
   - License declaration + `LICENSE` file inference/validation
   - Advisory summaries and severity/risk rollups
   - Root-cause/origin and runtime-impact heuristics
   - Install-time execution signals
   - Local package metadata (`description`, links, deprecation, TypeScript type availability, installed file count, CLI `bin` presence)
7. Write final output as either:
   - `dependency-radar.html` (self-contained report), or
   - `dependency-radar.json` (raw aggregated model)
8. Remove `.dependency-radar/` unless `--keep-temp` is set.

The scan is local-first: package metadata is read from `node_modules`; only audit/outdated commands require registry access.

## Usage Heuristics (`usage.runtimeImpact` and `usage.introduction`)

These two fields are inferred from local signals. They are intended as review hints, not strict truth.

### `usage.runtimeImpact`

`runtimeImpact` is inferred from the import graph and file-path classification:

1. Dependency imports are collected from source files (`import`, `export ... from`, `require()`, and static `import()`).
2. Each importing file is classified into one of: `runtime`, `build`, `testing`, `tooling`.
3. Classification is path-pattern based (examples):
   - `testing`: `__tests__`, `test`, `tests`, `e2e`, `cypress`, `playwright`, `*.test.*`, `*.spec.*`
   - `tooling`: eslint/prettier/stylelint/commitlint/lint-staged/husky/renovate/release configs
   - `build`: webpack/rollup/vite/tsconfig/babel/swc/esbuild/parcel/postcss/tailwind/storybook/turbo/nx configs and common `scripts/build*` paths
4. Per dependency, category weights are summed from import counts.
5. Result selection:
   - Single dominant category => that category
   - Strong majority (for example >= 70%) => that category
   - Otherwise => `mixed`

### `usage.introduction`

`introduction` is inferred from dependency graph roots, scope, and runtime impact:

1. If dependency is direct => `direct`
2. If `runtimeImpact` is `testing` => `testing`
3. If `runtimeImpact` is `tooling` or `build` => `tooling`
4. If inferred scope is `dev` => `tooling`
5. If inferred scope is `peer` and `runtimeImpact` is not `runtime` => `tooling`
6. If all root-cause direct dependencies are in a tooling allowlist => `tooling`
7. If any root-cause direct dependency is in a framework allowlist => `framework`
8. If root causes exist but none of the above match => `transitive`
9. Otherwise => `unknown`

### Validity and limits

- Valid as directional metadata for prioritization and triage.
- Not valid as a definitive runtime/ownership model.
- Accuracy depends on file naming conventions, static import detectability, and dependency graph quality from package manager output.

## Upgrade Blockers Heuristic (`upgrade.blockers`, `upgrade.blocksNodeMajor`)

`upgrade.blockers` is a local, static heuristic for upgrade friction. It does not run package code and does not query external APIs.

### How blockers are collected

For each installed dependency, Dependency Radar inspects local package metadata and install-surface signals and may add one or more blockers:

- `nodeEngine`: Added when `package.json#engines.node` looks restrictive (for example `>=16`, `^18`, `<20`, ranges with concrete major constraints). Permissive forms such as `*` and `>=0` are not flagged.
- `peerDependency`: Added when the package declares at least one non-optional peer dependency (`peerDependencies`, excluding peers marked `peerDependenciesMeta.<name>.optional: true`).
- `nativeBindings`: Added when native build/binary surface is detected (`binding.gyp`, `.node` binaries, or native build tooling in scripts such as `node-gyp`/`prebuild`).
- `installScripts`: Added when install lifecycle hooks are present (`preinstall`, `install`, or `postinstall`).
- `deprecated`: Added when the package is marked deprecated in installed metadata.

### `blocksNodeMajor` meaning

`upgrade.blocksNodeMajor` is only emitted when local signals suggest Node major upgrades may be risky for that package. It is set from a subset of blockers:

- `nodeEngine`
- `nativeBindings`
- `installScripts`

It is not set from `peerDependency` or `deprecated` alone.

### Accuracy and limits

- High signal: `nativeBindings`, `deprecated`, and non-optional `peerDependency` are generally reliable local indicators.
- Medium signal: `nodeEngine` is heuristic range parsing; unusual semver expressions may be under- or over-classified.
- Medium signal: `installScripts` indicates lifecycle execution surface, not guaranteed breakage.
- The field represents friction likelihood, not a guaranteed upgrade failure.
- Future versions may expand blocker categories; consumers should handle unknown blocker strings defensively.

## License Scanning

Dependency Radar validates SPDX licenses declared in `package.json` and can infer licenses from `LICENSE` files when declarations are missing or invalid. It works offline and uses a bundled SPDX identifier list (generated at build time) with no runtime network access. Each dependency gets a structured license record with:

- Declared SPDX validation (including deprecated IDs and `WITH` exceptions)
- Inferred SPDX license (with confidence: `high`, `medium`, `low`) based on deterministic text matching
- A status (`declared-only`, `inferred-only`, `match`, `mismatch`, `invalid-spdx`, `unknown`) to make review decisions easier

This logic applies to all dependencies (direct and transitive). Inferred licenses are never treated as authoritative over valid declared SPDX expressions.


## Setup

```bash
npm install
npm run build
```

## Requirements

- Node.js 14.14+

## Usage

The simplest way to run Dependency Radar is via npx. It runs in the current directory and writes an HTML report to disk.

Run a scan against the current project (writes `dependency-radar.html`):

```bash
npx dependency-radar
```

The `scan` command is the default and can also be run explicitly as `npx dependency-radar scan`.


Specify a project and output path:

```bash
npx dependency-radar --project ./my-app --out ./reports/dependency-radar.html
```

Keep the temporary `.dependency-radar` folder for debugging raw tool outputs:

```bash
npx dependency-radar --keep-temp
```

Skip `npm audit` and `npm outdated` (useful for offline scans):

```bash
npx dependency-radar --offline
```

Output JSON instead of HTML report:

```bash
npx dependency-radar --json
```

Open the generated report using the system default:

```bash
npx dependency-radar --open
```

Show options:

```bash
npx dependency-radar --help
```

## Package Manager Support

- npm: Supported for dependency tree, audit, outdated, single-package, and workspaces.
- pnpm: Supported for dependency tree, audit, outdated, and workspaces (with ls depth fallbacks for large projects).
- Yarn Classic (v1, node_modules linker): Supported for dependency tree, audit, outdated, and workspaces.
- Yarn Berry (v2+, node-modules linker): Dependency tree and audit work; outdated support depends on available Yarn commands/plugins and may be unavailable.
- Yarn Plug'n'Play (`nodeLinker: pnp`): Not supported yet.

## Scripts

- `npm run build` – generate SPDX/report assets and compile TypeScript to `dist/`
- `npm run dev` – run a scan from source (`ts-node src/cli.ts scan`)
- `npm run scan` – run a scan from the built output (`node dist/cli.js scan`)
- `npm run dev:report` – run the report UI dev server
- `npm run build:spdx` – rebuild bundled SPDX identifiers
- `npm run build:report-ui` – build report UI assets
- `npm run build:report` – rebuild report assets used by the CLI

### Fixture scripts:

- `npm run fixtures:install` – install core fixture dependencies
- `npm run fixtures:install:all` – install all fixture dependencies
- `npm run fixtures:scan` – scan the core fixture set
- `npm run fixtures:install:npm`
- `npm run fixtures:install:npm-heavy`
- `npm run fixtures:install:pnpm`
- `npm run fixtures:install:pnpm-hoisted`
- `npm run fixtures:install:yarn`
- `npm run fixtures:install:yarn-berry`
- `npm run fixtures:install:optional`
- `npm run fixtures:scan:npm`
- `npm run fixtures:scan:npm-heavy`
- `npm run fixtures:scan:pnpm`
- `npm run fixtures:scan:pnpm-hoisted`
- `npm run fixtures:scan:yarn`
- `npm run fixtures:scan:yarn-berry`
- `npm run fixtures:scan:optional`
- `npm run fixtures:scan:no-node-modules`

## Notes

- The target project must have dependencies installed (run `npm install`, `pnpm install`, or `yarn install` first).
- The scan runs on your machine and does not upload your code or dependencies anywhere.
- `npm audit`/`pnpm audit`/`yarn npm audit` and `npm outdated`/`pnpm outdated` perform registry lookups; use `--offline` for offline-only scans.
- On some Yarn Berry setups, `yarn outdated` is not available; the scan continues and marks outdated data as unavailable.
- A temporary `.dependency-radar` folder is created during the scan to store intermediate tool output.
- Use `--keep-temp` to retain this folder for debugging; otherwise it is deleted automatically.
- If some per-package tools fail (common in large workspaces), the scan continues and reports warnings; missing sections are marked unavailable where applicable.

## Output

Dependency Radar writes a single HTML file (dependency-radar.html by default).  
The file is fully self-contained and can be opened locally in a browser, shared with others, or attached to tickets and documentation.

### JSON output

Use `--json` to write the aggregated scan data as JSON (defaults to `dependency-radar.json`).

The JSON schema matches the `AggregatedData` TypeScript interface in `src/types.ts`. For quick reference:

```ts
export interface AggregatedData {
  schemaVersion: '1.2'; // Report schema version for compatibility checks
  generatedAt: string; // ISO timestamp when the scan finished
  dependencyRadarVersion: string; // CLI version that produced the report
  git: {
    branch: string; // Git branch name, empty when unavailable/detached
  };
  project: {
    projectDir: string; // Project path relative to the user's home directory (e.g. /Developer/app)
  };
  environment: {
    nodeVersion: string; // Node.js version from process.versions.node
    runtimeVersion: string; // Node.js runtime version from process.version
    minRequiredMajor: number; // Strictest Node major required by dependency engines (0 if unknown)
    platform?: string; // OS platform (process.platform)
    arch?: string; // CPU architecture (process.arch)
    ci?: boolean; // True when running in CI (process.env.CI === 'true')
    packageManagerField?: string; // package.json packageManager field (e.g. pnpm@9.1.0)
    packageManager?: 'npm' | 'pnpm' | 'yarn'; // Package manager used to scan
    packageManagerVersion?: string; // Version of the package manager used to scan
    toolVersions?: {
      npm?: string;
      pnpm?: string;
      yarn?: string;
    };
  };
  workspaces: {
    enabled: boolean; // True when the scan used workspace aggregation
    type?: 'npm' | 'pnpm' | 'yarn' | 'none'; // Workspace type if detected
    packageCount?: number; // Number of workspace packages scanned
  };
  summary: {
    dependencyCount: number; // Total dependencies in the graph
    directCount: number; // Dependencies listed in package.json
    transitiveCount: number; // Dependencies pulled in by other dependencies
  };
  dependencies: Record<string, DependencyRecord>; // Keyed by name@version
}

export interface DependencyRecord {
  package: {
    id: string; // Stable identifier in the form name@version
    name: string; // Package name from npm metadata
    version: string; // Installed version from npm ls
    description?: string; // Description from the installed package.json (if present)
    fileCount?: number; // Number of files in the installed package folder (excluding nested node_modules)
    hasBin?: true; // True if package.json declares at least one executable in `bin`
    deprecated: boolean; // True if the package.json has a deprecated flag
    links: {
      npm: string; // npm package page URL
      repository?: string; // Repository URL (if present)
      homepage?: string; // Homepage URL (if present)
      bugs?: string; // Issue tracker URL (if present)
    };
  };
  compliance: {
    license: {
      declared?: {
        spdxId: string; // SPDX ID or expression from package.json
        expression: boolean; // True when SPDX expression (AND/OR/WITH)
        deprecated: boolean; // True if SPDX ID is deprecated
        valid: boolean; // True if SPDX ID/expression is valid
      };
      inferred?: {
        spdxId: string; // SPDX ID inferred from LICENSE text
        confidence: 'high' | 'medium' | 'low'; // Heuristic confidence
      };
      exception?: {
        id: string; // SPDX exception id
        deprecated: boolean; // True if exception is deprecated
        valid: boolean; // True if exception id is valid
      };
      status:
        | 'declared-only'
        | 'inferred-only'
        | 'match'
        | 'mismatch'
        | 'invalid-spdx'
        | 'unknown';
    };
    licenseRisk: 'green' | 'amber' | 'red'; // Risk classification derived from declared/inferred SPDX ids
  };
  security: {
    summary: {
      critical: number; // npm audit counts for critical issues
      high: number; // npm audit counts for high issues
      moderate: number; // npm audit counts for moderate issues
      low: number; // npm audit counts for low issues
      highest: 'low' | 'moderate' | 'high' | 'critical' | 'none'; // Highest severity present
      risk: 'green' | 'amber' | 'red'; // Risk classification derived from audit counts
    };
    advisories?: Array<{
      id: string; // GHSA identifier
      title: string; // Human-readable advisory title
      severity: 'low' | 'moderate' | 'high' | 'critical';
      vulnerableRange: string; // Semver range
      fixAvailable: boolean; // True if npm audit indicates a fix exists
      url: string; // Advisory URL
    }>;
  };
  upgrade: {
    nodeEngine: string | null; // engines.node from the package.json (if present)
    outdatedStatus?: 'current' | 'patch' | 'minor' | 'major' | 'unknown'; // Derived from npm outdated (if present)
    latestVersion?: string; // npm latest version (present only when status is not current)
    blockers?: Array<'nodeEngine' | 'peerDependency' | 'nativeBindings' | 'installScripts' | 'deprecated'>; // Reasons for upgrade friction
    blocksNodeMajor?: boolean; // Present when local signals indicate a Node major bump is risky
  };
  usage: {
    direct: boolean; // True if declared in package.json (dependencies/devDependencies/etc.)
    scope: 'runtime' | 'dev' | 'optional' | 'peer'; // Scope inferred from the declaring root package(s)
    depth: number; // Minimum dependency tree depth observed in npm ls
    origins: {
      rootPackageCount: number; // Number of direct roots that introduce this dependency
      topRootPackages: Array<{ name: string; version: string }>; // Up to 10 root packages (name/version)
      parentPackageCount: number; // Number of direct parents
      topParentPackages: string[]; // Up to 5 direct parent ids (name@version)
      workspaces?: string[]; // Workspace packages that declare/use this dependency
    };
    introduction?: 'direct' | 'tooling' | 'framework' | 'testing' | 'transitive' | 'unknown'; // Heuristic for why the dependency exists
    runtimeImpact?: 'runtime' | 'build' | 'testing' | 'tooling' | 'mixed'; // Heuristic based on import locations
    importUsage?: {
      fileCount: number; // Number of project files importing this package (import graph)
      topFiles: string[]; // Top import locations (bounded to 5)
    };
    tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown'; // TypeScript type availability
  };
  graph: {
    fanIn: number; // Number of packages that depend on this package
    fanOut: number; // Number of packages this package depends on
    subDeps?: {
      // Declared outgoing dependency edges; values are tuples.
      // tuple[0] = declared version range, tuple[1] = resolved dependency id or null if not installed.
      // Only installed dependencies have full dependency records in the top-level list.
      dep?: Record<string, [string, string | null]>; // Declared runtime deps
      dev?: Record<string, [string, string | null]>; // Declared dev deps
      peer?: Record<string, [string, string | null]>; // Declared peer deps
      opt?: Record<string, [string, string | null]>; // Declared optional deps
    };
  };
  execution?: {
    risk: 'amber' | 'red'; // Install-time risk (green implied when absent)
    native?: true; // True if native bindings or build tooling are detected
    scripts?: {
      hooks: Array<'preinstall' | 'install' | 'postinstall' | 'prepare'>; // Lifecycle hooks detected
      complexity?: number; // Heuristic complexity (stored only when high)
      signals?: Array<
        | 'network-access'
        | 'dynamic-exec'
        | 'child-process'
        | 'encoding'
        | 'obfuscated'
        | 'reads-env'
        | 'reads-home'
        | 'uses-ssh'
      >; // Review-worthy install-time signals (sparse)
    };
  };
}
```

For full details and any future changes, see `src/types.ts`.

Environment data includes Node.js version, OS platform, CPU architecture, and package manager versions.
No personal information, usernames, paths, or environment variables are collected.

## Development

### Report UI Development

The HTML report UI is developed in a separate Vite project located in `report-ui/`. This provides a proper development environment with hot reload, TypeScript support, and sample data.

**Start the development server:**

```bash
npm run dev:report
```

This opens the report UI in your browser with sample data covering all dependency states (various licenses, vulnerability severities, usage statuses, etc.).

**Build workflow:**

1. Make changes in `report-ui/` (edit `style.css`, `main.ts`, `index.html`)
2. Run `npm run build:report` to compile and inject assets into `src/report-assets.ts`
3. Run `npm run build` to compile the full project (this runs `build:report` automatically)

**File structure:**

- `report-ui/index.html` – HTML template structure
- `report-ui/style.css` – All CSS styles
- `report-ui/main.ts` – TypeScript rendering logic
- `report-ui/sample-data.json` – Sample data for development
- `report-ui/types.ts` – Client-side TypeScript types
- `src/report-assets.ts` – Auto-generated file with bundled CSS/JS (do not edit directly)
