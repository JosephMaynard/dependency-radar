# Dependency Radar

Dependency Radar is a local-first CLI tool that inspects a Node.js project’s installed dependencies and generates a single, human-readable HTML report. The report highlights dependency structure, usage, size, licences, vulnerabilities, and other signals that help you understand risk and complexity hidden in your node_modules folder.

## What it does

- Analyses installed dependencies using only local data (no SaaS, no uploads by default)
- Combines multiple tools (npm audit, npm ls, import graph analysis) into a single report
- Shows direct vs sub-dependencies, dependency depth, and parent relationships
- Highlights licences, known vulnerabilities, install-time scripts, native modules, and package footprint
- Produces a single self-contained HTML file you can share or archive

## What it is not

- Not a CI service or hosted platform
- Not a replacement for dedicated security scanners
- Not a bundler or build tool
- Not a dependency updater

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

Skip `npm audit` (useful for offline scans):

```bash
npx dependency-radar --no-audit
```

Output JSON instead of HTML report:

```bash
npx dependency-radar --json
```

Show options:

```bash
npx dependency-radar --help
```

## Scripts

- `npm run build` – compile TypeScript to `dist/`
- `npm run dev` – run a scan from source (`ts-node`)
- `npm run scan` – run a scan from the built output

## Notes

- The target project must have node_modules installed (run npm install first).
- The scan is local-first and does not upload your code or dependencies anywhere.
- `npm audit` performs registry lookups; use `--no-audit` for offline-only scans.
- A temporary `.dependency-radar` folder is created during the scan to store intermediate tool output.
- Use `--keep-temp` to retain this folder for debugging; otherwise it is deleted automatically.
- If a tool fails, its section is marked as unavailable, but the report is still generated.

## Output

Dependency Radar writes a single HTML file (dependency-radar.html by default).  
The file is fully self-contained and can be opened locally in a browser, shared with others, or attached to tickets and documentation.

### JSON output

Use `--json` to write the aggregated scan data as JSON (defaults to `dependency-radar.json`).

The JSON schema matches the `AggregatedData` TypeScript interface in `src/types.ts`. For quick reference:

```ts
export interface AggregatedData {
  schemaVersion: '1.0'; // Report schema version for compatibility checks
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
  };
  workspaces: {
    enabled: boolean; // True when the scan used workspace aggregation
  };
  summary: {
    dependencyCount: number; // Total dependencies in the graph
    directCount: number; // Dependencies listed in package.json
    transitiveCount: number; // Dependencies pulled in by other dependencies
  };
  dependencies: Record<string, DependencyRecord>; // Keyed by name@version
}

export interface DependencyRecord {
  id: string; // Stable identifier in the form name@version
  name: string; // Package name from npm metadata
  version: string; // Installed version from npm ls
  direct: boolean; // True if declared in package.json (dependencies/devDependencies/etc.)
  scope: 'runtime' | 'dev' | 'optional' | 'peer'; // Scope inferred from the declaring root package(s)
  depth: number; // Minimum dependency tree depth observed in npm ls
  origins: {
    rootPackageCount: number; // Number of direct roots that introduce this dependency
    topRootPackages: string[]; // Up to 10 root package names that cause installation
    workspaces?: string[]; // Workspace packages that declare/use this dependency
  };
  license: string; // License string read from the installed package.json
  licenseRisk: 'green' | 'amber' | 'red'; // Risk classification derived from license string
  vulnerabilities: {
    critical: number; // npm audit counts for critical issues
    high: number; // npm audit counts for high issues
    moderate: number; // npm audit counts for moderate issues
    low: number; // npm audit counts for low issues
    highest: 'low' | 'moderate' | 'high' | 'critical' | 'none'; // Highest severity present
  };
  vulnRisk: 'green' | 'amber' | 'red'; // Risk classification derived from audit counts
  deprecated: boolean; // True if the package.json has a deprecated flag
  nodeEngine: string | null; // engines.node from the package.json (if present)
  build: {
    native: boolean; // True if native bindings detected (gyp/.node/scripts)
    installScripts: boolean; // True if preinstall/install/postinstall scripts are present
    risk: 'green' | 'amber' | 'red'; // Build risk derived from native/scripts flags
  };
  tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown'; // TypeScript type availability
  dependencySurface: {
    deps: number; // Count of production dependencies declared by this package
    dev: number; // Count of dev dependencies declared by this package
    peer: number; // Count of peer dependencies declared by this package
    opt: number; // Count of optional dependencies declared by this package
  };
  graph: {
    fanIn: number; // Number of packages that depend on this package
    fanOut: number; // Number of packages this package depends on
  };
  links: {
    npm: string; // npm package page URL
  };
  usage?: {
    fileCount: number; // Number of project files importing this package (import graph)
    topFiles: string[]; // Top import locations (bounded to 5)
  };
  introduction?: 'direct' | 'tooling' | 'framework' | 'testing' | 'transitive' | 'unknown'; // Heuristic for why the dependency exists
  runtimeImpact?: 'runtime' | 'build' | 'testing' | 'tooling' | 'mixed'; // Heuristic based on import locations
  upgrade?: {
    blocksNodeMajor: boolean; // True if local signals indicate a node major bump is risky
    blockers: Array<'nodeEngine' | 'peerDependency' | 'nativeBindings' | 'deprecated'>; // Reasons for upgrade friction
  };
  outdated?: {
    status: 'current' | 'patch' | 'minor' | 'major' | 'unknown'; // Derived from npm outdated (or unknown if ambiguous)
    latestVersion?: string; // npm latest version (present only when status is not current)
  };
}
```

For full details and any future changes, see `src/types.ts`.

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
