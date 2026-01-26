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
npx dependency-radar scan
```

Specify a project and output path:

```bash
npx dependency-radar scan --project ./my-app --out ./reports/dependency-radar.html
```

Keep the temporary `.dependency-radar` folder for debugging raw tool outputs:

```bash
npx dependency-radar scan --keep-temp
```

Skip `npm audit` (useful for offline scans):

```bash
npx dependency-radar scan --no-audit
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
