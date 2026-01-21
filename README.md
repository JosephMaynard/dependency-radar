# Dependency Radar

A Node.js + TypeScript CLI that scans project dependencies with npm audit, npm ls, license-checker, depcheck, and madge, then produces a single self-contained HTML report.

## Setup

```bash
npm install
npm run build
```

## Usage

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

## Scripts

- `npm run build` – compile TypeScript to `dist/`
- `npm run dev` – run a scan from source (`ts-node`)
- `npm run scan` – run a scan from the built output

## Notes

- The tool assumes `node_modules` is available in the target project.
- Each tool writes raw JSON into `.dependency-radar/` before aggregation.
- Sections corresponding to failed tools are marked as unavailable in the report, but the report still generates.
