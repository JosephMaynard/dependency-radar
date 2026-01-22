# Repository Guidelines

## Project Structure & Module Organization
- Source lives in `src/` (CLI in `src/cli.ts`, core aggregation in `src/aggregator.ts`, report rendering in `src/report.ts`, runners in `src/runners/`).
- Build artifacts output to `dist/` via TypeScript; do not edit generated files.
- Temporary scan data is written to `.dependency-radar/` in the target project; the default HTML report is `dependency-radar.html` at the repository root unless overridden.
- Type definitions are colocated in `src/types/` and shared utilities in `src/utils.ts`.

## Build, Test, and Development Commands
- `npm install` – install dependencies.
- `npm run build` – type-check and compile to `dist/`.
- `npm run dev` – run the CLI directly from TypeScript (via `ts-node`) for quick iteration.
- `npm run scan` or `npx dependency-radar scan` – execute the built CLI; accepts flags like `--project ./my-app --out ./reports/dependency-radar.html --keep-temp`.

## Coding Style & Naming Conventions
- Follow existing TypeScript style: 2-space indentation, single quotes, semicolons, and explicit return/parameter types under `strict` mode.
- Use `PascalCase` for types/interfaces/enums, `camelCase` for variables and functions, and descriptive filenames (e.g., `depcheckRunner.ts`).
- Keep modules small and focused; prefer pure functions that accept explicit inputs/outputs.
- Avoid editing `dist/`; adjust `src/` and rebuild instead.

## Testing Guidelines
- No automated test suite exists yet; validate changes by running `npm run build` and a representative `npm run dev -- --project <path>` or `npm run scan` against a sample project.
- When adding tests, co-locate them near the code under `src/` (e.g., `src/runners/__tests__/npmAudit.test.ts`) and mirror file names.
- Aim for meaningful coverage of runners, aggregation, and rendering paths; prefer deterministic fixtures over live network calls.

## Commit & Pull Request Guidelines
- Use clear, imperative commit subjects (e.g., `Add npm audit runner fallback`); group related changes in a single commit when practical.
- Summarize what changed and why in the PR description; link related issues and include before/after notes or sample report paths when UI/output changes.
- Highlight manual verification steps taken (`npm run build`, sample scan command) so reviewers can reproduce.

## Security & Configuration Tips
- Runners rely on project-local `node_modules`; ensure the target project is installed before scanning.
- Temporary files in `.dependency-radar/` may contain dependency metadata; avoid committing them and remove unless debugging with `--keep-temp`.
