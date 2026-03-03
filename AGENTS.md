# Dependency Radar Agent Notes

- Runtime dependencies must stay empty. `npx dependency-radar` must not install any dependencies.
- `devDependencies` are allowed.
- Dependencies used only to build report assets are allowed only if compiled/bundled into shipped JS so users do not install them at runtime.
- Edit `src/`; never edit generated files in `dist/`.
- Key files: `src/cli.ts`, `src/aggregator.ts`, `src/report.ts`, `src/runners/`, `src/types/`, `src/utils.ts`.
- Scan temp output is written to `.dependency-radar/` in the target project.
- Default report output is `dependency-radar.html` at the repo root.
