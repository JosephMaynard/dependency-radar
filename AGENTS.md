# Dependency Radar Agent Notes

- Runtime dependencies must stay empty. `npx dependency-radar` must not install any dependencies.
- `devDependencies` are allowed.
- Dependencies used only to build report assets are allowed only if compiled/bundled into shipped JS so users do not install them at runtime.
- Edit `src/`; never edit generated files in `dist/`.
- Key files: `src/cli.ts`, `src/aggregator.ts`, `src/report.ts`, `src/runners/`, `src/types.ts`, `src/utils.ts`, `src/httpClient.ts`, `src/maintenanceCache.ts`.
- The report UI lives in `report-ui/`; its header/filter markup is duplicated in `src/report.ts` and the two must be kept in sync. `npm run build:report` regenerates `src/report-assets.ts`.
- Scan temp output is written to `.dependency-radar/` in the target project.
- Default report output is `dependency-radar.html` at the repo root.
