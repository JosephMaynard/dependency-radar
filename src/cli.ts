#!/usr/bin/env node
import path from 'path';
import { aggregateData } from './aggregator';
import { runImportGraph } from './runners/importGraphRunner';
import { runNpmAudit } from './runners/npmAudit';
import { runNpmLs } from './runners/npmLs';
import { renderReport } from './report';
import fs from 'fs/promises';
import { ensureDir, removeDir } from './utils';

// Workspace detection and helpers
type WorkspaceType = 'pnpm' | 'npm' | 'yarn' | 'none';

interface WorkspaceDiscovery {
  type: WorkspaceType;
  packagePaths: string[]; // absolute paths
}

async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.stat(target);
    return true;
  } catch {
    return false;
  }
}

function normalizeSlashes(p: string): string {
  return p.split(path.sep).join('/');
}

async function listDirs(parent: string): Promise<string[]> {
  const entries = await fs.readdir(parent, { withFileTypes: true }).catch(() => [] as any);
  return (entries as any[])
    .filter((e: any) => e?.isDirectory?.())
    .map((e: any) => path.join(parent, e.name));
}

async function expandWorkspacePattern(root: string, pattern: string): Promise<string[]> {
  // Minimal glob support for common workspaces:
  // - "packages/*", "apps/*"
  // - "packages/**" (recursive)
  // - "./packages/*" (leading ./)
  const cleaned = pattern.trim().replace(/^[.][/\\]/, '');
  if (!cleaned) return [];

  // Disallow node_modules and hidden by default
  const parts = cleaned.split(/[/\\]/g).filter(Boolean);
  const isRecursive = parts.includes('**');

  // Find the segment containing * or **
  const starIndex = parts.findIndex((p) => p === '*' || p === '**');

  if (starIndex === -1) {
    const abs = path.resolve(root, cleaned);
    return (await pathExists(abs)) ? [abs] : [];
  }

  const baseParts = parts.slice(0, starIndex);
  const baseDir = path.resolve(root, baseParts.join(path.sep));
  if (!(await pathExists(baseDir))) return [];

  if (parts[starIndex] === '*' && starIndex === parts.length - 1) {
    // one-level children
    return await listDirs(baseDir);
  }

  if (parts[starIndex] === '**') {
    // recursive directories under base
    const out: string[] = [];
    async function walk(dir: string): Promise<void> {
      const children = await listDirs(dir);
      for (const child of children) {
        if (path.basename(child) === 'node_modules') continue;
        if (path.basename(child).startsWith('.')) continue;
        out.push(child);
        await walk(child);
      }
    }
    await walk(baseDir);
    return out;
  }

  // Fallback: treat as one-level
  return await listDirs(baseDir);
}

async function readJsonFile(filePath: string): Promise<any | undefined> {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

async function detectWorkspace(projectPath: string): Promise<WorkspaceDiscovery> {
  const rootPkgPath = path.join(projectPath, 'package.json');
  const rootPkg = await readJsonFile(rootPkgPath);

  const pnpmWorkspacePath = path.join(projectPath, 'pnpm-workspace.yaml');
  const hasPnpmWorkspace = await pathExists(pnpmWorkspacePath);

  let type: WorkspaceType = 'none';
  let patterns: string[] = [];

  if (hasPnpmWorkspace) {
    type = 'pnpm';
    // very small YAML parser for the only thing we care about: `packages:` list.
    const yaml = await fs.readFile(pnpmWorkspacePath, 'utf8');
    const lines = yaml.split(/\r?\n/);
    let inPackages = false;
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (/^packages\s*:\s*$/.test(trimmed)) {
        inPackages = true;
        continue;
      }
      if (inPackages) {
        // stop when we hit a new top-level key
        if (/^[A-Za-z0-9_-]+\s*:/.test(trimmed) && !trimmed.startsWith('-')) {
          inPackages = false;
          continue;
        }
        const m = trimmed.match(/^[-]\s*["']?([^"']+)["']?\s*$/);
        if (m && m[1]) patterns.push(m[1].trim());
      }
    }
  }

  // npm/yarn workspaces
  if (type === 'none' && rootPkg && rootPkg.workspaces) {
    type = 'npm';
    if (Array.isArray(rootPkg.workspaces)) patterns = rootPkg.workspaces;
    else if (Array.isArray(rootPkg.workspaces.packages)) patterns = rootPkg.workspaces.packages;

    // try to detect yarn berry pnp (unsupported) later via .yarnrc.yml
    const yarnrc = path.join(projectPath, '.yarnrc.yml');
    if (await pathExists(yarnrc)) {
      const y = await fs.readFile(yarnrc, 'utf8');
      if (/nodeLinker\s*:\s*pnp/.test(y)) {
        return { type: 'yarn', packagePaths: [] };
      }
    }
  }

  if (type === 'none') {
    return { type: 'none', packagePaths: [projectPath] };
  }

  // Expand patterns and keep only folders that contain package.json
  const candidates: string[] = [];
  for (const pat of patterns) {
    const expanded = await expandWorkspacePattern(projectPath, pat);
    candidates.push(...expanded);
  }

  const unique = Array.from(new Set(candidates.map((p) => path.resolve(p))))
    .filter((p) => !normalizeSlashes(p).includes('/node_modules/'));

  const packagePaths: string[] = [];
  for (const dir of unique) {
    const pkgJson = path.join(dir, 'package.json');
    if (await pathExists(pkgJson)) packagePaths.push(dir);
  }

  // Always include root if it contains a name (some repos keep a root package)
  if (await pathExists(path.join(projectPath, 'package.json'))) {
    // root may already be in the list; keep unique
    if (!packagePaths.includes(projectPath)) {
      // Only include root as a scanned package if it looks like a real package
      const root = await readJsonFile(path.join(projectPath, 'package.json'));
      if (root && typeof root.name === 'string' && root.name.trim().length > 0) {
        packagePaths.push(projectPath);
      }
    }
  }

  return { type, packagePaths: packagePaths.sort() };
}

async function readWorkspacePackageMeta(rootPath: string, packagePaths: string[]): Promise<Array<{ path: string; name: string; pkg: any }>> {
  const out: Array<{ path: string; name: string; pkg: any }> = [];
  for (const p of packagePaths) {
    const pkg = await readJsonFile(path.join(p, 'package.json'));
    const name = (pkg && typeof pkg.name === 'string' && pkg.name.trim()) ? pkg.name.trim() : path.basename(p);
    out.push({ path: p, name, pkg: pkg || {} });
  }
  return out;
}

function mergeDepsFromWorkspace(pkgs: Array<{ pkg: any }>): any {
  const merged: any = { dependencies: {}, devDependencies: {} };
  for (const entry of pkgs) {
    const deps = entry.pkg?.dependencies || {};
    const dev = entry.pkg?.devDependencies || {};
    Object.assign(merged.dependencies, deps);
    Object.assign(merged.devDependencies, dev);
  }
  return merged;
}

function mergeAuditResults(results: Array<any | undefined>): any | undefined {
  const defined = results.filter(Boolean);
  if (defined.length === 0) return undefined;
  const base: any = {};
  for (const r of defined) {
    if (!r || typeof r !== 'object') continue;
    // npm audit v7+ shape: { vulnerabilities: {..} }
    if (r.vulnerabilities && typeof r.vulnerabilities === 'object') {
      base.vulnerabilities = base.vulnerabilities || {};
      for (const [k, v] of Object.entries<any>(r.vulnerabilities)) {
        if (!base.vulnerabilities[k]) base.vulnerabilities[k] = v;
        else {
          // merge counts best-effort
          const existing = base.vulnerabilities[k];
          base.vulnerabilities[k] = { ...existing, ...v };
        }
      }
    }
    // legacy shape
    if (r.advisories && typeof r.advisories === 'object') {
      base.advisories = base.advisories || {};
      Object.assign(base.advisories, r.advisories);
    }
    // keep metadata if present
    if (r.metadata && !base.metadata) base.metadata = r.metadata;
  }
  return base;
}

function mergeImportGraphs(rootPath: string, packageMetas: Array<{ path: string; name: string }>, graphs: Array<any | undefined>): any {
  const files: Record<string, string[]> = {};
  const packages: Record<string, string[]> = {};
  const unresolvedImports: Array<{ importer: string; specifier: string }> = [];

  for (let i = 0; i < graphs.length; i++) {
    const g = graphs[i];
    const meta = packageMetas[i];
    if (!g || typeof g !== 'object') continue;
    const relBase = path.relative(rootPath, meta.path).split(path.sep).join('/');
    const prefix = relBase ? `${relBase}/` : '';

    const gf = g.files || {};
    const gp = g.packages || {};
    for (const [k, v] of Object.entries<any>(gf)) {
      files[`${prefix}${k}`] = Array.isArray(v) ? v.map((x) => `${prefix}${x}`) : [];
    }
    for (const [k, v] of Object.entries<any>(gp)) {
      packages[`${prefix}${k}`] = Array.isArray(v) ? v : [];
    }
    const unresolved = Array.isArray(g.unresolvedImports) ? g.unresolvedImports : [];
    unresolved.forEach((u: any) => {
      if (u && typeof u.importer === 'string' && typeof u.specifier === 'string') {
        unresolvedImports.push({ importer: `${prefix}${u.importer}`, specifier: u.specifier });
      }
    });
  }

  return { files, packages, unresolvedImports };
}

function buildWorkspaceUsageMap(packageMetas: Array<{ name: string; pkg: any }>, npmLsDatas: Array<any | undefined>): Map<string, string[]> {
  const usage = new Map<string, Set<string>>();

  const add = (depName: string, pkgName: string) => {
    if (!depName) return;
    if (!usage.has(depName)) usage.set(depName, new Set());
    usage.get(depName)!.add(pkgName);
  };

  // From declared deps
  for (const meta of packageMetas) {
    const pkgName = meta.name;
    const deps = meta.pkg?.dependencies || {};
    const dev = meta.pkg?.devDependencies || {};
    Object.keys(deps).forEach((d) => add(d, pkgName));
    Object.keys(dev).forEach((d) => add(d, pkgName));
  }

  // From npm ls trees (transitives)
  const walk = (node: any, pkgName: string): void => {
    if (!node || typeof node !== 'object') return;
    const name = node.name;
    if (typeof name === 'string') add(name, pkgName);
    const deps = node.dependencies;
    if (deps && typeof deps === 'object') {
      for (const [depName, child] of Object.entries<any>(deps)) {
        add(depName, pkgName);
        walk(child, pkgName);
      }
    }
  };

  for (let i = 0; i < npmLsDatas.length; i++) {
    const data = npmLsDatas[i];
    const meta = packageMetas[i];
    if (!data || typeof data !== 'object') continue;
    const deps = data.dependencies;
    if (deps && typeof deps === 'object') {
      for (const [depName, child] of Object.entries<any>(deps)) {
        add(depName, meta.name);
        walk(child, meta.name);
      }
    }
  }

  const out = new Map<string, string[]>();
  for (const [k, set] of usage.entries()) {
    out.set(k, Array.from(set).sort());
  }
  return out;
}

function buildCombinedNpmLs(rootPath: string, packageMetas: Array<{ path: string; name: string; pkg: any }>, npmLsDatas: Array<any | undefined>): any {
  // Build a synthetic root with each workspace package as a top-level node.
  // This avoids object-key collisions for normal packages and preserves per-package roots.
  const dependencies: Record<string, any> = {};

  for (let i = 0; i < npmLsDatas.length; i++) {
    const data = npmLsDatas[i];
    const meta = packageMetas[i];
    if (!meta) continue;
    const version = typeof meta.pkg?.version === 'string' ? meta.pkg.version : 'workspace';
    const nodeDeps = (data && typeof data === 'object' && data.dependencies && typeof data.dependencies === 'object')
      ? data.dependencies
      : {};

    dependencies[meta.name] = {
      name: meta.name,
      version,
      dependencies: nodeDeps
    };
  }

  return { name: 'dependency-radar-workspace', version: '0.0.0', dependencies };
}

interface CliOptions {
  command: 'scan';
  project: string;
  out: string;
  keepTemp: boolean;
  maintenance: boolean;
  audit: boolean;
  json: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    command: 'scan',
    project: process.cwd(),
    out: 'dependency-radar.html',
    keepTemp: false,
    maintenance: false,
    audit: true,
    json: false
  };

  const args = [...argv];
  if (args[0] && !args[0].startsWith('-')) {
    opts.command = args.shift() as 'scan';
  }

  while (args.length) {
    const arg = args.shift();
    if (!arg) break;
    if (arg === '--project' && args[0]) opts.project = args.shift()!;
    else if (arg === '--out' && args[0]) opts.out = args.shift()!;
    else if (arg === '--keep-temp') opts.keepTemp = true;
    else if (arg === '--maintenance') opts.maintenance = true;
    else if (arg === '--no-audit') opts.audit = false;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }

  return opts;
}

function printHelp(): void {
  console.log(`dependency-radar [scan] [options]

If no command is provided, \`scan\` is run by default.

Options:
  --project <path>   Project folder (default: cwd)
  --out <path>       Output HTML file (default: dependency-radar.html)
  --json             Write aggregated data to JSON (default filename: dependency-radar.json)
  --keep-temp        Keep .dependency-radar folder
  --maintenance      Enable slow maintenance checks (npm registry calls)
  --no-audit         Skip npm audit (useful for offline scans)
`);
}

async function run(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.command !== 'scan') {
    printHelp();
    process.exit(1);
    return;
  }

  const projectPath = path.resolve(opts.project);
  if (opts.json && opts.out === 'dependency-radar.html') {
    opts.out = 'dependency-radar.json';
  }
  let outputPath = path.resolve(opts.out);
  const startTime = Date.now();
  let dependencyCount = 0;
  try {
    const stat = await fs.stat(outputPath).catch(() => undefined);
    const endsWithSeparator = opts.out.endsWith('/') || opts.out.endsWith('\\');
    const hasExtension = Boolean(path.extname(outputPath));
    if ((stat && stat.isDirectory()) || endsWithSeparator || (!stat && !hasExtension)) {
      outputPath = path.join(outputPath, opts.json ? 'dependency-radar.json' : 'dependency-radar.html');
    }
  } catch (e) {
    // ignore, best-effort path normalization
  }
  const tempDir = path.join(projectPath, '.dependency-radar');

  // Workspace detection and reporting
  const workspace = await detectWorkspace(projectPath);
  if (workspace.type === 'yarn' && workspace.packagePaths.length === 0) {
    console.error('Yarn Plug\'n\'Play (nodeLinker: pnp) detected. This is not supported yet.');
    console.error('Switch to nodeLinker: node-modules or run in a non-PnP environment.');
    process.exit(1);
    return;
  }

  const packagePaths = workspace.packagePaths;
  const workspaceLabel = workspace.type === 'none' ? 'Single project' : `${workspace.type.toUpperCase()} workspace`;
  const stopSpinner = startSpinner(`Scanning ${workspaceLabel} at ${projectPath}`);
  try {
    await ensureDir(tempDir);

    // Run tools per package for best coverage.
    const packageMetas = await readWorkspacePackageMeta(projectPath, packagePaths);

    const perPackageAudit: Array<any | undefined> = [];
    const perPackageLs: Array<any | undefined> = [];
    const perPackageImportGraph: Array<any | undefined> = [];

    for (const meta of packageMetas) {
      const pkgTempDir = path.join(tempDir, meta.name.replace(/[^a-zA-Z0-9._-]/g, '_'));
      await ensureDir(pkgTempDir);
      const [a, l, ig] = await Promise.all([
        opts.audit ? runNpmAudit(meta.path, pkgTempDir).then(r => (r && r.ok ? r.data : undefined)).catch(() => undefined) : Promise.resolve(undefined),
        runNpmLs(meta.path, pkgTempDir).then(r => (r && r.ok ? r.data : undefined)).catch(() => undefined),
        runImportGraph(meta.path, pkgTempDir).then(r => (r && r.ok ? r.data : undefined)).catch(() => undefined)
      ]);
      perPackageAudit.push(a);
      perPackageLs.push(l);
      perPackageImportGraph.push(ig);
    }

    const mergedAuditData = mergeAuditResults(perPackageAudit);
    const mergedLsData = buildCombinedNpmLs(projectPath, packageMetas, perPackageLs);
    const mergedImportGraphData = mergeImportGraphs(projectPath, packageMetas, perPackageImportGraph);

    const workspaceUsage = buildWorkspaceUsageMap(packageMetas, perPackageLs);

    const auditResult = mergedAuditData ? { ok: true, data: mergedAuditData } : undefined;
    const npmLsResult = { ok: true, data: mergedLsData };
    const importGraphResult = { ok: true, data: mergedImportGraphData };

    // Build a merged package.json view for aggregator direct-dep checks.
    const mergedPkgForAggregator = mergeDepsFromWorkspace(packageMetas);

    if (opts.maintenance) {
      stopSpinner(true);
      console.log('Running maintenance checks (slow mode)');
      console.log('This may take several minutes depending on dependency count.');
    }

    const aggregated = await aggregateData({
      projectPath,
      maintenanceEnabled: opts.maintenance,
      onMaintenanceProgress: opts.maintenance
        ? (current, total, name) => {
            process.stdout.write(`\r[${current}/${total}] ${name}                      `);
          }
        : undefined,
      auditResult,
      npmLsResult,
      importGraphResult,
      pkgOverride: mergedPkgForAggregator,
      workspaceUsage,
    });
    dependencyCount = aggregated.dependencies.length;

    if (workspace.type !== 'none') {
      console.log(`Detected ${workspace.type.toUpperCase()} workspace with ${packagePaths.length} package${packagePaths.length === 1 ? '' : 's'}.`);
    }

    if (opts.maintenance) {
      process.stdout.write('\n');
    }

    if (opts.json) {
      await fs.mkdir(path.dirname(outputPath), { recursive: true });
      await fs.writeFile(outputPath, JSON.stringify(aggregated, null, 2), 'utf8');
    } else {
      await renderReport(aggregated, outputPath);
    }
    stopSpinner(true);
    console.log(`${opts.json ? 'JSON' : 'Report'} written to ${outputPath}`);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`Scan complete: ${dependencyCount} dependencies analysed in ${elapsed}s`);
  } catch (err: any) {
    stopSpinner(false);
    console.error('Failed to generate report:', err);
    process.exit(1);
  } finally {
    if (!opts.keepTemp) {
      await removeDir(tempDir);
    } else {
      console.log(`Temporary data kept at ${tempDir}`);
    }
  }
  
  // Always show CTA as the last output
  console.log('');
  console.log('Get additional risk analysis and a management-ready summary at https://dependency-radar.com');
}



run();

function startSpinner(text: string): (success?: boolean) => void {
  const frames = ['|', '/', '-', '\\'];
  let i = 0;
  process.stdout.write(`${frames[i]} ${text}`);
  const timer = setInterval(() => {
    i = (i + 1) % frames.length;
    process.stdout.write(`\r${frames[i]} ${text}`);
  }, 120);

  let stopped = false;

  return (success = true) => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    process.stdout.write(`\r${success ? '✔' : '✖'} ${text}\n`);
  };
}
