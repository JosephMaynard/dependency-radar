#!/usr/bin/env node
import path from 'path';
import { ChildProcess, spawn } from 'child_process';
import { platform } from 'os';
import { aggregateData } from './aggregator';
import { runImportGraph } from './runners/importGraphRunner';
import { runPackageAudit } from './runners/npmAudit';
import { runNpmLs } from './runners/npmLs';
import { runPackageOutdated } from './runners/npmOutdated';
import { renderReport } from './report';
import type { OutdatedEntry, OutdatedResult, ToolResult } from './types';
import fs from 'fs/promises';
import { ensureDir, removeDir, runCommand } from './utils';

// Workspace detection and helpers
type WorkspaceType = 'pnpm' | 'npm' | 'yarn' | 'none';
type PackageManager = 'npm' | 'pnpm' | 'yarn';

interface WorkspaceDiscovery {
  type: WorkspaceType;
  packagePaths: string[]; // absolute paths
}

type OutdatedAttempt = {
  attempted: boolean;
  result?: ToolResult<any>;
};

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

function isCI(): boolean {
  return process.env.CI === 'true' || process.env.CI === 'TRUE' || process.env.CI === '1'
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

async function getToolVersion(tool: string, cwd: string): Promise<string | undefined> {
  try {
    const result = await runCommand(tool, ['--version'], { cwd });
    const raw = (result.stdout || '').trim();
    if (!raw) return undefined;
    return raw.split(/\s+/)[0];
  } catch {
    return undefined;
  }
}

function compactToolVersions(versions: Record<string, string | undefined>): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(versions)) {
    if (value) out[key] = value;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

async function detectWorkspace(projectPath: string): Promise<WorkspaceDiscovery> {
  const rootPkgPath = path.join(projectPath, 'package.json');
  const rootPkg = await readJsonFile(rootPkgPath);
  const inferredManager = inferPackageManager(rootPkg);

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
    type = inferredManager || 'npm';
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

function inferPackageManager(rootPkg: any): PackageManager | undefined {
  const raw = typeof rootPkg?.packageManager === 'string' ? rootPkg.packageManager.trim() : '';
  if (!raw) return undefined;
  if (raw.startsWith('pnpm@') || raw === 'pnpm') return 'pnpm';
  if (raw.startsWith('yarn@') || raw === 'yarn') return 'yarn';
  if (raw.startsWith('npm@') || raw === 'npm') return 'npm';
  return undefined;
}

async function detectPackageManager(projectPath: string, rootPkg: any, workspaceType: WorkspaceType): Promise<PackageManager> {
  const inferred = inferPackageManager(rootPkg);
  if (inferred) return inferred;
  if (workspaceType === 'pnpm' || workspaceType === 'yarn') return workspaceType;
  const yarnrc = path.join(projectPath, '.yarnrc.yml');
  if (await pathExists(yarnrc)) {
    const y = await fs.readFile(yarnrc, 'utf8');
    if (/nodeLinker\s*:\s*pnp/.test(y)) {
      return 'yarn';
    }
  }
  if (await pathExists(path.join(projectPath, 'node_modules', '.pnpm'))) return 'pnpm';
  if (await pathExists(path.join(projectPath, 'node_modules', '.yarn-state.yml'))) return 'yarn';
  return 'npm';
}

async function detectScanManager(projectPath: string, fallback: PackageManager): Promise<PackageManager> {
  if (await pathExists(path.join(projectPath, 'pnpm-lock.yaml'))) return 'pnpm';
  if (await pathExists(path.join(projectPath, 'yarn.lock'))) return 'yarn';
  if (
    await pathExists(path.join(projectPath, 'package-lock.json')) ||
    await pathExists(path.join(projectPath, 'npm-shrinkwrap.json'))
  ) {
    return 'npm';
  }
  if (await pathExists(path.join(projectPath, 'node_modules', '.pnpm'))) return 'pnpm';
  if (await pathExists(path.join(projectPath, 'node_modules', '.yarn-state.yml'))) return 'yarn';
  return fallback;
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
  const merged: any = { dependencies: {}, devDependencies: {}, optionalDependencies: {} };
  for (const entry of pkgs) {
    const deps = entry.pkg?.dependencies || {};
    const dev = entry.pkg?.devDependencies || {};
    const opt = entry.pkg?.optionalDependencies || {};
    Object.assign(merged.dependencies, deps);
    Object.assign(merged.devDependencies, dev);
    Object.assign(merged.optionalDependencies, opt);
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

function collectDeclaredDeps(pkg: any): string[] {
  const out = new Set<string>();
  const sections = [
    pkg?.dependencies,
    pkg?.devDependencies,
    pkg?.optionalDependencies,
    pkg?.peerDependencies
  ];
  for (const deps of sections) {
    if (deps && typeof deps === 'object') {
      Object.keys(deps).forEach((name) => out.add(name));
    }
  }
  return Array.from(out);
}

function parseOutdatedData(data: any, unknownNames: Set<string>): OutdatedEntry[] {
  const entries: OutdatedEntry[] = [];
  if (!data || typeof data !== 'object') return entries;
  if (Array.isArray(data)) {
    for (const entry of data) {
      if (!entry || typeof entry !== 'object') continue;
      const name = typeof entry.name === 'string' ? entry.name : undefined;
      const current = typeof entry.current === 'string' ? entry.current : '';
      const latest = typeof entry.latest === 'string' ? entry.latest : undefined;
      const type = typeof entry.type === 'string' ? entry.type.toLowerCase() : '';
      if (!name || !current) continue;
      let status: 'patch' | 'minor' | 'major' | 'unknown' | 'current' = 'unknown';
      if (type === 'patch' || type === 'minor' || type === 'major') {
        status = type;
      } else if (latest) {
        status = classifyOutdated(current, latest);
      }
      if (status === 'current') continue;
      if (status === 'major' || status === 'minor' || status === 'patch') {
        entries.push({ name, currentVersion: current, status, latestVersion: latest });
        continue;
      }
      entries.push({ name, currentVersion: current, status: 'unknown' });
    }
    return entries;
  }
  for (const [name, info] of Object.entries<any>(data)) {
    if (!info || typeof info !== 'object') {
      unknownNames.add(name);
      continue;
    }
    const current = typeof info.current === 'string' ? info.current : '';
    const latest = typeof info.latest === 'string' ? info.latest : undefined;
    const type = typeof info.type === 'string' ? info.type.toLowerCase() : '';
    if (!current) {
      unknownNames.add(name);
      continue;
    }
    let status: 'patch' | 'minor' | 'major' | 'unknown' | 'current' = 'unknown';
    if (type === 'patch' || type === 'minor' || type === 'major') {
      status = type;
    } else if (latest) {
      status = classifyOutdated(current, latest);
    }

    if (status === 'current') continue;
    if (status === 'major' || status === 'minor' || status === 'patch') {
      if (latest) {
        entries.push({ name, currentVersion: current, status, latestVersion: latest });
      } else {
        entries.push({ name, currentVersion: current, status: 'unknown' });
      }
      continue;
    }
    entries.push({ name, currentVersion: current, status: 'unknown' });
  }
  return entries;
}

function parseSimpleVersion(value: string): { major: number; minor: number; patch: number } | undefined {
  if (!value || typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.includes('-') || trimmed.includes('+')) return undefined;
  const match = trimmed.match(/^v?(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return undefined;
  const major = Number.parseInt(match[1], 10);
  const minor = Number.parseInt(match[2], 10);
  const patch = Number.parseInt(match[3], 10);
  if ([major, minor, patch].some((n) => Number.isNaN(n))) return undefined;
  return { major, minor, patch };
}

function classifyOutdated(
  current: string,
  latest: string
): 'major' | 'minor' | 'patch' | 'current' | 'unknown' {
  const currentVer = parseSimpleVersion(current);
  const latestVer = parseSimpleVersion(latest);
  if (!currentVer || !latestVer) return 'unknown';
  if (currentVer.major !== latestVer.major) return 'major';
  if (currentVer.minor !== latestVer.minor) return 'minor';
  if (currentVer.patch !== latestVer.patch) return 'patch';
  return 'current';
}

function mergeOutdatedResults(results: OutdatedAttempt[]): OutdatedResult | undefined {
  const entries: OutdatedEntry[] = [];
  const unknownNames = new Set<string>();

  for (let i = 0; i < results.length; i++) {
    const attempt = results[i];
    if (!attempt.attempted) continue;
    const result = attempt.result;
    if (!result || !result.ok || !result.data || typeof result.data !== 'object') {
      continue;
    }
    entries.push(...parseOutdatedData(result.data, unknownNames));
  }

  if (entries.length === 0 && unknownNames.size === 0) {
    return undefined;
  }

  const merged = new Map<string, OutdatedEntry>();
  for (const entry of entries) {
    const key = `${entry.name}@${entry.currentVersion}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, entry);
      continue;
    }
    if (existing.status !== entry.status || existing.latestVersion !== entry.latestVersion) {
      merged.set(key, { name: entry.name, currentVersion: entry.currentVersion, status: 'unknown' });
    }
  }

  return {
    entries: Array.from(merged.values()),
    unknownNames: Array.from(unknownNames)
  };
}

function mergeImportGraphs(rootPath: string, packageMetas: Array<{ path: string; name: string }>, graphs: Array<any | undefined>): any {
  const files: Record<string, string[]> = {};
  const packages: Record<string, string[]> = {};
  const packageCounts: Record<string, Record<string, number>> = {};
  const unresolvedImports: Array<{ importer: string; specifier: string }> = [];

  for (let i = 0; i < graphs.length; i++) {
    const g = graphs[i];
    const meta = packageMetas[i];
    if (!g || typeof g !== 'object') continue;
    const relBase = path.relative(rootPath, meta.path).split(path.sep).join('/');
    const prefix = relBase ? `${relBase}/` : '';

    const gf = g.files || {};
    const gp = g.packages || {};
    const gc = g.packageCounts || {};
    for (const [k, v] of Object.entries<any>(gf)) {
      files[`${prefix}${k}`] = Array.isArray(v) ? v.map((x) => `${prefix}${x}`) : [];
    }
    for (const [k, v] of Object.entries<any>(gp)) {
      packages[`${prefix}${k}`] = Array.isArray(v) ? v : [];
    }
    for (const [k, v] of Object.entries<any>(gc)) {
      if (!v || typeof v !== 'object') continue;
      const next: Record<string, number> = {};
      for (const [dep, count] of Object.entries<any>(v)) {
        if (typeof count === 'number') next[dep] = count;
      }
      packageCounts[`${prefix}${k}`] = next;
    }
    const unresolved = Array.isArray(g.unresolvedImports) ? g.unresolvedImports : [];
    unresolved.forEach((u: any) => {
      if (u && typeof u.importer === 'string' && typeof u.specifier === 'string') {
        unresolvedImports.push({ importer: `${prefix}${u.importer}`, specifier: u.specifier });
      }
    });
  }

  return { files, packages, packageCounts, unresolvedImports };
}

function buildWorkspaceUsageMap(packageMetas: Array<{ name: string; pkg: any }>, dependencyGraphs: Array<any | undefined>): Map<string, string[]> {
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
    const opt = meta.pkg?.optionalDependencies || {};
    const peer = meta.pkg?.peerDependencies || {};
    Object.keys(deps).forEach((d) => {
      add(d, pkgName);
    });
    Object.keys(dev).forEach((d) => {
      add(d, pkgName);
    });
    Object.keys(opt).forEach((d) => {
      add(d, pkgName);
    });
    Object.keys(peer).forEach((d) => {
      add(d, pkgName);
    });
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

  for (let i = 0; i < dependencyGraphs.length; i++) {
    const data = dependencyGraphs[i];
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

function buildCombinedDependencyGraph(rootPath: string, packageMetas: Array<{ path: string; name: string; pkg: any }>, dependencyGraphs: Array<any | undefined>): any {
  // Build a synthetic root with each workspace package as a top-level node.
  // This avoids object-key collisions for normal packages and preserves per-package roots.
  const dependencies: Record<string, any> = {};

  for (let i = 0; i < dependencyGraphs.length; i++) {
    const data = dependencyGraphs[i];
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
  audit: boolean;
  outdated: boolean;
  json: boolean;
  open: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    command: 'scan',
    project: process.cwd(),
    out: 'dependency-radar.html',
    keepTemp: false,
    audit: true,
    outdated: true,
    json: false,
    open: false
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
    else if (arg === '--offline') {
      opts.audit = false;
      opts.outdated = false;
    }
    else if (arg === '--json') opts.json = true;
    else if (arg === '--open') opts.open = true;
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
  --offline          Skip npm audit and npm outdated (useful for offline scans)
  --open             Open the generated report using the system default application
`);
}

function openInBrowser(filePath: string): void {
  const normalizedPath = filePath.replace(/\\/g, '/');
  let child: ChildProcess;

  switch (platform()) {
    case 'darwin':
      child = spawn('open', [normalizedPath], { stdio: 'ignore', shell: false, detached: true });
      break;
    case 'win32':
      child = spawn('cmd', ['/c', 'start', '', normalizedPath], { stdio: 'ignore', shell: false, detached: true });
      break;
    default:
      child = spawn('xdg-open', [normalizedPath], { stdio: 'ignore', shell: false, detached: true });
      break;
  }

  child.on('error', (err) => {
    console.warn('Could not open report:', err.message);
  });
  child.unref();
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
  const rootPkg = await readJsonFile(path.join(projectPath, 'package.json'));
  const packageManager = await detectPackageManager(projectPath, rootPkg, workspace.type);
  const scanManager = await detectScanManager(projectPath, packageManager);
  const packageManagerField = typeof rootPkg?.packageManager === 'string'
    ? rootPkg.packageManager.trim()
    : undefined;
  const [npmVersion, pnpmVersion, yarnVersion] = await Promise.all([
    getToolVersion('npm', projectPath),
    getToolVersion('pnpm', projectPath),
    getToolVersion('yarn', projectPath)
  ]);
  const toolVersions = compactToolVersions({
    npm: npmVersion,
    pnpm: pnpmVersion,
    yarn: yarnVersion
  });
  const packageManagerVersion = scanManager === 'npm'
    ? npmVersion
    : scanManager === 'pnpm'
      ? pnpmVersion
      : yarnVersion;
  if (packageManager === 'yarn') {
    const yarnrc = path.join(projectPath, '.yarnrc.yml');
    if (await pathExists(yarnrc)) {
      const y = await fs.readFile(yarnrc, 'utf8');
      if (/nodeLinker\s*:\s*pnp/.test(y)) {
        console.error('Yarn Plug\'n\'Play (nodeLinker: pnp) detected. This is not supported yet.');
        console.error('Switch to nodeLinker: node-modules or run in a non-PnP environment.');
        process.exit(1);
        return;
      }
    }
  }

  const packagePaths = workspace.packagePaths;
  const workspaceLabel = workspace.type === 'none' ? 'Single project' : `${workspace.type.toUpperCase()} workspace`;
  console.log(`✔ ${workspaceLabel} detected`);
  if (workspace.type !== 'none' && scanManager !== workspace.type) {
    console.log(`✔ Using ${scanManager.toUpperCase()} for dependency data (lockfile detected)`);
  }
  const spinner = startSpinner(`Scanning ${workspaceLabel} at ${projectPath}`);
  try {
    await ensureDir(tempDir);

    // Run tools per package for best coverage.
    const packageMetas = await readWorkspacePackageMeta(projectPath, packagePaths);

    const perPackageAudit: Array<ToolResult<any> | undefined> = [];
    const perPackageLs: Array<ToolResult<any>> = [];
    const perPackageImportGraph: Array<ToolResult<any>> = [];
    const perPackageOutdated: OutdatedAttempt[] = [];

    for (const meta of packageMetas) {
      spinner.update(`Scanning ${workspaceLabel} (${perPackageLs.length + 1}/${packageMetas.length}) at ${projectPath}`);
      const pkgTempDir = path.join(tempDir, meta.name.replace(/[^a-zA-Z0-9._-]/g, '_'));
      await ensureDir(pkgTempDir);
      const [a, l, ig, o] = await Promise.all([
        opts.audit ? runPackageAudit(meta.path, pkgTempDir, scanManager, yarnVersion).catch((err) => ({ ok: false, error: String(err) } as ToolResult<any>)) : Promise.resolve(undefined),
        runNpmLs(meta.path, pkgTempDir, scanManager).catch((err) => ({ ok: false, error: String(err) } as ToolResult<any>)),
        runImportGraph(meta.path, pkgTempDir).catch((err) => ({ ok: false, error: String(err) } as ToolResult<any>)),
        opts.outdated
          ? runPackageOutdated(meta.path, pkgTempDir, scanManager).catch((err) => ({ ok: false, error: String(err) } as ToolResult<any>))
          : Promise.resolve(undefined)
      ]);
      perPackageAudit.push(a);
      perPackageLs.push(l);
      perPackageImportGraph.push(ig);
      perPackageOutdated.push({ attempted: Boolean(opts.outdated), result: o });
    }

    if (opts.audit) {
      const auditOk = perPackageAudit.every((r) => r && r.ok);
      if (auditOk) {
        spinner.log(`✔ ${scanManager.toUpperCase()} audit data collected`);
      } else {
        spinner.log(`✖ ${scanManager.toUpperCase()} audit data unavailable`);
      }
    }
    if (opts.outdated) {
      const outdatedOk = perPackageOutdated.every((r) => r.result && r.result.ok);
      if (outdatedOk) {
        spinner.log(`✔ ${scanManager.toUpperCase()} outdated data collected`);
      } else {
        spinner.log(`✖ ${scanManager.toUpperCase()} outdated data unavailable`);
      }
    }

    const mergedAuditData = mergeAuditResults(perPackageAudit.map((r) => (r && r.ok ? r.data : undefined)));
    const mergedGraphData = workspace.type === 'none'
      ? (perPackageLs[0] && perPackageLs[0].ok ? perPackageLs[0].data : undefined)
      : buildCombinedDependencyGraph(projectPath, packageMetas, perPackageLs.map((r) => (r && r.ok ? r.data : undefined)));
    const mergedImportGraphData = mergeImportGraphs(projectPath, packageMetas, perPackageImportGraph.map((r) => (r && r.ok ? r.data : undefined)));
    const workspaceUsage = buildWorkspaceUsageMap(packageMetas, perPackageLs.map((r) => (r && r.ok ? r.data : undefined)));
    const outdatedResult = mergeOutdatedResults(perPackageOutdated);

    const auditResult = mergedAuditData ? { ok: true, data: mergedAuditData } : undefined;
    const npmLsResult = { ok: true, data: mergedGraphData };
    const importGraphResult = { ok: true, data: mergedImportGraphData };

    // Build a merged package.json view for aggregator direct-dep checks.
    const mergedPkgForAggregator = mergeDepsFromWorkspace(packageMetas);

    const auditFailure = opts.audit ? perPackageAudit.find((r) => r && !r.ok) : undefined;
    const lsFailure = perPackageLs.find((r) => r && !r.ok);
    const importFailure = perPackageImportGraph.find((r) => r && !r.ok);
    if (auditFailure) {
      spinner.log(`Audit warning: ${auditFailure.error || 'Audit failed'}`);
    }
    if (lsFailure || importFailure) {
      const err = lsFailure || importFailure;
      throw new Error(err?.error || 'Tool execution failed');
    }

    const aggregated = await aggregateData({
      projectPath,
      auditResult,
      npmLsResult,
      importGraphResult,
      outdatedResult,
      pkgOverride: mergedPkgForAggregator,
      workspaceUsage,
      resolvePaths: [projectPath, ...packagePaths.filter((p) => p !== projectPath)],
      workspaceEnabled: workspace.type !== 'none',
      workspaceType: workspace.type,
      workspacePackageCount: packagePaths.length,
      packageManager: scanManager,
      packageManagerVersion,
      packageManagerField,
      platform: process.platform,
      arch: process.arch,
      ci: isCI(),
      ...(toolVersions ? { toolVersions } : {})
    });
    dependencyCount = Object.keys(aggregated.dependencies).length;

    if (workspace.type !== 'none') {
      console.log(`Detected ${workspace.type.toUpperCase()} workspace with ${packagePaths.length} package${packagePaths.length === 1 ? '' : 's'}.`);
    }

    if (opts.json) {
      await fs.mkdir(path.dirname(outputPath), { recursive: true });
      await fs.writeFile(outputPath, JSON.stringify(aggregated, null, 2), 'utf8');
    } else {
      await renderReport(aggregated, outputPath);
    }
    spinner.stop(true);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`✔ Scan complete: ${dependencyCount} dependencies analysed in ${elapsed}s`);
    console.log(`✔ ${opts.json ? 'JSON' : 'Report'} written to ${outputPath}`);
  } catch (err: any) {
    spinner.stop(false);
    console.error('Failed to generate report:', err);
    process.exit(1);
  } finally {
    if (!opts.keepTemp) {
      await removeDir(tempDir);
    } else {
      console.log(`✔ Temporary data kept at ${tempDir}`);
    }
  }

  if (opts.open && !isCI()) {
    console.log(`↗ Opening ${path.basename(outputPath)} using system default ${opts.json ? 'application' : 'browser'}.`);
    openInBrowser(outputPath);
  } else if (opts.open && isCI()) {
    console.log('✖ Skipping auto-open in CI environment.');
  }
  
  // Always show CTA as the last output
  console.log('');
  console.log('Get additional risk analysis and a management-ready summary at https://dependency-radar.com');
}



run();

function startSpinner(text: string): { stop: (success?: boolean) => void; update: (nextText: string) => void; log: (line: string) => void } {
  const frames = ['|', '/', '-', '\\'];
  let i = 0;
  let currentText = text;
  process.stdout.write(`${frames[i]} ${currentText}`);
  const timer = setInterval(() => {
    i = (i + 1) % frames.length;
    process.stdout.write(`\r\x1b[K${frames[i]} ${currentText}`);
  }, 120);

  let stopped = false;

  const stop = (success = true) => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    process.stdout.write(`\r\x1b[K${success ? '✔' : '✖'} ${currentText}\n`);
  };

  const update = (nextText: string) => {
    if (stopped) return;
    currentText = nextText;
    process.stdout.write(`\r\x1b[K${frames[i]} ${currentText}`);
  };

  const log = (line: string) => {
    if (stopped) {
      process.stdout.write(`${line}\n`);
      return;
    }
    process.stdout.write(`\r\x1b[K${line}\n`);
    process.stdout.write(`${frames[i]} ${currentText}`);
  };

  return { stop, update, log };
}
