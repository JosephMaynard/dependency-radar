import {
  AggregatedData,
  DependencyObject,
  Severity,
  ToolResult,
  VulnerabilitySummary
} from './types';
import {
  licenseRiskLevel,
  readPackageJson,
  readLicenseFromPackageJson,
  runCommand,
  vulnRiskLevel,
  getDependencyRadarVersion
} from './utils';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

interface AggregateInput {
  projectPath: string;
  auditResult?: ToolResult<any>;
  npmLsResult?: ToolResult<any>;
  importGraphResult?: ToolResult<any>;
  // Optional: allow CLI to pass a merged view of workspace package.json dependencies
  pkgOverride?: any;
  // Map dependency name -> workspace package names where it is used/declared
  workspaceUsage?: Map<string, string[]>;
  workspaceEnabled: boolean;
}

interface NodeInfo {
  name: string;
  version: string;
  key: string;
  depth: number;
  parents: Set<string>;
  children: Set<string>;
  dev?: boolean;
}

const dependencyRadarVersion = getDependencyRadarVersion();

async function getGitBranch(projectPath: string): Promise<string | undefined> {
  try {
    const result = await runCommand('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: projectPath });
    const branch = result.stdout?.trim();
    // HEAD means detached state
    if (!branch || branch === 'HEAD') {
      return undefined;
    }
    return branch;
  } catch {
    return undefined;
  }
}


function findRootCauses(node: NodeInfo, nodeMap: Map<string, NodeInfo>, pkg: any): string[] {
  // If it's a direct dependency, it's its own root cause
  if (isDirectDependency(node.name, pkg)) {
    return [node.name];
  }
  
  // BFS up the parent chain to find all direct dependencies that lead to this
  const rootCauses = new Set<string>();
  const visited = new Set<string>();
  const queue = [...node.parents];
  
  while (queue.length > 0) {
    const parentKey = queue.shift()!;
    if (visited.has(parentKey)) continue;
    visited.add(parentKey);
    
    const parent = nodeMap.get(parentKey);
    if (!parent) continue;
    
    if (isDirectDependency(parent.name, pkg)) {
      rootCauses.add(parent.name);
    } else {
      // Keep going up the chain
      for (const grandparent of parent.parents) {
        if (!visited.has(grandparent)) {
          queue.push(grandparent);
        }
      }
    }
  }
  
  return Array.from(rootCauses).sort();
}

function hashProjectPath(projectPath: string): string {
  return crypto.createHash('sha256').update(projectPath).digest('hex');
}

export async function aggregateData(input: AggregateInput): Promise<AggregatedData> {
  const pkg = input.pkgOverride || (await readPackageJson(input.projectPath));

  // Get git branch
  const gitBranch = await getGitBranch(input.projectPath);

  const nodeMap = buildNodeMap(input.npmLsResult?.data, pkg);
  const vulnMap = parseVulnerabilities(input.auditResult?.data);
  const importGraph = normalizeImportGraph(input.importGraphResult?.data);
  const usageResult = buildUsageSummary(importGraph, input.projectPath);
  const packageMetaCache = new Map<string, PackageMeta>();
  const packageStatCache = new Map<string, PackageStats>();

  const dependencies: Record<string, DependencyObject> = {};
  const licenseCache = new Map<string, { license?: string }>();
  const nodeEngineRanges: string[] = [];

  const nodes = Array.from(nodeMap.values());
  let directCount = 0;
  const MAX_TOP_ROOT_PACKAGES = 10; // cap to keep payload size predictable

  for (const node of nodes) {
    const direct = isDirectDependency(node.name, pkg);
    if (direct) directCount += 1;
    const cachedLicense = licenseCache.get(node.name);
    const license = cachedLicense ||
      (await readLicenseFromPackageJson(node.name, input.projectPath)) ||
      { license: undefined };
    if (!licenseCache.has(node.name) && license.license) {
      licenseCache.set(node.name, license);
    }
    const vulnerabilities = vulnMap.get(node.name) || emptyVulnSummary();
    const licenseValue = license.license || 'unknown';
    const licenseRisk = licenseRiskLevel(licenseValue);
    const vulnRisk = vulnRiskLevel(vulnerabilities.counts);
    
    // Calculate root causes (direct dependencies that cause this to be installed)
    const rootCauses = findRootCauses(node, nodeMap, pkg);

    const packageInsights = await gatherPackageInsights(
      node.name,
      input.projectPath,
      packageMetaCache,
      packageStatCache
    );
    if (packageInsights.nodeEngine) {
      nodeEngineRanges.push(packageInsights.nodeEngine);
    }

    const scope = determineScope(node.name, direct, rootCauses, pkg);
    const usage = usageResult.summary.get(node.name);
    const runtimeImpact = usageResult.runtimeImpact.get(node.name);
    const introduction = determineIntroduction(direct, rootCauses, runtimeImpact);
    const origins = buildOrigins(rootCauses, input.workspaceUsage?.get(node.name), input.workspaceEnabled, MAX_TOP_ROOT_PACKAGES);
    const buildRisk = determineBuildRisk(packageInsights.build.native, packageInsights.build.installScripts);
    const id = node.key;
    const upgrade = buildUpgradeBlock(packageInsights);

    dependencies[id] = {
      id,
      name: node.name,
      version: node.version,
      direct,
      scope,
      depth: node.depth,
      origins,
      license: licenseValue,
      licenseRisk,
      vulnerabilities: {
        critical: vulnerabilities.counts.critical,
        high: vulnerabilities.counts.high,
        moderate: vulnerabilities.counts.moderate,
        low: vulnerabilities.counts.low,
        highest: vulnerabilities.highestSeverity
      },
      vulnRisk,
      deprecated: packageInsights.deprecated,
      nodeEngine: packageInsights.nodeEngine,
      build: {
        native: packageInsights.build.native,
        installScripts: packageInsights.build.installScripts,
        risk: buildRisk
      },
      tsTypes: packageInsights.tsTypes,
      dependencySurface: packageInsights.dependencySurface,
      graph: {
        fanIn: node.parents.size,
        fanOut: node.children.size
      },
      links: {
        npm: `https://www.npmjs.com/package/${node.name}`
      },
      ...(usage ? { usage } : {}),
      ...(introduction ? { introduction } : {}),
      ...(runtimeImpact ? { runtimeImpact } : {}),
      ...(upgrade ? { upgrade } : {})
    };

  }

  const minRequiredMajor = deriveMinRequiredMajor(nodeEngineRanges);
  const runtimeVersion = process.version;
  const nodeVersion = process.versions.node;
  const dependencyCount = nodes.length;
  const transitiveCount = dependencyCount - directCount;

  return {
    schemaVersion: '1.0',
    generatedAt: new Date().toISOString(),
    dependencyRadarVersion,
    git: {
      branch: gitBranch || ''
    },
    project: {
      projectDir: input.projectPath,
      projectPathHash: hashProjectPath(input.projectPath)
    },
    environment: {
      nodeVersion,
      runtimeVersion,
      minRequiredMajor: minRequiredMajor ?? 0
    },
    workspaces: {
      enabled: input.workspaceEnabled
    },
    summary: {
      dependencyCount,
      directCount,
      transitiveCount
    },
    dependencies
  };
}

function deriveMinRequiredMajor(engineRanges: string[]): number | undefined {
  let strictest: number | undefined;
  for (const range of engineRanges) {
    const minMajor = parseMinMajorFromRange(range);
    if (minMajor === undefined) continue;
    if (strictest === undefined || minMajor > strictest) {
      strictest = minMajor;
    }
  }
  return strictest;
}

function parseMinMajorFromRange(range: string): number | undefined {
  const normalized = range.trim();
  if (!normalized) return undefined;
  const clauses = normalized.split('||').map((clause) => clause.trim()).filter(Boolean);
  if (clauses.length === 0) return undefined;
  let rangeMin: number | undefined;
  for (const clause of clauses) {
    const clauseMin = parseMinMajorFromClause(clause);
    // Conservative: skip ranges that allow any version in at least one clause.
    if (clauseMin === undefined) return undefined;
    if (rangeMin === undefined || clauseMin < rangeMin) {
      rangeMin = clauseMin;
    }
  }
  return rangeMin;
}

function parseMinMajorFromClause(clause: string): number | undefined {
  const hyphenMatch = clause.match(/(\d+)\s*-\s*\d+/);
  if (hyphenMatch) {
    return Number.parseInt(hyphenMatch[1], 10);
  }
  const tokens = clause.replace(/,/g, ' ').split(/\s+/).filter(Boolean);
  let clauseMin: number | undefined;
  for (const token of tokens) {
    if (token.startsWith('<')) continue;
    const major = parseMajorFromToken(token);
    if (major === undefined) continue;
    if (clauseMin === undefined || major > clauseMin) {
      clauseMin = major;
    }
  }
  return clauseMin;
}

function parseMajorFromToken(token: string): number | undefined {
  const trimmed = token.trim();
  if (!trimmed) return undefined;
  if (!/^[0-9^~=>v]/.test(trimmed)) return undefined;
  const match = trimmed.match(/v?(\d+)/);
  if (!match) return undefined;
  const major = Number.parseInt(match[1], 10);
  return Number.isNaN(major) ? undefined : major;
}

function buildNodeMap(lsData: any, pkg: any): Map<string, NodeInfo> {
  const map = new Map<string, NodeInfo>();

  const traverse = (node: any, depth: number, parentKey?: string, providedName?: string) => {
    const nodeName = node?.name || providedName;
    if (!node || !nodeName) return;
    const version = node.version || 'unknown';
    const key = `${nodeName}@${version}`;
    if (!map.has(key)) {
      map.set(key, {
        name: nodeName,
        version,
        key,
        depth,
        parents: new Set(parentKey ? [parentKey] : []),
        children: new Set<string>(),
        dev: node.dev
      });
    } else {
      const existing = map.get(key)!;
      existing.depth = Math.min(existing.depth, depth);
      if (parentKey) existing.parents.add(parentKey);
      if (existing.dev === undefined && node.dev !== undefined) existing.dev = node.dev;
      if (!existing.children) existing.children = new Set<string>();
    }
    if (node.dependencies && typeof node.dependencies === 'object') {
      Object.entries<any>(node.dependencies).forEach(([depName, child]: [string, any]) => {
        const childVersion = child?.version || 'unknown';
        const childKey = `${depName}@${childVersion}`;
        const current = map.get(key);
        if (current) {
          current.children.add(childKey);
        }
        traverse(child, depth + 1, key, depName);
      });
    }
  };

  if (lsData && lsData.dependencies) {
    Object.entries<any>(lsData.dependencies).forEach(([depName, child]: [string, any]) => traverse(child, 1, undefined, depName));
  } else {
    const deps = Object.keys(pkg.dependencies || {});
    const devDeps = Object.keys(pkg.devDependencies || {});
    deps.forEach((name) => {
      const version = pkg.dependencies[name];
      const key = `${name}@${version}`;
      map.set(key, { name, version, key, depth: 1, parents: new Set(), children: new Set(), dev: false });
    });
    devDeps.forEach((name) => {
      const version = pkg.devDependencies[name];
      const key = `${name}@${version}`;
      map.set(key, { name, version, key, depth: 1, parents: new Set(), children: new Set(), dev: true });
    });
  }

  return map;
}

function parseVulnerabilities(auditData: any): Map<string, VulnerabilitySummary> {
  const map = new Map<string, VulnerabilitySummary>();
  if (!auditData) return map;

  const ensureEntry = (name: string) => {
    if (!map.has(name)) {
      map.set(name, emptyVulnSummary());
    }
    return map.get(name)!;
  };

  if (auditData.vulnerabilities) {
    Object.values<any>(auditData.vulnerabilities).forEach((item: any) => {
      const name = item.name || 'unknown';
      const severity: Severity = normalizeSeverity(item.severity);
      const entry = ensureEntry(name);
      entry.counts[severity] = (entry.counts[severity] || 0) + 1;
      const viaList = Array.isArray(item.via) ? item.via : [];
      viaList
        .filter((v: any) => typeof v === 'object')
        .forEach((vul: any) => {
          const sev: Severity = normalizeSeverity(vul.severity) || severity;
          entry.counts[sev] = (entry.counts[sev] || 0) + 0;
        });
      entry.highestSeverity = computeHighestSeverity(entry.counts);
    });
  }

  if (auditData.advisories) {
    Object.values<any>(auditData.advisories).forEach((adv: any) => {
      const name = adv.module_name || adv.module || 'unknown';
      const severity: Severity = normalizeSeverity(adv.severity);
      const entry = ensureEntry(name);
      entry.counts[severity] = (entry.counts[severity] || 0) + 1;
      entry.highestSeverity = computeHighestSeverity(entry.counts);
    });
  }

  map.forEach((entry) => {
    entry.highestSeverity = computeHighestSeverity(entry.counts);
  });

  return map;
}

function normalizeSeverity(sev: any): Severity {
  const s = typeof sev === 'string' ? sev.toLowerCase() : 'low';
  if (s === 'moderate') return 'moderate';
  if (s === 'high') return 'high';
  if (s === 'critical') return 'critical';
  return 'low';
}

function emptyVulnSummary(): VulnerabilitySummary {
  return {
    counts: { low: 0, moderate: 0, high: 0, critical: 0 },
    highestSeverity: 'none'
  };
}

function computeHighestSeverity(counts: Record<Severity, number>): Severity | 'none' {
  if (counts.critical > 0) return 'critical';
  if (counts.high > 0) return 'high';
  if (counts.moderate > 0) return 'moderate';
  if (counts.low > 0) return 'low';
  return 'none';
}

interface ImportGraphData {
  packages: Record<string, string[]>;
  packageCounts?: Record<string, Record<string, number>>;
}

function normalizeImportGraph(data: any): ImportGraphData {
  if (data && typeof data === 'object' && data.packages) {
    return {
      packages: data.packages || {},
      packageCounts: data.packageCounts || {}
    };
  }
  return { packages: {} };
}

function normalizeImportPath(file: string, projectPath: string): string | undefined {
  if (!file || typeof file !== 'string') return undefined;
  if (file.includes('node_modules')) return undefined;
  let relativePath = file;
  if (path.isAbsolute(file)) {
    relativePath = path.relative(projectPath, file);
  }
  if (!relativePath) return undefined;
  const trimmed = relativePath.replace(/^[.][\\/]/, '');
  const normalized = trimmed.replace(/\\/g, '/');
  if (!normalized || normalized.startsWith('..')) return undefined;
  if (normalized.includes('node_modules')) return undefined;
  return normalized;
}

interface UsageSummary {
  fileCount: number;
  topFiles: string[];
}

interface UsageBuildResult {
  summary: Map<string, UsageSummary>;
  runtimeImpact: Map<string, DependencyObject['runtimeImpact']>;
}

function buildUsageSummary(graph: ImportGraphData, projectPath: string): UsageBuildResult {
  const summary = new Map<string, UsageSummary>();
  const runtimeImpact = new Map<string, DependencyObject['runtimeImpact']>();
  const byDep = new Map<string, Map<string, number>>();
  const packages = graph.packages || {};

  for (const [file, deps] of Object.entries(packages)) {
    if (!Array.isArray(deps) || deps.length === 0) continue;
    const normalizedFile = normalizeImportPath(file, projectPath);
    if (!normalizedFile) continue;
    const counts = graph.packageCounts?.[file] || {};
    const uniqueDeps = new Set(deps.filter((dep) => typeof dep === 'string' && dep));
    for (const dep of uniqueDeps) {
      if (!byDep.has(dep)) byDep.set(dep, new Map<string, number>());
      const fileMap = byDep.get(dep)!;
      const count = typeof counts[dep] === 'number' ? counts[dep] : 1;
      fileMap.set(normalizedFile, count);
    }
  }

  for (const [dep, fileMap] of byDep.entries()) {
    const entries = Array.from(fileMap.entries()).map(([file, count]) => ({
      file,
      count,
      depth: file.split('/').length,
      isTest: isTestFile(file)
    }));
    // Rank: prefer non-test files, then higher import counts, then closer to root.
    entries.sort((a, b) => {
      if (a.isTest !== b.isTest) return a.isTest ? 1 : -1;
      if (b.count !== a.count) return b.count - a.count;
      if (a.depth !== b.depth) return a.depth - b.depth;
      return a.file.localeCompare(b.file);
    });
    summary.set(dep, {
      fileCount: fileMap.size,
      topFiles: entries.slice(0, 5).map((entry) => entry.file)
    });
    runtimeImpact.set(dep, determineRuntimeImpactFromFiles(Array.from(fileMap.keys())));
  }

  return { summary, runtimeImpact };
}

function isDirectDependency(name: string, pkg: any): boolean {
  return Boolean((pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name]));
}

type DependencyScope = 'runtime' | 'dev' | 'optional' | 'peer';

function directScopeFromPackage(name: string, pkg: any): DependencyScope | undefined {
  if (pkg.dependencies && pkg.dependencies[name]) return 'runtime';
  if (pkg.devDependencies && pkg.devDependencies[name]) return 'dev';
  if (pkg.optionalDependencies && pkg.optionalDependencies[name]) return 'optional';
  if (pkg.peerDependencies && pkg.peerDependencies[name]) return 'peer';
  return undefined;
}

function determineScope(name: string, direct: boolean, rootCauses: string[], pkg: any): DependencyScope {
  if (direct) {
    return directScopeFromPackage(name, pkg) || 'runtime';
  }
  const scopes = new Set<DependencyScope>();
  for (const root of rootCauses) {
    const scope = directScopeFromPackage(root, pkg);
    if (scope) scopes.add(scope);
  }
  if (scopes.has('runtime')) return 'runtime';
  if (scopes.has('dev')) return 'dev';
  if (scopes.has('optional')) return 'optional';
  if (scopes.has('peer')) return 'peer';
  return 'runtime';
}

function buildOrigins(
  rootCauses: string[],
  workspaceList: string[] | undefined,
  workspaceEnabled: boolean,
  maxTop: number
): { rootPackageCount: number; topRootPackages: string[]; workspaces?: string[] } {
  const origins: { rootPackageCount: number; topRootPackages: string[]; workspaces?: string[] } = {
    rootPackageCount: rootCauses.length,
    topRootPackages: rootCauses.slice(0, maxTop)
  };
  if (workspaceEnabled && workspaceList && workspaceList.length > 0) {
    origins.workspaces = workspaceList;
  }
  return origins;
}

function determineBuildRisk(hasNative: boolean, hasInstallScripts: boolean): 'green' | 'amber' | 'red' {
  if (hasNative && hasInstallScripts) return 'red';
  if (hasNative || hasInstallScripts) return 'amber';
  return 'green';
}

function isTestFile(file: string): boolean {
  return /(^|\/)(__tests__|__mocks__|test|tests)(\/|$)/.test(file) || /\.(test|spec)\./.test(file);
}

function isToolingFile(file: string): boolean {
  return /(^|\/)(eslint|prettier|stylelint|commitlint|lint-staged|husky)[^\/]*\./.test(file);
}

function isBuildFile(file: string): boolean {
  return /(^|\/)(webpack|rollup|vite|tsconfig|babel|swc|esbuild|parcel|gulpfile|gruntfile|postcss|tailwind)[^\/]*\./.test(file);
}

function determineRuntimeImpactFromFiles(files: string[]): DependencyObject['runtimeImpact'] {
  const categories = new Set<'runtime' | 'build' | 'testing' | 'tooling'>();
  for (const file of files) {
    if (isTestFile(file)) {
      categories.add('testing');
    } else if (isToolingFile(file)) {
      categories.add('tooling');
    } else if (isBuildFile(file)) {
      categories.add('build');
    } else {
      categories.add('runtime');
    }
  }
  if (categories.size === 0) return 'runtime';
  if (categories.size > 1) return 'mixed';
  return Array.from(categories)[0];
}

const TOOLING_PACKAGES = new Set([
  'eslint',
  'prettier',
  'ts-node',
  'typescript',
  'babel',
  '@babel/core',
  'rollup',
  'webpack',
  'vite',
  'parcel',
  'swc',
  '@swc/core',
  'ts-jest',
  'eslint-config-prettier',
  'eslint-plugin-import',
  'lint-staged',
  'husky'
]);

const FRAMEWORK_PACKAGES = new Set([
  'next',
  'react-scripts',
  '@angular/core',
  '@angular/cli',
  'vue',
  'nuxt',
  'svelte',
  '@sveltejs/kit',
  'gatsby',
  'ember-cli',
  'remix',
  'expo'
]);

function isToolingPackage(name: string): boolean {
  if (TOOLING_PACKAGES.has(name)) return true;
  if (name.startsWith('@typescript-eslint/')) return true;
  if (name.startsWith('eslint-')) return true;
  return false;
}

function isFrameworkPackage(name: string): boolean {
  return FRAMEWORK_PACKAGES.has(name);
}

// Heuristic-only classification for why a dependency exists. Kept deterministic and bounded.
function determineIntroduction(
  direct: boolean,
  rootCauses: string[],
  runtimeImpact: DependencyObject['runtimeImpact']
): DependencyObject['introduction'] {
  if (direct) return 'direct';
  if (runtimeImpact === 'testing') return 'testing';
  if (rootCauses.length > 0 && rootCauses.every((root) => isToolingPackage(root))) return 'tooling';
  if (rootCauses.some((root) => isFrameworkPackage(root))) return 'framework';
  if (rootCauses.length > 0) return 'transitive';
  return 'unknown';
}

// Upgrade blockers derived only from local metadata (no external lookups).
function buildUpgradeBlock(
  insights: PackageInsights
): DependencyObject['upgrade'] | undefined {
  const blockers: Array<'nodeEngine' | 'peerDependency' | 'nativeBindings' | 'deprecated'> = [];
  if (insights.nodeEngine) blockers.push('nodeEngine');
  if (insights.dependencySurface.peer > 0) blockers.push('peerDependency');
  if (insights.build.native) blockers.push('nativeBindings');
  if (insights.deprecated) blockers.push('deprecated');

  return {
    blocksNodeMajor: blockers.length > 0,
    blockers
  };
}

interface PackageMeta {
  pkg: any;
  dir: string;
}

interface PackageStats {
  hasDts: boolean;
  hasNativeBinary: boolean;
  hasBindingGyp: boolean;
}

interface PackageInsights {
  deprecated: boolean;
  nodeEngine: string | null;
  dependencySurface: {
    deps: number;
    dev: number;
    peer: number;
    opt: number;
  };
  build: {
    native: boolean;
    installScripts: boolean;
  };
  tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown';
}

async function gatherPackageInsights(
  name: string,
  projectPath: string,
  metaCache: Map<string, PackageMeta>,
  statCache: Map<string, PackageStats>
): Promise<PackageInsights> {
  const meta = await loadPackageMeta(name, projectPath, metaCache);
  if (!meta) {
    return {
      deprecated: false,
      nodeEngine: null,
      dependencySurface: { deps: 0, dev: 0, peer: 0, opt: 0 },
      build: { native: false, installScripts: false },
      tsTypes: 'unknown'
    };
  }
  const pkg = meta?.pkg || {};
  const dir = meta?.dir;
  const stats = dir ? await calculatePackageStats(dir, statCache) : undefined;

  const dependencySurface = {
    deps: Object.keys(pkg.dependencies || {}).length,
    dev: Object.keys(pkg.devDependencies || {}).length,
    peer: Object.keys(pkg.peerDependencies || {}).length,
    opt: Object.keys(pkg.optionalDependencies || {}).length
  };

  const scripts = pkg.scripts || {};
  const deprecated = Boolean(pkg.deprecated);
  const nodeEngine = typeof pkg.engines?.node === 'string' ? pkg.engines.node : null;

  const hasDefinitelyTyped = await hasDefinitelyTypedPackage(name, projectPath, metaCache);
  const tsTypes = determineTypes(pkg, stats?.hasDts || false, hasDefinitelyTyped);
  const build = {
    native: Boolean(stats?.hasNativeBinary || stats?.hasBindingGyp || scriptsContainNativeBuild(scripts)),
    installScripts: hasInstallScripts(scripts)
  };

  return {
    deprecated,
    nodeEngine,
    dependencySurface,
    build,
    tsTypes
  };
}

async function loadPackageMeta(
  name: string,
  projectPath: string,
  cache: Map<string, PackageMeta>
): Promise<PackageMeta | undefined> {
  if (cache.has(name)) return cache.get(name);
  try {
    const pkgJsonPath = require.resolve(path.join(name, 'package.json'), { paths: [projectPath] });
    const pkgRaw = await fs.readFile(pkgJsonPath, 'utf8');
    const pkg = JSON.parse(pkgRaw);
    const meta = { pkg, dir: path.dirname(pkgJsonPath) };
    cache.set(name, meta);
    return meta;
  } catch (err) {
    return undefined;
  }
}

function toDefinitelyTypedPackageName(name: string): string | undefined {
  if (name.startsWith('@types/')) return name;
  if (name.startsWith('@')) {
    const scoped = name.slice(1).split('/');
    if (scoped.length < 2) return undefined;
    return `@types/${scoped[0]}__${scoped[1]}`;
  }
  return `@types/${name}`;
}

async function hasDefinitelyTypedPackage(
  name: string,
  projectPath: string,
  cache: Map<string, PackageMeta>
): Promise<boolean> {
  if (name.startsWith('@types/')) return true;
  const typesName = toDefinitelyTypedPackageName(name);
  if (!typesName) return false;
  const meta = await loadPackageMeta(typesName, projectPath, cache);
  return Boolean(meta);
}

async function calculatePackageStats(dir: string, cache: Map<string, PackageStats>): Promise<PackageStats> {
  if (cache.has(dir)) return cache.get(dir)!;
  let hasDts = false;
  let hasNativeBinary = false;
  let hasBindingGyp = false;

  async function walk(current: string): Promise<void> {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        if (entry.name.endsWith('.d.ts')) hasDts = true;
        if (entry.name.endsWith('.node')) hasNativeBinary = true;
        if (entry.name === 'binding.gyp') hasBindingGyp = true;
      }
    }
  }

  try {
    await walk(dir);
  } catch (err) {
    // best-effort; ignore inaccessible paths
  }
  const result: PackageStats = { hasDts, hasNativeBinary, hasBindingGyp };
  cache.set(dir, result);
  return result;
}

function determineTypes(
  pkg: any,
  hasDts: boolean,
  hasDefinitelyTyped: boolean
): 'bundled' | 'definitelyTyped' | 'none' {
  const hasBundled = Boolean(pkg.types || pkg.typings || hasDts);
  if (hasBundled) return 'bundled';
  if (hasDefinitelyTyped) return 'definitelyTyped';
  return 'none';
}

function scriptsContainNativeBuild(scripts: Record<string, any>): boolean {
  return (Object.values(scripts || {}) as any[]).some((cmd) => typeof cmd === 'string' && /node-?gyp|node-pre-gyp/.test(cmd));
}

function hasInstallScripts(scripts: Record<string, any>): boolean {
  return ['preinstall', 'install', 'postinstall'].some((key) => typeof scripts?.[key] === 'string' && scripts[key].trim().length > 0);
}
