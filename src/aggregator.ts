import {
  AggregatedData,
  DependencyRecord,
  ImportAnalysisSummary,
  ImportGraphInfo,
  MaintenanceInfo,
  PackageLinks,
  RawOutputs,
  Severity,
  ToolResult,
  UsageInfo,
  VulnerabilitySummary
} from './types';
import {
  licenseRiskLevel,
  maintenanceRisk,
  readPackageJson,
  readLicenseFromPackageJson,
  runCommand,
  delay,
  vulnRiskLevel,
  getDependencyRadarVersion
} from './utils';
import fs from 'fs/promises';
import path from 'path';

interface AggregateInput {
  projectPath: string;
  maintenanceEnabled: boolean;
  onMaintenanceProgress?: (current: number, total: number, name: string) => void;
  auditResult?: ToolResult<any>;
  npmLsResult?: ToolResult<any>;
  importGraphResult?: ToolResult<any>;
  // Optional: allow CLI to pass a merged view of workspace package.json dependencies
  pkgOverride?: any;
  // Map dependency name -> workspace package names where it is used/declared
  workspaceUsage?: Map<string, string[]>;
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

/**
 * Normalize repository URLs to browsable HTTPS format.
 * Handles: git+https://, git://, github:user/repo, git@github.com:user/repo.git
 */
function normalizeRepoUrl(url: string): string {
  if (!url) return url;
  
  // Handle shorthand: github:user/repo or user/repo
  if (url.match(/^(github:|gitlab:|bitbucket:)?[\w-]+\/[\w.-]+$/)) {
    const cleaned = url.replace(/^(github:|gitlab:|bitbucket:)/, '');
    const host = url.startsWith('gitlab:') ? 'gitlab.com' 
               : url.startsWith('bitbucket:') ? 'bitbucket.org' 
               : 'github.com';
    return `https://${host}/${cleaned}`;
  }
  
  // Handle git+https:// or git:// prefix
  let normalized = url.replace(/^git\+/, '').replace(/^git:\/\//, 'https://');
  
  // Handle git@host:user/repo.git SSH format
  normalized = normalized.replace(/^git@([^:]+):(.+)$/, 'https://$1/$2');
  
  // Remove .git suffix
  normalized = normalized.replace(/\.git$/, '');
  
  return normalized;
}

export async function aggregateData(input: AggregateInput): Promise<AggregatedData> {
  const pkg = input.pkgOverride || (await readPackageJson(input.projectPath));
  const raw: RawOutputs = {
    audit: input.auditResult?.data,
    npmLs: input.npmLsResult?.data,
    importGraph: input.importGraphResult?.data
  };

  const toolErrors: Record<string, string> = {};
  if (input.auditResult && !input.auditResult.ok) toolErrors['npm-audit'] = input.auditResult.error || 'unknown error';
  if (input.npmLsResult && !input.npmLsResult.ok) toolErrors['npm-ls'] = input.npmLsResult.error || 'unknown error';
  if (input.importGraphResult && !input.importGraphResult.ok) toolErrors['import-graph'] = input.importGraphResult.error || 'unknown error';

  // Get git branch
  const gitBranch = await getGitBranch(input.projectPath);

  const nodeMap = buildNodeMap(input.npmLsResult?.data, pkg);
  const vulnMap = parseVulnerabilities(input.auditResult?.data);
  const importGraph = normalizeImportGraph(input.importGraphResult?.data);
  const importInfo = buildImportInfo(importGraph.files);
  const importAnalysis = buildImportAnalysis(importGraph, pkg);
  const packageUsageCounts = new Map(Object.entries(importAnalysis.packageHotness));
  const maintenanceCache = new Map<string, MaintenanceInfo>();
  const runtimeCache = new Map<string, { classification: RuntimeClass; reason: string }>();
  const packageMetaCache = new Map<string, PackageMeta>();
  const packageStatCache = new Map<string, PackageStats>();

  const dependencies: DependencyRecord[] = [];
  const licenseCache = new Map<string, { license?: string; licenseFile?: string }>();
  const nodeEngineRanges: string[] = [];

  const nodes = Array.from(nodeMap.values());
  const totalDeps = nodes.length;
  let maintenanceIndex = 0;

  for (const node of nodes) {
    const direct = isDirectDependency(node.name, pkg);
    const cachedLicense = licenseCache.get(node.name);
    const license = cachedLicense ||
      (await readLicenseFromPackageJson(node.name, input.projectPath)) ||
      { license: undefined };
    if (!licenseCache.has(node.name) && (license.license || license.licenseFile)) {
      licenseCache.set(node.name, license);
    }
    const vulnerabilities = vulnMap.get(node.name) || emptyVulnSummary();
    const licenseRisk = licenseRiskLevel(license.license);
    const vulnRisk = vulnRiskLevel(vulnerabilities.counts);
    const usage = buildUsageInfo(node.name, packageUsageCounts, pkg);
    const maintenance = await resolveMaintenance(
      node.name,
      maintenanceCache,
      input.maintenanceEnabled,
      ++maintenanceIndex,
      totalDeps,
      input.onMaintenanceProgress
    );
    if (!maintenanceCache.has(node.name)) {
      maintenanceCache.set(node.name, maintenance);
    }

    const maintenanceRiskLevel = maintenanceRisk(maintenance.lastPublished);
    const runtimeData = classifyRuntime(node.key, pkg, nodeMap, runtimeCache);
    
    // Calculate root causes (direct dependencies that cause this to be installed)
    const rootCauses = findRootCauses(node, nodeMap, pkg);
    
    // Build dependedOnBy and dependsOn lists
    const dependedOnBy = Array.from(node.parents).map(key => {
      const parent = nodeMap.get(key);
      return parent ? parent.name : key.split('@')[0];
    });
    const dependsOn = Array.from(node.children).map(key => {
      const child = nodeMap.get(key);
      return child ? child.name : key.split('@')[0];
    });
    
    const packageInsights = await gatherPackageInsights(
      node.name,
      input.projectPath,
      packageMetaCache,
      packageStatCache,
      node.parents.size,
      node.children.size,
      dependedOnBy,
      dependsOn
    );
    if (packageInsights.identity.nodeEngine) {
      nodeEngineRanges.push(packageInsights.identity.nodeEngine);
    }

    dependencies.push({
      name: node.name,
      version: node.version,
      key: node.key,
      direct,
      transitive: !direct,
      depth: node.depth,
      parents: Array.from(node.parents),
      rootCauses,
      license,
      licenseRisk,
      vulnerabilities,
      vulnRisk,
      maintenance,
      maintenanceRisk: maintenanceRiskLevel,
      usage,
      identity: packageInsights.identity,
      dependencySurface: packageInsights.dependencySurface,
      sizeFootprint: packageInsights.sizeFootprint,
      buildPlatform: packageInsights.buildPlatform,
      moduleSystem: packageInsights.moduleSystem,
      typescript: packageInsights.typescript,
      graph: packageInsights.graph,
      links: packageInsights.links,
      importInfo,
      runtimeClass: runtimeData.classification,
      runtimeReason: runtimeData.reason,
      outdated: { status: 'unknown' },
      raw: {
        workspacePackages: input.workspaceUsage?.get(node.name) || []
      }
    });

  }

  dependencies.sort((a, b) => a.name.localeCompare(b.name));
  const runtimeVersion = process.version.replace(/^v/, '');
  const runtimeMajor = Number.parseInt(runtimeVersion.split('.')[0], 10);
  const minRequiredMajor = deriveMinRequiredMajor(nodeEngineRanges);

  return {
    generatedAt: new Date().toISOString(),
    projectPath: input.projectPath,
    dependencyRadarVersion,
    gitBranch,
    maintenanceEnabled: input.maintenanceEnabled,
    environment: {
      node: {
        runtimeVersion,
        runtimeMajor: Number.isNaN(runtimeMajor) ? 0 : runtimeMajor,
        minRequiredMajor,
        source: minRequiredMajor === undefined ? 'unknown' : 'dependency-engines'
      }
    },
    dependencies,
    toolErrors,
    raw,
    importAnalysis
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
          entry.items.push({
            title: vul.title || item.title || vul.name || name,
            severity: sev,
            url: vul.url,
            vulnerableRange: vul.range,
            fixAvailable: item.fixAvailable,
            paths: item.nodes
          });
          entry.counts[sev] = (entry.counts[sev] || 0) + 0; // already counted above
        });
      entry.highestSeverity = computeHighestSeverity(entry.counts);
    });
  }

  if (auditData.advisories) {
    Object.values<any>(auditData.advisories).forEach((adv: any) => {
      const name = adv.module_name || adv.module || 'unknown';
      const severity: Severity = normalizeSeverity(adv.severity);
      const entry = ensureEntry(name);
      entry.items.push({
        title: adv.title,
        severity,
        url: adv.url,
        vulnerableRange: adv.vulnerable_versions,
        fixAvailable: adv.fix_available,
        paths: (adv.findings || []).flatMap((f: any) => f.paths || [])
      });
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
    items: [],
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
  files: Record<string, string[]>;
  packages: Record<string, string[]>;
  unresolvedImports: Array<{ importer: string; specifier: string }>;
}

function normalizeImportGraph(data: any): ImportGraphData {
  if (data && typeof data === 'object' && data.files && data.packages) {
    return {
      files: data.files || {},
      packages: data.packages || {},
      unresolvedImports: Array.isArray(data.unresolvedImports) ? data.unresolvedImports : []
    };
  }
  return { files: data || {}, packages: {}, unresolvedImports: [] };
}

function buildUsageInfo(
  name: string,
  packageUsageCounts: Map<string, number>,
  pkg: any
): UsageInfo {
  const declared = Boolean((pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name]));
  const importedCount = packageUsageCounts.get(name) || 0;
  if (importedCount > 0) {
    if (declared) {
      return {
        status: 'imported',
        reason: `Imported by ${importedCount} file${importedCount === 1 ? '' : 's'} (static analysis)`
      };
    }
    return {
      status: 'undeclared',
      reason: 'Imported but not declared (may rely on transitive resolution; pnpm will usually break this)'
    };
  }
  if (declared) {
    return {
      status: 'not-imported',
      reason: 'Declared but never statically imported (may be used via tooling, scripts, or runtime plugins)'
    };
  }
  return {
    status: 'unknown',
    reason: 'Not statically imported; package is likely transitive or used dynamically'
  };
}

function buildImportAnalysis(graph: ImportGraphData, pkg: any): ImportAnalysisSummary {
  const packageImporters = new Map<string, Set<string>>();

  Object.entries(graph.packages || {}).forEach(([file, packages]) => {
    const unique = new Set(packages || []);
    unique.forEach((pkgName) => {
      if (!packageImporters.has(pkgName)) packageImporters.set(pkgName, new Set<string>());
      packageImporters.get(pkgName)!.add(file);
    });
  });

  const packageHotness: Record<string, number> = {};
  packageImporters.forEach((importers, name) => {
    packageHotness[name] = importers.size;
  });

  const declared = new Set<string>([
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.devDependencies || {})
  ]);
  const undeclaredImports = Array.from(packageImporters.keys())
    .filter((name) => !declared.has(name))
    .sort();

  return {
    staticOnly: true,
    notes: [
      'Import analysis is static only.',
      'Dynamic imports, runtime plugin loading, and tooling usage are not evaluated.'
    ],
    packageHotness,
    undeclaredImports,
    unresolvedImports: graph.unresolvedImports || []
  };
}

function buildImportInfo(graphData: any): ImportGraphInfo | undefined {
  if (!graphData || typeof graphData !== 'object') return undefined;
  const fanIn: Record<string, number> = {};
  const fanOut: Record<string, number> = {};
  Object.entries<any>(graphData).forEach(([file, deps]) => {
    fanOut[file] = Array.isArray(deps) ? deps.length : 0;
    (deps || []).forEach((dep: string) => {
      fanIn[dep] = (fanIn[dep] || 0) + 1;
    });
  });
  return { files: graphData, fanIn, fanOut };
}

function isDirectDependency(name: string, pkg: any): boolean {
  return Boolean((pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name]));
}

async function resolveMaintenance(
  name: string,
  cache: Map<string, MaintenanceInfo>,
  maintenanceEnabled: boolean,
  current: number,
  total: number,
  onProgress?: (current: number, total: number, name: string) => void
): Promise<MaintenanceInfo> {
  if (cache.has(name)) return cache.get(name)!;
  if (!maintenanceEnabled) {
    return { status: 'unknown', reason: 'maintenance checks disabled' } as MaintenanceInfo;
  }
  onProgress?.(current, total, name);
  try {
    await delay(1000);
    const res = await runCommand('npm', ['view', name, 'time', '--json']);
    const json = JSON.parse(res.stdout || '{}');
    const timestamps = Object.values<string>(json || {}).filter((v) => typeof v === 'string');
    const lastPublished = timestamps.sort().pop();
    if (lastPublished) {
      const risk = maintenanceRisk(lastPublished);
      const status: MaintenanceInfo['status'] = risk === 'green' ? 'active' : risk === 'amber' ? 'quiet' : risk === 'red' ? 'stale' : 'unknown';
      return { lastPublished, status, reason: 'npm view time' };
    }
    return { status: 'unknown', reason: 'npm view returned no data' } as MaintenanceInfo;
  } catch (err: any) {
    return { status: 'unknown', reason: 'lookup failed' } as MaintenanceInfo;
  }
}

type RuntimeClass = 'runtime' | 'build-time' | 'dev-only';

function classifyRuntime(
  nodeKey: string,
  pkg: any,
  map: Map<string, NodeInfo>,
  cache: Map<string, { classification: RuntimeClass; reason: string }>
): { classification: RuntimeClass; reason: string } {
  const cached = cache.get(nodeKey);
  if (cached) return cached;

  const node = map.get(nodeKey);
  if (!node) {
    const fallback = { classification: 'build-time' as RuntimeClass, reason: 'Unknown node in dependency graph' };
    cache.set(nodeKey, fallback);
    return fallback;
  }

  if (pkg.dependencies && pkg.dependencies[node.name]) {
    const result = { classification: 'runtime' as RuntimeClass, reason: 'Declared in dependencies' };
    cache.set(nodeKey, result);
    return result;
  }
  if (pkg.devDependencies && pkg.devDependencies[node.name]) {
    const result = { classification: 'dev-only' as RuntimeClass, reason: 'Declared in devDependencies' };
    cache.set(nodeKey, result);
    return result;
  }

  // Memoized recursion to inherit runtime class from parents; conservative for cycles.
  const parentClasses: RuntimeClass[] = [];
  const inProgress = cache.get(`__visiting__${nodeKey}`);
  if (inProgress) {
    const cycleFallback = { classification: 'build-time' as RuntimeClass, reason: 'Dependency cycle; defaulting to build-time' };
    cache.set(nodeKey, cycleFallback);
    return cycleFallback;
  }
  cache.set(`__visiting__${nodeKey}`, { classification: 'build-time', reason: 'visiting' });

  for (const parentKey of node.parents) {
    const parent = map.get(parentKey);
    if (!parent) continue;
    const parentClass = classifyRuntime(parentKey, pkg, map, cache).classification;
    parentClasses.push(parentClass);
  }

  cache.delete(`__visiting__${nodeKey}`);

  let result: { classification: RuntimeClass; reason: string };
  if (parentClasses.includes('runtime')) {
    result = { classification: 'runtime', reason: 'Transitive of runtime dependency' };
  } else if (parentClasses.includes('build-time')) {
    result = { classification: 'build-time', reason: 'Transitive of build-time dependency' };
  } else {
    result = { classification: 'dev-only', reason: 'Transitive of dev-only dependency' };
  }

  cache.set(nodeKey, result);
  return result;
}

interface PackageMeta {
  pkg: any;
  dir: string;
}

interface PackageStats {
  size: number;
  files: number;
  hasDts: boolean;
  hasNativeBinary: boolean;
  hasBindingGyp: boolean;
}

interface PackageInsights {
  identity: DependencyRecord['identity'];
  dependencySurface: DependencyRecord['dependencySurface'];
  sizeFootprint: DependencyRecord['sizeFootprint'];
  buildPlatform: DependencyRecord['buildPlatform'];
  moduleSystem: DependencyRecord['moduleSystem'];
  typescript: DependencyRecord['typescript'];
  graph: DependencyRecord['graph'];
  links: PackageLinks;
}

async function gatherPackageInsights(
  name: string,
  projectPath: string,
  metaCache: Map<string, PackageMeta>,
  statCache: Map<string, PackageStats>,
  fanIn: number,
  fanOut: number,
  dependedOnBy: string[],
  dependsOn: string[]
): Promise<PackageInsights> {
  const meta = await loadPackageMeta(name, projectPath, metaCache);
  const pkg = meta?.pkg || {};
  const dir = meta?.dir;
  const stats = dir ? await calculatePackageStats(dir, statCache) : undefined;

  const dependencySurface = {
    dependencies: Object.keys(pkg.dependencies || {}).length,
    devDependencies: Object.keys(pkg.devDependencies || {}).length,
    peerDependencies: Object.keys(pkg.peerDependencies || {}).length,
    optionalDependencies: Object.keys(pkg.optionalDependencies || {}).length,
    hasPeerDependencies: Object.keys(pkg.peerDependencies || {}).length > 0
  };

  const scripts = pkg.scripts || {};
  const identity = {
    deprecated: Boolean(pkg.deprecated),
    nodeEngine: typeof pkg.engines?.node === 'string' ? pkg.engines.node : null,
    hasRepository: Boolean(pkg.repository),
    hasFunding: Boolean(pkg.funding)
  };

  const moduleSystem = determineModuleSystem(pkg);
  const typescript = determineTypes(pkg, stats?.hasDts || false);
  const buildPlatform = {
    nativeBindings: Boolean(stats?.hasNativeBinary || stats?.hasBindingGyp || scriptsContainNativeBuild(scripts)),
    installScripts: hasInstallScripts(scripts)
  };

  const sizeFootprint = {
    installedSize: stats?.size || 0,
    fileCount: stats?.files || 0
  };

  const graph = {
    fanIn,
    fanOut,
    dependedOnBy,
    dependsOn
  };

  // Extract package links
  const links: PackageLinks = {
    npm: `https://www.npmjs.com/package/${name}`
  };
  
  // Repository can be string or object with url
  if (pkg.repository) {
    if (typeof pkg.repository === 'string') {
      links.repository = normalizeRepoUrl(pkg.repository);
    } else if (pkg.repository.url) {
      links.repository = normalizeRepoUrl(pkg.repository.url);
    }
  }
  
  // Bugs can be string or object with url
  if (pkg.bugs) {
    if (typeof pkg.bugs === 'string') {
      links.bugs = pkg.bugs;
    } else if (pkg.bugs.url) {
      links.bugs = pkg.bugs.url;
    }
  }
  
  // Homepage is a simple string
  if (pkg.homepage && typeof pkg.homepage === 'string') {
    links.homepage = pkg.homepage;
  }

  return {
    identity,
    dependencySurface,
    sizeFootprint,
    buildPlatform,
    moduleSystem,
    typescript,
    graph,
    links
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

async function calculatePackageStats(dir: string, cache: Map<string, PackageStats>): Promise<PackageStats> {
  if (cache.has(dir)) return cache.get(dir)!;
  let size = 0;
  let files = 0;
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
        const stat = await fs.stat(full);
        size += stat.size;
        files += 1;
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
  const result: PackageStats = { size, files, hasDts, hasNativeBinary, hasBindingGyp };
  cache.set(dir, result);
  return result;
}

function determineModuleSystem(pkg: any): DependencyRecord['moduleSystem'] {
  const typeField = pkg.type;
  const hasModuleField = Boolean(pkg.module);
  const hasExports = pkg.exports !== undefined;
  const conditionalExports = typeof pkg.exports === 'object' && pkg.exports !== null;

  let format: DependencyRecord['moduleSystem']['format'] = 'unknown';
  if (typeField === 'module') format = 'esm';
  else if (typeField === 'commonjs') format = 'commonjs';
  else if (hasModuleField || hasExports) format = 'dual';
  else format = 'commonjs';

  return { format, conditionalExports };
}

function determineTypes(pkg: any, hasDts: boolean): DependencyRecord['typescript'] {
  const hasBundled = Boolean(pkg.types || pkg.typings || hasDts);
  return { types: hasBundled ? 'bundled' : 'none' };
}

function scriptsContainNativeBuild(scripts: Record<string, any>): boolean {
  return (Object.values(scripts || {}) as any[]).some((cmd) => typeof cmd === 'string' && /node-?gyp|node-pre-gyp/.test(cmd));
}

function hasInstallScripts(scripts: Record<string, any>): boolean {
  return ['preinstall', 'install', 'postinstall'].some((key) => typeof scripts?.[key] === 'string' && scripts[key].trim().length > 0);
}
