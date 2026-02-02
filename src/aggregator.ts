import {
  AggregatedData,
  DependencyRecord,
  ExecutionHook,
  ExecutionSignal,
  OutdatedResult,
  OutdatedStatus,
  Severity,
  ToolResult,
  VulnerabilityAdvisory,
  VulnerabilitySummary
} from './types';
import {
  licenseRiskLevel,
  readPackageJson,
  readLicenseFromPackageJson,
  runCommand,
  vulnRiskLevel,
  getDependencyRadarVersion,
  resolvePackageJsonPath
} from './utils';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';

interface AggregateInput {
  projectPath: string;
  auditResult?: ToolResult<any>;
  npmLsResult?: ToolResult<any>;
  importGraphResult?: ToolResult<any>;
  outdatedResult?: OutdatedResult;
  // Optional: allow CLI to pass a merged view of workspace package.json dependencies
  pkgOverride?: any;
  // Map dependency name -> workspace package names where it is used/declared
  workspaceUsage?: Map<string, string[]>;
  // Paths to resolve dependency package.json from (workspace package roots, etc.)
  resolvePaths?: string[];
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


type RootPackageRef = { name: string; version: string };

function findRootCauses(node: NodeInfo, nodeMap: Map<string, NodeInfo>, pkg: any): RootPackageRef[] {
  // If it's a direct dependency, it's its own root cause
  if (isDirectDependency(node.name, pkg)) {
    return [{ name: node.name, version: node.version }];
  }
  
  // BFS up the parent chain to find all direct dependencies that lead to this
  const rootCauses = new Map<string, RootPackageRef>();
  const visited = new Set<string>();
  const queue = [...node.parents];
  
  while (queue.length > 0) {
    const parentKey = queue.shift()!;
    if (visited.has(parentKey)) continue;
    visited.add(parentKey);
    
    const parent = nodeMap.get(parentKey);
    if (!parent) continue;
    
    if (isDirectDependency(parent.name, pkg)) {
      rootCauses.set(parent.key, { name: parent.name, version: parent.version });
    } else {
      // Keep going up the chain
      for (const grandparent of parent.parents) {
        if (!visited.has(grandparent)) {
          queue.push(grandparent);
        }
      }
    }
  }
  
  return Array.from(rootCauses.values()).sort((a, b) => {
    const nameCompare = a.name.localeCompare(b.name);
    if (nameCompare !== 0) return nameCompare;
    return a.version.localeCompare(b.version);
  });
}

function formatProjectDir(projectPath: string): string {
  const home = os.homedir();
  const relative = path.relative(home, projectPath);
  if (relative && !relative.startsWith('..') && !path.isAbsolute(relative)) {
    return `/${relative.split(path.sep).join('/')}`;
  }
  return projectPath;
}

export async function aggregateData(input: AggregateInput): Promise<AggregatedData> {
  const pkg = input.pkgOverride || (await readPackageJson(input.projectPath));

  // Get git branch
  const gitBranch = await getGitBranch(input.projectPath);

  const nodeMap = buildNodeMap(input.npmLsResult?.data, pkg);
  const vulnMap = parseVulnerabilities(input.auditResult?.data);
  const importGraph = normalizeImportGraph(input.importGraphResult?.data);
  const usageResult = buildUsageSummary(importGraph, input.projectPath);
  const outdatedById = buildOutdatedMap(input.outdatedResult);
  const outdatedUnknownNames = new Set(input.outdatedResult?.unknownNames || []);
  const packageMetaCache = new Map<string, PackageMeta>();
  const resolvePaths = input.resolvePaths && input.resolvePaths.length > 0
    ? input.resolvePaths
    : [input.projectPath];
  const packageStatCache = new Map<string, PackageStats>();

  const dependencies: Record<string, DependencyRecord> = {};
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
      (await readLicenseFromPackageJson(node.name, resolvePaths)) ||
      { license: undefined };
    if (!licenseCache.has(node.name) && license.license) {
      licenseCache.set(node.name, license);
    }
    const vulnerabilities = vulnMap.get(node.name) || emptyVulnSummary();
    const licenseValue = license.license || 'unknown';
    const licenseRisk = licenseRiskLevel(licenseValue);
    
    // Calculate root causes (direct dependencies that cause this to be installed)
    const rootCauses = findRootCauses(node, nodeMap, pkg);

    const packageInsights = await gatherPackageInsights(
      node.name,
      resolvePaths,
      packageMetaCache,
      packageStatCache
    );
    if (packageInsights.nodeEngine) {
      nodeEngineRanges.push(packageInsights.nodeEngine);
    }

    const scope = determineScope(node.name, direct, rootCauses, pkg);
    const importUsage = usageResult.summary.get(node.name);
    const runtimeImpact = usageResult.runtimeImpact.get(node.name);
    const introduction = determineIntroduction(direct, rootCauses, runtimeImpact);
    const origins = buildOrigins(rootCauses, input.workspaceUsage?.get(node.name), input.workspaceEnabled, MAX_TOP_ROOT_PACKAGES);
    const execution = packageInsights.execution;
    const id = node.key;
    const upgrade = buildUpgradeBlock(packageInsights);
    const outdated = resolveOutdated(node, direct, outdatedById, outdatedUnknownNames);

    // Group fields by reviewer question to keep the JSON readable and source-agnostic.
    // Optional fields are only attached when meaningful to keep the payload sparse.
    const upgradeRecord: DependencyRecord['upgrade'] = {
      nodeEngine: packageInsights.nodeEngine,
      ...(outdated ? { outdatedStatus: outdated.status } : {}),
      ...(outdated?.latestVersion ? { latestVersion: outdated.latestVersion } : {}),
      ...(upgrade?.blockers ? { blockers: upgrade.blockers } : {}),
      ...(upgrade?.blocksNodeMajor ? { blocksNodeMajor: upgrade.blocksNodeMajor } : {})
    };

    dependencies[id] = {
      package: {
        id,
        name: node.name,
        version: node.version,
        ...(packageInsights.description ? { description: packageInsights.description } : {}),
        deprecated: packageInsights.deprecated,
        links: {
          npm: `https://www.npmjs.com/package/${node.name}`,
          ...(packageInsights.links?.repository ? { repository: packageInsights.links.repository } : {}),
          ...(packageInsights.links?.homepage ? { homepage: packageInsights.links.homepage } : {}),
          ...(packageInsights.links?.bugs ? { bugs: packageInsights.links.bugs } : {})
        }
      },
      compliance: {
        license: licenseValue,
        licenseRisk
      },
      security: {
        summary: {
          critical: vulnerabilities.counts.critical,
          high: vulnerabilities.counts.high,
          moderate: vulnerabilities.counts.moderate,
          low: vulnerabilities.counts.low,
          highest: vulnerabilities.highestSeverity,
          risk: vulnerabilities.risk
        },
        ...(vulnerabilities.advisories && vulnerabilities.advisories.length > 0 ? { advisories: vulnerabilities.advisories } : {})
      },
      upgrade: upgradeRecord,
      usage: {
        direct,
        scope,
        depth: node.depth,
        origins,
        ...(introduction ? { introduction } : {}),
        ...(runtimeImpact ? { runtimeImpact } : {}),
        ...(importUsage ? { importUsage } : {}),
        tsTypes: packageInsights.tsTypes
      },
      graph: {
        fanIn: node.parents.size,
        fanOut: node.children.size,
        dependencySurface: packageInsights.dependencySurface
      },
      ...(execution ? { execution } : {})
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
      projectDir: formatProjectDir(input.projectPath)
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

function buildOutdatedMap(outdatedResult?: OutdatedResult): Map<string, { status: 'patch' | 'minor' | 'major' | 'unknown'; latestVersion?: string }> {
  const map = new Map<string, { status: 'patch' | 'minor' | 'major' | 'unknown'; latestVersion?: string }>();
  if (!outdatedResult || !Array.isArray(outdatedResult.entries)) return map;
  for (const entry of outdatedResult.entries) {
    if (!entry || typeof entry.name !== 'string' || typeof entry.currentVersion !== 'string') continue;
    const key = `${entry.name}@${entry.currentVersion}`;
    if (entry.status === 'patch' || entry.status === 'minor' || entry.status === 'major') {
      if (entry.latestVersion) {
        map.set(key, { status: entry.status, latestVersion: entry.latestVersion });
      } else {
        map.set(key, { status: 'unknown' });
      }
      continue;
    }
    map.set(key, { status: 'unknown' });
  }
  return map;
}

function resolveOutdated(
  node: NodeInfo,
  direct: boolean,
  outdatedById: Map<string, { status: 'patch' | 'minor' | 'major' | 'unknown'; latestVersion?: string }>,
  unknownNames: Set<string>
): { status: OutdatedStatus; latestVersion?: string } | undefined {
  const entry = outdatedById.get(node.key);
  if (entry) {
    if (entry.status === 'patch' || entry.status === 'minor' || entry.status === 'major') {
      if (entry.latestVersion) {
        return { status: entry.status, latestVersion: entry.latestVersion };
      }
      return { status: 'unknown' };
    }
    return { status: 'unknown' };
  }
  if (direct && unknownNames.has(node.name)) {
    return { status: 'unknown' };
  }
  return undefined;
}

const GHSA_ID_REGEX = /GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}/i;

function extractGhsaId(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const match = value.match(GHSA_ID_REGEX);
  return match ? match[0].toUpperCase() : undefined;
}

function extractNpmAdvisoryId(url: string): string | undefined {
  const match = url.match(/advisories\/(\d+)/i);
  return match ? match[1] : undefined;
}

function resolveAdvisoryId(advisory: any, fallbackUrl?: string): string | undefined {
  const ghsa =
    extractGhsaId(advisory?.github_advisory_id) ||
    extractGhsaId(advisory?.ghsaId) ||
    extractGhsaId(advisory?.ghsa_id) ||
    extractGhsaId(advisory?.source) ||
    extractGhsaId(advisory?.id) ||
    extractGhsaId(advisory?.url) ||
    (fallbackUrl ? extractGhsaId(fallbackUrl) : undefined);
  if (ghsa) return ghsa;
  const url = typeof advisory?.url === 'string' ? advisory.url : undefined;
  const npmId = url ? extractNpmAdvisoryId(url) : undefined;
  if (npmId) return npmId;
  if (advisory?.source !== undefined) return String(advisory.source);
  if (advisory?.id !== undefined) return String(advisory.id);
  return undefined;
}

function resolveAdvisoryUrl(advisory: any, id: string | undefined): string | undefined {
  if (typeof advisory?.url === 'string' && advisory.url.trim()) return advisory.url.trim();
  if (id) {
    if (/^GHSA-/i.test(id)) return `https://github.com/advisories/${id}`;
    if (/^\d+$/.test(id)) return `https://www.npmjs.com/advisories/${id}`;
  }
  return undefined;
}

function resolveFixAvailable(value: any, patchedVersions?: string): boolean {
  if (typeof value === 'boolean') return value;
  if (value && typeof value === 'object') return true;
  if (typeof patchedVersions === 'string') {
    const trimmed = patchedVersions.trim();
    return Boolean(trimmed && trimmed !== '<0.0.0');
  }
  return false;
}

function normalizeAdvisoryRange(value: any): string {
  if (typeof value === 'string' && value.trim()) return value.trim();
  return 'unknown';
}

function buildAdvisoryFromVia(via: any, item: any): VulnerabilityAdvisory | undefined {
  if (!via || typeof via !== 'object') return undefined;
  const id = resolveAdvisoryId(via, via.url) || resolveAdvisoryId(item, item?.url);
  const title = typeof via.title === 'string' && via.title.trim()
    ? via.title.trim()
    : typeof via.name === 'string' && via.name.trim()
      ? via.name.trim()
      : 'Advisory';
  const severity: Severity = normalizeSeverity(via.severity || item?.severity);
  const vulnerableRange = normalizeAdvisoryRange(via.range || via.vulnerable_versions || item?.range);
  const fixAvailable = resolveFixAvailable(via.fixAvailable ?? item?.fixAvailable, via.patched_versions);
  const url = resolveAdvisoryUrl(via, id) || resolveAdvisoryUrl(item, id);

  if (!id) return undefined;
  return {
    id,
    title,
    severity,
    vulnerableRange,
    fixAvailable,
    url: url || ''
  };
}

function buildAdvisoryFromLegacy(adv: any): VulnerabilityAdvisory | undefined {
  if (!adv || typeof adv !== 'object') return undefined;
  const id = resolveAdvisoryId(adv, adv.url);
  const title = typeof adv.title === 'string' && adv.title.trim()
    ? adv.title.trim()
    : typeof adv.module_name === 'string' && adv.module_name.trim()
      ? adv.module_name.trim()
      : 'Advisory';
  const severity: Severity = normalizeSeverity(adv.severity);
  const vulnerableRange = normalizeAdvisoryRange(adv.vulnerable_versions || adv.vulnerableRange || adv.range);
  const fixAvailable = resolveFixAvailable(adv.fix_available, adv.patched_versions);
  const url = resolveAdvisoryUrl(adv, id);

  if (!id) return undefined;
  return {
    id,
    title,
    severity,
    vulnerableRange,
    fixAvailable,
    url: url || ''
  };
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

  const advisoryKeys = new Map<string, Set<string>>();
  const deferredViaStrings: Array<{ name: string; via: string[] }> = [];
  const addAdvisory = (name: string, advisory: VulnerabilityAdvisory) => {
    const entry = ensureEntry(name);
    const key = `${advisory.id}|${advisory.vulnerableRange}`;
    let keys = advisoryKeys.get(name);
    if (!keys) {
      keys = new Set<string>();
      advisoryKeys.set(name, keys);
    }
    if (keys.has(key)) return;
    keys.add(key);
    if (!entry.advisories) entry.advisories = [];
    entry.advisories.push(advisory);
  };

  // Advisories are disclosed findings from npm audit (not malware detection).
  // Summary-only output loses evidence and is a data loss bug.
  if (auditData.vulnerabilities) {
    Object.values<any>(auditData.vulnerabilities).forEach((item: any) => {
      const name = item.name || 'unknown';
      const viaList = Array.isArray(item.via) ? item.via : [];
      let added = false;
      for (const via of viaList) {
        if (via && typeof via === 'object') {
          const advisory = buildAdvisoryFromVia(via, item);
          if (advisory) {
            addAdvisory(name, advisory);
            added = true;
          }
        }
      }
      const viaStrings = viaList.filter((via: unknown) => typeof via === 'string') as string[];
      if (viaStrings.length > 0) {
        deferredViaStrings.push({ name, via: viaStrings });
      }
      if (!added) {
        const fallback = buildAdvisoryFromVia(item, item);
        if (fallback) addAdvisory(name, fallback);
      }
    });
  }

  if (auditData.advisories) {
    Object.values<any>(auditData.advisories).forEach((adv: any) => {
      const name = adv.module_name || adv.module || 'unknown';
      const advisory = buildAdvisoryFromLegacy(adv);
      if (advisory) addAdvisory(name, advisory);
    });
  }

  // One-level expansion: map string "via" references to their advisories without storing paths.
  for (const entry of deferredViaStrings) {
    for (const refName of entry.via) {
      const referenced = map.get(refName);
      if (referenced?.advisories) {
        for (const advisory of referenced.advisories) {
          addAdvisory(entry.name, advisory);
        }
      }
    }
  }

  map.forEach((entry) => {
    const counts = { low: 0, moderate: 0, high: 0, critical: 0 };
    if (entry.advisories) {
      for (const advisory of entry.advisories) {
        counts[advisory.severity] += 1;
      }
    }
    entry.counts = counts;
    entry.highestSeverity = computeHighestSeverity(counts);
    entry.risk = vulnRiskLevel(counts);
    if (entry.advisories && entry.advisories.length > 0) {
      entry.advisories.sort((a, b) => {
        const order = { critical: 4, high: 3, moderate: 2, low: 1 };
        const diff = order[b.severity] - order[a.severity];
        if (diff !== 0) return diff;
        return a.title.localeCompare(b.title);
      });
    }
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
    highestSeverity: 'none',
    risk: 'green'
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
  runtimeImpact: Map<string, DependencyRecord['usage']['runtimeImpact']>;
}

function buildUsageSummary(graph: ImportGraphData, projectPath: string): UsageBuildResult {
  const summary = new Map<string, UsageSummary>();
  const runtimeImpact = new Map<string, DependencyRecord['usage']['runtimeImpact']>();
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

function determineScope(name: string, direct: boolean, rootCauses: RootPackageRef[], pkg: any): DependencyScope {
  if (direct) {
    return directScopeFromPackage(name, pkg) || 'runtime';
  }
  const scopes = new Set<DependencyScope>();
  for (const root of rootCauses) {
    const scope = directScopeFromPackage(root.name, pkg);
    if (scope) scopes.add(scope);
  }
  if (scopes.has('runtime')) return 'runtime';
  if (scopes.has('dev')) return 'dev';
  if (scopes.has('optional')) return 'optional';
  if (scopes.has('peer')) return 'peer';
  return 'runtime';
}

function buildOrigins(
  rootCauses: RootPackageRef[],
  workspaceList: string[] | undefined,
  workspaceEnabled: boolean,
  maxTop: number
): { rootPackageCount: number; topRootPackages: RootPackageRef[]; workspaces?: string[] } {
  const origins: { rootPackageCount: number; topRootPackages: RootPackageRef[]; workspaces?: string[] } = {
    rootPackageCount: rootCauses.length,
    topRootPackages: rootCauses.slice(0, maxTop)
  };
  if (workspaceEnabled && workspaceList && workspaceList.length > 0) {
    origins.workspaces = workspaceList;
  }
  return origins;
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

function determineRuntimeImpactFromFiles(files: string[]): DependencyRecord['usage']['runtimeImpact'] {
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
  rootCauses: RootPackageRef[],
  runtimeImpact: DependencyRecord['usage']['runtimeImpact']
): DependencyRecord['usage']['introduction'] {
  const rootNames = rootCauses.map((root) => root.name);
  if (direct) return 'direct';
  if (runtimeImpact === 'testing') return 'testing';
  if (rootNames.length > 0 && rootNames.every((root) => isToolingPackage(root))) return 'tooling';
  if (rootNames.some((root) => isFrameworkPackage(root))) return 'framework';
  if (rootNames.length > 0) return 'transitive';
  return 'unknown';
}

// Upgrade blockers derived only from local metadata (no external lookups).
function buildUpgradeBlock(
  insights: PackageInsights
): { blockers: Array<'nodeEngine' | 'peerDependency' | 'nativeBindings' | 'deprecated'>; blocksNodeMajor: boolean } | undefined {
  const blockers: Array<'nodeEngine' | 'peerDependency' | 'nativeBindings' | 'deprecated'> = [];
  if (insights.nodeEngine) blockers.push('nodeEngine');
  if (insights.dependencySurface.peer > 0) blockers.push('peerDependency');
  if (insights.execution?.native) blockers.push('nativeBindings');
  if (insights.deprecated) blockers.push('deprecated');

  if (blockers.length === 0) return undefined;
  return {
    blocksNodeMajor: true,
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
  description?: string;
  dependencySurface: {
    deps: number;
    dev: number;
    peer: number;
    opt: number;
  };
  links?: {
    repository?: string;
    homepage?: string;
    bugs?: string;
  };
  execution?: DependencyRecord['execution'];
  tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown';
}

async function gatherPackageInsights(
  name: string,
  resolvePaths: string[],
  metaCache: Map<string, PackageMeta>,
  statCache: Map<string, PackageStats>
): Promise<PackageInsights> {
  const meta = await loadPackageMeta(name, resolvePaths, metaCache);
  if (!meta) {
    return {
      deprecated: false,
      nodeEngine: null,
      dependencySurface: { deps: 0, dev: 0, peer: 0, opt: 0 },
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
  const description = typeof pkg.description === 'string' && pkg.description.trim()
    ? pkg.description.trim()
    : undefined;

  const hasDefinitelyTyped = await hasDefinitelyTypedPackage(name, resolvePaths, metaCache);
  const tsTypes = determineTypes(pkg, stats?.hasDts || false, hasDefinitelyTyped);
  const links = extractPackageLinks(pkg);
  const execution = await deriveExecutionInfo(scripts, dir, stats);

  return {
    deprecated,
    nodeEngine,
    description,
    dependencySurface,
    links,
    execution,
    tsTypes
  };
}

async function loadPackageMeta(
  name: string,
  resolvePaths: string[],
  cache: Map<string, PackageMeta>
): Promise<PackageMeta | undefined> {
  if (cache.has(name)) return cache.get(name);
  try {
    const pkgJsonPath = await resolvePackageJsonPath(name, resolvePaths);
    if (!pkgJsonPath) return undefined;
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
  resolvePaths: string[],
  cache: Map<string, PackageMeta>
): Promise<boolean> {
  if (name.startsWith('@types/')) return true;
  const typesName = toDefinitelyTypedPackageName(name);
  if (!typesName) return false;
  const meta = await loadPackageMeta(typesName, resolvePaths, cache);
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

const REPO_SHORTHAND_HOSTS: Record<string, string> = {
  github: 'github.com',
  gitlab: 'gitlab.com',
  bitbucket: 'bitbucket.org'
};

function normalizeUrl(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  let url = trimmed.replace(/^git\+/, '');

  if (url.startsWith('ssh://')) {
    url = url.slice('ssh://'.length);
    if (url.startsWith('git@')) {
      const match = url.match(/^git@([^:]+):(.+)$/);
      if (match) {
        url = `https://${match[1]}/${match[2]}`;
      } else {
        url = `https://${url}`;
      }
    } else {
      url = `https://${url}`;
    }
  }

  if (url.startsWith('git@')) {
    const match = url.match(/^git@([^:]+):(.+)$/);
    if (match) {
      url = `https://${match[1]}/${match[2]}`;
    }
  }

  const shorthand = url.match(/^(github|gitlab|bitbucket):(.+)$/i);
  if (shorthand) {
    const host = REPO_SHORTHAND_HOSTS[shorthand[1].toLowerCase()];
    url = `https://${host}/${shorthand[2]}`;
  }

  if (url.startsWith('git://')) {
    url = `https://${url.slice('git://'.length)}`;
  }

  const hashIndex = url.indexOf('#');
  const hash = hashIndex === -1 ? '' : url.slice(hashIndex);
  const base = hashIndex === -1 ? url : url.slice(0, hashIndex);
  const cleaned = base.endsWith('.git') ? base.slice(0, -4) : base;

  return cleaned + hash;
}

function normalizeLinkValue(value: any): string | undefined {
  if (!value) return undefined;
  if (typeof value === 'string') return normalizeUrl(value);
  if (typeof value === 'object' && typeof value.url === 'string') {
    return normalizeUrl(value.url);
  }
  return undefined;
}

function extractPackageLinks(pkg: any): PackageInsights['links'] | undefined {
  const repository = normalizeLinkValue(pkg?.repository);
  const homepage = normalizeLinkValue(pkg?.homepage);
  const bugs = normalizeLinkValue(pkg?.bugs);

  if (!repository && !homepage && !bugs) return undefined;
  return {
    ...(repository ? { repository } : {}),
    ...(homepage ? { homepage } : {}),
    ...(bugs ? { bugs } : {})
  };
}

const LIFECYCLE_HOOKS: ExecutionHook[] = ['preinstall', 'install', 'postinstall', 'prepare'];
const EXECUTION_SIGNAL_ORDER: ExecutionSignal[] = [
  'network-access',
  'dynamic-exec',
  'child-process',
  'encoding',
  'obfuscated',
  'reads-env',
  'reads-home',
  'uses-ssh'
];
const INSTALL_SCRIPT_MAX_BYTES = 200_000;
const COMPLEXITY_THRESHOLD = 12;

function collectLifecycleScripts(
  scripts: Record<string, any>
): Partial<Record<ExecutionHook, string>> {
  const lifecycle: Partial<Record<ExecutionHook, string>> = {};
  for (const hook of LIFECYCLE_HOOKS) {
    const cmd = scripts?.[hook];
    if (typeof cmd === 'string' && cmd.trim().length > 0) {
      lifecycle[hook] = cmd.trim();
    }
  }
  return lifecycle;
}

function scriptsContainNativeTooling(scripts: Record<string, any>): boolean {
  return (Object.values(scripts || {}) as any[]).some((cmd) =>
    typeof cmd === 'string' && /node-?gyp|node-pre-gyp|prebuild/i.test(cmd)
  );
}

function scoreLifecycleScripts(
  lifecycleScripts: Partial<Record<ExecutionHook, string>>
): number {
  const commands = Object.values(lifecycleScripts).filter((cmd): cmd is string => typeof cmd === 'string');
  const combined = commands.join(' ');
  if (!combined) return 0;
  const lengthScore = Math.ceil(combined.length / 40);
  const andCount = (combined.match(/&&/g) || []).length;
  const orCount = (combined.match(/\|\|/g) || []).length;
  const semicolons = (combined.match(/;/g) || []).length;
  const pipeCount = Math.max(0, (combined.match(/\|/g) || []).length - orCount * 2);
  const inlineNodeExec = (combined.match(/\bnode\s+-[ep]\b/gi) || []).length;
  const inlineEval = (combined.match(/\beval\s*\(/g) || []).length;
  const inlineFunction = (combined.match(/new\s+Function\s*\(/g) || []).length;
  return lengthScore + (andCount + orCount + semicolons + pipeCount) * 2 + (inlineNodeExec + inlineEval + inlineFunction) * 5;
}

function tokenizeCommand(command: string): string[] {
  const tokens: string[] = [];
  const matcher = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = matcher.exec(command))) {
    tokens.push(match[1] ?? match[2] ?? match[3]);
  }
  return tokens;
}

function isNodeToken(token: string): boolean {
  const base = path.basename(token).toLowerCase();
  return base === 'node' || base === 'node.exe';
}

function extractNodeScriptPath(command: string): string | undefined {
  const tokens = tokenizeCommand(command);
  for (let i = 0; i < tokens.length; i += 1) {
    if (!isNodeToken(tokens[i])) continue;
    let idx = i + 1;
    while (idx < tokens.length) {
      const token = tokens[idx];
      if (token === '-e' || token === '-p' || token === '--eval') {
        return undefined;
      }
      if (token === '-r' || token === '--require') {
        idx += 2;
        continue;
      }
      if (token.startsWith('-')) {
        idx += 1;
        continue;
      }
      const cleaned = token.replace(/[;|&]+$/, '');
      if (cleaned.includes('://')) return undefined;
      if (cleaned.endsWith('.js') || cleaned.endsWith('.cjs') || cleaned.endsWith('.mjs')) {
        return cleaned;
      }
      return undefined;
    }
  }
  return undefined;
}

function findReferencedInstallScript(
  lifecycleScripts: Partial<Record<ExecutionHook, string>>
): string | undefined {
  for (const hook of LIFECYCLE_HOOKS) {
    const command = lifecycleScripts[hook];
    if (!command) continue;
    const candidate = extractNodeScriptPath(command);
    if (candidate) return candidate;
  }
  return undefined;
}

async function readInstallScriptFile(
  scriptPath: string,
  packageDir: string
): Promise<string | undefined> {
  const resolvedDir = path.resolve(packageDir);
  const resolvedPath = path.resolve(resolvedDir, scriptPath);
  if (!resolvedPath.startsWith(resolvedDir + path.sep)) return undefined;
  try {
    const stat = await fs.stat(resolvedPath);
    if (!stat.isFile()) return undefined;
    if (stat.size > INSTALL_SCRIPT_MAX_BYTES) return undefined;
    return await fs.readFile(resolvedPath, 'utf8');
  } catch {
    return undefined;
  }
}

function textHasAny(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text));
}

function detectScriptSignals(text: string, signals: Set<ExecutionSignal>): void {
  // Signals are derived from static text inspection only: no code execution and no import walking.
  // They are NOT malware detection; they merely highlight review-worthy install-time behavior.

  // "network-access" surfaces install scripts that fetch remote resources (review for expected downloads; does NOT imply exfiltration).
  if (textHasAny(text, [/\bcurl\b/i, /\bwget\b/i, /https?:\/\//i, /\bfetch\s*\(/i, /\baxios\b/i, /node-fetch/i])) {
    signals.add('network-access');
  }
  // "reads-env" highlights environment access (does NOT imply exfiltration).
  if (textHasAny(text, [/\bprocess\.env\b/, /\bprintenv\b/i, /\benv\s*\|/i])) {
    signals.add('reads-env');
  }
  // "reads-home" highlights access to user home paths (does NOT imply credential theft).
  if (textHasAny(text, [/\$HOME\b/, /process\.env\.HOME\b/, /os\.homedir\s*\(/, /~\//])) {
    signals.add('reads-home');
  }
  // "uses-ssh" flags access to SSH-related paths (does NOT imply key exfiltration).
  if (textHasAny(text, [/\.ssh\b/i, /id_rsa\b/i, /known_hosts\b/i, /\.npmrc\b/i])) {
    signals.add('uses-ssh');
  }
}

function isObfuscated(text: string): boolean {
  const lines = text.split(/\r?\n/);
  let longest = 0;
  for (const line of lines) {
    if (line.length > longest) longest = line.length;
    if (longest >= 4000) return true;
  }
  if (text.length >= 2000) {
    const nonWhitespace = text.replace(/\s/g, '');
    const ratio = nonWhitespace.length / text.length;
    if (ratio > 0.9) return true;
  }
  return /[A-Za-z0-9+/]{800,}={0,2}/.test(text);
}

function detectFileSignals(text: string, signals: Set<ExecutionSignal>): void {
  // Signals from a single directly-referenced JS file (no execution, no imports, no deep scanning).
  // These are review cues only and do NOT imply malicious intent.
  detectScriptSignals(text, signals);

  // "dynamic-exec" flags dynamic code execution APIs (does NOT imply malicious behavior).
  if (textHasAny(text, [/\beval\s*\(/, /new\s+Function\s*\(/, /\bvm\.runIn/i])) {
    signals.add('dynamic-exec');
  }
  // "child-process" flags process spawning (does NOT imply abuse).
  if (textHasAny(text, [/\bchild_process\.exec\b/, /\bspawn\s*\(/, /\bexecSync\s*\(/])) {
    signals.add('child-process');
  }
  // "encoding" flags explicit encode/decode flows (does NOT imply obfuscation intent).
  if (textHasAny(text, [/Buffer\.from\s*\(/, /\.toString\(\s*['"]base64['"]\s*\)/i, /\batob\s*\(/, /\bbtoa\s*\(/])) {
    signals.add('encoding');
  }
  // "obfuscated" flags minified or opaque install-time code (does NOT imply malware).
  if (isObfuscated(text)) {
    signals.add('obfuscated');
  }
}

function determineExecutionRisk(
  hasScripts: boolean,
  hasSignals: boolean,
  highComplexity: boolean,
  hooks: ExecutionHook[]
): 'amber' | 'red' {
  const hasInstallHook = hooks.includes('install') || hooks.includes('postinstall');
  if (hasScripts && (hasSignals || (highComplexity && hasInstallHook))) return 'red';
  return 'amber';
}

async function deriveExecutionInfo(
  scripts: Record<string, any>,
  packageDir: string | undefined,
  stats: PackageStats | undefined
): Promise<DependencyRecord['execution'] | undefined> {
  const lifecycleScripts = collectLifecycleScripts(scripts);
  const hooks = LIFECYCLE_HOOKS.filter((hook) => Boolean(lifecycleScripts[hook]));
  const hasScripts = hooks.length > 0;
  const hasNative = Boolean(stats?.hasNativeBinary || stats?.hasBindingGyp || scriptsContainNativeTooling(scripts));

  if (!hasScripts && !hasNative) return undefined;

  const signals = new Set<ExecutionSignal>();
  const combinedScripts = hooks.map((hook) => lifecycleScripts[hook]!).join('\n');
  if (combinedScripts) {
    detectScriptSignals(combinedScripts, signals);
  }

  if (hasScripts && packageDir) {
    const referencedScript = findReferencedInstallScript(lifecycleScripts);
    if (referencedScript) {
      const fileContent = await readInstallScriptFile(referencedScript, packageDir);
      if (fileContent) {
        detectFileSignals(fileContent, signals);
      }
    }
  }

  const complexityScore = hasScripts ? scoreLifecycleScripts(lifecycleScripts) : 0;
  const complexity = complexityScore >= COMPLEXITY_THRESHOLD ? complexityScore : undefined;

  const signalList = EXECUTION_SIGNAL_ORDER.filter((signal) => signals.has(signal));

  const scriptsInfo: NonNullable<DependencyRecord['execution']>['scripts'] = {
    hooks,
    ...(complexity !== undefined ? { complexity } : {}),
    ...(signalList.length > 0 ? { signals: signalList } : {})
  };

  const risk = determineExecutionRisk(hasScripts, signalList.length > 0, complexity !== undefined, hooks);
  const execution: DependencyRecord['execution'] = { risk };
  // Native is surface description only; not a behavioral signal.
  if (hasNative) execution.native = true;
  if (hasScripts) execution.scripts = scriptsInfo;
  return execution;
}
